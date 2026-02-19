"""
Full Database-Connected Index Advisor Pipeline.

This is the end-to-end pipeline that runs against a live PostgreSQL database:
    1. Connect and collect statistics (pg_stat_user_tables, pg_stat_statements)
    2. Extract scans from top queries
    3. Classify tables automatically
    4. Generate candidate indexes
    5. (Optional) Cost candidates with HypoPG
    6. Apply HOT guard and functional dependency optimization
    7. Solve with CP-SAT (or greedy fallback)
    8. Detect redundant/unused existing indexes
    9. Return CREATE/DROP recommendations

This is the module that powers `querysense index check` and `querysense index advise`.

Usage:
    from querysense.index.advisor_pipeline import IndexAdvisorPipeline

    pipeline = IndexAdvisorPipeline()
    result = await pipeline.advise("postgresql://localhost/mydb")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RecommendedIndex:
    """A recommended index from the pipeline."""

    table: str
    columns: tuple[str, ...]
    index_type: str = "btree"
    create_sql: str = ""
    scans_covered: int = 0
    total_frequency: int = 0
    improvement_ratio: float = 0.0
    iwo_score: float = 0.0
    hypopg_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "columns": list(self.columns),
            "index_type": self.index_type,
            "create_sql": self.create_sql,
            "scans_covered": self.scans_covered,
            "total_frequency": self.total_frequency,
            "improvement_ratio": round(self.improvement_ratio, 4),
            "iwo_score": round(self.iwo_score, 2),
            "hypopg_verified": self.hypopg_verified,
        }


@dataclass
class PipelineResult:
    """Complete result from the advisor pipeline."""

    tables_analyzed: int = 0
    scans_extracted: int = 0
    candidates_generated: int = 0
    candidates_after_iwo: int = 0
    total_cost_reduction_pct: float = 0.0
    total_iwo: float = 0.0
    total_time_ms: float = 0.0
    solver_method: str = "CP-SAT"

    recommended_indexes: list[RecommendedIndex] = field(default_factory=list)
    dropped_indexes: list[str] = field(default_factory=list)

    # Per-table details
    table_classifications: dict[str, str] = field(default_factory=dict)
    hot_warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tables_analyzed": self.tables_analyzed,
            "scans_extracted": self.scans_extracted,
            "candidates_generated": self.candidates_generated,
            "candidates_after_iwo": self.candidates_after_iwo,
            "total_cost_reduction_pct": round(self.total_cost_reduction_pct, 2),
            "total_iwo": round(self.total_iwo, 2),
            "total_time_ms": round(self.total_time_ms, 1),
            "solver_method": self.solver_method,
            "recommended_indexes": [r.to_dict() for r in self.recommended_indexes],
            "dropped_indexes": self.dropped_indexes,
            "table_classifications": self.table_classifications,
            "hot_warnings": self.hot_warnings,
        }


class IndexAdvisorPipeline:
    """
    End-to-end index advisor that connects to a live PostgreSQL database.

    Orchestrates: stats collection -> scan extraction -> classification ->
    candidate generation -> HOT guard -> CP solve -> consolidation.
    """

    def __init__(
        self,
        max_indexes_per_table: int = 8,
        use_hypopg: bool = True,
        top_queries: int = 100,
        time_limit: float = 10.0,
    ) -> None:
        self.max_indexes_per_table = max_indexes_per_table
        self.use_hypopg = use_hypopg
        self.top_queries = top_queries
        self.time_limit = time_limit

    async def advise(
        self,
        dsn: str,
        schema: str = "public",
        tables: list[str] | None = None,
    ) -> PipelineResult:
        """
        Run the full advisory pipeline against a PostgreSQL database.

        Args:
            dsn: PostgreSQL connection string.
            schema: Schema to analyze.
            tables: Optional list of specific tables. If None, auto-discovers.

        Returns:
            PipelineResult with recommendations.
        """
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "asyncpg is required for database-connected index advising.\n"
                "Install with: pip install querysense[db]"
            )

        t0 = time.perf_counter()

        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor
        from querysense.index.consolidation import IndexConsolidator
        from querysense.index.cp_model import (
            Index,
            Rule,
            RuleName,
            Scan,
            SolverSettings,
        )
        from querysense.index.scan_extractor import ScanExtractor
        from querysense.index.stats_collector import StatsCollector

        conn = await asyncpg.connect(dsn)
        result = PipelineResult()

        try:
            collector = StatsCollector(conn)
            extractor = ScanExtractor()
            advisor = ConstraintProgrammingIndexAdvisor()
            consolidator = IndexConsolidator()
            result.solver_method = advisor.solver_method

            # Step 1: Discover tables to analyze
            if not tables:
                rows = await conn.fetch(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = $1 "
                    "ORDER BY tablename",
                    schema,
                )
                tables = [r["tablename"] for r in rows]

            # Step 2: For each table, run the pipeline
            for table_name in tables:
                # Collect statistics
                table_stats = await collector.collect_table_stats(table_name, schema)

                # Skip small/ignored tables
                classification_type = advisor.classifier.classify(table_stats)
                result.table_classifications[table_name] = classification_type.value

                if classification_type.value == "ignore":
                    continue

                result.tables_analyzed += 1

                # Collect existing indexes
                existing = await collector.collect_existing_indexes(table_name)

                # Collect top queries
                query_entries = await collector.collect_top_queries(
                    table_name, limit=self.top_queries
                )
                if not query_entries:
                    continue

                # Extract scans and candidates from queries
                queries = [{"sql": q.sql, "frequency": q.frequency} for q in query_entries]
                candidate_set = extractor.extract_from_queries(queries, table=table_name)

                result.scans_extracted += len(candidate_set.scans)
                result.candidates_generated += len(candidate_set.candidates)

                if not candidate_set.scans:
                    continue

                # Build candidate Index objects
                candidate_indexes = candidate_set.candidates

                # Include existing indexes as candidates (may be de-selected)
                for ex in existing:
                    cp_idx = ex.to_cp_index()
                    if cp_idx.id not in {c.id for c in candidate_indexes}:
                        candidate_indexes.append(cp_idx)

                # Run full analysis (classification, HOT, FD, IWO, CP solve)
                recommendation = advisor.analyze_table(
                    table_name,
                    table_stats,
                    candidate_indexes,
                    candidate_set.scans,
                )

                result.candidates_after_iwo += len(candidate_indexes)

                # Collect HOT warnings
                for w in recommendation.hot_warnings:
                    result.hot_warnings.append(w.to_dict())

                # Record recommendations
                for idx_id in recommendation.solution.selected_indexes:
                    idx = next(
                        (c for c in candidate_indexes if c.id == idx_id),
                        None,
                    )
                    if idx and not idx.is_existing:
                        # Count scans this index covers
                        scans_covered = sum(
                            1
                            for sr in recommendation.solution.scan_results
                            if sr.covering_index == idx_id
                        )
                        total_freq = sum(
                            s.frequency
                            for s in candidate_set.scans
                            if idx_id in s.index_costs
                        )

                        cols = ", ".join(idx.columns)
                        using = f" USING {idx.index_type}" if idx.index_type != "btree" else ""
                        name = idx.name or f"idx_{table_name}_{'_'.join(idx.columns[:3])}"
                        create = f"CREATE INDEX CONCURRENTLY {name} ON {table_name}{using} ({cols});"

                        iwo = next(
                            (r.iwo_score for r in recommendation.iwo_results if r.index_name == idx_id),
                            0.0,
                        )

                        result.recommended_indexes.append(
                            RecommendedIndex(
                                table=table_name,
                                columns=idx.columns,
                                index_type=idx.index_type,
                                create_sql=create,
                                scans_covered=scans_covered,
                                total_frequency=total_freq,
                                iwo_score=iwo,
                            )
                        )

                # Consolidation: find drops
                consolidation = consolidator.merge_with_cp_recommendations(
                    recommendation.solution.selected_indexes, existing
                )
                for drop_sql in consolidation.indexes_to_drop:
                    # Extract index name from DROP statement
                    result.dropped_indexes.append(drop_sql)

                # Accumulate IWO
                result.total_iwo += recommendation.solution.total_write_overhead

        finally:
            await conn.close()

        result.total_time_ms = (time.perf_counter() - t0) * 1000
        return result
