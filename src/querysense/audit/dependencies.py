"""
Focused Column Dependency Detector — per-column-pair correlation analysis.

Detects functional dependencies between specific columns by sampling actual
data and measuring correlation. Generates CREATE STATISTICS commands to fix
planner estimation errors caused by assumed independence.

Based on pganalyze "Best Practices for Optimizing Postgres Query Performance"
(p.6-7): The 20,000% improvement example from fixing correlated column estimates.

Unlike the schema-wide scan in functional_deps.py, this module focuses on
user-specified column pairs for targeted analysis.

Usage:
    from querysense.audit.dependencies import ColumnDependencyDetector

    detector = ColumnDependencyDetector()
    result = await detector.analyze(dsn, "orders", ["user_id", "status"])
    print(result.explanation)
    print(result.create_stats_sql)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ColumnPairAnalysis:
    """Analysis of dependency between two columns."""

    col_a: str = ""
    col_b: str = ""
    distinct_a: int = 0
    distinct_b: int = 0
    distinct_combined: int = 0
    independent_estimate: int = 0  # distinct_a * distinct_b
    overestimate_ratio: float = 0.0  # independent / actual
    dependency_degree: float = 0.0  # 0-1, how strong
    top_combinations: list[dict[str, Any]] = field(default_factory=list)
    is_functionally_dependent: bool = False

    @property
    def has_correlation(self) -> bool:
        return self.overestimate_ratio > 2.0

    @property
    def severity(self) -> str:
        if self.overestimate_ratio > 100:
            return "CRITICAL"
        if self.overestimate_ratio > 10:
            return "HIGH"
        if self.overestimate_ratio > 2:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "col_a": self.col_a,
            "col_b": self.col_b,
            "distinct_a": self.distinct_a,
            "distinct_b": self.distinct_b,
            "distinct_combined": self.distinct_combined,
            "independent_estimate": self.independent_estimate,
            "overestimate_ratio": round(self.overestimate_ratio, 1),
            "dependency_degree": round(self.dependency_degree, 2),
            "top_combinations": self.top_combinations,
            "is_functionally_dependent": self.is_functionally_dependent,
            "has_correlation": self.has_correlation,
            "severity": self.severity,
        }


@dataclass
class DependencyReport:
    """Full dependency analysis report for a table."""

    table: str = ""
    schema: str = "public"
    columns: list[str] = field(default_factory=list)
    row_count: int = 0
    sample_size: int = 0
    pair_analyses: list[ColumnPairAnalysis] = field(default_factory=list)
    existing_stats: list[str] = field(default_factory=list)

    @property
    def has_correlations(self) -> bool:
        return any(p.has_correlation for p in self.pair_analyses)

    @property
    def create_stats_sql(self) -> str:
        """Generate CREATE STATISTICS for correlated column pairs."""
        if not self.has_correlations:
            return "-- No significant correlations detected"

        correlated = [p for p in self.pair_analyses if p.has_correlation]
        all_cols = set()
        for p in correlated:
            all_cols.add(p.col_a)
            all_cols.add(p.col_b)

        cols_str = ", ".join(sorted(all_cols))
        stat_name = f"st_{self.table}_{'_'.join(sorted(all_cols)[:3])}"

        lines = [
            f"-- Column dependency detected: estimation errors up to "
            f"{max(p.overestimate_ratio for p in correlated):.0f}x",
            f"CREATE STATISTICS IF NOT EXISTS {stat_name}",
            f"    (dependencies, ndistinct, mcv)",
            f"    ON {cols_str}",
            f"    FROM {self.schema}.{self.table};",
            "",
            f"ANALYZE {self.schema}.{self.table};",
        ]
        return "\n".join(lines)

    @property
    def explanation(self) -> str:
        """Full educational explanation."""
        sections: list[str] = []
        fqn = f"{self.schema}.{self.table}" if self.schema != "public" else self.table

        sections.append(f"COLUMN DEPENDENCY ANALYSIS")
        sections.append("=" * 60)
        sections.append(f"Table: {fqn} ({self.row_count:,} rows)")
        sections.append(f"Columns: {', '.join(self.columns)}")
        sections.append(f"Sample: {self.sample_size:,} rows")
        sections.append("")

        for pair in self.pair_analyses:
            if pair.has_correlation:
                sections.append(f"CORRELATION DETECTED: {pair.col_a} <-> {pair.col_b}")
                sections.append(f"  Distinct values: {pair.col_a}={pair.distinct_a:,}, "
                                f"{pair.col_b}={pair.distinct_b:,}")
                sections.append(f"  Combined distinct: {pair.distinct_combined:,}")
                sections.append(f"  Independent estimate: {pair.independent_estimate:,} "
                                f"({pair.overestimate_ratio:.0f}x overestimate)")
                sections.append(f"  Dependency degree: {pair.dependency_degree:.0%}")
                sections.append("")

                if pair.is_functionally_dependent:
                    sections.append(f"  FUNCTIONAL DEPENDENCY: {pair.col_a} -> {pair.col_b}")
                    sections.append(f"  Every {pair.col_a} value maps to exactly one {pair.col_b} value.")
                    sections.append("")

                if pair.top_combinations:
                    sections.append("  Top value combinations:")
                    for combo in pair.top_combinations[:5]:
                        sections.append(f"    {pair.col_a}={combo['a']}, "
                                        f"{pair.col_b}={combo['b']}: "
                                        f"{combo['count']:,} rows ({combo['pct']:.1f}%)")
                    sections.append("")

                sections.append(f"  Impact: The planner assumes independence between these")
                sections.append(f"  columns, producing row estimates that are {pair.overestimate_ratio:.0f}x wrong.")
                sections.append(f"  This causes wrong join strategies (nested loops instead of hash),")
                sections.append(f"  wrong index choices, and up to {pair.overestimate_ratio * 10:.0f}x slower queries.")
                sections.append("")
            else:
                sections.append(f"OK: {pair.col_a} <-> {pair.col_b} "
                                f"(ratio: {pair.overestimate_ratio:.1f}x — independent enough)")
                sections.append("")

        if self.has_correlations:
            sections.append("RECOMMENDATION")
            sections.append("-" * 40)
            sections.append(self.create_stats_sql)
            sections.append("")
            sections.append("EXPECTED IMPROVEMENT")
            sections.append("-" * 40)
            sections.append("  Join cardinality estimates: much more accurate")
            sections.append("  Query planning: more likely to choose optimal join strategies")
            max_ratio = max(p.overestimate_ratio for p in self.pair_analyses if p.has_correlation)
            sections.append(f"  Potential speedup: up to {max_ratio:.0f}x for affected queries")

        if self.existing_stats:
            sections.append("")
            sections.append("EXISTING EXTENDED STATISTICS")
            for stat in self.existing_stats:
                sections.append(f"  {stat}")

        return "\n".join(sections)

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "schema": self.schema,
            "columns": self.columns,
            "row_count": self.row_count,
            "sample_size": self.sample_size,
            "pair_analyses": [p.to_dict() for p in self.pair_analyses],
            "existing_stats": self.existing_stats,
            "has_correlations": self.has_correlations,
            "create_stats_sql": self.create_stats_sql,
            "explanation": self.explanation,
        }


class ColumnDependencyDetector:
    """
    Detect functional dependencies between specific columns.

    Uses data sampling + statistics comparison to identify when
    the planner's independence assumption is wrong.
    """

    def __init__(self, sample_size: int = 10000) -> None:
        self.sample_size = sample_size

    async def analyze(
        self,
        dsn: str,
        table: str,
        columns: list[str],
        schema: str = "public",
    ) -> DependencyReport:
        """Analyze dependencies between specified columns."""
        import asyncpg

        conn = await asyncpg.connect(dsn)
        try:
            report = DependencyReport(
                table=table, schema=schema, columns=columns,
            )

            # Get row count
            row_count = await conn.fetchval(
                f"SELECT reltuples::bigint FROM pg_class "
                f"WHERE relname = $1",
                table,
            )
            report.row_count = int(row_count or 0)
            report.sample_size = min(self.sample_size, report.row_count)

            # Analyze each column pair
            for i, col_a in enumerate(columns):
                for col_b in columns[i + 1:]:
                    pair = await self._analyze_pair(conn, schema, table, col_a, col_b)
                    report.pair_analyses.append(pair)

            # Check for existing extended statistics
            try:
                existing = await conn.fetch(
                    "SELECT stxname FROM pg_statistic_ext "
                    "WHERE stxrelid = $1::regclass",
                    f"{schema}.{table}",
                )
                report.existing_stats = [r["stxname"] for r in existing]
            except Exception:
                pass

            return report
        finally:
            await conn.close()

    async def _analyze_pair(
        self,
        conn: Any,
        schema: str,
        table: str,
        col_a: str,
        col_b: str,
    ) -> ColumnPairAnalysis:
        """Analyze dependency between two columns."""
        fqn = f"{schema}.{table}"
        result = ColumnPairAnalysis(col_a=col_a, col_b=col_b)

        try:
            # Get distinct counts
            stats = await conn.fetchrow(f"""
                SELECT
                    (SELECT COUNT(DISTINCT {col_a}) FROM {fqn}) AS distinct_a,
                    (SELECT COUNT(DISTINCT {col_b}) FROM {fqn}) AS distinct_b,
                    (SELECT COUNT(DISTINCT ({col_a}, {col_b})) FROM {fqn}) AS distinct_combined
            """)

            result.distinct_a = int(stats["distinct_a"] or 0)
            result.distinct_b = int(stats["distinct_b"] or 0)
            result.distinct_combined = int(stats["distinct_combined"] or 0)

            # Independence estimate: distinct_a * distinct_b
            result.independent_estimate = result.distinct_a * result.distinct_b

            # Overestimate ratio
            if result.distinct_combined > 0:
                result.overestimate_ratio = (
                    result.independent_estimate / result.distinct_combined
                )
            else:
                result.overestimate_ratio = 1.0

            # Dependency degree: 1 - (actual / independent)
            if result.independent_estimate > 0:
                result.dependency_degree = max(
                    0, 1 - (result.distinct_combined / result.independent_estimate)
                )

            # Check for functional dependency (A -> B)
            if result.distinct_combined == result.distinct_a:
                result.is_functionally_dependent = True

            # Get top value combinations
            combos = await conn.fetch(f"""
                SELECT {col_a} AS a, {col_b} AS b, COUNT(*) AS cnt
                FROM {fqn}
                GROUP BY {col_a}, {col_b}
                ORDER BY cnt DESC
                LIMIT 10
            """)

            row_count_val = await conn.fetchval(f"SELECT COUNT(*) FROM {fqn}")
            total = int(row_count_val or 1)

            result.top_combinations = [
                {
                    "a": str(r["a"]),
                    "b": str(r["b"]),
                    "count": int(r["cnt"]),
                    "pct": int(r["cnt"]) / total * 100,
                }
                for r in combos
            ]

        except Exception as e:
            logger.warning("Failed to analyze pair %s/%s: %s", col_a, col_b, e)

        return result
