"""
Functional Dependency Detection — use pg_stats_ext for multi-column statistics.

PostgreSQL's extended statistics (CREATE STATISTICS) track functional
dependencies and multi-column correlations. When column A functionally
determines column B (e.g., zip_code → city), the planner can make much
better row estimates for queries filtering on both.

Without extended statistics, the planner assumes columns are independent,
often producing estimates that are orders of magnitude wrong.

This module:
1. Detects column pairs that likely have functional dependencies
2. Identifies queries suffering from bad multi-column estimates
3. Generates CREATE STATISTICS commands
4. Monitors existing extended statistics effectiveness

Based on pganalyze's "PostgreSQL Intelligence" functional dependency work.

Usage:
    from querysense.functional_deps import FunctionalDepDetector, FDAnalysis

    detector = FunctionalDepDetector()
    analysis = await detector.analyze(dsn="postgresql://localhost/mydb")
    for rec in analysis.recommendations:
        print(rec.create_stats_sql)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FunctionalDependency:
    """A detected functional dependency between columns."""
    table: str
    schema: str
    source_column: str  # The determining column
    dependent_column: str  # The determined column
    dependency_degree: float  # 0-1, how strong the dependency is
    distinct_source: int  # Number of distinct values in source
    distinct_dependent: int  # Number of distinct values in dependent
    row_count: int


@dataclass
class NDDistinct:
    """N-distinct correlation between a set of columns."""
    table: str
    schema: str
    columns: list[str]
    actual_ndistinct: int
    independent_estimate: int  # What planner would estimate without stats
    overestimate_ratio: float  # independent / actual (>1 = overestimate)


@dataclass
class StatsRecommendation:
    """A recommendation to create extended statistics."""
    table: str
    schema: str
    columns: list[str]
    stat_type: str  # dependencies, ndistinct, mcv
    reason: str
    estimated_improvement: str
    priority: int  # 1=highest

    @property
    def stats_name(self) -> str:
        cols = "_".join(self.columns[:3])
        return f"stats_{self.table}_{cols}"

    @property
    def create_stats_sql(self) -> str:
        col_list = ", ".join(self.columns)
        return (
            f"CREATE STATISTICS IF NOT EXISTS {self.stats_name}\n"
            f"  ({self.stat_type}) ON {col_list}\n"
            f"  FROM {self.schema}.{self.table};\n"
            f"ANALYZE {self.schema}.{self.table};"
        )


@dataclass
class ExistingStats:
    """An existing extended statistics object."""
    name: str
    schema: str
    table: str
    columns: list[str]
    stat_types: list[str]  # dependencies, ndistinct, mcv
    has_data: bool  # Has been ANALYZEd


@dataclass
class FDAnalysis:
    """Complete functional dependency analysis."""
    dependencies: list[FunctionalDependency] = field(default_factory=list)
    ndistinct_issues: list[NDDistinct] = field(default_factory=list)
    recommendations: list[StatsRecommendation] = field(default_factory=list)
    existing_stats: list[ExistingStats] = field(default_factory=list)
    tables_analyzed: int = 0

    @property
    def fix_script(self) -> str:
        lines = ["-- QuerySense Extended Statistics Script", ""]
        for rec in self.recommendations:
            lines.append(f"-- {rec.reason}")
            lines.append(rec.create_stats_sql)
            lines.append("")
        return "\n".join(lines)


class FunctionalDepDetector:
    """
    Detect functional dependencies and recommend extended statistics.

    Connects to a live database and analyzes column relationships
    to find cases where CREATE STATISTICS would improve planner estimates.
    """

    async def analyze(
        self,
        dsn: str,
        schema: str = "public",
        min_rows: int = 10000,
    ) -> FDAnalysis:
        """Run functional dependency analysis."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            analysis = FDAnalysis()

            # Check existing extended statistics
            analysis.existing_stats = await self._fetch_existing_stats(conn)

            # Get tables with enough rows to matter
            tables = await conn.fetch("""
                SELECT relname, n_live_tup
                FROM pg_stat_user_tables
                WHERE schemaname = $1 AND n_live_tup >= $2
                ORDER BY n_live_tup DESC
                LIMIT 30
            """, schema, min_rows)

            analysis.tables_analyzed = len(tables)

            for tbl_row in tables:
                table = tbl_row["relname"]
                row_count = tbl_row["n_live_tup"]

                # Detect functional dependencies via n_distinct ratios
                deps = await self._detect_dependencies(conn, table, schema, row_count)
                analysis.dependencies.extend(deps)

                # Check for n-distinct estimate issues
                nd_issues = await self._check_ndistinct(conn, table, schema, row_count)
                analysis.ndistinct_issues.extend(nd_issues)

            # Generate recommendations
            analysis.recommendations = self._generate_recommendations(analysis)

            return analysis
        finally:
            await conn.close()

    async def _fetch_existing_stats(self, conn: Any) -> list[ExistingStats]:
        """Fetch existing extended statistics objects."""
        try:
            rows = await conn.fetch("""
                SELECT
                    s.stxname,
                    n.nspname,
                    c.relname,
                    array_agg(a.attname ORDER BY a.attnum) AS columns,
                    s.stxkind::text[] AS stat_types
                FROM pg_statistic_ext s
                JOIN pg_class c ON c.oid = s.stxrelid
                JOIN pg_namespace n ON n.oid = s.stxnamespace
                JOIN pg_statistic_ext_data d ON d.stxoid = s.oid
                JOIN pg_attribute a ON a.attrelid = s.stxrelid AND a.attnum = ANY(s.stxkeys)
                GROUP BY s.stxname, n.nspname, c.relname, s.stxkind
            """)
        except Exception:
            # pg_statistic_ext_data may not exist in older PG versions
            return []

        kind_map = {"d": "dependencies", "f": "ndistinct", "m": "mcv"}

        return [
            ExistingStats(
                name=row["stxname"],
                schema=row["nspname"],
                table=row["relname"],
                columns=list(row["columns"] or []),
                stat_types=[kind_map.get(k, k) for k in (row["stat_types"] or [])],
                has_data=True,
            )
            for row in rows
        ]

    async def _detect_dependencies(
        self,
        conn: Any,
        table: str,
        schema: str,
        row_count: int,
    ) -> list[FunctionalDependency]:
        """
        Detect likely functional dependencies between columns.

        A functional dependency A → B exists when knowing A uniquely
        determines B. We detect this by comparing n_distinct values.
        """
        deps: list[FunctionalDependency] = []

        # Get column statistics
        rows = await conn.fetch("""
            SELECT
                a.attname,
                s.n_distinct,
                s.null_frac
            FROM pg_stats s
            JOIN pg_attribute a ON a.attname = s.attname AND a.attrelid = (
                SELECT oid FROM pg_class WHERE relname = $1
                AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = $2)
            )
            WHERE s.schemaname = $2
              AND s.tablename = $1
              AND a.attnum > 0
              AND NOT a.attisdropped
              AND s.n_distinct != 0
        """, table, schema)

        if len(rows) < 2:
            return deps

        # Convert n_distinct (negative means fraction of rows)
        col_stats: list[dict] = []
        for row in rows:
            nd = row["n_distinct"]
            if nd < 0:
                distinct = int(abs(nd) * row_count)
            else:
                distinct = int(nd)
            col_stats.append({
                "name": row["attname"],
                "distinct": max(distinct, 1),
                "null_frac": row["null_frac"],
            })

        # Check all pairs for functional dependency
        for i, col_a in enumerate(col_stats):
            for col_b in col_stats[i + 1:]:
                # If A has fewer distinct values than B and A's distinct ≈ B's,
                # then A → B or B → A might hold
                a_dist = col_a["distinct"]
                b_dist = col_b["distinct"]

                # A → B: if distinct(A) ≈ distinct(A, B), then A determines B
                # Heuristic: if distinct(A) ≈ distinct(B) and both << row_count
                if a_dist > 0 and b_dist > 0:
                    ratio = min(a_dist, b_dist) / max(a_dist, b_dist)

                    # If one column has very few distinct values and the other has
                    # approximately the same, it's likely a dependency
                    if ratio > 0.8 and a_dist < row_count * 0.1:
                        degree = ratio
                        if a_dist <= b_dist:
                            deps.append(FunctionalDependency(
                                table=table,
                                schema=schema,
                                source_column=col_a["name"],
                                dependent_column=col_b["name"],
                                dependency_degree=degree,
                                distinct_source=a_dist,
                                distinct_dependent=b_dist,
                                row_count=row_count,
                            ))
                        else:
                            deps.append(FunctionalDependency(
                                table=table,
                                schema=schema,
                                source_column=col_b["name"],
                                dependent_column=col_a["name"],
                                dependency_degree=degree,
                                distinct_source=b_dist,
                                distinct_dependent=a_dist,
                                row_count=row_count,
                            ))

        return deps

    async def _check_ndistinct(
        self,
        conn: Any,
        table: str,
        schema: str,
        row_count: int,
    ) -> list[NDDistinct]:
        """Check for multi-column n-distinct estimation issues."""
        issues: list[NDDistinct] = []

        # Get commonly queried column pairs from pg_stat_statements
        try:
            import re
            query_rows = await conn.fetch("""
                SELECT query, calls
                FROM pg_stat_statements
                WHERE query ~* $1
                  AND calls > 10
                ORDER BY calls DESC
                LIMIT 50
            """, f"FROM\\s+.*{table}")
        except Exception:
            return issues

        # Extract WHERE column pairs
        for qrow in query_rows:
            query = qrow["query"].upper()
            # Find multi-column WHERE conditions
            where_match = re.search(r"WHERE\s+(.*?)(?:GROUP|ORDER|LIMIT|$)", query, re.DOTALL)
            if not where_match:
                continue

            where_clause = where_match.group(1)
            # Extract column names from conditions
            cols = re.findall(r"(\w+)\s*(?:=|IN|>|<|>=|<=)", where_clause)
            cols = [c.lower() for c in cols
                    if c.upper() not in ("AND", "OR", "NOT", "NULL", "TRUE", "FALSE", "SELECT")]

            if len(cols) >= 2:
                # This query filters on multiple columns — might benefit from extended stats
                issues.append(NDDistinct(
                    table=table,
                    schema=schema,
                    columns=cols[:4],  # Limit to 4 columns
                    actual_ndistinct=0,  # Would need actual count
                    independent_estimate=0,
                    overestimate_ratio=0,
                ))

        return issues

    def _generate_recommendations(self, analysis: FDAnalysis) -> list[StatsRecommendation]:
        """Generate CREATE STATISTICS recommendations."""
        recs: list[StatsRecommendation] = []
        seen: set[str] = set()

        # From functional dependencies
        for dep in analysis.dependencies:
            key = f"{dep.table}_{dep.source_column}_{dep.dependent_column}"
            if key in seen:
                continue
            seen.add(key)

            recs.append(StatsRecommendation(
                table=dep.table,
                schema=dep.schema,
                columns=[dep.source_column, dep.dependent_column],
                stat_type="dependencies",
                reason=(
                    f"{dep.source_column} → {dep.dependent_column} "
                    f"(degree: {dep.dependency_degree:.0%}, "
                    f"{dep.distinct_source} → {dep.distinct_dependent} distinct values)"
                ),
                estimated_improvement="Row estimates could improve 10-100x for multi-column filters",
                priority=1,
            ))

        # From n-distinct issues
        for nd in analysis.ndistinct_issues:
            key = f"{nd.table}_{'_'.join(sorted(nd.columns))}"
            if key in seen:
                continue
            seen.add(key)

            # Check if existing stats already cover these columns
            already_covered = any(
                set(nd.columns).issubset(set(es.columns))
                for es in analysis.existing_stats
                if es.table == nd.table
            )
            if already_covered:
                continue

            recs.append(StatsRecommendation(
                table=nd.table,
                schema=nd.schema,
                columns=nd.columns,
                stat_type="ndistinct, dependencies",
                reason=f"Multi-column filter on ({', '.join(nd.columns)}) — planner assumes independence",
                estimated_improvement="Better cardinality estimates for multi-column WHERE clauses",
                priority=2,
            ))

        recs.sort(key=lambda r: r.priority)
        return recs
