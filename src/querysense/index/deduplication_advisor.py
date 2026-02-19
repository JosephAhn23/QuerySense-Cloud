"""
Deduplication-Aware Index Advisor.

PostgreSQL 13+ enables B-tree deduplication by default, which can reduce
index size by up to 3x for columns with high duplication.

This module:
1. Analyzes column statistics to estimate deduplication benefit
2. Calculates index size with and without dedup
3. Recommends indexes considering dedup savings
4. Identifies existing indexes that benefit from dedup

Based on pganalyze blog: Postgres B-Tree deduplication benchmarks.

Usage:
    from querysense.index.deduplication_advisor import DeduplicationAdvisor
    advisor = DeduplicationAdvisor()
    report = await advisor.analyze(dsn, schema="public", table="orders")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ColumnStats:
    """Statistics about a column from pg_stats."""
    name: str
    total_rows: int
    distinct_values: int
    null_count: int
    avg_width: int
    most_common_freqs: list[float] = field(default_factory=list)

    @property
    def duplication_factor(self) -> float:
        if self.distinct_values == 0:
            return float("inf") if self.total_rows > 0 else 0
        return self.total_rows / self.distinct_values

    @property
    def cardinality_type(self) -> str:
        if self.total_rows == 0:
            return "empty"
        ratio = self.distinct_values / self.total_rows
        if ratio > 0.9:
            return "high"
        elif ratio > 0.5:
            return "medium"
        elif ratio > 0.1:
            return "low"
        return "very_low"


@dataclass
class DedupSavings:
    """Deduplication savings analysis for an index."""
    columns: list[str]
    size_with_dedup_mb: float
    size_without_dedup_mb: float
    savings_mb: float
    savings_percent: float
    benefit_level: str  # critical, high, moderate, low, minimal
    duplication_factor: float


@dataclass
class DedupIndexRecommendation:
    """Index recommendation with deduplication analysis."""
    table: str
    columns: list[str]
    estimated_size_mb: float
    size_without_dedup_mb: float
    dedup_savings_percent: float
    scan_speedup: float
    write_overhead: float
    priority: int  # 1-10
    create_sql: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class DeduplicationReport:
    """Full deduplication analysis report."""
    table: str = ""
    pg_version: int = 0
    dedup_available: bool = False
    column_stats: list[ColumnStats] = field(default_factory=list)
    existing_index_savings: list[DedupSavings] = field(default_factory=list)
    recommendations: list[DedupIndexRecommendation] = field(default_factory=list)
    total_potential_savings_mb: float = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "dedup_available": self.dedup_available,
            "total_potential_savings_mb": round(self.total_potential_savings_mb, 2),
            "existing_index_savings": [
                {"columns": s.columns, "savings_mb": s.savings_mb,
                 "savings_pct": s.savings_percent, "benefit": s.benefit_level}
                for s in self.existing_index_savings
            ],
            "recommendations": [
                {"columns": r.columns, "size_mb": r.estimated_size_mb,
                 "dedup_savings_pct": r.dedup_savings_percent, "priority": r.priority}
                for r in self.recommendations
            ],
        }


class DeduplicationAdvisor:
    """
    Analyze indexes for PG13+ deduplication benefits.

    Deduplication stores each unique value once in the index leaf pages,
    with a posting list of TIDs. Benefits are highest for columns with
    low cardinality (many duplicate values).
    """

    TUPLE_OVERHEAD = 24  # bytes per index tuple
    TID_SIZE = 6  # bytes per TID pointer

    async def analyze(
        self,
        dsn: str,
        schema: str = "public",
        table: str | None = None,
    ) -> DeduplicationReport:
        """Run full deduplication analysis."""
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        report = DeduplicationReport()
        conn = await asyncpg.connect(dsn)

        try:
            # Check PG version
            ver = await conn.fetchval("SELECT current_setting('server_version_num')::int")
            report.pg_version = ver
            report.dedup_available = ver >= 130000  # PG13+

            if table:
                report.table = f"{schema}.{table}"
                await self._analyze_table(conn, schema, table, report)
            else:
                # Analyze all user tables
                tables = await conn.fetch("""
                    SELECT tablename FROM pg_tables
                    WHERE schemaname = $1
                    ORDER BY pg_relation_size(
                        quote_ident($1) || '.' || quote_ident(tablename)
                    ) DESC
                    LIMIT 30
                """, schema)
                for row in tables:
                    await self._analyze_table(conn, schema, row["tablename"], report)

            report.total_potential_savings_mb = sum(
                s.savings_mb for s in report.existing_index_savings
            )

        finally:
            await conn.close()

        return report

    async def analyze_column(
        self, conn: Any, schema: str, table: str, column: str,
    ) -> ColumnStats | None:
        """Gather statistics for a single column."""
        row = await conn.fetchrow("""
            SELECT n_distinct, null_frac, avg_width
            FROM pg_stats
            WHERE schemaname = $1 AND tablename = $2 AND attname = $3
        """, schema, table, column)

        if not row:
            return None

        total = await conn.fetchval("""
            SELECT reltuples FROM pg_class
            WHERE relname = $1 AND relnamespace = (
                SELECT oid FROM pg_namespace WHERE nspname = $2
            )
        """, table, schema)

        total = int(max(total or 0, 0))
        n_distinct = row["n_distinct"]

        if n_distinct < 0:
            distinct = int(-n_distinct * total)
        else:
            distinct = int(n_distinct)

        # Get MCV frequencies
        mcv_row = await conn.fetchrow("""
            SELECT most_common_freqs
            FROM pg_stats
            WHERE schemaname = $1 AND tablename = $2 AND attname = $3
                AND most_common_freqs IS NOT NULL
        """, schema, table, column)

        mcv_freqs: list[float] = []
        if mcv_row and mcv_row["most_common_freqs"]:
            mcv_freqs = [float(f) for f in mcv_row["most_common_freqs"]]

        return ColumnStats(
            name=column,
            total_rows=total,
            distinct_values=max(distinct, 1),
            null_count=int(row["null_frac"] * total),
            avg_width=row["avg_width"] or 8,
            most_common_freqs=mcv_freqs,
        )

    def estimate_index_size(
        self,
        stats: list[ColumnStats],
        with_deduplication: bool = True,
    ) -> float:
        """Estimate index size in MB with/without deduplication."""
        if not stats:
            return 0

        row_count = stats[0].total_rows
        column_width = sum(s.avg_width for s in stats)

        if with_deduplication and self._would_benefit(stats):
            distinct = self._estimate_distinct_combinations(stats)
            # With dedup: unique values stored once + TID posting lists
            size_bytes = (
                distinct * (column_width + self.TUPLE_OVERHEAD)
                + row_count * self.TID_SIZE
            )
        else:
            size_bytes = row_count * (column_width + self.TUPLE_OVERHEAD)

        # B-tree overhead (fill factor, internal pages ~20%)
        return (size_bytes * 1.2) / (1024 * 1024)

    def calculate_dedup_savings(
        self, stats: list[ColumnStats],
    ) -> DedupSavings:
        """Calculate storage savings from deduplication."""
        with_dedup = self.estimate_index_size(stats, True)
        without_dedup = self.estimate_index_size(stats, False)

        savings = without_dedup - with_dedup
        pct = (savings / without_dedup * 100) if without_dedup > 0 else 0

        avg_dup = sum(s.duplication_factor for s in stats) / len(stats)

        return DedupSavings(
            columns=[s.name for s in stats],
            size_with_dedup_mb=round(with_dedup, 2),
            size_without_dedup_mb=round(without_dedup, 2),
            savings_mb=round(savings, 2),
            savings_percent=round(pct, 1),
            benefit_level=self._benefit_level(pct),
            duplication_factor=round(avg_dup, 1),
        )

    # ── Internal ─────────────────────────────────────────────────────

    async def _analyze_table(
        self, conn: Any, schema: str, table: str,
        report: DeduplicationReport,
    ) -> None:
        """Analyze a single table's indexes for dedup benefits."""
        # Get existing indexes
        indexes = await conn.fetch("""
            SELECT
                i.relname AS index_name,
                pg_get_indexdef(i.oid) AS indexdef,
                pg_relation_size(i.oid) AS index_size,
                array_agg(a.attname ORDER BY x.ordinality) AS columns
            FROM pg_index ix
            JOIN pg_class i ON ix.indexrelid = i.oid
            JOIN pg_class t ON ix.indrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            CROSS JOIN LATERAL unnest(ix.indkey)
                WITH ORDINALITY AS x(attnum, ordinality)
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = x.attnum
            WHERE n.nspname = $1 AND t.relname = $2
                AND ix.indisprimary = false
            GROUP BY i.relname, i.oid
        """, schema, table)

        for idx_row in indexes:
            cols = idx_row["columns"]
            col_stats: list[ColumnStats] = []

            for col in cols:
                stats = await self.analyze_column(conn, schema, table, col)
                if stats:
                    col_stats.append(stats)
                    if stats not in report.column_stats:
                        report.column_stats.append(stats)

            if col_stats:
                savings = self.calculate_dedup_savings(col_stats)
                if savings.savings_percent > 5:
                    report.existing_index_savings.append(savings)

    def _would_benefit(self, stats: list[ColumnStats]) -> bool:
        avg_dup = sum(s.duplication_factor for s in stats) / len(stats)
        return avg_dup > 5

    def _estimate_distinct_combinations(self, stats: list[ColumnStats]) -> int:
        if not stats:
            return 0
        product = 1
        for s in stats:
            product *= s.distinct_values
        return min(product, stats[0].total_rows)

    def _benefit_level(self, savings_pct: float) -> str:
        if savings_pct > 50:
            return "critical"
        if savings_pct > 30:
            return "high"
        if savings_pct > 15:
            return "moderate"
        if savings_pct > 5:
            return "low"
        return "minimal"
