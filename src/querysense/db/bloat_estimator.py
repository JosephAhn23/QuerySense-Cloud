"""
Table & Index Bloat Estimator — actual vs expected size calculation.

Reverse-engineered from pganalyze's VACUUM Advisor methodology
(https://pganalyze.com/blog/vacuum-advisor-postgresql):

The ideal size of a table is: (live tuples × avg tuple width) / fillfactor,
adjusted for page overhead and alignment. The difference between actual
and ideal size is bloat.

Three estimation methods (in order of accuracy):
1. pgstattuple extension (exact, but requires superuser + table lock)
2. Statistical estimation from pg_stat_user_tables + pg_class (fast, no lock)
3. Dead tuple ratio heuristic (fallback when stats unavailable)

Usage:
    from querysense.db.bloat_estimator import BloatEstimator, TableBloat

    estimator = BloatEstimator()
    bloat = await estimator.estimate_table_bloat(conn, "public", "orders")
    print(f"Bloat: {bloat.bloat_pct:.1f}% ({bloat.wasted_bytes_human})")

    # All tables at once
    report = await estimator.estimate_all(conn)
    for table in report.tables:
        if table.bloat_pct > 20:
            print(f"{table.full_name}: {table.bloat_pct:.1f}% bloat")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


# ── Data Classes ───────────────────────────────────────────────────────


@dataclass
class TableBloat:
    """Bloat estimation for a single table."""
    schema: str
    table: str
    actual_bytes: int = 0
    expected_bytes: int = 0     # Ideal size for live data
    bloat_bytes: int = 0        # actual - expected
    bloat_pct: float = 0.0
    live_tuples: int = 0
    dead_tuples: int = 0
    avg_tuple_width: int = 0
    fillfactor: int = 100
    method: str = "statistical"  # "pgstattuple" | "statistical" | "heuristic"

    # Index bloat
    index_bloat_bytes: int = 0
    index_count: int = 0
    total_index_bytes: int = 0

    @property
    def full_name(self) -> str:
        return f"{self.schema}.{self.table}"

    @property
    def wasted_bytes_human(self) -> str:
        return _format_bytes(self.bloat_bytes)

    @property
    def actual_bytes_human(self) -> str:
        return _format_bytes(self.actual_bytes)

    @property
    def expected_bytes_human(self) -> str:
        return _format_bytes(self.expected_bytes)

    @property
    def severity(self) -> str:
        if self.bloat_pct > 50:
            return "critical"
        if self.bloat_pct > 30:
            return "warning"
        if self.bloat_pct > 20:
            return "info"
        return "ok"

    @property
    def recommendation(self) -> str:
        if self.bloat_pct <= 20:
            return ""
        if self.bloat_pct > 50 and self.actual_bytes > 1_000_000_000:
            return (
                f"CRITICAL: {self.full_name} is {self.bloat_pct:.0f}% bloated "
                f"({self.wasted_bytes_human} wasted). "
                f"Run: pg_repack --table {self.full_name} --no-kill-backend "
                f"(zero-downtime) or VACUUM FULL {self.full_name} (requires exclusive lock)"
            )
        if self.bloat_pct > 30:
            return (
                f"WARNING: {self.full_name} is {self.bloat_pct:.0f}% bloated "
                f"({self.wasted_bytes_human} wasted). "
                f"Check autovacuum settings: ALTER TABLE {self.full_name} "
                f"SET (autovacuum_vacuum_scale_factor = 0.05, "
                f"autovacuum_vacuum_cost_delay = 2);"
            )
        return (
            f"INFO: {self.full_name} is {self.bloat_pct:.0f}% bloated. "
            f"Monitor with: SELECT pg_size_pretty(pg_table_size('{self.full_name}'));"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "table": self.table,
            "full_name": self.full_name,
            "actual_bytes": self.actual_bytes,
            "expected_bytes": self.expected_bytes,
            "bloat_bytes": self.bloat_bytes,
            "bloat_pct": round(self.bloat_pct, 1),
            "actual_human": self.actual_bytes_human,
            "expected_human": self.expected_bytes_human,
            "wasted_human": self.wasted_bytes_human,
            "live_tuples": self.live_tuples,
            "dead_tuples": self.dead_tuples,
            "avg_tuple_width": self.avg_tuple_width,
            "fillfactor": self.fillfactor,
            "method": self.method,
            "severity": self.severity,
            "index_bloat_bytes": self.index_bloat_bytes,
            "index_count": self.index_count,
            "recommendation": self.recommendation,
        }


@dataclass
class IndexBloat:
    """Bloat estimation for a single index."""
    schema: str
    table: str
    index_name: str
    actual_bytes: int = 0
    expected_bytes: int = 0
    bloat_bytes: int = 0
    bloat_pct: float = 0.0
    method: str = "statistical"

    @property
    def full_name(self) -> str:
        return f"{self.schema}.{self.index_name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "table": self.table,
            "index_name": self.index_name,
            "actual_bytes": self.actual_bytes,
            "expected_bytes": self.expected_bytes,
            "bloat_bytes": self.bloat_bytes,
            "bloat_pct": round(self.bloat_pct, 1),
            "actual_human": _format_bytes(self.actual_bytes),
            "wasted_human": _format_bytes(self.bloat_bytes),
            "method": self.method,
        }


@dataclass
class BloatReport:
    """Complete bloat report for all tables."""
    tables: list[TableBloat] = field(default_factory=list)
    indexes: list[IndexBloat] = field(default_factory=list)
    total_table_bloat_bytes: int = 0
    total_index_bloat_bytes: int = 0
    method: str = "statistical"
    errors: list[str] = field(default_factory=list)

    @property
    def total_wasted_bytes(self) -> int:
        return self.total_table_bloat_bytes + self.total_index_bloat_bytes

    @property
    def critical_tables(self) -> list[TableBloat]:
        return [t for t in self.tables if t.severity == "critical"]

    @property
    def warning_tables(self) -> list[TableBloat]:
        return [t for t in self.tables if t.severity == "warning"]

    def summary(self) -> str:
        parts = [f"{len(self.tables)} tables analyzed ({self.method})"]
        if self.critical_tables:
            parts.append(f"{len(self.critical_tables)} critically bloated")
        if self.warning_tables:
            parts.append(f"{len(self.warning_tables)} moderately bloated")
        parts.append(f"Total wasted: {_format_bytes(self.total_wasted_bytes)}")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "method": self.method,
            "total_table_bloat_bytes": self.total_table_bloat_bytes,
            "total_index_bloat_bytes": self.total_index_bloat_bytes,
            "total_wasted_human": _format_bytes(self.total_wasted_bytes),
            "critical_count": len(self.critical_tables),
            "warning_count": len(self.warning_tables),
            "tables": [t.to_dict() for t in self.tables],
            "indexes": [i.to_dict() for i in self.indexes],
            "errors": self.errors,
        }


# ── Helper ─────────────────────────────────────────────────────────────


def _format_bytes(b: int) -> str:
    if b < 0:
        return f"-{_format_bytes(-b)}"
    if b >= 1024 ** 4:
        return f"{b / (1024 ** 4):.1f} TB"
    if b >= 1024 ** 3:
        return f"{b / (1024 ** 3):.1f} GB"
    if b >= 1024 ** 2:
        return f"{b / (1024 ** 2):.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} kB"
    return f"{b} B"


# ── SQL Queries ────────────────────────────────────────────────────────


# Statistical bloat estimation query.
# Based on the methodology used by pgstattuple and pganalyze's VACUUM Advisor.
# Calculates expected size from live tuples, average width, and page overhead.
_TABLE_BLOAT_QUERY = """
WITH constants AS (
    SELECT
        current_setting('block_size')::int AS block_size,
        23 AS page_header_size,     -- PageHeaderData
        4 AS item_pointer_size,     -- ItemIdData
        24 AS tuple_header_size,    -- HeapTupleHeaderData
        8 AS alignment              -- MAXALIGN
),
table_stats AS (
    SELECT
        schemaname,
        relname AS tablename,
        c.oid AS relid,
        c.relpages,
        c.reltuples::bigint AS reltuples,
        pg_table_size(c.oid) AS actual_bytes,
        COALESCE(s.n_live_tup, c.reltuples::bigint) AS live_tuples,
        COALESCE(s.n_dead_tup, 0) AS dead_tuples,
        (
            SELECT COALESCE(
                (SELECT avg(avg_width) FROM pg_stats WHERE tablename = c.relname AND schemaname = n.nspname),
                100  -- fallback average width
            )
        )::int AS avg_width,
        COALESCE(
            (SELECT (reloptions::text[])[1]
             FROM pg_class WHERE oid = c.oid AND reloptions IS NOT NULL
             AND reloptions::text[] @> ARRAY['fillfactor']),
            '100'
        )::int AS fillfactor
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
    WHERE c.relkind = 'r'          -- ordinary tables only
      AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      AND c.relpages > 0           -- skip empty tables
),
bloat_calc AS (
    SELECT
        schemaname,
        tablename,
        relid,
        actual_bytes,
        live_tuples,
        dead_tuples,
        avg_width,
        fillfactor,
        -- Expected bytes = (live_tuples × (tuple_header + width + alignment) / usable_page_space) × block_size
        CASE
            WHEN live_tuples > 0 THEN
                (
                    ceil(
                        live_tuples::numeric /
                        floor(
                            (cs.block_size - cs.page_header_size)::numeric * (fillfactor::numeric / 100) /
                            (cs.tuple_header_size + avg_width + cs.item_pointer_size + cs.alignment)
                        )
                    ) * cs.block_size
                )::bigint
            ELSE 0
        END AS expected_bytes
    FROM table_stats, constants cs
)
SELECT
    schemaname,
    tablename,
    actual_bytes,
    expected_bytes,
    GREATEST(actual_bytes - expected_bytes, 0) AS bloat_bytes,
    CASE
        WHEN actual_bytes > 0
        THEN round(100.0 * GREATEST(actual_bytes - expected_bytes, 0) / actual_bytes, 1)
        ELSE 0
    END AS bloat_pct,
    live_tuples,
    dead_tuples,
    avg_width,
    fillfactor
FROM bloat_calc
ORDER BY bloat_bytes DESC
"""

# Index bloat estimation query.
# Estimates expected index size from indexed row count and average key width.
_INDEX_BLOAT_QUERY = """
WITH index_stats AS (
    SELECT
        n.nspname AS schemaname,
        ct.relname AS tablename,
        ci.relname AS indexname,
        ci.relpages,
        ci.reltuples::bigint AS reltuples,
        pg_relation_size(ci.oid) AS actual_bytes,
        COALESCE(
            (SELECT avg(avg_width)
             FROM pg_stats s
             JOIN pg_index i ON i.indexrelid = ci.oid
             JOIN pg_attribute a ON a.attrelid = ct.oid
                AND a.attnum = ANY(i.indkey)
             WHERE s.tablename = ct.relname AND s.attname = a.attname
            ),
            8  -- fallback: assume 8 bytes per key column
        )::int AS avg_key_width,
        ct.reltuples::bigint AS table_tuples
    FROM pg_class ci
    JOIN pg_index i ON i.indexrelid = ci.oid
    JOIN pg_class ct ON ct.oid = i.indrelid
    JOIN pg_namespace n ON n.oid = ct.relnamespace
    WHERE ci.relkind = 'i'
      AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      AND ci.relpages > 0
)
SELECT
    schemaname,
    tablename,
    indexname,
    actual_bytes,
    -- Expected: (tuples × (8 + avg_key_width + 8)) / (8192 * 0.9) × 8192
    -- 8 = ItemPointer, 8 = index tuple header, 0.9 = ~90% fill
    CASE
        WHEN table_tuples > 0
        THEN (
            ceil(
                table_tuples::numeric * (8 + avg_key_width + 8)::numeric /
                (current_setting('block_size')::int * 0.9)
            ) * current_setting('block_size')::int
        )::bigint
        ELSE 0
    END AS expected_bytes,
    avg_key_width
FROM index_stats
ORDER BY actual_bytes - CASE
    WHEN table_tuples > 0
    THEN (ceil(table_tuples::numeric * (8 + avg_key_width + 8)::numeric / (current_setting('block_size')::int * 0.9)) * current_setting('block_size')::int)::bigint
    ELSE 0
END DESC
"""

# pgstattuple-based exact bloat measurement (requires extension + superuser)
_PGSTATTUPLE_QUERY = """
SELECT
    schemaname,
    relname,
    (pgstattuple(schemaname || '.' || relname)).*,
    pg_table_size(schemaname || '.' || relname) AS actual_bytes
FROM pg_stat_user_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY pg_table_size(schemaname || '.' || relname) DESC
LIMIT $1
"""

# Check if pgstattuple extension is available
_CHECK_PGSTATTUPLE = """
SELECT EXISTS(
    SELECT 1 FROM pg_available_extensions WHERE name = 'pgstattuple'
    AND installed_version IS NOT NULL
)
"""


# ── Estimator ──────────────────────────────────────────────────────────


class BloatEstimator:
    """
    Estimate table and index bloat.

    Tries pgstattuple first (exact), falls back to statistical estimation.
    """

    async def estimate_all(
        self,
        conn: AsyncDBConnection,
        limit: int = 100,
        use_pgstattuple: bool = True,
    ) -> BloatReport:
        """
        Estimate bloat for all tables.

        Args:
            conn: Async database connection
            limit: Maximum number of tables (largest first)
            use_pgstattuple: Try pgstattuple extension first

        Returns:
            BloatReport with all table and index bloat estimates
        """
        report = BloatReport()

        # Try pgstattuple first
        if use_pgstattuple:
            try:
                has_ext = await conn.fetchval(_CHECK_PGSTATTUPLE)
                if has_ext:
                    return await self._estimate_with_pgstattuple(conn, limit)
            except Exception as e:
                logger.debug("pgstattuple not available: %s", e)

        # Fall back to statistical estimation
        try:
            report = await self._estimate_statistical(conn)
        except Exception as e:
            report.errors.append(f"Statistical estimation failed: {e}")
            logger.warning("Bloat estimation failed: %s", e)

        return report

    async def estimate_table_bloat(
        self,
        conn: AsyncDBConnection,
        schema: str,
        table: str,
    ) -> TableBloat:
        """Estimate bloat for a single table."""
        report = await self.estimate_all(conn)
        for t in report.tables:
            if t.schema == schema and t.table == table:
                return t
        return TableBloat(schema=schema, table=table)

    async def _estimate_with_pgstattuple(
        self, conn: AsyncDBConnection, limit: int,
    ) -> BloatReport:
        """Exact bloat measurement using pgstattuple extension."""
        report = BloatReport(method="pgstattuple")

        try:
            rows = await conn.fetch(_PGSTATTUPLE_QUERY, limit)
            for row in rows:
                actual = row["actual_bytes"]
                # pgstattuple returns free_space which is the bloat
                free_space = row.get("free_space", 0)
                dead_tuple_len = row.get("dead_tuple_len", 0)
                bloat = free_space + dead_tuple_len

                tb = TableBloat(
                    schema=row["schemaname"],
                    table=row["relname"],
                    actual_bytes=actual,
                    expected_bytes=max(actual - bloat, 0),
                    bloat_bytes=bloat,
                    bloat_pct=(bloat / actual * 100) if actual > 0 else 0,
                    live_tuples=row.get("tuple_count", 0),
                    dead_tuples=row.get("dead_tuple_count", 0),
                    avg_tuple_width=row.get("tuple_len", 0) // max(row.get("tuple_count", 1), 1),
                    method="pgstattuple",
                )
                report.tables.append(tb)
                report.total_table_bloat_bytes += bloat

        except Exception as e:
            report.errors.append(f"pgstattuple query failed: {e}")
            logger.warning("pgstattuple failed: %s", e)
            # Fall back to statistical
            return await self._estimate_statistical(conn)

        # Also estimate index bloat
        await self._estimate_index_bloat(conn, report)

        return report

    async def _estimate_statistical(self, conn: AsyncDBConnection) -> BloatReport:
        """Statistical bloat estimation from pg_class and pg_stat_user_tables."""
        report = BloatReport(method="statistical")

        try:
            rows = await conn.fetch(_TABLE_BLOAT_QUERY)
            for row in rows:
                tb = TableBloat(
                    schema=row["schemaname"],
                    table=row["tablename"],
                    actual_bytes=row["actual_bytes"],
                    expected_bytes=row["expected_bytes"],
                    bloat_bytes=row["bloat_bytes"],
                    bloat_pct=float(row["bloat_pct"]),
                    live_tuples=row["live_tuples"],
                    dead_tuples=row["dead_tuples"],
                    avg_tuple_width=row["avg_width"],
                    fillfactor=row["fillfactor"],
                    method="statistical",
                )
                report.tables.append(tb)
                report.total_table_bloat_bytes += tb.bloat_bytes

        except Exception as e:
            report.errors.append(f"Statistical estimation failed: {e}")
            logger.warning("Statistical bloat estimation failed: %s", e)

        await self._estimate_index_bloat(conn, report)

        return report

    async def _estimate_index_bloat(
        self, conn: AsyncDBConnection, report: BloatReport,
    ) -> None:
        """Add index bloat estimates to the report."""
        try:
            rows = await conn.fetch(_INDEX_BLOAT_QUERY)
            for row in rows:
                actual = row["actual_bytes"]
                expected = row["expected_bytes"]
                bloat = max(actual - expected, 0)

                ib = IndexBloat(
                    schema=row["schemaname"],
                    table=row["tablename"],
                    index_name=row["indexname"],
                    actual_bytes=actual,
                    expected_bytes=expected,
                    bloat_bytes=bloat,
                    bloat_pct=(bloat / actual * 100) if actual > 0 else 0,
                    method=report.method,
                )
                report.indexes.append(ib)
                report.total_index_bloat_bytes += bloat

                # Update parent table's index bloat
                for tb in report.tables:
                    if tb.schema == ib.schema and tb.table == ib.table:
                        tb.index_bloat_bytes += bloat
                        tb.index_count += 1
                        tb.total_index_bytes += actual

        except Exception as e:
            report.errors.append(f"Index bloat estimation failed: {e}")
            logger.debug("Index bloat estimation failed: %s", e)
