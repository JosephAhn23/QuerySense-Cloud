"""
Statistics Collector — Fetch PostgreSQL catalog data for the CP index advisor.

Collects the statistics needed for:
    - Workload classification (read/write optimized)
    - HOT update detection
    - Write overhead calculation
    - Existing index inventory

Uses read-only queries against pg_stat_user_tables, pg_stat_user_indexes,
and pg_stat_statements (if available).

Usage:
    from querysense.index.stats_collector import StatsCollector

    collector = StatsCollector(conn)
    table_stats = await collector.collect_table_stats("orders")
    existing = await collector.collect_existing_indexes("orders")
    top_queries = await collector.collect_top_queries("orders")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from querysense.index.cp_model import Index
from querysense.index.workload_classifier import TableStats


class AsyncDBConnection(Protocol):
    """Protocol for async database connections."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...
    async def execute(self, query: str, *args: Any) -> str: ...


# ------------------------------------------------------------------
# SQL queries
# ------------------------------------------------------------------

TABLE_STATS_QUERY = """
SELECT
    schemaname,
    relname,
    pg_relation_size(relid) AS table_size_bytes,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch,
    n_tup_ins,
    n_tup_upd,
    n_tup_del,
    n_tup_hot_upd,
    n_live_tup,
    n_dead_tup,
    EXTRACT(EPOCH FROM (now() - COALESCE(stats_reset, '2000-01-01'::timestamptz)))
        AS stats_reset_seconds
FROM pg_stat_user_tables
WHERE relname = $1
LIMIT 1;
"""

EXISTING_INDEXES_QUERY = """
SELECT
    ci.relname AS index_name,
    array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns,
    ix.indisunique AS is_unique,
    ix.indisprimary AS is_primary,
    am.amname AS index_type,
    pg_relation_size(ci.oid) AS index_size_bytes,
    pg_get_indexdef(ci.oid) AS definition
FROM pg_index ix
JOIN pg_class ct ON ct.oid = ix.indrelid
JOIN pg_class ci ON ci.oid = ix.indexrelid
JOIN pg_namespace n ON n.oid = ct.relnamespace
JOIN pg_am am ON am.oid = ci.relam
JOIN pg_attribute a ON a.attrelid = ct.oid AND a.attnum = ANY(ix.indkey)
WHERE ct.relname = $1
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
GROUP BY ci.relname, ix.indisunique, ix.indisprimary, am.amname, ci.oid
ORDER BY ci.relname;
"""

INDEX_USAGE_QUERY = """
SELECT
    indexrelname AS index_name,
    idx_scan AS scans,
    idx_tup_read AS tuples_read,
    idx_tup_fetch AS tuples_fetched,
    pg_relation_size(indexrelid) AS size_bytes
FROM pg_stat_user_indexes
WHERE relname = $1
ORDER BY idx_scan DESC;
"""

TOP_QUERIES_QUERY = """
SELECT
    query,
    calls,
    total_exec_time AS total_time_ms,
    mean_exec_time AS mean_time_ms,
    rows
FROM pg_stat_statements
WHERE query ILIKE $1
ORDER BY total_exec_time DESC
LIMIT $2;
"""

COLUMN_UPDATE_FREQUENCY_QUERY = """
SELECT
    attname AS column_name,
    n_distinct,
    correlation
FROM pg_stats
WHERE tablename = $1
  AND schemaname = COALESCE($2, 'public');
"""

EXTENDED_STATS_QUERY = """
SELECT
    stxname AS stat_name,
    (
        SELECT array_agg(a.attname ORDER BY a.attnum)
        FROM unnest(stxkeys) AS k(attnum)
        JOIN pg_attribute a ON a.attrelid = stxrelid AND a.attnum = k.attnum
    ) AS columns
FROM pg_statistic_ext
WHERE stxrelid = $1::regclass;
"""


@dataclass
class ExistingIndex:
    """An index that currently exists in the database."""

    name: str
    columns: list[str]
    is_unique: bool
    is_primary: bool
    index_type: str
    size_bytes: int
    definition: str
    scans: int = 0
    tuples_read: int = 0

    def to_cp_index(self) -> Index:
        """Convert to CP model Index."""
        return Index(
            id=self.name,
            name=self.name,
            columns=tuple(self.columns),
            is_existing=True,
            index_type=self.index_type,
            size_bytes=self.size_bytes,
            definition=self.definition,
        )


@dataclass
class QueryEntry:
    """A query from pg_stat_statements."""

    sql: str
    calls: int = 0
    total_time_ms: float = 0.0
    mean_time_ms: float = 0.0
    rows: int = 0

    @property
    def frequency(self) -> int:
        """Approximate calls per day (assuming stats cover ~1 day)."""
        return max(1, self.calls)


class StatsCollector:
    """
    Collect PostgreSQL statistics for the CP index advisor.

    Gathers table stats, existing indexes, and top queries for
    a target table, converting them into the formats needed by
    the workload classifier, HOT detector, and CP solver.
    """

    def __init__(self, conn: AsyncDBConnection) -> None:
        self.conn = conn

    async def collect_table_stats(
        self,
        table: str,
        schema: str = "public",
    ) -> TableStats:
        """
        Collect workload statistics for a table.

        Returns a TableStats object suitable for the workload classifier.
        """
        try:
            rows = await self.conn.fetch(TABLE_STATS_QUERY, table)
        except Exception:
            return TableStats(table_name=table, schema_name=schema)

        if not rows:
            return TableStats(table_name=table, schema_name=schema)

        r = rows[0]
        # Support both dict-like and tuple-like row access
        def _get(row: Any, key: str, idx: int, default: Any = 0) -> Any:
            if hasattr(row, key):
                return getattr(row, key) or default
            if isinstance(row, dict):
                return row.get(key, default)
            if isinstance(row, (list, tuple)) and idx < len(row):
                return row[idx] if row[idx] is not None else default
            return default

        return TableStats(
            table_name=table,
            schema_name=str(_get(r, "schemaname", 0, schema)),
            table_size_bytes=int(_get(r, "table_size_bytes", 2, 0)),
            seq_scan=int(_get(r, "seq_scan", 3, 0)),
            seq_tup_read=int(_get(r, "seq_tup_read", 4, 0)),
            idx_scan=int(_get(r, "idx_scan", 5, 0)),
            idx_tup_fetch=int(_get(r, "idx_tup_fetch", 6, 0)),
            n_tup_ins=int(_get(r, "n_tup_ins", 7, 0)),
            n_tup_upd=int(_get(r, "n_tup_upd", 8, 0)),
            n_tup_del=int(_get(r, "n_tup_del", 9, 0)),
            n_tup_hot_upd=int(_get(r, "n_tup_hot_upd", 10, 0)),
            stats_reset_seconds=float(_get(r, "stats_reset_seconds", 13, 86400.0)),
        )

    async def collect_existing_indexes(
        self, table: str
    ) -> list[ExistingIndex]:
        """Collect all existing indexes on a table."""
        try:
            rows = await self.conn.fetch(EXISTING_INDEXES_QUERY, table)
        except Exception:
            return []

        # Also get usage stats
        usage: dict[str, dict[str, int]] = {}
        try:
            usage_rows = await self.conn.fetch(INDEX_USAGE_QUERY, table)
            for ur in usage_rows:
                name = ur[0] if isinstance(ur, (list, tuple)) else getattr(ur, "index_name", "")
                scans = ur[1] if isinstance(ur, (list, tuple)) else getattr(ur, "scans", 0)
                reads = ur[2] if isinstance(ur, (list, tuple)) else getattr(ur, "tuples_read", 0)
                usage[str(name)] = {"scans": int(scans or 0), "reads": int(reads or 0)}
        except Exception:
            pass

        indexes: list[ExistingIndex] = []
        for r in rows:
            if isinstance(r, (list, tuple)):
                name, cols, unique, primary, idx_type, size, defn = r[:7]
            else:
                name = getattr(r, "index_name", "")
                cols = getattr(r, "columns", [])
                unique = getattr(r, "is_unique", False)
                primary = getattr(r, "is_primary", False)
                idx_type = getattr(r, "index_type", "btree")
                size = getattr(r, "index_size_bytes", 0)
                defn = getattr(r, "definition", "")

            u = usage.get(str(name), {})
            indexes.append(
                ExistingIndex(
                    name=str(name),
                    columns=list(cols) if cols else [],
                    is_unique=bool(unique),
                    is_primary=bool(primary),
                    index_type=str(idx_type),
                    size_bytes=int(size or 0),
                    definition=str(defn),
                    scans=u.get("scans", 0),
                    tuples_read=u.get("reads", 0),
                )
            )

        return indexes

    async def collect_top_queries(
        self,
        table: str,
        limit: int = 20,
    ) -> list[QueryEntry]:
        """
        Collect top queries touching a table from pg_stat_statements.

        Requires pg_stat_statements extension.
        """
        try:
            pattern = f"%{table}%"
            rows = await self.conn.fetch(TOP_QUERIES_QUERY, pattern, limit)
        except Exception:
            return []

        entries: list[QueryEntry] = []
        for r in rows:
            if isinstance(r, (list, tuple)):
                sql, calls, total, mean, row_count = r[:5]
            else:
                sql = getattr(r, "query", "")
                calls = getattr(r, "calls", 0)
                total = getattr(r, "total_time_ms", 0)
                mean = getattr(r, "mean_time_ms", 0)
                row_count = getattr(r, "rows", 0)

            entries.append(
                QueryEntry(
                    sql=str(sql),
                    calls=int(calls or 0),
                    total_time_ms=float(total or 0),
                    mean_time_ms=float(mean or 0),
                    rows=int(row_count or 0),
                )
            )

        return entries

    async def collect_column_update_frequencies(
        self,
        table: str,
        schema: str = "public",
    ) -> dict[str, float]:
        """
        Estimate per-column update frequency.

        Note: PostgreSQL doesn't track per-column update counts natively.
        We use correlation and n_distinct from pg_stats as proxies.
        Columns with high correlation to physical order are more likely
        to be append-only; others are more likely updated.
        """
        try:
            rows = await self.conn.fetch(COLUMN_UPDATE_FREQUENCY_QUERY, table, schema)
        except Exception:
            return {}

        # Get total update rate
        stats = await self.collect_table_stats(table, schema)
        writes_pm = stats.writes_per_minute

        frequencies: dict[str, float] = {}
        for r in rows:
            if isinstance(r, (list, tuple)):
                col_name, n_distinct, correlation = r[:3]
            else:
                col_name = getattr(r, "column_name", "")
                n_distinct = getattr(r, "n_distinct", 0)
                correlation = getattr(r, "correlation", 0)

            # Heuristic: low correlation = more likely to be updated
            corr = abs(float(correlation or 0))
            update_likelihood = 1.0 - corr  # 0=perfectly ordered, 1=random
            frequencies[str(col_name)] = writes_pm * update_likelihood * 0.3

        return frequencies

    async def collect_extended_statistics(
        self, table: str
    ) -> list[dict[str, Any]]:
        """Collect extended statistics (CREATE STATISTICS) for FD detection."""
        try:
            rows = await self.conn.fetch(EXTENDED_STATS_QUERY, table)
        except Exception:
            return []

        results: list[dict[str, Any]] = []
        for r in rows:
            if isinstance(r, (list, tuple)):
                stat_name, columns = r[:2]
            else:
                stat_name = getattr(r, "stat_name", "")
                columns = getattr(r, "columns", [])

            results.append({
                "name": str(stat_name),
                "columns": list(columns) if columns else [],
            })

        return results
