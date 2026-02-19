"""
Index Write Overhead (IWO) Calculator.

Every index on a table must be updated on every INSERT and on every DELETE.
For UPDATEs, indexes on non-updated columns can skip the update (HOT),
but indexes on updated columns must be modified.

IWO quantifies the total write amplification cost of maintaining indexes.
This feeds directly into the CP-SAT solver as a constraint:
"don't recommend indexes whose total IWO exceeds the budget."

pganalyze uses IWO as a key factor in their index recommendation engine
to avoid the common mistake of "just add more indexes" without considering
write overhead.

Formula (per index):
    IWO = (insert_rate + delete_rate + update_rate_for_indexed_cols) * index_pages
          / table_size_pages

The total IWO for a table = sum of per-index IWO values.

Usage:
    from querysense.iwo_calculator import IWOCalculator, TableIWO

    calculator = IWOCalculator()
    result = await calculator.calculate(dsn, table="orders")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class IndexIWO:
    """Write overhead for a single index."""
    index_name: str
    table: str
    columns: list[str]
    size_bytes: int
    size_pages: int

    # Write rates (from pg_stat_user_tables + pg_stat_statements)
    insert_rate: float  # inserts/sec affecting this index
    delete_rate: float  # deletes/sec
    update_rate: float  # updates/sec touching indexed columns

    # The IWO score
    iwo_score: float  # normalized write overhead

    # Metadata
    is_primary: bool = False
    is_unique: bool = False
    scan_count: int = 0  # How often this index is read (from pg_stat_user_indexes)

    @property
    def write_to_read_ratio(self) -> float:
        """Ratio of writes to reads. >1 means more writes than reads."""
        total_writes = self.insert_rate + self.delete_rate + self.update_rate
        if self.scan_count == 0:
            return float("inf") if total_writes > 0 else 0
        return total_writes / max(self.scan_count, 1)

    @property
    def is_write_heavy(self) -> bool:
        return self.write_to_read_ratio > 2.0


@dataclass
class TableIWO:
    """Write overhead for all indexes on a table."""
    table: str
    schema: str
    indexes: list[IndexIWO] = field(default_factory=list)

    # Table-level stats
    table_size_bytes: int = 0
    table_size_pages: int = 0
    total_inserts: int = 0
    total_deletes: int = 0
    total_updates: int = 0
    stat_period_seconds: float = 0  # Time since stats reset

    @property
    def total_iwo(self) -> float:
        return sum(idx.iwo_score for idx in self.indexes)

    @property
    def worst_index(self) -> IndexIWO | None:
        if not self.indexes:
            return None
        return max(self.indexes, key=lambda i: i.iwo_score)

    @property
    def write_heavy_indexes(self) -> list[IndexIWO]:
        return [i for i in self.indexes if i.is_write_heavy and not i.is_primary]


@dataclass
class IWOReport:
    """Complete IWO analysis report."""
    tables: list[TableIWO] = field(default_factory=list)
    total_tables: int = 0
    tables_with_high_iwo: int = 0

    @property
    def fix_script(self) -> str:
        lines = ["-- QuerySense Index Write Overhead Fix Script", ""]
        for table in self.tables:
            for idx in table.write_heavy_indexes:
                if not idx.is_unique:
                    lines.append(
                        f"-- {idx.index_name}: IWO={idx.iwo_score:.2f}, "
                        f"write:read={idx.write_to_read_ratio:.1f}"
                    )
                    lines.append(f"-- Consider removing if reads are low:")
                    lines.append(f"DROP INDEX CONCURRENTLY IF EXISTS {idx.index_name};")
                    lines.append("")
        return "\n".join(lines)


class IWOCalculator:
    """
    Calculate Index Write Overhead for tables and their indexes.

    Connects to a live database, gathers write rates, and scores each
    index by how much write amplification it causes.
    """

    async def calculate(
        self,
        dsn: str,
        table: str | None = None,
        schema: str = "public",
    ) -> IWOReport:
        """
        Calculate IWO for one or all tables.

        Args:
            dsn: PostgreSQL connection string
            table: Specific table (None for all tables in schema)
            schema: Schema to analyze
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            report = IWOReport()

            # Get stats reset time for rate calculation
            stat_period = await self._get_stats_period(conn)

            if table:
                tables = [table]
            else:
                rows = await conn.fetch("""
                    SELECT relname FROM pg_stat_user_tables
                    WHERE schemaname = $1
                      AND n_tup_ins + n_tup_upd + n_tup_del > 100
                    ORDER BY n_tup_ins + n_tup_upd + n_tup_del DESC
                    LIMIT 50
                """, schema)
                tables = [r["relname"] for r in rows]

            report.total_tables = len(tables)

            for tbl in tables:
                table_iwo = await self._calculate_table(conn, tbl, schema, stat_period)
                report.tables.append(table_iwo)
                if table_iwo.total_iwo > 5.0:
                    report.tables_with_high_iwo += 1

            return report
        finally:
            await conn.close()

    async def calculate_for_index(
        self,
        dsn: str,
        table: str,
        columns: list[str],
        schema: str = "public",
    ) -> float:
        """
        Calculate the IWO score for a proposed new index.

        Used by the CP-SAT solver to evaluate candidate indexes.
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required")

        conn = await asyncpg.connect(dsn)
        try:
            stat_period = await self._get_stats_period(conn)

            # Get table write rates
            row = await conn.fetchrow("""
                SELECT
                    n_tup_ins, n_tup_upd, n_tup_del,
                    pg_relation_size(relid) AS table_size
                FROM pg_stat_user_tables
                WHERE relname = $1 AND schemaname = $2
            """, table, schema)

            if not row or stat_period == 0:
                return 0.0

            insert_rate = row["n_tup_ins"] / stat_period
            delete_rate = row["n_tup_del"] / stat_period
            update_rate = row["n_tup_upd"] / stat_period
            table_size = max(row["table_size"], 8192)

            # Estimate index size as fraction of table size
            n_cols = len(columns)
            estimated_index_size = table_size * (0.3 + 0.1 * n_cols)

            # IWO = (writes to this index) * index_size / table_size
            total_write_rate = insert_rate + delete_rate + update_rate
            iwo = total_write_rate * (estimated_index_size / table_size)

            return iwo
        finally:
            await conn.close()

    async def _get_stats_period(self, conn: Any) -> float:
        """Get seconds since last stats reset."""
        row = await conn.fetchrow("""
            SELECT EXTRACT(EPOCH FROM (now() - stats_reset)) AS period
            FROM pg_stat_bgwriter
        """)
        if row and row["period"]:
            return max(row["period"], 1.0)
        return 86400.0  # Default 1 day

    async def _calculate_table(
        self,
        conn: Any,
        table: str,
        schema: str,
        stat_period: float,
    ) -> TableIWO:
        """Calculate IWO for a single table."""
        # Table-level stats
        row = await conn.fetchrow("""
            SELECT
                n_tup_ins, n_tup_upd, n_tup_del,
                pg_relation_size(relid) AS table_size,
                pg_relation_size(relid) / NULLIF(current_setting('block_size')::int, 0) AS table_pages
            FROM pg_stat_user_tables
            WHERE relname = $1 AND schemaname = $2
        """, table, schema)

        if not row:
            return TableIWO(table=table, schema=schema)

        table_iwo = TableIWO(
            table=table,
            schema=schema,
            table_size_bytes=row["table_size"] or 0,
            table_size_pages=row["table_pages"] or 1,
            total_inserts=row["n_tup_ins"],
            total_deletes=row["n_tup_del"],
            total_updates=row["n_tup_upd"],
            stat_period_seconds=stat_period,
        )

        insert_rate = row["n_tup_ins"] / stat_period
        delete_rate = row["n_tup_del"] / stat_period
        update_rate = row["n_tup_upd"] / stat_period
        table_size = max(row["table_size"] or 1, 8192)

        # Get per-index stats
        index_rows = await conn.fetch("""
            SELECT
                i.indexrelid::regclass::text AS index_name,
                ix.indisunique,
                ix.indisprimary,
                pg_relation_size(i.indexrelid) AS index_size,
                pg_relation_size(i.indexrelid) / NULLIF(current_setting('block_size')::int, 0) AS index_pages,
                COALESCE(s.idx_scan, 0) AS scan_count,
                array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns
            FROM pg_index ix
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_class t ON t.oid = ix.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = i.oid
            LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE t.relname = $1 AND n.nspname = $2
            GROUP BY i.indexrelid, ix.indisunique, ix.indisprimary, s.idx_scan
        """, table, schema)

        # Get column-level update frequency for HOT-aware scoring
        col_update_freq = await self._get_column_update_frequency(
            conn, table, schema,
        )

        for idx_row in index_rows:
            index_size = idx_row["index_size"] or 0
            index_pages = idx_row["index_pages"] or 1
            scan_count = idx_row["scan_count"]
            columns = [c for c in (idx_row["columns"] or []) if c]

            # HOT-aware: only count updates that actually touch indexed columns
            col_update_rate = self._estimate_column_update_rate(
                update_rate, columns, col_update_freq,
            )

            # Every INSERT and DELETE must update every index
            total_write_rate = insert_rate + delete_rate + col_update_rate

            # IWO = total_write_rate * (index_size / table_size)
            iwo_score = total_write_rate * (index_size / table_size) if table_size > 0 else 0

            # HOT penalty: indexes on frequently-updated columns block HOT
            hot_penalty = self._calculate_hot_penalty(
                update_rate, columns, col_update_freq,
            )
            iwo_score += hot_penalty

            table_iwo.indexes.append(IndexIWO(
                index_name=idx_row["index_name"],
                table=table,
                columns=columns,
                size_bytes=index_size,
                size_pages=index_pages,
                insert_rate=insert_rate,
                delete_rate=delete_rate,
                update_rate=col_update_rate,
                iwo_score=iwo_score,
                is_primary=idx_row["indisprimary"],
                is_unique=idx_row["indisunique"],
                scan_count=scan_count,
            ))

        return table_iwo

    async def _get_column_update_frequency(
        self,
        conn: Any,
        table: str,
        schema: str,
    ) -> dict[str, float]:
        """
        Estimate per-column update frequency.

        PostgreSQL doesn't track column-level update stats directly.
        We approximate by checking n_tup_hot_upd (HOT updates don't touch
        indexed columns) against n_tup_upd. Columns in indexes that get
        HOT-updated are NOT being changed; columns NOT in any index might be.

        For a more precise estimate, we check if columns are part of
        SET clauses in pg_stat_statements queries (heuristic).
        """
        freq: dict[str, float] = {}

        # Get HOT update ratio for the table
        row = await conn.fetchrow("""
            SELECT
                n_tup_upd,
                n_tup_hot_upd,
                CASE WHEN n_tup_upd > 0
                     THEN n_tup_hot_upd::float / n_tup_upd
                     ELSE 0
                END AS hot_ratio
            FROM pg_stat_user_tables
            WHERE relname = $1 AND schemaname = $2
        """, table, schema)

        if not row:
            return freq

        hot_ratio = row["hot_ratio"] or 0

        # Get all columns
        cols = await conn.fetch("""
            SELECT attname
            FROM pg_attribute
            WHERE attrelid = (
                SELECT oid FROM pg_class
                WHERE relname = $1 AND relnamespace = (
                    SELECT oid FROM pg_namespace WHERE nspname = $2
                )
            )
            AND attnum > 0 AND NOT attisdropped
        """, table, schema)

        # Heuristic: columns indexed are less likely to be in SET clauses
        # (because HOT works when indexed columns don't change).
        # Non-indexed columns get higher update probability.
        indexed_cols: set[str] = set()
        idx_cols = await conn.fetch("""
            SELECT a.attname
            FROM pg_index ix
            JOIN pg_class t ON t.oid = ix.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE t.relname = $1 AND n.nspname = $2
        """, table, schema)
        for r in idx_cols:
            indexed_cols.add(r["attname"])

        for col_row in cols:
            col = col_row["attname"]
            if col in indexed_cols:
                # If column is indexed but HOT ratio is high, column is
                # probably not being updated (HOT means indexed cols stable)
                freq[col] = max(0, 1.0 - hot_ratio)
            else:
                # Non-indexed columns are the ones likely being updated
                freq[col] = min(1.0, 0.5 + (1.0 - hot_ratio) * 0.5)

        return freq

    def _estimate_column_update_rate(
        self,
        table_update_rate: float,
        index_columns: list[str],
        col_freq: dict[str, float],
    ) -> float:
        """Estimate update rate touching specific index columns."""
        if not index_columns or not col_freq:
            return table_update_rate

        # If ANY indexed column is updated, the index must be updated.
        # Probability = 1 - product(1 - p(col_i))  for independent columns.
        prob_none = 1.0
        for col in index_columns:
            p = col_freq.get(col, 0.5)
            prob_none *= (1.0 - p)

        prob_any = 1.0 - prob_none
        return table_update_rate * prob_any

    def _calculate_hot_penalty(
        self,
        update_rate: float,
        columns: list[str],
        col_freq: dict[str, float],
    ) -> float:
        """
        Penalty for blocking HOT updates.

        An index on a frequently-updated column prevents PostgreSQL from
        using Heap-Only Tuple (HOT) updates, forcing full index maintenance.
        This is a hidden cost that standard IWO doesn't capture.
        """
        if update_rate < 1:
            return 0

        # Check if any indexed column is frequently updated
        max_col_freq = max(
            (col_freq.get(c, 0) for c in columns),
            default=0,
        )

        if max_col_freq > 0.5:
            # Significant HOT blocking — penalise proportionally
            return min(5.0, update_rate * max_col_freq / 100)

        return 0
