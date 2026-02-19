"""
HOT Update Detection — find indexes blocking Heap-Only Tuple updates.

HOT (Heap-Only Tuple) updates are PostgreSQL's optimization for UPDATE operations
that don't modify any indexed column. When an UPDATE only changes non-indexed
columns, PostgreSQL can avoid updating every index entry, making the update
significantly faster (often 10-50x for wide-index tables).

The problem: every index on a table must be updated when any indexed column
changes. An index on columns that are frequently updated prevents HOT updates
for that table entirely if the UPDATE touches those columns.

This module:
1. Identifies which columns are frequently updated
2. Cross-references with existing indexes
3. Flags indexes whose columns are update-hot (blocking HOT updates)
4. Estimates the performance gain from enabling HOT updates
5. Suggests partial indexes or covering index restructuring

Based on pganalyze's "PostgreSQL Intelligence" work on HOT update detection.

Usage:
    from querysense.hot_update_detector import HOTDetector, HOTAnalysis

    detector = HOTDetector()
    analysis = await detector.analyze(dsn="postgresql://localhost/mydb")
    for finding in analysis.findings:
        print(f"{finding.table}: {finding.description}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HOTFinding:
    """A finding from HOT update analysis."""
    table: str
    severity: str  # critical, warning, info
    description: str
    index_name: str = ""
    index_columns: list[str] = field(default_factory=list)
    updated_columns: list[str] = field(default_factory=list)
    hot_update_ratio: float = 0.0  # Current HOT ratio (0-1)
    potential_hot_ratio: float = 0.0  # HOT ratio if index removed/restructured
    estimated_speedup: str = ""
    fix_command: str = ""
    impact: str = ""


@dataclass
class TableHOTStats:
    """HOT statistics for a table."""
    table: str
    schema: str
    n_tup_upd: int  # Total updates
    n_tup_hot_upd: int  # HOT updates
    hot_ratio: float  # n_tup_hot_upd / n_tup_upd
    n_live_tup: int
    n_indexes: int
    indexed_columns: list[str]  # All indexed columns
    fillfactor: int = 100  # Table fillfactor


@dataclass
class HOTAnalysis:
    """Complete HOT update analysis result."""
    findings: list[HOTFinding] = field(default_factory=list)
    tables_analyzed: int = 0
    tables_with_low_hot: int = 0
    potential_improvement_tables: int = 0

    @property
    def fix_script(self) -> str:
        lines = ["-- QuerySense HOT Update Fix Script", ""]
        for f in self.findings:
            if f.severity in ("critical", "warning") and f.fix_command:
                lines.append(f"-- {f.table}: {f.description}")
                lines.append(f"{f.fix_command}")
                lines.append("")
        return "\n".join(lines)


class HOTDetector:
    """
    Detect indexes that block HOT updates and suggest improvements.

    Connects to a live database and cross-references update patterns
    with index definitions to find optimization opportunities.
    """

    async def analyze(
        self,
        dsn: str,
        schema: str = "public",
        min_updates: int = 1000,
        low_hot_threshold: float = 0.5,
    ) -> HOTAnalysis:
        """
        Run HOT update analysis.

        Args:
            dsn: PostgreSQL connection string
            schema: Schema to analyze
            min_updates: Minimum updates on a table to consider
            low_hot_threshold: HOT ratio below this is flagged
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            analysis = HOTAnalysis()

            # Get table HOT stats
            tables = await self._fetch_hot_stats(conn, schema, min_updates)
            analysis.tables_analyzed = len(tables)

            for table_stats in tables:
                if table_stats.hot_ratio < low_hot_threshold and table_stats.n_tup_upd > min_updates:
                    analysis.tables_with_low_hot += 1

                    # Get the update column patterns from pg_stat_statements
                    update_cols = await self._get_update_columns(conn, table_stats.table)

                    # Get index details
                    indexes = await self._get_table_indexes(conn, table_stats.table, schema)

                    # Find indexes blocking HOT
                    findings = self._find_blocking_indexes(
                        table_stats, indexes, update_cols, low_hot_threshold,
                    )
                    analysis.findings.extend(findings)

                    if findings:
                        analysis.potential_improvement_tables += 1

            # Check fillfactor
            for table_stats in tables:
                if table_stats.hot_ratio < 0.8 and table_stats.fillfactor == 100:
                    analysis.findings.append(HOTFinding(
                        table=f"{table_stats.schema}.{table_stats.table}",
                        severity="info",
                        description=(
                            f"fillfactor=100 (default). Reducing to 80-90 reserves "
                            f"space for HOT updates on the same page."
                        ),
                        hot_update_ratio=table_stats.hot_ratio,
                        fix_command=(
                            f"ALTER TABLE {table_stats.schema}.{table_stats.table} "
                            f"SET (fillfactor = 85);\n"
                            f"-- Then rewrite the table to apply:\n"
                            f"VACUUM (FULL) {table_stats.schema}.{table_stats.table};"
                        ),
                        impact="10-30% improvement in UPDATE throughput for write-heavy tables",
                    ))

            return analysis
        finally:
            await conn.close()

    async def _fetch_hot_stats(
        self, conn: Any, schema: str, min_updates: int,
    ) -> list[TableHOTStats]:
        """Fetch HOT update statistics for all tables."""
        rows = await conn.fetch("""
            SELECT
                s.schemaname,
                s.relname,
                s.n_tup_upd,
                s.n_tup_hot_upd,
                CASE WHEN s.n_tup_upd > 0
                     THEN s.n_tup_hot_upd::float / s.n_tup_upd
                     ELSE 1.0 END AS hot_ratio,
                s.n_live_tup,
                (SELECT count(*) FROM pg_index WHERE indrelid = c.oid) AS n_indexes,
                COALESCE(
                    (SELECT reloptions FROM pg_class WHERE oid = c.oid),
                    ARRAY[]::text[]
                ) AS reloptions
            FROM pg_stat_user_tables s
            JOIN pg_class c ON c.oid = s.relid
            WHERE s.schemaname = $1
              AND s.n_tup_upd >= $2
            ORDER BY s.n_tup_upd DESC
        """, schema, min_updates)

        tables: list[TableHOTStats] = []
        for row in rows:
            # Parse fillfactor from reloptions
            fillfactor = 100
            for opt in (row["reloptions"] or []):
                if opt.startswith("fillfactor="):
                    try:
                        fillfactor = int(opt.split("=")[1])
                    except ValueError:
                        pass

            tables.append(TableHOTStats(
                table=row["relname"],
                schema=row["schemaname"],
                n_tup_upd=row["n_tup_upd"],
                n_tup_hot_upd=row["n_tup_hot_upd"],
                hot_ratio=row["hot_ratio"],
                n_live_tup=row["n_live_tup"],
                n_indexes=row["n_indexes"],
                indexed_columns=[],
                fillfactor=fillfactor,
            ))

        return tables

    async def _get_update_columns(self, conn: Any, table: str) -> list[str]:
        """
        Infer which columns are frequently updated.

        Uses pg_stat_statements to find UPDATE queries targeting this table
        and extracts the SET column list.
        """
        try:
            rows = await conn.fetch("""
                SELECT query, calls
                FROM pg_stat_statements
                WHERE query ~* $1
                  AND calls > 5
                ORDER BY calls DESC
                LIMIT 20
            """, f"UPDATE\\s+.*{table}\\s+SET")
        except Exception:
            return []

        import re
        columns: dict[str, int] = {}
        for row in rows:
            query = row["query"]
            calls = row["calls"]

            # Extract SET column = ... patterns
            set_match = re.search(r"SET\s+(.*?)(?:\s+WHERE|\s+RETURNING|\s*$)", query, re.IGNORECASE)
            if set_match:
                set_clause = set_match.group(1)
                for part in set_clause.split(","):
                    col_match = re.match(r"\s*(\w+)\s*=", part.strip())
                    if col_match:
                        col = col_match.group(1).lower()
                        columns[col] = columns.get(col, 0) + calls

        # Return sorted by frequency
        return sorted(columns.keys(), key=lambda c: columns[c], reverse=True)

    async def _get_table_indexes(
        self, conn: Any, table: str, schema: str,
    ) -> list[dict[str, Any]]:
        """Get all indexes on a table with their column lists."""
        rows = await conn.fetch("""
            SELECT
                i.indexrelid::regclass::text AS index_name,
                pg_get_indexdef(i.indexrelid) AS index_def,
                ix.indisunique,
                ix.indisprimary,
                array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns
            FROM pg_index ix
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_class t ON t.oid = ix.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE t.relname = $1
              AND n.nspname = $2
            GROUP BY i.indexrelid, ix.indisunique, ix.indisprimary
        """, table, schema)

        return [
            {
                "name": row["index_name"],
                "definition": row["index_def"],
                "is_unique": row["indisunique"],
                "is_primary": row["indisprimary"],
                "columns": [c for c in (row["columns"] or []) if c],
            }
            for row in rows
        ]

    def _find_blocking_indexes(
        self,
        table_stats: TableHOTStats,
        indexes: list[dict],
        update_cols: list[str],
        threshold: float,
    ) -> list[HOTFinding]:
        """Find indexes whose columns overlap with frequently-updated columns."""
        findings: list[HOTFinding] = []

        if not update_cols:
            return findings

        update_set = set(c.lower() for c in update_cols)

        for idx in indexes:
            idx_cols = [c.lower() for c in idx["columns"]]
            overlap = update_set.intersection(idx_cols)

            if overlap:
                # This index blocks HOT for updates on these columns
                is_pk = idx["is_primary"]
                is_unique = idx["is_unique"]

                if is_pk:
                    # Can't remove PK index — suggest restructuring
                    findings.append(HOTFinding(
                        table=f"{table_stats.schema}.{table_stats.table}",
                        severity="info",
                        description=(
                            f"Primary key includes updated column(s): {', '.join(overlap)}. "
                            f"Consider if these columns truly need to be in the PK."
                        ),
                        index_name=idx["name"],
                        index_columns=idx_cols,
                        updated_columns=list(overlap),
                        hot_update_ratio=table_stats.hot_ratio,
                        impact="PK cannot be restructured easily, but review if necessary",
                    ))
                elif is_unique:
                    findings.append(HOTFinding(
                        table=f"{table_stats.schema}.{table_stats.table}",
                        severity="warning",
                        description=(
                            f"UNIQUE index '{idx['name']}' includes updated column(s): "
                            f"{', '.join(overlap)}. Every UPDATE on these columns "
                            f"prevents HOT updates."
                        ),
                        index_name=idx["name"],
                        index_columns=idx_cols,
                        updated_columns=list(overlap),
                        hot_update_ratio=table_stats.hot_ratio,
                        estimated_speedup="2-10x for UPDATE throughput if HOT enabled",
                        fix_command=(
                            f"-- Investigate if unique constraint on {', '.join(overlap)} is needed\n"
                            f"-- If not, consider restructuring:\n"
                            f"-- DROP INDEX CONCURRENTLY {idx['name']};\n"
                            f"-- CREATE INDEX CONCURRENTLY ... without the updated columns"
                        ),
                        impact="HOT updates blocked for all UPDATEs touching these columns",
                    ))
                else:
                    # Non-unique, non-PK index — candidate for removal/restructuring
                    non_overlap = [c for c in idx_cols if c not in overlap]
                    findings.append(HOTFinding(
                        table=f"{table_stats.schema}.{table_stats.table}",
                        severity="warning" if table_stats.hot_ratio < 0.3 else "info",
                        description=(
                            f"Index '{idx['name']}' on ({', '.join(idx_cols)}) includes "
                            f"frequently-updated column(s): {', '.join(overlap)}. "
                            f"Current HOT ratio: {table_stats.hot_ratio:.0%}."
                        ),
                        index_name=idx["name"],
                        index_columns=idx_cols,
                        updated_columns=list(overlap),
                        hot_update_ratio=table_stats.hot_ratio,
                        potential_hot_ratio=min(0.95, table_stats.hot_ratio + 0.4),
                        estimated_speedup="2-5x for UPDATE throughput",
                        fix_command=(
                            f"-- Remove updated columns from index to enable HOT:\n"
                            f"DROP INDEX CONCURRENTLY IF EXISTS {idx['name']};\n"
                            + (f"CREATE INDEX CONCURRENTLY ON {table_stats.schema}.{table_stats.table} "
                               f"({', '.join(non_overlap)});" if non_overlap else
                               f"-- No remaining columns — index can be dropped entirely")
                        ),
                        impact=(
                            f"HOT ratio could improve from {table_stats.hot_ratio:.0%} to "
                            f"~{min(0.95, table_stats.hot_ratio + 0.4):.0%}"
                        ),
                    ))

        return findings
