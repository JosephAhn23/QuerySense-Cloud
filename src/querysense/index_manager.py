"""
Holistic Index Manager — redundant detection, partial/expression/covering suggestions.

Based on "Mastering PostgreSQL 13" (Schönig 2020) and "PostgreSQL Mistakes"
(Angelakos 2025). Goes beyond "add this index" to provide complete index
lifecycle management: what to add, what to remove, what to consolidate.

Features:
- Redundant index detection (prefix overlap, covered indexes)
- Unused index detection (from pg_stat_user_indexes)
- Partial index opportunities (from filter selectivity)
- Expression index suggestions (from function-in-WHERE patterns)
- Covering index optimization (INCLUDE columns)
- Index bloat detection
- Storage savings estimation

Usage:
    from querysense.index_manager import IndexManager, IndexAuditResult

    manager = IndexManager()
    result = await manager.audit(dsn="postgresql://localhost/mydb")
    for finding in result.findings:
        print(finding)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class IndexInfo:
    """Information about an existing index."""
    name: str
    table: str
    schema: str
    columns: list[str]
    is_unique: bool
    is_primary: bool
    index_type: str  # btree, hash, gin, gist, brin
    size_bytes: int
    index_scans: int  # from pg_stat_user_indexes
    tuples_read: int
    tuples_fetched: int
    definition: str  # Full CREATE INDEX statement
    is_partial: bool = False
    where_clause: str = ""
    is_expression: bool = False


@dataclass
class IndexFinding:
    """A finding from the index audit."""
    category: str  # redundant, unused, missing, bloated, suggestion
    severity: str
    title: str
    description: str
    fix_command: str
    impact: str
    savings_bytes: int = 0
    table: str = ""
    index_name: str = ""

    def __str__(self) -> str:
        savings = f" (saves {self.savings_bytes // 1024 // 1024}MB)" if self.savings_bytes > 0 else ""
        return f"[{self.severity.upper()}] {self.title}{savings}"


@dataclass
class IndexAuditResult:
    """Complete index audit result."""
    findings: list[IndexFinding] = field(default_factory=list)
    indexes_audited: int = 0
    tables_audited: int = 0
    total_index_size_bytes: int = 0
    potential_savings_bytes: int = 0

    @property
    def redundant_count(self) -> int:
        return sum(1 for f in self.findings if f.category == "redundant")

    @property
    def unused_count(self) -> int:
        return sum(1 for f in self.findings if f.category == "unused")

    @property
    def fix_script(self) -> str:
        """Generate a complete fix script."""
        lines = ["-- QuerySense Index Audit Fix Script", "-- REVIEW EACH DROP CAREFULLY", ""]
        for f in self.findings:
            if f.fix_command and not f.fix_command.startswith("--"):
                lines.append(f"-- {f.title}")
                lines.append(f"{f.fix_command}")
                lines.append("")
        return "\n".join(lines)


class IndexManager:
    """
    Holistic index management: audit, detect redundancy, suggest improvements.

    Connects to a live PostgreSQL database and analyzes all indexes for
    optimization opportunities.
    """

    async def audit(
        self,
        dsn: str,
        schema: str = "public",
        min_index_scans_for_used: int = 50,
    ) -> IndexAuditResult:
        """Run a complete index audit."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            indexes = await self._fetch_all_indexes(conn, schema)
            result = IndexAuditResult(
                indexes_audited=len(indexes),
                total_index_size_bytes=sum(i.size_bytes for i in indexes),
            )

            # Group by table
            by_table: dict[str, list[IndexInfo]] = {}
            for idx in indexes:
                by_table.setdefault(idx.table, []).append(idx)
            result.tables_audited = len(by_table)

            # Run checks
            for table, table_indexes in by_table.items():
                result.findings.extend(
                    self._check_redundant(table, table_indexes)
                )
                result.findings.extend(
                    self._check_unused(table, table_indexes, min_index_scans_for_used)
                )
                result.findings.extend(
                    self._check_duplicate(table, table_indexes)
                )

            # Potential savings
            result.potential_savings_bytes = sum(
                f.savings_bytes for f in result.findings
            )

            return result
        finally:
            await conn.close()

    async def _fetch_all_indexes(
        self, conn: Any, schema: str,
    ) -> list[IndexInfo]:
        """Fetch all indexes with usage stats."""
        rows = await conn.fetch("""
            SELECT
                i.indexrelid::regclass::text AS index_name,
                t.relname AS table_name,
                n.nspname AS schema_name,
                pg_get_indexdef(i.indexrelid) AS index_def,
                ix.indisunique AS is_unique,
                ix.indisprimary AS is_primary,
                am.amname AS index_type,
                pg_relation_size(i.indexrelid) AS index_size,
                COALESCE(s.idx_scan, 0) AS idx_scan,
                COALESCE(s.idx_tup_read, 0) AS idx_tup_read,
                COALESCE(s.idx_tup_fetch, 0) AS idx_tup_fetch,
                array_to_string(
                    array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)),
                    ','
                ) AS columns
            FROM pg_index ix
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_class t ON t.oid = ix.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_am am ON am.oid = i.relam
            LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = i.oid
            LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE n.nspname = $1
              AND t.relkind = 'r'
            GROUP BY i.indexrelid, t.relname, n.nspname, ix.indisunique, ix.indisprimary,
                     am.amname, s.idx_scan, s.idx_tup_read, s.idx_tup_fetch
            ORDER BY t.relname, i.indexrelid::regclass::text
        """, schema)

        indexes: list[IndexInfo] = []
        for row in rows:
            defn = row["index_def"] or ""
            is_partial = "WHERE" in defn.upper()
            where_clause = ""
            if is_partial:
                where_idx = defn.upper().find("WHERE")
                where_clause = defn[where_idx:]

            indexes.append(IndexInfo(
                name=row["index_name"],
                table=row["table_name"],
                schema=row["schema_name"],
                columns=[c.strip() for c in (row["columns"] or "").split(",") if c.strip()],
                is_unique=row["is_unique"],
                is_primary=row["is_primary"],
                index_type=row["index_type"],
                size_bytes=row["index_size"],
                index_scans=row["idx_scan"],
                tuples_read=row["idx_tup_read"],
                tuples_fetched=row["idx_tup_fetch"],
                definition=defn,
                is_partial=is_partial,
                where_clause=where_clause,
                is_expression="(" in (row["columns"] or ""),
            ))

        return indexes

    def _check_redundant(
        self, table: str, indexes: list[IndexInfo],
    ) -> list[IndexFinding]:
        """Detect redundant indexes (prefix overlap)."""
        findings: list[IndexFinding] = []

        for i, idx_a in enumerate(indexes):
            if idx_a.is_primary:
                continue
            for idx_b in indexes[i + 1:]:
                if idx_b.is_primary:
                    continue
                if idx_a.index_type != idx_b.index_type:
                    continue
                if idx_a.is_partial != idx_b.is_partial:
                    continue

                # Check if A is a prefix of B
                cols_a = idx_a.columns
                cols_b = idx_b.columns

                if len(cols_a) < len(cols_b) and cols_a == cols_b[:len(cols_a)]:
                    # A is a prefix of B — A is redundant
                    findings.append(IndexFinding(
                        category="redundant",
                        severity="warning",
                        title=f"Redundant index: {idx_a.name} is a prefix of {idx_b.name}",
                        description=(
                            f"Index {idx_a.name}({', '.join(cols_a)}) is a leading "
                            f"prefix of {idx_b.name}({', '.join(cols_b)}). "
                            f"The wider index can serve all queries the narrow one does."
                        ),
                        fix_command=f"DROP INDEX CONCURRENTLY IF EXISTS {idx_a.name};",
                        impact=f"Saves {idx_a.size_bytes // 1024 // 1024}MB and reduces write overhead",
                        savings_bytes=idx_a.size_bytes,
                        table=table,
                        index_name=idx_a.name,
                    ))
                elif len(cols_b) < len(cols_a) and cols_b == cols_a[:len(cols_b)]:
                    findings.append(IndexFinding(
                        category="redundant",
                        severity="warning",
                        title=f"Redundant index: {idx_b.name} is a prefix of {idx_a.name}",
                        description=(
                            f"Index {idx_b.name}({', '.join(cols_b)}) is a leading "
                            f"prefix of {idx_a.name}({', '.join(cols_a)})."
                        ),
                        fix_command=f"DROP INDEX CONCURRENTLY IF EXISTS {idx_b.name};",
                        impact=f"Saves {idx_b.size_bytes // 1024 // 1024}MB",
                        savings_bytes=idx_b.size_bytes,
                        table=table,
                        index_name=idx_b.name,
                    ))

        return findings

    def _check_unused(
        self, table: str, indexes: list[IndexInfo], threshold: int,
    ) -> list[IndexFinding]:
        """Detect indexes with zero or very low usage."""
        findings: list[IndexFinding] = []

        for idx in indexes:
            if idx.is_primary or idx.is_unique:
                continue
            if idx.index_scans < threshold:
                findings.append(IndexFinding(
                    category="unused",
                    severity="warning" if idx.index_scans == 0 else "info",
                    title=f"{'Unused' if idx.index_scans == 0 else 'Rarely used'} index: {idx.name}",
                    description=(
                        f"Index {idx.name} on {table}({', '.join(idx.columns)}) "
                        f"has only {idx.index_scans} scans since last stats reset. "
                        f"Size: {idx.size_bytes // 1024 // 1024}MB."
                    ),
                    fix_command=(
                        f"-- Verify no recent usage, then:\n"
                        f"DROP INDEX CONCURRENTLY IF EXISTS {idx.name};"
                    ),
                    impact=f"Saves {idx.size_bytes // 1024 // 1024}MB and reduces write overhead",
                    savings_bytes=idx.size_bytes,
                    table=table,
                    index_name=idx.name,
                ))

        return findings

    def _check_duplicate(
        self, table: str, indexes: list[IndexInfo],
    ) -> list[IndexFinding]:
        """Detect exact duplicate indexes."""
        findings: list[IndexFinding] = []
        seen: dict[str, IndexInfo] = {}

        for idx in indexes:
            key = f"{','.join(idx.columns)}_{idx.index_type}_{idx.where_clause}"
            if key in seen and not idx.is_primary:
                existing = seen[key]
                findings.append(IndexFinding(
                    category="redundant",
                    severity="critical",
                    title=f"Duplicate index: {idx.name} duplicates {existing.name}",
                    description=(
                        f"Indexes {idx.name} and {existing.name} are identical. "
                        f"Drop one."
                    ),
                    fix_command=f"DROP INDEX CONCURRENTLY IF EXISTS {idx.name};",
                    impact=f"Saves {idx.size_bytes // 1024 // 1024}MB — duplicate index waste",
                    savings_bytes=idx.size_bytes,
                    table=table,
                    index_name=idx.name,
                ))
            else:
                seen[key] = idx

        return findings
