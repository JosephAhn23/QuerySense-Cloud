"""
Redundant and duplicate index detection.

Scans existing database indexes to find:
- Exact duplicate indexes (same columns, same order)
- Prefix-redundant indexes (e.g. idx(a) is redundant if idx(a,b) exists)
- Unused indexes (zero scans from pg_stat_user_indexes)
- Overlapping indexes that waste space and slow writes

Closes the gap vs EverSQL's redundant index detection.

Usage:
    from querysense.db.index_bloat import detect_redundant_indexes, IndexReport

    report = await detect_redundant_indexes(conn)
    for issue in report.issues:
        print(issue)
    print(f"Potential savings: {report.total_waste_bytes / 1024**2:.0f} MB")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class ExistingIndex:
    """An index found in the database."""

    name: str
    table: str
    schema: str = "public"
    columns: tuple[str, ...] = ()
    is_unique: bool = False
    is_primary: bool = False
    index_type: str = "btree"
    size_bytes: int = 0
    idx_scan: int = 0
    idx_tup_read: int = 0
    idx_tup_fetch: int = 0

    @property
    def is_unused(self) -> bool:
        """Index has never been scanned (since stats reset)."""
        return self.idx_scan == 0 and not self.is_primary and not self.is_unique

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)


@dataclass
class IndexIssue:
    """A detected index issue."""

    severity: str  # "critical", "warning", "info"
    issue_type: str  # "duplicate", "redundant", "unused", "overlapping"
    index_name: str
    table: str
    message: str
    drop_sql: str = ""
    waste_bytes: int = 0

    def __str__(self) -> str:
        s = f"[{self.severity.upper()}] {self.issue_type}: {self.index_name} on {self.table}"
        s += f" - {self.message}"
        if self.drop_sql:
            s += f"\n  Fix: {self.drop_sql}"
        return s


@dataclass
class IndexReport:
    """Complete index health report."""

    indexes: list[ExistingIndex] = field(default_factory=list)
    issues: list[IndexIssue] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_waste_bytes(self) -> int:
        return sum(i.waste_bytes for i in self.issues)

    @property
    def duplicate_count(self) -> int:
        return sum(1 for i in self.issues if i.issue_type == "duplicate")

    @property
    def redundant_count(self) -> int:
        return sum(1 for i in self.issues if i.issue_type == "redundant")

    @property
    def unused_count(self) -> int:
        return sum(1 for i in self.issues if i.issue_type == "unused")

    def summary(self) -> str:
        parts = [f"{len(self.indexes)} indexes scanned"]
        if self.issues:
            parts.append(f"{len(self.issues)} issues found")
        if self.duplicate_count:
            parts.append(f"{self.duplicate_count} duplicates")
        if self.redundant_count:
            parts.append(f"{self.redundant_count} redundant")
        if self.unused_count:
            parts.append(f"{self.unused_count} unused")
        if self.total_waste_bytes:
            parts.append(f"{self.total_waste_bytes / 1024 ** 2:.1f} MB wasted")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "total_indexes": len(self.indexes),
            "issues_count": len(self.issues),
            "duplicate_count": self.duplicate_count,
            "redundant_count": self.redundant_count,
            "unused_count": self.unused_count,
            "total_waste_mb": round(self.total_waste_bytes / 1024 ** 2, 1),
            "issues": [
                {
                    "severity": i.severity,
                    "type": i.issue_type,
                    "index": i.index_name,
                    "table": i.table,
                    "message": i.message,
                    "drop_sql": i.drop_sql,
                    "waste_mb": round(i.waste_bytes / 1024 ** 2, 1),
                }
                for i in self.issues
            ],
            "errors": self.errors,
        }


async def detect_redundant_indexes(
    conn: AsyncDBConnection,
    schema: str = "public",
    min_size_bytes: int = 0,
) -> IndexReport:
    """
    Scan database for redundant, duplicate, and unused indexes.

    Args:
        conn: Database connection
        schema: Schema to scan
        min_size_bytes: Minimum index size to consider (0 = all)
    """
    report = IndexReport()

    # Fetch all indexes with usage stats
    try:
        rows = await conn.fetch(
            """SELECT i.relname AS index_name,
                      t.relname AS table_name,
                      n.nspname AS schema_name,
                      array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns,
                      ix.indisunique,
                      ix.indisprimary,
                      am.amname AS index_type,
                      pg_relation_size(i.oid) AS size_bytes,
                      COALESCE(s.idx_scan, 0) AS idx_scan,
                      COALESCE(s.idx_tup_read, 0) AS idx_tup_read,
                      COALESCE(s.idx_tup_fetch, 0) AS idx_tup_fetch
               FROM pg_index ix
               JOIN pg_class i ON i.oid = ix.indexrelid
               JOIN pg_class t ON t.oid = ix.indrelid
               JOIN pg_namespace n ON n.oid = t.relnamespace
               JOIN pg_am am ON am.oid = i.relam
               JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
               LEFT JOIN pg_stat_user_indexes s
                    ON s.indexrelid = i.oid
               WHERE n.nspname = $1
                 AND am.amname = 'btree'
               GROUP BY i.relname, t.relname, n.nspname,
                        ix.indisunique, ix.indisprimary, am.amname,
                        i.oid, s.idx_scan, s.idx_tup_read, s.idx_tup_fetch
               ORDER BY t.relname, i.relname""",
            schema,
        )
    except Exception as e:
        report.errors.append(f"index_scan: {e}")
        return report

    for row in rows:
        idx = ExistingIndex(
            name=row["index_name"],
            table=row["table_name"],
            schema=row["schema_name"],
            columns=tuple(row["columns"]),
            is_unique=row["indisunique"],
            is_primary=row["indisprimary"],
            index_type=row["index_type"],
            size_bytes=row["size_bytes"] or 0,
            idx_scan=row["idx_scan"],
            idx_tup_read=row["idx_tup_read"],
            idx_tup_fetch=row["idx_tup_fetch"],
        )
        report.indexes.append(idx)

    # Group indexes by table
    by_table: dict[str, list[ExistingIndex]] = {}
    for idx in report.indexes:
        by_table.setdefault(idx.table, []).append(idx)

    # Detect issues per table
    for table, indexes in by_table.items():
        _detect_duplicates(indexes, report)
        _detect_prefix_redundant(indexes, report)
        _detect_unused(indexes, report, min_size_bytes)

    return report


def _detect_duplicates(indexes: list[ExistingIndex], report: IndexReport) -> None:
    """Find exact duplicate indexes (same columns, same order)."""
    seen: dict[tuple[str, ...], ExistingIndex] = {}
    for idx in indexes:
        key = idx.columns
        if key in seen:
            existing = seen[key]
            # Keep the one that's primary/unique; drop the other
            if idx.is_primary or idx.is_unique:
                victim = existing
            else:
                victim = idx

            report.issues.append(IndexIssue(
                severity="warning",
                issue_type="duplicate",
                index_name=victim.name,
                table=victim.table,
                message=(
                    f"Exact duplicate of {existing.name if victim != existing else idx.name} "
                    f"on ({', '.join(victim.columns)})"
                ),
                drop_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {victim.schema}.{victim.name};",
                waste_bytes=victim.size_bytes,
            ))
        else:
            seen[key] = idx


def _detect_prefix_redundant(indexes: list[ExistingIndex], report: IndexReport) -> None:
    """Find indexes that are a prefix of a wider index."""
    for i, narrow in enumerate(indexes):
        if narrow.is_primary or narrow.is_unique:
            continue
        for wide in indexes:
            if wide.name == narrow.name:
                continue
            if len(wide.columns) <= len(narrow.columns):
                continue
            # Check if narrow columns are a prefix of wide columns
            if wide.columns[: len(narrow.columns)] == narrow.columns:
                report.issues.append(IndexIssue(
                    severity="info",
                    issue_type="redundant",
                    index_name=narrow.name,
                    table=narrow.table,
                    message=(
                        f"({', '.join(narrow.columns)}) is a prefix of "
                        f"{wide.name} ({', '.join(wide.columns)})"
                    ),
                    drop_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {narrow.schema}.{narrow.name};",
                    waste_bytes=narrow.size_bytes,
                ))
                break  # Only report once per narrow index


def _detect_unused(
    indexes: list[ExistingIndex],
    report: IndexReport,
    min_size_bytes: int,
) -> None:
    """Find indexes that have never been scanned."""
    for idx in indexes:
        if not idx.is_unused:
            continue
        if idx.size_bytes < min_size_bytes:
            continue
        report.issues.append(IndexIssue(
            severity="info" if idx.size_bytes < 10 * 1024 * 1024 else "warning",
            issue_type="unused",
            index_name=idx.name,
            table=idx.table,
            message=(
                f"Never scanned since stats reset ({idx.size_mb:.1f} MB)"
            ),
            drop_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {idx.schema}.{idx.name};",
            waste_bytes=idx.size_bytes,
        ))
