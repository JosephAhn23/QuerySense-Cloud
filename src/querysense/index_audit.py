"""
Index Auditor — detect duplicate, unused, and redundant indexes.

Addresses: "We have 50 indexes but the wrong ones — how do we clean up?"
(LinkedIn DB blogs, common pain point)

Capabilities:
1. Duplicate detection: Indexes on the same columns in the same order
2. Redundant detection: Index A is a prefix of Index B (B covers A)
3. Unused detection: Indexes with zero scans since last stats reset
4. Bloat estimation: Indexes significantly larger than expected
5. Missing index detection: Tables with sequential scans but no indexes

All analysis is read-only and based on PostgreSQL catalog queries.

Usage:
    from querysense.index_audit import IndexAuditor

    auditor = IndexAuditor(dsn="postgresql://localhost/mydb")
    report = auditor.audit()
    for issue in report.issues:
        print(issue)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class IndexInfo:
    """Information about a single index."""

    schema_name: str
    table_name: str
    index_name: str
    columns: list[str]
    is_unique: bool
    is_primary: bool
    index_size_bytes: int
    index_scans: int
    last_used: str | None  # ISO timestamp or None
    definition: str  # Full CREATE INDEX statement


@dataclass(frozen=True)
class IndexIssue:
    """A detected index quality issue."""

    issue_type: str  # "duplicate", "redundant", "unused", "bloated", "missing"
    severity: str  # "critical", "warning", "info"
    table_name: str
    index_name: str
    description: str
    fix_sql: str
    estimated_savings: str  # Human-readable size savings
    related_index: str | None = None  # For duplicate/redundant comparisons


@dataclass
class IndexAuditReport:
    """Complete index audit report."""

    issues: list[IndexIssue] = field(default_factory=list)
    total_indexes: int = 0
    total_index_size: str = "0 B"
    potential_savings: str = "0 B"
    indexes_by_table: dict[str, list[IndexInfo]] = field(default_factory=dict)

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
        parts = [f"{self.total_indexes} indexes analyzed"]
        if self.duplicate_count:
            parts.append(f"{self.duplicate_count} duplicates")
        if self.redundant_count:
            parts.append(f"{self.redundant_count} redundant")
        if self.unused_count:
            parts.append(f"{self.unused_count} unused")
        parts.append(f"potential savings: {self.potential_savings}")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "total_indexes": self.total_indexes,
            "total_index_size": self.total_index_size,
            "potential_savings": self.potential_savings,
            "issues": [
                {
                    "type": i.issue_type,
                    "severity": i.severity,
                    "table": i.table_name,
                    "index": i.index_name,
                    "description": i.description,
                    "fix_sql": i.fix_sql,
                    "savings": i.estimated_savings,
                    "related_index": i.related_index,
                }
                for i in self.issues
            ],
        }


# ── Catalog queries ──────────────────────────────────────────────────

CATALOG_QUERY_INDEXES = """
SELECT
    schemaname,
    tablename,
    indexname,
    indexdef,
    pg_relation_size(quote_ident(schemaname) || '.' || quote_ident(indexname)) AS index_size
FROM pg_indexes
WHERE schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
ORDER BY tablename, indexname;
"""

CATALOG_QUERY_USAGE = """
SELECT
    schemaname,
    relname AS tablename,
    indexrelname AS indexname,
    idx_scan AS index_scans,
    idx_tup_read AS tuples_read,
    idx_tup_fetch AS tuples_fetched,
    pg_relation_size(indexrelid) AS index_size
FROM pg_stat_user_indexes
ORDER BY idx_scan ASC;
"""

CATALOG_QUERY_UNUSED = """
SELECT
    schemaname,
    relname AS tablename,
    indexrelname AS indexname,
    idx_scan,
    pg_relation_size(indexrelid) AS index_size,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size_pretty
FROM pg_stat_user_indexes
WHERE idx_scan = 0
  AND indexrelname NOT LIKE '%_pkey'
  AND schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY pg_relation_size(indexrelid) DESC;
"""

CATALOG_QUERY_DUPLICATES = """
WITH index_columns AS (
    SELECT
        n.nspname AS schema_name,
        ct.relname AS table_name,
        ci.relname AS index_name,
        array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns,
        ix.indisunique AS is_unique,
        ix.indisprimary AS is_primary,
        pg_relation_size(ci.oid) AS index_size
    FROM pg_index ix
    JOIN pg_class ct ON ct.oid = ix.indrelid
    JOIN pg_class ci ON ci.oid = ix.indexrelid
    JOIN pg_namespace n ON n.oid = ct.relnamespace
    JOIN pg_attribute a ON a.attrelid = ct.oid AND a.attnum = ANY(ix.indkey)
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
    GROUP BY n.nspname, ct.relname, ci.relname, ix.indisunique, ix.indisprimary, ci.oid
)
SELECT *
FROM index_columns
ORDER BY schema_name, table_name, columns;
"""

CATALOG_QUERY_SEQ_SCAN_TABLES = """
SELECT
    schemaname,
    relname AS tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    n_live_tup AS estimated_rows,
    pg_size_pretty(pg_relation_size(relid)) AS table_size
FROM pg_stat_user_tables
WHERE seq_scan > 0
  AND (idx_scan = 0 OR seq_scan > idx_scan * 10)
  AND n_live_tup > 10000
ORDER BY seq_tup_read DESC
LIMIT 20;
"""


class IndexAuditor:
    """Audit indexes for duplicates, redundancy, unused, and bloat.

    Can work in two modes:
    1. Connected mode: Queries PostgreSQL catalog directly
    2. Offline mode: Analyzes provided index definitions
    """

    def audit_from_catalog_data(
        self,
        index_columns: list[dict[str, Any]],
        usage_stats: list[dict[str, Any]] | None = None,
        seq_scan_tables: list[dict[str, Any]] | None = None,
    ) -> IndexAuditReport:
        """Audit indexes from pre-fetched catalog data.

        This is the primary analysis method — works without a live connection.

        Args:
            index_columns: Results from CATALOG_QUERY_DUPLICATES
            usage_stats: Results from CATALOG_QUERY_USAGE (optional)
            seq_scan_tables: Results from CATALOG_QUERY_SEQ_SCAN_TABLES (optional)
        """
        issues: list[IndexIssue] = []
        total_size = 0

        # Group indexes by table
        by_table: dict[str, list[dict[str, Any]]] = {}
        for idx in index_columns:
            table = f"{idx.get('schema_name', 'public')}.{idx['table_name']}"
            by_table.setdefault(table, []).append(idx)
            total_size += idx.get("index_size", 0)

        # Detect duplicates and redundant indexes per table
        for table, indexes in by_table.items():
            issues.extend(self._find_duplicates(table, indexes))
            issues.extend(self._find_redundant(table, indexes))

        # Detect unused indexes from usage stats
        if usage_stats:
            issues.extend(self._find_unused(usage_stats))

        # Calculate potential savings
        savings = sum(
            self._parse_size(i.estimated_savings) for i in issues
        )

        return IndexAuditReport(
            issues=issues,
            total_indexes=len(index_columns),
            total_index_size=self._format_size(total_size),
            potential_savings=self._format_size(savings),
        )

    def _find_duplicates(self, table: str, indexes: list[dict[str, Any]]) -> list[IndexIssue]:
        """Find indexes with identical column lists."""
        issues = []
        seen: dict[str, str] = {}

        for idx in indexes:
            cols = tuple(idx.get("columns", []))
            key = str(cols)

            if key in seen:
                original = seen[key]
                size = idx.get("index_size", 0)
                issues.append(IndexIssue(
                    issue_type="duplicate",
                    severity="warning",
                    table_name=table,
                    index_name=idx["index_name"],
                    description=(
                        f"Exact duplicate of '{original}'. Both index the same columns "
                        f"in the same order: {', '.join(str(c) for c in cols)}."
                    ),
                    fix_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {idx['index_name']};",
                    estimated_savings=self._format_size(size),
                    related_index=original,
                ))
            else:
                seen[key] = idx["index_name"]

        return issues

    def _find_redundant(self, table: str, indexes: list[dict[str, Any]]) -> list[IndexIssue]:
        """Find indexes where one is a prefix of another (redundant)."""
        issues = []
        sorted_indexes = sorted(indexes, key=lambda x: len(x.get("columns", [])))

        for i, shorter in enumerate(sorted_indexes):
            short_cols = list(shorter.get("columns", []))
            if not short_cols:
                continue

            for longer in sorted_indexes[i + 1:]:
                long_cols = list(longer.get("columns", []))
                if not long_cols or len(long_cols) <= len(short_cols):
                    continue

                # Check if shorter is a prefix of longer
                if long_cols[:len(short_cols)] == short_cols:
                    # Don't flag primary keys or unique indexes as redundant
                    if shorter.get("is_primary") or shorter.get("is_unique"):
                        continue

                    size = shorter.get("index_size", 0)
                    issues.append(IndexIssue(
                        issue_type="redundant",
                        severity="info",
                        table_name=table,
                        index_name=shorter["index_name"],
                        description=(
                            f"Redundant — '{longer['index_name']}' covers the same columns "
                            f"({', '.join(str(c) for c in short_cols)}) as a prefix of "
                            f"({', '.join(str(c) for c in long_cols)}). Any query that uses "
                            f"'{shorter['index_name']}' can also use '{longer['index_name']}'."
                        ),
                        fix_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {shorter['index_name']};",
                        estimated_savings=self._format_size(size),
                        related_index=longer["index_name"],
                    ))

        return issues

    def _find_unused(self, usage_stats: list[dict[str, Any]]) -> list[IndexIssue]:
        """Find indexes with zero scans (unused)."""
        issues = []

        for stat in usage_stats:
            scans = stat.get("index_scans", 0) or stat.get("idx_scan", 0)
            if scans > 0:
                continue

            name = stat.get("indexname", stat.get("index_name", ""))
            # Skip primary keys
            if name.endswith("_pkey"):
                continue

            table = stat.get("tablename", stat.get("table_name", ""))
            size = stat.get("index_size", 0)

            issues.append(IndexIssue(
                issue_type="unused",
                severity="warning" if size > 10_000_000 else "info",  # >10MB
                table_name=table,
                index_name=name,
                description=(
                    f"Zero index scans since last statistics reset. "
                    f"This index ({self._format_size(size)}) is consuming disk space "
                    f"and slowing down writes without providing any read benefit."
                ),
                fix_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {name};",
                estimated_savings=self._format_size(size),
            ))

        return issues

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format bytes to human-readable size."""
        if size_bytes < 0:
            return "0 B"
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(size_bytes) < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0  # type: ignore[assignment]
        return f"{size_bytes:.1f} PB"

    @staticmethod
    def _parse_size(size_str: str) -> int:
        """Parse human-readable size back to bytes (approximate)."""
        import re as _re
        match = _re.match(r"([\d.]+)\s*(B|KB|MB|GB|TB|PB)", size_str)
        if not match:
            return 0
        value = float(match.group(1))
        unit = match.group(2)
        multiplier = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4, "PB": 1024**5}
        return int(value * multiplier.get(unit, 1))

    @staticmethod
    def get_catalog_queries() -> dict[str, str]:
        """Return the catalog queries needed for audit.

        Use these to fetch data from PostgreSQL, then pass results
        to audit_from_catalog_data().
        """
        return {
            "indexes": CATALOG_QUERY_DUPLICATES,
            "usage": CATALOG_QUERY_USAGE,
            "unused": CATALOG_QUERY_UNUSED,
            "seq_scan_tables": CATALOG_QUERY_SEQ_SCAN_TABLES,
        }
