"""
GIN/JSONB Index Advisor — Detect suboptimal GIN indexes and recommend fixes.

Inspired by Notion's 733% performance improvement: switching a default GIN
operator class to jsonb_path_ops on a JSONB containment query reduced runtime
from ~5000ms to ~600ms.

This module:
    1. Discovers all GIN indexes and their operator classes
    2. Detects default operator class on JSONB columns (should be jsonb_path_ops
       when only @> containment queries are used)
    3. Identifies unused GIN indexes (zero scans)
    4. Estimates the write overhead of GIN indexes (they're expensive to maintain)
    5. Recommends operator class changes with CREATE/DROP INDEX DDL

Usage:
    from querysense.audit.gin_advisor import GINIndexAdvisor

    advisor = GINIndexAdvisor()
    report = await advisor.analyze(conn)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class GINIndex:
    """A GIN index with its metadata."""

    schema: str = "public"
    table: str = ""
    index_name: str = ""
    columns: list[str] = field(default_factory=list)
    operator_class: str = ""          # jsonb_ops, jsonb_path_ops, etc.
    index_size_bytes: int = 0
    idx_scan: int = 0
    idx_tup_read: int = 0
    idx_tup_fetch: int = 0
    column_types: list[str] = field(default_factory=list)
    is_valid: bool = True

    @property
    def qualified_table(self) -> str:
        return f"{self.schema}.{self.table}"

    @property
    def index_size_mb(self) -> float:
        return self.index_size_bytes / (1024 * 1024)

    @property
    def is_unused(self) -> bool:
        return self.idx_scan == 0

    @property
    def has_jsonb_columns(self) -> bool:
        return any("jsonb" in t.lower() for t in self.column_types)

    @property
    def uses_default_jsonb_ops(self) -> bool:
        if not self.has_jsonb_columns:
            return False
        if not self.operator_class or self.operator_class == "default":
            return True
        return "jsonb_ops" in self.operator_class and "path_ops" not in self.operator_class

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "table": self.table,
            "index_name": self.index_name,
            "columns": self.columns,
            "operator_class": self.operator_class,
            "index_size_mb": round(self.index_size_mb, 1),
            "idx_scan": self.idx_scan,
            "is_unused": self.is_unused,
            "has_jsonb_columns": self.has_jsonb_columns,
            "uses_default_jsonb_ops": self.uses_default_jsonb_ops,
        }


@dataclass
class GINFinding:
    """A GIN index finding."""

    severity: str
    index_name: str
    title: str
    description: str
    recommendation: str
    fix_sql: str = ""
    impact_estimate: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "index_name": self.index_name,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "fix_sql": self.fix_sql,
            "impact_estimate": self.impact_estimate,
        }


@dataclass
class GINReport:
    """Complete GIN index analysis report."""

    indexes: list[GINIndex] = field(default_factory=list)
    findings: list[GINFinding] = field(default_factory=list)
    total_gin_indexes: int = 0
    total_gin_size_mb: float = 0.0
    unused_count: int = 0
    suboptimal_opclass_count: int = 0

    @property
    def is_healthy(self) -> bool:
        return not any(f.severity in ("critical", "warning") for f in self.findings)

    @property
    def summary(self) -> str:
        parts = [f"{self.total_gin_indexes} GIN indexes ({self.total_gin_size_mb:.0f}MB)"]
        if self.suboptimal_opclass_count:
            parts.append(
                f"{self.suboptimal_opclass_count} using suboptimal operator class"
            )
        if self.unused_count:
            parts.append(f"{self.unused_count} unused")
        return ". ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_gin_indexes": self.total_gin_indexes,
            "total_gin_size_mb": round(self.total_gin_size_mb, 1),
            "unused_count": self.unused_count,
            "suboptimal_opclass_count": self.suboptimal_opclass_count,
            "indexes": [i.to_dict() for i in self.indexes],
            "findings": [f.to_dict() for f in self.findings],
            "is_healthy": self.is_healthy,
        }


class GINIndexAdvisor:
    """
    Analyze GIN indexes for suboptimal operator classes and unused indexes.

    The key insight from Notion: default jsonb_ops supports all JSONB operators
    but is larger and slower than jsonb_path_ops, which only supports @>
    containment. If your queries only use @>, switching gives massive speedups.
    """

    async def analyze(self, conn: AsyncDBConnection) -> GINReport:
        """Run full GIN index analysis."""
        report = GINReport()

        indexes = await self._discover_gin_indexes(conn)
        report.indexes = indexes
        report.total_gin_indexes = len(indexes)
        report.total_gin_size_mb = sum(i.index_size_mb for i in indexes)
        report.unused_count = sum(1 for i in indexes if i.is_unused)

        # Check for suboptimal operator classes
        self._check_operator_classes(report)
        self._check_unused(report)
        self._check_write_overhead(report)

        return report

    async def _discover_gin_indexes(self, conn: AsyncDBConnection) -> list[GINIndex]:
        """Discover all GIN indexes with their metadata."""
        try:
            rows = await conn.fetch(
                "SELECT "
                "  n.nspname AS schema, "
                "  t.relname AS table_name, "
                "  i.relname AS index_name, "
                "  pg_get_indexdef(ix.indexrelid) AS indexdef, "
                "  pg_relation_size(i.oid) AS index_size, "
                "  COALESCE(s.idx_scan, 0) AS idx_scan, "
                "  COALESCE(s.idx_tup_read, 0) AS idx_tup_read, "
                "  COALESCE(s.idx_tup_fetch, 0) AS idx_tup_fetch, "
                "  ix.indisvalid, "
                "  am.amname "
                "FROM pg_index ix "
                "JOIN pg_class i ON i.oid = ix.indexrelid "
                "JOIN pg_class t ON t.oid = ix.indrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                "JOIN pg_am am ON am.oid = i.relam "
                "LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = ix.indexrelid "
                "WHERE am.amname = 'gin' "
                "  AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
                "ORDER BY pg_relation_size(i.oid) DESC"
            )
        except Exception:
            return []

        indexes: list[GINIndex] = []
        for r in rows:
            if isinstance(r, (list, tuple)):
                schema, table, idx_name, indexdef = r[0], r[1], r[2], r[3]
                size, scans, tup_read, tup_fetch = r[4], r[5], r[6], r[7]
                valid, amname = r[8], r[9]
            else:
                schema = getattr(r, "schema", "")
                table = getattr(r, "table_name", "")
                idx_name = getattr(r, "index_name", "")
                indexdef = getattr(r, "indexdef", "")
                size = getattr(r, "index_size", 0)
                scans = getattr(r, "idx_scan", 0)
                tup_read = getattr(r, "idx_tup_read", 0)
                tup_fetch = getattr(r, "idx_tup_fetch", 0)
                valid = getattr(r, "indisvalid", True)
                amname = getattr(r, "amname", "gin")

            idx = GINIndex(
                schema=str(schema),
                table=str(table),
                index_name=str(idx_name),
                index_size_bytes=int(size or 0),
                idx_scan=int(scans or 0),
                idx_tup_read=int(tup_read or 0),
                idx_tup_fetch=int(tup_fetch or 0),
                is_valid=bool(valid),
            )

            # Parse indexdef for columns and operator class
            indexdef_str = str(indexdef or "")
            idx.columns = self._extract_columns(indexdef_str)
            idx.operator_class = self._extract_opclass(indexdef_str)
            idx.column_types = await self._get_column_types(conn, str(schema), str(table), idx.columns)

            indexes.append(idx)

        return indexes

    async def _get_column_types(
        self, conn: AsyncDBConnection,
        schema: str, table: str, columns: list[str],
    ) -> list[str]:
        """Get data types for columns."""
        types: list[str] = []
        for col in columns:
            try:
                t = await conn.fetchval(
                    "SELECT data_type FROM information_schema.columns "
                    "WHERE table_schema = $1 AND table_name = $2 AND column_name = $3",
                    schema, table, col,
                )
                types.append(str(t) if t else "unknown")
            except Exception:
                types.append("unknown")
        return types

    @staticmethod
    def _extract_columns(indexdef: str) -> list[str]:
        """Extract column names from CREATE INDEX definition."""
        import re
        match = re.search(r"\((.+?)\)", indexdef)
        if not match:
            return []
        cols_str = match.group(1)
        # Remove operator class suffixes and options
        cols = []
        for part in cols_str.split(","):
            col = part.strip().split()[0].strip('"')
            if col and not col.startswith("("):
                cols.append(col)
        return cols

    @staticmethod
    def _extract_opclass(indexdef: str) -> str:
        """Extract operator class from CREATE INDEX definition."""
        indexdef_lower = indexdef.lower()
        if "jsonb_path_ops" in indexdef_lower:
            return "jsonb_path_ops"
        if "jsonb_ops" in indexdef_lower:
            return "jsonb_ops"
        if "gin_trgm_ops" in indexdef_lower:
            return "gin_trgm_ops"
        if "array_ops" in indexdef_lower:
            return "array_ops"
        # Default: no explicit operator class
        return "default"

    def _check_operator_classes(self, report: GINReport) -> None:
        """Check for suboptimal GIN operator classes on JSONB columns."""
        for idx in report.indexes:
            if idx.uses_default_jsonb_ops:
                report.suboptimal_opclass_count += 1

                cols = ", ".join(idx.columns)
                new_name = f"{idx.index_name}_path_ops"

                report.findings.append(GINFinding(
                    severity="warning",
                    index_name=idx.index_name,
                    title=(
                        f"{idx.index_name}: default jsonb_ops on JSONB column "
                        f"({idx.index_size_mb:.0f}MB)"
                    ),
                    description=(
                        f"Index {idx.index_name} on {idx.qualified_table}({cols}) "
                        f"uses the default jsonb_ops operator class. If queries only "
                        f"use @> (containment), jsonb_path_ops is 2-8x faster and "
                        f"significantly smaller. Notion saw a 733% improvement from "
                        f"this exact change."
                    ),
                    recommendation=(
                        f"If queries only use @> on these columns, switch to jsonb_path_ops. "
                        f"Note: jsonb_path_ops does NOT support ?, ?|, ?& operators."
                    ),
                    fix_sql=(
                        f"-- Create new index with jsonb_path_ops (CONCURRENTLY to avoid locks)\n"
                        f"CREATE INDEX CONCURRENTLY {new_name}\n"
                        f"  ON {idx.qualified_table} USING gin ({cols} jsonb_path_ops);\n"
                        f"-- Verify new index is used, then drop old\n"
                        f"-- DROP INDEX CONCURRENTLY {idx.index_name};"
                    ),
                    impact_estimate="Potential 2-8x speedup for @> containment queries",
                    evidence={
                        "current_opclass": idx.operator_class,
                        "index_size_mb": round(idx.index_size_mb, 1),
                        "idx_scan": idx.idx_scan,
                    },
                ))

    def _check_unused(self, report: GINReport) -> None:
        """Flag unused GIN indexes (expensive to maintain for zero benefit)."""
        for idx in report.indexes:
            if idx.is_unused and idx.index_size_bytes > 0:
                report.findings.append(GINFinding(
                    severity="warning",
                    index_name=idx.index_name,
                    title=f"{idx.index_name}: unused GIN index ({idx.index_size_mb:.0f}MB)",
                    description=(
                        f"GIN index {idx.index_name} on {idx.qualified_table} has "
                        f"0 scans since stats reset. GIN indexes are expensive to "
                        f"maintain on writes — every INSERT/UPDATE must update the "
                        f"inverted index."
                    ),
                    recommendation="Drop this index to reduce write overhead and storage.",
                    fix_sql=f"DROP INDEX CONCURRENTLY {idx.schema}.{idx.index_name};",
                    evidence={
                        "index_size_mb": round(idx.index_size_mb, 1),
                        "idx_scan": 0,
                    },
                ))

    def _check_write_overhead(self, report: GINReport) -> None:
        """Warn about GIN indexes on high-write tables."""
        for idx in report.indexes:
            # GIN indexes with very low scan/size ratio = high cost, low value
            if idx.index_size_mb > 100 and idx.idx_scan < 100:
                report.findings.append(GINFinding(
                    severity="notice",
                    index_name=idx.index_name,
                    title=(
                        f"{idx.index_name}: large GIN index ({idx.index_size_mb:.0f}MB) "
                        f"with only {idx.idx_scan} scans"
                    ),
                    description=(
                        f"This GIN index is {idx.index_size_mb:.0f}MB but has only been "
                        f"scanned {idx.idx_scan} times. GIN indexes have high write "
                        f"amplification — consider if this index is justified."
                    ),
                    recommendation="Monitor usage and consider dropping if not needed.",
                ))
