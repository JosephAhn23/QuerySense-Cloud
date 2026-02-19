"""
Index Bloat Impact Calculator — Quantify the cost of keeping each index.

"Unused indexes contributing to table bloat" was a key finding at Notion.
pganalyze showed not just WHICH indexes were unused, but the COST of keeping them.

This module:
    1. Estimates physical bloat of each index (ideal vs actual size)
    2. Calculates write overhead per index (inserts + updates that touch it)
    3. Shows storage savings from dropping unused/redundant indexes
    4. Computes the "cost of ownership" for each index

Usage:
    from querysense.audit.index_bloat import IndexBloatCalculator

    calc = IndexBloatCalculator()
    report = await calc.analyze(conn)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class IndexBloatEntry:
    """Bloat and cost analysis for a single index."""

    schema: str = "public"
    table: str = ""
    index_name: str = ""
    index_size_bytes: int = 0
    estimated_bloat_bytes: int = 0
    estimated_bloat_ratio: float = 0.0
    idx_scan: int = 0
    idx_tup_read: int = 0
    idx_tup_fetch: int = 0

    # Write cost metrics
    table_inserts: int = 0
    table_updates: int = 0
    table_hot_updates: int = 0

    # Index metadata
    is_unique: bool = False
    is_primary: bool = False
    index_type: str = "btree"
    columns: str = ""
    stats_age_seconds: float = 0.0

    @property
    def qualified_table(self) -> str:
        return f"{self.schema}.{self.table}"

    @property
    def index_size_mb(self) -> float:
        return self.index_size_bytes / (1024 * 1024)

    @property
    def bloat_mb(self) -> float:
        return self.estimated_bloat_bytes / (1024 * 1024)

    @property
    def is_unused(self) -> bool:
        return self.idx_scan == 0

    @property
    def write_operations(self) -> int:
        """Estimated write operations this index must handle.
        Every INSERT adds to every index. Non-HOT UPDATEs add to every index."""
        non_hot_updates = self.table_updates - self.table_hot_updates
        return self.table_inserts + max(0, non_hot_updates)

    @property
    def writes_per_hour(self) -> float:
        if self.stats_age_seconds <= 0:
            return 0
        return self.write_operations / (self.stats_age_seconds / 3600)

    @property
    def write_overhead_mb_per_hour(self) -> float:
        """Rough estimate of write amplification in MB/hour.
        Each index write is ~8-16 bytes (B-tree leaf entry)."""
        return (self.writes_per_hour * 12) / (1024 * 1024)

    @property
    def cost_score(self) -> float:
        """Cost-benefit score. High = expensive relative to usage.
        score = (write_overhead * size) / (scans + 1)"""
        writes = max(self.write_operations, 1)
        scans = max(self.idx_scan, 1)
        return (writes * self.index_size_mb) / scans

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "table": self.table,
            "index_name": self.index_name,
            "index_size_mb": round(self.index_size_mb, 1),
            "bloat_mb": round(self.bloat_mb, 1),
            "bloat_ratio": round(self.estimated_bloat_ratio, 3),
            "idx_scan": self.idx_scan,
            "is_unused": self.is_unused,
            "is_unique": self.is_unique,
            "is_primary": self.is_primary,
            "index_type": self.index_type,
            "columns": self.columns,
            "write_operations": self.write_operations,
            "writes_per_hour": round(self.writes_per_hour, 1),
            "cost_score": round(self.cost_score, 1),
        }


@dataclass
class IndexBloatFinding:
    """An index bloat finding."""

    severity: str
    title: str
    description: str
    recommendation: str
    fix_sql: str = ""
    savings_mb: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "fix_sql": self.fix_sql,
            "savings_mb": round(self.savings_mb, 1),
        }


@dataclass
class IndexBloatReport:
    """Complete index bloat impact report."""

    indexes: list[IndexBloatEntry] = field(default_factory=list)
    findings: list[IndexBloatFinding] = field(default_factory=list)
    total_indexes: int = 0
    total_index_size_mb: float = 0.0
    total_bloat_mb: float = 0.0
    unused_count: int = 0
    unused_size_mb: float = 0.0
    potential_savings_mb: float = 0.0

    @property
    def summary(self) -> str:
        return (
            f"{self.total_indexes} indexes ({self.total_index_size_mb:.0f}MB). "
            f"Estimated bloat: {self.total_bloat_mb:.0f}MB. "
            f"Unused: {self.unused_count} ({self.unused_size_mb:.0f}MB droppable)."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_indexes": self.total_indexes,
            "total_index_size_mb": round(self.total_index_size_mb, 1),
            "total_bloat_mb": round(self.total_bloat_mb, 1),
            "unused_count": self.unused_count,
            "unused_size_mb": round(self.unused_size_mb, 1),
            "potential_savings_mb": round(self.potential_savings_mb, 1),
            "findings": [f.to_dict() for f in self.findings],
            "indexes": [i.to_dict() for i in self.indexes[:50]],
        }


class IndexBloatCalculator:
    """
    Calculate per-index bloat and write overhead cost.

    Goes beyond "this index is unused" to show "this unused index costs
    you X MB/hour in write amplification and Y GB of storage."
    """

    async def analyze(self, conn: AsyncDBConnection) -> IndexBloatReport:
        """Run full index bloat analysis."""
        report = IndexBloatReport()

        stats_age = await self._get_stats_age(conn)
        entries = await self._collect_index_stats(conn, stats_age)
        bloat_data = await self._estimate_bloat(conn)

        # Merge bloat estimates
        bloat_map = {b["index_name"]: b for b in bloat_data}
        for e in entries:
            if e.index_name in bloat_map:
                b = bloat_map[e.index_name]
                e.estimated_bloat_bytes = int(b.get("bloat_bytes", 0))
                e.estimated_bloat_ratio = float(b.get("bloat_ratio", 0))

            report.total_index_size_mb += e.index_size_mb
            report.total_bloat_mb += e.bloat_mb
            if e.is_unused and not e.is_primary and not e.is_unique:
                report.unused_count += 1
                report.unused_size_mb += e.index_size_mb

        report.indexes = sorted(entries, key=lambda e: -e.cost_score)
        report.total_indexes = len(entries)
        report.potential_savings_mb = report.unused_size_mb + report.total_bloat_mb

        self._generate_findings(report)

        return report

    async def _get_stats_age(self, conn: AsyncDBConnection) -> float:
        try:
            val = await conn.fetchval(
                "SELECT EXTRACT(EPOCH FROM (now() - stats_reset))::float "
                "FROM pg_stat_database WHERE datname = current_database()"
            )
            return float(val) if val else 0.0
        except Exception:
            return 0.0

    async def _collect_index_stats(
        self, conn: AsyncDBConnection, stats_age: float,
    ) -> list[IndexBloatEntry]:
        """Collect index statistics with write overhead data."""
        try:
            rows = await conn.fetch(
                "SELECT "
                "  n.nspname, t.relname AS table_name, i.relname AS index_name, "
                "  pg_relation_size(i.oid) AS index_size, "
                "  COALESCE(s.idx_scan, 0), COALESCE(s.idx_tup_read, 0), "
                "  COALESCE(s.idx_tup_fetch, 0), "
                "  ix.indisunique, ix.indisprimary, "
                "  am.amname, "
                "  pg_get_indexdef(ix.indexrelid) AS indexdef, "
                "  COALESCE(ts.n_tup_ins, 0), COALESCE(ts.n_tup_upd, 0), "
                "  COALESCE(ts.n_tup_hot_upd, 0) "
                "FROM pg_index ix "
                "JOIN pg_class i ON i.oid = ix.indexrelid "
                "JOIN pg_class t ON t.oid = ix.indrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                "JOIN pg_am am ON am.oid = i.relam "
                "LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = ix.indexrelid "
                "LEFT JOIN pg_stat_user_tables ts ON ts.relid = ix.indrelid "
                "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
                "ORDER BY pg_relation_size(i.oid) DESC"
            )
        except Exception:
            return []

        entries: list[IndexBloatEntry] = []
        for r in rows:
            if isinstance(r, (list, tuple)):
                vals = list(r)
            else:
                vals = [
                    getattr(r, "nspname", ""), getattr(r, "table_name", ""),
                    getattr(r, "index_name", ""), getattr(r, "index_size", 0),
                    getattr(r, "idx_scan", 0), getattr(r, "idx_tup_read", 0),
                    getattr(r, "idx_tup_fetch", 0),
                    getattr(r, "indisunique", False), getattr(r, "indisprimary", False),
                    getattr(r, "amname", ""), getattr(r, "indexdef", ""),
                    getattr(r, "n_tup_ins", 0), getattr(r, "n_tup_upd", 0),
                    getattr(r, "n_tup_hot_upd", 0),
                ]

            entries.append(IndexBloatEntry(
                schema=str(vals[0]),
                table=str(vals[1]),
                index_name=str(vals[2]),
                index_size_bytes=int(vals[3] or 0),
                idx_scan=int(vals[4] or 0),
                idx_tup_read=int(vals[5] or 0),
                idx_tup_fetch=int(vals[6] or 0),
                is_unique=bool(vals[7]),
                is_primary=bool(vals[8]),
                index_type=str(vals[9] or "btree"),
                columns=str(vals[10] or ""),
                table_inserts=int(vals[11] or 0),
                table_updates=int(vals[12] or 0),
                table_hot_updates=int(vals[13] or 0),
                stats_age_seconds=stats_age,
            ))

        return entries

    async def _estimate_bloat(self, conn: AsyncDBConnection) -> list[dict[str, Any]]:
        """Estimate index bloat using pgstattuple-style heuristic."""
        # Use the pg_relation_size / expected size heuristic
        try:
            rows = await conn.fetch(
                "SELECT "
                "  ci.relname AS index_name, "
                "  pg_relation_size(ci.oid) AS actual_size, "
                "  COALESCE(pg_stat_get_live_tuples(ct.oid), 0) AS live_tuples, "
                "  (SELECT avg_width FROM pg_stats WHERE tablename = ct.relname LIMIT 1) AS avg_width "
                "FROM pg_index ix "
                "JOIN pg_class ci ON ci.oid = ix.indexrelid "
                "JOIN pg_class ct ON ct.oid = ix.indrelid "
                "JOIN pg_namespace n ON n.oid = ct.relnamespace "
                "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
                "  AND pg_relation_size(ci.oid) > 0"
            )
        except Exception:
            return []

        results: list[dict[str, Any]] = []
        for r in rows:
            if isinstance(r, (list, tuple)):
                name, actual, tuples, avg_w = r[0], r[1], r[2], r[3]
            else:
                name = getattr(r, "index_name", "")
                actual = getattr(r, "actual_size", 0)
                tuples = getattr(r, "live_tuples", 0)
                avg_w = getattr(r, "avg_width", None)

            actual_i = int(actual or 0)
            tuples_i = int(tuples or 0)
            width = int(avg_w or 24)  # default B-tree entry ~24 bytes

            if tuples_i > 0 and actual_i > 0:
                # Ideal size: tuples * (entry_width + overhead) / fill_factor
                # B-tree leaf page fill factor ~90%, each entry ~(width + 8) bytes
                entry_size = width + 8
                ideal = int(tuples_i * entry_size / 0.9)
                bloat = max(0, actual_i - ideal)
                ratio = bloat / actual_i if actual_i > 0 else 0
            else:
                bloat = 0
                ratio = 0.0

            results.append({
                "index_name": str(name),
                "bloat_bytes": bloat,
                "bloat_ratio": ratio,
            })

        return results

    def _generate_findings(self, report: IndexBloatReport) -> None:
        """Generate findings from the analysis."""
        # Unused indexes (not PK/unique)
        for e in report.indexes:
            if e.is_unused and not e.is_primary and not e.is_unique and e.index_size_mb > 1:
                writes_hr = e.writes_per_hour
                report.findings.append(IndexBloatFinding(
                    severity="warning",
                    title=(
                        f"{e.index_name}: unused ({e.index_size_mb:.0f}MB), "
                        f"costs {writes_hr:,.0f} writes/hr"
                    ),
                    description=(
                        f"Index {e.index_name} on {e.qualified_table} has 0 scans "
                        f"but handles ~{writes_hr:,.0f} write operations/hour. "
                        f"Dropping saves {e.index_size_mb:.0f}MB storage and "
                        f"reduces write amplification."
                    ),
                    recommendation="Drop this index.",
                    fix_sql=f"DROP INDEX CONCURRENTLY {e.schema}.{e.index_name};",
                    savings_mb=e.index_size_mb,
                ))

        # Highly bloated indexes
        for e in report.indexes:
            if e.estimated_bloat_ratio > 0.5 and e.bloat_mb > 10:
                report.findings.append(IndexBloatFinding(
                    severity="warning",
                    title=(
                        f"{e.index_name}: {e.estimated_bloat_ratio:.0%} bloated "
                        f"({e.bloat_mb:.0f}MB wasted)"
                    ),
                    description=(
                        f"Index is {e.estimated_bloat_ratio:.0%} bloated. "
                        f"REINDEX will reclaim {e.bloat_mb:.0f}MB."
                    ),
                    recommendation="REINDEX to reclaim space.",
                    fix_sql=f"REINDEX INDEX CONCURRENTLY {e.schema}.{e.index_name};",
                    savings_mb=e.bloat_mb,
                ))

        # Total potential savings
        if report.potential_savings_mb > 100:
            report.findings.insert(0, IndexBloatFinding(
                severity="info",
                title=f"Potential savings: {report.potential_savings_mb:.0f}MB",
                description=(
                    f"Dropping unused indexes saves {report.unused_size_mb:.0f}MB. "
                    f"Reindexing bloated indexes reclaims {report.total_bloat_mb:.0f}MB."
                ),
                recommendation="Review unused and bloated indexes below.",
            ))
