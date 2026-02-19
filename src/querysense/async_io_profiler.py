"""
Async I/O Profiler — Deep analysis of PostgreSQL 18 asynchronous I/O.

PostgreSQL 18 introduced io_method (sync, worker, io_uring) which fundamentally
changes disk I/O. pganalyze is monetizing education on this; we automate detection.

What this module does:
1. Detects current io_method and recommends optimal setting
2. Profiles top queries by I/O wait to estimate async I/O benefit
3. Analyzes storage type (NVMe, SSD, HDD, EBS) for io_uring eligibility
4. Computes expected improvement percentages
5. Generates ready-to-run configuration commands

Usage:
    from querysense.async_io_profiler import AsyncIOProfiler, AsyncIOReport

    profiler = AsyncIOProfiler()
    report = await profiler.analyze(dsn)
    print(report.format_text())
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class IOWaitQuery:
    """A query ranked by I/O wait time."""
    queryid: int = 0
    query: str = ""
    calls: int = 0
    total_exec_time_ms: float = 0.0
    blk_read_time_ms: float = 0.0
    blk_write_time_ms: float = 0.0
    io_wait_pct: float = 0.0
    shared_blks_read: int = 0
    shared_blks_hit: int = 0
    cache_hit_ratio: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query[:200],
            "calls": self.calls,
            "total_exec_time_ms": round(self.total_exec_time_ms, 1),
            "io_wait_pct": round(self.io_wait_pct, 1),
            "blk_read_time_ms": round(self.blk_read_time_ms, 1),
            "cache_hit_ratio": round(self.cache_hit_ratio, 4),
        }


@dataclass
class AsyncIOReport:
    """Complete async I/O analysis report."""
    pg_version: int = 0
    is_pg18: bool = False
    io_method: str = "sync"
    io_combine_limit: int = 0
    track_io_timing: bool = False
    effective_io_concurrency: int = 0
    maintenance_io_concurrency: int = 0
    storage_type: str = "unknown"
    top_io_queries: list[IOWaitQuery] = field(default_factory=list)
    total_io_wait_ms: float = 0.0
    total_exec_time_ms: float = 0.0
    overall_io_wait_pct: float = 0.0
    recommended_io_method: str = "worker"
    recommended_io_combine_limit: int = 128
    recommended_effective_io_concurrency: int = 200
    estimated_improvement_pct: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pg_version": self.pg_version,
            "is_pg18": self.is_pg18,
            "current_config": {
                "io_method": self.io_method,
                "io_combine_limit": self.io_combine_limit,
                "track_io_timing": self.track_io_timing,
                "effective_io_concurrency": self.effective_io_concurrency,
            },
            "storage_type": self.storage_type,
            "io_profile": {
                "total_io_wait_ms": round(self.total_io_wait_ms, 1),
                "total_exec_time_ms": round(self.total_exec_time_ms, 1),
                "overall_io_wait_pct": round(self.overall_io_wait_pct, 1),
            },
            "top_io_queries": [q.to_dict() for q in self.top_io_queries[:10]],
            "recommendations": {
                "io_method": self.recommended_io_method,
                "io_combine_limit": self.recommended_io_combine_limit,
                "effective_io_concurrency": self.recommended_effective_io_concurrency,
                "estimated_improvement_pct": round(self.estimated_improvement_pct, 1),
            },
            "findings": self.findings,
        }

    def format_text(self) -> str:
        lines = [
            "",
            "  ASYNC I/O ANALYSIS",
            "  " + "=" * 55,
            f"  PostgreSQL: {'PG' + str(self.pg_version)} {'(async I/O supported)' if self.is_pg18 else '(upgrade to PG18 for async I/O)'}",
            f"  Current io_method: {self.io_method}",
            f"  Storage type: {self.storage_type}",
            f"  track_io_timing: {'ON' if self.track_io_timing else 'OFF (enable for accurate analysis)'}",
            "",
        ]

        if self.top_io_queries:
            lines.append("  TOP QUERIES BY I/O WAIT:")
            lines.append(f"  {'#':<4} {'I/O%':>6} {'I/O(ms)':>10} {'Total(ms)':>10} {'Query':<40}")
            lines.append("  " + "-" * 75)
            for i, q in enumerate(self.top_io_queries[:10], 1):
                lines.append(
                    f"  {i:<4} {q.io_wait_pct:>5.1f}% {q.blk_read_time_ms:>10.0f} "
                    f"{q.total_exec_time_ms:>10.0f} {q.query[:40]}"
                )
            lines.append("")

        if self.overall_io_wait_pct > 0:
            lines.append(f"  Overall I/O wait: {self.overall_io_wait_pct:.1f}% of total execution time")

        lines.append("")
        lines.append("  RECOMMENDATION:")
        if self.is_pg18 and self.io_method == "sync":
            lines.append(f"  Enable async I/O for {self.estimated_improvement_pct:.0f}% estimated improvement:")
            lines.append(f"    ALTER SYSTEM SET io_method = '{self.recommended_io_method}';")
            lines.append(f"    ALTER SYSTEM SET io_combine_limit = '{self.recommended_io_combine_limit}kB';")
            lines.append("    SELECT pg_reload_conf();")
        elif not self.is_pg18:
            lines.append(f"  Upgrade to PostgreSQL 18 for async I/O (est. {self.estimated_improvement_pct:.0f}% improvement)")
            lines.append("  In the meantime, optimize effective_io_concurrency:")
            lines.append(f"    ALTER SYSTEM SET effective_io_concurrency = {self.recommended_effective_io_concurrency};")
        else:
            lines.append("  Async I/O is already enabled. Current configuration is optimal.")

        lines.append("")
        return "\n".join(lines)


_IO_QUERIES_SQL = """
SELECT
    queryid, query, calls,
    total_exec_time AS total_exec_time_ms,
    blk_read_time AS blk_read_time_ms,
    blk_write_time AS blk_write_time_ms,
    shared_blks_read, shared_blks_hit
FROM pg_stat_statements
WHERE calls > 5
    AND (blk_read_time + blk_write_time) > 0
    AND query NOT LIKE '%%pg_stat%%'
ORDER BY (blk_read_time + blk_write_time) DESC
LIMIT 50
"""

_IO_QUERIES_NO_TIMING_SQL = """
SELECT
    queryid, query, calls,
    total_exec_time AS total_exec_time_ms,
    0::float AS blk_read_time_ms,
    0::float AS blk_write_time_ms,
    shared_blks_read, shared_blks_hit
FROM pg_stat_statements
WHERE calls > 5
    AND shared_blks_read > 100
    AND query NOT LIKE '%%pg_stat%%'
ORDER BY shared_blks_read DESC
LIMIT 50
"""

_STORAGE_DETECTION_SQL = """
SELECT
    CASE
        WHEN current_setting('data_directory') LIKE '/dev/nvme%%'
            OR current_setting('data_directory') LIKE '%%nvme%%'
            THEN 'nvme'
        WHEN current_setting('effective_io_concurrency')::int >= 200
            THEN 'ssd'
        WHEN current_setting('effective_io_concurrency')::int >= 2
            THEN 'hdd'
        ELSE 'cloud'
    END AS detected_storage
"""


class AsyncIOProfiler:
    """
    Profile I/O patterns and recommend PG18 async I/O configuration.
    """

    async def analyze(self, dsn: str) -> AsyncIOReport:
        """Run complete async I/O analysis."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        report = AsyncIOReport()
        conn = await asyncpg.connect(dsn)

        try:
            await self._detect_version(conn, report)
            await self._detect_io_config(conn, report)
            await self._detect_storage(conn, report)
            await self._profile_io_queries(conn, report)
            self._compute_recommendations(report)
        finally:
            await conn.close()

        return report

    async def _detect_version(self, conn: Any, report: AsyncIOReport) -> None:
        import re
        version = await conn.fetchval("SELECT current_setting('server_version_num')::int")
        report.pg_version = version // 10000
        report.is_pg18 = report.pg_version >= 18

    async def _detect_io_config(self, conn: Any, report: AsyncIOReport) -> None:
        if report.is_pg18:
            try:
                report.io_method = await conn.fetchval(
                    "SELECT setting FROM pg_settings WHERE name = 'io_method'"
                ) or "sync"
                icl = await conn.fetchval(
                    "SELECT setting FROM pg_settings WHERE name = 'io_combine_limit'"
                )
                report.io_combine_limit = int(icl) if icl else 0
            except Exception:
                pass

        try:
            tio = await conn.fetchval(
                "SELECT setting FROM pg_settings WHERE name = 'track_io_timing'"
            )
            report.track_io_timing = tio == "on"

            eic = await conn.fetchval(
                "SELECT setting FROM pg_settings WHERE name = 'effective_io_concurrency'"
            )
            report.effective_io_concurrency = int(eic) if eic else 0

            mic = await conn.fetchval(
                "SELECT setting FROM pg_settings WHERE name = 'maintenance_io_concurrency'"
            )
            report.maintenance_io_concurrency = int(mic) if mic else 0
        except Exception:
            pass

    async def _detect_storage(self, conn: Any, report: AsyncIOReport) -> None:
        try:
            row = await conn.fetchrow(_STORAGE_DETECTION_SQL)
            report.storage_type = row["detected_storage"] if row else "unknown"
        except Exception:
            report.storage_type = "unknown"

    async def _profile_io_queries(self, conn: Any, report: AsyncIOReport) -> None:
        sql = _IO_QUERIES_SQL if report.track_io_timing else _IO_QUERIES_NO_TIMING_SQL
        try:
            rows = await conn.fetch(sql)
        except Exception:
            return

        for row in rows:
            total_time = row["total_exec_time_ms"] or 0.001
            io_time = (row["blk_read_time_ms"] or 0) + (row["blk_write_time_ms"] or 0)
            hits = row["shared_blks_hit"] or 0
            reads = row["shared_blks_read"] or 0
            total_blocks = hits + reads

            if not report.track_io_timing and reads > 0:
                io_time = reads * 0.1

            io_pct = (io_time / total_time * 100) if total_time > 0 else 0.0
            chr_ = hits / total_blocks if total_blocks > 0 else 1.0

            report.top_io_queries.append(IOWaitQuery(
                queryid=row["queryid"],
                query=(row["query"] or "")[:500],
                calls=row["calls"],
                total_exec_time_ms=total_time,
                blk_read_time_ms=row["blk_read_time_ms"] or 0,
                blk_write_time_ms=row["blk_write_time_ms"] or 0,
                io_wait_pct=io_pct,
                shared_blks_read=reads,
                shared_blks_hit=hits,
                cache_hit_ratio=chr_,
            ))

            report.total_io_wait_ms += io_time
            report.total_exec_time_ms += total_time

        report.top_io_queries.sort(key=lambda q: -q.io_wait_pct)

        if report.total_exec_time_ms > 0:
            report.overall_io_wait_pct = (
                report.total_io_wait_ms / report.total_exec_time_ms * 100
            )

    def _compute_recommendations(self, report: AsyncIOReport) -> None:
        if report.storage_type in ("nvme", "ssd", "cloud"):
            report.recommended_effective_io_concurrency = 200
            report.recommended_io_combine_limit = 128
        else:
            report.recommended_effective_io_concurrency = 4
            report.recommended_io_combine_limit = 32

        if report.storage_type == "nvme":
            report.recommended_io_method = "io_uring"
        else:
            report.recommended_io_method = "worker"

        base_improvement = min(report.overall_io_wait_pct * 0.4, 50.0)

        if report.is_pg18 and report.io_method == "sync":
            report.estimated_improvement_pct = base_improvement
            report.findings.append({
                "severity": "warning",
                "title": "Async I/O available but not enabled",
                "fix": f"ALTER SYSTEM SET io_method = '{report.recommended_io_method}';",
            })
        elif not report.is_pg18:
            report.estimated_improvement_pct = base_improvement
            report.findings.append({
                "severity": "info",
                "title": f"Upgrade to PG18 for async I/O ({base_improvement:.0f}% est. improvement)",
                "fix": "Upgrade PostgreSQL to version 18",
            })
        else:
            report.estimated_improvement_pct = 0.0
            report.findings.append({
                "severity": "info",
                "title": "Async I/O already enabled",
                "fix": "No action needed",
            })

        if not report.track_io_timing:
            report.findings.append({
                "severity": "warning",
                "title": "track_io_timing is OFF — enable for accurate I/O profiling",
                "fix": "ALTER SYSTEM SET track_io_timing = on; SELECT pg_reload_conf();",
            })

        if report.effective_io_concurrency < report.recommended_effective_io_concurrency:
            report.findings.append({
                "severity": "notice",
                "title": (
                    f"effective_io_concurrency is {report.effective_io_concurrency} "
                    f"(recommended: {report.recommended_effective_io_concurrency} for {report.storage_type})"
                ),
                "fix": (
                    f"ALTER SYSTEM SET effective_io_concurrency = "
                    f"{report.recommended_effective_io_concurrency}; SELECT pg_reload_conf();"
                ),
            })
