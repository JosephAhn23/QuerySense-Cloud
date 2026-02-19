"""
Query Load Profiler — Workload attribution from pg_stat_statements.

"This new feature was responsible for 20% of the application's query load."
    — Ben Hughes, Software Engineer, Notion

Analyzes pg_stat_statements to:
    1. Profile top queries by % of total CPU time, I/O, and calls
    2. Detect query load spikes (queries that grew significantly)
    3. Identify resource hogs (high mean time, high total time)
    4. Group queries by table/pattern for workload attribution

Usage:
    from querysense.audit.query_load import QueryLoadProfiler

    profiler = QueryLoadProfiler()
    report = await profiler.analyze(conn)
    for q in report.top_by_time[:10]:
        print(f"{q.pct_total_time:.1f}% | {q.mean_time_ms:.1f}ms | {q.query[:60]}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class QueryProfile:
    """Profile of a single normalized query."""

    queryid: int = 0
    query: str = ""
    calls: int = 0
    total_time_ms: float = 0.0
    mean_time_ms: float = 0.0
    min_time_ms: float = 0.0
    max_time_ms: float = 0.0
    stddev_time_ms: float = 0.0
    rows: int = 0
    shared_blks_hit: int = 0
    shared_blks_read: int = 0
    temp_blks_written: int = 0
    blk_read_time_ms: float = 0.0
    blk_write_time_ms: float = 0.0

    # Computed: % of total workload
    pct_total_time: float = 0.0
    pct_total_calls: float = 0.0
    pct_total_io: float = 0.0

    # Extracted table name (best effort)
    primary_table: str = ""

    @property
    def cache_hit_ratio(self) -> float:
        total = self.shared_blks_hit + self.shared_blks_read
        if total == 0:
            return 1.0
        return self.shared_blks_hit / total

    @property
    def is_spilling(self) -> bool:
        return self.temp_blks_written > 0

    @property
    def time_variance(self) -> float:
        """Coefficient of variation (stddev/mean). High = unstable."""
        if self.mean_time_ms == 0:
            return 0
        return self.stddev_time_ms / self.mean_time_ms

    def to_dict(self) -> dict[str, Any]:
        return {
            "queryid": self.queryid,
            "query": self.query[:300],
            "calls": self.calls,
            "total_time_ms": round(self.total_time_ms, 1),
            "mean_time_ms": round(self.mean_time_ms, 2),
            "max_time_ms": round(self.max_time_ms, 1),
            "rows": self.rows,
            "pct_total_time": round(self.pct_total_time, 2),
            "pct_total_calls": round(self.pct_total_calls, 2),
            "cache_hit_ratio": round(self.cache_hit_ratio, 4),
            "is_spilling": self.is_spilling,
            "primary_table": self.primary_table,
        }


@dataclass
class TableLoadProfile:
    """Aggregate load attributed to a single table."""

    table: str = ""
    total_time_ms: float = 0.0
    total_calls: int = 0
    query_count: int = 0
    pct_total_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "total_time_ms": round(self.total_time_ms, 1),
            "total_calls": self.total_calls,
            "query_count": self.query_count,
            "pct_total_time": round(self.pct_total_time, 2),
        }


@dataclass
class QueryLoadFinding:
    """A query load finding."""

    severity: str
    title: str
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass
class QueryLoadReport:
    """Complete query load profiling report."""

    top_by_time: list[QueryProfile] = field(default_factory=list)
    top_by_calls: list[QueryProfile] = field(default_factory=list)
    top_by_mean_time: list[QueryProfile] = field(default_factory=list)
    table_load: list[TableLoadProfile] = field(default_factory=list)
    findings: list[QueryLoadFinding] = field(default_factory=list)
    total_queries: int = 0
    total_time_ms: float = 0.0
    total_calls: int = 0
    stats_reset: str = ""

    @property
    def summary(self) -> str:
        return (
            f"{self.total_queries} unique queries, "
            f"{self.total_calls:,} total calls, "
            f"{self.total_time_ms / 1000:.0f}s total CPU time"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_queries": self.total_queries,
            "total_calls": self.total_calls,
            "total_time_ms": round(self.total_time_ms, 1),
            "top_by_time": [q.to_dict() for q in self.top_by_time],
            "top_by_calls": [q.to_dict() for q in self.top_by_calls],
            "top_by_mean_time": [q.to_dict() for q in self.top_by_mean_time],
            "table_load": [t.to_dict() for t in self.table_load],
            "findings": [f.to_dict() for f in self.findings],
        }


# Table extraction from SQL
_TABLE_PATTERN = re.compile(
    r"(?:FROM|JOIN|UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+"
    r"(?:ONLY\s+)?\"?(\w+)\"?\.?\"?(\w+)?\"?",
    re.IGNORECASE,
)


class QueryLoadProfiler:
    """
    Profile query workload from pg_stat_statements.

    Shows which queries consume what % of total CPU, I/O, and calls.
    Detects resource hogs, unstable queries, and table-level attribution.
    """

    def __init__(self, top_n: int = 25) -> None:
        self.top_n = top_n

    async def analyze(self, conn: AsyncDBConnection) -> QueryLoadReport:
        """Run full query load analysis."""
        report = QueryLoadReport()

        # Check pg_stat_statements is available
        try:
            report.stats_reset = str(
                await conn.fetchval(
                    "SELECT stats_reset::text FROM pg_stat_database "
                    "WHERE datname = current_database()"
                ) or ""
            )
        except Exception:
            pass

        profiles = await self._collect_profiles(conn)
        if not profiles:
            report.findings.append(QueryLoadFinding(
                severity="warning",
                title="pg_stat_statements not available",
                description="Cannot profile queries without pg_stat_statements extension.",
                recommendation="CREATE EXTENSION IF NOT EXISTS pg_stat_statements;",
            ))
            return report

        # Calculate totals
        report.total_time_ms = sum(p.total_time_ms for p in profiles)
        report.total_calls = sum(p.calls for p in profiles)
        report.total_queries = len(profiles)

        # Calculate percentages
        for p in profiles:
            if report.total_time_ms > 0:
                p.pct_total_time = (p.total_time_ms / report.total_time_ms) * 100
            if report.total_calls > 0:
                p.pct_total_calls = (p.calls / report.total_calls) * 100
            p.primary_table = self._extract_table(p.query)

        # Build sorted lists
        report.top_by_time = sorted(profiles, key=lambda p: -p.total_time_ms)[:self.top_n]
        report.top_by_calls = sorted(profiles, key=lambda p: -p.calls)[:self.top_n]
        report.top_by_mean_time = sorted(
            [p for p in profiles if p.calls >= 10],
            key=lambda p: -p.mean_time_ms,
        )[:self.top_n]

        # Table-level attribution
        report.table_load = self._build_table_load(profiles, report.total_time_ms)

        # Generate findings
        self._generate_findings(report, profiles)

        return report

    async def _collect_profiles(self, conn: AsyncDBConnection) -> list[QueryProfile]:
        """Collect query profiles from pg_stat_statements."""
        try:
            rows = await conn.fetch(
                "SELECT "
                "  queryid, query, calls, "
                "  total_exec_time AS total_time, "
                "  mean_exec_time AS mean_time, "
                "  min_exec_time AS min_time, "
                "  max_exec_time AS max_time, "
                "  stddev_exec_time AS stddev_time, "
                "  rows, "
                "  shared_blks_hit, shared_blks_read, "
                "  temp_blks_written, "
                "  blk_read_time, blk_write_time "
                "FROM pg_stat_statements "
                "WHERE calls > 0 "
                "ORDER BY total_exec_time DESC "
                "LIMIT 500"
            )
        except Exception:
            # Try older column names (PG < 13)
            try:
                rows = await conn.fetch(
                    "SELECT "
                    "  queryid, query, calls, "
                    "  total_time, mean_time, min_time, max_time, stddev_time, "
                    "  rows, "
                    "  shared_blks_hit, shared_blks_read, "
                    "  temp_blks_written, "
                    "  blk_read_time, blk_write_time "
                    "FROM pg_stat_statements "
                    "WHERE calls > 0 "
                    "ORDER BY total_time DESC "
                    "LIMIT 500"
                )
            except Exception:
                return []

        profiles: list[QueryProfile] = []
        for r in rows:
            if isinstance(r, (list, tuple)):
                vals = list(r)
            else:
                vals = [
                    getattr(r, "queryid", 0),
                    getattr(r, "query", ""),
                    getattr(r, "calls", 0),
                    getattr(r, "total_time", 0),
                    getattr(r, "mean_time", 0),
                    getattr(r, "min_time", 0),
                    getattr(r, "max_time", 0),
                    getattr(r, "stddev_time", 0),
                    getattr(r, "rows", 0),
                    getattr(r, "shared_blks_hit", 0),
                    getattr(r, "shared_blks_read", 0),
                    getattr(r, "temp_blks_written", 0),
                    getattr(r, "blk_read_time", 0),
                    getattr(r, "blk_write_time", 0),
                ]

            profiles.append(QueryProfile(
                queryid=int(vals[0] or 0),
                query=str(vals[1] or ""),
                calls=int(vals[2] or 0),
                total_time_ms=float(vals[3] or 0),
                mean_time_ms=float(vals[4] or 0),
                min_time_ms=float(vals[5] or 0),
                max_time_ms=float(vals[6] or 0),
                stddev_time_ms=float(vals[7] or 0),
                rows=int(vals[8] or 0),
                shared_blks_hit=int(vals[9] or 0),
                shared_blks_read=int(vals[10] or 0),
                temp_blks_written=int(vals[11] or 0),
                blk_read_time_ms=float(vals[12] or 0),
                blk_write_time_ms=float(vals[13] or 0),
            ))

        return profiles

    @staticmethod
    def _extract_table(query: str) -> str:
        """Extract primary table name from a query."""
        match = _TABLE_PATTERN.search(query)
        if match:
            schema, table = match.groups()
            if table:
                return f"{schema}.{table}"
            return schema
        return ""

    @staticmethod
    def _build_table_load(
        profiles: list[QueryProfile],
        total_time: float,
    ) -> list[TableLoadProfile]:
        """Aggregate query load by table."""
        table_map: dict[str, TableLoadProfile] = {}
        for p in profiles:
            tbl = p.primary_table or "(unknown)"
            if tbl not in table_map:
                table_map[tbl] = TableLoadProfile(table=tbl)
            table_map[tbl].total_time_ms += p.total_time_ms
            table_map[tbl].total_calls += p.calls
            table_map[tbl].query_count += 1

        for t in table_map.values():
            if total_time > 0:
                t.pct_total_time = (t.total_time_ms / total_time) * 100

        return sorted(table_map.values(), key=lambda t: -t.total_time_ms)

    def _generate_findings(
        self,
        report: QueryLoadReport,
        profiles: list[QueryProfile],
    ) -> None:
        """Generate findings about query load patterns."""
        # Finding: single query dominating workload
        for p in report.top_by_time[:3]:
            if p.pct_total_time > 30:
                report.findings.append(QueryLoadFinding(
                    severity="warning",
                    title=f"Query dominates workload: {p.pct_total_time:.0f}% of total time",
                    description=f"Query: {p.query[:100]}...",
                    recommendation="Optimize this query or review if it can be cached/batched.",
                    evidence={"queryid": p.queryid, "pct": round(p.pct_total_time, 1)},
                ))

        # Finding: table dominates workload
        for t in report.table_load[:3]:
            if t.pct_total_time > 40:
                report.findings.append(QueryLoadFinding(
                    severity="warning",
                    title=f"Table '{t.table}' accounts for {t.pct_total_time:.0f}% of query load",
                    description=(
                        f"{t.query_count} different queries on '{t.table}' "
                        f"consume {t.pct_total_time:.0f}% of total CPU time."
                    ),
                    recommendation="Review indexes and query patterns on this table.",
                    evidence={"table": t.table, "pct": round(t.pct_total_time, 1)},
                ))

        # Finding: queries with high variance (unstable)
        unstable = [p for p in profiles if p.time_variance > 5.0 and p.calls >= 10]
        for p in sorted(unstable, key=lambda p: -p.time_variance)[:5]:
            report.findings.append(QueryLoadFinding(
                severity="notice",
                title=f"Unstable query: mean={p.mean_time_ms:.0f}ms, max={p.max_time_ms:.0f}ms",
                description=(
                    f"Query has high time variance (CV={p.time_variance:.1f}). "
                    f"This may indicate plan instability or lock contention. "
                    f"Query: {p.query[:100]}..."
                ),
                recommendation="Check for plan flips with: querysense audit plan-record",
                evidence={"mean_ms": round(p.mean_time_ms, 1), "max_ms": round(p.max_time_ms, 1)},
            ))

        # Finding: queries spilling to disk
        spilling = [p for p in profiles if p.is_spilling]
        if spilling:
            total_spill = sum(p.temp_blks_written for p in spilling) * 8192
            report.findings.append(QueryLoadFinding(
                severity="warning",
                title=f"{len(spilling)} queries spilling to temp files ({total_spill // (1024*1024)}MB)",
                description="Queries are running out of work_mem and writing temp files.",
                recommendation="Increase work_mem or optimize the queries.",
                evidence={"spilling_queries": len(spilling)},
            ))
