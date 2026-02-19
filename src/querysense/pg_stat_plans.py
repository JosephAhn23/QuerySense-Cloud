"""
pg_stat_plans Integration — plan-level metrics tracking.

pganalyze announced pg_stat_plans as their new open-source extension
for PostgreSQL 18, leveraging the PlannedStmt.PlanID column.

This module provides:
1. Detection of pg_stat_plans availability
2. Plan-level metrics collection (execution time, calls, rows per plan)
3. Plan change detection — alert when a query switches plans
4. Plan regression detection — detect when a new plan is slower
5. Historical plan tracking — store plan hashes over time

Works with PG18+ (native pg_stat_plans) and PG14-17 (queryid-based fallback).

Usage:
    from querysense.pg_stat_plans import PlanTracker
    tracker = PlanTracker()
    report = await tracker.analyze(dsn)
    for change in report.plan_changes:
        print(f"Query {change.queryid}: plan changed, {change.regression_pct}% slower")
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PlanMetrics:
    """Metrics for a specific plan of a query."""
    plan_id: str = ""
    queryid: int = 0
    query_text: str = ""
    calls: int = 0
    total_exec_time_ms: float = 0
    mean_exec_time_ms: float = 0
    min_exec_time_ms: float = 0
    max_exec_time_ms: float = 0
    rows: int = 0
    shared_blks_hit: int = 0
    shared_blks_read: int = 0
    plan_text: str = ""

    @property
    def cache_hit_ratio(self) -> float:
        total = self.shared_blks_hit + self.shared_blks_read
        if total == 0:
            return 1.0
        return self.shared_blks_hit / total


@dataclass
class PlanChange:
    """Detected plan change for a query."""
    queryid: int
    query_text: str = ""
    old_plan_id: str = ""
    new_plan_id: str = ""
    old_mean_time_ms: float = 0
    new_mean_time_ms: float = 0
    regression_pct: float = 0  # Positive = slower, negative = faster
    is_regression: bool = False


@dataclass
class PlanTrackerReport:
    """Report from plan tracking analysis."""
    has_pg_stat_plans: bool = False
    pg_version: int = 0
    total_plans: int = 0
    total_queries: int = 0
    plans: list[PlanMetrics] = field(default_factory=list)
    plan_changes: list[PlanChange] = field(default_factory=list)
    queries_with_multiple_plans: list[dict[str, Any]] = field(default_factory=list)
    top_volatile_queries: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_pg_stat_plans": self.has_pg_stat_plans,
            "pg_version": self.pg_version,
            "total_plans": self.total_plans,
            "total_queries": self.total_queries,
            "plan_changes": len(self.plan_changes),
            "regressions": sum(1 for c in self.plan_changes if c.is_regression),
            "multi_plan_queries": len(self.queries_with_multiple_plans),
        }


class PlanTracker:
    """
    Track plan-level metrics and detect plan changes.

    On PG18+: Uses pg_stat_plans extension for native plan tracking.
    On PG14-17: Falls back to pg_stat_statements queryid + plan hash detection.
    """

    def __init__(self) -> None:
        self._baseline: dict[int, PlanMetrics] = {}

    async def analyze(
        self,
        dsn: str,
        top_n: int = 50,
        min_calls: int = 5,
    ) -> PlanTrackerReport:
        """
        Analyze plan-level metrics.

        Detects:
        - Queries with multiple active plans
        - Plan changes since last baseline
        - Performance regressions from plan changes
        """
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        report = PlanTrackerReport()
        conn = await asyncpg.connect(dsn)

        try:
            # Detect version
            version = await conn.fetchval(
                "SELECT current_setting('server_version_num')::int"
            )
            report.pg_version = version

            # Check for pg_stat_plans
            report.has_pg_stat_plans = await self._check_extension(conn)

            if report.has_pg_stat_plans:
                await self._analyze_with_pg_stat_plans(conn, report, top_n, min_calls)
            else:
                await self._analyze_with_pg_stat_statements(conn, report, top_n, min_calls)

            # Detect plan changes against baseline
            self._detect_plan_changes(report)

        finally:
            await conn.close()

        return report

    async def snapshot(self, dsn: str) -> dict[int, PlanMetrics]:
        """
        Take a snapshot of current plan metrics for future comparison.

        Store this and pass to detect_changes() later.
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required")

        conn = await asyncpg.connect(dsn)
        try:
            has_ext = await self._check_extension(conn)
            plans: dict[int, PlanMetrics] = {}

            if has_ext:
                rows = await conn.fetch("""
                    SELECT
                        planid::text AS plan_id,
                        queryid,
                        calls,
                        total_exec_time AS total_time,
                        mean_exec_time AS mean_time,
                        rows
                    FROM pg_stat_plans
                    WHERE calls > 0
                """)
            else:
                rows = await conn.fetch("""
                    SELECT
                        queryid,
                        calls,
                        mean_exec_time AS mean_time,
                        total_exec_time AS total_time,
                        rows,
                        query
                    FROM pg_stat_statements
                    WHERE calls > 0
                    ORDER BY total_exec_time DESC
                    LIMIT 200
                """)

            for row in rows:
                qid = int(row["queryid"])
                plans[qid] = PlanMetrics(
                    plan_id=str(row.get("plan_id", qid)),
                    queryid=qid,
                    calls=row["calls"],
                    total_exec_time_ms=float(row["total_time"]),
                    mean_exec_time_ms=float(row["mean_time"]),
                    rows=row["rows"],
                    query_text=row.get("query", ""),
                )

            self._baseline = plans
            return plans

        finally:
            await conn.close()

    def detect_changes(
        self,
        current: dict[int, PlanMetrics],
        baseline: dict[int, PlanMetrics] | None = None,
        regression_threshold: float = 50.0,
    ) -> list[PlanChange]:
        """
        Compare current plan metrics against a baseline.

        Args:
            current: Current plan metrics snapshot
            baseline: Previous snapshot (uses internal baseline if None)
            regression_threshold: Percentage increase to flag as regression
        """
        base = baseline or self._baseline
        changes: list[PlanChange] = []

        for qid, curr in current.items():
            if qid not in base:
                continue

            prev = base[qid]

            # Plan ID changed
            if curr.plan_id != prev.plan_id:
                pct = 0.0
                if prev.mean_exec_time_ms > 0:
                    pct = (
                        (curr.mean_exec_time_ms - prev.mean_exec_time_ms)
                        / prev.mean_exec_time_ms * 100
                    )

                changes.append(PlanChange(
                    queryid=qid,
                    query_text=curr.query_text or prev.query_text,
                    old_plan_id=prev.plan_id,
                    new_plan_id=curr.plan_id,
                    old_mean_time_ms=prev.mean_exec_time_ms,
                    new_mean_time_ms=curr.mean_exec_time_ms,
                    regression_pct=pct,
                    is_regression=pct > regression_threshold,
                ))

            # Same plan but significant time increase
            elif prev.mean_exec_time_ms > 0:
                pct = (
                    (curr.mean_exec_time_ms - prev.mean_exec_time_ms)
                    / prev.mean_exec_time_ms * 100
                )
                if pct > regression_threshold:
                    changes.append(PlanChange(
                        queryid=qid,
                        query_text=curr.query_text or prev.query_text,
                        old_plan_id=prev.plan_id,
                        new_plan_id=curr.plan_id,
                        old_mean_time_ms=prev.mean_exec_time_ms,
                        new_mean_time_ms=curr.mean_exec_time_ms,
                        regression_pct=pct,
                        is_regression=True,
                    ))

        return sorted(changes, key=lambda c: c.regression_pct, reverse=True)

    # ── Internal methods ─────────────────────────────────────────────

    async def _check_extension(self, conn: Any) -> bool:
        """Check if pg_stat_plans extension is installed."""
        try:
            row = await conn.fetchval("""
                SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_plans'
            """)
            return row is not None
        except Exception:
            return False

    async def _analyze_with_pg_stat_plans(
        self, conn: Any, report: PlanTrackerReport,
        top_n: int, min_calls: int,
    ) -> None:
        """Analyze using native pg_stat_plans extension (PG18+)."""
        rows = await conn.fetch(f"""
            SELECT
                p.planid::text AS plan_id,
                p.queryid,
                s.query,
                p.calls,
                p.total_exec_time,
                p.mean_exec_time,
                p.min_exec_time,
                p.max_exec_time,
                p.rows,
                p.shared_blks_hit,
                p.shared_blks_read
            FROM pg_stat_plans p
            JOIN pg_stat_statements s ON p.queryid = s.queryid
            WHERE p.calls >= $1
            ORDER BY p.total_exec_time DESC
            LIMIT $2
        """, min_calls, top_n)

        seen_queryids: dict[int, int] = {}
        for row in rows:
            pm = PlanMetrics(
                plan_id=row["plan_id"],
                queryid=int(row["queryid"]),
                query_text=row["query"],
                calls=row["calls"],
                total_exec_time_ms=float(row["total_exec_time"]),
                mean_exec_time_ms=float(row["mean_exec_time"]),
                min_exec_time_ms=float(row.get("min_exec_time", 0)),
                max_exec_time_ms=float(row.get("max_exec_time", 0)),
                rows=row["rows"],
                shared_blks_hit=row["shared_blks_hit"],
                shared_blks_read=row["shared_blks_read"],
            )
            report.plans.append(pm)

            qid = int(row["queryid"])
            seen_queryids[qid] = seen_queryids.get(qid, 0) + 1

        report.total_plans = len(report.plans)
        report.total_queries = len(seen_queryids)

        # Queries with multiple plans
        for qid, count in seen_queryids.items():
            if count > 1:
                plans_for_query = [p for p in report.plans if p.queryid == qid]
                report.queries_with_multiple_plans.append({
                    "queryid": qid,
                    "query": plans_for_query[0].query_text[:200] if plans_for_query else "",
                    "plan_count": count,
                    "time_variance": max(p.mean_exec_time_ms for p in plans_for_query)
                                   - min(p.mean_exec_time_ms for p in plans_for_query),
                })

    async def _analyze_with_pg_stat_statements(
        self, conn: Any, report: PlanTrackerReport,
        top_n: int, min_calls: int,
    ) -> None:
        """Fallback: use pg_stat_statements with queryid-based tracking."""
        rows = await conn.fetch(f"""
            SELECT
                queryid,
                query,
                calls,
                total_exec_time,
                mean_exec_time,
                min_exec_time,
                max_exec_time,
                rows,
                shared_blks_hit,
                shared_blks_read
            FROM pg_stat_statements
            WHERE calls >= $1
            ORDER BY total_exec_time DESC
            LIMIT $2
        """, min_calls, top_n)

        for row in rows:
            query_hash = hashlib.md5(
                row["query"].encode()
            ).hexdigest()[:12]

            pm = PlanMetrics(
                plan_id=f"qid_{row['queryid']}_{query_hash}",
                queryid=int(row["queryid"]),
                query_text=row["query"],
                calls=row["calls"],
                total_exec_time_ms=float(row["total_exec_time"]),
                mean_exec_time_ms=float(row["mean_exec_time"]),
                min_exec_time_ms=float(row.get("min_exec_time", 0)),
                max_exec_time_ms=float(row.get("max_exec_time", 0)),
                rows=row["rows"],
                shared_blks_hit=row["shared_blks_hit"],
                shared_blks_read=row["shared_blks_read"],
            )
            report.plans.append(pm)

            # Detect plan instability via time variance
            if pm.max_exec_time_ms > pm.mean_exec_time_ms * 10:
                report.top_volatile_queries.append({
                    "queryid": pm.queryid,
                    "query": pm.query_text[:200],
                    "mean_ms": pm.mean_exec_time_ms,
                    "max_ms": pm.max_exec_time_ms,
                    "variance_ratio": pm.max_exec_time_ms / pm.mean_exec_time_ms
                        if pm.mean_exec_time_ms > 0 else 0,
                })

        report.total_plans = len(report.plans)
        report.total_queries = len(report.plans)

    def _detect_plan_changes(self, report: PlanTrackerReport) -> None:
        """Detect plan changes against internal baseline."""
        if not self._baseline:
            # First run — set baseline
            for pm in report.plans:
                self._baseline[pm.queryid] = pm
            return

        current = {pm.queryid: pm for pm in report.plans}
        report.plan_changes = self.detect_changes(current)
