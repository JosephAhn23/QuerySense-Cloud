"""
Plan Statistics Collector — Aurora aurora_stat_plans + pg_store_plans.

Extends QuerySense's existing pg_stat_plans module with support for:
1. Amazon Aurora's aurora_stat_plans (per-plan stats, no extension needed)
2. pg_store_plans extension (community, works on any PG12+)
3. Plan fingerprinting for cross-snapshot comparison
4. Plan regression detection (performance degradation after plan flip)
5. Plan history timeline

This complements src/querysense/pg_stat_plans.py (PG18 native) by adding
support for older PG versions and Aurora-managed environments.

Usage:
    from querysense.collectors.plan_statistics import PlanStatisticsCollector
    collector = PlanStatisticsCollector()
    stats = await collector.collect(dsn)
    changes = collector.detect_changes(stats, previous_stats)
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PlanSnapshot:
    """Statistics for a specific query plan from a single collection."""
    queryid: int
    planid: int
    plan_fingerprint: str
    calls: int
    total_time_ms: float
    mean_time_ms: float
    plan_source: str  # 'aurora_stat_plans', 'pg_store_plans', 'pg_stat_plans'
    explain_text: str = ""
    captured_at: datetime = field(default_factory=datetime.now)


@dataclass
class PlanFlip:
    """Detected plan change event."""
    queryid: int
    query_text: str
    old_planid: int
    new_planid: int
    old_mean_ms: float
    new_mean_ms: float
    performance_delta_pct: float
    severity: str  # CRITICAL, WARNING, INFO
    detected_at: datetime = field(default_factory=datetime.now)


@dataclass
class CollectionReport:
    """Result of a plan statistics collection run."""
    source: str = ""
    plans_collected: int = 0
    snapshots: list[PlanSnapshot] = field(default_factory=list)
    plan_flips: list[PlanFlip] = field(default_factory=list)
    regressions: list[PlanFlip] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "plans_collected": self.plans_collected,
            "plan_flips": len(self.plan_flips),
            "regressions": [
                {
                    "queryid": r.queryid,
                    "old_ms": round(r.old_mean_ms, 2),
                    "new_ms": round(r.new_mean_ms, 2),
                    "delta_pct": round(r.performance_delta_pct, 1),
                    "severity": r.severity,
                }
                for r in self.regressions
            ],
        }


class PlanStatisticsCollector:
    """
    Collect per-plan statistics from PostgreSQL.

    Supports three backends (auto-detected in priority order):
    1. pg_stat_plans (PG18+ native, highest fidelity)
    2. aurora_stat_plans (Aurora-managed, no extension needed)
    3. pg_store_plans (community extension, PG12+)
    """

    def __init__(self) -> None:
        self._previous: dict[int, PlanSnapshot] = {}

    async def collect(
        self,
        dsn: str,
        top_n: int = 100,
    ) -> CollectionReport:
        """
        Auto-detect the best available backend and collect plan stats.
        """
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        report = CollectionReport()

        try:
            # Try backends in priority order
            source, snapshots = await self._try_pg_stat_plans(conn, top_n)
            if not snapshots:
                source, snapshots = await self._try_aurora_stat_plans(conn, top_n)
            if not snapshots:
                source, snapshots = await self._try_pg_store_plans(conn, top_n)

            report.source = source
            report.plans_collected = len(snapshots)
            report.snapshots = snapshots

            # Detect plan changes against previous collection
            report.plan_flips = self._detect_flips(snapshots)
            report.regressions = [
                f for f in report.plan_flips if f.performance_delta_pct > 0
            ]

            # Update previous state
            for snap in snapshots:
                self._previous[snap.queryid] = snap

        finally:
            await conn.close()

        return report

    # ── Backend: pg_stat_plans (PG18+) ───────────────────────────────

    async def _try_pg_stat_plans(
        self, conn: Any, top_n: int,
    ) -> tuple[str, list[PlanSnapshot]]:
        has = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_plans'
            )
        """)
        if not has:
            return "", []

        rows = await conn.fetch("""
            SELECT
                queryid, planid, calls,
                total_exec_time AS total_time,
                mean_exec_time AS mean_time,
                query
            FROM pg_stat_plans
            WHERE queryid IS NOT NULL AND calls > 0
            ORDER BY total_exec_time DESC
            LIMIT $1
        """, top_n)

        snapshots = [
            PlanSnapshot(
                queryid=r["queryid"], planid=r["planid"],
                plan_fingerprint=self._fingerprint(str(r["planid"])),
                calls=r["calls"],
                total_time_ms=r["total_time"],
                mean_time_ms=r["mean_time"],
                plan_source="pg_stat_plans",
                explain_text=r.get("query", ""),
            )
            for r in rows
        ]
        return "pg_stat_plans", snapshots

    # ── Backend: aurora_stat_plans (Aurora) ───────────────────────────

    async def _try_aurora_stat_plans(
        self, conn: Any, top_n: int,
    ) -> tuple[str, list[PlanSnapshot]]:
        has = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM pg_proc WHERE proname = 'aurora_stat_plans'
            )
        """)
        if not has:
            return "", []

        rows = await conn.fetch("""
            SELECT
                queryid, planid, calls,
                total_time, mean_exec_time,
                plan_type, plan_captured_time, explain_plan
            FROM aurora_stat_plans(true)
            WHERE queryid IS NOT NULL AND calls > 0
            ORDER BY total_time DESC
            LIMIT $1
        """, top_n)

        snapshots = [
            PlanSnapshot(
                queryid=r["queryid"], planid=r["planid"],
                plan_fingerprint=self._fingerprint(r.get("explain_plan", "")),
                calls=r["calls"],
                total_time_ms=r["total_time"],
                mean_time_ms=r["mean_exec_time"],
                plan_source="aurora_stat_plans",
                explain_text=r.get("explain_plan", ""),
                captured_at=r.get("plan_captured_time", datetime.now()),
            )
            for r in rows
        ]
        return "aurora_stat_plans", snapshots

    # ── Backend: pg_store_plans (community) ──────────────────────────

    async def _try_pg_store_plans(
        self, conn: Any, top_n: int,
    ) -> tuple[str, list[PlanSnapshot]]:
        has = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM pg_extension WHERE extname = 'pg_store_plans'
            )
        """)
        if not has:
            return "", []

        rows = await conn.fetch("""
            SELECT
                queryid, planid, calls,
                total_time, mean_time
            FROM pg_store_plans
            WHERE queryid IS NOT NULL AND calls > 0
            ORDER BY total_time DESC
            LIMIT $1
        """, top_n)

        snapshots = [
            PlanSnapshot(
                queryid=r["queryid"], planid=r["planid"],
                plan_fingerprint=self._fingerprint(str(r["planid"])),
                calls=r["calls"],
                total_time_ms=r["total_time"],
                mean_time_ms=r["mean_time"],
                plan_source="pg_store_plans",
            )
            for r in rows
        ]
        return "pg_store_plans", snapshots

    # ── Plan change detection ────────────────────────────────────────

    def _detect_flips(
        self, current: list[PlanSnapshot],
    ) -> list[PlanFlip]:
        if not self._previous:
            return []

        flips: list[PlanFlip] = []
        for snap in current:
            prev = self._previous.get(snap.queryid)
            if not prev:
                continue
            if prev.planid == snap.planid:
                continue

            delta = (
                (snap.mean_time_ms - prev.mean_time_ms) / prev.mean_time_ms * 100
                if prev.mean_time_ms > 0 else 0
            )

            if abs(delta) > 50:
                severity = "CRITICAL"
            elif abs(delta) > 20:
                severity = "WARNING"
            else:
                severity = "INFO"

            flips.append(PlanFlip(
                queryid=snap.queryid,
                query_text=snap.explain_text[:200],
                old_planid=prev.planid,
                new_planid=snap.planid,
                old_mean_ms=prev.mean_time_ms,
                new_mean_ms=snap.mean_time_ms,
                performance_delta_pct=round(delta, 1),
                severity=severity,
            ))

        return sorted(flips, key=lambda f: abs(f.performance_delta_pct), reverse=True)

    # ── Plan fingerprinting ──────────────────────────────────────────

    @staticmethod
    def _fingerprint(plan_text: str) -> str:
        """
        Normalize an EXPLAIN plan to a structural fingerprint.

        Strips costs, timings, buffer counts so that structurally
        identical plans produce the same hash.
        """
        normalized = re.sub(r"actual time=[\d.]+\.\.[\d.]+", "", plan_text)
        normalized = re.sub(r"cost=[\d.]+\.\.[\d.]+", "", normalized)
        normalized = re.sub(r"rows=\d+", "", normalized)
        normalized = re.sub(r"width=\d+", "", normalized)
        normalized = re.sub(r"Buffers:.*", "", normalized)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]
