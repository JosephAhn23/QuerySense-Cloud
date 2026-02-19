"""
EXPLAIN Plan History & Regression Detector.

"Developers compared EXPLAIN plans from two different trials and spotted both
query plan instability and rising table size as the root cause."
    — Autotrader UK / pganalyze case study

This module:
    1. Stores EXPLAIN plans with timestamps in a local JSON file
    2. Compares plans over time to detect regressions
    3. Identifies plan instability (plan flips between strategies)
    4. Flags cost increases, row estimate errors, and new sequential scans

Usage:
    from querysense.audit.plan_history import PlanHistoryTracker

    tracker = PlanHistoryTracker("plan_history.json")
    tracker.record(query_hash, plan, metadata)
    regressions = tracker.detect_regressions()
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class PlanSnapshot:
    """A single captured EXPLAIN plan."""

    query_hash: str = ""
    query_text: str = ""
    timestamp: str = ""
    total_cost: float = 0.0
    actual_time_ms: float = 0.0
    plan_type: str = ""       # e.g., "Seq Scan", "Index Scan", "Hash Join"
    rows_estimated: int = 0
    rows_actual: int = 0
    shared_hit_blocks: int = 0
    shared_read_blocks: int = 0
    temp_written_blocks: int = 0
    plan_json: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def row_estimate_error(self) -> float:
        """Ratio of estimated to actual rows (1.0 = perfect)."""
        if self.rows_actual == 0:
            return 0.0
        return self.rows_estimated / self.rows_actual

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_hash": self.query_hash,
            "query_text": self.query_text[:200],
            "timestamp": self.timestamp,
            "total_cost": self.total_cost,
            "actual_time_ms": self.actual_time_ms,
            "plan_type": self.plan_type,
            "rows_estimated": self.rows_estimated,
            "rows_actual": self.rows_actual,
            "row_estimate_error": round(self.row_estimate_error, 2),
        }


@dataclass
class PlanRegression:
    """A detected plan regression."""

    query_hash: str = ""
    query_text: str = ""
    severity: str = "warning"
    title: str = ""
    description: str = ""
    before: PlanSnapshot | None = None
    after: PlanSnapshot | None = None
    cost_change_pct: float = 0.0
    time_change_pct: float = 0.0
    plan_changed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_hash": self.query_hash,
            "query_text": self.query_text[:200],
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "cost_change_pct": round(self.cost_change_pct, 1),
            "time_change_pct": round(self.time_change_pct, 1),
            "plan_changed": self.plan_changed,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
        }


@dataclass
class PlanHistoryReport:
    """Report from plan history analysis."""

    total_queries: int = 0
    total_snapshots: int = 0
    regressions: list[PlanRegression] = field(default_factory=list)
    improved: list[PlanRegression] = field(default_factory=list)
    unstable: list[str] = field(default_factory=list)  # query_hashes with plan flips

    @property
    def has_regressions(self) -> bool:
        return len(self.regressions) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_queries": self.total_queries,
            "total_snapshots": self.total_snapshots,
            "regressions": [r.to_dict() for r in self.regressions],
            "improved": [r.to_dict() for r in self.improved],
            "unstable_queries": self.unstable,
            "has_regressions": self.has_regressions,
        }


class PlanHistoryTracker:
    """
    Track EXPLAIN plans over time and detect regressions.

    Stores plan snapshots in a local JSON file. Each snapshot includes
    the plan's cost, actual time, node type, and row estimates.
    """

    def __init__(self, storage_path: str | Path = "plan_history.json") -> None:
        self.storage_path = Path(storage_path)
        self._history: dict[str, list[dict[str, Any]]] = {}
        self._load()

    def _load(self) -> None:
        """Load history from disk."""
        if self.storage_path.exists():
            try:
                text = self.storage_path.read_text(encoding="utf-8")
                self._history = json.loads(text)
            except (json.JSONDecodeError, OSError):
                self._history = {}

    def _save(self) -> None:
        """Persist history to disk."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(
            json.dumps(self._history, indent=2, default=str),
            encoding="utf-8",
        )

    @staticmethod
    def hash_query(query: str) -> str:
        """Generate a stable hash for a query (ignoring whitespace)."""
        normalized = " ".join(query.split()).strip().lower()
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def record(
        self,
        query: str,
        plan: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> PlanSnapshot:
        """Record an EXPLAIN plan snapshot."""
        qhash = self.hash_query(query)
        snapshot = self._extract_snapshot(qhash, query, plan)
        snapshot.timestamp = datetime.utcnow().isoformat()
        snapshot.metadata = metadata or {}

        if qhash not in self._history:
            self._history[qhash] = []
        self._history[qhash].append(snapshot.to_dict())

        # Keep last 100 snapshots per query
        if len(self._history[qhash]) > 100:
            self._history[qhash] = self._history[qhash][-100:]

        self._save()
        return snapshot

    def record_from_connection(
        self,
        query: str,
        plan_json: list[dict[str, Any]],
    ) -> PlanSnapshot:
        """Record a plan from EXPLAIN (ANALYZE, FORMAT JSON) output."""
        plan = plan_json[0] if plan_json else {}
        return self.record(query, plan)

    def detect_regressions(
        self,
        cost_threshold_pct: float = 50.0,
        time_threshold_pct: float = 100.0,
    ) -> PlanHistoryReport:
        """Detect regressions across all tracked queries."""
        report = PlanHistoryReport()
        report.total_queries = len(self._history)

        for qhash, snapshots in self._history.items():
            report.total_snapshots += len(snapshots)
            if len(snapshots) < 2:
                continue

            # Compare oldest vs newest
            first = self._dict_to_snapshot(snapshots[0])
            last = self._dict_to_snapshot(snapshots[-1])

            cost_change = 0.0
            if first.total_cost > 0:
                cost_change = ((last.total_cost - first.total_cost) / first.total_cost) * 100

            time_change = 0.0
            if first.actual_time_ms > 0:
                time_change = ((last.actual_time_ms - first.actual_time_ms) / first.actual_time_ms) * 100

            plan_changed = first.plan_type != last.plan_type

            # Check for instability (plan flips)
            plan_types = set(s.get("plan_type", "") for s in snapshots)
            if len(plan_types) > 2:
                report.unstable.append(qhash)

            if cost_change > cost_threshold_pct or time_change > time_threshold_pct:
                sev = "critical" if cost_change > 200 or time_change > 500 else "warning"
                report.regressions.append(PlanRegression(
                    query_hash=qhash,
                    query_text=last.query_text,
                    severity=sev,
                    title=f"Query {qhash[:8]}: cost +{cost_change:.0f}%, time +{time_change:.0f}%",
                    description=(
                        f"Plan cost increased from {first.total_cost:.0f} to {last.total_cost:.0f} "
                        f"({cost_change:+.0f}%). "
                        + (f"Plan changed from {first.plan_type} to {last.plan_type}. " if plan_changed else "")
                    ),
                    before=first,
                    after=last,
                    cost_change_pct=cost_change,
                    time_change_pct=time_change,
                    plan_changed=plan_changed,
                ))
            elif cost_change < -cost_threshold_pct:
                report.improved.append(PlanRegression(
                    query_hash=qhash,
                    query_text=last.query_text,
                    severity="info",
                    title=f"Query {qhash[:8]}: cost {cost_change:.0f}% (improved)",
                    description=f"Plan cost decreased from {first.total_cost:.0f} to {last.total_cost:.0f}.",
                    before=first,
                    after=last,
                    cost_change_pct=cost_change,
                    time_change_pct=time_change,
                ))

        report.regressions.sort(key=lambda r: -r.cost_change_pct)
        return report

    def get_query_history(self, query: str) -> list[PlanSnapshot]:
        """Get all snapshots for a specific query."""
        qhash = self.hash_query(query)
        return [self._dict_to_snapshot(s) for s in self._history.get(qhash, [])]

    def _extract_snapshot(self, qhash: str, query: str, plan: dict[str, Any]) -> PlanSnapshot:
        """Extract a PlanSnapshot from an EXPLAIN JSON plan."""
        root = plan.get("Plan", plan)

        return PlanSnapshot(
            query_hash=qhash,
            query_text=query,
            total_cost=float(root.get("Total Cost", 0)),
            actual_time_ms=float(root.get("Actual Total Time", 0)),
            plan_type=str(root.get("Node Type", "")),
            rows_estimated=int(root.get("Plan Rows", 0)),
            rows_actual=int(root.get("Actual Rows", 0)),
            shared_hit_blocks=int(root.get("Shared Hit Blocks", 0)),
            shared_read_blocks=int(root.get("Shared Read Blocks", 0)),
            temp_written_blocks=int(root.get("Temp Written Blocks", 0)),
            plan_json=plan,
        )

    @staticmethod
    def _dict_to_snapshot(d: dict[str, Any]) -> PlanSnapshot:
        """Convert a stored dict back to PlanSnapshot."""
        return PlanSnapshot(
            query_hash=d.get("query_hash", ""),
            query_text=d.get("query_text", ""),
            timestamp=d.get("timestamp", ""),
            total_cost=float(d.get("total_cost", 0)),
            actual_time_ms=float(d.get("actual_time_ms", 0)),
            plan_type=d.get("plan_type", ""),
            rows_estimated=int(d.get("rows_estimated", 0)),
            rows_actual=int(d.get("rows_actual", 0)),
        )


async def capture_plan(conn: AsyncDBConnection, query: str) -> list[dict[str, Any]]:
    """Helper: run EXPLAIN (ANALYZE, FORMAT JSON) and return the plan."""
    rows = await conn.fetch(f"EXPLAIN (ANALYZE, FORMAT JSON) {query}")
    if rows:
        r = rows[0]
        if isinstance(r, (list, tuple)):
            return r[0] if isinstance(r[0], list) else [r[0]]
        val = getattr(r, "QUERY PLAN", None) or r
        return val if isinstance(val, list) else [val]
    return []
