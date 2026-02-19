"""
Plan History Store — track query plan performance over time.

Addresses weakness #1 (vs pganalyze): "QuerySense only sees one plan at a
time with no memory of past executions."

This module stores analysis snapshots per query, enabling:
- Historical trend tracking (cost/time going up or down)
- Regression detection across multiple runs
- "Was this query always slow or did it get worse?"
- Performance trend visualization over days/weeks/months

Storage: JSON file at `.querysense/history.json`, version-controlled.

Usage:
    from querysense.history import HistoryStore

    store = HistoryStore()
    store.record("get_user_by_id", result, explain)
    store.save()

    trend = store.trend("get_user_by_id")
    print(f"Cost trend: {trend.cost_direction}")  # "improving" / "degrading"
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult
    from querysense.parser.models import ExplainOutput

logger = logging.getLogger(__name__)

HISTORY_SCHEMA_VERSION = "1.0"
MAX_SNAPSHOTS_PER_QUERY = 100


@dataclass(frozen=True)
class PlanSnapshot:
    """A point-in-time capture of a query plan analysis."""

    timestamp: str
    total_cost: float
    execution_time_ms: float | None
    plan_rows: int
    actual_rows: int | None
    node_count: int
    findings_count: int
    critical_count: int
    warning_count: int
    structure_hash: str
    top_findings: tuple[str, ...] = ()  # rule_ids


@dataclass
class QueryTrend:
    """Trend analysis for a query over time."""

    query_id: str
    snapshot_count: int
    first_seen: str
    last_seen: str
    cost_direction: str  # "improving", "degrading", "stable", "insufficient_data"
    cost_change_pct: float  # % change from first to last
    current_cost: float
    min_cost: float
    max_cost: float
    avg_cost: float
    current_findings: int
    plan_changes: int  # number of times structure hash changed
    last_structure_hash: str


class HistoryStore:
    """
    Manages plan history storage and trend analysis.

    Stores snapshots of analysis results per query in a JSON file.
    Each snapshot captures cost, timing, findings, and plan structure.
    """

    def __init__(self, path: str | Path = ".querysense/history.json") -> None:
        self.path = Path(path)
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": HISTORY_SCHEMA_VERSION, "queries": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load history from %s: %s", self.path, e)
            return {"schema_version": HISTORY_SCHEMA_VERSION, "queries": {}}

    def save(self) -> None:
        """Persist history to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @property
    def queries(self) -> dict[str, Any]:
        return self._data.get("queries", {})

    def record(
        self,
        query_id: str,
        result: "AnalysisResult",
        explain: "ExplainOutput",
    ) -> PlanSnapshot:
        """
        Record an analysis snapshot for a query.

        Args:
            query_id: Identifier for the query
            result: Analysis result to record
            explain: Parsed EXPLAIN output

        Returns:
            The recorded PlanSnapshot
        """
        from querysense.baseline import _compute_structure_hash, _normalize_plan_tree

        normalized = _normalize_plan_tree(explain.plan)
        structure_hash = _compute_structure_hash(normalized)

        summary = result.summary()
        snapshot = PlanSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_cost=explain.plan.total_cost,
            execution_time_ms=explain.execution_time,
            plan_rows=explain.plan.plan_rows,
            actual_rows=explain.plan.actual_rows,
            node_count=len(explain.all_nodes),
            findings_count=summary["total"],
            critical_count=summary["critical"],
            warning_count=summary["warning"],
            structure_hash=structure_hash,
            top_findings=tuple(f.rule_id for f in result.findings[:5]),
        )

        # Store
        self._data.setdefault("queries", {})
        self._data["queries"].setdefault(query_id, {"snapshots": []})
        snapshots = self._data["queries"][query_id]["snapshots"]
        snapshots.append(self._snapshot_to_dict(snapshot))

        # Trim old snapshots
        if len(snapshots) > MAX_SNAPSHOTS_PER_QUERY:
            self._data["queries"][query_id]["snapshots"] = snapshots[-MAX_SNAPSHOTS_PER_QUERY:]

        return snapshot

    def trend(self, query_id: str) -> QueryTrend | None:
        """
        Compute trend analysis for a query.

        Returns None if query has no history.
        """
        entry = self.queries.get(query_id)
        if not entry or not entry.get("snapshots"):
            return None

        snapshots = entry["snapshots"]
        costs = [s["total_cost"] for s in snapshots]
        findings = [s["findings_count"] for s in snapshots]
        hashes = [s["structure_hash"] for s in snapshots]

        # Count plan structure changes
        plan_changes = sum(
            1 for i in range(1, len(hashes)) if hashes[i] != hashes[i - 1]
        )

        # Determine cost direction
        if len(costs) < 2:
            direction = "insufficient_data"
            change_pct = 0.0
        else:
            first_cost = costs[0]
            last_cost = costs[-1]
            if first_cost > 0:
                change_pct = ((last_cost - first_cost) / first_cost) * 100
            else:
                change_pct = 0.0

            if change_pct < -10:
                direction = "improving"
            elif change_pct > 10:
                direction = "degrading"
            else:
                direction = "stable"

        return QueryTrend(
            query_id=query_id,
            snapshot_count=len(snapshots),
            first_seen=snapshots[0]["timestamp"],
            last_seen=snapshots[-1]["timestamp"],
            cost_direction=direction,
            cost_change_pct=round(change_pct, 2),
            current_cost=costs[-1],
            min_cost=min(costs),
            max_cost=max(costs),
            avg_cost=round(sum(costs) / len(costs), 2),
            current_findings=findings[-1],
            plan_changes=plan_changes,
            last_structure_hash=hashes[-1],
        )

    def all_trends(self) -> list[QueryTrend]:
        """Compute trends for all tracked queries."""
        trends: list[QueryTrend] = []
        for qid in self.queries:
            t = self.trend(qid)
            if t:
                trends.append(t)
        return sorted(trends, key=lambda t: t.current_cost, reverse=True)

    def list_queries(self) -> list[str]:
        """List all query IDs with history."""
        return list(self.queries.keys())

    def remove(self, query_id: str) -> bool:
        """Remove history for a query."""
        if query_id in self.queries:
            del self._data["queries"][query_id]
            return True
        return False

    def stats(self) -> dict[str, Any]:
        """Get history store statistics."""
        total_snapshots = sum(
            len(q.get("snapshots", []))
            for q in self.queries.values()
        )
        return {
            "total_queries": len(self.queries),
            "total_snapshots": total_snapshots,
            "path": str(self.path),
            "exists": self.path.exists(),
        }

    @staticmethod
    def _snapshot_to_dict(s: PlanSnapshot) -> dict[str, Any]:
        return {
            "timestamp": s.timestamp,
            "total_cost": s.total_cost,
            "execution_time_ms": s.execution_time_ms,
            "plan_rows": s.plan_rows,
            "actual_rows": s.actual_rows,
            "node_count": s.node_count,
            "findings_count": s.findings_count,
            "critical_count": s.critical_count,
            "warning_count": s.warning_count,
            "structure_hash": s.structure_hash,
            "top_findings": list(s.top_findings),
        }
