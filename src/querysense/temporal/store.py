"""
Temporal store: persists plan snapshots over time.

Each snapshot captures a plan fingerprint, key metrics, and metadata
at a point in time.  The store supports time-series queries for
change-point detection and drift analysis.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence


@dataclass(frozen=True)
class PlanSnapshot:
    """
    A point-in-time snapshot of a query plan's key characteristics.

    Attributes:
        query_id: Stable identifier for the query (e.g. normalized hash).
        timestamp: When this snapshot was taken.
        structure_hash: IR structural fingerprint hash.
        latency_p50_ms: Median latency (if available).
        latency_p95_ms: 95th percentile latency (if available).
        rows_processed: Total rows processed (if available).
        cost_total: Total plan cost.
        node_count: Number of nodes in the plan tree.
        plan_features: Structural features for drift detection.
        metadata: Arbitrary metadata (deploy tag, PG version, etc.).
    """

    query_id: str
    timestamp: datetime
    structure_hash: str
    latency_p50_ms: float | None = None
    latency_p95_ms: float | None = None
    rows_processed: float | None = None
    cost_total: float | None = None
    node_count: int = 0
    plan_features: dict[str, int | float] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "timestamp": self.timestamp.isoformat(),
            "structure_hash": self.structure_hash,
            "latency_p50_ms": self.latency_p50_ms,
            "latency_p95_ms": self.latency_p95_ms,
            "rows_processed": self.rows_processed,
            "cost_total": self.cost_total,
            "node_count": self.node_count,
            "plan_features": self.plan_features,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PlanSnapshot:
        return cls(
            query_id=data["query_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            structure_hash=data["structure_hash"],
            latency_p50_ms=data.get("latency_p50_ms"),
            latency_p95_ms=data.get("latency_p95_ms"),
            rows_processed=data.get("rows_processed"),
            cost_total=data.get("cost_total"),
            node_count=data.get("node_count", 0),
            plan_features=data.get("plan_features", {}),
            metadata=data.get("metadata", {}),
        )


def plan_features_from_ir(ir_plan: Any) -> dict[str, int | float]:
    """
    Extract structural features from an IR plan for time-series tracking.

    Features include counts of operator types, max depth, etc.
    """
    from querysense.ir.operators import is_join, is_scan, is_sort, is_aggregate

    features: dict[str, int | float] = {
        "node_count": 0,
        "scan_count": 0,
        "join_count": 0,
        "sort_count": 0,
        "agg_count": 0,
        "seq_scan_count": 0,
        "max_depth": 0,
        "max_est_rows": 0,
        "total_cost": 0,
    }

    from querysense.ir.operators import IROperator

    for node in ir_plan.all_nodes():
        features["node_count"] += 1
        if is_scan(node.operator):
            features["scan_count"] += 1
        if node.operator == IROperator.SCAN_SEQ:
            features["seq_scan_count"] += 1
        if is_join(node.operator):
            features["join_count"] += 1
        if is_sort(node.operator):
            features["sort_count"] += 1
        if is_aggregate(node.operator):
            features["agg_count"] += 1
        features["max_depth"] = max(features["max_depth"], node.depth)
        est = node.properties.cardinality.estimated_rows
        if est is not None and est > features["max_est_rows"]:
            features["max_est_rows"] = est

    root_cost = ir_plan.root.properties.cost.total_cost
    if root_cost is not None:
        features["total_cost"] = root_cost

    return features


class TemporalStore(ABC):
    """Abstract interface for temporal snapshot storage."""

    @abstractmethod
    def store(self, snapshot: PlanSnapshot) -> None:
        """Store a new snapshot."""
        ...

    @abstractmethod
    def query(
        self,
        query_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 1000,
    ) -> list[PlanSnapshot]:
        """Retrieve snapshots for a query, ordered by timestamp."""
        ...

    @abstractmethod
    def latest(self, query_id: str) -> PlanSnapshot | None:
        """Get the most recent snapshot for a query."""
        ...

    @abstractmethod
    def all_query_ids(self) -> list[str]:
        """List all unique query IDs."""
        ...


class InMemoryTemporalStore(TemporalStore):
    """
    In-memory temporal store, useful for testing and single-session analysis.
    """

    def __init__(self) -> None:
        self._store: dict[str, list[PlanSnapshot]] = {}

    def store(self, snapshot: PlanSnapshot) -> None:
        if snapshot.query_id not in self._store:
            self._store[snapshot.query_id] = []
        self._store[snapshot.query_id].append(snapshot)
        self._store[snapshot.query_id].sort(key=lambda s: s.timestamp)

    def query(
        self,
        query_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 1000,
    ) -> list[PlanSnapshot]:
        snapshots = self._store.get(query_id, [])
        result = []
        for s in snapshots:
            if since and s.timestamp < since:
                continue
            if until and s.timestamp > until:
                continue
            result.append(s)
            if len(result) >= limit:
                break
        return result

    def latest(self, query_id: str) -> PlanSnapshot | None:
        snapshots = self._store.get(query_id, [])
        return snapshots[-1] if snapshots else None

    def all_query_ids(self) -> list[str]:
        return list(self._store.keys())

    def export_json(self) -> str:
        """Export all snapshots as JSON."""
        data = {}
        for qid, snaps in self._store.items():
            data[qid] = [s.to_dict() for s in snaps]
        return json.dumps(data, indent=2)

    def import_json(self, json_str: str) -> None:
        """Import snapshots from JSON."""
        data = json.loads(json_str)
        for qid, snaps in data.items():
            for s in snaps:
                self.store(PlanSnapshot.from_dict(s))
