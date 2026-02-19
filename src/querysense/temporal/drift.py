"""
Drift analysis: classify temporal changes into actionable categories.

Uses change-point detection results and plan fingerprints to distinguish:
- **Plan regression**: structure changed + latency worsened
- **Data drift**: structure stable + latency gradually increased
- **Environmental shift**: many queries regress simultaneously
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Sequence

from querysense.temporal.changepoint import (
    Changepoint,
    detect_changepoints,
    pelt_changepoints,
)
from querysense.temporal.store import PlanSnapshot, TemporalStore


class DriftType(str, Enum):
    """Classification of a temporal performance change."""
    PLAN_REGRESSION = "plan_regression"
    DATA_DRIFT = "data_drift"
    ENVIRONMENTAL = "environmental"
    IMPROVEMENT = "improvement"
    STABLE = "stable"


@dataclass(frozen=True)
class DriftEvent:
    """
    A detected performance drift event.

    Attributes:
        query_id: The query that experienced drift.
        drift_type: Classification of the change.
        changepoint: The detected change point.
        old_hash: Plan structure hash before the change.
        new_hash: Plan structure hash after the change (if changed).
        timestamp: Approximate time of the change.
        description: Human-readable explanation.
        severity: 0-100 severity score.
    """

    query_id: str
    drift_type: DriftType
    changepoint: Changepoint | None = None
    old_hash: str = ""
    new_hash: str = ""
    timestamp: datetime | None = None
    description: str = ""
    severity: float = 0.0


class DriftAnalyzer:
    """
    Analyzes temporal plan data to detect and classify drift events.

    Usage::

        store = InMemoryTemporalStore()
        # ... populate store with snapshots ...
        analyzer = DriftAnalyzer(store)
        events = analyzer.analyze_query("q_order_lookup")
        for event in events:
            print(f"{event.drift_type}: {event.description}")
    """

    def __init__(
        self,
        store: TemporalStore,
        min_snapshots: int = 5,
        latency_threshold_pct: float = 0.20,
        use_pelt: bool = True,
    ):
        self.store = store
        self.min_snapshots = min_snapshots
        self.latency_threshold_pct = latency_threshold_pct
        self.use_pelt = use_pelt

    def analyze_query(
        self,
        query_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[DriftEvent]:
        """
        Analyze drift for a single query.

        Returns a list of DriftEvent objects, one per detected change.
        """
        snapshots = self.store.query(
            query_id, since=since, until=until
        )

        if len(snapshots) < self.min_snapshots:
            return []

        events: list[DriftEvent] = []

        # Extract time series
        latencies = self._extract_latency_series(snapshots)
        hashes = [s.structure_hash for s in snapshots]
        timestamps = [s.timestamp for s in snapshots]

        if not latencies:
            return []

        # Detect changepoints in latency series
        if self.use_pelt:
            changepoints = pelt_changepoints(latencies)
        else:
            changepoints = detect_changepoints(
                latencies, threshold_pct=self.latency_threshold_pct
            )

        for cp in changepoints:
            idx = cp.index
            if idx < 0 or idx >= len(snapshots):
                continue

            # Check if plan structure changed at/near the changepoint
            hash_before = hashes[max(0, idx - 1)]
            hash_after = hashes[min(idx, len(hashes) - 1)]
            structure_changed = hash_before != hash_after

            # Classify the drift
            if cp.direction == "decrease":
                drift_type = DriftType.IMPROVEMENT
                severity = 0.0
            elif structure_changed:
                drift_type = DriftType.PLAN_REGRESSION
                severity = min(100, cp.magnitude / max(cp.before_mean, 1) * 100)
            else:
                drift_type = DriftType.DATA_DRIFT
                severity = min(80, cp.magnitude / max(cp.before_mean, 1) * 100)

            event = DriftEvent(
                query_id=query_id,
                drift_type=drift_type,
                changepoint=cp,
                old_hash=hash_before,
                new_hash=hash_after,
                timestamp=timestamps[idx] if idx < len(timestamps) else None,
                description=self._describe_event(
                    drift_type, cp, structure_changed, query_id
                ),
                severity=severity,
            )
            events.append(event)

        return events

    def analyze_all(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[DriftEvent]:
        """
        Analyze drift across all tracked queries.

        Also detects environmental shifts (multiple queries regressing
        simultaneously).
        """
        all_events: list[DriftEvent] = []
        query_ids = self.store.all_query_ids()

        for qid in query_ids:
            events = self.analyze_query(qid, since=since, until=until)
            all_events.extend(events)

        # Detect environmental shifts: multiple regressions at similar times
        regressions = [
            e for e in all_events
            if e.drift_type == DriftType.PLAN_REGRESSION and e.timestamp
        ]

        if len(regressions) >= 3:
            # Group by approximate timestamp (within 1 hour windows)
            clusters = self._cluster_events(regressions, window_seconds=3600)
            for cluster in clusters:
                if len(cluster) >= 3:
                    # Reclassify as environmental
                    for event in cluster:
                        idx = all_events.index(event)
                        all_events[idx] = DriftEvent(
                            query_id=event.query_id,
                            drift_type=DriftType.ENVIRONMENTAL,
                            changepoint=event.changepoint,
                            old_hash=event.old_hash,
                            new_hash=event.new_hash,
                            timestamp=event.timestamp,
                            description=(
                                f"Environmental shift detected: {len(cluster)} "
                                f"queries regressed simultaneously around "
                                f"{event.timestamp}. Likely caused by a config "
                                f"change, deployment, or infrastructure event."
                            ),
                            severity=max(e.severity for e in cluster),
                        )

        return all_events

    def _extract_latency_series(
        self, snapshots: list[PlanSnapshot]
    ) -> list[float]:
        """Extract latency values, preferring p95 then p50 then cost."""
        series: list[float] = []
        for s in snapshots:
            if s.latency_p95_ms is not None:
                series.append(s.latency_p95_ms)
            elif s.latency_p50_ms is not None:
                series.append(s.latency_p50_ms)
            elif s.cost_total is not None:
                series.append(s.cost_total)
            else:
                series.append(0.0)
        return series

    def _describe_event(
        self,
        drift_type: DriftType,
        cp: Changepoint,
        structure_changed: bool,
        query_id: str,
    ) -> str:
        """Generate human-readable description of a drift event."""
        pct_change = (
            (cp.after_mean - cp.before_mean) / cp.before_mean * 100
            if cp.before_mean != 0
            else 0
        )

        if drift_type == DriftType.IMPROVEMENT:
            return (
                f"Query '{query_id}' improved: latency decreased from "
                f"{cp.before_mean:.1f}ms to {cp.after_mean:.1f}ms "
                f"({pct_change:+.0f}%)."
            )
        elif drift_type == DriftType.PLAN_REGRESSION:
            return (
                f"Plan regression for '{query_id}': plan structure changed "
                f"and latency increased from {cp.before_mean:.1f}ms to "
                f"{cp.after_mean:.1f}ms ({pct_change:+.0f}%). "
                f"Likely caused by statistics change, config change, or "
                f"schema change."
            )
        elif drift_type == DriftType.DATA_DRIFT:
            return (
                f"Data drift for '{query_id}': plan structure unchanged but "
                f"latency increased from {cp.before_mean:.1f}ms to "
                f"{cp.after_mean:.1f}ms ({pct_change:+.0f}%). "
                f"Likely caused by data growth or distribution change."
            )
        else:
            return f"Performance change detected for '{query_id}'."

    def _cluster_events(
        self,
        events: list[DriftEvent],
        window_seconds: int,
    ) -> list[list[DriftEvent]]:
        """Cluster events by timestamp proximity."""
        if not events:
            return []

        sorted_events = sorted(
            events, key=lambda e: e.timestamp or datetime.min.replace(tzinfo=timezone.utc)
        )

        clusters: list[list[DriftEvent]] = [[sorted_events[0]]]

        for event in sorted_events[1:]:
            last = clusters[-1][-1]
            if (
                event.timestamp
                and last.timestamp
                and (event.timestamp - last.timestamp).total_seconds()
                <= window_seconds
            ):
                clusters[-1].append(event)
            else:
                clusters.append([event])

        return clusters
