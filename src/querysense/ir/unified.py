"""
Unified analysis: combines rule-based analysis with causal ranking.

Provides a high-level entry point that:
1. Translates a raw plan into the universal IR
2. Runs causal analysis to produce ranked root-cause hypotheses
3. Optionally stores snapshots for temporal analysis
4. Returns a combined report with both rule findings and causal insights

This is the "new world" entry point that supersedes the legacy analyzer
for cross-engine analysis.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from querysense.causal.engine import CausalEngine, CausalReport
from querysense.ir.adapters.base import auto_detect_adapter
from querysense.ir.adapters.postgres import PostgresAdapter
from querysense.ir.adapters.mysql import MySQLAdapter
from querysense.ir.adapters.sqlserver import SQLServerAdapter
from querysense.ir.annotations import IRCapability
from querysense.ir.plan import IRPlan
from querysense.temporal.store import (
    InMemoryTemporalStore,
    PlanSnapshot,
    TemporalStore,
    plan_features_from_ir,
)

logger = logging.getLogger(__name__)


@dataclass
class UnifiedReport:
    """
    Combined analysis report with both rule findings and causal insights.

    Attributes:
        ir_plan: The universal IR plan.
        causal_report: Ranked root-cause hypotheses.
        plan_fingerprint: Multi-component fingerprint.
        capabilities: Derived capabilities.
        snapshots_stored: Whether a temporal snapshot was stored.
        errors: Any errors encountered.
    """

    ir_plan: IRPlan
    causal_report: CausalReport
    plan_fingerprint: dict[str, str] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    snapshots_stored: bool = False
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"=== Universal IR Analysis ({self.ir_plan.engine}) ===",
            f"Nodes: {self.ir_plan.node_count}",
            f"Capabilities: {', '.join(self.capabilities[:8])}{'...' if len(self.capabilities) > 8 else ''}",
            f"Structure Hash: {self.plan_fingerprint.get('structure', 'N/A')[:12]}",
            "",
        ]

        if self.causal_report.has_findings:
            lines.append("--- Causal Root-Cause Analysis ---")
            lines.append(self.causal_report.summary())
        else:
            lines.append("No root-cause hypotheses matched.")

        if self.errors:
            lines.append(f"\nWarnings: {', '.join(self.errors)}")

        return "\n".join(lines)


class UnifiedAnalyzer:
    """
    Unified analyzer that combines IR translation, causal analysis,
    and temporal tracking.

    Usage::

        analyzer = UnifiedAnalyzer()

        # From raw EXPLAIN JSON (auto-detects engine)
        report = analyzer.analyze_raw(explain_json)

        # Print causal root causes
        print(report.causal_report.summary())

        # Check if plan regressed
        if report.causal_report.top_cause:
            print(f"Top cause: {report.causal_report.top_cause.hypothesis.title}")
    """

    def __init__(
        self,
        temporal_store: TemporalStore | None = None,
        causal_engine: CausalEngine | None = None,
        store_snapshots: bool = True,
    ):
        self.temporal_store = temporal_store or InMemoryTemporalStore()
        self.causal_engine = causal_engine or CausalEngine()
        self.store_snapshots = store_snapshots

    def analyze_raw(
        self,
        raw_plan: Any,
        engine: str | None = None,
        sql: str | None = None,
        query_id: str | None = None,
        db_facts: dict[str, Any] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> UnifiedReport:
        """
        Analyze a raw plan from any supported engine.

        Args:
            raw_plan: Raw plan data (JSON dict, XML string, etc.).
            engine: Engine hint ("postgres", "mysql", "sqlserver", "oracle").
                    If None, auto-detects from plan format.
            sql: Optional SQL query text.
            query_id: Stable query identifier for temporal tracking.
            db_facts: Optional database facts for causal analysis.
            metadata: Optional metadata for temporal snapshots.

        Returns:
            UnifiedReport with IR plan, causal analysis, and fingerprint.
        """
        errors: list[str] = []

        # Step 1: Translate to IR
        try:
            ir_plan = self._translate(raw_plan, engine, sql)
        except Exception as exc:
            logger.error("Failed to translate plan: %s", exc)
            raise

        # Step 2: Causal analysis
        try:
            causal_report = self.causal_engine.analyze(ir_plan, db_facts=db_facts)
        except Exception as exc:
            logger.warning("Causal analysis failed: %s", exc)
            errors.append(f"Causal analysis error: {exc}")
            causal_report = CausalReport(engine=ir_plan.engine)

        # Step 3: Store temporal snapshot
        stored = False
        if self.store_snapshots and query_id:
            try:
                self._store_snapshot(ir_plan, query_id, metadata)
                stored = True
            except Exception as exc:
                logger.warning("Failed to store snapshot: %s", exc)
                errors.append(f"Snapshot storage error: {exc}")

        fingerprint = ir_plan.full_fingerprint()

        return UnifiedReport(
            ir_plan=ir_plan,
            causal_report=causal_report,
            plan_fingerprint=fingerprint,
            capabilities=sorted(c.value for c in ir_plan.capabilities),
            snapshots_stored=stored,
            errors=errors,
        )

    def analyze_ir(
        self,
        ir_plan: IRPlan,
        db_facts: dict[str, Any] | None = None,
        query_id: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> UnifiedReport:
        """
        Analyze an already-translated IR plan.
        """
        errors: list[str] = []

        try:
            causal_report = self.causal_engine.analyze(ir_plan, db_facts=db_facts)
        except Exception as exc:
            logger.warning("Causal analysis failed: %s", exc)
            errors.append(f"Causal analysis error: {exc}")
            causal_report = CausalReport(engine=ir_plan.engine)

        stored = False
        if self.store_snapshots and query_id:
            try:
                self._store_snapshot(ir_plan, query_id, metadata)
                stored = True
            except Exception as exc:
                errors.append(f"Snapshot storage error: {exc}")

        return UnifiedReport(
            ir_plan=ir_plan,
            causal_report=causal_report,
            plan_fingerprint=ir_plan.full_fingerprint(),
            capabilities=sorted(c.value for c in ir_plan.capabilities),
            snapshots_stored=stored,
            errors=errors,
        )

    def _translate(
        self, raw_plan: Any, engine: str | None, sql: str | None,
    ) -> IRPlan:
        """Translate raw plan to IR, with engine auto-detection."""
        adapter_map = {
            "postgres": PostgresAdapter,
            "postgresql": PostgresAdapter,
            "mysql": MySQLAdapter,
            "sqlserver": SQLServerAdapter,
        }

        if engine and engine.lower() in adapter_map:
            adapter = adapter_map[engine.lower()]()
        else:
            adapter = auto_detect_adapter(raw_plan)

        return adapter.translate(raw_plan, sql=sql)

    def _store_snapshot(
        self,
        ir_plan: IRPlan,
        query_id: str,
        metadata: dict[str, str] | None,
    ) -> None:
        """Store a temporal snapshot for drift detection."""
        features = plan_features_from_ir(ir_plan)

        snapshot = PlanSnapshot(
            query_id=query_id,
            timestamp=datetime.now(timezone.utc),
            structure_hash=ir_plan.structure_hash(),
            cost_total=ir_plan.root.properties.cost.total_cost,
            node_count=ir_plan.node_count,
            plan_features=features,
            metadata=metadata or {},
        )

        # If plan has execution time, use it as latency
        if ir_plan.execution_time_ms is not None:
            snapshot = PlanSnapshot(
                query_id=snapshot.query_id,
                timestamp=snapshot.timestamp,
                structure_hash=snapshot.structure_hash,
                latency_p50_ms=ir_plan.execution_time_ms,
                cost_total=snapshot.cost_total,
                node_count=snapshot.node_count,
                plan_features=snapshot.plan_features,
                metadata=snapshot.metadata,
            )

        self.temporal_store.store(snapshot)
