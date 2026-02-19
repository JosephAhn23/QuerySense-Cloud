"""
Cost Model Calibrator + Plan Stability Analyzer.

Two critical capabilities for understanding the planner's mind:

1. **Cost Calibrator**: Compare estimated costs vs actual execution to find
   where PostgreSQL's cost model is miscalibrated. When the cost model is
   wrong, the planner makes wrong decisions.

2. **Plan Stability Analyzer**: Detect when different parameter values cause
   wildly different plans (parameter sniffing). Critical for ORM-generated
   queries where the same prepared statement runs with different values.

Usage:
    from querysense.cost_calibrator import CostCalibrator, PlanStabilityAnalyzer

    calibrator = CostCalibrator()
    report = calibrator.calibrate(plans)
    print(f"seq_page_cost accuracy: {report.knob_accuracy['seq_page_cost']:.0%}")

    stability = PlanStabilityAnalyzer()
    result = stability.analyze(plans_with_different_params)
    for issue in result.instabilities:
        print(f"Unstable: {issue.description}")
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any


# ── Cost Model Calibrator ────────────────────────────────────────────

@dataclass
class CostAccuracy:
    """Accuracy of a cost model parameter."""
    parameter: str
    estimated_total: float = 0.0
    actual_total: float = 0.0
    accuracy: float = 1.0          # 0-1, higher = more accurate
    sample_count: int = 0
    worst_error_ratio: float = 0.0
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "parameter": self.parameter,
            "accuracy": round(self.accuracy, 4),
            "sample_count": self.sample_count,
            "worst_error_ratio": round(self.worst_error_ratio, 2),
            "recommendation": self.recommendation,
        }


@dataclass
class NodeCostComparison:
    """Cost comparison for a single plan node."""
    node_type: str
    table: str = ""
    estimated_cost: float = 0.0
    actual_time_ms: float = 0.0
    cost_per_ms: float = 0.0       # Estimated cost / actual ms
    error_ratio: float = 0.0       # |est - actual| / max(actual, 1)
    rows_estimated: int = 0
    rows_actual: int = 0

    @property
    def is_overestimated(self) -> bool:
        return self.estimated_cost > self.actual_time_ms * 2

    @property
    def is_underestimated(self) -> bool:
        return self.estimated_cost < self.actual_time_ms * 0.5 and self.actual_time_ms > 1


@dataclass
class CalibrationReport:
    """Full cost model calibration report."""
    comparisons: list[NodeCostComparison] = field(default_factory=list)
    knob_accuracy: dict[str, CostAccuracy] = field(default_factory=dict)
    overall_accuracy: float = 0.0
    overestimated_count: int = 0
    underestimated_count: int = 0
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_accuracy": round(self.overall_accuracy, 4),
            "overestimated": self.overestimated_count,
            "underestimated": self.underestimated_count,
            "knob_accuracy": {k: v.to_dict() for k, v in self.knob_accuracy.items()},
            "recommendations": self.recommendations,
            "top_miscalibrations": [
                {
                    "node_type": c.node_type,
                    "table": c.table,
                    "estimated_cost": round(c.estimated_cost, 2),
                    "actual_time_ms": round(c.actual_time_ms, 2),
                    "error_ratio": round(c.error_ratio, 2),
                }
                for c in sorted(self.comparisons, key=lambda x: -x.error_ratio)[:10]
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  COST MODEL CALIBRATION REPORT")
        lines.append("  " + "=" * 60)
        lines.append(f"  Overall accuracy: {self.overall_accuracy:.0%}")
        lines.append(f"  Overestimated: {self.overestimated_count} nodes")
        lines.append(f"  Underestimated: {self.underestimated_count} nodes")
        lines.append("")

        if self.knob_accuracy:
            lines.append("  Cost Parameter Accuracy:")
            for name, acc in sorted(self.knob_accuracy.items(), key=lambda x: x[1].accuracy):
                bar = "#" * int(acc.accuracy * 20)
                lines.append(f"    {name:<25} {acc.accuracy:>5.0%} [{bar:<20}] ({acc.sample_count} samples)")
                if acc.recommendation:
                    lines.append(f"      Suggestion: {acc.recommendation}")
            lines.append("")

        if self.recommendations:
            lines.append("  Recommendations:")
            for rec in self.recommendations:
                lines.append(f"    * {rec}")
            lines.append("")

        worst = sorted(self.comparisons, key=lambda x: -x.error_ratio)[:5]
        if worst:
            lines.append("  Worst Miscalibrations:")
            for c in worst:
                direction = "OVER" if c.is_overestimated else "UNDER"
                lines.append(
                    f"    {c.node_type} on {c.table}: "
                    f"est={c.estimated_cost:.0f} actual={c.actual_time_ms:.1f}ms "
                    f"({c.error_ratio:.0f}x {direction})"
                )
            lines.append("")

        return "\n".join(lines)


class CostCalibrator:
    """Compare estimated costs to actual execution for cost model calibration."""

    def calibrate(self, plans: list[dict[str, Any]]) -> CalibrationReport:
        """Calibrate the cost model from EXPLAIN ANALYZE plans."""
        comparisons: list[NodeCostComparison] = []

        for plan_data in plans:
            plan = self._extract_plan(plan_data)
            if not plan:
                continue
            self._walk_and_compare(plan, comparisons)

        if not comparisons:
            return CalibrationReport()

        # Calculate overall accuracy
        total_error = sum(c.error_ratio for c in comparisons)
        overall_accuracy = max(0, 1.0 - (total_error / len(comparisons) / 10))

        over = sum(1 for c in comparisons if c.is_overestimated)
        under = sum(1 for c in comparisons if c.is_underestimated)

        # Assess cost parameter accuracy
        knob_accuracy = self._assess_knob_accuracy(comparisons)

        # Generate recommendations
        recs = self._generate_recommendations(comparisons, knob_accuracy)

        return CalibrationReport(
            comparisons=comparisons,
            knob_accuracy=knob_accuracy,
            overall_accuracy=overall_accuracy,
            overestimated_count=over,
            underestimated_count=under,
            recommendations=recs,
        )

    def _walk_and_compare(self, node: dict[str, Any], comps: list[NodeCostComparison]) -> None:
        actual_time = node.get("Actual Total Time")
        if actual_time is None:
            return

        est_cost = node.get("Total Cost", 0.0)
        loops = node.get("Actual Loops") or 1
        actual_total = actual_time * loops

        error = 0.0
        if actual_total > 0:
            error = abs(est_cost - actual_total) / actual_total
        elif est_cost > 0:
            error = est_cost

        comps.append(NodeCostComparison(
            node_type=node.get("Node Type", ""),
            table=node.get("Relation Name", ""),
            estimated_cost=est_cost,
            actual_time_ms=actual_total,
            cost_per_ms=est_cost / actual_total if actual_total > 0 else 0,
            error_ratio=error,
            rows_estimated=node.get("Plan Rows", 0),
            rows_actual=node.get("Actual Rows") or 0,
        ))

        for child in node.get("Plans", []):
            self._walk_and_compare(child, comps)

    def _assess_knob_accuracy(self, comparisons: list[NodeCostComparison]) -> dict[str, CostAccuracy]:
        """Map node types to cost parameters and assess accuracy."""
        # Node type -> primary cost parameter mapping
        param_map = {
            "Seq Scan": "seq_page_cost",
            "Index Scan": "random_page_cost",
            "Index Only Scan": "random_page_cost",
            "Bitmap Heap Scan": "random_page_cost",
            "Sort": "cpu_operator_cost",
            "Hash": "cpu_operator_cost",
            "Hash Join": "cpu_tuple_cost",
            "Merge Join": "cpu_tuple_cost",
            "Nested Loop": "cpu_tuple_cost",
            "Aggregate": "cpu_operator_cost",
            "Gather": "parallel_setup_cost",
        }

        param_data: dict[str, list[NodeCostComparison]] = {}
        for c in comparisons:
            param = param_map.get(c.node_type, "other")
            param_data.setdefault(param, []).append(c)

        results: dict[str, CostAccuracy] = {}
        for param, nodes in param_data.items():
            if not nodes:
                continue

            avg_error = sum(n.error_ratio for n in nodes) / len(nodes)
            accuracy = max(0, 1.0 - avg_error / 5)
            worst = max(n.error_ratio for n in nodes)

            rec = ""
            if accuracy < 0.5:
                if param == "seq_page_cost":
                    rec = "Reduce seq_page_cost for SSD storage: SET seq_page_cost = 1.0;"
                elif param == "random_page_cost":
                    rec = "Reduce random_page_cost for SSD: SET random_page_cost = 1.1;"
                elif param == "cpu_tuple_cost":
                    rec = "Adjust cpu_tuple_cost based on your CPU speed"
                elif param == "parallel_setup_cost":
                    rec = "Reduce parallel_setup_cost to encourage parallelism"

            results[param] = CostAccuracy(
                parameter=param,
                accuracy=accuracy,
                sample_count=len(nodes),
                worst_error_ratio=worst,
                recommendation=rec,
            )

        return results

    def _generate_recommendations(
        self, comparisons: list[NodeCostComparison], knobs: dict[str, CostAccuracy],
    ) -> list[str]:
        recs: list[str] = []

        # SSD detection
        seq_nodes = [c for c in comparisons if c.node_type == "Seq Scan" and c.actual_time_ms > 0]
        idx_nodes = [c for c in comparisons if "Index" in c.node_type and c.actual_time_ms > 0]

        if seq_nodes and idx_nodes:
            seq_cost_ratio = sum(c.cost_per_ms for c in seq_nodes) / len(seq_nodes)
            idx_cost_ratio = sum(c.cost_per_ms for c in idx_nodes) / len(idx_nodes)

            if seq_cost_ratio > 0 and idx_cost_ratio > 0:
                ratio = seq_cost_ratio / idx_cost_ratio
                if ratio > 0.8:
                    recs.append(
                        "SSD storage detected: seq_page_cost and random_page_cost should be "
                        "nearly equal. Set random_page_cost = 1.1 (default is 4.0)"
                    )

        # Row estimation
        bad_estimates = [c for c in comparisons if c.error_ratio > 10]
        if len(bad_estimates) > len(comparisons) * 0.2:
            recs.append(
                f"{len(bad_estimates)} nodes ({len(bad_estimates)*100//len(comparisons)}%) have >10x "
                f"cost estimation errors. Run ANALYZE on affected tables."
            )

        # Systematic over/under estimation
        over_count = sum(1 for c in comparisons if c.is_overestimated)
        under_count = sum(1 for c in comparisons if c.is_underestimated)
        if over_count > len(comparisons) * 0.5:
            recs.append(
                "Cost model systematically overestimates -- planner may avoid good plans. "
                "Consider reducing cpu_tuple_cost and cpu_operator_cost."
            )
        elif under_count > len(comparisons) * 0.5:
            recs.append(
                "Cost model systematically underestimates -- planner may choose expensive plans "
                "thinking they're cheap. Consider increasing random_page_cost."
            )

        return recs

    def _extract_plan(self, data: Any) -> dict[str, Any] | None:
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            return data.get("Plan", data if "Node Type" in data else None)
        return None


# ── Plan Stability Analyzer ──────────────────────────────────────────

@dataclass
class PlanInstability:
    """A detected plan instability."""
    description: str
    severity: str = "warning"
    plan_signatures: list[str] = field(default_factory=list)
    cost_range: tuple[float, float] = (0.0, 0.0)
    cost_variance: float = 0.0
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "severity": self.severity,
            "plan_count": len(self.plan_signatures),
            "cost_range": [round(self.cost_range[0], 2), round(self.cost_range[1], 2)],
            "cost_variance": round(self.cost_variance, 2),
            "recommendation": self.recommendation,
        }


@dataclass
class StabilityResult:
    """Result of plan stability analysis."""
    plans_analyzed: int = 0
    distinct_plans: int = 0
    is_stable: bool = True
    instabilities: list[PlanInstability] = field(default_factory=list)
    plan_signatures: list[str] = field(default_factory=list)
    cost_values: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plans_analyzed": self.plans_analyzed,
            "distinct_plans": self.distinct_plans,
            "is_stable": self.is_stable,
            "instabilities": [i.to_dict() for i in self.instabilities],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  PLAN STABILITY ANALYSIS")
        lines.append("  " + "=" * 60)
        status = "STABLE" if self.is_stable else "UNSTABLE"
        lines.append(f"  Status: {status}")
        lines.append(f"  Plans analyzed: {self.plans_analyzed}")
        lines.append(f"  Distinct plans: {self.distinct_plans}")

        if self.cost_values:
            lines.append(f"  Cost range: {min(self.cost_values):.0f} - {max(self.cost_values):.0f}")
        lines.append("")

        for inst in self.instabilities:
            lines.append(f"  [{inst.severity.upper()}] {inst.description}")
            if inst.recommendation:
                lines.append(f"    Fix: {inst.recommendation}")
            lines.append("")

        return "\n".join(lines)


class PlanStabilityAnalyzer:
    """
    Detect plan instability across different executions.

    Particularly important for prepared statements and ORM-generated
    queries where different parameter values can cause wildly different
    plans (parameter sniffing).
    """

    def analyze(self, plans: list[dict[str, Any]]) -> StabilityResult:
        """Analyze a set of plans for the same query template."""
        if len(plans) < 2:
            return StabilityResult(plans_analyzed=len(plans), is_stable=True)

        signatures: list[str] = []
        costs: list[float] = []

        for plan_data in plans:
            plan = self._extract_plan(plan_data)
            if not plan:
                continue
            sig = self._plan_signature(plan)
            signatures.append(sig)
            costs.append(plan.get("Total Cost", 0.0))

        distinct = len(set(signatures))
        instabilities: list[PlanInstability] = []

        # Plan shape instability
        if distinct > 1:
            instabilities.append(PlanInstability(
                description=f"Plan shape varies: {distinct} distinct plans across {len(signatures)} executions",
                severity="warning" if distinct <= 3 else "critical",
                plan_signatures=list(set(signatures)),
                recommendation=(
                    "Consider: (1) Plan pinning with pg_hint_plan, "
                    "(2) Forcing generic plans: SET plan_cache_mode = 'force_generic_plan', "
                    "(3) Improving statistics with CREATE STATISTICS for correlated columns"
                ),
            ))

        # Cost variance
        if costs and len(costs) >= 2:
            mean_cost = sum(costs) / len(costs)
            variance = sum((c - mean_cost) ** 2 for c in costs) / len(costs)
            cv = math.sqrt(variance) / mean_cost if mean_cost > 0 else 0

            if cv > 0.5:
                instabilities.append(PlanInstability(
                    description=f"High cost variance (CV={cv:.1f}): costs range from {min(costs):.0f} to {max(costs):.0f}",
                    severity="warning",
                    cost_range=(min(costs), max(costs)),
                    cost_variance=cv,
                    recommendation=(
                        "Parameter sniffing detected. Consider: "
                        "(1) Using PREPAREd statements with explicit plan control, "
                        "(2) Splitting query into OLTP/OLAP variants based on selectivity"
                    ),
                ))

        is_stable = len(instabilities) == 0

        return StabilityResult(
            plans_analyzed=len(plans),
            distinct_plans=distinct,
            is_stable=is_stable,
            instabilities=instabilities,
            plan_signatures=signatures,
            cost_values=costs,
        )

    def _plan_signature(self, node: dict[str, Any]) -> str:
        """Generate a structural signature for a plan (ignoring costs/rows)."""
        parts: list[str] = []
        self._sig_walk(node, parts)
        return "|".join(parts)

    def _sig_walk(self, node: dict[str, Any], parts: list[str]) -> None:
        nt = node.get("Node Type", "?")
        table = node.get("Relation Name", "")
        idx = node.get("Index Name", "")
        parts.append(f"{nt}:{table}:{idx}")
        for child in node.get("Plans", []):
            self._sig_walk(child, parts)

    def _extract_plan(self, data: Any) -> dict[str, Any] | None:
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            return data.get("Plan", data if "Node Type" in data else None)
        return None
