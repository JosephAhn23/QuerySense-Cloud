"""
Causal analysis engine for query plan diagnosis.

Implements three diagnostic methods from the research literature:

1. **LEO-style estimated-vs-actual comparison** (IBM LEO, 2001)
   At each plan node, compare estimated vs actual row counts,
   compute multiplicative adjustment factors, and trace error
   propagation through the plan tree.

2. **Cardinality error propagation** (Leis et al., TU Munich, 2015)
   The Join Order Benchmark paper demonstrated that cardinality
   estimation errors are the dominant root cause of suboptimal plans.
   This module traces how misestimates at leaf nodes propagate
   upward, amplifying at each join.

3. **Root cause classification** (SQL Server CE Feedback pattern)
   Identify which model assumption failed: independence, uniformity,
   containment, or inclusion. Provides actionable diagnostics.

The critical insight: actual execution time is the only reliable
cross-engine metric. Estimated row counts are more comparable than
cost units since all engines use similar statistical estimation
methods (histograms, selectivity estimates).

Usage:
    from querysense.analyzer.causal import CausalAnalyzer

    analyzer = CausalAnalyzer()
    diagnosis = analyzer.diagnose(ir_plan)

    for node_diag in diagnosis.node_diagnoses:
        if node_diag.is_critical:
            print(f"{node_diag.path}: {node_diag.root_cause}")
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, unique
from typing import Any

from querysense.ir.operators import IROperator, is_join, is_scan, is_aggregate
from querysense.ir.plan import IRNode, IRPlan


# =============================================================================
# Root Cause Classification (SQL Server CE Feedback pattern)
# =============================================================================


@unique
class CardinalityErrorType(str, Enum):
    """
    Classification of cardinality estimation failures.

    Based on SQL Server's CE Feedback model assumptions:
    - INDEPENDENCE: Optimizer assumed predicates are independent
    - UNIFORMITY: Optimizer assumed uniform data distribution
    - CONTAINMENT: Optimizer assumed join containment
    - INCLUSION: Optimizer assumed referential inclusion
    - CORRELATION: Predicates are correlated but optimizer didn't know
    - SKEW: Data distribution is skewed
    - STALE_STATS: Statistics are outdated
    - UNKNOWN: Cannot determine the specific failure mode
    """

    INDEPENDENCE = "independence"
    UNIFORMITY = "uniformity"
    CONTAINMENT = "containment"
    INCLUSION = "inclusion"
    CORRELATION = "correlation"
    SKEW = "skew"
    STALE_STATS = "stale_stats"
    UNKNOWN = "unknown"


@unique
class EstimateDirection(str, Enum):
    """Whether the optimizer over- or under-estimated."""

    OVERESTIMATE = "overestimate"
    UNDERESTIMATE = "underestimate"
    ACCURATE = "accurate"


@unique
class Severity(str, Enum):
    """Severity of a cardinality error."""

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Per-Node Diagnosis
# =============================================================================


@dataclass(frozen=True)
class NodeDiagnosis:
    """
    Causal diagnosis for a single plan node.

    Encapsulates the LEO-style comparison plus root cause analysis.
    """

    # Identity
    path: str
    node_type: str
    relation: str | None
    engine: str

    # Row estimates
    estimated_rows: float | None
    actual_rows: float | None

    # LEO-style adjustment factor
    adjustment_factor: float  # max(actual/est, est/actual)
    direction: EstimateDirection
    severity: Severity

    # Error propagation
    is_leaf: bool
    is_error_source: bool  # True if this node is a root cause (not inherited)
    inherited_error_factor: float  # Error inherited from children
    local_error_factor: float  # Error introduced at this node

    # Root cause classification
    error_type: CardinalityErrorType
    error_type_rationale: str

    # Impact assessment
    downstream_impact: int  # Number of ancestor nodes affected
    cost_impact: float  # Estimated cost of the misestimate

    @property
    def is_critical(self) -> bool:
        return self.severity in (Severity.HIGH, Severity.CRITICAL)

    @property
    def ratio_display(self) -> str:
        if self.adjustment_factor >= 1:
            if self.direction == EstimateDirection.UNDERESTIMATE:
                return f"{self.adjustment_factor:.0f}x underestimated"
            elif self.direction == EstimateDirection.OVERESTIMATE:
                return f"{self.adjustment_factor:.0f}x overestimated"
        return "accurate"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "node_type": self.node_type,
            "relation": self.relation,
            "estimated_rows": self.estimated_rows,
            "actual_rows": self.actual_rows,
            "adjustment_factor": self.adjustment_factor,
            "direction": self.direction.value,
            "severity": self.severity.value,
            "is_error_source": self.is_error_source,
            "error_type": self.error_type.value,
            "error_type_rationale": self.error_type_rationale,
            "downstream_impact": self.downstream_impact,
        }


# =============================================================================
# Plan-Level Diagnosis
# =============================================================================


@dataclass(frozen=True)
class PlanDiagnosis:
    """Complete causal diagnosis for an execution plan."""

    engine: str
    node_diagnoses: tuple[NodeDiagnosis, ...]
    total_nodes: int
    nodes_with_estimates: int

    @property
    def error_sources(self) -> tuple[NodeDiagnosis, ...]:
        return tuple(d for d in self.node_diagnoses if d.is_error_source)

    @property
    def critical_errors(self) -> tuple[NodeDiagnosis, ...]:
        return tuple(d for d in self.node_diagnoses if d.is_critical)

    @property
    def max_error_factor(self) -> float:
        if not self.node_diagnoses:
            return 1.0
        return max(d.adjustment_factor for d in self.node_diagnoses)

    @property
    def worst_node(self) -> NodeDiagnosis | None:
        if not self.node_diagnoses:
            return None
        return max(self.node_diagnoses, key=lambda d: d.adjustment_factor)

    @property
    def dominant_error_type(self) -> CardinalityErrorType:
        sources = self.error_sources
        if not sources:
            return CardinalityErrorType.UNKNOWN
        type_counts: dict[CardinalityErrorType, int] = {}
        for s in sources:
            type_counts[s.error_type] = type_counts.get(s.error_type, 0) + 1
        return max(type_counts, key=lambda t: type_counts[t])

    def summary(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "total_nodes": self.total_nodes,
            "nodes_with_estimates": self.nodes_with_estimates,
            "error_source_count": len(self.error_sources),
            "critical_error_count": len(self.critical_errors),
            "max_error_factor": self.max_error_factor,
            "dominant_error_type": self.dominant_error_type.value,
        }


# =============================================================================
# Causal Analyzer
# =============================================================================

# Thresholds (based on Leis et al. JOB paper and production experience)
_ACCURATE_THRESHOLD = 2.0
_LOW_THRESHOLD = 10.0
_MODERATE_THRESHOLD = 100.0
_HIGH_THRESHOLD = 1000.0


class CausalAnalyzer:
    """
    Diagnoses query plan performance using causal analysis.

    Implements the LEO feedback loop: at each node, compare
    estimated vs actual row counts, classify the error, and trace
    propagation through the plan tree.
    """

    def __init__(
        self,
        *,
        accurate_threshold: float = _ACCURATE_THRESHOLD,
        low_threshold: float = _LOW_THRESHOLD,
        moderate_threshold: float = _MODERATE_THRESHOLD,
        high_threshold: float = _HIGH_THRESHOLD,
    ) -> None:
        self._accurate = accurate_threshold
        self._low = low_threshold
        self._moderate = moderate_threshold
        self._high = high_threshold

    def diagnose(self, ir_plan: IRPlan) -> PlanDiagnosis:
        """
        Perform causal analysis on an IR plan.

        Walks the plan tree bottom-up, computing adjustment factors
        and classifying error types at each node.
        """
        diagnoses: list[NodeDiagnosis] = []

        self._diagnose_node(
            ir_plan.root,
            engine=ir_plan.engine,
            parent_error=1.0,
            diagnoses=diagnoses,
        )

        total_nodes = ir_plan.node_count
        nodes_with_estimates = sum(
            1 for d in diagnoses if d.estimated_rows is not None
        )

        final = self._compute_downstream_impact(diagnoses)

        return PlanDiagnosis(
            engine=ir_plan.engine,
            node_diagnoses=tuple(final),
            total_nodes=total_nodes,
            nodes_with_estimates=nodes_with_estimates,
        )

    def _diagnose_node(
        self,
        node: IRNode,
        engine: str,
        parent_error: float,
        diagnoses: list[NodeDiagnosis],
    ) -> float:
        """
        Recursively diagnose a node and its children.

        Returns the cumulative error factor at this node.
        """
        # Process children first (bottom-up)
        child_errors: list[float] = []
        for child in node.children:
            child_error = self._diagnose_node(
                child,
                engine=engine,
                parent_error=parent_error,
                diagnoses=diagnoses,
            )
            child_errors.append(child_error)

        inherited_error = max(child_errors) if child_errors else 1.0

        # Get cardinality signals
        card = node.properties.cardinality
        if card.estimated_rows is None or card.actual_rows is None:
            return inherited_error

        est = max(card.estimated_rows, 1.0)
        act = max(card.actual_rows, 1.0)

        # LEO-style symmetric adjustment factor
        adjustment_factor = max(act / est, est / act)
        adjustment_factor = max(adjustment_factor, 1.0)

        # Direction
        if adjustment_factor <= self._accurate:
            direction = EstimateDirection.ACCURATE
        elif act > est:
            direction = EstimateDirection.UNDERESTIMATE
        else:
            direction = EstimateDirection.OVERESTIMATE

        # Severity
        severity = self._classify_severity(adjustment_factor)

        # Local vs inherited error
        local_error = adjustment_factor / max(inherited_error, 1.0)
        is_error_source = (
            local_error > self._accurate
            and severity != Severity.NONE
            and adjustment_factor > inherited_error * 1.5
        )

        # Root cause classification
        error_type, rationale = self._classify_error_type(
            node, adjustment_factor, direction, is_error_source
        )

        # Cost impact
        total_cost = node.properties.cost.total_cost or 0.0
        cost_impact = abs(act - est) * total_cost / max(est, 1)

        diagnosis = NodeDiagnosis(
            path=node.path or node.id,
            node_type=node.algorithm or node.operator.value,
            relation=node.properties.relation_name,
            engine=engine,
            estimated_rows=card.estimated_rows,
            actual_rows=card.actual_rows,
            adjustment_factor=adjustment_factor,
            direction=direction,
            severity=severity,
            is_leaf=len(node.children) == 0,
            is_error_source=is_error_source,
            inherited_error_factor=inherited_error,
            local_error_factor=local_error,
            error_type=error_type,
            error_type_rationale=rationale,
            downstream_impact=0,
            cost_impact=cost_impact,
        )
        diagnoses.append(diagnosis)

        return adjustment_factor

    def _classify_severity(self, factor: float) -> Severity:
        if factor <= self._accurate:
            return Severity.NONE
        if factor <= self._low:
            return Severity.LOW
        if factor <= self._moderate:
            return Severity.MODERATE
        if factor <= self._high:
            return Severity.HIGH
        return Severity.CRITICAL

    def _classify_error_type(
        self,
        node: IRNode,
        factor: float,
        direction: EstimateDirection,
        is_source: bool,
    ) -> tuple[CardinalityErrorType, str]:
        """
        Classify the root cause of a cardinality error.

        Uses heuristics based on node type and error patterns.
        """
        if not is_source or factor <= self._accurate:
            return CardinalityErrorType.UNKNOWN, ""

        op = node.operator

        # Joins: containment or inclusion
        if is_join(op):
            if direction == EstimateDirection.UNDERESTIMATE:
                return (
                    CardinalityErrorType.CONTAINMENT,
                    "Join produced more rows than expected — optimizer assumed "
                    "containment (all join key values match) but data has "
                    "many-to-many relationships or unexpected duplicates.",
                )
            return (
                CardinalityErrorType.INCLUSION,
                "Join produced fewer rows than expected — optimizer assumed "
                "referential inclusion but join keys have low overlap.",
            )

        # Scans with multiple predicates → independence assumption
        preds = node.properties.predicates
        filter_count = sum(
            1 for p in [preds.filter_condition, preds.index_condition]
            if p is not None
        )
        if is_scan(op) and filter_count >= 2:
            return (
                CardinalityErrorType.INDEPENDENCE,
                f"Scan has {filter_count} filter conditions — optimizer assumed "
                "predicates are independent (p(A AND B) = p(A)*p(B)) but "
                "columns are likely correlated.",
            )

        # Scans with very large errors → stale stats
        if is_scan(op):
            if factor > self._high:
                return (
                    CardinalityErrorType.STALE_STATS,
                    f"Estimation error of {factor:.0f}x on table scan suggests "
                    "statistics are severely outdated. Run ANALYZE on the table.",
                )
            if direction == EstimateDirection.UNDERESTIMATE:
                return (
                    CardinalityErrorType.SKEW,
                    "Data distribution is skewed — frequent values dominate "
                    "and the histogram doesn't capture them accurately.",
                )
            return (
                CardinalityErrorType.UNIFORMITY,
                "Optimizer assumed uniform distribution but actual data "
                "is non-uniform. Consider creating extended statistics.",
            )

        # Aggregation errors
        if is_aggregate(op):
            return (
                CardinalityErrorType.CORRELATION,
                "Group-by cardinality was misestimated — the number of "
                "distinct groups differs from what statistics predicted.",
            )

        return CardinalityErrorType.UNKNOWN, "Could not determine specific error type."

    def _compute_downstream_impact(
        self,
        diagnoses: list[NodeDiagnosis],
    ) -> list[NodeDiagnosis]:
        """Compute how many downstream nodes each error source affects."""
        result: list[NodeDiagnosis] = []

        for diag in diagnoses:
            if not diag.is_error_source:
                result.append(diag)
                continue

            impact = sum(
                1
                for other in diagnoses
                if other.path.startswith(diag.path) and other.path != diag.path
            )

            # Rebuild with updated impact (frozen dataclass)
            result.append(
                NodeDiagnosis(
                    path=diag.path,
                    node_type=diag.node_type,
                    relation=diag.relation,
                    engine=diag.engine,
                    estimated_rows=diag.estimated_rows,
                    actual_rows=diag.actual_rows,
                    adjustment_factor=diag.adjustment_factor,
                    direction=diag.direction,
                    severity=diag.severity,
                    is_leaf=diag.is_leaf,
                    is_error_source=diag.is_error_source,
                    inherited_error_factor=diag.inherited_error_factor,
                    local_error_factor=diag.local_error_factor,
                    error_type=diag.error_type,
                    error_type_rationale=diag.error_type_rationale,
                    downstream_impact=impact,
                    cost_impact=diag.cost_impact,
                )
            )

        return result
