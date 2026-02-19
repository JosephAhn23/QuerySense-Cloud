"""
Rule: Cardinality Drift (Causal Analysis)

Uses the causal analysis engine to detect and diagnose cardinality
estimation errors with root cause classification. This rule goes
beyond simple estimated-vs-actual comparison by tracing error
propagation through the plan tree and classifying the model
assumption that failed.

Based on three research foundations:
1. LEO (IBM, 2001): Estimated vs actual comparison with adjustment factors
2. Leis et al. (TU Munich, 2015): Cardinality errors as dominant root cause
3. SQL Server CE Feedback: Root cause classification (independence,
   uniformity, containment, inclusion)

This rule requires EXPLAIN ANALYZE data (actual row counts).

Why it matters:
- Cardinality estimation errors are the #1 cause of suboptimal plans
- Only ~5% of plans fall within 10x of optimal (Leis et al.)
- Underestimates are far more damaging than overestimates
- They cause wrong join strategies, wrong memory allocations, and
  catastrophic nested loop explosions

What makes this different from BAD_ROW_ESTIMATE:
- BAD_ROW_ESTIMATE flags individual nodes with bad estimates
- CARDINALITY_DRIFT traces error propagation through the tree,
  identifies root causes, and classifies the optimizer assumption
  that failed (independence, containment, skew, stale stats)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.causal import (
    CausalAnalyzer,
    CardinalityErrorType,
    NodeDiagnosis,
    Severity as CausalSeverity,
)
from querysense.analyzer.models import (
    Finding,
    ImpactBand,
    NodeContext,
    RulePhase,
    Severity,
)
from querysense.analyzer.path import NodePath
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class CardinalityDriftConfig(RuleConfig):
    """Configuration for cardinality drift detection."""

    # Minimum adjustment factor to report (default: 10x)
    min_factor: float = 10.0
    # Maximum findings to report per plan
    max_findings: int = 5
    # Whether to include non-source nodes (inherited errors)
    include_inherited: bool = False


# Map causal severity to querysense severity
_SEVERITY_MAP = {
    CausalSeverity.NONE: Severity.INFO,
    CausalSeverity.LOW: Severity.INFO,
    CausalSeverity.MODERATE: Severity.WARNING,
    CausalSeverity.HIGH: Severity.WARNING,
    CausalSeverity.CRITICAL: Severity.CRITICAL,
}

# Map error types to human-readable labels
_ERROR_TYPE_LABELS = {
    CardinalityErrorType.INDEPENDENCE: "Predicate Independence Assumption",
    CardinalityErrorType.UNIFORMITY: "Uniform Distribution Assumption",
    CardinalityErrorType.CONTAINMENT: "Join Containment Assumption",
    CardinalityErrorType.INCLUSION: "Referential Inclusion Assumption",
    CardinalityErrorType.CORRELATION: "Column Correlation",
    CardinalityErrorType.SKEW: "Data Skew",
    CardinalityErrorType.STALE_STATS: "Stale Statistics",
    CardinalityErrorType.UNKNOWN: "Unknown",
}

# Map error types to suggested fixes
_ERROR_TYPE_FIXES: dict[CardinalityErrorType, str] = {
    CardinalityErrorType.INDEPENDENCE: (
        "Create extended/multivariate statistics on the correlated columns "
        "(PostgreSQL: CREATE STATISTICS, SQL Server: CREATE STATISTICS WITH FULLSCAN)"
    ),
    CardinalityErrorType.UNIFORMITY: (
        "Update statistics with higher sample rate or create a histogram "
        "on the filtered column"
    ),
    CardinalityErrorType.CONTAINMENT: (
        "Check for many-to-many join relationships or unexpected duplicates "
        "in join key columns; consider adding a unique constraint if appropriate"
    ),
    CardinalityErrorType.INCLUSION: (
        "Verify referential integrity between joined tables; consider "
        "adding foreign key constraints to help the optimizer"
    ),
    CardinalityErrorType.CORRELATION: (
        "Create extended statistics covering the GROUP BY columns "
        "to help the optimizer estimate distinct group counts"
    ),
    CardinalityErrorType.SKEW: (
        "Run ANALYZE/UPDATE STATISTICS with increased histogram buckets; "
        "consider partitioning on the skewed column"
    ),
    CardinalityErrorType.STALE_STATS: (
        "Run ANALYZE (PostgreSQL/MySQL) or UPDATE STATISTICS (SQL Server) "
        "or DBMS_STATS.GATHER_TABLE_STATS (Oracle) on the affected table"
    ),
    CardinalityErrorType.UNKNOWN: (
        "Investigate the plan node's filter conditions and join predicates "
        "for potential estimation issues"
    ),
}


@register_rule
class CardinalityDrift(Rule):
    """
    Detect and diagnose cardinality estimation errors with causal analysis.

    Uses the CausalAnalyzer to trace error propagation through the plan
    tree and classify root causes using the SQL Server CE Feedback taxonomy.

    This is an AGGREGATE-phase rule because it analyzes the entire plan
    tree as a unit rather than individual nodes.
    """

    rule_id = "CARDINALITY_DRIFT"
    version = "1.0.0"
    severity = Severity.WARNING
    description = (
        "Causal analysis of cardinality estimation errors with "
        "root cause classification and propagation tracking"
    )
    config_schema = CardinalityDriftConfig
    phase = RulePhase.AGGREGATE
    requires: tuple[str, ...] = ("ir_plan",)
    provides: tuple[str, ...] = ("causal_diagnosis",)

    def __init__(self, config: RuleConfig | dict | None = None) -> None:
        super().__init__(config)
        self._causal = CausalAnalyzer()

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Analyze the plan for cardinality estimation errors.

        Converts the plan to IR, runs causal analysis, and produces
        findings with root cause classification.
        """
        from querysense.ir.adapters.base import auto_convert

        # Convert to IR
        try:
            ir_plan = auto_convert(explain.raw_plan)
        except (ValueError, KeyError):
            return []

        # Check if we have actual row counts
        has_actuals = any(
            node.actual_rows is not None
            for node in ir_plan.root.iter_all()
        )
        if not has_actuals:
            return []

        # Run causal analysis
        diagnosis = self._causal.diagnose(ir_plan)

        if not diagnosis.node_diagnoses:
            return []

        config: CardinalityDriftConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        # Filter and sort diagnoses
        relevant = [
            d for d in diagnosis.node_diagnoses
            if d.adjustment_factor >= config.min_factor
            and (config.include_inherited or d.is_error_source)
        ]
        relevant.sort(key=lambda d: d.adjustment_factor, reverse=True)
        relevant = relevant[: config.max_findings]

        for diag in relevant:
            finding = self._diagnosis_to_finding(diag, diagnosis.total_nodes)
            findings.append(finding)

        # Add plan-level summary if there are critical errors
        if diagnosis.critical_errors:
            summary = self._plan_summary_finding(diagnosis)
            findings.insert(0, summary)

        return findings

    def _diagnosis_to_finding(
        self,
        diag: NodeDiagnosis,
        total_nodes: int,
    ) -> Finding:
        """Convert a NodeDiagnosis to a Finding."""
        error_label = _ERROR_TYPE_LABELS.get(diag.error_type, "Unknown")
        fix = _ERROR_TYPE_FIXES.get(diag.error_type, "")

        # Build description
        desc_parts = [
            f"Cardinality estimation error of {diag.adjustment_factor:.0f}x "
            f"({diag.ratio_display}).",
        ]
        if diag.estimated_rows is not None and diag.actual_rows is not None:
            desc_parts.append(
                f"Estimated {diag.estimated_rows:,} rows but "
                f"actual was {diag.actual_rows:,}."
            )
        if diag.error_type_rationale:
            desc_parts.append(f"Root cause: {diag.error_type_rationale}")

        # Impact band based on severity
        impact = ImpactBand.MEDIUM
        if diag.severity == CausalSeverity.HIGH:
            impact = ImpactBand.HIGH
        elif diag.severity == CausalSeverity.CRITICAL:
            impact = ImpactBand.CRITICAL

        context = NodeContext(
            path=NodePath.from_segments(diag.path.split(" → ")),
            node_type=diag.node_type,
            relation_name=diag.relation,
            actual_rows=diag.actual_rows,
            plan_rows=diag.estimated_rows,
            total_cost=diag.cost_impact,
            startup_cost=0.0,
        )

        return Finding(
            rule_id=self.rule_id,
            severity=_SEVERITY_MAP.get(diag.severity, Severity.WARNING),
            context=context,
            title=f"Cardinality drift: {error_label}",
            description=" ".join(desc_parts),
            suggestion=fix,
            metrics={
                "adjustment_factor": diag.adjustment_factor,
                "direction": diag.direction.value,
                "error_type": diag.error_type.value,
                "is_error_source": diag.is_error_source,
                "downstream_impact": diag.downstream_impact,
                "inherited_error_factor": diag.inherited_error_factor,
                "local_error_factor": diag.local_error_factor,
            },
            impact_band=impact,
        )

    def _plan_summary_finding(self, diagnosis) -> Finding:
        """Create a plan-level summary finding for critical errors."""
        n_critical = len(diagnosis.critical_errors)
        n_sources = len(diagnosis.error_sources)
        worst = diagnosis.worst_node

        desc = (
            f"Plan has {n_critical} critical cardinality error(s) across "
            f"{n_sources} root cause(s). "
            f"Worst error: {worst.adjustment_factor:.0f}x at "
            f"{worst.node_type}"
            + (f" on {worst.relation}" if worst.relation else "")
            + f". Dominant failure mode: "
            f"{_ERROR_TYPE_LABELS.get(diagnosis.dominant_error_type, 'Unknown')}."
        )

        context = NodeContext(
            path=NodePath.root(),
            node_type="Plan",
            total_cost=0.0,
            startup_cost=0.0,
        )

        return Finding(
            rule_id=self.rule_id,
            severity=Severity.CRITICAL,
            context=context,
            title="Critical cardinality estimation failures detected",
            description=desc,
            suggestion=(
                "Multiple cardinality estimation failures indicate systemic "
                "statistics quality issues. Run a full ANALYZE on all affected "
                "tables and consider creating extended statistics for correlated "
                "column pairs."
            ),
            metrics={
                "critical_count": n_critical,
                "source_count": n_sources,
                "max_error_factor": diagnosis.max_error_factor,
                "dominant_error_type": diagnosis.dominant_error_type.value,
            },
            impact_band=ImpactBand.CRITICAL,
        )
