"""
Rule: Plan Shape Regression (AGGREGATE)

Detects plan structure changes against a stored baseline, enabling
merge-gate enforcement of plan stability in CI/CD pipelines.

Why it matters:
- The same logical query can become orders-of-magnitude slower after
  stats shifts, maintenance, schema/index changes, or upgrades
- Plan instability is the #1 operational risk cited by senior Postgres
  engineers: "site goes down because Postgres changed its plan"
- Existing tools focus on visualization/monitoring, not merge-gate
  enforcement; plan comparison remains historically ad-hoc

How it works:
- Requires a baseline stored via BaselineStore (`.querysense/baselines.json`)
- Compares the current plan's normalized structure against the baseline
- Fires CRITICAL for structural changes (scan type flips, join type flips,
  new Seq Scans, removed index scans)
- Fires WARNING for cost regressions above a configurable threshold

When it's okay:
- Intentional plan changes (use a waiver: re-record the baseline)
- New queries with no baseline yet (rule SKIPs cleanly)

CI usage:
    querysense analyze plan.json --baseline .querysense/baselines.json --query-id get_user
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import (
    Finding,
    ImpactBand,
    NodeContext,
    RulePhase,
    Severity,
)
from querysense.analyzer.path import NodePath
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig, RuleContext

if TYPE_CHECKING:
    from querysense.baseline import BaselineDiff, BaselineStore
    from querysense.parser.models import ExplainOutput

logger = logging.getLogger(__name__)


class PlanShapeRegressionConfig(RuleConfig):
    """
    Configuration for plan shape regression detection.

    Attributes:
        cost_regression_threshold_pct: Percent cost increase to trigger
            a WARNING even without structural changes (default 25%).
        baseline_path: Path to baseline file. If empty, rule SKIPs.
        query_id: Query identifier to compare against. If empty, rule SKIPs.
    """

    cost_regression_threshold_pct: float = Field(
        default=25.0,
        ge=1.0,
        le=1000.0,
        description="Percent cost increase to trigger warning (no structural change)",
    )
    baseline_path: str = Field(
        default=".querysense/baselines.json",
        description="Path to the baselines JSON file",
    )
    query_id: str = Field(
        default="",
        description="Query identifier to compare against in the baseline store",
    )


# Dangerous plan transitions that almost always indicate regression
_DANGEROUS_TRANSITIONS: set[tuple[str, str]] = {
    ("Index Scan", "Seq Scan"),
    ("Index Only Scan", "Seq Scan"),
    ("Bitmap Heap Scan", "Seq Scan"),
    ("Hash Join", "Nested Loop"),
    ("Merge Join", "Nested Loop"),
}


@register_rule
class PlanShapeRegression(Rule):
    """
    Detect plan structure regressions against a stored baseline.

    This AGGREGATE rule compares the current plan against a recorded
    baseline and fires findings for structural changes (scan type flips,
    join type flips) and significant cost regressions.

    The rule uses BaselineStore for comparison and is designed to be
    the first-class CI gate for plan stability enforcement.
    """

    rule_id = "PLAN_SHAPE_REGRESSION"
    version = "1.0.0"
    severity = Severity.CRITICAL
    description = "Detects plan structure regressions against stored baselines"
    config_schema = PlanShapeRegressionConfig
    phase = RulePhase.AGGREGATE

    # No hard capability requirements — gracefully SKIP if no baseline
    requires: tuple[str, ...] = ()
    provides: tuple[str, ...] = ("plan_regression_findings",)

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Compare current plan against baseline and detect regressions.

        If no baseline is configured or no query_id is set, returns
        an empty list (rule effectively SKIPs without error).
        """
        config: PlanShapeRegressionConfig = self.config  # type: ignore[assignment]

        if not config.query_id:
            return []

        # Lazy import to avoid circular dependency
        from querysense.baseline import BaselineStore

        try:
            store = BaselineStore(config.baseline_path)
        except Exception:
            logger.debug(
                "Could not load baselines from %s, skipping regression check",
                config.baseline_path,
            )
            return []

        if not store.has_baseline(config.query_id):
            return []

        diff = store.compare(config.query_id, explain)

        if diff.status == "UNCHANGED":
            return self._check_cost_only(diff, config)

        if diff.status == "CHANGED":
            return self._build_regression_findings(diff, config)

        return []

    def _check_cost_only(
        self,
        diff: "BaselineDiff",
        config: PlanShapeRegressionConfig,
    ) -> list[Finding]:
        """Check for cost-only regression (no structural change)."""
        if not diff.has_cost_regression:
            return []

        pct = diff.cost_change_percent
        if pct < config.cost_regression_threshold_pct:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=Severity.WARNING,
                context=NodeContext.root("Query"),
                title=(
                    f"Plan cost regression for '{diff.query_id}' "
                    f"({pct:+.1f}% increase)"
                ),
                description=(
                    f"Plan structure is unchanged but total cost increased "
                    f"from {diff.cost_before:,.0f} to {diff.cost_after:,.0f} "
                    f"({pct:+.1f}%). This may indicate data growth or "
                    f"statistics changes that are degrading performance "
                    f"without altering the plan shape."
                ),
                suggestion=(
                    f"-- Investigate cost increase for query '{diff.query_id}':\n"
                    f"-- 1. Check if table statistics are up to date (ANALYZE)\n"
                    f"-- 2. Verify data distribution hasn't shifted significantly\n"
                    f"-- 3. If cost increase is expected, re-record the baseline:\n"
                    f"--    querysense baseline record --query-id {diff.query_id}"
                ),
                metrics={
                    "cost_before": diff.cost_before,
                    "cost_after": diff.cost_after,
                    "cost_change_pct": pct,
                },
                impact_band=ImpactBand.MEDIUM,
                assumptions=(
                    "Baseline was recorded under representative conditions",
                    "Cost increase reflects real performance degradation",
                ),
                verification_steps=(
                    "Run EXPLAIN ANALYZE to compare actual execution times",
                    "Check pg_stat_user_tables for recent ANALYZE timestamps",
                    "Compare row counts against baseline expectations",
                ),
            )
        ]

    def _build_regression_findings(
        self,
        diff: "BaselineDiff",
        config: PlanShapeRegressionConfig,
    ) -> list[Finding]:
        """Build findings for structural plan changes."""
        findings: list[Finding] = []

        # Check for dangerous node type transitions
        for change in diff.node_type_changes:
            before = change["before"]
            after = change["after"]
            path = change.get("path", "0")
            relation = change.get("relation", "")

            is_dangerous = (before, after) in _DANGEROUS_TRANSITIONS
            severity = Severity.CRITICAL if is_dangerous else Severity.WARNING

            relation_label = f" on {relation}" if relation else ""
            title = (
                f"Plan node changed: {before} -> {after}{relation_label} "
                f"(query '{diff.query_id}')"
            )

            if is_dangerous:
                description = (
                    f"Dangerous plan regression detected at path {path}: "
                    f"{before} changed to {after}{relation_label}. "
                    f"This transition typically causes orders-of-magnitude "
                    f"slowdowns. The planner switched away from an efficient "
                    f"access method, likely due to statistics changes, "
                    f"schema modifications, or a version upgrade."
                )
                impact = ImpactBand.HIGH
            else:
                description = (
                    f"Plan node at path {path} changed from {before} to "
                    f"{after}{relation_label}. While not always harmful, "
                    f"unexpected plan changes can indicate regression. "
                    f"Review the change and re-record the baseline if intentional."
                )
                impact = ImpactBand.UNKNOWN

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=NodeContext.root("Query"),
                title=title,
                description=description,
                suggestion=(
                    f"-- Plan regression detected for '{diff.query_id}':\n"
                    f"-- 1. Compare plans: querysense diff --baseline --query-id {diff.query_id}\n"
                    f"-- 2. If regression: investigate statistics, indexes, schema changes\n"
                    f"-- 3. If intentional: re-record baseline:\n"
                    f"--    querysense baseline record --query-id {diff.query_id}\n"
                    f"-- 4. Consider pinning the plan with pg_hint_plan if critical"
                ),
                metrics={
                    "cost_before": diff.cost_before,
                    "cost_after": diff.cost_after,
                    "cost_change_pct": diff.cost_change_percent,
                    "node_type_changes": len(diff.node_type_changes),
                    "nodes_added": len(diff.nodes_added),
                    "nodes_removed": len(diff.nodes_removed),
                },
                impact_band=impact,
                assumptions=(
                    "Baseline was recorded under representative conditions",
                    "Plan structure change was not intentional",
                ),
                verification_steps=(
                    "Run EXPLAIN ANALYZE on both old and new plan shapes",
                    "Check if ANALYZE was run recently on affected tables",
                    "Verify no schema or index changes were made",
                    "Test with explicit plan hints to confirm which plan is faster",
                ),
            ))

        # Report added/removed nodes at WARNING level
        if diff.nodes_added or diff.nodes_removed:
            added_desc = ", ".join(diff.nodes_added[:5]) if diff.nodes_added else "none"
            removed_desc = ", ".join(diff.nodes_removed[:5]) if diff.nodes_removed else "none"

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=Severity.WARNING,
                context=NodeContext.root("Query"),
                title=(
                    f"Plan tree structure changed for '{diff.query_id}' "
                    f"(+{len(diff.nodes_added)}, -{len(diff.nodes_removed)} nodes)"
                ),
                description=(
                    f"Plan tree gained {len(diff.nodes_added)} nodes and lost "
                    f"{len(diff.nodes_removed)} nodes compared to baseline.\n"
                    f"Added: {added_desc}\n"
                    f"Removed: {removed_desc}\n\n"
                    f"Structure hash: {diff.baseline_structure_hash} -> "
                    f"{diff.current_structure_hash}"
                ),
                suggestion=(
                    f"-- Review plan tree changes:\n"
                    f"-- querysense diff --baseline --query-id {diff.query_id}\n"
                    f"-- If changes are expected, update the baseline."
                ),
                metrics={
                    "nodes_added": len(diff.nodes_added),
                    "nodes_removed": len(diff.nodes_removed),
                },
                impact_band=ImpactBand.UNKNOWN,
            ))

        return findings
