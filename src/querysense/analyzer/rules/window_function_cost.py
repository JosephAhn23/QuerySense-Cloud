"""Rule: Window Function Cost — detects expensive WindowAgg operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class WindowFunctionConfig(RuleConfig):
    min_rows: int = Field(default=50_000, ge=100, description="Minimum rows for warning")
    cost_ratio_warning: float = Field(default=0.3, ge=0.0, le=1.0, description="Cost ratio of plan to warn")


@register_rule
class WindowFunctionCost(Rule):
    """Detect expensive window function operations."""

    rule_id = "WINDOW_FUNCTION_COST"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "WindowAgg consuming significant portion of query cost"
    config_schema = WindowFunctionConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: WindowFunctionConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        root_cost = explain.plan.total_cost
        if root_cost <= 0:
            return findings

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "WindowAgg":
                continue

            actual_rows = node.actual_rows or node.plan_rows or 0
            if actual_rows < config.min_rows:
                continue

            cost_ratio = node.total_cost / root_cost if root_cost > 0 else 0

            if cost_ratio < config.cost_ratio_warning:
                continue

            context = NodeContext.from_node(node, path, parent)

            # Check if there's a Sort child (window functions often need sorting)
            has_sort_child = False
            if node.plans:
                for child in node.plans:
                    if child.node_type == "Sort":
                        has_sort_child = True

            suggestion_parts = [
                "-- Window functions on large result sets are expensive.",
                "-- Consider these optimizations:",
            ]
            if has_sort_child:
                suggestion_parts.append(
                    "-- 1. Add an index matching the PARTITION BY / ORDER BY columns"
                )
            suggestion_parts.extend([
                "-- 2. Filter rows BEFORE the window function (use a subquery/CTE)",
                "-- 3. Consider materializing results if the window is reused",
                "-- 4. Use ROWS BETWEEN for running aggregates instead of default RANGE",
            ])

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                context=context,
                title=f"Expensive window function ({actual_rows:,} rows, {cost_ratio:.0%} of plan cost)",
                description=(
                    f"WindowAgg processes {actual_rows:,} rows and accounts for "
                    f"{cost_ratio:.0%} of total plan cost. Window functions require "
                    f"sorting and maintaining frame state, which is expensive on "
                    f"large datasets."
                ),
                suggestion="\n".join(suggestion_parts),
                impact_band=ImpactBand.MEDIUM if cost_ratio < 0.5 else ImpactBand.HIGH,
                metrics={
                    "actual_rows": actual_rows,
                    "cost_ratio": round(cost_ratio, 4),
                    "total_cost": node.total_cost,
                    "has_sort": int(has_sort_child),
                },
            ))

        return findings
