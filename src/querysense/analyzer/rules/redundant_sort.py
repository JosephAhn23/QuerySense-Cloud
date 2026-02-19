"""Rule: Redundant Sort — detects consecutive sort operations that could be eliminated."""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


@register_rule
class RedundantSort(Rule):
    """Detect multiple Sort nodes that may be redundant."""

    rule_id = "REDUNDANT_SORT"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Multiple sort operations that could be consolidated or eliminated"
    phase = RulePhase.AGGREGATE

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Collect all sort nodes
        sort_nodes: list[tuple] = []
        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type == "Sort":
                sort_key = node.raw.get("Sort Key", [])
                sort_nodes.append((path, node, parent, sort_key))

        if len(sort_nodes) < 2:
            return findings

        # Check for consecutive sorts with same or subset keys
        for i in range(len(sort_nodes)):
            for j in range(i + 1, len(sort_nodes)):
                _, node_i, _, keys_i = sort_nodes[i]
                path_j, node_j, parent_j, keys_j = sort_nodes[j]

                # Same sort keys = redundant
                if keys_i and keys_j and set(keys_i) == set(keys_j):
                    context = NodeContext.from_node(node_j, path_j, parent_j)
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        context=context,
                        title=f"Redundant sort on {', '.join(str(k) for k in keys_j)}",
                        description=(
                            f"This Sort node uses the same key(s) as another Sort in "
                            f"the plan. The data is already sorted from the first sort. "
                            f"This usually happens with CTEs, subqueries, or when the "
                            f"planner doesn't recognize existing order."
                        ),
                        suggestion=(
                            f"-- Consider restructuring the query to avoid redundant sorts\n"
                            f"-- If using CTEs, try inlining them (PG12+ can auto-inline)\n"
                            f"-- Or add an ORDER BY only at the final query level"
                        ),
                        impact_band=ImpactBand.LOW,
                        metrics={
                            "sort_count": len(sort_nodes),
                            "sort_cost": node_j.total_cost,
                        },
                    ))
                    break  # Only report once per duplicate pair

        return findings
