"""Rule: Append Many Children — detects UNION ALL or partition scans with many branches."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class AppendConfig(RuleConfig):
    min_children: int = Field(default=10, ge=3, description="Minimum child nodes to warn")
    critical_children: int = Field(default=50, ge=10, description="Children to escalate to critical")


@register_rule
class AppendManyChildren(Rule):
    """Detect Append/MergeAppend with many child plans."""

    rule_id = "APPEND_MANY_CHILDREN"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Append/MergeAppend scanning many partitions or UNION branches"
    config_schema = AppendConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: AppendConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in ("Append", "MergeAppend"):
                continue

            child_count = len(node.plans) if node.plans else 0
            if child_count < config.min_children:
                continue

            severity = (
                Severity.CRITICAL if child_count >= config.critical_children
                else self.severity
            )
            context = NodeContext.from_node(node, path, parent)

            # Check if children are partition scans
            scan_types = set()
            tables = set()
            if node.plans:
                for child in node.plans:
                    scan_types.add(child.node_type)
                    if child.relation_name:
                        tables.add(child.relation_name)

            is_partition = len(tables) > 1 and any("Scan" in t for t in scan_types)

            if is_partition:
                description = (
                    f"{node.node_type} scans {child_count} partitions. "
                    f"This usually means partition pruning is not working — "
                    f"the query doesn't include the partition key in WHERE."
                )
                suggestion = (
                    "-- Add the partition key to WHERE to enable partition pruning\n"
                    "-- Check: SHOW enable_partition_pruning; (should be 'on')\n"
                    "-- The query should filter on the partitioned column"
                )
            else:
                description = (
                    f"{node.node_type} combines {child_count} branches. "
                    f"Large UNION ALL chains are often a sign that the query "
                    f"could be restructured using a single scan with OR conditions "
                    f"or an IN clause."
                )
                suggestion = (
                    "-- Consider replacing UNION ALL chains with:\n"
                    "-- 1. A single query with OR / IN conditions\n"
                    "-- 2. A VALUES list joined to the main table\n"
                    "-- 3. An ANY(ARRAY[...]) predicate"
                )

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"{node.node_type} with {child_count} children",
                description=description,
                suggestion=suggestion,
                impact_band=ImpactBand.MEDIUM if child_count < 30 else ImpactBand.HIGH,
                metrics={
                    "child_count": child_count,
                    "is_partition_scan": int(is_partition),
                    "total_cost": node.total_cost,
                },
            ))

        return findings
