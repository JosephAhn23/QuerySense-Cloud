"""Rule: TID Scan Performance — detects TID scans which may indicate design issues."""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


@register_rule
class TidScanPerformance(Rule):
    """Detect TID scans which may indicate application-level ctid usage."""

    rule_id = "TID_SCAN_DETECTED"
    version = "1.0.0"
    severity = Severity.INFO
    description = "TID scan detected — may indicate ctid-based access anti-pattern"

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "Tid Scan":
                continue

            table = node.relation_name or "unknown"
            context = NodeContext.from_node(node, path, parent)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                context=context,
                title=f"TID Scan on {table}",
                description=(
                    f"A TID (Tuple ID) scan accesses rows by their physical location "
                    f"(ctid). While fast for single-row access, relying on ctids is "
                    f"fragile — they change after VACUUM, UPDATE, or table rewrite. "
                    f"This pattern usually indicates the application is caching ctids, "
                    f"which can lead to wrong-row bugs."
                ),
                suggestion=(
                    f"-- Replace ctid-based access with a proper primary key lookup\n"
                    f"-- Before: SELECT * FROM {table} WHERE ctid = '(0,1)'\n"
                    f"-- After:  SELECT * FROM {table} WHERE id = 123"
                ),
                impact_band=ImpactBand.LOW,
                metrics={"total_cost": node.total_cost},
            ))

        return findings
