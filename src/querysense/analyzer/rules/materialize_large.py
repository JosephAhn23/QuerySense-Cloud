"""Rule: Materialize Large Result — large Materialize nodes wasting memory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class MaterializeLargeConfig(RuleConfig):
    min_rows: int = Field(default=100_000, ge=1000, description="Minimum rows to trigger warning")
    critical_rows: int = Field(default=1_000_000, ge=10_000, description="Rows to escalate to critical")


@register_rule
class MaterializeLarge(Rule):
    """Detect Materialize nodes buffering large result sets."""

    rule_id = "MATERIALIZE_LARGE_RESULT"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Materialize node buffering large number of rows in memory"
    config_schema = MaterializeLargeConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: MaterializeLargeConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "Materialize":
                continue

            actual_rows = node.actual_rows or node.plan_rows or 0
            if actual_rows < config.min_rows:
                continue

            severity = (
                Severity.CRITICAL if actual_rows >= config.critical_rows
                else self.severity
            )
            context = NodeContext.from_node(node, path, parent)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Materialize buffering {actual_rows:,} rows",
                description=(
                    f"A Materialize node is buffering {actual_rows:,} rows in memory. "
                    f"This happens when PostgreSQL needs to re-read a subquery result "
                    f"multiple times (e.g., in nested loops). Large materializations "
                    f"consume significant memory and may spill to disk."
                ),
                suggestion=(
                    "-- Consider restructuring to avoid materialization:\n"
                    "-- 1. Replace correlated subqueries with JOINs\n"
                    "-- 2. Use EXISTS instead of IN for large subqueries\n"
                    "-- 3. Increase work_mem if spilling to disk\n"
                    "-- 4. Consider a materialized view for frequently-used subqueries"
                ),
                impact_band=ImpactBand.MEDIUM,
                metrics={
                    "materialized_rows": actual_rows,
                    "total_cost": node.total_cost,
                },
            ))

        return findings
