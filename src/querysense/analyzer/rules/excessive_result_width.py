"""Rule: Excessive Result Width — queries returning too many columns."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class ExcessiveWidthConfig(RuleConfig):
    width_warning_bytes: int = Field(default=500, ge=100, description="Plan Width bytes to warn")
    width_critical_bytes: int = Field(default=2000, ge=500, description="Plan Width bytes for critical")
    min_rows: int = Field(default=10_000, ge=100, description="Minimum rows to check")


@register_rule
class ExcessiveResultWidth(Rule):
    """Detect queries with excessively wide result sets."""

    rule_id = "EXCESSIVE_RESULT_WIDTH"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Query returns very wide rows — may indicate SELECT * anti-pattern"
    config_schema = ExcessiveWidthConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: ExcessiveWidthConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        # Only check root node or scan nodes
        for path, node, parent in self.iter_nodes_with_parent(explain):
            if not node.is_scan_node and path.depth > 0:
                continue

            plan_width = node.raw.get("Plan Width", 0)
            actual_rows = node.actual_rows or node.plan_rows or 0

            if plan_width < config.width_warning_bytes:
                continue
            if actual_rows < config.min_rows:
                continue

            severity = (
                Severity.WARNING if plan_width >= config.width_critical_bytes
                else self.severity
            )

            table = node.relation_name or "result"
            context = NodeContext.from_node(node, path, parent)
            estimated_mb = (plan_width * actual_rows) / (1024 * 1024)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Wide result: {plan_width} bytes/row x {actual_rows:,} rows (~{estimated_mb:.0f}MB) from {table}",
                description=(
                    f"Query returns {plan_width} bytes per row across {actual_rows:,} "
                    f"rows (~{estimated_mb:.0f}MB total). Wide results increase I/O, "
                    f"network transfer, and memory usage. This often indicates a "
                    f"SELECT * pattern when only a few columns are needed."
                ),
                suggestion=(
                    f"-- Select only the columns you need instead of SELECT *\n"
                    f"-- This reduces I/O, memory, and network transfer\n"
                    f"-- Before: SELECT * FROM {table} WHERE ...\n"
                    f"-- After:  SELECT col1, col2 FROM {table} WHERE ...\n"
                    f"--\n"
                    f"-- For index-only scans, a covering index can avoid heap access:\n"
                    f"-- CREATE INDEX ON {table} (filter_col) INCLUDE (col1, col2);"
                ),
                impact_band=ImpactBand.LOW if estimated_mb < 100 else ImpactBand.MEDIUM,
                metrics={
                    "plan_width_bytes": plan_width,
                    "actual_rows": actual_rows,
                    "estimated_mb": round(estimated_mb, 1),
                },
            ))

        return findings
