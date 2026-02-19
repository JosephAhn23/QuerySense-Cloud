"""Rule: Sequential Scan Without Filter — full table scan with no WHERE clause."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class SeqScanNoFilterConfig(RuleConfig):
    min_rows: int = Field(default=50_000, ge=1000, description="Minimum rows for warning")
    critical_rows: int = Field(default=500_000, ge=10_000, description="Rows to escalate")


@register_rule
class SeqScanNoFilter(Rule):
    """Detect sequential scans with no filter (reading entire table)."""

    rule_id = "SEQ_SCAN_NO_FILTER"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Sequential scan reading entire table with no filter condition"
    config_schema = SeqScanNoFilterConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: SeqScanNoFilterConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "Seq Scan":
                continue

            # This rule specifically targets scans WITHOUT filters
            if node.filter or node.raw.get("Index Cond"):
                continue

            actual_rows = node.actual_rows or node.plan_rows or 0
            if actual_rows < config.min_rows:
                continue

            severity = (
                Severity.CRITICAL if actual_rows >= config.critical_rows
                else self.severity
            )

            table = node.relation_name or "unknown"
            context = NodeContext.from_node(node, path, parent)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Full table scan on {table} ({actual_rows:,} rows, no filter)",
                description=(
                    f"Sequential scan reads all {actual_rows:,} rows from '{table}' "
                    f"with no WHERE clause filtering. This typically means:\n"
                    f"1. The query is missing a WHERE clause\n"
                    f"2. A JOIN is producing a cross-product\n"
                    f"3. The application is loading an entire table into memory"
                ),
                suggestion=(
                    f"-- Add a WHERE clause to filter rows:\n"
                    f"-- SELECT ... FROM {table} WHERE <condition>;\n"
                    f"--\n"
                    f"-- If you need all rows, consider:\n"
                    f"-- 1. LIMIT to paginate results\n"
                    f"-- 2. A materialized view for aggregations\n"
                    f"-- 3. COPY for bulk export instead of SELECT *"
                ),
                impact_band=ImpactBand.MEDIUM if actual_rows < 200_000 else ImpactBand.HIGH,
                metrics={
                    "rows_scanned": actual_rows,
                    "total_cost": node.total_cost,
                },
            ))

        return findings
