"""Rule: Limit Without Index — LIMIT with Seq Scan that could use an index."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class LimitWithoutIndexConfig(RuleConfig):
    min_child_rows: int = Field(default=10_000, ge=100, description="Minimum child rows to warn")
    max_limit_rows: int = Field(default=100, ge=1, description="Maximum LIMIT value to flag")


@register_rule
class LimitWithoutIndex(Rule):
    """Detect LIMIT on top of Seq Scan (index could satisfy LIMIT cheaply)."""

    rule_id = "LIMIT_WITHOUT_INDEX"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "LIMIT over sequential scan — an index could avoid scanning the full table"
    config_schema = LimitWithoutIndexConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: LimitWithoutIndexConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "Limit":
                continue

            # Check children for Seq Scan or Sort -> Seq Scan
            if not node.plans:
                continue

            child = node.plans[0]

            # Pattern 1: Limit -> Sort -> Seq Scan
            seq_scan_node = None
            sort_node = None
            if child.node_type == "Sort" and child.plans:
                sort_node = child
                grandchild = child.plans[0]
                if grandchild.node_type == "Seq Scan":
                    seq_scan_node = grandchild

            # Pattern 2: Limit -> Seq Scan
            elif child.node_type == "Seq Scan":
                seq_scan_node = child

            if seq_scan_node is None:
                continue

            child_rows = seq_scan_node.actual_rows or seq_scan_node.plan_rows or 0
            if child_rows < config.min_child_rows:
                continue

            limit_rows = node.actual_rows or node.plan_rows or 0
            if limit_rows > config.max_limit_rows:
                continue

            table = seq_scan_node.relation_name or "unknown"
            context = NodeContext.from_node(node, path, parent)

            sort_info = ""
            suggestion = ""
            if sort_node:
                sort_key = sort_node.raw.get("Sort Key", [])
                sort_info = f" with ORDER BY {', '.join(str(k) for k in sort_key)}" if sort_key else ""
                if sort_key:
                    cols = ", ".join(str(k).split()[0] for k in sort_key)
                    suggestion = (
                        f"-- An index can satisfy both the ORDER BY and LIMIT:\n"
                        f"CREATE INDEX ON {table} ({cols});\n"
                        f"-- PostgreSQL will use an index scan and stop after {limit_rows} rows"
                    )
            if not suggestion:
                suggestion = (
                    f"-- Add an index on the filter/sort columns of {table}\n"
                    f"-- so PostgreSQL can stop scanning after {limit_rows} rows"
                )

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                context=context,
                title=f"LIMIT {limit_rows} scans {child_rows:,} rows from {table}{sort_info}",
                description=(
                    f"A LIMIT {limit_rows} query is scanning {child_rows:,} rows via "
                    f"sequential scan on '{table}'{sort_info}. With an appropriate "
                    f"index, PostgreSQL could read only {limit_rows} rows from the "
                    f"index instead of scanning and sorting the entire table."
                ),
                suggestion=suggestion,
                impact_band=ImpactBand.HIGH,
                metrics={
                    "limit_rows": limit_rows,
                    "scanned_rows": child_rows,
                    "waste_ratio": round(child_rows / max(limit_rows, 1), 1),
                },
            ))

        return findings
