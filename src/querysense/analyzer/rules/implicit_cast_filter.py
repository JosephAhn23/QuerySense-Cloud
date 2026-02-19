"""Rule: Implicit Cast in Filter — type casts preventing index usage."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput

# Patterns that indicate implicit or explicit casts in filters
_CAST_PATTERNS = [
    re.compile(r"\((\w+)\)::(\w+)"),           # (column)::type
    re.compile(r"(\w+)::(\w+)\s*[=<>!]"),       # column::type = ...
    re.compile(r"CAST\((\w+)\s+AS\s+(\w+)\)", re.IGNORECASE),  # CAST(col AS type)
    re.compile(r"(\w+)::text\s"),               # column::text (common anti-pattern)
]

_FUNCTION_PATTERNS = [
    re.compile(r"lower\((\w+)\)", re.IGNORECASE),
    re.compile(r"upper\((\w+)\)", re.IGNORECASE),
    re.compile(r"trim\((\w+)\)", re.IGNORECASE),
    re.compile(r"date_trunc\([^,]+,\s*(\w+)\)", re.IGNORECASE),
    re.compile(r"extract\([^,]+\s+FROM\s+(\w+)\)", re.IGNORECASE),
]


class ImplicitCastConfig(RuleConfig):
    min_plan_rows: int = Field(default=1000, ge=0, description="Minimum rows to check")
    check_functions: bool = Field(default=True, description="Also flag function-wrapped columns")


@register_rule
class ImplicitCastFilter(Rule):
    """Detect implicit type casts and function calls in filter conditions."""

    rule_id = "IMPLICIT_CAST_FILTER"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Type cast or function in filter prevents index usage"
    config_schema = ImplicitCastConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: ImplicitCastConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Only check scan nodes with filters
            if not node.filter and not node.raw.get("Index Cond"):
                continue

            plan_rows = node.plan_rows or 0
            if plan_rows < config.min_plan_rows:
                continue

            filter_text = node.filter or ""
            index_cond = node.raw.get("Index Cond", "")
            combined = f"{filter_text} {index_cond}"

            issues: list[str] = []

            # Check for casts
            for pattern in _CAST_PATTERNS:
                matches = pattern.findall(combined)
                for match in matches:
                    col = match[0] if isinstance(match, tuple) else match
                    issues.append(f"Type cast on column '{col}'")

            # Check for function wrapping
            if config.check_functions:
                for pattern in _FUNCTION_PATTERNS:
                    matches = pattern.findall(combined)
                    for col in matches:
                        issues.append(f"Function call on column '{col}'")

            if not issues:
                continue

            table = node.relation_name or "unknown"
            context = NodeContext.from_node(node, path, parent)

            # Build suggestion based on issue type
            suggestion_lines = [
                f"-- Casts/functions in WHERE clauses prevent index usage on {table}.",
                f"-- Found: {'; '.join(issues[:3])}",
                f"--",
                f"-- Options:",
                f"-- 1. Store data in the correct type to avoid runtime casts",
                f"-- 2. Create an expression index:",
            ]

            # Try to suggest expression index for common patterns
            if any("lower" in i.lower() for i in issues):
                suggestion_lines.append(
                    f"CREATE INDEX ON {table} (LOWER(column_name));"
                )
            elif any("Type cast" in i for i in issues):
                suggestion_lines.append(
                    f"CREATE INDEX ON {table} ((column_name::target_type));"
                )
            else:
                suggestion_lines.append(
                    f"CREATE INDEX ON {table} (expression_here);"
                )

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                context=context,
                title=f"Cast/function in filter on {table} prevents index use",
                description=(
                    f"Filter condition on '{table}' contains type casts or function "
                    f"calls that prevent PostgreSQL from using a standard B-tree "
                    f"index. Issues found: {'; '.join(issues[:5])}. "
                    f"Filter: {filter_text[:100]}"
                ),
                suggestion="\n".join(suggestion_lines),
                impact_band=ImpactBand.MEDIUM,
                metrics={
                    "issues_found": len(issues),
                    "plan_rows": plan_rows,
                },
            ))

        return findings
