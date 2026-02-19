"""
Rule: CTE Materialization Risk

Detects Common Table Expressions (CTEs) that are materialized when they
could be inlined, and vice versa — a perennial source of "spooky"
regressions across PostgreSQL version upgrades.

Why it matters:
- Before Postgres 12, CTEs were always materialized (optimization fences)
- After Postgres 12, non-recursive CTEs referenced once are inlined by default
- Teams relying on CTE fences for plan stability get broken on upgrade
- Teams suffering from CTE fences get unexpected plan changes too
- MATERIALIZED/NOT MATERIALIZED hints exist but aren't widely used
- CTE materialization defeats predicate pushdown and join reordering

Detection strategy:
- CTE Scan nodes indicate materialized CTEs
- Check if the CTE is referenced only once (unnecessary materialization)
- Detect Materialize nodes under CTE paths
- Flag CTE Scans in performance-critical positions (join inner, filter-heavy)

When it's okay:
- CTEs referenced multiple times (materialization avoids re-execution)
- Deliberate optimization fences using MATERIALIZED keyword
- Recursive CTEs (always materialized, by design)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import (
    Finding,
    ImpactBand,
    NodeContext,
    RulePhase,
    Severity,
)
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput, PlanNode


class CTEMaterializationConfig(RuleConfig):
    """
    Configuration for CTE materialization risk detection.

    Attributes:
        min_cost: Minimum total cost of the CTE Scan to report.
    """

    min_cost: float = Field(
        default=100.0,
        ge=0.0,
        description="Minimum total cost of CTE Scan node to report",
    )


@register_rule
class CTEMaterializationRisk(Rule):
    """
    Detect CTE materialization patterns that may cause regressions.

    Flags:
    1. CTE Scan nodes (materialized CTEs) with high cost
    2. Single-reference CTEs that are materialized (wasteful)
    3. CTE Scans that block predicate pushdown (filter on outer query
       that could be pushed into the CTE)
    """

    rule_id = "CTE_MATERIALIZATION_RISK"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects CTE materialization that may degrade performance"
    phase = RulePhase.PER_NODE

    config_schema = CTEMaterializationConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find CTE Scan nodes with materialization risk."""
        config: CTEMaterializationConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        # First pass: count CTE references by name
        cte_ref_counts: dict[str, int] = {}
        for path, node in self.iter_nodes(explain):
            if node.node_type == "CTE Scan":
                cte_name = _get_cte_name(node)
                if cte_name:
                    cte_ref_counts[cte_name] = cte_ref_counts.get(cte_name, 0) + 1

        # Second pass: analyze each CTE Scan
        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "CTE Scan":
                continue

            if node.total_cost < config.min_cost:
                continue

            cte_name = _get_cte_name(node)
            ref_count = cte_ref_counts.get(cte_name or "", 0)

            context = NodeContext.from_node(node, path, parent)

            # Single-reference CTE that is materialized
            if ref_count == 1:
                findings.append(self._single_ref_finding(
                    node, context, cte_name, parent
                ))
            else:
                # Multi-reference CTE — materialization is justified,
                # but flag if cost is very high
                if node.total_cost > config.min_cost * 10:
                    findings.append(self._expensive_cte_finding(
                        node, context, cte_name, ref_count
                    ))

            # Check for blocked predicate pushdown
            pushdown_finding = self._check_blocked_pushdown(
                node, context, cte_name, parent
            )
            if pushdown_finding:
                findings.append(pushdown_finding)

        return findings

    def _single_ref_finding(
        self,
        node: "PlanNode",
        context: NodeContext,
        cte_name: str | None,
        parent: "PlanNode | None",
    ) -> Finding:
        """Finding for single-reference materialized CTE."""
        name = cte_name or "unnamed CTE"
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING,
            context=context,
            title=(
                f"CTE '{name}' materialized but referenced only once "
                f"(cost={node.total_cost:,.0f})"
            ),
            description=(
                f"CTE '{name}' is materialized (CTE Scan) but referenced only "
                f"once in the query. In PostgreSQL 12+, single-reference CTEs "
                f"are normally inlined (not materialized), allowing the planner "
                f"to push predicates and reorder joins.\n\n"
                f"If this CTE is materialized, it may be because:\n"
                f"- The MATERIALIZED keyword was explicitly used\n"
                f"- The CTE has side effects (data-modifying statements)\n"
                f"- The CTE is recursive\n"
                f"- You're running PostgreSQL < 12 where CTEs are always materialized"
            ),
            suggestion=(
                f"-- Try inlining the CTE for better optimization:\n"
                f"-- Replace WITH {name} AS (...) SELECT ... FROM {name}\n"
                f"-- with a subquery or JOIN\n"
                f"\n"
                f"-- Or explicitly control materialization (Postgres 12+):\n"
                f"-- WITH {name} AS NOT MATERIALIZED (...)\n"
                f"\n"
                f"-- Docs: https://www.postgresql.org/docs/current/queries-with.html"
            ),
            metrics={
                "total_cost": node.total_cost,
                "ref_count": 1,
            },
            impact_band=ImpactBand.MEDIUM,
            assumptions=(
                "CTE is not recursive",
                "CTE does not contain data-modifying statements",
                "Inlining would allow predicate pushdown",
            ),
            verification_steps=(
                "Rewrite the CTE as a subquery and compare plans",
                "Test with NOT MATERIALIZED hint (Postgres 12+)",
                "Check if predicates from the outer query could benefit from pushdown",
            ),
        )

    def _expensive_cte_finding(
        self,
        node: "PlanNode",
        context: NodeContext,
        cte_name: str | None,
        ref_count: int,
    ) -> Finding:
        """Finding for expensive multi-reference CTE."""
        name = cte_name or "unnamed CTE"
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.INFO,
            context=context,
            title=(
                f"Expensive materialized CTE '{name}' "
                f"(cost={node.total_cost:,.0f}, {ref_count} references)"
            ),
            description=(
                f"CTE '{name}' is materialized and referenced {ref_count} times. "
                f"Materialization is correct here (avoids re-execution), but the "
                f"CTE is expensive (cost={node.total_cost:,.0f}). Consider "
                f"optimizing the CTE body itself or creating a temporary table."
            ),
            suggestion=(
                f"-- If the CTE is expensive, consider materializing to a temp table:\n"
                f"CREATE TEMP TABLE tmp_{name} AS (<cte_body>);\n"
                f"ANALYZE tmp_{name};\n"
                f"-- Then use tmp_{name} in the main query\n"
                f"-- This gives the planner real statistics on the materialized data"
            ),
            metrics={
                "total_cost": node.total_cost,
                "ref_count": ref_count,
            },
            impact_band=ImpactBand.LOW,
        )

    def _check_blocked_pushdown(
        self,
        node: "PlanNode",
        context: NodeContext,
        cte_name: str | None,
        parent: "PlanNode | None",
    ) -> Finding | None:
        """Check if outer filter could be pushed into the CTE."""
        if parent is None:
            return None

        # If the parent has a filter that references the CTE,
        # pushdown is blocked by materialization
        if not parent.filter:
            return None

        # Heuristic: if parent filters rows from the CTE Scan,
        # pushdown would have been beneficial
        rows_removed = parent.rows_removed_by_filter or 0
        actual_rows = parent.actual_rows or parent.plan_rows or 0

        if rows_removed == 0:
            return None

        total_before = actual_rows + rows_removed
        if total_before == 0:
            return None

        filter_selectivity = actual_rows / total_before

        # Only flag if the filter is selective (removes > 50% of rows)
        if filter_selectivity > 0.5:
            return None

        name = cte_name or "unnamed CTE"

        return Finding(
            rule_id=self.rule_id,
            severity=Severity.INFO,
            context=context,
            title=(
                f"CTE '{name}' blocks predicate pushdown "
                f"(filter removes {rows_removed:,} of {total_before:,} rows)"
            ),
            description=(
                f"The parent node filters {rows_removed:,} rows from CTE '{name}' "
                f"(selectivity={filter_selectivity:.0%}). Because the CTE is "
                f"materialized, this filter cannot be pushed into the CTE body, "
                f"meaning the CTE produces and materializes rows that are "
                f"immediately discarded.\n\n"
                f"Parent filter: {parent.filter}"
            ),
            suggestion=(
                f"-- Move the filter into the CTE body:\n"
                f"-- WITH {name} AS (\n"
                f"--   SELECT ... FROM ... WHERE <moved_filter>\n"
                f"-- )\n"
                f"-- Or use NOT MATERIALIZED (Postgres 12+) to allow pushdown:\n"
                f"-- WITH {name} AS NOT MATERIALIZED (...)"
            ),
            metrics={
                "rows_removed": rows_removed,
                "total_before_filter": total_before,
                "filter_selectivity": round(filter_selectivity, 4),
            },
            impact_band=ImpactBand.MEDIUM,
        )


def _get_cte_name(node: "PlanNode") -> str | None:
    """
    Extract the CTE name from a CTE Scan node.

    The CTE name is stored in model_extra as "CTE Name" or in the alias.
    """
    if node.model_extra:
        name = node.model_extra.get("CTE Name")
        if isinstance(name, str):
            return name

    # Fallback: the alias often matches the CTE name
    if node.alias:
        return node.alias

    return None
