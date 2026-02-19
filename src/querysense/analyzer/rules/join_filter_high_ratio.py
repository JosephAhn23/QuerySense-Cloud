"""
Rule: Join Filter High Discard Ratio

Detects join operations (Nested Loop, Hash Join, Merge Join) where the
"Rows Removed by Join Filter" is much larger than the rows actually kept,
indicating the join condition or join strategy is suboptimal.

Why it matters:
- "Rows Removed by Join Filter" means the executor joined two row sets and
  then threw away most of the combinations — this is wasted CPU and I/O
- High discard in a Nested Loop means the inner scan is executing many
  times for rows that don't match — a Hash Join or better index may help
- High discard in a Hash Join means the hash condition isn't selective
  enough and a secondary filter is doing the heavy lifting
- This pattern often indicates a missing join index or a suboptimal join
  order chosen by the planner due to bad statistics

When it happens:
- Missing index on the join column of the inner table
- Join condition on low-selectivity columns (e.g., status = status)
- Implicit cross-join behavior from ORM-generated queries
- Join on expression that prevents index usage

Detection:
- Join nodes with "Rows Removed by Join Filter" > threshold
- Ratio of removed rows to kept rows determines severity

Requires EXPLAIN ANALYZE (Rows Removed by Join Filter is runtime data).
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


class JoinFilterConfig(RuleConfig):
    """
    Configuration for join filter detection.

    Attributes:
        min_rows_removed: Minimum rows removed by join filter to trigger.
        warning_ratio: Removed/kept ratio to trigger WARNING.
        critical_ratio: Removed/kept ratio to trigger CRITICAL.
    """

    min_rows_removed: int = Field(
        default=10_000,
        ge=0,
        description="Minimum rows removed by join filter to trigger",
    )
    warning_ratio: float = Field(
        default=10.0,
        ge=1.0,
        description="Removed/kept ratio to trigger WARNING (e.g., 10 = 10x more removed than kept)",
    )
    critical_ratio: float = Field(
        default=100.0,
        ge=1.0,
        description="Removed/kept ratio to trigger CRITICAL",
    )


@register_rule
class JoinFilterHighRatio(Rule):
    """
    Detect joins where the join filter discards a disproportionate number
    of rows, suggesting the join is performing near-cartesian product
    behavior before filtering.
    """

    rule_id = "JOIN_FILTER_HIGH_RATIO"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects joins where the filter discards most combined rows"
    phase = RulePhase.PER_NODE

    config_schema = JoinFilterConfig

    _JOIN_TYPES = {"Nested Loop", "Hash Join", "Merge Join"}

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find join nodes with high filter discard ratios."""
        config: JoinFilterConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in self._JOIN_TYPES:
                continue

            # "Rows Removed by Join Filter" is in model_extra
            rows_removed = _get_extra_int(node, "Rows Removed by Join Filter")
            if rows_removed < config.min_rows_removed:
                continue

            actual_rows = node.actual_rows
            if actual_rows is None or actual_rows == 0:
                actual_rows = 1  # Prevent division by zero

            ratio = rows_removed / actual_rows

            if ratio < config.warning_ratio:
                continue

            # Determine severity
            if ratio >= config.critical_ratio:
                severity = Severity.CRITICAL
            else:
                severity = Severity.WARNING

            context = NodeContext.from_node(node, path, parent)

            # Compute impact score
            # High ratio + high volume = high impact
            ratio_score = min(ratio / 20.0, 5.0)  # ratio contributes up to 5
            volume_score = min(rows_removed / 500_000, 5.0)  # volume contributes up to 5
            impact_score = min(round(ratio_score + volume_score, 1), 10.0)

            # Get join condition info
            join_cond = (
                node.join_filter
                or node.hash_cond
                or node.merge_cond
                or "unknown"
            )

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"{node.node_type} filter discards {rows_removed:,} rows "
                    f"({ratio:.0f}x more than kept)"
                ),
                description=self._build_description(
                    node, actual_rows, rows_removed, ratio
                ),
                suggestion=self._build_suggestion(node),
                metrics={
                    "rows_kept": actual_rows,
                    "rows_removed_by_join_filter": rows_removed,
                    "discard_ratio": round(ratio, 2),
                    "total_cost": node.total_cost,
                    "join_type": node.node_type,
                },
                impact_band=(
                    ImpactBand.HIGH if ratio >= 100
                    else ImpactBand.MEDIUM
                ),
                impact_score=impact_score,
                assumptions=(
                    "The join filter is compensating for an imprecise join condition",
                    "A more selective join condition or index would reduce the row explosion",
                    "Row statistics for the joined tables are reasonably accurate",
                ),
                verification_steps=(
                    "Check if there's an index on the join column of the inner table",
                    "Verify statistics are current: ANALYZE <both_tables>",
                    "Consider rewriting with a more selective join condition",
                    "Try SET enable_nestloop = off to test alternative join strategies",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        kept: int,
        removed: int,
        ratio: float,
    ) -> str:
        """Build detailed description of the join filter problem."""
        parts = [
            f"{node.node_type} produced {kept + removed:,} row combinations "
            f"but the Join Filter kept only {kept:,} — discarding "
            f"{removed:,} rows ({ratio:.0f}x the kept count)."
        ]

        if node.join_filter:
            parts.append(f"Join Filter: {node.join_filter}")
        if node.hash_cond:
            parts.append(f"Hash Cond: {node.hash_cond}")
        if node.merge_cond:
            parts.append(f"Merge Cond: {node.merge_cond}")

        if node.node_type == "Nested Loop":
            loops = node.actual_loops or 1
            parts.append(
                f"The Nested Loop executed {loops:,} iterations. With a high "
                f"discard ratio, the inner scan is doing significant wasted work "
                f"on each iteration. Adding an index on the inner table's join "
                f"column or switching to a Hash Join may help."
            )
        elif node.node_type == "Hash Join":
            parts.append(
                "The Hash Join's condition is not selective enough — most "
                "rows that hash-match are then discarded by the Join Filter. "
                "This suggests the join condition should include additional "
                "columns for better selectivity."
            )

        if ratio > 100:
            parts.append(
                f"A {ratio:.0f}x discard ratio indicates near-cartesian join "
                f"behavior. This is one of the most impactful performance "
                f"problems to fix."
            )

        return " ".join(parts)

    def _build_suggestion(self, node: "PlanNode") -> str:
        """Build actionable fix suggestion."""
        lines: list[str] = []

        lines.append("-- 1. Add an index on the inner table's join column:")
        lines.append("-- CREATE INDEX ON <inner_table> (<join_column>);")
        lines.append("")

        if node.join_filter:
            lines.append("-- 2. If possible, move the Join Filter into the join condition:")
            lines.append(f"-- Current Join Filter: {node.join_filter}")
            lines.append("-- Rewrite: add these conditions to the ON clause")
            lines.append("")

        lines.append("-- 3. Update statistics on both tables:")
        lines.append("ANALYZE;  -- or ANALYZE <specific_tables>")
        lines.append("")

        if node.node_type == "Nested Loop":
            lines.append("-- 4. Test alternative join strategies:")
            lines.append("SET enable_nestloop = off;")
            lines.append("-- Re-run EXPLAIN ANALYZE to see if Hash/Merge Join is better")
            lines.append("")

        lines.append(
            "-- Docs: https://www.postgresql.org/docs/current/planner-optimizer.html"
        )

        return "\n".join(lines)


def _get_extra_int(node: "PlanNode", key: str) -> int:
    """Safely extract an integer from PlanNode.model_extra."""
    if node.model_extra:
        value = node.model_extra.get(key, 0)
        if isinstance(value, int):
            return value
    return 0
