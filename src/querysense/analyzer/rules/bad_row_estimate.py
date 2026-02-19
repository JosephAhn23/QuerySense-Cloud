"""
Rule: Bad Row Estimate

Detects severe mismatches between planner estimates and actual row counts,
and chains through to identify downstream join strategy risks driven by
those misestimates.

Why it matters:
- PostgreSQL plans queries based on row estimates
- Wrong estimates → wrong join strategies, wrong index choices, wrong memory allocation
- A 1000x error means the planner is making decisions based on lies
- Cardinality estimation accuracy is the main determinant of plan quality:
  a 50x-80x misestimate can drive a Hash Join → Nested Loop flip that
  explodes execution time

When it happens:
- After bulk INSERT/UPDATE/DELETE without ANALYZE
- Tables with uneven data distribution
- Tables with many NULLs
- After schema changes
- Correlated columns without extended statistics

Join-risk chaining (v2.0):
- When a misestimate occurs on a node whose parent is a join, the rule
  now flags the downstream consequence: the join strategy may be wrong.
- This turns "bad estimate" from a diagnostic observation into a
  deterministic policy: "block merges that introduce unstable join
  patterns driven by misestimates."
"""

from __future__ import annotations

from typing import TYPE_CHECKING

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


# Join types that are fragile under misestimation
_JOIN_TYPES = {"Nested Loop", "Hash Join", "Merge Join"}

# Risky join/estimate combinations: (join_type, estimate_direction)
# Nested Loop is dangerous when rows are underestimated (more rows → more loops)
# Hash Join is dangerous when rows are underestimated (hash table too small)
_RISKY_JOIN_PATTERNS: dict[str, str] = {
    "Nested Loop": "underestimated",
    "Hash Join": "underestimated",
}


@register_rule
class BadRowEstimate(Rule):
    """
    Detect severe row estimation errors and downstream join-risk.

    Severity based on ratio:
    - > 1000x: CRITICAL (production emergency)
    - > 100x: WARNING (needs attention)
    - > 10x: INFO (worth investigating)

    v2.0: Now chains through to parent join nodes to flag cases where
    the misestimate directly drives a risky join strategy choice.
    """

    rule_id = "BAD_ROW_ESTIMATE"
    version = "2.0.0"
    severity = Severity.WARNING  # Default, overridden based on ratio
    description = "Detects severe row estimation errors and downstream join risks"
    phase = RulePhase.PER_NODE

    # Provide capability for downstream rules
    provides: tuple[str, ...] = ("join_findings",)

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find nodes with severe estimation errors and join-risk chaining."""
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Need both estimate and actual to compare
            if node.plan_rows is None or node.actual_rows is None:
                continue

            # Skip tiny tables (noise)
            if node.actual_rows < 100:
                continue

            # Calculate ratio (handle division by zero)
            estimated = max(node.plan_rows, 1)
            actual = node.actual_rows

            # Ratio can be in either direction
            if actual > estimated:
                ratio = actual / estimated
                direction = "underestimated"
            else:
                ratio = estimated / actual
                direction = "overestimated"

            # Skip small errors
            if ratio < 10:
                continue

            # Determine severity based on ratio
            if ratio >= 1000:
                severity = Severity.CRITICAL
            elif ratio >= 100:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            # Build context
            context = NodeContext.from_node(node, path, parent)
            table_name = node.relation_name or "unknown table"

            finding = Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Row estimation error on {table_name} ({ratio:,.0f}x off)",
                description=self._build_description(node, ratio, direction),
                suggestion=self._build_suggestion(node, ratio),
                metrics={
                    "estimated_rows": node.plan_rows,
                    "actual_rows": actual,
                    "ratio": ratio,
                    "direction": direction,
                },
                impact_band=(
                    ImpactBand.HIGH if ratio >= 100
                    else ImpactBand.MEDIUM if ratio >= 50
                    else ImpactBand.LOW
                ),
                assumptions=(
                    "Statistics are stale or insufficient for this data distribution",
                    "ANALYZE would improve estimate accuracy",
                ),
                verification_steps=(
                    "Run ANALYZE on the affected table(s)",
                    "Check n_distinct and correlation in pg_stats for the filtered column",
                    "Consider CREATE STATISTICS for correlated columns",
                ),
            )
            findings.append(finding)

            # === Join-risk chaining (v2.0) ===
            # If the parent is a join node, flag the downstream consequence
            if parent and parent.node_type in _JOIN_TYPES:
                join_finding = self._check_join_risk(
                    node, parent, path, ratio, direction, table_name
                )
                if join_finding:
                    findings.append(join_finding)

        return findings

    def _check_join_risk(
        self,
        node: "PlanNode",
        parent: "PlanNode",
        path,
        ratio: float,
        direction: str,
        table_name: str,
    ) -> Finding | None:
        """
        Check if a misestimate drives a risky join strategy.

        Returns a secondary finding when the parent join type is known
        to be fragile under the observed direction of misestimation.
        """
        join_type = parent.node_type

        # Check if this is a risky combination
        risky_direction = _RISKY_JOIN_PATTERNS.get(join_type)
        if risky_direction and direction != risky_direction:
            return None  # The misestimate direction doesn't trigger risk for this join

        # Only flag significant misestimates for join risk
        if ratio < 50:
            return None

        # Determine what would be a safer join
        if join_type == "Nested Loop":
            safer_join = "Hash Join or Merge Join"
            risk_desc = (
                f"The planner chose Nested Loop because it estimated far fewer "
                f"rows than actually exist. With {ratio:,.0f}x more rows, "
                f"the Nested Loop executes far more iterations than planned, "
                f"potentially causing orders-of-magnitude slowdown."
            )
        elif join_type == "Hash Join":
            safer_join = "Merge Join"
            risk_desc = (
                f"The planner sized the hash table for {node.plan_rows:,} rows "
                f"but {node.actual_rows:,} rows arrived ({ratio:,.0f}x more). "
                f"This likely caused hash spills to disk, degrading performance."
            )
        else:
            safer_join = "alternative join strategy"
            risk_desc = (
                f"Row estimation error of {ratio:,.0f}x on a join input "
                f"may have caused the planner to choose a suboptimal "
                f"join strategy."
            )

        context = NodeContext.from_node(parent, path)

        return Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING,
            context=context,
            title=(
                f"Misestimate-driven {join_type} on {table_name} "
                f"({ratio:,.0f}x off → risky join)"
            ),
            description=(
                f"{risk_desc}\n\n"
                f"Root cause: row estimate on '{table_name}' was {ratio:,.0f}x "
                f"off ({direction}). Fix the estimate to let the planner choose "
                f"the right join strategy."
            ),
            suggestion=(
                f"-- Fix the root cause (statistics):\n"
                f"ANALYZE {table_name};\n"
                f"\n"
                f"-- For correlated columns, add extended statistics:\n"
                f"CREATE STATISTICS ON col1, col2 FROM {table_name};\n"
                f"ANALYZE {table_name};\n"
                f"\n"
                f"-- To verify improvement:\n"
                f"-- 1. Run EXPLAIN ANALYZE after ANALYZE\n"
                f"-- 2. Check if join type changes to {safer_join}\n"
                f"-- 3. Compare execution times"
            ),
            metrics={
                "join_type": join_type,
                "estimated_rows": node.plan_rows or 0,
                "actual_rows": node.actual_rows or 0,
                "ratio": ratio,
                "direction": direction,
            },
            impact_band=ImpactBand.HIGH,
            assumptions=(
                f"The planner would choose {safer_join} with accurate estimates",
                "The misestimate is the root cause of the join strategy choice",
            ),
            verification_steps=(
                "Run ANALYZE and re-run EXPLAIN ANALYZE to see if join type changes",
                "Test with SET enable_nestloop = off to compare Hash Join performance",
                "Check if extended statistics would improve the estimate",
            ),
        )

    def _build_description(self, node: "PlanNode", ratio: float, direction: str) -> str:
        """Build description explaining the impact."""
        table = node.relation_name or "this table"

        parts = [
            f"Planner {direction} by {ratio:,.0f}x.",
            f"Estimated: {node.plan_rows:,} rows. Actual: {node.actual_rows:,} rows.",
        ]

        if ratio >= 100:
            parts.append(
                "When estimates are this wrong, PostgreSQL makes bad decisions: "
                "picks wrong join strategies, disables helpful indexes, "
                "allocates insufficient memory."
            )

        return " ".join(parts)

    def _build_suggestion(self, node: "PlanNode", ratio: float) -> str:
        """Build actionable suggestion."""
        table = node.relation_name
        docs_url = "https://www.postgresql.org/docs/current/routine-vacuuming.html#VACUUM-FOR-STATISTICS"

        if table:
            sql = f"ANALYZE {table};"
        else:
            sql = "ANALYZE;"

        lines = [
            sql,
            "-- Run ANALYZE after bulk inserts/updates/deletes",
        ]

        if ratio >= 50:
            lines.extend([
                "",
                "-- For persistent misestimates, add extended statistics:",
                "-- CREATE STATISTICS ON col1, col2 FROM <table>;",
                "-- ANALYZE <table>;",
                "",
                "-- Or increase statistics target for the column:",
                "-- ALTER TABLE <table> ALTER COLUMN <col> SET STATISTICS 1000;",
                "-- ANALYZE <table>;",
            ])

        lines.extend([
            "",
            f"-- Docs: {docs_url}",
        ])

        return "\n".join(lines)
