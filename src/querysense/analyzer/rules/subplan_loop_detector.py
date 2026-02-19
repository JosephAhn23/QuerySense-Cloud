"""
Rule: Correlated SubPlan Loop Detector

Inspired by pganalyze "Waiting for Postgres 17: Improved EXPLAIN for
SubPlan nodes" (E108) — SubPlan nodes execute once per parent row,
which can be catastrophic for large tables.

From the article:
  - A SubPlan on tenk1 (10K rows) executed the onek scan 10,000 times
  - Postgres uses SubPlans when it can't pull up a sub-SELECT into a JOIN
  - ANY can often be pulled up into a Semi Join, but ALL cannot

Detection:
  Find SubPlan-like patterns in EXPLAIN output:
  - Nodes with high actual_loops relative to parent rows
  - Filter conditions referencing SubPlan (from node.raw)
  - Nodes nested under scans with disproportionate loop counts
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


class SubPlanLoopConfig(RuleConfig):
    min_loops: int = Field(
        default=100,
        ge=1,
        description="Minimum loop count to trigger a finding",
    )
    critical_loops: int = Field(
        default=10_000,
        ge=1,
        description="Loop count for CRITICAL severity",
    )


@register_rule
class SubPlanLoopDetector(Rule):
    """
    Detect nodes with excessive loop counts indicating a correlated
    subplan that executes once per parent row.

    When Postgres can't pull up a sub-SELECT into a JOIN, it creates
    a SubPlan that runs N times (where N = parent row count). This
    turns an O(n) operation into O(n*m) and is often the root cause
    of unexpectedly slow queries.
    """

    rule_id = "SUBPLAN_HIGH_LOOPS"
    version = "1.0.0"
    severity = Severity.WARNING
    description = (
        "Detects correlated subplans with high loop counts that "
        "execute once per parent row"
    )
    phase = RulePhase.PER_NODE
    config_schema = SubPlanLoopConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: SubPlanLoopConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            loops = node.actual_loops
            if loops is None or loops < config.min_loops:
                continue

            if parent is None:
                continue

            parent_loops = parent.actual_loops or 1
            if loops <= parent_loops:
                continue

            parent_filter = parent.filter or ""
            parent_raw = parent.raw if hasattr(parent, "raw") else {}
            filter_str = parent_raw.get("Filter", parent_filter)

            is_subplan_like = (
                "SubPlan" in str(filter_str)
                or "InitPlan" in str(filter_str)
                or loops > parent_loops * 2
            )

            if not is_subplan_like and loops <= config.min_loops:
                continue

            if loops >= config.critical_loops:
                severity = Severity.CRITICAL
            elif loops >= config.min_loops * 10:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "inner relation"

            per_loop_time = node.actual_total_time or 0.0
            total_time = per_loop_time * loops

            base_score = 3.0
            if loops >= 10_000:
                base_score = 8.0
            elif loops >= 1_000:
                base_score = 6.0
            elif loops >= 100:
                base_score = 4.0
            impact_score = min(round(base_score, 1), 10.0)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"{node.node_type} on {table} executes {loops:,} times "
                    f"(correlated subplan pattern)"
                ),
                description=self._build_description(
                    node, parent, loops, per_loop_time, total_time,
                ),
                suggestion=self._build_suggestion(node, parent),
                metrics={
                    "actual_loops": loops,
                    "parent_loops": parent_loops,
                    "per_loop_time_ms": round(per_loop_time, 3),
                    "total_time_ms": round(total_time, 3),
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.HIGH if loops >= 10_000
                    else ImpactBand.MEDIUM if loops >= 1_000
                    else ImpactBand.LOW
                ),
                impact_score=impact_score,
                assumptions=(
                    "This node is part of a correlated subplan or nested loop",
                    "High loop count causes O(n*m) behavior",
                    "Rewriting as a JOIN or using EXISTS could reduce loops to 1",
                ),
                verification_steps=(
                    "Check if the sub-SELECT can use ANY instead of ALL",
                    "Try rewriting as an explicit JOIN or EXISTS",
                    "Consider adding an index on the join/filter columns",
                    "Check if PG17+ improved SubPlan display helps diagnosis",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        parent: "PlanNode",
        loops: int,
        per_loop_time: float,
        total_time: float,
    ) -> str:
        table = node.relation_name or "the inner relation"
        parent_type = parent.node_type

        parts = [
            f"{node.node_type} on {table} is executed {loops:,} times "
            f"under a {parent_type} node."
        ]

        if per_loop_time > 0:
            parts.append(
                f"Each execution takes {per_loop_time:.3f}ms, "
                f"for a total of {total_time:.1f}ms."
            )

        parts.append(
            "This pattern typically indicates a correlated subplan — "
            "a sub-SELECT that Postgres couldn't pull up into a JOIN. "
            "The subplan runs once per parent row, causing O(n*m) behavior. "
            "Postgres uses SubPlans when ALL, NOT IN, or certain correlated "
            "WHERE clauses prevent join pull-up."
        )

        if loops >= 10_000:
            parts.append(
                f"At {loops:,} loops this is severely impacting performance. "
                f"Rewriting the query to use EXISTS or an explicit JOIN "
                f"could reduce this to a single pass."
            )

        return " ".join(parts)

    def _build_suggestion(
        self,
        node: "PlanNode",
        parent: "PlanNode",
    ) -> str:
        table = node.relation_name or "<table>"
        return "\n".join([
            "-- Rewrite the correlated sub-SELECT as a JOIN:",
            f"-- Before: WHERE col < ALL (SELECT val FROM {table} WHERE ...)",
            f"-- After:  LEFT JOIN {table} ON ... WHERE ...",
            "",
            "-- Or use EXISTS (allows join pull-up):",
            f"-- WHERE EXISTS (SELECT 1 FROM {table} WHERE ...)",
            "",
            "-- If using NOT IN, consider NOT EXISTS instead:",
            f"-- WHERE col NOT IN (SELECT ...) → WHERE NOT EXISTS (...)",
            "-- NOT EXISTS allows Postgres to use a Hash Anti Join",
            "",
            f"-- Add an index on {table}'s join/filter columns to speed",
            "-- up each iteration if rewriting isn't possible:",
            f"-- CREATE INDEX ON {table} (<join_column>);",
            "",
            "-- Ref: https://www.postgresql.org/docs/current/using-explain.html",
        ])
