"""
Rule: Generic Plan Hazard

Detects query plans generated with generic (parameterized) planning that
use suboptimal access methods, indicating parameter sensitivity risk.

Why it matters:
- Prepared statements (often created implicitly by drivers/ORMs) start
  with custom plans (per-parameter-set) then flip to generic plans after
  5 executions (Postgres heuristic)
- Generic plans don't know parameter values, so the planner uses average
  selectivity estimates that can be wildly wrong
- Engineers report 10x-1000x regressions when generic plans kick in:
  "it's fast in psql but slow in the app"
- The behavior is invisible at the application layer — the SQL looks
  identical, but the plan is fundamentally different

Detection strategy:
- Look for parameter markers ($1, $2, etc.) in Filter, Index Cond,
  Hash Cond, Join Filter, and Recheck Cond
- Flag Seq Scans with parameterized filters (generic plan couldn't
  optimize to index scan because selectivity is unknown)
- Flag Nested Loop joins with parameterized inner scans
- Available with EXPLAIN (GENERIC_PLAN) in Postgres 16+, or when
  drivers send parameterized queries

When it's okay:
- Low-cardinality filters where all parameter values give similar plans
- Small tables where Seq Scan is always optimal regardless of parameter
"""

from __future__ import annotations

import re
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


# Pattern to detect parameter markers: $1, $2, ... $N
_PARAM_MARKER_RE = re.compile(r"\$\d+")

# Node types that are dangerous when parameterized
_DANGEROUS_PARAMETERIZED_SCANS = {"Seq Scan"}
_DANGEROUS_PARAMETERIZED_JOINS = {"Nested Loop"}


class GenericPlanHazardConfig(RuleConfig):
    """
    Configuration for generic plan hazard detection.

    Attributes:
        min_plan_rows: Minimum estimated rows to flag a parameterized scan.
            Small tables are not worth flagging even with generic plans.
    """

    min_plan_rows: int = Field(
        default=1000,
        ge=0,
        description="Minimum plan_rows to flag a parameterized scan (skip tiny tables)",
    )


@register_rule
class GenericPlanHazard(Rule):
    """
    Detect parameterized plans with suboptimal access methods.

    Flags plans where parameter markers ($1, $2, ...) appear in filter
    conditions on nodes that use expensive access methods (Seq Scan,
    Nested Loop). These patterns indicate the generic plan could not
    optimize for the actual parameter values.
    """

    rule_id = "GENERIC_PLAN_HAZARD"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects generic/parameterized plans with suboptimal access methods"
    phase = RulePhase.PER_NODE

    config_schema = GenericPlanHazardConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find parameterized nodes with dangerous access methods."""
        config: GenericPlanHazardConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            finding = self._check_parameterized_scan(node, path, parent, config)
            if finding:
                findings.append(finding)

            finding = self._check_parameterized_join(node, path, parent, config)
            if finding:
                findings.append(finding)

        return findings

    def _check_parameterized_scan(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
        config: GenericPlanHazardConfig,
    ) -> Finding | None:
        """Check for Seq Scans with parameterized filters."""
        if node.node_type not in _DANGEROUS_PARAMETERIZED_SCANS:
            return None

        # Check all condition fields for parameter markers
        params = _find_params_in_conditions(node)
        if not params:
            return None

        # Skip small tables
        estimated_rows = node.plan_rows
        if estimated_rows < config.min_plan_rows:
            return None

        table = node.relation_name or "unknown table"
        param_list = ", ".join(sorted(params))
        context = NodeContext.from_node(node, path, parent)

        return Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING,
            context=context,
            title=(
                f"Generic plan: Seq Scan on {table} with parameters "
                f"({param_list})"
            ),
            description=(
                f"Sequential scan on '{table}' ({estimated_rows:,} estimated rows) "
                f"uses parameters {param_list} in its filter condition. "
                f"This suggests a generic (parameterized) plan where the planner "
                f"cannot optimize for specific parameter values.\n\n"
                f"With custom planning (per-parameter), PostgreSQL might choose "
                f"an Index Scan for selective values. The generic plan uses average "
                f"selectivity estimates which can be wildly wrong for skewed data."
            ),
            suggestion=self._build_scan_suggestion(node, params),
            metrics={
                "estimated_rows": estimated_rows,
                "total_cost": node.total_cost,
                "param_count": len(params),
            },
            impact_band=ImpactBand.HIGH,
            assumptions=(
                "Plan was generated in generic mode (PREPARE or driver auto-prepare)",
                "Parameter selectivity varies significantly across values",
            ),
            verification_steps=(
                "Compare: EXPLAIN with literal values vs EXPLAIN (GENERIC_PLAN)",
                "Check driver settings: disable auto-prepare or increase threshold",
                "SET plan_cache_mode = 'force_custom_plan' to test custom planning",
                "Review pg_prepared_statements for cached generic plans",
            ),
        )

    def _check_parameterized_join(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
        config: GenericPlanHazardConfig,
    ) -> Finding | None:
        """Check for Nested Loops with parameterized inner paths."""
        if node.node_type not in _DANGEROUS_PARAMETERIZED_JOINS:
            return None

        # Check join filter and child conditions for parameters
        join_params = set()
        if node.join_filter:
            join_params.update(_PARAM_MARKER_RE.findall(node.join_filter))

        # Check inner child (second plan child) for parameterized conditions
        inner_params = set()
        if len(node.plans) >= 2:
            inner = node.plans[1]
            inner_params = _find_params_in_conditions(inner)

        all_params = join_params | inner_params
        if not all_params:
            return None

        # Skip unless significant row estimates
        estimated_rows = node.plan_rows
        if estimated_rows < config.min_plan_rows:
            return None

        param_list = ", ".join(sorted(all_params))
        context = NodeContext.from_node(node, path, parent)

        return Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING,
            context=context,
            title=(
                f"Generic plan: Nested Loop with parameters ({param_list})"
            ),
            description=(
                f"Nested Loop join uses parameters {param_list}. "
                f"In a generic plan, the planner may choose Nested Loop "
                f"because it cannot estimate selectivity of parameterized "
                f"conditions. With specific parameter values, a Hash Join "
                f"or Merge Join might be significantly faster.\n\n"
                f"This pattern is a common source of 'fast in psql, slow "
                f"in the app' problems."
            ),
            suggestion=(
                "-- Test with custom planning to see if join type changes:\n"
                "SET plan_cache_mode = 'force_custom_plan';\n"
                "\n"
                "-- Or test with literal values:\n"
                "EXPLAIN ANALYZE <query with actual values>;\n"
                "\n"
                "-- If the plan improves, consider:\n"
                "-- 1. Disabling auto-prepare in your driver/ORM\n"
                "-- 2. Using plan_cache_mode = 'force_custom_plan' for this session\n"
                "-- 3. Adding statistics targets to help the generic planner:\n"
                "--    ALTER TABLE <table> ALTER COLUMN <col> SET STATISTICS 1000;\n"
                "\n"
                "-- Docs: https://www.postgresql.org/docs/current/sql-prepare.html"
            ),
            metrics={
                "estimated_rows": estimated_rows,
                "total_cost": node.total_cost,
                "param_count": len(all_params),
            },
            impact_band=ImpactBand.HIGH,
            assumptions=(
                "Plan was generated in generic mode",
                "Custom planning would choose a different join strategy",
            ),
            verification_steps=(
                "Compare plans with and without plan_cache_mode = force_custom_plan",
                "Test with representative parameter values to measure difference",
                "Check if driver supports per-statement plan_cache_mode override",
            ),
        )

    def _build_scan_suggestion(
        self,
        node: "PlanNode",
        params: set[str],
    ) -> str:
        """Build suggestion for parameterized seq scan."""
        table = node.relation_name or "<table>"
        lines = [
            "-- Force custom planning to test if Index Scan is used:",
            "SET plan_cache_mode = 'force_custom_plan';",
            "",
            "-- Or test with literal values:",
            "EXPLAIN ANALYZE <query with actual values>;",
            "",
        ]

        if node.filter:
            lines.append(f"-- Current filter: {node.filter}")
            lines.append(
                f"-- Consider adding an index on {table} for the filtered column(s)"
            )
            lines.append("")

        lines.extend([
            "-- Driver-level fixes:",
            "-- pgx (Go): set PreferSimpleProtocol or increase PrepareThreshold",
            "-- JDBC: set prepareThreshold=-1 to disable server-side prepares",
            "-- psycopg: use execute() instead of executemany() for varying plans",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/sql-prepare.html",
        ])

        return "\n".join(lines)


def _find_params_in_conditions(node: "PlanNode") -> set[str]:
    """Find all parameter markers in a node's conditions."""
    params: set[str] = set()
    conditions = [
        node.filter,
        node.index_cond,
        node.hash_cond,
        node.join_filter,
        node.recheck_cond,
        node.merge_cond,
    ]
    for cond in conditions:
        if cond:
            params.update(_PARAM_MARKER_RE.findall(cond))
    return params
