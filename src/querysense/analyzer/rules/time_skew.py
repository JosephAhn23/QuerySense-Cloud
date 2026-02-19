"""
Rule: Execution Time Skew Analysis (AGGREGATE)

Detects when execution time is concentrated in a small number of nodes,
indicating optimization opportunities. Combines time analysis with
row estimate accuracy to diagnose root causes.

This rule provides the "why is my query slow" narrative that is
the hallmark of deep analysis tools like pgMustard and pganalyze.

Why it matters:
- Time distribution reveals the actual bottleneck (not just cost estimates)
- Correlating time with row estimate errors identifies planner mistakes
- Loop multipliers can hide the true cost of apparently fast nodes
- Time skew + join type = actionable root cause diagnosis

Requires:
- EXPLAIN (ANALYZE) output with actual timing data
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


class TimeSkewConfig(RuleConfig):
    """Configuration for time skew detection."""

    skew_threshold_pct: float = 60.0  # % of total time in single node
    loop_amplification_threshold: int = 10  # loops * time threshold
    estimate_error_threshold: float = 10.0  # 10x off in row estimate


@register_rule
class TimeSkew(Rule):
    """
    Analyze execution time distribution to find performance bottlenecks.

    This AGGREGATE rule:
    1. Computes exclusive (self) time for each node
    2. Identifies nodes consuming disproportionate time
    3. Correlates with row estimate accuracy
    4. Detects loop amplification (fast node * many loops = slow)
    5. Generates root cause narratives
    """

    rule_id = "TIME_SKEW"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects execution time concentration and correlates with row estimate accuracy"
    config_schema = TimeSkewConfig
    phase = RulePhase.AGGREGATE
    requires: tuple[str, ...] = ("prior_findings",)
    provides: tuple[str, ...] = ("time_analysis",)

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: TimeSkewConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        # Need ANALYZE data
        if explain.plan.actual_total_time is None:
            return findings

        total_time = explain.plan.actual_total_time
        if total_time <= 0:
            return findings

        # Build time distribution
        time_nodes: list[tuple[float, float, "PlanNode", NodeContext]] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.actual_total_time is None:
                continue

            exclusive_time = _exclusive_time(node)
            loops = node.actual_loops or 1
            # Total wall-clock contribution = exclusive_time * loops
            total_contribution = exclusive_time * loops
            time_pct = (total_contribution / total_time * 100) if total_time > 0 else 0.0

            context = NodeContext.from_node(node, path, parent)
            time_nodes.append((time_pct, total_contribution, node, context))

        # Sort by time percentage descending
        time_nodes.sort(key=lambda x: x[0], reverse=True)

        # Check 1: Time skew — single node dominates
        for time_pct, total_contribution, node, context in time_nodes:
            if time_pct < config.skew_threshold_pct:
                break

            table = node.relation_name or node.node_type
            loops = node.actual_loops or 1

            # Diagnose root cause
            root_cause = _diagnose_root_cause(node, time_pct)

            severity = Severity.CRITICAL if time_pct >= 80 else Severity.WARNING

            metrics: dict[str, int | float] = {
                "time_pct": round(time_pct, 1),
                "exclusive_time_ms": round(_exclusive_time(node), 2),
                "total_time_ms": round(total_time, 2),
                "loops": loops,
            }
            if node.actual_rows is not None:
                metrics["actual_rows"] = node.actual_rows
            if node.plan_rows is not None:
                metrics["plan_rows"] = node.plan_rows
                if node.actual_rows is not None and node.plan_rows > 0:
                    metrics["estimate_ratio"] = round(
                        node.actual_rows / node.plan_rows, 2,
                    )

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Time bottleneck: {node.node_type} on {table} "
                    f"consumes {time_pct:.0f}% of execution time"
                ),
                description=_build_time_description(
                    node, time_pct, total_time, root_cause,
                ),
                suggestion=_build_time_suggestion(node, root_cause),
                impact_band=(
                    ImpactBand.HIGH if time_pct >= 70 else ImpactBand.MEDIUM
                ),
                impact_score=min(10.0, time_pct / 10.0),
                metrics=metrics,
                assumptions=(
                    "Timing data from EXPLAIN ANALYZE reflects actual execution",
                    "Exclusive time excludes time spent in child nodes",
                    "Loop count multiplies per-loop time for total contribution",
                ),
                verification_steps=(
                    "Run EXPLAIN (ANALYZE, BUFFERS, VERBOSE) for detailed breakdown",
                    "Run the query 3 times to get stable timing (eliminate cache effects)",
                    "Check if row estimates match actuals",
                ),
            ))

        # Check 2: Loop amplification
        for time_pct, total_contribution, node, context in time_nodes:
            loops = node.actual_loops or 1
            if loops < config.loop_amplification_threshold:
                continue

            exclusive_time = _exclusive_time(node)
            if exclusive_time <= 0.1:  # Skip trivially fast nodes
                continue

            total_contribution = exclusive_time * loops
            amplified_pct = (total_contribution / total_time * 100) if total_time > 0 else 0.0

            if amplified_pct < 10:  # Only report significant contributions
                continue

            table = node.relation_name or node.node_type

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=Severity.WARNING,
                context=context,
                title=(
                    f"Loop amplification: {node.node_type} on {table} "
                    f"runs {loops:,}x ({exclusive_time:.1f}ms * {loops:,} = "
                    f"{total_contribution:.0f}ms)"
                ),
                description=(
                    f"This {node.node_type} executes {loops:,} times "
                    f"(once per outer row). Each execution takes "
                    f"{exclusive_time:.2f}ms, totaling {total_contribution:.0f}ms "
                    f"({amplified_pct:.1f}% of query time).\n\n"
                    f"Loop amplification is the #1 hidden performance killer. "
                    f"A node that looks fast per-iteration becomes the bottleneck "
                    f"when multiplied by thousands of loops.\n\n"
                    f"Common causes:\n"
                    f"- Nested Loop join with unexpectedly many outer rows\n"
                    f"- Correlated subquery executing once per row\n"
                    f"- Index scan inside a loop with bad row estimates on the outer side"
                ),
                suggestion=(
                    f"-- Loop amplification: {exclusive_time:.1f}ms * {loops:,} loops = "
                    f"{total_contribution:.0f}ms\n"
                    f"-- Consider:\n"
                    f"--   1. Switch to Hash Join: SET enable_nestloop = off;\n"
                    f"--   2. Reduce outer rows with a WHERE clause or index\n"
                    f"--   3. Add index on inner table's join key\n"
                    f"--   4. Check if outer row estimate is accurate"
                ),
                impact_band=ImpactBand.HIGH,
                impact_score=min(9.0, amplified_pct / 10.0),
                metrics={
                    "loops": loops,
                    "per_loop_time_ms": round(exclusive_time, 2),
                    "total_time_ms": round(total_contribution, 2),
                    "amplified_pct": round(amplified_pct, 1),
                },
            ))

        return findings


def _exclusive_time(node: "PlanNode") -> float:
    """Compute exclusive (self) time for a node."""
    if node.actual_total_time is None:
        return 0.0
    children_time = sum(
        (c.actual_total_time or 0.0) for c in (node.plans or [])
    )
    return max(0.0, node.actual_total_time - children_time)


def _diagnose_root_cause(node: "PlanNode", time_pct: float) -> str:
    """Diagnose the root cause of time concentration."""
    nt = node.node_type.lower()
    has_estimate_error = False

    if node.actual_rows is not None and node.plan_rows is not None:
        ratio = node.actual_rows / max(node.plan_rows, 1)
        has_estimate_error = ratio > 10 or ratio < 0.1

    if "seq scan" in nt:
        if has_estimate_error:
            return "missing_index_with_bad_stats"
        return "missing_index"
    if "nested loop" in nt:
        if has_estimate_error:
            return "bad_join_estimate"
        return "nested_loop_inefficiency"
    if "sort" in nt:
        return "expensive_sort"
    if "hash" in nt and "join" in nt:
        return "hash_join_build"
    if "index scan" in nt and has_estimate_error:
        return "index_scan_with_bad_stats"
    if "aggregate" in nt:
        return "expensive_aggregation"

    return "general_bottleneck"


def _build_time_description(
    node: "PlanNode",
    time_pct: float,
    total_time: float,
    root_cause: str,
) -> str:
    """Build detailed description with root cause narrative."""
    exclusive = _exclusive_time(node)
    loops = node.actual_loops or 1
    table = node.relation_name or ""

    parts = [
        f"This {node.node_type} consumes {time_pct:.1f}% of total "
        f"execution time ({exclusive:.1f}ms"
    ]
    if loops > 1:
        parts.append(f" x {loops:,} loops = {exclusive * loops:.0f}ms")
    parts.append(f" out of {total_time:.1f}ms total).")

    # Root cause narrative
    narratives = {
        "missing_index": (
            f"\n\nRoot cause: Missing index on '{table}'. "
            f"A sequential scan is reading every row because no suitable "
            f"index exists for the query predicates."
        ),
        "missing_index_with_bad_stats": (
            f"\n\nRoot cause: Missing index + stale statistics on '{table}'. "
            f"Row estimates are significantly off, AND the table lacks a "
            f"suitable index. Fix both for maximum improvement."
        ),
        "bad_join_estimate": (
            f"\n\nRoot cause: Bad row estimate caused wrong join strategy. "
            f"The planner chose Nested Loop because it underestimated the "
            f"number of rows, but the actual count makes Hash Join better."
        ),
        "nested_loop_inefficiency": (
            f"\n\nRoot cause: Nested Loop executing too many iterations. "
            f"The inner side is scanned once per outer row. Consider "
            f"Hash Join or reducing the outer row count."
        ),
        "expensive_sort": (
            f"\n\nRoot cause: Expensive sort operation. "
            f"The data set is too large to sort in work_mem, causing "
            f"disk spills. Consider an index that provides pre-sorted data."
        ),
        "hash_join_build": (
            f"\n\nRoot cause: Hash Join build phase is expensive. "
            f"The inner relation is large, making the hash table build costly."
        ),
        "index_scan_with_bad_stats": (
            f"\n\nRoot cause: Index scan returns far more/fewer rows than expected. "
            f"Statistics for '{table}' may be stale. Run ANALYZE."
        ),
        "expensive_aggregation": (
            f"\n\nRoot cause: Aggregation processing a large dataset. "
            f"Consider pre-filtering, materialized views, or partial indexes."
        ),
        "general_bottleneck": (
            f"\n\nThis node is the primary time consumer in the plan."
        ),
    }

    parts.append(narratives.get(root_cause, narratives["general_bottleneck"]))

    # Add row estimate info if available
    if node.actual_rows is not None and node.plan_rows is not None:
        ratio = node.actual_rows / max(node.plan_rows, 1)
        if ratio > 2 or ratio < 0.5:
            direction = "underestimated" if ratio > 1 else "overestimated"
            parts.append(
                f"\n\nRow estimate accuracy: {direction} by {abs(ratio):.1f}x "
                f"(estimated {node.plan_rows:,}, actual {node.actual_rows:,})"
            )

    return "".join(parts)


def _build_time_suggestion(node: "PlanNode", root_cause: str) -> str:
    """Build suggestion based on root cause diagnosis."""
    table = node.relation_name or "<table>"

    suggestions = {
        "missing_index": (
            f"-- Missing index detected on {table}\n"
            f"-- Step 1: Identify filtered columns from the query\n"
            f"-- Step 2: Create a targeted index:\n"
            f"CREATE INDEX CONCURRENTLY idx_{table}_perf ON {table}(<filtered_columns>);\n\n"
            f"-- Step 3: Verify improvement:\n"
            f"EXPLAIN (ANALYZE, BUFFERS) <your_query>;"
        ),
        "missing_index_with_bad_stats": (
            f"-- Missing index + stale statistics on {table}\n"
            f"-- Step 1: Update statistics:\n"
            f"ANALYZE {table};\n\n"
            f"-- Step 2: Create a targeted index:\n"
            f"CREATE INDEX CONCURRENTLY idx_{table}_perf ON {table}(<filtered_columns>);\n\n"
            f"-- Step 3: Verify both fixes took effect:\n"
            f"EXPLAIN (ANALYZE, BUFFERS) <your_query>;"
        ),
        "bad_join_estimate": (
            f"-- Bad row estimate caused wrong join strategy\n"
            f"-- Step 1: Update statistics:\n"
            f"ANALYZE {table};\n\n"
            f"-- Step 2: If still wrong, consider extended statistics:\n"
            f"CREATE STATISTICS stx_{table} ON <correlated_columns> FROM {table};\n"
            f"ANALYZE {table};\n\n"
            f"-- Step 3: Test forcing hash join:\n"
            f"SET enable_nestloop = off;\n"
            f"EXPLAIN (ANALYZE) <your_query>;"
        ),
        "nested_loop_inefficiency": (
            f"-- Nested Loop with too many iterations\n"
            f"-- Option 1: Force Hash Join:\n"
            f"SET enable_nestloop = off;\n\n"
            f"-- Option 2: Add index on inner table's join key:\n"
            f"CREATE INDEX CONCURRENTLY idx_{table}_join ON {table}(<join_column>);\n\n"
            f"-- Option 3: Reduce outer rows with better WHERE clause"
        ),
        "expensive_sort": (
            f"-- Expensive sort operation\n"
            f"-- Option 1: Create an index matching the sort order:\n"
            f"CREATE INDEX CONCURRENTLY idx_{table}_sort ON {table}(<sort_columns>);\n\n"
            f"-- Option 2: Increase work_mem to avoid disk spill:\n"
            f"SET work_mem = '256MB';  -- Adjust based on available RAM"
        ),
    }

    return suggestions.get(root_cause, (
        f"-- Performance bottleneck in {node.node_type}\n"
        f"-- Run EXPLAIN (ANALYZE, BUFFERS, VERBOSE) for detailed profiling\n"
        f"-- Check row estimate accuracy and statistics freshness"
    ))
