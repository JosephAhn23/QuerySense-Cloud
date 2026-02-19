"""
Rule: Cost Hotspot Detection (AGGREGATE)

Identifies nodes that consume a disproportionate share of total plan cost.
This is the single most useful "depth" signal a plan analyzer can surface —
it tells the user exactly where to focus optimization effort.

pgMustard calls this "time is spent here" tips. pganalyze surfaces similar
data via its EXPLAIN visualization. We compute it quantitatively and
expose both cost % and time % per node.

Why it matters:
- A node consuming 90% of total cost is THE bottleneck
- Knowing the bottleneck type (scan, join, sort, agg) narrows the fix
- Cost concentration enables prioritized optimization

When it's okay:
- A single root node with 100% cost (trivial plan)
- High cost % on a node that processes most rows (proportional)
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


class CostHotspotConfig(RuleConfig):
    """Configuration for cost hotspot detection."""

    hotspot_threshold_pct: float = 50.0  # % of total cost to flag
    critical_threshold_pct: float = 80.0  # % of total cost to escalate to CRITICAL
    min_absolute_cost: float = 100.0  # Ignore cheap plans


@register_rule
class CostHotspot(Rule):
    """
    Identify plan nodes that dominate total execution cost.

    This AGGREGATE rule computes cost distribution across the entire
    plan tree and flags nodes consuming more than the configured
    threshold. Provides cost %, time %, and buffer breakdowns.
    """

    rule_id = "COST_HOTSPOT"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Identifies nodes consuming a disproportionate share of plan cost"
    config_schema = CostHotspotConfig
    phase = RulePhase.AGGREGATE
    requires: tuple[str, ...] = ("prior_findings",)
    provides: tuple[str, ...] = ("cost_hotspots",)

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: CostHotspotConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        total_cost = explain.plan.total_cost
        if total_cost < config.min_absolute_cost:
            return findings

        # Compute total execution time if available
        total_time = _sum_exclusive_time(explain.plan)

        # Collect all leaf + high-cost nodes
        hotspots: list[tuple[float, float, "PlanNode"]] = []
        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Exclusive cost = this node's cost minus children's cost
            children_cost = sum(c.total_cost for c in (node.plans or []))
            exclusive_cost = max(0.0, node.total_cost - children_cost)
            cost_pct = (exclusive_cost / total_cost * 100) if total_cost > 0 else 0.0

            # Exclusive time
            exclusive_time = _exclusive_time(node)
            time_pct = (exclusive_time / total_time * 100) if total_time > 0 else 0.0

            if cost_pct >= config.hotspot_threshold_pct:
                hotspots.append((cost_pct, time_pct, node))

                severity = (
                    Severity.CRITICAL
                    if cost_pct >= config.critical_threshold_pct
                    else Severity.WARNING
                )

                impact_band = (
                    ImpactBand.HIGH
                    if cost_pct >= config.critical_threshold_pct
                    else ImpactBand.MEDIUM
                )

                context = NodeContext.from_node(node, path, parent)

                # Determine bottleneck type
                bottleneck_type = _classify_bottleneck(node)

                metrics: dict[str, int | float] = {
                    "cost_pct": round(cost_pct, 1),
                    "exclusive_cost": round(exclusive_cost, 2),
                    "total_plan_cost": round(total_cost, 2),
                }
                if total_time > 0:
                    metrics["time_pct"] = round(time_pct, 1)
                    metrics["exclusive_time_ms"] = round(exclusive_time, 2)
                if node.actual_rows is not None:
                    metrics["actual_rows"] = node.actual_rows
                if node.shared_hit_blocks is not None:
                    metrics["shared_hit_blocks"] = node.shared_hit_blocks
                if node.shared_read_blocks is not None:
                    metrics["shared_read_blocks"] = node.shared_read_blocks

                table = node.relation_name or "unknown"
                finding = Finding(
                    rule_id=self.rule_id,
                    severity=severity,
                    context=context,
                    title=(
                        f"Cost hotspot: {node.node_type} on {table} "
                        f"consumes {cost_pct:.0f}% of plan cost"
                    ),
                    description=_build_description(
                        node, cost_pct, time_pct, total_cost, bottleneck_type,
                    ),
                    suggestion=_build_suggestion(node, bottleneck_type, cost_pct),
                    impact_band=impact_band,
                    impact_score=min(10.0, cost_pct / 10.0),
                    metrics=metrics,
                    assumptions=(
                        "Cost model accuracy depends on statistics freshness",
                        "Exclusive cost excludes child node costs",
                    ),
                    verification_steps=(
                        "Run EXPLAIN (ANALYZE, BUFFERS) to get actual timing",
                        "Check if table statistics are current: SELECT last_analyze FROM pg_stat_user_tables",
                        f"Profile the {bottleneck_type} operation in isolation",
                    ),
                )
                findings.append(finding)

        return findings


def _exclusive_time(node: "PlanNode") -> float:
    """Compute exclusive (self) time for a node."""
    if node.actual_total_time is None:
        return 0.0
    children_time = sum(
        (c.actual_total_time or 0.0) for c in (node.plans or [])
    )
    return max(0.0, node.actual_total_time - children_time)


def _sum_exclusive_time(node: "PlanNode") -> float:
    """Sum exclusive time across all nodes (equals total execution time)."""
    total = _exclusive_time(node)
    for child in node.plans or []:
        total += _sum_exclusive_time(child)
    return total


def _classify_bottleneck(node: "PlanNode") -> str:
    """Classify the type of bottleneck based on node type."""
    nt = node.node_type.lower()
    if "scan" in nt:
        return "scan"
    if "join" in nt or "loop" in nt:
        return "join"
    if "sort" in nt:
        return "sort"
    if "aggregate" in nt or "group" in nt:
        return "aggregation"
    if "hash" in nt:
        return "hash"
    if "materialize" in nt or "cte" in nt:
        return "materialization"
    return "computation"


def _build_description(
    node: "PlanNode",
    cost_pct: float,
    time_pct: float,
    total_cost: float,
    bottleneck_type: str,
) -> str:
    """Build a detailed description of the cost hotspot."""
    table = node.relation_name or ""
    parts = [
        f"This {node.node_type} node is the dominant cost center in the plan, "
        f"consuming {cost_pct:.1f}% of total cost ({node.total_cost:,.0f} "
        f"out of {total_cost:,.0f})."
    ]

    if time_pct > 0:
        parts.append(f" It accounts for {time_pct:.1f}% of actual execution time.")

    parts.append(f"\n\nBottleneck type: {bottleneck_type}")

    if bottleneck_type == "scan" and table:
        parts.append(
            f"\nThe scan on '{table}' is the primary cost driver. "
            "Consider whether an index can reduce the scan cost."
        )
    elif bottleneck_type == "join":
        parts.append(
            "\nThe join operation dominates cost. Consider whether "
            "join order, join method, or pre-filtering can reduce work."
        )
    elif bottleneck_type == "sort":
        parts.append(
            "\nThe sort operation dominates cost. Consider whether "
            "an index can provide pre-sorted data to eliminate the sort."
        )
    elif bottleneck_type == "aggregation":
        parts.append(
            "\nThe aggregation dominates cost. Consider whether "
            "pre-aggregation, materialized views, or index-only scans can help."
        )

    if node.actual_rows is not None and node.plan_rows is not None:
        ratio = node.actual_rows / max(node.plan_rows, 1)
        if ratio > 10 or ratio < 0.1:
            parts.append(
                f"\n\nRow estimate accuracy: {ratio:.1f}x off "
                f"(estimated {node.plan_rows:,}, actual {node.actual_rows:,}). "
                "This may be causing the planner to choose a suboptimal strategy."
            )

    return "".join(parts)


def _build_suggestion(
    node: "PlanNode",
    bottleneck_type: str,
    cost_pct: float,
) -> str:
    """Build actionable suggestion based on bottleneck type."""
    table = node.relation_name or "<table>"
    suggestions: list[str] = []

    if bottleneck_type == "scan":
        if node.filter:
            suggestions.append(
                f"-- This {node.node_type} consumes {cost_pct:.0f}% of plan cost\n"
                f"-- Filter: {node.filter}\n"
                f"-- Consider adding a targeted index:\n"
                f"CREATE INDEX CONCURRENTLY idx_{table}_hotspot ON {table}(<filtered_columns>);"
            )
        else:
            suggestions.append(
                f"-- Scan on {table} consumes {cost_pct:.0f}% of plan cost\n"
                f"-- Consider: partial index, covering index, or table partitioning"
            )
    elif bottleneck_type == "sort":
        suggestions.append(
            f"-- Sort consumes {cost_pct:.0f}% of plan cost\n"
            f"-- Consider an index that provides pre-sorted output:\n"
            f"-- CREATE INDEX CONCURRENTLY idx_{table}_sorted ON {table}(<sort_columns>);\n"
            f"-- Or increase work_mem for this session:\n"
            f"SET work_mem = '256MB';  -- Adjust based on available RAM"
        )
    elif bottleneck_type == "join":
        suggestions.append(
            f"-- Join consumes {cost_pct:.0f}% of plan cost\n"
            f"-- Consider:\n"
            f"--   1. Add index on join key columns\n"
            f"--   2. Pre-filter rows before the join (push WHERE down)\n"
            f"--   3. Force a different join method: SET enable_nestloop = off;"
        )
    elif bottleneck_type == "aggregation":
        suggestions.append(
            f"-- Aggregation consumes {cost_pct:.0f}% of plan cost\n"
            f"-- Consider:\n"
            f"--   1. Pre-aggregate with a materialized view\n"
            f"--   2. Use an index-only scan to avoid heap access\n"
            f"--   3. Increase work_mem: SET work_mem = '256MB';"
        )
    else:
        suggestions.append(
            f"-- {node.node_type} consumes {cost_pct:.0f}% of plan cost\n"
            f"-- Investigate whether this operation can be eliminated or reduced"
        )

    return "\n".join(suggestions)
