"""
Rule: Partition Pruning Failure

Detects queries on partitioned tables that scan all partitions instead
of pruning irrelevant ones. This is a growing problem as partition adoption
increases and tooling hasn't kept up.

Why it matters:
- Partitioned tables exist to reduce I/O by scanning only relevant partitions
- Without pruning, queries scan every partition (defeating the purpose)
- Common causes: runtime expressions, type mismatches, volatile functions,
  CTE-derived values preventing plan-time pruning

Detection strategy:
- Find Append/MergeAppend nodes (partition scans)
- Count child plans (partitions being scanned)
- Check for "Subplans Removed" annotation (indicates pruning occurred)
- Flag when all partitions are scanned and filter conditions exist

When it's okay:
- Query intentionally scans all partitions (e.g., full aggregation)
- Table has very few partitions (cost of pruning check > scan)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

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


class PartitionPruningConfig(RuleConfig):
    """
    Configuration for partition pruning detection.

    Attributes:
        min_partitions: Minimum number of partitions to trigger (default 3).
            Tables with fewer partitions may not benefit from pruning checks.
    """

    min_partitions: int = Field(
        default=3,
        ge=2,
        le=10000,
        description="Minimum partition count to trigger warning",
    )


# Node types that indicate partition scans
_PARTITION_PARENT_TYPES = {"Append", "MergeAppend"}


@register_rule
class PartitionPruningFailure(Rule):
    """
    Detect queries that scan all partitions without pruning.

    Checks Append/MergeAppend nodes for:
    1. All child partitions present (no "Subplans Removed")
    2. Filter conditions that suggest pruning should occur
    3. "(never executed)" annotations indicating runtime-only pruning

    This rule operates on EXPLAIN output alone (Level 1) but provides
    better suggestions when SQL is available (Level 2).
    """

    rule_id = "PARTITION_PRUNING_FAILURE"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects queries that scan all partitions without pruning"
    config_schema = PartitionPruningConfig
    phase = RulePhase.PER_NODE

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Find Append/MergeAppend nodes where partition pruning failed.

        Checks:
        1. Node is Append or MergeAppend (partition scan parent)
        2. Has more children than min_partitions threshold
        3. No "Subplans Removed" annotation (no pruning occurred)
        4. At least one child has a filter condition (suggests pruning was possible)
        """
        config: PartitionPruningConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in _PARTITION_PARENT_TYPES:
                continue

            children = node.plans
            total_partitions = len(children)

            # Skip if too few partitions
            if total_partitions < config.min_partitions:
                continue

            # Check for pruning indicators in the raw model data
            # PostgreSQL reports "Subplans Removed: N" when plan-time pruning occurs
            subplans_removed = _get_subplans_removed(node)

            if subplans_removed > 0:
                # Pruning is working - some partitions were eliminated
                continue

            # Check if any child partition has a filter condition
            # (suggests the query has a WHERE clause on the partition key)
            has_filter = _children_have_filters(children)

            # Check for runtime pruning indicators:
            # "(never executed)" in actual loops means runtime pruning occurred
            # but plan-time pruning did not
            never_executed_count = _count_never_executed(children)
            has_runtime_pruning_only = never_executed_count > 0 and subplans_removed == 0

            # Flag if all partitions are scanned (no pruning at all)
            # OR if only runtime pruning occurred (less efficient than plan-time)
            if not has_filter and not has_runtime_pruning_only:
                # No filters and no runtime pruning - might be intentional full scan
                continue

            # Build the finding
            severity = self.severity
            if total_partitions >= 50:
                severity = Severity.CRITICAL

            context = NodeContext.from_node(node, path, parent)

            if has_runtime_pruning_only:
                title = (
                    f"Runtime-only partition pruning on {node.node_type} "
                    f"({total_partitions} partitions, "
                    f"{never_executed_count} skipped at runtime)"
                )
                description = (
                    f"{node.node_type} scans {total_partitions} partitions. "
                    f"{never_executed_count} were skipped at runtime but not at "
                    f"plan time. Plan-time pruning is more efficient because it "
                    f"avoids initializing partition scans entirely.\n\n"
                    f"Common causes: CTE-derived values, parameterized queries "
                    f"with prepared statements, or volatile function calls in "
                    f"the WHERE clause."
                )
                impact = ImpactBand.MEDIUM
            else:
                title = (
                    f"No partition pruning on {node.node_type} "
                    f"({total_partitions} partitions scanned)"
                )
                description = (
                    f"{node.node_type} scans all {total_partitions} partitions "
                    f"despite filter conditions on child scans. This defeats the "
                    f"purpose of partitioning.\n\n"
                    f"Common causes: type mismatch between filter value and "
                    f"partition key, runtime expressions that prevent plan-time "
                    f"pruning, or missing partition key in the WHERE clause."
                )
                impact = ImpactBand.HIGH

            suggestion = self._build_suggestion(node, total_partitions, has_runtime_pruning_only)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=title,
                description=description,
                suggestion=suggestion,
                metrics={
                    "total_partitions": total_partitions,
                    "subplans_removed": subplans_removed,
                    "never_executed": never_executed_count,
                    "total_cost": node.total_cost,
                },
                impact_band=impact,
                assumptions=(
                    "Table is partitioned (Append/MergeAppend indicates partition scan)",
                    "Filter conditions suggest partition key is in the WHERE clause",
                ),
                verification_steps=(
                    "Check that the WHERE clause references the partition key column",
                    "Verify the filter value type matches the partition key type",
                    "Run EXPLAIN with literal values instead of parameters to test plan-time pruning",
                    "Check for volatile functions in the WHERE clause that prevent pruning",
                ),
            ))

        return findings

    def _build_suggestion(
        self,
        node: "PlanNode",
        total_partitions: int,
        runtime_only: bool,
    ) -> str:
        """Build actionable suggestion for partition pruning failure."""
        parts: list[str] = []

        if runtime_only:
            parts.append(
                "-- Runtime pruning is working but plan-time pruning is not.\n"
                "-- To enable plan-time pruning:"
            )
            parts.append(
                "-- 1. Use literal values instead of subquery/CTE-derived values"
            )
            parts.append(
                "-- 2. Avoid volatile functions on the partition key column"
            )
            parts.append(
                "-- 3. For prepared statements, consider using EXECUTE with literal values"
            )
        else:
            parts.append(
                f"-- All {total_partitions} partitions are being scanned.\n"
                "-- To enable partition pruning:"
            )
            parts.append(
                "-- 1. Ensure your WHERE clause includes the partition key column"
            )
            parts.append(
                "-- 2. Verify the filter value type matches the partition key type exactly"
            )
            parts.append(
                "-- 3. Use explicit casts if needed: WHERE partition_key = value::correct_type"
            )

        parts.append("")
        parts.append("-- Verify pruning with:")
        parts.append("-- EXPLAIN (ANALYZE, FORMAT JSON) <your query>")
        parts.append("-- Look for 'Subplans Removed: N' in the Append node")

        return "\n".join(parts)


def _get_subplans_removed(node: "PlanNode") -> int:
    """
    Extract 'Subplans Removed' count from a plan node.

    PostgreSQL includes this field when plan-time partition pruning
    eliminates partitions from the scan.
    """
    # The field may be in model_extra since it's not a standard PlanNode field
    if node.model_extra:
        removed = node.model_extra.get("Subplans Removed", 0)
        if isinstance(removed, int):
            return removed
    return 0


def _children_have_filters(children: list["PlanNode"]) -> bool:
    """Check if any child partition scan has a filter condition."""
    for child in children:
        if child.filter:
            return True
        # Check grandchildren too (filter might be on the actual scan node)
        for grandchild in child.plans:
            if grandchild.filter or grandchild.index_cond:
                return True
    return False


def _count_never_executed(children: list["PlanNode"]) -> int:
    """
    Count child nodes that were never executed (runtime pruning).

    When actual_loops == 0, the partition was pruned at runtime
    but not at plan time.
    """
    count = 0
    for child in children:
        if child.actual_loops is not None and child.actual_loops == 0:
            count += 1
    return count
