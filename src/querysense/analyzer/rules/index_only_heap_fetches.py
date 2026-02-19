"""
Rule: Index Only Scan with Excessive Heap Fetches

Detects "Index Only Scan" nodes that are forced to fetch heap pages due to
stale visibility map data, negating the primary benefit of index-only scans.

Why it matters:
- Index Only Scans are supposed to avoid heap access entirely
- Heap Fetches occur when the visibility map bit is not set (tuple may not
  be all-visible), requiring a trip to the heap page to verify visibility
- High Heap Fetches can make an "Index Only Scan" as expensive as a
  regular Index Scan
- This is a recurring source of confusion: "I have a covering index but
  it's still slow" — the answer is often heap fetches

When it happens:
- After bulk writes without VACUUM (visibility map not updated)
- High-write tables where autovacuum can't keep up
- Tables with aggressive HOT updates that don't clear visibility bits

Detection:
- "Index Only Scan" nodes with "Heap Fetches" > 0 in EXPLAIN ANALYZE
- Severity based on ratio of heap fetches to rows returned

Requires EXPLAIN ANALYZE (Heap Fetches is runtime data).
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


class IndexOnlyHeapFetchesConfig(RuleConfig):
    """
    Configuration for Index Only Scan heap fetches detection.

    Attributes:
        min_heap_fetches: Minimum heap fetches to trigger (default 100).
        heap_fetch_ratio_warning: Heap fetches / rows ratio for WARNING.
        heap_fetch_ratio_critical: Heap fetches / rows ratio for CRITICAL.
    """

    min_heap_fetches: int = Field(
        default=100,
        ge=0,
        description="Minimum heap fetches to trigger a finding",
    )
    heap_fetch_ratio_warning: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Heap fetches / rows ratio to trigger WARNING",
    )
    heap_fetch_ratio_critical: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Heap fetches / rows ratio to trigger CRITICAL",
    )


@register_rule
class IndexOnlyHeapFetches(Rule):
    """
    Detect Index Only Scans with excessive heap fetches.

    Index Only Scans should avoid touching the heap entirely. When
    the visibility map is stale (after writes without VACUUM), the
    executor must fetch heap pages to verify tuple visibility, degrading
    performance to regular-index-scan levels.
    """

    rule_id = "INDEX_ONLY_HEAP_FETCHES"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects Index Only Scans degraded by heap fetches"
    phase = RulePhase.PER_NODE

    config_schema = IndexOnlyHeapFetchesConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find Index Only Scan nodes with excessive heap fetches."""
        config: IndexOnlyHeapFetchesConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "Index Only Scan":
                continue

            heap_fetches = _get_heap_fetches(node)

            if heap_fetches < config.min_heap_fetches:
                continue

            # Calculate ratio against actual rows (if available)
            actual_rows = node.actual_rows or node.plan_rows or 1
            loops = node.actual_loops or 1
            total_heap_fetches = heap_fetches  # Already total across loops
            total_rows = actual_rows * loops

            ratio = total_heap_fetches / total_rows if total_rows > 0 else 1.0
            ratio = min(ratio, 1.0)  # Cap at 1.0

            # Determine severity
            if ratio >= config.heap_fetch_ratio_critical:
                severity = Severity.CRITICAL
            elif ratio >= config.heap_fetch_ratio_warning:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "unknown table"
            index = node.index_name or "unknown index"

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Index Only Scan on {table} has "
                    f"{total_heap_fetches:,} heap fetches "
                    f"({ratio:.0%} of rows)"
                ),
                description=self._build_description(
                    node, total_heap_fetches, total_rows, ratio
                ),
                suggestion=self._build_suggestion(node),
                metrics={
                    "heap_fetches": total_heap_fetches,
                    "actual_rows": total_rows,
                    "heap_fetch_ratio": round(ratio, 4),
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.HIGH if ratio > 0.9
                    else ImpactBand.MEDIUM if ratio > 0.5
                    else ImpactBand.LOW
                ),
                assumptions=(
                    "Heap fetches indicate stale visibility map",
                    "VACUUM would refresh the visibility map and reduce heap fetches",
                ),
                verification_steps=(
                    "Check last VACUUM time: SELECT last_vacuum, last_autovacuum "
                    "FROM pg_stat_user_tables WHERE relname = '<table>'",
                    "Run VACUUM on the table and re-run the query",
                    "Check autovacuum settings if this recurs frequently",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        heap_fetches: int,
        total_rows: int,
        ratio: float,
    ) -> str:
        """Build detailed description."""
        table = node.relation_name or "this table"
        index = node.index_name or "the covering index"
        parts = [
            f"Index Only Scan using '{index}' on '{table}' performed "
            f"{heap_fetches:,} heap fetches out of {total_rows:,} rows "
            f"returned ({ratio:.0%})."
        ]

        if ratio > 0.9:
            parts.append(
                "Nearly every row required a heap page visit, completely "
                "negating the benefit of the covering index. The scan is "
                "effectively as expensive as a regular Index Scan."
            )
        elif ratio > 0.5:
            parts.append(
                "More than half of returned rows required heap fetches. "
                "The covering index is providing partial but degraded benefit."
            )

        parts.append(
            "Heap fetches occur when the visibility map bit is not set for "
            "a page — typically after writes without a subsequent VACUUM."
        )

        return " ".join(parts)

    def _build_suggestion(self, node: "PlanNode") -> str:
        """Build actionable suggestion."""
        table = node.relation_name or "<table>"
        lines = [
            f"VACUUM {table};",
            f"-- Refreshes the visibility map so Index Only Scans skip the heap",
            "",
            "-- For ongoing protection, tune autovacuum:",
            f"ALTER TABLE {table} SET (autovacuum_vacuum_scale_factor = 0.01);",
            f"-- Vacuums after 1% of rows change (default is 20%)",
            "",
            "-- Monitor visibility map coverage:",
            f"SELECT n_dead_tup, last_vacuum, last_autovacuum",
            f"FROM pg_stat_user_tables WHERE relname = '{table}';",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/routine-vacuuming.html",
        ]
        return "\n".join(lines)


def _get_heap_fetches(node: "PlanNode") -> int:
    """Extract Heap Fetches from PlanNode.model_extra."""
    if node.model_extra:
        value = node.model_extra.get("Heap Fetches", 0)
        if isinstance(value, int):
            return value
    return 0
