"""
Rule: Sort Avoidable With Index

Detects Sort nodes in the plan that could be eliminated by adding an index
on the sort key columns. Sorts are one of the most expensive operations in
query plans, and when an index can provide pre-sorted data, the Sort node
is eliminated entirely — often producing 10-100x speedups for ORDER BY
queries on large result sets.

Why it matters:
- Sort operations require O(n log n) comparisons in memory
- If data exceeds work_mem, sort spills to disk (external sort) — much worse
- An index on the sort columns provides O(1) sorted output
- Eliminating a sort can convert a plan from "scan → sort → limit" to
  "index scan → limit" which only reads the exact rows needed
- This is one of the highest-ROI optimizations: one CREATE INDEX statement
  can eliminate the most expensive node in the plan

When it happens:
- ORDER BY columns don't have a matching index
- Index exists but column order doesn't match the ORDER BY
- Composite index exists but ORDER BY uses a different prefix
- GROUP BY / DISTINCT / UNION operations trigger implicit sorts

Detection:
- Sort nodes in the plan tree
- Sort key analysis to suggest matching index columns
- Severity escalation for large sorts or sorts that spill to disk

Does NOT require EXPLAIN ANALYZE (sort_key is always present in Sort nodes).
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


class SortAvoidableConfig(RuleConfig):
    """
    Configuration for sort-avoidable detection.

    Attributes:
        min_plan_rows: Minimum estimated rows for the sort to trigger.
        max_sort_keys: Maximum sort key columns to include in suggestion.
    """

    min_plan_rows: int = Field(
        default=1000,
        ge=0,
        description="Minimum estimated rows in the sort to trigger",
    )
    max_sort_keys: int = Field(
        default=4,
        ge=1,
        le=16,
        description="Maximum sort key columns to include in index suggestion",
    )


@register_rule
class SortAvoidableWithIndex(Rule):
    """
    Detect Sort nodes that could be eliminated by a matching index.

    Analyzes the sort key columns and the child scan node to determine
    whether a B-tree index on the sort key columns (with matching sort
    direction) could provide pre-sorted output and eliminate the Sort
    node entirely.
    """

    rule_id = "SORT_AVOIDABLE_WITH_INDEX"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects sorts that could be eliminated with a matching index"
    phase = RulePhase.PER_NODE

    config_schema = SortAvoidableConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find Sort nodes that could be eliminated with an index."""
        config: SortAvoidableConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in {"Sort", "Incremental Sort"}:
                continue

            # Need sort keys to suggest an index
            if not node.sort_key:
                continue

            # Skip small sorts (not worth optimizing)
            rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
            if rows < config.min_plan_rows:
                continue

            # Find the table being sorted (look at child scan nodes)
            table_name = self._find_source_table(node)
            if not table_name:
                continue

            # Check if sort already comes from an index (child is Index Scan)
            if self._sort_provided_by_index(node):
                continue

            # Determine severity
            is_disk_spill = (
                node.sort_space_type == "Disk"
                or (node.sort_method and "external" in (node.sort_method or "").lower())
            )

            if is_disk_spill:
                severity = Severity.CRITICAL
            elif rows > 100_000:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            context = NodeContext.from_node(node, path, parent)

            # Parse sort keys for index suggestion
            sort_columns = self._parse_sort_keys(
                node.sort_key, config.max_sort_keys
            )

            # Compute impact score
            # Larger sorts + disk spill = higher impact
            if is_disk_spill:
                impact_score = min(8.0 + min(rows / 1_000_000, 2.0), 10.0)
            elif rows > 100_000:
                impact_score = min(5.0 + min(rows / 500_000, 3.0), 8.0)
            else:
                impact_score = min(2.0 + rows / 50_000, 5.0)
            impact_score = round(impact_score, 1)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Sort on {table_name} ({rows:,} rows) avoidable with index"
                    + (" — spilling to disk!" if is_disk_spill else "")
                ),
                description=self._build_description(
                    node, table_name, rows, sort_columns, is_disk_spill
                ),
                suggestion=self._build_suggestion(
                    table_name, sort_columns, node
                ),
                metrics={
                    "sort_rows": rows,
                    "sort_keys_count": len(node.sort_key),
                    "total_cost": node.total_cost,
                    "is_disk_spill": 1 if is_disk_spill else 0,
                    "sort_space_kb": node.sort_space_used or 0,
                },
                impact_band=(
                    ImpactBand.HIGH if is_disk_spill or rows > 100_000
                    else ImpactBand.MEDIUM if rows > 10_000
                    else ImpactBand.LOW
                ),
                impact_score=impact_score,
                assumptions=(
                    "No existing index provides the required sort order",
                    "The sort columns come from a single table",
                    "A B-tree index can provide the needed ordering",
                ),
                verification_steps=(
                    "Check existing indexes: \\di+ <table>",
                    "Create the suggested index",
                    "Re-run EXPLAIN ANALYZE — the Sort node should disappear",
                    "Verify the plan uses Index Scan instead of Seq Scan + Sort",
                ),
            ))

        return findings

    def _find_source_table(self, sort_node: "PlanNode") -> str | None:
        """
        Find the primary table being sorted by looking at child nodes.

        Walks down through the sort node's children to find the first
        scan node with a relation_name.
        """
        for child in sort_node.plans:
            table = self._find_table_recursive(child)
            if table:
                return table
        return None

    def _find_table_recursive(self, node: "PlanNode") -> str | None:
        """Recursively find the first table name in the subtree."""
        if node.relation_name:
            return node.relation_name
        for child in node.plans:
            table = self._find_table_recursive(child)
            if table:
                return table
        return None

    def _sort_provided_by_index(self, sort_node: "PlanNode") -> bool:
        """
        Check if the sort input already comes from an ordered index scan.

        If the child is an Index Scan or Index Only Scan, the sort might
        already be provided by the index order — in that case the Sort node
        is either a re-sort (different columns) or a paranoid sort. We
        skip these to avoid false positives.
        """
        if not sort_node.plans:
            return False

        child = sort_node.plans[0]

        # Direct index scan child — sort may already be provided
        if child.node_type in {"Index Scan", "Index Only Scan"}:
            return True

        # Incremental Sort already partially uses index order
        if child.node_type == "Incremental Sort":
            return True

        return False

    def _parse_sort_keys(
        self, sort_keys: list[str], max_keys: int
    ) -> list[tuple[str, str]]:
        """
        Parse sort key strings into (column, direction) tuples.

        Sort keys in EXPLAIN look like:
        - "orders.created_at"
        - "orders.created_at DESC"
        - "orders.status NULLS FIRST"
        - "orders.created_at DESC NULLS LAST"
        """
        import re

        result: list[tuple[str, str]] = []

        for key in sort_keys[:max_keys]:
            key = key.strip()

            # Detect direction
            direction = "ASC"
            if " DESC" in key.upper():
                direction = "DESC"

            # Extract column name (remove direction, NULLS, table prefix)
            col = re.split(r"\s+(?:ASC|DESC|NULLS|FIRST|LAST)\b", key, flags=re.IGNORECASE)[0].strip()

            # Remove table prefix if present (e.g., "orders.created_at" → "created_at")
            if "." in col:
                col = col.split(".")[-1]

            if col:
                result.append((col, direction))

        return result

    def _build_description(
        self,
        node: "PlanNode",
        table: str,
        rows: int,
        sort_columns: list[tuple[str, str]],
        is_disk_spill: bool,
    ) -> str:
        """Build detailed description."""
        cols_str = ", ".join(
            f"{col} {d}" if d != "ASC" else col
            for col, d in sort_columns
        )
        parts = [
            f"Sort node on '{table}' is sorting {rows:,} rows by ({cols_str})."
        ]

        if is_disk_spill:
            space_kb = node.sort_space_used or 0
            parts.append(
                f"The sort spilled {space_kb / 1024:.1f}MB to disk, making it "
                f"significantly slower than an in-memory sort."
            )

        parts.append(
            "A B-tree index on the sort columns would provide pre-sorted "
            "output, eliminating this Sort node entirely. The planner would "
            "use an Index Scan instead, which reads rows in the desired order "
            "without any sorting step."
        )

        if rows > 100_000:
            parts.append(
                f"With {rows:,} rows, the sort is a major cost center. "
                f"Eliminating it would likely produce a significant speedup."
            )

        return " ".join(parts)

    def _build_suggestion(
        self,
        table: str,
        sort_columns: list[tuple[str, str]],
        node: "PlanNode",
    ) -> str:
        """Build actionable index suggestion."""
        lines: list[str] = []

        if sort_columns:
            # Build index columns with direction
            idx_cols: list[str] = []
            for col, direction in sort_columns:
                if direction == "DESC":
                    idx_cols.append(f"{col} DESC")
                else:
                    idx_cols.append(col)

            cols_str = ", ".join(idx_cols)
            idx_name = f"idx_{table}_sort_{'_'.join(c for c, _ in sort_columns[:3])}"

            lines.append(f"CREATE INDEX {idx_name} ON {table} ({cols_str});")
            lines.append(f"-- Provides pre-sorted output, eliminating the Sort node")
        else:
            lines.append(f"-- Add an index on {table} matching the sort key columns")
            if node.sort_key:
                lines.append(f"-- Sort keys: {', '.join(node.sort_key[:4])}")

        lines.append("")
        lines.append("-- For queries with WHERE + ORDER BY, consider a composite index:")
        lines.append(f"-- CREATE INDEX ON {table} (<where_columns>, <sort_columns>);")
        lines.append("-- Equality columns first, then sort columns")
        lines.append("")
        lines.append("-- After creating the index:")
        lines.append("-- 1. The Sort node should disappear from the plan")
        lines.append("-- 2. An Index Scan should appear instead of Seq Scan + Sort")
        lines.append("-- 3. For LIMIT queries, only the needed rows are read")
        lines.append("")
        lines.append(
            "-- Docs: https://www.postgresql.org/docs/current/indexes-ordering.html"
        )

        return "\n".join(lines)
