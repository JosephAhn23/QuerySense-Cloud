"""
Rule: Inefficient Index Scan (High Filter Discard Ratio)

Detects Index Scan nodes where the index condition is not selective enough,
causing the executor to fetch many rows from the index only to discard most
of them via the Filter condition. This is a common sign of a suboptimal index.

Why it matters:
- The index is doing work (fetching heap tuples) that gets thrown away
- Each discarded row costs a heap page fetch + visibility check
- A more selective index (covering the filter columns) could eliminate waste
- This is one of the most common "hidden" performance issues: the query
  has an index, looks fine, but is secretly slow because the wrong index
  is chosen or the right index doesn't exist

When it happens:
- Index on (a) but query filters on (a, b) — the b filter becomes a
  post-index "Filter" that discards rows
- Composite index with wrong column order (range column first)
- Partial index that isn't selective enough for the workload
- ORM-generated queries that add extra WHERE clauses not covered by indexes

Detection:
- Index Scan or Index Only Scan nodes with "Rows Removed by Filter" > 0
- Ratio of removed rows to actual rows indicates severity
- Higher ratio = more wasted work

Requires EXPLAIN ANALYZE (Rows Removed by Filter is runtime data).
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


class InefficientIndexScanConfig(RuleConfig):
    """
    Configuration for inefficient index scan detection.

    Attributes:
        min_rows_removed: Minimum rows removed by filter to trigger.
        warning_discard_ratio: Discard ratio for WARNING (0.0-1.0).
        critical_discard_ratio: Discard ratio for CRITICAL (0.0-1.0).
    """

    min_rows_removed: int = Field(
        default=1000,
        ge=0,
        description="Minimum rows removed by filter to trigger a finding",
    )
    warning_discard_ratio: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Discard ratio (removed / total) to trigger WARNING",
    )
    critical_discard_ratio: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Discard ratio (removed / total) to trigger CRITICAL",
    )


@register_rule
class InefficientIndexScan(Rule):
    """
    Detect Index Scans where the post-index Filter discards a large
    fraction of rows, indicating the index is not selective enough.

    An index scan that fetches 100K rows from the index but the Filter
    keeps only 1K means 99% of heap fetches were wasted. A better
    composite index covering the filter columns would eliminate this.
    """

    rule_id = "INEFFICIENT_INDEX_SCAN"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects index scans where filter discards most fetched rows"
    phase = RulePhase.PER_NODE

    config_schema = InefficientIndexScanConfig

    # Index-based scan types to check
    _INDEX_SCAN_TYPES = {"Index Scan", "Index Only Scan", "Bitmap Heap Scan"}

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find index scans with high filter discard ratios."""
        config: InefficientIndexScanConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in self._INDEX_SCAN_TYPES:
                continue

            rows_removed = node.rows_removed_by_filter
            if rows_removed is None or rows_removed < config.min_rows_removed:
                continue

            actual_rows = node.actual_rows
            if actual_rows is None:
                continue

            total_fetched = actual_rows + rows_removed
            if total_fetched == 0:
                continue

            discard_ratio = rows_removed / total_fetched

            if discard_ratio < config.warning_discard_ratio:
                continue

            # Determine severity
            if discard_ratio >= config.critical_discard_ratio:
                severity = Severity.CRITICAL
            else:
                severity = Severity.WARNING

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "unknown table"
            index = node.index_name or "current index"

            # Compute impact score (0-10)
            # Base: ratio maps 0.5-1.0 → 3-9, plus bonus for volume
            base_score = 3.0 + (discard_ratio - 0.5) * 12.0  # 3-9
            volume_bonus = min(rows_removed / 100_000, 1.0)  # up to +1
            impact_score = min(round(base_score + volume_bonus, 1), 10.0)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Index scan on {table} discards {discard_ratio:.0%} of "
                    f"fetched rows ({rows_removed:,} removed by filter)"
                ),
                description=self._build_description(
                    node, actual_rows, rows_removed, discard_ratio
                ),
                suggestion=self._build_suggestion(node),
                metrics={
                    "rows_returned": actual_rows,
                    "rows_removed_by_filter": rows_removed,
                    "total_fetched": total_fetched,
                    "discard_ratio": round(discard_ratio, 4),
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.HIGH if discard_ratio > 0.9
                    else ImpactBand.MEDIUM
                ),
                impact_score=impact_score,
                assumptions=(
                    "A more selective index would reduce unnecessary heap fetches",
                    "The filter columns are not covered by the current index condition",
                    "Adding filter columns to the index is safe for write performance",
                ),
                verification_steps=(
                    "Check existing indexes: \\di+ <table>",
                    "Compare index condition vs filter condition in EXPLAIN output",
                    "Create a composite index covering both conditions",
                    "Re-run EXPLAIN ANALYZE to verify Rows Removed by Filter drops",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        actual_rows: int,
        rows_removed: int,
        discard_ratio: float,
    ) -> str:
        """Build detailed description of the inefficiency."""
        table = node.relation_name or "this table"
        index = node.index_name or "the index"
        total = actual_rows + rows_removed

        parts = [
            f"{node.node_type} using '{index}' on '{table}' fetched "
            f"{total:,} rows from the index but the Filter kept only "
            f"{actual_rows:,} ({discard_ratio:.0%} discarded)."
        ]

        if node.index_cond:
            parts.append(f"Index Cond: {node.index_cond}")

        if node.filter:
            parts.append(f"Filter: {node.filter}")

        parts.append(
            "Each discarded row required a heap page fetch that was wasted. "
            "A composite index that covers both the index condition and filter "
            "columns would eliminate this overhead."
        )

        if discard_ratio > 0.95:
            parts.append(
                f"Over 95% of fetched rows are thrown away — this index scan "
                f"is doing almost as much work as a sequential scan but with "
                f"the added overhead of random I/O."
            )

        return " ".join(parts)

    def _build_suggestion(self, node: "PlanNode") -> str:
        """Build actionable fix suggestion."""
        table = node.relation_name or "<table>"
        lines: list[str] = []

        # Extract column hints from conditions
        index_cols = _extract_column_hints(node.index_cond) if node.index_cond else []
        filter_cols = _extract_column_hints(node.filter) if node.filter else []

        if index_cols and filter_cols:
            all_cols = index_cols + [c for c in filter_cols if c not in index_cols]
            cols_str = ", ".join(all_cols)
            lines.append(
                f"CREATE INDEX ON {table} ({cols_str});"
            )
            lines.append(
                f"-- Composite index covering both index condition and filter"
            )
            lines.append(f"-- Index Cond columns: {', '.join(index_cols)}")
            lines.append(f"-- Filter columns: {', '.join(filter_cols)}")
        elif filter_cols:
            cols_str = ", ".join(filter_cols)
            lines.append(f"CREATE INDEX ON {table} ({cols_str});")
            lines.append("-- Covers the filter columns currently causing row discards")
        else:
            lines.append(
                f"-- Add a composite index on {table} covering both"
            )
            lines.append("-- the Index Cond and Filter columns from the EXPLAIN output")
            if node.index_cond:
                lines.append(f"-- Index Cond: {node.index_cond}")
            if node.filter:
                lines.append(f"-- Filter: {node.filter}")

        lines.append("")
        lines.append("-- After creating the index, verify:")
        lines.append("-- 1. 'Rows Removed by Filter' drops to near zero")
        lines.append("-- 2. Total cost decreases")
        lines.append("")
        lines.append(
            "-- Docs: https://www.postgresql.org/docs/current/indexes-multicolumn.html"
        )

        return "\n".join(lines)


def _extract_column_hints(condition: str) -> list[str]:
    """
    Extract likely column names from a condition string.

    Heuristic: looks for identifiers before operators.
    Not perfect but provides useful hints for index suggestions.
    """
    import re

    # Match column references like: table.column, column
    # Before operators: =, <, >, <=, >=, <>, !=, LIKE, IN, IS
    pattern = re.compile(
        r"(?:(\w+)\.)?(\w+)\s*(?:=|<>|!=|<=|>=|<|>|\bLIKE\b|\bIN\b|\bIS\b)",
        re.IGNORECASE,
    )

    columns: list[str] = []
    for match in pattern.finditer(condition):
        col = match.group(2)
        # Skip common non-column tokens
        if col.upper() not in {
            "NULL", "TRUE", "FALSE", "ANY", "ALL", "NOT", "AND", "OR",
        }:
            if col not in columns:
                columns.append(col)

    return columns
