"""
Rule: Backward Index Scan Detection

Detects Index Scan nodes running in "Backward" direction, which is slower
than forward scans and can be eliminated with a DESC index.

Why it matters:
- Backward index scans traverse the B-tree in reverse leaf-page order
- Each leaf page access follows the "previous page" pointer instead of
  the optimized "next page" pointer, causing additional random I/O
- On spinning disks, backward scans are measurably slower (5-30%)
- On SSDs, the difference is smaller but still exists due to CPU overhead
  and worse cache locality
- For ORDER BY ... DESC LIMIT N queries, a DESC index turns a backward
  scan into a forward scan, often with significant improvement
- This is a common pattern: "SELECT * FROM events ORDER BY created_at DESC
  LIMIT 20" — a forward scan on a DESC index reads just 1-2 pages

When it happens:
- ORDER BY column DESC without a matching DESC index
- Queries fetching "latest N rows" from time-series tables
- Pagination queries (OFFSET/LIMIT) on reverse-ordered data
- MAX() on a B-tree indexed column (planner uses backward scan)

Detection:
- Index Scan or Index Only Scan with "Scan Direction" = "Backward"
- Severity based on row count and whether a LIMIT is present

Does NOT require EXPLAIN ANALYZE (Scan Direction is in all EXPLAIN output).
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


class BackwardIndexScanConfig(RuleConfig):
    """
    Configuration for backward index scan detection.

    Attributes:
        min_plan_rows: Minimum estimated rows to trigger.
        report_all: If True, report all backward scans (even small ones).
    """

    min_plan_rows: int = Field(
        default=100,
        ge=0,
        description="Minimum estimated rows to trigger a finding",
    )
    report_all: bool = Field(
        default=False,
        description="Report all backward scans regardless of size",
    )


@register_rule
class BackwardIndexScan(Rule):
    """
    Detect backward index scans that could benefit from a DESC index.

    Backward scans are less efficient than forward scans. When the query
    consistently needs reverse-ordered data (e.g., ORDER BY created_at DESC),
    a DESC index eliminates the backward traversal.
    """

    rule_id = "BACKWARD_INDEX_SCAN"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Detects backward index scans suggesting DESC index would help"
    phase = RulePhase.PER_NODE

    config_schema = BackwardIndexScanConfig

    _INDEX_SCAN_TYPES = {"Index Scan", "Index Only Scan"}

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find backward index scans."""
        config: BackwardIndexScanConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in self._INDEX_SCAN_TYPES:
                continue

            if node.scan_direction != "Backward":
                continue

            rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
            if not config.report_all and rows < config.min_plan_rows:
                continue

            # Check if parent is a Limit node (common pattern: ORDER BY DESC LIMIT N)
            has_limit = parent is not None and parent.node_type == "Limit"

            # Severity: upgrade if large backward scan
            if rows > 100_000:
                severity = Severity.WARNING
            elif has_limit and rows > 1000:
                severity = Severity.INFO
            else:
                severity = Severity.INFO

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "unknown table"
            index = node.index_name or "current index"

            # Compute impact score
            # Backward scans are a moderate optimization opportunity
            if rows > 100_000:
                impact_score = min(4.0 + min(rows / 500_000, 3.0), 7.0)
            elif has_limit:
                impact_score = 3.0
            else:
                impact_score = min(1.0 + rows / 50_000, 3.0)
            impact_score = round(impact_score, 1)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Backward index scan on {table} using {index} "
                    f"({rows:,} rows)"
                    + (" with LIMIT" if has_limit else "")
                ),
                description=self._build_description(
                    node, table, index, rows, has_limit
                ),
                suggestion=self._build_suggestion(node, table, index),
                metrics={
                    "rows_scanned": rows,
                    "total_cost": node.total_cost,
                    "has_limit": 1 if has_limit else 0,
                },
                impact_band=(
                    ImpactBand.MEDIUM if rows > 100_000
                    else ImpactBand.LOW
                ),
                impact_score=impact_score,
                assumptions=(
                    "The query consistently needs reverse-ordered data",
                    "A DESC index would convert backward scan to forward scan",
                    "The cost of maintaining a DESC index is acceptable",
                ),
                verification_steps=(
                    "Check if this query pattern is frequent (pg_stat_statements)",
                    "Create the DESC index and re-run EXPLAIN ANALYZE",
                    "Verify Scan Direction changes from 'Backward' to 'Forward'",
                    "Compare execution times before and after",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        table: str,
        index: str,
        rows: int,
        has_limit: bool,
    ) -> str:
        """Build detailed description."""
        parts = [
            f"{node.node_type} on '{table}' using index '{index}' is "
            f"scanning {rows:,} rows in backward direction."
        ]

        if has_limit:
            parts.append(
                "This is likely an ORDER BY ... DESC LIMIT query. A DESC "
                "index would turn the backward scan into a forward scan, "
                "which has better cache locality and I/O patterns."
            )

        parts.append(
            "Backward index scans traverse B-tree leaf pages in reverse "
            "order using the 'previous page' pointer, which is less "
            "efficient than forward traversal. On large scans, this adds "
            "measurable overhead (5-30% on spinning disks, less on SSDs)."
        )

        if node.index_cond:
            parts.append(f"Index Cond: {node.index_cond}")

        return " ".join(parts)

    def _build_suggestion(
        self,
        node: "PlanNode",
        table: str,
        index: str,
    ) -> str:
        """Build actionable suggestion for DESC index."""
        lines: list[str] = []

        # Try to extract the indexed column from the index name or condition
        lines.append(f"-- Replace the ASC index with a DESC index:")
        lines.append(f"-- Current index: {index}")
        lines.append(f"CREATE INDEX {index}_desc ON {table} (<column> DESC);")
        lines.append("")
        lines.append("-- For composite indexes, DESC only the column(s) used")
        lines.append("-- for reverse ordering:")
        lines.append(f"-- CREATE INDEX ON {table} (col1, col2 DESC);")
        lines.append("")
        lines.append("-- After creating the DESC index, optionally drop the old one:")
        lines.append(f"-- DROP INDEX {index};  -- only if no other queries need ASC order")
        lines.append("")
        lines.append("-- Note: PostgreSQL can use ASC indexes for DESC scans (backward),")
        lines.append("-- but a native DESC index is more efficient for consistent DESC access.")
        lines.append("")
        lines.append(
            "-- Docs: https://www.postgresql.org/docs/current/indexes-ordering.html"
        )

        return "\n".join(lines)
