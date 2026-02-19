"""
Rule: Partial Index Opportunity

Detects sequential or index scans with highly selective filter conditions
where a partial index (CREATE INDEX ... WHERE condition) would be
dramatically more efficient than a full table index.

Why it matters:
- A partial index only indexes rows matching the WHERE condition
- For highly selective queries (e.g., WHERE status = 'active' when 5% of
  rows are active), a partial index is 20x smaller than a full index
- Smaller indexes = faster scans, less memory, less I/O, faster VACUUM
- Partial indexes are one of PostgreSQL's most powerful but underused features
- Developers often create full B-tree indexes when a partial index covering
  only the frequently queried subset would be far more efficient

When it happens:
- Queries that consistently filter on a specific value (status = 'pending')
- Boolean filters (WHERE is_active = true, WHERE deleted_at IS NULL)
- Enum-like columns where one value is queried 90%+ of the time
- Time-based filters (WHERE created_at > '2025-01-01')
- Soft-delete patterns (WHERE deleted = false)

Detection:
- Scan nodes with Filter that removes >90% of rows
- The filter pattern suggests a stable, selective condition
- High ratio of Rows Removed by Filter to Actual Rows

Requires EXPLAIN ANALYZE (needs Rows Removed by Filter).

Addresses pain point #10: "GIN indexes, partial indexes, and non-obvious
index types are never suggested."
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


# Patterns that suggest good partial index candidates
# These are stable, selective conditions commonly used in applications
_PARTIAL_INDEX_PATTERNS = re.compile(
    r"""
    \b(
        status\s*=                       # Status enum filter
        |state\s*=                       # State enum filter
        |is_active\s*=\s*(true|'t')      # Boolean active flag
        |is_deleted\s*=\s*(false|'f')    # Soft delete (not deleted)
        |deleted\s*=\s*(false|'f')       # Soft delete
        |deleted_at\s+IS\s+NULL          # Soft delete (null timestamp)
        |archived\s*=\s*(false|'f')      # Archive flag
        |published\s*=\s*(true|'t')      # Published flag
        |enabled\s*=\s*(true|'t')        # Enabled flag
        |visible\s*=\s*(true|'t')        # Visibility flag
        |type\s*=                        # Type discriminator
        |kind\s*=                        # Kind discriminator
        |category\s*=                    # Category filter
        |priority\s*=                    # Priority filter
        |role\s*=                        # Role filter
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


class PartialIndexConfig(RuleConfig):
    """
    Configuration for partial index opportunity detection.

    Attributes:
        min_rows_removed: Minimum rows removed by filter to trigger.
        min_selectivity: Minimum selectivity ratio (removed/total) to trigger.
        min_total_rows: Minimum total rows (before filter) to trigger.
    """

    min_rows_removed: int = Field(
        default=5000,
        ge=0,
        description="Minimum rows removed by filter to trigger",
    )
    min_selectivity: float = Field(
        default=0.9,
        ge=0.5,
        le=1.0,
        description="Minimum selectivity (removed/total) to suggest partial index",
    )
    min_total_rows: int = Field(
        default=10_000,
        ge=100,
        description="Minimum total rows (before filter) to trigger",
    )


@register_rule
class PartialIndexOpportunity(Rule):
    """
    Detect highly selective filter conditions where a partial index
    (CREATE INDEX ... WHERE condition) would dramatically reduce index
    size and improve query performance.
    """

    rule_id = "PARTIAL_INDEX_OPPORTUNITY"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Suggests partial indexes for highly selective filter conditions"
    phase = RulePhase.PER_NODE

    config_schema = PartialIndexConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find scan nodes with highly selective filters."""
        config: PartialIndexConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if not node.is_scan_node:
                continue

            if not node.filter:
                continue

            rows_removed = node.rows_removed_by_filter
            actual_rows = node.actual_rows

            if rows_removed is None or actual_rows is None:
                continue

            if rows_removed < config.min_rows_removed:
                continue

            total_rows = actual_rows + rows_removed
            if total_rows < config.min_total_rows:
                continue

            selectivity = rows_removed / total_rows if total_rows > 0 else 0.0

            if selectivity < config.min_selectivity:
                continue

            # Check if filter matches a good partial index pattern
            has_pattern = bool(_PARTIAL_INDEX_PATTERNS.search(node.filter))

            # Even without a recognized pattern, very high selectivity is notable
            if not has_pattern and selectivity < 0.95:
                continue

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "unknown table"

            # Severity: upgrade for very high selectivity + large tables
            if selectivity > 0.98 and total_rows > 100_000:
                severity = Severity.WARNING
            elif selectivity > 0.95 and total_rows > 50_000:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            # Impact score
            # Partial indexes save proportional to selectivity
            size_reduction = selectivity  # e.g., 0.95 = 95% smaller index
            if total_rows > 100_000:
                impact_score = min(5.0 + size_reduction * 4.0, 9.0)
            elif total_rows > 10_000:
                impact_score = min(3.0 + size_reduction * 3.0, 6.0)
            else:
                impact_score = min(2.0 + size_reduction * 2.0, 4.0)
            impact_score = round(impact_score, 1)

            kept_pct = (1.0 - selectivity) * 100

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Partial index opportunity on {table} — filter keeps only "
                    f"{kept_pct:.1f}% of {total_rows:,} rows"
                ),
                description=self._build_description(
                    node, table, actual_rows, rows_removed,
                    selectivity, has_pattern
                ),
                suggestion=self._build_suggestion(
                    node, table, actual_rows, selectivity
                ),
                metrics={
                    "rows_kept": actual_rows,
                    "rows_removed": rows_removed,
                    "total_rows": total_rows,
                    "selectivity": round(selectivity, 4),
                    "estimated_index_size_reduction": round(selectivity, 4),
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.HIGH if selectivity > 0.98 and total_rows > 100_000
                    else ImpactBand.MEDIUM if selectivity > 0.95
                    else ImpactBand.LOW
                ),
                impact_score=impact_score,
                assumptions=(
                    "The filter condition is stable and doesn't change between queries",
                    "The matching row subset is a small fraction of the total table",
                    f"A partial index would be ~{selectivity:.0%} smaller than a full index",
                ),
                verification_steps=(
                    "Verify the filter condition is used consistently across queries",
                    f"Check current indexes: \\di+ {table}",
                    "Create the partial index and compare plan costs",
                    "Monitor partial index size vs full index size",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        table: str,
        actual_rows: int,
        rows_removed: int,
        selectivity: float,
        has_pattern: bool,
    ) -> str:
        """Build detailed description."""
        total = actual_rows + rows_removed
        kept_pct = (1.0 - selectivity) * 100

        parts = [
            f"{node.node_type} on '{table}' scanned {total:,} rows but the "
            f"Filter kept only {actual_rows:,} ({kept_pct:.1f}%)."
        ]

        parts.append(f"Filter: {node.filter}")

        if has_pattern:
            parts.append(
                "This filter matches a common partial index pattern (status/boolean/"
                "soft-delete). A partial index on this condition would index only "
                "the matching subset of rows."
            )

        parts.append(
            f"A partial index covering only the {kept_pct:.1f}% of rows that match "
            f"the filter would be ~{selectivity:.0%} smaller than a full index, "
            f"resulting in faster lookups, less memory usage, and faster maintenance."
        )

        return " ".join(parts)

    def _build_suggestion(
        self,
        node: "PlanNode",
        table: str,
        actual_rows: int,
        selectivity: float,
    ) -> str:
        """Build actionable partial index suggestion."""
        lines: list[str] = []
        filter_cond = node.filter or "<filter_condition>"

        # Try to extract a clean WHERE clause from the filter
        where_clause = _simplify_filter_for_where(filter_cond)

        lines.append(f"-- Partial index: indexes only the {(1.0 - selectivity) * 100:.0f}% of rows that match")
        lines.append(f"CREATE INDEX ON {table} (<indexed_columns>)")
        lines.append(f"  WHERE {where_clause};")
        lines.append("")
        lines.append(f"-- Full filter from EXPLAIN: {filter_cond}")
        lines.append("")
        lines.append("-- Benefits of partial indexes:")
        lines.append(f"-- 1. Index is ~{selectivity:.0%} smaller than a full index")
        lines.append("-- 2. INSERT/UPDATE only touches index for matching rows")
        lines.append("-- 3. VACUUM is faster on smaller indexes")
        lines.append("-- 4. Index fits better in shared_buffers cache")
        lines.append("")
        lines.append("-- Important: your query WHERE clause must match the index WHERE clause")
        lines.append("-- PostgreSQL can only use a partial index if it can prove the query")
        lines.append("-- condition implies the index condition.")
        lines.append("")
        lines.append("-- Docs: https://www.postgresql.org/docs/current/indexes-partial.html")

        return "\n".join(lines)


def _simplify_filter_for_where(filter_str: str) -> str:
    """
    Attempt to simplify an EXPLAIN Filter string into a valid WHERE clause.

    EXPLAIN filters look like: ((status)::text = 'active'::text)
    We try to clean these up into: status = 'active'
    """
    result = filter_str

    # Remove outer parentheses
    while result.startswith("(") and result.endswith(")"):
        inner = result[1:-1]
        # Only strip if balanced
        depth = 0
        balanced = True
        for ch in inner:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if depth < 0:
                balanced = False
                break
        if balanced and depth == 0:
            result = inner
        else:
            break

    # Remove PostgreSQL type casts: (column)::type → column
    result = re.sub(r"\((\w+)\)::\w+", r"\1", result)

    # Remove literal type casts: 'value'::type → 'value'
    result = re.sub(r"'([^']*)'::[\w\s]+", r"'\1'", result)

    return result.strip()
