"""
Rule: Index Column Order Mismatch

Detects when an index scan's condition uses a non-leading column of a
composite index, causing PostgreSQL to fall back to a sequential scan or
an inefficient index scan that reads far more rows than necessary.

Real-world example (CounterPath / pganalyze case study):
  - Table had index on (user_id, account_id)
  - Query filtered only by account_id
  - Result: constant sequential scans, 400% CPU utilisation
  - Fix: add index on (account_id) → CPU dropped to 25% instantly

Why it matters:
- B-tree indexes are prefix-based: only leftmost columns are usable for
  equality/range lookups.  An index on (A, B) is useless for WHERE B = ?.
- The planner may still *choose* the index via a full index scan + filter,
  which looks like an index scan in EXPLAIN but performs almost as poorly
  as a sequential scan (random I/O on every matching row).
- This is one of the most common "silent" performance killers in production
  Postgres, especially in ORM-heavy applications where queries evolve but
  indexes don't.

Detection strategy:
- Find Index Scan / Index Only Scan nodes where the index condition
  references a column that appears to be a non-leading column.
- Also detect Seq Scan nodes on tables that have a Filter mentioning
  columns that might be covered by an existing index in wrong order
  (when raw plan exposes "Index Cond" vs "Filter" mismatch).
- Use "Rows Removed by Filter" as a severity multiplier: the more rows
  discarded, the more likely the column order is wrong.
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


class IndexColumnOrderConfig(RuleConfig):
    min_rows_removed: int = Field(
        default=500,
        ge=0,
        description="Minimum rows removed by filter to flag a mismatch",
    )
    warning_discard_ratio: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Filter discard ratio to trigger WARNING",
    )
    critical_discard_ratio: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Filter discard ratio to trigger CRITICAL",
    )
    min_total_rows: int = Field(
        default=1000,
        ge=0,
        description="Minimum total fetched rows (actual + removed) to trigger",
    )


_COL_RE = re.compile(
    r"(?:(\w+)\.)?(\w+)\s*(?:=|<>|!=|<=|>=|<|>|\bLIKE\b|\bIN\b|\bIS\b)",
    re.IGNORECASE,
)

_NON_COLUMNS = frozenset({
    "NULL", "TRUE", "FALSE", "ANY", "ALL", "NOT", "AND", "OR",
})


def _extract_columns(condition: str | None) -> list[str]:
    """Extract probable column names from a SQL condition string."""
    if not condition:
        return []
    cols: list[str] = []
    for m in _COL_RE.finditer(condition):
        col = m.group(2)
        if col.upper() not in _NON_COLUMNS and col not in cols:
            cols.append(col)
    return cols


@register_rule
class IndexColumnOrder(Rule):
    """
    Detect index scans where the filter discards many rows because the
    query predicate doesn't match the leading column(s) of the chosen index.

    This is the classic (user_id, account_id) vs WHERE account_id = ?
    pattern: the index exists, the planner picks it, but it performs a
    near-full-index scan with post-filter, wasting CPU and I/O.
    """

    rule_id = "INDEX_COLUMN_ORDER"
    version = "1.0.0"
    severity = Severity.WARNING
    description = (
        "Detects index scans where the leading index column doesn't match "
        "the query predicate, causing excessive row filtering"
    )
    phase = RulePhase.PER_NODE
    config_schema = IndexColumnOrderConfig

    _INDEX_SCAN_TYPES = {"Index Scan", "Index Only Scan"}

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: IndexColumnOrderConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in self._INDEX_SCAN_TYPES:
                continue

            rows_removed = node.rows_removed_by_filter
            if rows_removed is None or rows_removed < config.min_rows_removed:
                continue

            actual = node.actual_rows
            if actual is None:
                continue

            total_fetched = actual + rows_removed
            if total_fetched < config.min_total_rows:
                continue

            discard_ratio = rows_removed / total_fetched
            if discard_ratio < config.warning_discard_ratio:
                continue

            index_cols = _extract_columns(node.index_cond)
            filter_cols = _extract_columns(node.filter)

            if not filter_cols:
                continue

            non_leading = [c for c in filter_cols if c not in index_cols]
            if not non_leading:
                continue

            if discard_ratio >= config.critical_discard_ratio:
                severity = Severity.CRITICAL
            else:
                severity = Severity.WARNING

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "unknown table"
            index = node.index_name or "current index"

            base = 4.0 + (discard_ratio - 0.6) * 15.0
            vol_bonus = min(rows_removed / 100_000, 1.5)
            impact_score = min(round(base + vol_bonus, 1), 10.0)

            ideal_cols = non_leading + index_cols
            ideal_cols_str = ", ".join(ideal_cols)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Index column order mismatch on {table}: filter on "
                    f"{', '.join(non_leading)} not in leading index columns "
                    f"({discard_ratio:.0%} rows discarded)"
                ),
                description=self._build_description(
                    node, table, index, actual, rows_removed,
                    discard_ratio, index_cols, filter_cols, non_leading,
                ),
                suggestion=self._build_suggestion(
                    table, index, ideal_cols_str, non_leading,
                    index_cols, filter_cols,
                ),
                metrics={
                    "rows_returned": actual,
                    "rows_removed_by_filter": rows_removed,
                    "total_fetched": total_fetched,
                    "discard_ratio": round(discard_ratio, 4),
                    "non_leading_columns": len(non_leading),
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.HIGH if discard_ratio >= 0.9
                    else ImpactBand.MEDIUM
                ),
                impact_score=impact_score,
                assumptions=(
                    "The filter columns are not in the leading position of "
                    "the current index",
                    "Reordering or adding a new index with the filter column "
                    "as the leading column would eliminate post-index filtering",
                    "Query pattern is frequent enough to justify a new index",
                ),
                verification_steps=(
                    f"Check current index definition: \\di+ {index}",
                    "Verify filter columns vs index column order",
                    f"CREATE INDEX ON {table} ({ideal_cols_str})",
                    "Re-run EXPLAIN ANALYZE and verify 'Rows Removed by "
                    "Filter' drops to near zero",
                    "Monitor CPU utilisation before and after the change",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        table: str,
        index: str,
        actual: int,
        rows_removed: int,
        discard_ratio: float,
        index_cols: list[str],
        filter_cols: list[str],
        non_leading: list[str],
    ) -> str:
        total = actual + rows_removed
        parts = [
            f"{node.node_type} on '{table}' using '{index}' fetched "
            f"{total:,} rows but discarded {rows_removed:,} "
            f"({discard_ratio:.0%}) via post-index Filter."
        ]

        if index_cols:
            parts.append(
                f"Index condition uses: {', '.join(index_cols)}."
            )
        parts.append(
            f"Filter condition requires: {', '.join(filter_cols)}, "
            f"but {', '.join(non_leading)} {'is' if len(non_leading) == 1 else 'are'} "
            f"not in the index's leading columns."
        )

        parts.append(
            "B-tree indexes are prefix-based: only the leftmost columns "
            "are used for efficient lookups. When your query predicate "
            "targets a non-leading column, PostgreSQL must scan the "
            "entire index and filter rows afterwards — effectively as "
            "slow as a sequential scan but with random I/O overhead."
        )

        if discard_ratio >= 0.95:
            parts.append(
                "Over 95% of rows are discarded — this index is almost "
                "useless for this query pattern. A correctly ordered "
                "composite index could reduce CPU and I/O by 10-100x "
                "(similar to the CounterPath case: 400% CPU → 25%)."
            )

        return " ".join(parts)

    def _build_suggestion(
        self,
        table: str,
        index: str,
        ideal_cols_str: str,
        non_leading: list[str],
        index_cols: list[str],
        filter_cols: list[str],
    ) -> str:
        lines = [
            f"-- The current index '{index}' has the wrong column order",
            f"-- for this query.  Filter columns {non_leading} should be",
            f"-- in the leading position.",
            f"",
            f"-- Option 1: Create a new index with correct column order",
            f"CREATE INDEX ON {table} ({ideal_cols_str});",
            f"",
            f"-- Option 2: If the old index is only used by this query,",
            f"-- replace it:",
            f"-- DROP INDEX {index};",
            f"-- CREATE INDEX ON {table} ({ideal_cols_str});",
            f"",
            f"-- After the change, verify with:",
            f"-- EXPLAIN (ANALYZE, BUFFERS) <your query>",
            f"-- 'Rows Removed by Filter' should drop to near zero.",
            f"",
            f"-- Docs: https://www.postgresql.org/docs/current/"
            f"indexes-multicolumn.html",
        ]
        return "\n".join(lines)
