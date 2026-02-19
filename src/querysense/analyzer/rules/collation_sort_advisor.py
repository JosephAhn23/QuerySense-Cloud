"""
Rule: Collation Sort Performance Advisor

Inspired by pganalyze "Waiting for Postgres 17: The new built-in C.UTF-8
locale" (E107) — sorting with linguistic collation (en_US.UTF-8) can be
2x slower than binary sorting (C or C.UTF-8).

The article demonstrated:
  - C.UTF-8 locale: 193ms for sorting 1M text values
  - en_US.UTF-8 locale: 461ms for the same operation (2.4x slower)
  - Adding COLLATE "C" to the column reference: back to 189ms

Detection strategy:
  Identify Sort nodes where:
  - The sort consumes a large fraction of total plan time
  - Sort Key references text columns (string comparison is expensive)
  - Estimated or actual rows are large enough to matter
  - No explicit COLLATE is present in the sort key

This rule suggests adding COLLATE "C" or COLLATE "C.UTF-8" (PG17+)
to ORDER BY expressions when linguistic ordering isn't needed.
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


class CollationSortConfig(RuleConfig):
    min_sort_rows: int = Field(
        default=10_000,
        ge=0,
        description="Minimum rows in sort to trigger",
    )
    sort_time_pct_threshold: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Minimum fraction of total time spent in sort",
    )


@register_rule
class CollationSortAdvisor(Rule):
    """
    Detect expensive Sort nodes on text columns where binary collation
    (COLLATE "C") could dramatically reduce sort time.

    Linguistic collation requires Unicode-aware string comparison on every
    pair, which is 2-3x slower than byte-wise comparison for most workloads.
    """

    rule_id = "COLLATION_SORT_EXPENSIVE"
    version = "1.0.0"
    severity = Severity.INFO
    description = (
        "Detects expensive text sorts where COLLATE C could improve "
        "performance by 2-3x"
    )
    phase = RulePhase.PER_NODE
    config_schema = CollationSortConfig

    _SORT_TYPES = {"Sort", "Incremental Sort"}

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: CollationSortConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        root_time = None
        if explain.plan.actual_total_time is not None:
            root_time = explain.plan.actual_total_time

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in self._SORT_TYPES:
                continue

            rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
            if rows < config.min_sort_rows:
                continue

            sort_keys = node.raw.get("Sort Key", [])
            if not sort_keys:
                continue

            has_collate = any(
                "collate" in str(k).lower() for k in sort_keys
            )
            if has_collate:
                continue

            is_text_sort = any(
                "::" in str(k) and "text" in str(k).lower()
                for k in sort_keys
            ) or any(
                not any(c.isdigit() for c in str(k)) and "." not in str(k)
                for k in sort_keys
            )

            sort_time = node.actual_total_time
            if sort_time is not None and root_time and root_time > 0:
                sort_pct = sort_time / root_time
                if sort_pct < config.sort_time_pct_threshold:
                    continue
            else:
                sort_pct = None

            if rows > 100_000:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            context = NodeContext.from_node(node, path, parent)

            base_score = 2.0
            if sort_pct and sort_pct > 0.5:
                base_score += 3.0
            if rows > 100_000:
                base_score += 2.0
            elif rows > 10_000:
                base_score += 1.0
            impact_score = min(round(base_score, 1), 8.0)

            sort_key_str = ", ".join(str(k) for k in sort_keys)

            pct_str = ""
            if sort_pct is not None:
                pct_str = f", {sort_pct:.0%} of total time"

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Expensive text sort on {rows:,} rows"
                    f"{pct_str} — COLLATE C could help"
                ),
                description=self._build_description(
                    node, rows, sort_keys, sort_pct,
                ),
                suggestion=self._build_suggestion(sort_key_str),
                metrics={
                    "rows_sorted": rows,
                    "sort_time_ms": sort_time or 0.0,
                    "sort_time_pct": round(sort_pct, 4) if sort_pct else 0.0,
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.MEDIUM if rows > 100_000
                    else ImpactBand.LOW
                ),
                impact_score=impact_score,
                assumptions=(
                    "The sort uses the database's default linguistic collation",
                    "Binary (byte-wise) sorting is acceptable for this use case",
                    "The performance improvement is typically 2-3x for large sorts",
                ),
                verification_steps=(
                    "Add COLLATE \"C\" to your ORDER BY columns and re-run",
                    "Compare execution time with and without COLLATE",
                    "Consider upgrading to PG17+ for the builtin C.UTF-8 locale",
                    "If linguistic ordering is needed, keep the current collation",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        rows: int,
        sort_keys: list,
        sort_pct: float | None,
    ) -> str:
        parts = [
            f"{node.node_type} is sorting {rows:,} rows using the "
            f"database's default collation."
        ]

        if sort_pct and sort_pct > 0.3:
            parts.append(
                f"This sort consumes {sort_pct:.0%} of the total query time."
            )

        parts.append(
            "Linguistic collation (e.g. en_US.UTF-8) requires Unicode-aware "
            "string comparison, which is 2-3x slower than binary comparison. "
            "If you don't need language-specific sort order (e.g. German "
            "umlauts sorting after their base character), switching to "
            "COLLATE \"C\" can cut sort time in half."
        )

        sort_method = node.raw.get("Sort Method", "")
        if sort_method:
            space_type = node.raw.get("Sort Space Type", "")
            space_used = node.raw.get("Sort Space Used", "")
            parts.append(
                f"Sort method: {sort_method}"
                + (f" ({space_type}: {space_used}kB)" if space_type else "")
            )

        return " ".join(parts)

    def _build_suggestion(self, sort_key_str: str) -> str:
        return "\n".join([
            "-- Add COLLATE \"C\" to your ORDER BY columns:",
            f"-- ORDER BY {sort_key_str} → ORDER BY {sort_key_str} COLLATE \"C\"",
            "",
            "-- Or for PostgreSQL 17+, use the builtin C.UTF-8 locale:",
            "-- CREATE DATABASE mydb LOCALE_PROVIDER = builtin",
            "--   BUILTIN_LOCALE = 'C.UTF-8';",
            "",
            "-- For indexes, create a collation-aware index:",
            "-- CREATE INDEX ON mytable (column COLLATE \"C\");",
            "",
            "-- This preserves Unicode-aware UPPER/LOWER functions",
            "-- while getting binary sort performance.",
            "",
            "-- Ref: https://www.postgresql.org/docs/17/collation.html",
        ])
