"""
Rule: GIN Index Opportunity

Detects filter conditions on array, JSONB, full-text search, and
hstore columns where a GIN index would dramatically improve performance
over sequential scanning.

Why it matters:
- B-tree indexes cannot accelerate containment operators (@>, ?, &&)
- JSONB queries without GIN indexes always fall back to sequential scan
- Full-text search with tsvector requires GIN for to_tsvector() lookups
- Array containment checks (@>, &&) need GIN(array_ops)
- These are some of the fastest-growing PostgreSQL use cases (JSON APIs,
  search, tagging systems) and developers routinely miss the index

When it happens:
- JSONB column with @>, ?, ?|, ?& operators and no GIN index
- Array column with @>, &&, <@ operators and no GIN index
- tsvector column with @@ operator and no GIN index
- hstore column with @>, ?, ?|, ?& operators and no GIN index

Detection:
- Seq Scan or Filter containing GIN-eligible operators
- Filter string parsing for operator patterns
- Large row counts amplify severity (GIN benefit scales with table size)

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


# Operators that require GIN indexes for efficient evaluation
_GIN_OPERATORS = re.compile(
    r"""
    \s(                         # Preceded by whitespace
        @>                      # Contains (JSONB, array, hstore)
        |<@                     # Contained by
        |&&                     # Overlap (array)
        |\?\|                   # Any key exists (JSONB, hstore)
        |\?\&                   # All keys exist (JSONB, hstore)
        |\?                     # Key exists (JSONB, hstore)
        |@@                     # Full-text search match
    )\s
    """,
    re.VERBOSE,
)

# Function patterns that suggest GIN-indexable operations
_GIN_FUNCTIONS = re.compile(
    r"""
    \b(
        to_tsvector             # Full-text search
        |plainto_tsquery        # Full-text query
        |phraseto_tsquery       # Full-text phrase query
        |websearch_to_tsquery   # Full-text web search
        |ts_rank                # Full-text ranking
        |ts_rank_cd             # Full-text ranking (cover density)
        |jsonb_path_exists      # JSONB path check
        |jsonb_path_match       # JSONB path match
        |jsonb_path_query       # JSONB path query
        |array_position         # Array search (could use GIN)
        |array_positions        # Array search
    )\s*\(
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Type hints from operator usage
_OPERATOR_TYPE_HINTS: dict[str, str] = {
    "@>": "JSONB/array/hstore containment",
    "<@": "JSONB/array/hstore contained-by",
    "&&": "array overlap",
    "?": "JSONB/hstore key existence",
    "?|": "JSONB/hstore any-key existence",
    "?&": "JSONB/hstore all-keys existence",
    "@@": "full-text search match",
}


class GinIndexConfig(RuleConfig):
    """
    Configuration for GIN index opportunity detection.

    Attributes:
        min_plan_rows: Minimum plan rows to trigger.
        check_filter: Check Filter conditions.
        check_recheck: Check Recheck Cond (bitmap scans).
    """

    min_plan_rows: int = Field(
        default=500,
        ge=0,
        description="Minimum plan rows to trigger a finding",
    )
    check_filter: bool = Field(
        default=True,
        description="Check Filter conditions for GIN-eligible operators",
    )
    check_recheck: bool = Field(
        default=True,
        description="Check Recheck Cond for GIN-eligible operators",
    )


@register_rule
class GinIndexOpportunity(Rule):
    """
    Detect filter conditions where a GIN index would dramatically
    improve performance for JSONB, array, full-text, and hstore queries.
    """

    rule_id = "GIN_INDEX_OPPORTUNITY"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects JSONB/array/full-text filters that need GIN indexes"
    phase = RulePhase.PER_NODE

    config_schema = GinIndexConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find filter conditions that would benefit from GIN indexes."""
        config: GinIndexConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Only check scan nodes (where filters run)
            if not node.is_scan_node:
                continue

            rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
            if rows < config.min_plan_rows:
                continue

            # Check Filter condition
            if config.check_filter and node.filter:
                findings.extend(
                    self._check_condition(node, path, parent, node.filter, "Filter")
                )

            # Check Recheck Cond (bitmap heap scans)
            if config.check_recheck and node.recheck_cond:
                findings.extend(
                    self._check_condition(node, path, parent, node.recheck_cond, "Recheck Cond")
                )

        return findings

    def _check_condition(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
        condition: str,
        condition_type: str,
    ) -> list[Finding]:
        """Check a condition string for GIN-eligible operators."""
        findings: list[Finding] = []

        # Check for GIN operators
        operator_matches = list(_GIN_OPERATORS.finditer(condition))
        function_matches = list(_GIN_FUNCTIONS.finditer(condition))

        if not operator_matches and not function_matches:
            return findings

        context = NodeContext.from_node(node, path, parent)
        table = node.relation_name or "unknown table"
        rows = node.actual_rows if node.actual_rows is not None else node.plan_rows

        # Collect detected operators
        detected_ops: list[str] = []
        for match in operator_matches:
            op = match.group(1).strip()
            hint = _OPERATOR_TYPE_HINTS.get(op, "GIN-eligible operation")
            detected_ops.append(f"{op} ({hint})")

        detected_funcs: list[str] = []
        for match in function_matches:
            detected_funcs.append(match.group(1))

        # Determine the likely column type
        if any("@@" in op for op in detected_ops) or any(
            f in ("to_tsvector", "plainto_tsquery", "websearch_to_tsquery")
            for f in detected_funcs
        ):
            index_type = "GIN"
            column_hint = "tsvector"
            suggestion_detail = "full-text search"
        elif any("&&" in op for op in detected_ops):
            index_type = "GIN"
            column_hint = "array"
            suggestion_detail = "array overlap/containment"
        elif any("@>" in op or "<@" in op for op in detected_ops):
            index_type = "GIN"
            column_hint = "jsonb/array"
            suggestion_detail = "JSONB/array containment"
        elif any("?" in op for op in detected_ops):
            index_type = "GIN"
            column_hint = "jsonb/hstore"
            suggestion_detail = "key existence check"
        else:
            index_type = "GIN"
            column_hint = "jsonb/array/tsvector"
            suggestion_detail = "specialized data type operation"

        # Severity based on row count and scan type
        if node.node_type == "Seq Scan" and rows > 10_000:
            severity = Severity.CRITICAL if rows > 100_000 else Severity.WARNING
        else:
            severity = Severity.WARNING

        # Impact score
        if rows > 100_000:
            impact_score = min(7.0 + min(rows / 500_000, 3.0), 10.0)
        elif rows > 10_000:
            impact_score = min(4.0 + min(rows / 50_000, 3.0), 7.0)
        else:
            impact_score = 3.0
        impact_score = round(impact_score, 1)

        ops_str = ", ".join(detected_ops[:3])
        funcs_str = ", ".join(detected_funcs[:3])
        detail = ops_str if ops_str else funcs_str

        findings.append(Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=(
                f"GIN index needed on {table} for {suggestion_detail} "
                f"({rows:,} rows scanned)"
            ),
            description=self._build_description(
                node, table, condition, condition_type,
                detected_ops, detected_funcs, rows
            ),
            suggestion=self._build_suggestion(
                table, index_type, column_hint, condition, detected_funcs
            ),
            metrics={
                "rows_scanned": rows,
                "total_cost": node.total_cost,
                "detected_operators": len(detected_ops),
                "detected_functions": len(detected_funcs),
            },
            impact_band=(
                ImpactBand.HIGH if rows > 100_000
                else ImpactBand.MEDIUM if rows > 10_000
                else ImpactBand.LOW
            ),
            impact_score=impact_score,
            assumptions=(
                f"No GIN index exists on the {column_hint} column(s)",
                "The operator pattern indicates a GIN-indexable data type",
                "GIN index creation and maintenance overhead is acceptable",
            ),
            verification_steps=(
                f"Check existing indexes: \\di+ {table}",
                "Verify the column data type supports GIN indexing",
                "Create the GIN index and re-run EXPLAIN ANALYZE",
                "Monitor GIN index size and write amplification",
            ),
        ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        table: str,
        condition: str,
        condition_type: str,
        detected_ops: list[str],
        detected_funcs: list[str],
        rows: int,
    ) -> str:
        """Build detailed description."""
        parts = [
            f"{node.node_type} on '{table}' is scanning {rows:,} rows "
            f"with a {condition_type} that uses GIN-eligible operators."
        ]

        parts.append(f"{condition_type}: {condition}")

        if detected_ops:
            ops_str = ", ".join(detected_ops[:3])
            parts.append(f"Detected operators: {ops_str}")

        if detected_funcs:
            funcs_str = ", ".join(detected_funcs[:3])
            parts.append(f"Detected functions: {funcs_str}")

        parts.append(
            "B-tree indexes cannot accelerate these operators. A GIN index "
            "provides inverted-index lookups that are orders of magnitude "
            "faster for containment, existence, and full-text queries."
        )

        return " ".join(parts)

    def _build_suggestion(
        self,
        table: str,
        index_type: str,
        column_hint: str,
        condition: str,
        detected_funcs: list[str],
    ) -> str:
        """Build actionable GIN index suggestion."""
        lines: list[str] = []

        if "to_tsvector" in detected_funcs or "@@" in condition:
            lines.append(f"-- Full-text search: create a GIN index on the tsvector column")
            lines.append(f"CREATE INDEX ON {table} USING GIN (<tsvector_column>);")
            lines.append(f"")
            lines.append(f"-- Or on an expression (if no tsvector column exists):")
            lines.append(f"CREATE INDEX ON {table} USING GIN (to_tsvector('english', <text_column>));")
        elif "&&" in condition or "@>" in condition or "<@" in condition:
            lines.append(f"-- JSONB/array containment: create a GIN index")
            lines.append(f"CREATE INDEX ON {table} USING GIN (<column>);")
            lines.append(f"")
            lines.append(f"-- For JSONB with specific path queries, use jsonb_path_ops:")
            lines.append(f"CREATE INDEX ON {table} USING GIN (<column> jsonb_path_ops);")
            lines.append(f"-- jsonb_path_ops is smaller and faster for @> queries")
        elif "?" in condition:
            lines.append(f"-- JSONB/hstore key existence: create a GIN index")
            lines.append(f"CREATE INDEX ON {table} USING GIN (<column>);")
        else:
            lines.append(f"CREATE INDEX ON {table} USING GIN (<column>);")

        lines.append("")
        lines.append("-- GIN index notes:")
        lines.append("-- 1. GIN indexes are larger than B-tree and slower to update")
        lines.append("-- 2. Consider gin_pending_list_limit for write-heavy tables")
        lines.append("-- 3. Use CONCURRENTLY to avoid locking the table:")
        lines.append(f"--    CREATE INDEX CONCURRENTLY ON {table} USING GIN (<column>);")
        lines.append("")
        lines.append("-- Docs: https://www.postgresql.org/docs/current/gin-intro.html")

        return "\n".join(lines)
