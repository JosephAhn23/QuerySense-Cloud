"""
Rule: Non-Sargable Predicate Detection

Detects implicit casts, function-wrapped columns, and collation issues
in Filter and Index Cond expressions that prevent index usage.

Why it matters:
- Indexes "randomly stop being used" because of implicit casts,
  collation behavior, or function-wrapped columns
- This is invisible at the app layer — the SQL "looks fine" but the
  plan shows a cast like (id)::numeric = '...' or lower(name) = '...'
- ORM/query-builder type rewrites are a common source (e.g., jOOQ
  casting bigint to numeric, Hibernate implicit casts)
- A single non-sargable predicate can flip an Index Scan to Seq Scan,
  causing 10-1000x regression on large tables

Detection strategy:
- Parse Filter and Index Cond strings for cast patterns:
  (column)::type, CAST(column AS type)
- Parse for function-wrapped columns: function(column)
- Flag when these appear on Seq Scan nodes (index can't be used)
- Flag when they appear in Index Cond (index used but recheck needed)
- Detect collation annotations that suggest locale-dependent behavior

Limitations:
- Works on the text representation of conditions from EXPLAIN JSON
- Cannot know the original SQL or ORM that generated the cast
- Heuristic detection: some casts/functions are legitimate
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


# ============================================================================
# Regex patterns for non-sargable constructs in EXPLAIN conditions
# ============================================================================

# Cast pattern: (column_expr)::type  e.g., (id)::numeric, (created_at)::date
_CAST_PATTERN = re.compile(
    r"\(([a-zA-Z_][a-zA-Z0-9_.]*)\)::([a-zA-Z_][a-zA-Z0-9_ ]*)",
)

# SQL CAST pattern: CAST(column AS type)
_SQL_CAST_PATTERN = re.compile(
    r"CAST\s*\(\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s+AS\s+([a-zA-Z_][a-zA-Z0-9_ ]*)\)",
    re.IGNORECASE,
)

# Function-on-column pattern: function(column)
# Excludes common legitimate aggregates and operators
_FUNC_PATTERN = re.compile(
    r"\b(lower|upper|trim|btrim|ltrim|rtrim|substr|substring|replace|"
    r"to_char|to_date|to_timestamp|to_number|"
    r"date_trunc|date_part|extract|"
    r"abs|round|ceil|floor|trunc|"
    r"length|char_length|octet_length|"
    r"md5|encode|decode|"
    r"coalesce|nullif|greatest|least)\s*\("
    r"([a-zA-Z_][a-zA-Z0-9_.]*)",
    re.IGNORECASE,
)

# Collation annotation: COLLATE "some_collation"
_COLLATION_PATTERN = re.compile(
    r'COLLATE\s+"([^"]+)"',
    re.IGNORECASE,
)

# Common non-default collations that prevent index use for LIKE prefix
_PROBLEMATIC_COLLATIONS = {"en_US.UTF-8", "en_US.utf8", "C.UTF-8"}


class NonSargableFilterConfig(RuleConfig):
    """
    Configuration for non-sargable predicate detection.

    Attributes:
        check_filter: Check Filter conditions (default True).
        check_index_cond: Check Index Cond for casts (default True).
        min_plan_rows: Minimum plan_rows to report (skip tiny tables).
    """

    check_filter: bool = Field(
        default=True,
        description="Detect non-sargable predicates in Filter conditions",
    )
    check_index_cond: bool = Field(
        default=True,
        description="Detect casts in Index Cond expressions",
    )
    min_plan_rows: int = Field(
        default=100,
        ge=0,
        description="Minimum plan_rows to report (skip trivial scans)",
    )


@register_rule
class NonSargableFilter(Rule):
    """
    Detect casts, functions, and collation issues that prevent index usage.

    Scans Filter and Index Cond strings for patterns that make predicates
    non-sargable: implicit casts, function-wrapped columns, and problematic
    collation annotations.
    """

    rule_id = "NON_SARGABLE_FILTER"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects casts and functions on indexed columns preventing index use"
    phase = RulePhase.PER_NODE

    config_schema = NonSargableFilterConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find non-sargable predicates in plan conditions."""
        config: NonSargableFilterConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Check Filter on scan nodes
            if config.check_filter and node.filter and node.is_scan_node:
                if node.plan_rows >= config.min_plan_rows:
                    findings.extend(
                        self._check_condition(
                            node, path, parent, node.filter, "Filter"
                        )
                    )

            # Check Index Cond for casts (index is used but with recheck)
            if config.check_index_cond and node.index_cond:
                if node.plan_rows >= config.min_plan_rows:
                    findings.extend(
                        self._check_condition(
                            node, path, parent, node.index_cond, "Index Cond"
                        )
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
        """Check a single condition string for non-sargable patterns."""
        findings: list[Finding] = []
        context = NodeContext.from_node(node, path, parent)

        # 1. Check for explicit casts: (column)::type
        for match in _CAST_PATTERN.finditer(condition):
            column = match.group(1)
            cast_type = match.group(2).strip()
            findings.append(self._build_cast_finding(
                node, context, column, cast_type, condition_type, condition
            ))

        # 2. Check for SQL CAST syntax: CAST(column AS type)
        for match in _SQL_CAST_PATTERN.finditer(condition):
            column = match.group(1)
            cast_type = match.group(2).strip()
            findings.append(self._build_cast_finding(
                node, context, column, cast_type, condition_type, condition
            ))

        # 3. Check for function-wrapped columns
        for match in _FUNC_PATTERN.finditer(condition):
            func_name = match.group(1)
            column = match.group(2)
            findings.append(self._build_function_finding(
                node, context, func_name, column, condition_type, condition
            ))

        # 4. Check for collation issues (especially with LIKE)
        for match in _COLLATION_PATTERN.finditer(condition):
            collation = match.group(1)
            findings.append(self._build_collation_finding(
                node, context, collation, condition_type, condition
            ))

        return findings

    def _build_cast_finding(
        self,
        node: "PlanNode",
        context: NodeContext,
        column: str,
        cast_type: str,
        condition_type: str,
        full_condition: str,
    ) -> Finding:
        """Build finding for implicit/explicit cast on indexed column."""
        table = node.relation_name or "unknown table"
        is_seq = node.node_type == "Seq Scan"

        if is_seq:
            severity = Severity.WARNING
            impact = ImpactBand.HIGH
            impact_desc = (
                "The cast prevents PostgreSQL from using any index on the "
                "original column type, forcing a sequential scan."
            )
        else:
            severity = Severity.INFO
            impact = ImpactBand.LOW
            impact_desc = (
                "The cast appears in an index condition. PostgreSQL may still "
                "use the index but with reduced efficiency (recheck needed)."
            )

        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=(
                f"Cast on column '{column}'::{cast_type} in {condition_type} "
                f"on {table}"
            ),
            description=(
                f"Column '{column}' is cast to {cast_type} in the "
                f"{condition_type}: {full_condition}\n\n"
                f"{impact_desc}\n\n"
                f"Common source: ORM/query builder type mismatches "
                f"(e.g., jOOQ casting bigint to numeric, Hibernate implicit casts)."
            ),
            suggestion=(
                f"-- Fix the type mismatch at the application layer:\n"
                f"-- 1. Ensure the parameter type matches the column type exactly\n"
                f"-- 2. For ORM-generated SQL, check type mappings\n"
                f"-- 3. If the cast is necessary, add an expression index:\n"
                f"CREATE INDEX ON {table} (({column})::{cast_type});\n"
                f"\n"
                f"-- Verify with: EXPLAIN ANALYZE <query with corrected types>"
            ),
            metrics={
                "column": column,
                "cast_type": cast_type,
                "total_cost": node.total_cost,
            },
            impact_band=impact,
            assumptions=(
                "The cast prevents optimal index usage",
                "Fixing the type at the application layer is preferable to expression indexes",
            ),
            verification_steps=(
                "Test the query with explicit correct-type parameter",
                "Check ORM/driver type mappings for the column",
                "Compare plans with and without the cast",
            ),
        )

    def _build_function_finding(
        self,
        node: "PlanNode",
        context: NodeContext,
        func_name: str,
        column: str,
        condition_type: str,
        full_condition: str,
    ) -> Finding:
        """Build finding for function-wrapped column in condition."""
        table = node.relation_name or "unknown table"

        return Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING,
            context=context,
            title=(
                f"Function {func_name}({column}) in {condition_type} on {table}"
            ),
            description=(
                f"Column '{column}' is wrapped in function '{func_name}()' in "
                f"the {condition_type}: {full_condition}\n\n"
                f"PostgreSQL cannot use a B-tree index on '{column}' when the "
                f"column is wrapped in a function. The planner must evaluate "
                f"the function for every row, preventing index-based filtering."
            ),
            suggestion=(
                f"-- Option 1: Add an expression index:\n"
                f"CREATE INDEX ON {table} ({func_name}({column}));\n"
                f"\n"
                f"-- Option 2: Rewrite the query to avoid the function:\n"
                f"-- For case-insensitive search, use citext type instead of lower()\n"
                f"-- For date_trunc, use range conditions: col >= '...' AND col < '...'\n"
                f"\n"
                f"-- Docs: https://www.postgresql.org/docs/current/indexes-expressional.html"
            ),
            metrics={
                "function": func_name,
                "column": column,
                "total_cost": node.total_cost,
            },
            impact_band=ImpactBand.MEDIUM,
            assumptions=(
                "No expression index exists for the function call",
                "The function application is not needed at the index level",
            ),
            verification_steps=(
                "Check if an expression index already exists",
                "Test with rewritten query to see if plan improves",
                "Verify the function is deterministic (required for expression indexes)",
            ),
        )

    def _build_collation_finding(
        self,
        node: "PlanNode",
        context: NodeContext,
        collation: str,
        condition_type: str,
        full_condition: str,
    ) -> Finding:
        """Build finding for collation annotation in condition."""
        table = node.relation_name or "unknown table"

        return Finding(
            rule_id=self.rule_id,
            severity=Severity.INFO,
            context=context,
            title=(
                f"Collation '{collation}' in {condition_type} on {table}"
            ),
            description=(
                f"Condition uses COLLATE \"{collation}\": {full_condition}\n\n"
                f"Non-C collations can prevent B-tree indexes from being used "
                f"for LIKE prefix searches (e.g., LIKE 'foo%'). PostgreSQL "
                f"cannot assume safe range mapping for arbitrary collations."
            ),
            suggestion=(
                f"-- For LIKE prefix searches with non-C collation:\n"
                f"CREATE INDEX ON {table} (<column> varchar_pattern_ops);\n"
                f"-- Or for text columns:\n"
                f"CREATE INDEX ON {table} (<column> text_pattern_ops);\n"
                f"\n"
                f"-- These operator classes enable LIKE prefix optimization\n"
                f"-- regardless of collation.\n"
                f"\n"
                f"-- Docs: https://www.postgresql.org/docs/current/indexes-opclass.html"
            ),
            metrics={
                "collation": collation,
                "total_cost": node.total_cost,
            },
            impact_band=ImpactBand.LOW,
            assumptions=(
                "Index exists but collation prevents LIKE optimization",
                "Query uses LIKE prefix pattern that could use the index",
            ),
            verification_steps=(
                "Test with text_pattern_ops index",
                "Check if the collation is needed for correctness",
                "Compare plans with and without the operator class index",
            ),
        )
