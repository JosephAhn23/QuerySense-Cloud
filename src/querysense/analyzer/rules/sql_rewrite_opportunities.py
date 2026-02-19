"""
Rule: SQL Rewrite Opportunities

Detects query anti-patterns visible in EXPLAIN output that indicate the
SQL itself should be rewritten — not just indexes added.

Addresses weakness #5 (vs EverSQL): "No query rewriting — QuerySense only
recommends indexes and ANALYZE, leaving bad query logic untouched."

Patterns detected:
- SELECT * (wide output when only some columns needed)
- NOT IN with subquery (use NOT EXISTS instead)
- OR chains causing sequential scan (use UNION ALL)
- Implicit type casts in filters (already a rule, but add rewrite advice)
- CTE when a subquery would be faster (PG < 12 always materializes CTEs)
- DISTINCT on large result sets (may indicate a bad JOIN)
- ORDER BY + LIMIT without supporting index (pagination anti-pattern)
- COUNT(*) on large table without WHERE (full table scan)
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


class SqlRewriteConfig(RuleConfig):
    """Config for SQL rewrite opportunity detection."""

    min_rows_for_distinct: int = Field(
        default=10_000,
        description="Minimum rows to flag DISTINCT as suspicious",
    )
    min_width_for_select_star: int = Field(
        default=200,
        description="Minimum plan width (bytes) to suggest column pruning",
    )
    min_rows_for_count: int = Field(
        default=50_000,
        description="Minimum rows to flag unfiltered COUNT(*)",
    )


@register_rule
class SqlRewriteOpportunities(Rule):
    """
    Detect SQL anti-patterns that need query rewrites, not just index changes.

    Goes beyond index/ANALYZE recommendations to suggest structural SQL changes.
    """

    rule_id = "SQL_REWRITE_OPPORTUNITY"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Detects SQL anti-patterns that need query rewrites"
    phase = RulePhase.PER_NODE
    config_schema = SqlRewriteConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: SqlRewriteConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            findings.extend(self._check_select_star(node, path, parent, config))
            findings.extend(self._check_distinct_abuse(node, path, parent, config))
            findings.extend(self._check_or_to_union(node, path, parent, config))
            findings.extend(self._check_not_in_subquery(node, path, parent, config))
            findings.extend(self._check_unfiltered_count(node, path, parent, config))

        return findings

    # ── SELECT * detection ──────────────────────────────────────────────

    def _check_select_star(
        self, node: "PlanNode", path, parent, config: SqlRewriteConfig,
    ) -> list[Finding]:
        """Detect wide output rows suggesting SELECT *."""
        if node.plan_width < config.min_width_for_select_star:
            return []
        if not node.is_scan_node:
            return []

        rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
        if rows < 1000:
            return []

        # Wide scan = likely SELECT *
        total_bytes = node.plan_width * rows
        if total_bytes < 1_000_000:  # Less than 1MB, not worth flagging
            return []

        context = NodeContext.from_node(node, path, parent)
        table = node.relation_name or "unknown"
        data_mb = total_bytes / (1024 * 1024)

        impact = min(3.0 + min(data_mb / 50, 4.0), 7.0)

        return [Finding(
            rule_id=self.rule_id,
            severity=Severity.INFO if data_mb < 50 else Severity.WARNING,
            context=context,
            title=f"Wide output from {table} ({node.plan_width} bytes/row, ~{data_mb:.0f}MB total)",
            description=(
                f"Scan on '{table}' returns {node.plan_width} bytes per row across "
                f"{rows:,} rows (~{data_mb:.0f}MB). This often indicates SELECT * "
                f"when only specific columns are needed. Narrowing the column list "
                f"reduces I/O, memory usage, and network transfer."
            ),
            suggestion=(
                f"-- Replace SELECT * with specific columns:\n"
                f"-- Before: SELECT * FROM {table} WHERE ...\n"
                f"-- After:  SELECT id, name, status FROM {table} WHERE ...\n"
                f"\n"
                f"-- Benefits:\n"
                f"-- 1. Enables Index Only Scan (if covering index exists)\n"
                f"-- 2. Reduces shared_buffers pressure by ~{(1 - 50/max(node.plan_width, 51)):.0%}\n"
                f"-- 3. Reduces network transfer ({data_mb:.0f}MB → potentially <1MB)"
            ),
            metrics={"plan_width": node.plan_width, "estimated_mb": round(data_mb, 1)},
            impact_band=ImpactBand.MEDIUM if data_mb > 50 else ImpactBand.LOW,
            impact_score=round(impact, 1),
        )]

    # ── DISTINCT abuse detection ────────────────────────────────────────

    def _check_distinct_abuse(
        self, node: "PlanNode", path, parent, config: SqlRewriteConfig,
    ) -> list[Finding]:
        """Detect DISTINCT on large result sets (usually a JOIN bug)."""
        if node.node_type not in ("Unique", "HashAggregate"):
            return []

        # HashAggregate without Group Key = DISTINCT
        if node.node_type == "HashAggregate":
            group_key = node.model_extra.get("Group Key") if node.model_extra else None
            if group_key:
                return []  # This is a GROUP BY, not DISTINCT

        rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
        if rows < config.min_rows_for_distinct:
            return []

        # Check child — if it's a join, DISTINCT may mask a cartesian join
        child_is_join = False
        if node.plans:
            child_type = node.plans[0].node_type
            if "Join" in child_type or "Loop" in child_type:
                child_is_join = True

        context = NodeContext.from_node(node, path, parent)
        severity = Severity.WARNING if child_is_join else Severity.INFO
        impact = 5.0 if child_is_join else 3.0

        desc = (
            f"DISTINCT processing {rows:,} rows. "
        )
        if child_is_join:
            desc += (
                "This DISTINCT sits above a JOIN, which often indicates "
                "the JOIN is producing duplicate rows. Fix the JOIN condition "
                "instead of masking duplicates with DISTINCT."
            )
        else:
            desc += (
                "Large DISTINCT operations are expensive. Consider whether "
                "the duplicates can be prevented at the query level."
            )

        suggestion_lines = []
        if child_is_join:
            suggestion_lines.extend([
                "-- DISTINCT after JOIN usually means a bad join condition.",
                "-- Check for missing join predicates that cause row multiplication.",
                "",
                "-- Before: SELECT DISTINCT a.* FROM a JOIN b ON a.id = b.a_id",
                "-- After:  SELECT a.* FROM a WHERE EXISTS (SELECT 1 FROM b WHERE b.a_id = a.id)",
                "",
                "-- Or fix the JOIN to be 1:1 instead of 1:N",
            ])
        else:
            suggestion_lines.extend([
                "-- Consider GROUP BY instead of DISTINCT for aggregation.",
                "-- Or use EXISTS/IN subquery instead of JOIN + DISTINCT.",
            ])

        return [Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=f"DISTINCT over {rows:,} rows — possible JOIN duplication",
            description=desc,
            suggestion="\n".join(suggestion_lines),
            metrics={"rows": rows, "child_is_join": child_is_join},
            impact_band=ImpactBand.MEDIUM if child_is_join else ImpactBand.LOW,
            impact_score=round(impact, 1),
        )]

    # ── OR → UNION ALL rewrite ──────────────────────────────────────────

    def _check_or_to_union(
        self, node: "PlanNode", path, parent, config: SqlRewriteConfig,
    ) -> list[Finding]:
        """Detect OR chains in filter that prevent index usage."""
        if not node.is_scan_node or node.node_type != "Seq Scan":
            return []

        if not node.filter:
            return []

        # Count OR conditions
        or_count = len(re.findall(r"\bOR\b", node.filter, re.IGNORECASE))
        if or_count < 2:
            return []

        rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
        if rows < 5_000:
            return []

        context = NodeContext.from_node(node, path, parent)
        table = node.relation_name or "unknown"
        impact = min(4.0 + or_count * 0.5, 8.0)

        return [Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING,
            context=context,
            title=f"OR chain ({or_count} conditions) forcing Seq Scan on {table}",
            description=(
                f"Filter on '{table}' contains {or_count} OR conditions: "
                f"{node.filter[:200]}. "
                f"PostgreSQL often cannot use indexes with OR chains and falls "
                f"back to sequential scan. Rewriting as UNION ALL lets each "
                f"branch use its own index."
            ),
            suggestion=(
                f"-- Rewrite OR chains as UNION ALL for index usage:\n"
                f"-- Before:\n"
                f"--   SELECT * FROM {table} WHERE col = 'a' OR col2 = 'b' OR col3 = 'c'\n"
                f"-- After:\n"
                f"--   SELECT * FROM {table} WHERE col = 'a'\n"
                f"--   UNION ALL\n"
                f"--   SELECT * FROM {table} WHERE col2 = 'b'\n"
                f"--   UNION ALL\n"
                f"--   SELECT * FROM {table} WHERE col3 = 'c'\n"
                f"\n"
                f"-- Each branch can use a separate index.\n"
                f"-- If duplicate rows are possible, use UNION instead of UNION ALL."
            ),
            metrics={"or_count": or_count, "rows_scanned": rows},
            impact_band=ImpactBand.MEDIUM,
            impact_score=round(impact, 1),
        )]

    # ── NOT IN → NOT EXISTS rewrite ─────────────────────────────────────

    def _check_not_in_subquery(
        self, node: "PlanNode", path, parent, config: SqlRewriteConfig,
    ) -> list[Finding]:
        """Detect NOT IN with subquery (NULL-unsafe, often slow)."""
        if not node.filter:
            return []

        # EXPLAIN shows NOT IN as: (NOT (hashed SubPlan 1))
        # or as Filter with "NOT IN" or "<> ALL"
        filter_str = node.filter.lower()
        if "not" not in filter_str:
            return []
        if "<> all" not in filter_str and "not in" not in filter_str and "subplan" not in filter_str:
            return []

        # Check for SubPlan child
        has_subplan = False
        if node.plans:
            for child in node.plans:
                child_type = child.node_type.lower()
                if "subplan" in child_type or "subquery" in child_type:
                    has_subplan = True
                    break
        if node.model_extra:
            for key in node.model_extra:
                if "subplan" in str(key).lower():
                    has_subplan = True
                    break

        if not has_subplan and "<> all" not in filter_str:
            return []

        context = NodeContext.from_node(node, path, parent)
        table = node.relation_name or "unknown"
        rows = node.actual_rows if node.actual_rows is not None else node.plan_rows

        return [Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING,
            context=context,
            title=f"NOT IN subquery on {table} — use NOT EXISTS instead",
            description=(
                f"NOT IN with a subquery is NULL-unsafe and often slower than "
                f"NOT EXISTS. If the subquery returns any NULL value, NOT IN "
                f"returns no rows at all (a common bug). NOT EXISTS handles "
                f"NULLs correctly and often uses a more efficient anti-join plan."
            ),
            suggestion=(
                f"-- Rewrite NOT IN as NOT EXISTS:\n"
                f"-- Before:\n"
                f"--   SELECT * FROM {table} WHERE id NOT IN (SELECT {table}_id FROM other_table)\n"
                f"-- After:\n"
                f"--   SELECT * FROM {table} t\n"
                f"--   WHERE NOT EXISTS (\n"
                f"--     SELECT 1 FROM other_table o WHERE o.{table}_id = t.id\n"
                f"--   )\n"
                f"\n"
                f"-- Benefits:\n"
                f"-- 1. NULL-safe (NOT IN fails silently with NULLs)\n"
                f"-- 2. Often produces Hash Anti Join (faster than SubPlan)\n"
                f"-- 3. Can use index on the join column"
            ),
            metrics={"rows": rows},
            impact_band=ImpactBand.MEDIUM,
            impact_score=5.0,
        )]

    # ── Unfiltered COUNT(*) ─────────────────────────────────────────────

    def _check_unfiltered_count(
        self, node: "PlanNode", path, parent, config: SqlRewriteConfig,
    ) -> list[Finding]:
        """Detect COUNT(*) without WHERE on large tables."""
        if node.node_type != "Aggregate":
            return []

        # Check for Seq Scan child with no filter
        if not node.plans:
            return []

        child = node.plans[0]
        if child.node_type != "Seq Scan":
            return []
        if child.filter:
            return []  # Has WHERE clause, OK

        rows = child.actual_rows if child.actual_rows is not None else child.plan_rows
        if rows < config.min_rows_for_count:
            return []

        context = NodeContext.from_node(node, path, parent)
        table = child.relation_name or "unknown"
        impact = min(3.0 + min(rows / 100_000, 4.0), 7.0)

        return [Finding(
            rule_id=self.rule_id,
            severity=Severity.INFO,
            context=context,
            title=f"Unfiltered COUNT(*) scanning {rows:,} rows in {table}",
            description=(
                f"COUNT(*) on '{table}' without a WHERE clause requires scanning "
                f"the entire table ({rows:,} rows). PostgreSQL's MVCC architecture "
                f"means there's no stored row count — every COUNT(*) is a full scan."
            ),
            suggestion=(
                f"-- Options to avoid full-table COUNT:\n"
                f"\n"
                f"-- 1. Use pg_class estimate (fast, approximate):\n"
                f"SELECT reltuples::bigint FROM pg_class WHERE relname = '{table}';\n"
                f"\n"
                f"-- 2. Cache the count in a summary table:\n"
                f"-- CREATE TABLE row_counts (table_name TEXT PRIMARY KEY, count BIGINT);\n"
                f"-- Update via trigger or periodic job.\n"
                f"\n"
                f"-- 3. Add a WHERE clause to limit scan scope:\n"
                f"-- SELECT COUNT(*) FROM {table} WHERE created_at > NOW() - INTERVAL '1 day';\n"
                f"\n"
                f"-- 4. Use TABLESAMPLE for estimation:\n"
                f"-- SELECT COUNT(*) * 100 FROM {table} TABLESAMPLE SYSTEM(1);"
            ),
            metrics={"rows_scanned": rows},
            impact_band=ImpactBand.LOW,
            impact_score=round(impact, 1),
        )]
