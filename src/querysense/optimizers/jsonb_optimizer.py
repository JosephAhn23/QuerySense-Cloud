"""
JSONB Query Optimizer & Statistics Advisor.

Based on pganalyze blog articles:
  - "Postgres Planner Quirks: How to fix bad JSONB selectivity estimates" (E115)
  - "Postgres performance cliffs with large JSONB values and TOAST" (E3)
  - "Performance implications of medium size values and TOAST" (E89)

Key insight: PostgreSQL uses a hardcoded selectivity estimate (contsel = 0.1%)
for the @> contains operator on JSONB columns.  This causes the planner to
severely underestimate the number of matching rows, leading to nested-loop
plans when hash/merge joins would be far faster.

Fix strategies:
  1. Rewrite @> to ->> equality (uses B-tree stats, not GIN contsel)
  2. Create extended statistics on JSONB expressions (PG14+)
  3. Add expression indexes for B-tree access

Usage:
    from querysense.optimizers.jsonb_optimizer import JSONBOptimizer

    opt = JSONBOptimizer()
    issues = opt.analyze_query(
        "SELECT * FROM events WHERE data @> '{\"type\": \"click\"}'",
        plan=plan_dict,
    )
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


# PostgreSQL's hardcoded contsel value for @> on JSONB
PG_CONTSEL_FALLBACK = 0.001  # 0.1 %


@dataclass(frozen=True)
class JSONBField:
    """JSONB field reference extracted from a query."""
    column: str
    field_path: tuple[str, ...]
    operator: str  # '->>', '->', '@>', '?', '?|', '?&'
    comparison_value: Any = None
    comparison_operator: str = ""  # '=', '>', '<', etc.


@dataclass(frozen=True)
class JSONBOptimization:
    """A single JSONB optimization recommendation."""
    query_pattern: str
    issue_type: str  # 'contains_selectivity', 'missing_statistics', 'expression_index'
    description: str
    severity: str  # 'critical', 'warning', 'info'
    estimated_improvement_pct: float
    fix_sql: tuple[str, ...]
    alternatives: tuple[str, ...]


@dataclass(frozen=True)
class JSONBStatistics:
    """Statistics snapshot for a JSONB column."""
    column: str
    table: str
    null_frac: float
    n_distinct: float
    most_common_vals: tuple[Any, ...] = ()
    most_common_freqs: tuple[float, ...] = ()
    has_extended_stats: bool = False


class JSONBOptimizer:
    """
    Analyze JSONB queries for selectivity estimation problems and
    recommend index, statistics, or rewrite fixes.
    """

    _EXTRACT_RE = re.compile(
        r"(\w+)\s*->>?\s*'([^']+)'",
        re.IGNORECASE,
    )
    _CONTAINS_RE = re.compile(
        r"(\w+)\s*@>\s*'(\{[^}]+\})'",
        re.IGNORECASE,
    )
    _HAS_KEY_RE = re.compile(
        r"(\w+)\s*\?\s*'([^']+)'",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self._contsel_detected = False

    @property
    def contsel_detected(self) -> bool:
        return self._contsel_detected

    def analyze_query(
        self,
        query: str,
        plan: dict[str, Any] | None = None,
    ) -> list[JSONBOptimization]:
        """Return optimization recommendations for a JSONB query."""
        fields = self.extract_jsonb_fields(query)
        if not fields:
            return []

        optimizations: list[JSONBOptimization] = []

        for fld in fields:
            if fld.operator == "@>":
                if opt := self._check_contains_selectivity(fld, plan):
                    optimizations.append(opt)
            elif fld.operator in ("->>", "->"):
                if opt := self._check_field_extraction(fld, query):
                    optimizations.append(opt)
            elif fld.operator in ("?", "?|", "?&"):
                if opt := self._check_has_key(fld):
                    optimizations.append(opt)

        if self._contsel_detected:
            if opt := self._recommend_extended_statistics(fields):
                optimizations.append(opt)

        return optimizations

    def extract_jsonb_fields(self, query: str) -> list[JSONBField]:
        """Extract all JSONB field references from *query*."""
        fields: list[JSONBField] = []

        for m in self._EXTRACT_RE.finditer(query):
            fields.append(JSONBField(
                column=m.group(1),
                field_path=(m.group(2),),
                operator="->>" if "->>" in m.group(0) else "->",
            ))

        for m in self._CONTAINS_RE.finditer(query):
            try:
                obj = json.loads(m.group(2).replace("'", '"'))
                for key, val in obj.items():
                    fields.append(JSONBField(
                        column=m.group(1),
                        field_path=(key,),
                        operator="@>",
                        comparison_value=val,
                        comparison_operator="=",
                    ))
            except (json.JSONDecodeError, ValueError):
                fields.append(JSONBField(
                    column=m.group(1),
                    field_path=(),
                    operator="@>",
                ))

        for m in self._HAS_KEY_RE.finditer(query):
            fields.append(JSONBField(
                column=m.group(1),
                field_path=(m.group(2),),
                operator="?",
            ))

        return fields

    def suggest_rewrite(self, query: str) -> dict[str, Any]:
        """Suggest rewriting @> to ->> equality for better plan estimates."""
        suggestions: list[dict[str, str]] = []

        if "@>" in query:
            suggestions.append({
                "type": "rewrite_contains_to_equality",
                "from": "@> (contains operator — uses contsel 0.1%)",
                "to": "->> (field extraction — uses real column statistics)",
                "benefit": "Uses B-tree index and histogram stats instead of GIN contsel fallback",
            })

        if "@>" in query and " OR " in query.upper():
            suggestions.append({
                "type": "union_rewrite",
                "from": "Multiple @> OR conditions",
                "to": "UNION ALL of individual conditions",
                "benefit": "Better plan stability — each branch optimised independently",
            })

        return {
            "query_length": len(query),
            "has_contains_operator": "@>" in query,
            "has_field_extraction": "->>" in query,
            "recommends_extended_stats": "@>" in query or "->>" in query,
            "suggestions": suggestions,
        }

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_contains_selectivity(
        self,
        fld: JSONBField,
        plan: dict[str, Any] | None,
    ) -> JSONBOptimization | None:
        if plan:
            est = self._first_rows(plan, "Plan Rows")
            act = self._first_rows(plan, "Actual Rows")
            if est is not None and act is not None and act > 0:
                ratio = est / act
                if ratio > 100 or ratio < 0.01:
                    self._contsel_detected = True
                    factor = max(ratio, 1 / ratio)
                    path_str = ".".join(fld.field_path) if fld.field_path else fld.column
                    return JSONBOptimization(
                        query_pattern=f"{fld.column} @> '{{...{path_str}...}}'",
                        issue_type="contains_selectivity",
                        description=(
                            f"PostgreSQL used hardcoded 0.1% selectivity "
                            f"(off by {factor:.0f}x). Rewrite to ->> equality "
                            f"or add extended statistics."
                        ),
                        severity="critical" if factor > 1000 else "warning",
                        estimated_improvement_pct=min(99, (1 - 1 / factor) * 100),
                        fix_sql=(
                            f"-- Rewrite contains to equality:",
                            f"WHERE {fld.column} ->> '{path_str}' = '{fld.comparison_value}';",
                            "",
                            f"-- Or create extended statistics (PG14+):",
                            f"CREATE STATISTICS IF NOT EXISTS stats_{fld.column}_{path_str}",
                            f"  ON (({fld.column} ->> '{path_str}'))",
                            f"  FROM <table_name>;",
                            "ANALYZE <table_name>;",
                        ),
                        alternatives=(
                            "Use GIN index with jsonb_path_ops for contains queries",
                            "Increase default_statistics_target for better sampling",
                        ),
                    )

        path_str = ".".join(fld.field_path) if fld.field_path else fld.column
        return JSONBOptimization(
            query_pattern=f"{fld.column} @> ...",
            issue_type="contains_selectivity",
            description=(
                "The @> operator uses a hardcoded 0.1% selectivity estimate. "
                "This often causes severe row-count misestimates."
            ),
            severity="warning",
            estimated_improvement_pct=50.0,
            fix_sql=(
                f"WHERE {fld.column} ->> '{path_str}' = '<value>';",
            ),
            alternatives=(
                "Run EXPLAIN ANALYZE to measure actual vs estimated rows",
            ),
        )

    def _check_field_extraction(
        self,
        fld: JSONBField,
        query: str,
    ) -> JSONBOptimization | None:
        if "=" not in query:
            return None

        path = fld.field_path[0] if fld.field_path else "key"
        return JSONBOptimization(
            query_pattern=f"{fld.column} ->> '{path}' = ...",
            issue_type="expression_index",
            description=(
                "JSONB field extraction without an expression index or "
                "extended statistics may cause planner misestimates."
            ),
            severity="info",
            estimated_improvement_pct=40.0,
            fix_sql=(
                f"CREATE INDEX CONCURRENTLY idx_{fld.column}_{path}",
                f"  ON <table_name> (({fld.column} ->> '{path}'));",
                "",
                f"CREATE STATISTICS IF NOT EXISTS stats_{fld.column}_{path}",
                f"  ON (({fld.column} ->> '{path}'))",
                f"  FROM <table_name>;",
                "ANALYZE <table_name>;",
            ),
            alternatives=(
                "Ensure statistics target >= 1000 for the expression",
                "Consider normalizing the field into a regular column",
            ),
        )

    def _check_has_key(self, fld: JSONBField) -> JSONBOptimization | None:
        key = fld.field_path[0] if fld.field_path else "key"
        return JSONBOptimization(
            query_pattern=f"{fld.column} ? '{key}'",
            issue_type="has_key_index",
            description=(
                "The ? (has-key) operator benefits from a GIN index "
                "with the default jsonb_ops class."
            ),
            severity="info",
            estimated_improvement_pct=30.0,
            fix_sql=(
                f"CREATE INDEX CONCURRENTLY idx_{fld.column}_gin",
                f"  ON <table_name> USING GIN ({fld.column});",
            ),
            alternatives=(
                "Use jsonb_path_ops if you only need @> queries (smaller index)",
            ),
        )

    def _recommend_extended_statistics(
        self,
        fields: list[JSONBField],
    ) -> JSONBOptimization | None:
        if not fields:
            return None
        paths = [
            f.field_path[0]
            for f in fields
            if f.field_path
        ]
        if not paths:
            return None

        col = fields[0].column
        expr_list = ", ".join(
            f"({col} ->> '{p}')" for p in paths
        )
        return JSONBOptimization(
            query_pattern="JSONB query with poor estimates",
            issue_type="missing_statistics",
            description=(
                "Extended statistics on JSONB expressions improve the "
                "planner's row-count estimates (PG14+ required)."
            ),
            severity="info",
            estimated_improvement_pct=30.0,
            fix_sql=(
                "CREATE STATISTICS IF NOT EXISTS stats_jsonb_exprs",
                f"  ON {expr_list}",
                "  FROM <table_name>;",
                "ANALYZE <table_name>;",
            ),
            alternatives=(
                "Requires PostgreSQL 14+ for expression statistics",
                "Functional indexes also help the planner",
            ),
        )

    @staticmethod
    def _first_rows(plan: dict[str, Any], key: str) -> float | None:
        if key in plan:
            return float(plan[key])
        for child in plan.get("Plans", []):
            val = JSONBOptimizer._first_rows(child, key)
            if val is not None:
                return val
        return None


def generate_jsonb_statistics_sql(
    table: str,
    column: str,
    paths: list[str],
) -> str:
    """Generate CREATE STATISTICS SQL for common JSONB paths."""
    lines: list[str] = []
    for path in paths:
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", path)
        lines.append(
            f"CREATE STATISTICS IF NOT EXISTS stats_{table}_{safe}\n"
            f"  ON (({column} ->> '{path}'))\n"
            f"  FROM {table};"
        )
    lines.append(f"\nANALYZE {table};")
    return "\n\n".join(lines)
