"""
Knowledge base of PostgreSQL planner quirks and fixes.

Based on pganalyze's "Postgres Planner Quirks" blog series covering
ORDER BY + LIMIT, Incremental Sort, and Presorted Aggregate regressions.

Usage:
    from querysense.planner.quirks_knowledge import PlannerQuirksKB

    kb = PlannerQuirksKB()
    quirk = kb.detect_quirk(plan_dict, sql)
    if quirk:
        print(kb.explain_quirk(quirk))
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class QuirkCategory(Enum):
    ORDER_BY_LIMIT = "order_by_limit"
    INCREMENTAL_SORT = "incremental_sort"
    JSONB_SELECTIVITY = "jsonb_selectivity"
    JOIN_EQUIVALENCE = "join_equivalence"
    CORRELATION = "correlation"
    STATISTICS = "statistics"


@dataclass
class PlannerQuirk:
    """Known PostgreSQL planner quirk."""
    name: str
    category: QuirkCategory
    description: str
    symptoms: List[str]
    root_cause: str
    affected_versions: List[str]
    detection_patterns: List[str]
    fixes: List[Dict[str, str]]
    example_query: Optional[str] = None
    blog_reference: Optional[str] = None


# ── Knowledge Base ───────────────────────────────────────────────────────

_QUIRKS: list[PlannerQuirk] = [
    PlannerQuirk(
        name="ORDER BY + LIMIT Wrong Index",
        category=QuirkCategory.ORDER_BY_LIMIT,
        description=(
            "Postgres chooses the ORDER BY column's index instead of the "
            "WHERE clause index when LIMIT is present"
        ),
        symptoms=[
            "Query slow with ORDER BY + LIMIT",
            "Using primary key index instead of filter column index",
            "High 'Rows Removed by Filter' in Index Scan",
            "Query fast without ORDER BY",
        ],
        root_cause=(
            "Planner optimistically assumes it will find matching rows "
            "quickly in sorted order"
        ),
        affected_versions=["9.6+"],
        detection_patterns=[
            r"Index Scan.*ORDER BY.*LIMIT",
            r"Rows Removed by Filter.*>.*100",
        ],
        fixes=[
            {
                "type": "workaround",
                "description": "Add +0 to ORDER BY column",
                "sql": "ORDER BY column + 0",
            },
            {
                "type": "statistics",
                "description": "Increase statistics target",
                "sql": "ALTER TABLE t ALTER COLUMN col SET STATISTICS 1000;",
            },
            {
                "type": "index",
                "description": "Create composite index",
                "sql": "CREATE INDEX ON t(filter_col, order_col);",
            },
            {
                "type": "session",
                "description": "Disable incremental sort",
                "sql": "SET enable_incremental_sort = off;",
            },
        ],
        example_query=(
            "SELECT * FROM items WHERE object_id = 123 ORDER BY id DESC LIMIT 1;"
        ),
        blog_reference=(
            "https://pganalyze.com/blog/5mins-postgres-113-order-by-limit-index-usage"
        ),
    ),
    PlannerQuirk(
        name="Incremental Sort Misestimate",
        category=QuirkCategory.INCREMENTAL_SORT,
        description=(
            "Incremental Sort chooses wrong index due to group count "
            "misestimate"
        ),
        symptoms=[
            "Slower after upgrading to PG13+",
            "Incremental Sort node in plan",
            "Large difference between estimated and actual groups",
            "Using index for sort instead of filter",
        ],
        root_cause="estimate_num_groups overestimates groups after filtering",
        affected_versions=["13", "14", "15", "16", "17"],
        detection_patterns=[
            r"Incremental Sort",
            r"Presorted Key:",
        ],
        fixes=[
            {
                "type": "session",
                "description": "Disable incremental sort",
                "sql": "SET enable_incremental_sort = off;",
            },
            {
                "type": "statistics",
                "description": "Create extended statistics",
                "sql": "CREATE STATISTICS ON (col1, col2) FROM t;",
            },
            {
                "type": "index",
                "description": "Create composite index",
                "sql": "CREATE INDEX ON t(filter_col, sort_col1, sort_col2);",
            },
        ],
        example_query="SELECT * FROM t WHERE b = 3 ORDER BY c, d LIMIT 10;",
        blog_reference=(
            "https://pganalyze.com/blog/5mins-postgres-120-incremental-sort"
        ),
    ),
    PlannerQuirk(
        name="Presorted Aggregate Slow",
        category=QuirkCategory.INCREMENTAL_SORT,
        description=(
            "array_agg / string_agg with ORDER BY becomes slower in PG16 "
            "due to unnecessary Incremental Sort from presorted aggregate "
            "optimization"
        ),
        symptoms=[
            "Slower after upgrading to PG16",
            "array_agg or string_agg with ORDER BY",
            "Incremental Sort appears in plan",
            "Turning off incremental sort alone doesn't help",
        ],
        root_cause=(
            "Presorted aggregate optimization adds unnecessary sort step"
        ),
        affected_versions=["16", "17"],
        detection_patterns=[
            r"array_agg.*ORDER BY",
            r"GroupAggregate.*Incremental Sort",
            r"Presorted Key:",
        ],
        fixes=[
            {
                "type": "session",
                "description": "Disable presorted aggregate",
                "sql": "SET enable_presorted_aggregate = off;",
            },
            {
                "type": "session",
                "description": "Also disable incremental sort",
                "sql": "SET enable_incremental_sort = off;",
            },
        ],
        example_query=(
            "SELECT a, array_agg(c ORDER BY c) FROM t GROUP BY a;"
        ),
        blog_reference=(
            "https://pganalyze.com/blog/5mins-postgres-120-incremental-sort"
        ),
    ),
    PlannerQuirk(
        name="JSONB Selectivity Flat 0.1%",
        category=QuirkCategory.JSONB_SELECTIVITY,
        description=(
            "Planner always estimates 0.1% selectivity for JSONB @> "
            "containment queries regardless of actual data distribution"
        ),
        symptoms=[
            "Bad row estimate for JSONB @> queries",
            "Nested Loop chosen when Hash Join would be better",
            "Extremely slow JSONB filter queries on large tables",
        ],
        root_cause=(
            "No extended statistics support for JSONB operators; planner "
            "falls back to a hard-coded 0.1% default selectivity"
        ),
        affected_versions=["9.4+"],
        detection_patterns=[
            r"@>",
            r"Rows Removed by Filter.*jsonb",
        ],
        fixes=[
            {
                "type": "workaround",
                "description": "Extract key into a generated column and index it",
                "sql": (
                    "ALTER TABLE t ADD COLUMN key_val text "
                    "GENERATED ALWAYS AS (data->>'key') STORED;\n"
                    "CREATE INDEX ON t(key_val);"
                ),
            },
            {
                "type": "statistics",
                "description": "Increase default_statistics_target for the table",
                "sql": "ALTER TABLE t ALTER COLUMN data SET STATISTICS 1000;",
            },
        ],
        example_query=(
            "SELECT * FROM events WHERE payload @> '{\"type\": \"click\"}';"
        ),
        blog_reference=None,
    ),
]


# ── Public Class ─────────────────────────────────────────────────────────


class PlannerQuirksKB:
    """
    Knowledge base of PostgreSQL planner quirks.
    Detects quirks from EXPLAIN plans and provides fix recommendations.
    """

    QUIRKS = _QUIRKS

    def detect_quirk(
        self, plan: Dict, query: str
    ) -> Optional[PlannerQuirk]:
        """Detect if a plan exhibits a known quirk."""
        plan_text = str(plan)

        for quirk in self.QUIRKS:
            matches = 0
            for pattern in quirk.detection_patterns:
                if re.search(pattern, plan_text, re.IGNORECASE):
                    matches += 1
            if quirk.category == QuirkCategory.ORDER_BY_LIMIT:
                if "ORDER BY" in query.upper() and "LIMIT" in query.upper():
                    matches += 1
            if matches >= 2:
                return quirk
        return None

    def detect_all_quirks(
        self, plan: Dict, query: str
    ) -> List[PlannerQuirk]:
        """Return all matching quirks (not just the first)."""
        plan_text = str(plan)
        found: list[PlannerQuirk] = []

        for quirk in self.QUIRKS:
            matches = 0
            for pattern in quirk.detection_patterns:
                if re.search(pattern, plan_text, re.IGNORECASE):
                    matches += 1
            if quirk.category == QuirkCategory.ORDER_BY_LIMIT:
                if "ORDER BY" in query.upper() and "LIMIT" in query.upper():
                    matches += 1
            if matches >= 2:
                found.append(quirk)
        return found

    def get_fix_recommendations(
        self, quirk: PlannerQuirk, context: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Get context-specific fix recommendations."""
        recs: list[dict[str, str]] = []
        for fix in quirk.fixes:
            rec = dict(fix)
            rec["applicable_versions"] = ", ".join(quirk.affected_versions)

            sql = rec.get("sql", "")
            if "table" in context:
                sql = sql.replace(" t(", f" {context['table']}(")
                sql = sql.replace(" t ", f" {context['table']} ")
            if "columns" in context and len(context["columns"]) >= 2:
                sql = sql.replace("filter_col", context["columns"][0])
                sql = sql.replace("order_col", context["columns"][1])
                sql = sql.replace("sort_col1", context["columns"][1])
            if "column" in context:
                sql = sql.replace(" col ", f" {context['column']} ")
            rec["sql"] = sql
            recs.append(rec)
        return recs

    def explain_quirk(self, quirk: PlannerQuirk) -> str:
        """Generate human-readable explanation."""
        lines = [
            f"## {quirk.name}",
            "",
            f"**Category:** {quirk.category.value}",
            "",
            f"**Description:** {quirk.description}",
            "",
            "**Symptoms:**",
        ]
        for s in quirk.symptoms:
            lines.append(f"- {s}")
        lines.extend([
            "",
            f"**Root Cause:** {quirk.root_cause}",
            "",
            f"**Affected Versions:** {', '.join(quirk.affected_versions)}",
            "",
            "**Fixes:**",
        ])
        for fix in quirk.fixes:
            lines.append(f"- **{fix['type']}:** {fix['description']}")
            lines.append(f"  ```sql\n  {fix['sql']}\n  ```")

        if quirk.example_query:
            lines.extend([
                "",
                "**Example:**",
                f"```sql\n{quirk.example_query}\n```",
            ])
        if quirk.blog_reference:
            lines.extend(["", f"**Reference:** {quirk.blog_reference}"])

        return "\n".join(lines)

    def generate_test_suite(self, version: str) -> List[Dict[str, str]]:
        """Generate test queries to detect quirks for a PG version."""
        tests: list[dict[str, str]] = []

        if version >= "13":
            tests.append({
                "name": "Incremental Sort Misestimate",
                "query": (
                    "CREATE TEMP TABLE inc_sort_test AS\n"
                    "SELECT (i%1000)::int AS a, (i%500)::int AS b, i AS c\n"
                    "FROM generate_series(1,1000000) i;\n"
                    "CREATE INDEX ON inc_sort_test(a);\n"
                    "CREATE INDEX ON inc_sort_test(b);\n"
                    "ANALYZE inc_sort_test;\n"
                    "EXPLAIN (ANALYZE, BUFFERS)\n"
                    "SELECT * FROM inc_sort_test WHERE b=3 ORDER BY a,c LIMIT 10;"
                ),
                "expected_issue": "Index Scan using inc_sort_test_b_idx",
            })

        if version >= "16":
            tests.append({
                "name": "Presorted Aggregate Slow",
                "query": (
                    "CREATE TEMP TABLE agg_test AS\n"
                    "SELECT (i%100)::int AS a, i AS b, (i%300)::text AS c\n"
                    "FROM generate_series(1,100000) i;\n"
                    "CREATE INDEX ON agg_test(a, b);\n"
                    "ANALYZE agg_test;\n"
                    "EXPLAIN (ANALYZE, BUFFERS)\n"
                    "SELECT a, array_agg(c ORDER BY c) FROM agg_test GROUP BY a;"
                ),
                "expected_issue": "GroupAggregate.*Incremental Sort",
            })

        tests.append({
            "name": "ORDER BY + LIMIT Wrong Index",
            "query": (
                "CREATE TEMP TABLE order_limit_test (\n"
                "  id SERIAL PRIMARY KEY, filter_col int, data text\n"
                ");\n"
                "INSERT INTO order_limit_test (filter_col, data)\n"
                "SELECT (random()*100)::int, 'data_' || i\n"
                "FROM generate_series(1,100000) i;\n"
                "CREATE INDEX ON order_limit_test(filter_col);\n"
                "ANALYZE order_limit_test;\n"
                "EXPLAIN (ANALYZE, BUFFERS)\n"
                "SELECT * FROM order_limit_test\n"
                "WHERE filter_col = 50 ORDER BY id LIMIT 10;"
            ),
            "expected_issue": "Index Scan using order_limit_test_pkey",
        })

        return tests

    def list_quirks(self) -> List[Dict[str, str]]:
        """Return a summary of all known quirks."""
        return [
            {
                "name": q.name,
                "category": q.category.value,
                "versions": ", ".join(q.affected_versions),
                "description": q.description,
            }
            for q in self.QUIRKS
        ]
