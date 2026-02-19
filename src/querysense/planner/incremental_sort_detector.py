"""
Incremental Sort Detector & Optimizer.

Detects problematic Incremental Sort usage in PostgreSQL query plans.
Based on pganalyze blog: Postgres Planner Quirks — Incremental Sort.

Key problems identified:
1. Correlated column misestimates causing bad Incremental Sort choices
2. ORDER BY + LIMIT selecting the wrong index (using IS instead of direct scan)
3. Presorted aggregate (PG16+) regressions with array_agg/string_agg
4. High group count misestimates in estimate_num_groups

Usage:
    from querysense.planner.incremental_sort_detector import IncrementalSortDetector
    detector = IncrementalSortDetector()
    issues = detector.analyze_plan(plan_dict, query_text)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class SortIssueType(Enum):
    INCREMENTAL_SORT_MISUSE = "incremental_sort_misuse"
    ORDER_BY_LIMIT_WRONG_INDEX = "order_by_limit_wrong_index"
    PRESORTED_AGGREGATE_SLOW = "presorted_aggregate_slow"
    CORRELATED_COLUMNS_MISESTIMATE = "correlated_columns_misestimate"


@dataclass
class SortIssue:
    """Detected sort-related performance issue."""
    issue_type: SortIssueType
    severity: str  # CRITICAL, WARNING, INFO
    description: str
    table: str
    sort_key: list[str]
    estimated_groups: int
    actual_groups: int
    misestimate_factor: float
    execution_time_ms: float
    suggested_fixes: list[str]
    postgres_version_range: str = "13+"


@dataclass
class IncrementalSortReport:
    """Full report from Incremental Sort analysis."""
    issues: list[SortIssue] = field(default_factory=list)
    incremental_sort_nodes: int = 0
    total_sort_nodes: int = 0
    fix_recommendations: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_issues(self) -> bool:
        return len(self.issues) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "issues": [
                {
                    "type": i.issue_type.value,
                    "severity": i.severity,
                    "description": i.description,
                    "table": i.table,
                    "sort_key": i.sort_key,
                    "misestimate_factor": i.misestimate_factor,
                    "execution_time_ms": i.execution_time_ms,
                    "fixes": i.suggested_fixes,
                }
                for i in self.issues
            ],
            "incremental_sort_nodes": self.incremental_sort_nodes,
            "fix_recommendations": self.fix_recommendations,
        }


class IncrementalSortDetector:
    """
    Detect problematic Incremental Sort usage in EXPLAIN plans.

    Incremental Sort (PG13+) sorts data in groups using a presorted key
    prefix. When the planner misestimates the number of groups, performance
    can degrade catastrophically — sometimes 100x slower than a full sort.

    This detector identifies three main problem patterns:
    1. Correlated columns causing group count misestimates
    2. ORDER BY + LIMIT choosing IS over a direct index scan
    3. Presorted aggregate (PG16+) unnecessary sort overhead
    """

    MISESTIMATE_WARNING = 10
    MISESTIMATE_CRITICAL = 100
    FILTER_RATIO_THRESHOLD = 100  # rows_removed / rows_returned

    def analyze_plan(
        self,
        plan: dict[str, Any],
        query: str = "",
    ) -> IncrementalSortReport:
        """Analyze EXPLAIN plan for Incremental Sort issues."""
        # Unwrap outer list/Plan wrapper
        root = plan
        if isinstance(plan, list):
            root = plan[0]
        if "Plan" in root:
            root = root["Plan"]

        report = IncrementalSortReport()

        inc_sort_nodes = self._find_nodes(root, "Incremental Sort")
        all_sort_nodes = (
            self._find_nodes(root, "Sort")
            + self._find_nodes(root, "Incremental Sort")
        )
        report.incremental_sort_nodes = len(inc_sort_nodes)
        report.total_sort_nodes = len(all_sort_nodes)

        for node in inc_sort_nodes:
            issue = self._analyze_incremental_sort_node(node, root, query)
            if issue:
                report.issues.append(issue)

        order_issue = self._check_order_by_limit_pattern(root, query)
        if order_issue:
            report.issues.append(order_issue)

        agg_issue = self._check_presorted_aggregate(root, query)
        if agg_issue:
            report.issues.append(agg_issue)

        report.fix_recommendations = self._generate_fix_recommendations(report.issues, root)
        return report

    # ── Node finding ─────────────────────────────────────────────────

    def _find_nodes(
        self, plan: dict[str, Any], node_type: str,
    ) -> list[dict[str, Any]]:
        nodes: list[dict[str, Any]] = []
        if plan.get("Node Type") == node_type:
            nodes.append(plan)
        for child in plan.get("Plans", []):
            nodes.extend(self._find_nodes(child, node_type))
        return nodes

    # ── Core analysis ────────────────────────────────────────────────

    def _analyze_incremental_sort_node(
        self,
        node: dict[str, Any],
        full_plan: dict[str, Any],
        query: str,
    ) -> SortIssue | None:
        """
        Check if an Incremental Sort node has a group count misestimate.

        When estimate_num_groups is wrong (correlated columns, skewed data),
        Incremental Sort allocates wrong-sized sort batches and thrashes.
        """
        sort_key = node.get("Sort Key", [])
        if not sort_key:
            return None

        actual_rows = node.get("Actual Rows", 0)
        planned_rows = node.get("Plan Rows", 1)
        if planned_rows <= 0:
            planned_rows = 1

        misestimate = actual_rows / planned_rows

        if misestimate <= self.MISESTIMATE_WARNING and misestimate >= (1 / self.MISESTIMATE_WARNING):
            return None

        correlated = self._has_correlated_columns(full_plan)
        table = self._extract_table(full_plan)

        fixes: list[str] = []
        if correlated:
            fixes.append(
                f"CREATE STATISTICS ON ({', '.join(sort_key[:3])}) FROM {table};"
            )
        fixes.append("SET enable_incremental_sort = off;  -- test if this helps")

        better_index = self._suggest_where_index(full_plan, query, table)
        if better_index:
            fixes.insert(0, better_index)

        severity = (
            "CRITICAL" if abs(misestimate) > self.MISESTIMATE_CRITICAL
            else "WARNING"
        )

        return SortIssue(
            issue_type=SortIssueType.INCREMENTAL_SORT_MISUSE,
            severity=severity,
            description=(
                f"Incremental Sort group misestimate: planned {planned_rows}, "
                f"actual {actual_rows} ({misestimate:.1f}x off)"
            ),
            table=table,
            sort_key=sort_key,
            estimated_groups=int(planned_rows),
            actual_groups=int(actual_rows),
            misestimate_factor=round(misestimate, 2),
            execution_time_ms=node.get("Actual Total Time", 0),
            suggested_fixes=fixes,
        )

    def _check_order_by_limit_pattern(
        self,
        plan: dict[str, Any],
        query: str,
    ) -> SortIssue | None:
        """
        Detect ORDER BY + LIMIT + wrong index choice.

        The planner picks an index matching the ORDER BY, then filters rows
        from the scan. If many rows are filtered out, a WHERE-matching index
        with an explicit sort would be faster.
        """
        q = query.upper()
        if "ORDER BY" not in q or "LIMIT" not in q:
            return None

        scan_nodes = (
            self._find_nodes(plan, "Index Scan")
            + self._find_nodes(plan, "Index Only Scan")
        )

        for scan in scan_nodes:
            rows_removed = scan.get("Rows Removed by Filter", 0)
            rows_returned = scan.get("Actual Rows", 0)

            if rows_returned < 1:
                continue

            ratio = rows_removed / rows_returned
            if ratio > self.FILTER_RATIO_THRESHOLD:
                table = scan.get("Relation Name", self._extract_table(plan))
                return SortIssue(
                    issue_type=SortIssueType.ORDER_BY_LIMIT_WRONG_INDEX,
                    severity="CRITICAL",
                    description=(
                        f"ORDER BY + LIMIT using wrong index: "
                        f"{rows_removed} rows filtered after scan "
                        f"({ratio:.0f}x filter ratio)"
                    ),
                    table=table,
                    sort_key=plan.get("Sort Key", []),
                    estimated_groups=0,
                    actual_groups=0,
                    misestimate_factor=round(ratio, 1),
                    execution_time_ms=plan.get("Actual Total Time", 0),
                    suggested_fixes=[
                        "SET enable_incremental_sort = off;",
                        "Add +0 to ORDER BY column (e.g. ORDER BY col + 0) to discourage wrong index",
                        f"CREATE INDEX ON {table} (<where-columns>) to let planner use filter-first strategy",
                    ],
                    postgres_version_range="13-17",
                )

        return None

    def _check_presorted_aggregate(
        self,
        plan: dict[str, Any],
        query: str,
    ) -> SortIssue | None:
        """
        Detect presorted aggregate (PG16+) causing unnecessary overhead.

        array_agg(...ORDER BY ...) combined with GROUP BY can trigger
        Incremental Sort → GroupAggregate when HashAggregate would be faster.
        """
        group_aggs = self._find_nodes(plan, "GroupAggregate")
        inc_sorts = self._find_nodes(plan, "Incremental Sort")

        if not group_aggs or not inc_sorts:
            return None

        q = query.lower()
        has_ordered_agg = any(
            fn in q for fn in ("array_agg", "string_agg", "xmlagg", "json_agg")
        ) and "order by" in q

        if not has_ordered_agg:
            return None

        table = self._extract_table(plan)
        return SortIssue(
            issue_type=SortIssueType.PRESORTED_AGGREGATE_SLOW,
            severity="WARNING",
            description="Presorted aggregate with Incremental Sort causing unnecessary overhead",
            table=table,
            sort_key=plan.get("Sort Key", []),
            estimated_groups=0,
            actual_groups=0,
            misestimate_factor=0,
            execution_time_ms=plan.get("Actual Total Time", 0),
            suggested_fixes=[
                "SET enable_presorted_aggregate = off;  -- PG16+",
                "SET enable_incremental_sort = off;",
                "Add index on GROUP BY columns to avoid sort entirely",
            ],
            postgres_version_range="16+",
        )

    # ── Helpers ──────────────────────────────────────────────────────

    def _has_correlated_columns(self, plan: dict[str, Any]) -> bool:
        """Check if filters involve multiple columns from the same table."""
        table_cols: dict[str, set[str]] = {}

        def _walk(node: dict[str, Any]) -> None:
            for key in ("Filter", "Index Cond", "Recheck Cond"):
                text = node.get(key, "")
                if not text:
                    continue
                cols = re.findall(r"(\w+)\.(\w+)", text)
                for tbl, col in cols:
                    table_cols.setdefault(tbl, set()).add(col)
            for child in node.get("Plans", []):
                _walk(child)

        _walk(plan)
        return any(len(cols) > 1 for cols in table_cols.values())

    def _extract_table(self, plan: dict[str, Any]) -> str:
        if "Relation Name" in plan:
            return plan["Relation Name"]
        for child in plan.get("Plans", []):
            table = self._extract_table(child)
            if table:
                return table
        return "unknown"

    def _suggest_where_index(
        self,
        plan: dict[str, Any],
        query: str,
        table: str,
    ) -> str | None:
        where_match = re.search(
            r"WHERE\s+(.+?)(?=\s+(?:ORDER|GROUP|LIMIT|HAVING|$))",
            query, re.IGNORECASE | re.DOTALL,
        )
        if not where_match:
            return None
        eq_cols = re.findall(r"(\w+)\s*=", where_match.group(1))
        if eq_cols:
            cols = ", ".join(dict.fromkeys(eq_cols))
            return f"CREATE INDEX ON {table} ({cols});"
        return None

    def _generate_fix_recommendations(
        self,
        issues: list[SortIssue],
        plan: dict[str, Any],
    ) -> dict[str, list[str]]:
        if not issues:
            return {}

        fixes: dict[str, list[str]] = {
            "session_level": [],
            "index_recommendations": [],
            "statistics_recommendations": [],
        }

        seen: set[str] = set()
        for issue in issues:
            for fix in issue.suggested_fixes:
                if fix not in seen:
                    seen.add(fix)
                    if fix.startswith("SET "):
                        fixes["session_level"].append(fix)
                    elif fix.startswith("CREATE INDEX"):
                        fixes["index_recommendations"].append(fix)
                    elif fix.startswith("CREATE STATISTICS"):
                        fixes["statistics_recommendations"].append(fix)

        return {k: v for k, v in fixes.items() if v}
