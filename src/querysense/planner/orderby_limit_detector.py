"""
Detect when ORDER BY + LIMIT causes wrong index choice.

Based on pganalyze "Postgres Planner Quirks: ORDER BY + LIMIT impact".
The planner optimistically assumes it will find matching rows quickly
in sorted order, but when selectivity is low, it reads (and discards)
far too many rows.

Usage:
    from querysense.planner.orderby_limit_detector import OrderByLimitDetector

    detector = OrderByLimitDetector()
    issue = detector.analyze_plan(plan_dict, sql)
    if issue:
        print(issue.severity, issue.fix_sql)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class OrderByLimitIssue:
    """Detected ORDER BY + LIMIT performance issue."""
    query: str
    table: str
    filter_column: str
    order_column: str
    index_used: str
    correct_index: Optional[str]
    rows_removed: int
    rows_returned: int
    execution_time_ms: float
    severity: str  # "critical", "warning", "info"
    fix_sql: str
    all_fixes: Dict[str, str]


class OrderByLimitDetector:
    """
    Detects when ORDER BY + LIMIT causes wrong index selection.
    Provides fixes: +0 trick, statistics tuning, composite index.
    """

    _PATTERN = re.compile(
        r"SELECT.*FROM\s+(\w+).*WHERE\s+(\w+)\s*=\s*\S+.*ORDER\s+BY\s+(\w+).*LIMIT",
        re.IGNORECASE | re.DOTALL,
    )

    def analyze_plan(
        self, plan: Dict, query: str
    ) -> Optional[OrderByLimitIssue]:
        if "ORDER BY" not in query.upper() or "LIMIT" not in query.upper():
            return None

        match = self._PATTERN.search(query)
        if not match:
            return None

        table = match.group(1)
        filter_col = match.group(2)
        order_col = match.group(3)

        root = plan.get("Plan", plan)
        for scan in self._find_nodes(root, "Index Scan"):
            index_name = scan.get("Index Name", "")
            if (
                order_col.lower() in index_name.lower()
                and filter_col.lower() not in index_name.lower()
            ):
                rows_removed = scan.get("Rows Removed by Filter", 0)
                rows_returned = scan.get("Actual Rows", 1)

                if rows_removed > rows_returned * 100:
                    correct_index = self._find_correct_index(
                        root, filter_col
                    )
                    severity = (
                        "critical" if rows_removed > 1_000_000 else "warning"
                    )
                    fixes = self._generate_fixes(
                        table, filter_col, order_col, query
                    )

                    return OrderByLimitIssue(
                        query=query,
                        table=table,
                        filter_column=filter_col,
                        order_column=order_col,
                        index_used=index_name,
                        correct_index=correct_index,
                        rows_removed=rows_removed,
                        rows_returned=rows_returned,
                        execution_time_ms=plan.get(
                            "Execution Time",
                            root.get("Actual Total Time", 0),
                        ),
                        severity=severity,
                        fix_sql=fixes["primary"],
                        all_fixes=fixes,
                    )
        return None

    # ------------------------------------------------------------------

    def _find_nodes(self, node: Dict, node_type: str) -> List[Dict]:
        nodes: list[Dict] = []
        if node.get("Node Type") == node_type:
            nodes.append(node)
        for child in node.get("Plans", []):
            nodes.extend(self._find_nodes(child, node_type))
        return nodes

    def _find_correct_index(
        self, root: Dict, filter_col: str
    ) -> Optional[str]:
        for scan in self._find_nodes(root, "Bitmap Index Scan"):
            if filter_col.lower() in scan.get("Index Name", "").lower():
                return scan["Index Name"]
        for scan in self._find_nodes(root, "Index Scan"):
            if filter_col.lower() in scan.get("Index Name", "").lower():
                return scan["Index Name"]
        return None

    def _generate_fixes(
        self,
        table: str,
        filter_col: str,
        order_col: str,
        query: str,
    ) -> Dict[str, str]:
        modified = re.sub(
            rf"ORDER\s+BY\s+{re.escape(order_col)}",
            f"ORDER BY {order_col} + 0",
            query,
            flags=re.IGNORECASE,
        )
        return {
            "primary": modified.strip(),
            "statistics": (
                f"ALTER TABLE {table} ALTER COLUMN {filter_col} SET STATISTICS 1000;\n"
                f"ALTER TABLE {table} ALTER COLUMN {order_col} SET STATISTICS 1000;\n"
                f"ANALYZE {table};\n"
                f"\n"
                f"CREATE STATISTICS {table}_{filter_col}_{order_col}_stats "
                f"ON {filter_col}, {order_col} FROM {table};\n"
                f"ANALYZE {table};"
            ),
            "session": f"SET enable_incremental_sort = off;\n{query}",
            "index": (
                f"CREATE INDEX CONCURRENTLY idx_{table}_{filter_col}_{order_col} "
                f"ON {table}({filter_col}, {order_col});"
            ),
        }

    # ------------------------------------------------------------------

    def estimate_impact(self, issue: OrderByLimitIssue) -> Dict:
        """Estimate speedup from applying fixes (based on pganalyze 155ms->44ms benchmark)."""
        current_ms = issue.execution_time_ms
        if current_ms == 0:
            current_ms = issue.rows_removed / 10_000
        improved_ms = current_ms / 3.5
        return {
            "current_ms": round(current_ms, 2),
            "estimated_ms": round(improved_ms, 2),
            "speedup_factor": round(current_ms / max(improved_ms, 0.1), 1),
            "time_saved_ms": round(current_ms - improved_ms, 2),
            "rows_saved": issue.rows_removed,
            "recommendation": (
                "critical" if issue.rows_removed > 1_000_000 else "recommended"
            ),
        }

    def bulk_detect(
        self, plans: List[Dict], queries: List[str]
    ) -> List[OrderByLimitIssue]:
        """Detect issues across multiple queries, sorted by rows_removed desc."""
        issues: list[OrderByLimitIssue] = []
        for plan, query in zip(plans, queries):
            if issue := self.analyze_plan(plan, query):
                issues.append(issue)
        return sorted(issues, key=lambda x: x.rows_removed, reverse=True)


class OrderByLimitWorkaround:
    """Safe workarounds for ORDER BY + LIMIT planner issues."""

    @staticmethod
    def add_zero_trick(query: str, order_column: str) -> str:
        """Apply +0 trick to prevent index misuse on the ORDER BY column."""
        for suffix in ("", " DESC", " ASC"):
            query = query.replace(
                f"ORDER BY {order_column}{suffix}",
                f"ORDER BY {order_column} + 0{suffix}",
            )
        return query

    @staticmethod
    def suggest_statistics_target(
        table: str,
        filter_col: str,
        order_col: str,
        distinct_values: int,
    ) -> str:
        """Suggest appropriate statistics target based on cardinality."""
        if distinct_values > 1_000_000:
            target = 1666
        elif distinct_values > 100_000:
            target = 1000
        elif distinct_values > 10_000:
            target = 500
        else:
            target = 250

        return (
            f"ALTER TABLE {table} ALTER COLUMN {filter_col} SET STATISTICS {target};\n"
            f"ALTER TABLE {table} ALTER COLUMN {order_col} SET STATISTICS {target};\n"
            f"ANALYZE {table};"
        )
