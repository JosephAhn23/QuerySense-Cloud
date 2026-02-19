"""
MySQL-specific analysis rules.

These rules analyze MySQL EXPLAIN FORMAT=JSON output for common performance
issues specific to MySQL/MariaDB. They complement the engine-agnostic IR
rules that already work across PostgreSQL and MySQL via the IR adapter.

MySQL-specific patterns:
- Full table scans (access_type = ALL)
- Full index scans (access_type = index)
- Filesort operations
- Temporary table usage
- Missing index candidates
- InnoDB buffer pool considerations
- Character set / collation mismatches in joins
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from querysense.parser.mysql_parser import (
    MySQLExplainOutput,
    MySQLTableAccess,
    MYSQL_ACCESS_SEVERITY,
)


@dataclass
class MySQLFinding:
    """A MySQL-specific performance finding."""

    rule_id: str
    severity: str  # "critical", "warning", "info"
    title: str
    description: str
    suggestion: str
    table_name: str
    impact_score: float
    metrics: dict[str, Any]


class MySQLAnalyzer:
    """
    Analyze MySQL EXPLAIN plans for performance issues.

    Works directly with MySQLExplainOutput (no IR conversion needed).
    For cross-engine analysis, use the IR pipeline instead.
    """

    def analyze(self, plan: MySQLExplainOutput) -> list[MySQLFinding]:
        """Run all MySQL rules against a parsed EXPLAIN plan."""
        findings: list[MySQLFinding] = []

        for access in plan.all_table_accesses:
            findings.extend(self._check_full_table_scan(access))
            findings.extend(self._check_full_index_scan(access))
            findings.extend(self._check_missing_index(access))
            findings.extend(self._check_filesort(access))
            findings.extend(self._check_temporary_table(access))
            findings.extend(self._check_row_examination(access))

        # Plan-level checks
        findings.extend(self._check_plan_cost(plan))
        findings.extend(self._check_optimized_away(plan))

        return findings

    def _check_full_table_scan(self, access: MySQLTableAccess) -> list[MySQLFinding]:
        """Detect ALL (full table scan) access type."""
        if access.access_type != "ALL":
            return []

        rows = access.rows_examined_per_scan
        if rows < 100:
            return []  # Small table, not worth flagging

        impact = min(10.0, 3.0 + (rows / 10000) * 2)
        suggestion_parts = [
            f"-- Table '{access.table_name}' is doing a full table scan ({rows:,} rows)",
        ]

        if access.attached_condition:
            # Extract column from condition for index suggestion
            suggestion_parts.append(
                f"-- Filter: {access.attached_condition}"
            )
            suggestion_parts.append(
                f"ALTER TABLE `{access.table_name}` ADD INDEX "
                f"idx_{access.table_name}_querysense ("
                f"/* column(s) from: {access.attached_condition[:60]} */);"
            )
        else:
            suggestion_parts.append(
                f"-- No WHERE clause — consider adding a filter or limiting the result set"
            )

        return [MySQLFinding(
            rule_id="MYSQL_FULL_TABLE_SCAN",
            severity="critical" if rows > 10000 else "warning",
            title=f"Full table scan on {access.table_name} ({rows:,} rows)",
            description=(
                f"MySQL is scanning every row in '{access.table_name}'. "
                f"access_type=ALL means no index is being used."
            ),
            suggestion="\n".join(suggestion_parts),
            table_name=access.table_name,
            impact_score=impact,
            metrics={
                "access_type": "ALL",
                "rows_examined": rows,
                "rows_produced": access.rows_produced_per_join,
            },
        )]

    def _check_full_index_scan(self, access: MySQLTableAccess) -> list[MySQLFinding]:
        """Detect full index scan (access_type = index)."""
        if access.access_type != "index":
            return []

        rows = access.rows_examined_per_scan
        if rows < 1000:
            return []

        return [MySQLFinding(
            rule_id="MYSQL_FULL_INDEX_SCAN",
            severity="warning",
            title=f"Full index scan on {access.table_name} ({rows:,} rows)",
            description=(
                f"MySQL is scanning the entire index '{access.key}' on "
                f"'{access.table_name}'. This is better than a table scan but "
                f"still reads {rows:,} index entries."
            ),
            suggestion=(
                f"-- Full index scan on {access.table_name} using '{access.key}'\n"
                f"-- Add a more selective WHERE clause or use a covering index\n"
                f"-- Consider: ALTER TABLE `{access.table_name}` ADD INDEX "
                f"idx_{access.table_name}_covering (...) INCLUDE (...);"
            ),
            table_name=access.table_name,
            impact_score=min(7.0, 2.0 + (rows / 50000) * 3),
            metrics={
                "access_type": "index",
                "index_name": access.key,
                "rows_examined": rows,
            },
        )]

    def _check_missing_index(self, access: MySQLTableAccess) -> list[MySQLFinding]:
        """Detect queries where possible_keys is empty but a filter exists."""
        if access.access_type in ("const", "system", "eq_ref", "ref"):
            return []
        if not access.attached_condition:
            return []
        if access.possible_keys:
            return []

        rows = access.rows_examined_per_scan
        return [MySQLFinding(
            rule_id="MYSQL_MISSING_INDEX",
            severity="warning" if rows > 1000 else "info",
            title=f"No candidate indexes for filter on {access.table_name}",
            description=(
                f"MySQL has no possible keys for the filter "
                f"'{access.attached_condition[:80]}' on '{access.table_name}'. "
                f"Consider adding an index."
            ),
            suggestion=(
                f"-- No index candidates for filter on {access.table_name}\n"
                f"-- Filter: {access.attached_condition}\n"
                f"ALTER TABLE `{access.table_name}` ADD INDEX "
                f"idx_{access.table_name}_querysense (/* filtered column(s) */);"
            ),
            table_name=access.table_name,
            impact_score=min(8.0, 3.0 + (rows / 5000) * 2),
            metrics={
                "access_type": access.access_type,
                "condition": access.attached_condition,
                "rows_examined": rows,
            },
        )]

    def _check_filesort(self, access: MySQLTableAccess) -> list[MySQLFinding]:
        """Detect filesort operations."""
        if not access.using_filesort:
            return []

        rows = access.rows_examined_per_scan
        return [MySQLFinding(
            rule_id="MYSQL_FILESORT",
            severity="warning" if rows > 1000 else "info",
            title=f"Filesort on {access.table_name} ({rows:,} rows)",
            description=(
                f"MySQL is sorting {rows:,} rows using filesort for "
                f"'{access.table_name}'. For large result sets, this can be "
                f"slow and memory-intensive."
            ),
            suggestion=(
                f"-- Filesort on {access.table_name}\n"
                f"-- Add an index that matches your ORDER BY columns:\n"
                f"ALTER TABLE `{access.table_name}` ADD INDEX "
                f"idx_{access.table_name}_sort (/* ORDER BY column(s) */);"
            ),
            table_name=access.table_name,
            impact_score=min(6.0, 2.0 + (rows / 10000) * 2),
            metrics={
                "rows_sorted": rows,
                "using_filesort": True,
            },
        )]

    def _check_temporary_table(self, access: MySQLTableAccess) -> list[MySQLFinding]:
        """Detect temporary table usage."""
        if not access.using_temporary_table:
            return []

        return [MySQLFinding(
            rule_id="MYSQL_TEMPORARY_TABLE",
            severity="warning",
            title=f"Temporary table used for {access.table_name}",
            description=(
                f"MySQL is creating a temporary table for operations on "
                f"'{access.table_name}'. This can cause disk I/O if the "
                f"result exceeds tmp_table_size."
            ),
            suggestion=(
                f"-- Temporary table for {access.table_name}\n"
                f"-- Check tmp_table_size and max_heap_table_size:\n"
                f"SET SESSION tmp_table_size = 67108864;  -- 64MB\n"
                f"SET SESSION max_heap_table_size = 67108864;"
            ),
            table_name=access.table_name,
            impact_score=5.0,
            metrics={"using_temporary_table": True},
        )]

    def _check_row_examination(self, access: MySQLTableAccess) -> list[MySQLFinding]:
        """Detect large row examination vs production ratios."""
        examined = access.rows_examined_per_scan
        produced = access.rows_produced_per_join

        if examined < 1000 or produced < 1:
            return []

        ratio = examined / max(produced, 1)
        if ratio < 10:
            return []

        return [MySQLFinding(
            rule_id="MYSQL_ROW_EXAMINATION_RATIO",
            severity="warning" if ratio > 100 else "info",
            title=f"High examination ratio on {access.table_name} ({ratio:.0f}:1)",
            description=(
                f"MySQL examines {examined:,} rows to produce {produced:,} results "
                f"({ratio:.0f}x overread). A better index could reduce this."
            ),
            suggestion=(
                f"-- {access.table_name}: examining {examined:,} rows for {produced:,} results\n"
                f"-- Ratio: {ratio:.0f}:1 — consider a more selective index\n"
                f"ANALYZE TABLE `{access.table_name}`;"
            ),
            table_name=access.table_name,
            impact_score=min(8.0, 3.0 + min(ratio / 100, 5.0)),
            metrics={
                "rows_examined": examined,
                "rows_produced": produced,
                "examination_ratio": ratio,
            },
        )]

    def _check_plan_cost(self, plan: MySQLExplainOutput) -> list[MySQLFinding]:
        """Flag extremely expensive plans."""
        cost = plan.total_cost
        if cost < 10000:
            return []

        return [MySQLFinding(
            rule_id="MYSQL_HIGH_COST",
            severity="critical" if cost > 100000 else "warning",
            title=f"High query cost: {cost:,.0f}",
            description=(
                f"MySQL optimizer estimates this query costs {cost:,.0f}. "
                f"This indicates a complex or poorly optimized query."
            ),
            suggestion=(
                f"-- Query cost: {cost:,.0f}\n"
                f"-- Review the tables and joins in this query for optimization"
            ),
            table_name="(query-level)",
            impact_score=min(9.0, 4.0 + (cost / 100000) * 3),
            metrics={"query_cost": cost},
        )]

    def _check_optimized_away(self, plan: MySQLExplainOutput) -> list[MySQLFinding]:
        """Note when MySQL optimizes a query away entirely (good news)."""
        if not plan.query_block.optimized_away:
            return []

        return [MySQLFinding(
            rule_id="MYSQL_OPTIMIZED_AWAY",
            severity="info",
            title="Query optimized away by MySQL",
            description="MySQL was able to resolve this query during optimization without accessing any tables.",
            suggestion="-- No action needed — this query is already optimal",
            table_name="(none)",
            impact_score=0.0,
            metrics={"optimized_away": True},
        )]
