"""
Raw SQL Optimizer — rewrite suggestions + Active Record equivalents.

Analyzes raw SQL queries used in Rails apps (find_by_sql, execute) and:
1. Detects missing indexes
2. Suggests subquery rewrites
3. Generates Active Record equivalents
4. Recommends materialized views for expensive aggregations

Based on pganalyze "Advanced Database Programming with Rails" (p.4).

Usage:
    from querysense.rails.optimize import RailsOptimizer

    optimizer = RailsOptimizer()
    report = optimizer.optimize(sql)
    print(report.optimized_sql)
    print(report.active_record_equivalent)
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field
from typing import Any


@dataclass
class IndexRecommendation:
    """A recommended database index."""

    table: str
    columns: list[str]
    reason: str
    is_partial: bool = False
    partial_condition: str = ""

    @property
    def create_sql(self) -> str:
        cols = ", ".join(self.columns)
        name = f"idx_{self.table}_{'_'.join(self.columns)}"
        if len(name) > 63:
            name = name[:63]
        base = f"CREATE INDEX CONCURRENTLY {name} ON {self.table}({cols})"
        if self.is_partial and self.partial_condition:
            base += f" WHERE {self.partial_condition}"
        return base + ";"

    @property
    def migration_rb(self) -> str:
        cols = ", ".join(f":{c}" for c in self.columns)
        add_line = f"    add_index :{self.table}, [{cols}], algorithm: :concurrently"
        if self.is_partial and self.partial_condition:
            add_line += f', where: "{self.partial_condition}"'
        return textwrap.dedent(f"""\
            class AddIndexTo{self.table.title().replace('_', '')} < ActiveRecord::Migration[7.1]
              disable_ddl_transaction!

              def change
            {add_line}
              end
            end
        """)

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "columns": self.columns,
            "reason": self.reason,
            "create_sql": self.create_sql,
        }


@dataclass
class RewriteSuggestion:
    """A SQL rewrite suggestion."""

    description: str
    original_fragment: str
    rewritten_sql: str
    reason: str
    performance_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "original_fragment": self.original_fragment,
            "rewritten_sql": self.rewritten_sql,
            "reason": self.reason,
            "performance_note": self.performance_note,
        }


@dataclass
class OptimizationReport:
    """Full optimization report for a SQL query."""

    original_sql: str = ""
    query_type: str = ""
    tables: list[str] = field(default_factory=list)
    joins: list[str] = field(default_factory=list)
    where_columns: list[tuple[str, str]] = field(default_factory=list)
    index_recommendations: list[IndexRecommendation] = field(default_factory=list)
    rewrites: list[RewriteSuggestion] = field(default_factory=list)
    active_record_equivalent: str = ""
    should_materialize: bool = False
    materialized_view_sql: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_sql": self.original_sql[:500],
            "query_type": self.query_type,
            "tables": self.tables,
            "joins": self.joins,
            "where_columns": [{"table": t, "column": c} for t, c in self.where_columns],
            "index_recommendations": [r.to_dict() for r in self.index_recommendations],
            "rewrites": [r.to_dict() for r in self.rewrites],
            "active_record_equivalent": self.active_record_equivalent,
            "should_materialize": self.should_materialize,
            "materialized_view_sql": self.materialized_view_sql,
        }


_TABLE_RE = re.compile(r"\bFROM\s+\"?(\w+)\"?", re.IGNORECASE)
_JOIN_RE = re.compile(r"\bJOIN\s+\"?(\w+)\"?", re.IGNORECASE)
_WHERE_COL_RE = re.compile(
    r"\"?(\w+)\"?\.\"?(\w+)\"?\s*(?:=|IN|IS|>|<|>=|<=|LIKE|BETWEEN|<>|!=)",
    re.IGNORECASE,
)
_AGG_RE = re.compile(r"\b(COUNT|SUM|AVG|MIN|MAX)\s*\(", re.IGNORECASE)
_GROUP_RE = re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE)
_SUBQUERY_RE = re.compile(r"\(\s*SELECT\b", re.IGNORECASE)
_ORDER_RE = re.compile(r"\bORDER\s+BY\b", re.IGNORECASE)
_LIMIT_RE = re.compile(r"\bLIMIT\s+\d+", re.IGNORECASE)
_LEFT_JOIN_RE = re.compile(r"\bLEFT\s+(?:OUTER\s+)?JOIN\s+\"?(\w+)\"?", re.IGNORECASE)


class RailsOptimizer:
    """
    Optimize raw SQL queries for Rails apps.

    Suggests indexes, rewrites, Active Record equivalents,
    and materialized views.
    """

    def optimize(self, sql: str) -> OptimizationReport:
        """Analyze and optimize a SQL query."""
        report = OptimizationReport(original_sql=sql)

        upper = sql.upper().strip()
        if upper.startswith("SELECT"):
            report.query_type = "SELECT"
        elif upper.startswith("WITH"):
            report.query_type = "CTE"
        elif upper.startswith("INSERT"):
            report.query_type = "INSERT"
        elif upper.startswith("UPDATE"):
            report.query_type = "UPDATE"
        else:
            report.query_type = "OTHER"

        report.tables = _TABLE_RE.findall(sql)
        report.joins = _JOIN_RE.findall(sql)
        report.where_columns = _WHERE_COL_RE.findall(sql)

        self._detect_missing_indexes(report)
        self._detect_join_rewrites(report)
        self._detect_subquery_opportunities(report)
        self._detect_materialization(report)
        self._generate_active_record(report)

        return report

    def _detect_missing_indexes(self, report: OptimizationReport) -> None:
        """Recommend indexes for WHERE clause columns."""
        seen: set[tuple[str, str]] = set()
        for tbl, col in report.where_columns:
            key = (tbl.lower(), col.lower())
            if key in seen:
                continue
            seen.add(key)

            if col.lower() in ("id", "pk"):
                continue

            report.index_recommendations.append(IndexRecommendation(
                table=tbl,
                columns=[col],
                reason=f"Column {tbl}.{col} is used in WHERE clause",
            ))

    def _detect_join_rewrites(self, report: OptimizationReport) -> None:
        """Suggest subquery rewrites for JOINs used only for filtering."""
        sql = report.original_sql
        left_joins = _LEFT_JOIN_RE.findall(sql)

        for join_table in left_joins:
            if _AGG_RE.search(sql):
                report.rewrites.append(RewriteSuggestion(
                    description=f"Convert LEFT JOIN {join_table} to correlated subquery",
                    original_fragment=f"LEFT JOIN {join_table}",
                    rewritten_sql=(
                        f"(SELECT COUNT(*) FROM {join_table} "
                        f"WHERE {join_table}.{report.tables[0] if report.tables else 'parent'}_id "
                        f"= {report.tables[0] if report.tables else 'parent'}.id) AS {join_table}_count"
                    ),
                    reason=(
                        "Correlated subqueries can be faster than LEFT JOIN + GROUP BY "
                        "because PostgreSQL can use index-only scans on the subquery"
                    ),
                    performance_note="Typically 2-5x faster for COUNT/SUM aggregations",
                ))

    def _detect_subquery_opportunities(self, report: OptimizationReport) -> None:
        """Detect queries that could benefit from subqueries."""
        sql = report.original_sql

        if len(report.joins) >= 2 and not _SUBQUERY_RE.search(sql):
            report.rewrites.append(RewriteSuggestion(
                description="Multi-table join could use subquery for filtering",
                original_fragment="Multiple JOINs",
                rewritten_sql=(
                    f"-- Use IN subquery to filter before joining:\n"
                    f"SELECT * FROM {report.tables[0] if report.tables else 'main_table'}\n"
                    f"WHERE {report.tables[0] + '_id' if len(report.tables) > 1 else 'id'} IN (\n"
                    f"  SELECT id FROM {report.joins[0]} WHERE ...\n"
                    f")"
                ),
                reason="Filter rows early with subquery to reduce join input size",
            ))

    def _detect_materialization(self, report: OptimizationReport) -> None:
        """Recommend materialized views for expensive aggregations."""
        sql = report.original_sql

        has_agg = bool(_AGG_RE.search(sql))
        has_group = bool(_GROUP_RE.search(sql))
        has_join = len(report.joins) >= 1

        if has_agg and has_group and has_join:
            report.should_materialize = True
            view_name = "mv_" + "_".join(report.tables[:2])
            report.materialized_view_sql = (
                f"CREATE MATERIALIZED VIEW {view_name} AS\n"
                f"{sql.rstrip(';')}\n"
                f"WITH DATA;\n\n"
                f"-- Refresh periodically:\n"
                f"-- REFRESH MATERIALIZED VIEW CONCURRENTLY {view_name};"
            )

    def _generate_active_record(self, report: OptimizationReport) -> None:
        """Generate Active Record equivalent of the SQL query."""
        if not report.tables:
            report.active_record_equivalent = "# Could not determine base model"
            return

        base = report.tables[0]
        model = base.title().replace("_", "")
        if model.endswith("s"):
            model = model[:-1]

        parts: list[str] = [model]

        for join in report.joins:
            assoc = join.lower()
            if assoc.endswith("s"):
                assoc_singular = assoc[:-1]
            else:
                assoc_singular = assoc
            parts.append(f".joins(:{assoc})")

        where_parts: list[str] = []
        for tbl, col in report.where_columns:
            where_parts.append(f"{tbl}: {{ {col}: ... }}")
        if where_parts:
            parts.append(f".where({', '.join(where_parts)})")

        if _AGG_RE.search(report.original_sql):
            aggs = _AGG_RE.findall(report.original_sql)
            for agg in set(aggs):
                parts.append(f"  # .{agg.lower}(...)")

        if _ORDER_RE.search(report.original_sql):
            parts.append(".order(...)")

        if _LIMIT_RE.search(report.original_sql):
            match = re.search(r"LIMIT\s+(\d+)", report.original_sql, re.IGNORECASE)
            if match:
                parts.append(f".limit({match.group(1)})")

        report.active_record_equivalent = "\n".join([
            "# Active Record equivalent:",
            "".join(parts),
        ])
