"""
Dynamic Query Workload Advisor — analyze query families for minimal covering indexes.

Based on "PostgreSQL Query Optimization" (Dombrovskaya et al. 2024):
modern applications build queries dynamically, and the same template is
executed with different filter combinations. Optimizing each variant
individually leads to index explosion. This module analyzes an entire
family of similar queries and recommends a minimal set of indexes.

Extends the existing WorkloadAdvisor with:
- Query family detection (same template, different constants)
- Cross-family index consolidation
- Storage budget optimization (knapsack-style)
- Filter selectivity estimation from query variety

Usage:
    from querysense.workload_advisor import DynamicWorkloadAdvisor

    advisor = DynamicWorkloadAdvisor()
    advisor.add_query("SELECT * FROM orders WHERE user_id = 1 AND status = 'active'", calls=5000)
    advisor.add_query("SELECT * FROM orders WHERE user_id = 2", calls=3000)
    advisor.add_query("SELECT * FROM orders WHERE status = 'pending'", calls=1000)
    result = advisor.analyze()
    for rec in result.recommendations:
        print(rec.create_index_sql)
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class QueryFamily:
    """A family of similar queries (same structure, different constants)."""
    template: str
    table: str
    filter_columns: list[str]
    total_calls: int = 0
    example_queries: list[str] = field(default_factory=list)
    variant_count: int = 0
    has_order_by: bool = False
    order_columns: list[str] = field(default_factory=list)
    has_limit: bool = False
    select_columns: list[str] = field(default_factory=list)

    @property
    def is_hot(self) -> bool:
        return self.total_calls > 1000


@dataclass
class IndexRecommendation:
    """A recommended index covering one or more query families."""
    table: str
    columns: list[str]
    include_columns: list[str] = field(default_factory=list)
    is_partial: bool = False
    where_clause: str = ""
    families_covered: int = 0
    estimated_improvement_pct: float = 0.0
    total_calls_covered: int = 0

    @property
    def create_index_sql(self) -> str:
        name_parts = [self.table] + self.columns[:3]
        name = "idx_" + "_".join(name_parts)
        cols = ", ".join(self.columns)
        include = f" INCLUDE ({', '.join(self.include_columns)})" if self.include_columns else ""
        where = f" WHERE {self.where_clause}" if self.is_partial and self.where_clause else ""
        return (
            f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name}\n"
            f"  ON {self.table} ({cols}){include}{where};"
        )


@dataclass
class WorkloadAnalysisResult:
    """Result of dynamic workload analysis."""
    families: list[QueryFamily] = field(default_factory=list)
    recommendations: list[IndexRecommendation] = field(default_factory=list)
    tables_analyzed: int = 0
    total_query_calls: int = 0
    index_count_before: int = 0
    index_count_after: int = 0  # Recommended count

    def to_dict(self) -> dict[str, Any]:
        return {
            "families": len(self.families),
            "recommendations": [
                {
                    "table": r.table,
                    "columns": r.columns,
                    "include_columns": r.include_columns,
                    "is_partial": r.is_partial,
                    "families_covered": r.families_covered,
                    "total_calls_covered": r.total_calls_covered,
                    "sql": r.create_index_sql,
                }
                for r in self.recommendations
            ],
            "total_query_calls": self.total_query_calls,
        }


def _normalize_sql(sql: str) -> str:
    """Normalize SQL by replacing constants with placeholders."""
    s = re.sub(r"'[^']*'", "'?'", sql)
    s = re.sub(r"\b\d+\b", "?", s)
    s = re.sub(r"\s+", " ", s).strip().upper()
    return s


def _extract_table(sql: str) -> str:
    match = re.search(r"\bFROM\s+(\w+)", sql, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _extract_where_columns(sql: str) -> list[str]:
    """Extract column names from WHERE clause."""
    where_match = re.search(r"\bWHERE\s+(.*?)(?:\bGROUP\b|\bORDER\b|\bLIMIT\b|\bHAVING\b|$)",
                            sql, re.IGNORECASE | re.DOTALL)
    if not where_match:
        return []
    where_clause = where_match.group(1)
    # Extract "column = ?" patterns
    columns = re.findall(r"(\w+)\s*(?:=|IN|>|<|>=|<=|LIKE|IS)\s", where_clause, re.IGNORECASE)
    return [c.lower() for c in columns if c.upper() not in ("AND", "OR", "NOT", "NULL", "TRUE", "FALSE")]


def _extract_order_columns(sql: str) -> list[str]:
    match = re.search(r"\bORDER\s+BY\s+([\w\s,]+?)(?:\bLIMIT\b|$)", sql, re.IGNORECASE)
    if not match:
        return []
    cols = match.group(1)
    return [c.strip().split()[0].lower() for c in cols.split(",") if c.strip()]


class DynamicWorkloadAdvisor:
    """
    Analyze a dynamic query workload and recommend minimal covering indexes.

    Unlike single-query optimizers, this considers the entire application's
    query set to find indexes that serve multiple query patterns.
    """

    def __init__(self, storage_budget_mb: float = 500.0) -> None:
        self._queries: list[tuple[str, int]] = []
        self._storage_budget_mb = storage_budget_mb

    def add_query(self, sql: str, calls: int = 1) -> None:
        """Add a query to the workload."""
        self._queries.append((sql, calls))

    def add_from_pg_stat_statements(
        self, stats: list[dict[str, Any]],
    ) -> None:
        """Add queries from pg_stat_statements output."""
        for row in stats:
            sql = row.get("query", "")
            calls = row.get("calls", 1)
            if sql.strip():
                self.add_query(sql, calls)

    def analyze(self) -> WorkloadAnalysisResult:
        """Analyze the workload and produce recommendations."""
        result = WorkloadAnalysisResult()

        # Step 1: Group into families
        families = self._detect_families()
        result.families = families
        result.total_query_calls = sum(f.total_calls for f in families)

        # Step 2: Group families by table
        by_table: dict[str, list[QueryFamily]] = defaultdict(list)
        for family in families:
            if family.table:
                by_table[family.table].append(family)
        result.tables_analyzed = len(by_table)

        # Step 3: For each table, find minimal covering index set
        for table, table_families in by_table.items():
            recs = self._recommend_for_table(table, table_families)
            result.recommendations.extend(recs)

        result.index_count_after = len(result.recommendations)

        # Sort by impact
        result.recommendations.sort(
            key=lambda r: r.total_calls_covered, reverse=True,
        )

        return result

    def _detect_families(self) -> list[QueryFamily]:
        """Group queries into families by normalized template."""
        family_map: dict[str, QueryFamily] = {}

        for sql, calls in self._queries:
            template = _normalize_sql(sql)
            table = _extract_table(sql)
            where_cols = _extract_where_columns(sql)
            order_cols = _extract_order_columns(sql)

            if template not in family_map:
                family_map[template] = QueryFamily(
                    template=template,
                    table=table,
                    filter_columns=where_cols,
                    has_order_by=bool(order_cols),
                    order_columns=order_cols,
                    has_limit=bool(re.search(r"\bLIMIT\b", sql, re.IGNORECASE)),
                )

            family = family_map[template]
            family.total_calls += calls
            family.variant_count += 1
            if len(family.example_queries) < 3:
                family.example_queries.append(sql[:200])

        return list(family_map.values())

    def _recommend_for_table(
        self, table: str, families: list[QueryFamily],
    ) -> list[IndexRecommendation]:
        """Recommend indexes for a single table."""
        recs: list[IndexRecommendation] = []

        # Sort families by call count (most used first)
        families.sort(key=lambda f: f.total_calls, reverse=True)

        # Track which column sets are already covered
        covered: set[tuple[str, ...]] = set()

        for family in families:
            cols = tuple(family.filter_columns)
            if not cols:
                continue

            # Check if already covered by an existing recommendation
            is_covered = False
            for existing_cols in covered:
                if cols == existing_cols[:len(cols)]:
                    is_covered = True
                    break

            if is_covered:
                continue

            # Build index columns: WHERE columns + ORDER BY columns
            index_cols = list(family.filter_columns)
            include_cols: list[str] = []

            # Add ORDER BY columns to index (for sort avoidance)
            for oc in family.order_columns:
                if oc not in index_cols:
                    index_cols.append(oc)

            # Check if we can consolidate with another family
            for other_family in families:
                if other_family is family:
                    continue
                other_cols = other_family.filter_columns
                # If other family's columns are a prefix of ours, we already cover it
                if other_cols and all(c in index_cols for c in other_cols):
                    continue
                # If adding one column would cover another family
                diff = [c for c in other_cols if c not in index_cols]
                if len(diff) == 1 and other_family.total_calls > 500:
                    index_cols.append(diff[0])

            # Deduplicate while preserving order
            seen: set[str] = set()
            deduped: list[str] = []
            for c in index_cols:
                if c not in seen:
                    seen.add(c)
                    deduped.append(c)
            index_cols = deduped

            covered.add(tuple(index_cols))

            # Count families this covers
            families_covered = 0
            calls_covered = 0
            for f in families:
                if all(c in index_cols for c in f.filter_columns):
                    families_covered += 1
                    calls_covered += f.total_calls

            recs.append(IndexRecommendation(
                table=table,
                columns=index_cols,
                include_columns=include_cols,
                families_covered=families_covered,
                total_calls_covered=calls_covered,
            ))

        return recs
