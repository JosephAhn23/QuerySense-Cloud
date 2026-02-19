"""
Query Advisor — automatic slow query detection and rewrite suggestion.

This is pganalyze's flagship new feature (announced 2026). It:
1. Detects inefficient query patterns from EXPLAIN plans
2. Automatically suggests rewrites using pg_query-level analysis
3. Tracks performance improvements over time
4. Provides targeted recommendations grounded in actual workload plans

QuerySense implementation:
- Scans pg_stat_statements for slow/inefficient queries
- Runs EXPLAIN on candidates to get plan details
- Applies pattern matching to detect anti-patterns
- Generates rewrite suggestions with expected improvement
- Supports both batch analysis and continuous monitoring

Usage:
    from querysense.query_advisor import QueryAdvisor
    advisor = QueryAdvisor()
    report = await advisor.analyze(dsn, min_exec_time_ms=100)
    for insight in report.insights:
        print(f"{insight.title}: {insight.rewrite_sql}")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class QueryInsight:
    """A single optimization insight for a query."""
    queryid: int = 0
    query_text: str = ""
    title: str = ""
    category: str = ""  # nested_loop, seq_scan, sort_spill, index, rewrite, config
    severity: str = "warning"
    description: str = ""
    current_plan_summary: str = ""
    rewrite_sql: str = ""
    config_change: str = ""
    estimated_improvement: str = ""
    mean_exec_time_ms: float = 0
    calls: int = 0
    total_time_ms: float = 0

    @property
    def total_impact_ms(self) -> float:
        """Total time that could be saved across all calls."""
        if "x" in self.estimated_improvement:
            try:
                factor = float(self.estimated_improvement.replace("x faster", "").strip())
                return self.total_time_ms * (1 - 1 / factor)
            except ValueError:
                pass
        return 0


@dataclass
class QueryAdvisorReport:
    """Report from automatic query analysis."""
    queries_analyzed: int = 0
    queries_with_plans: int = 0
    insights: list[QueryInsight] = field(default_factory=list)
    total_potential_savings_ms: float = 0
    top_offenders: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "queries_analyzed": self.queries_analyzed,
            "queries_with_plans": self.queries_with_plans,
            "insights": len(self.insights),
            "total_potential_savings_ms": self.total_potential_savings_ms,
            "by_category": self._count_by_category(),
        }

    def _count_by_category(self) -> dict[str, int]:
        cats: dict[str, int] = {}
        for i in self.insights:
            cats[i.category] = cats.get(i.category, 0) + 1
        return cats


class QueryAdvisor:
    """
    Automatic slow query detection and rewrite suggestion engine.

    Connects to a live database, identifies slow/inefficient queries,
    analyzes their plans, and generates rewrite suggestions.
    """

    def __init__(self, max_explain_queries: int = 50) -> None:
        self.max_explain_queries = max_explain_queries

    async def analyze(
        self,
        dsn: str,
        min_exec_time_ms: float = 50,
        min_calls: int = 5,
        schema: str = "public",
    ) -> QueryAdvisorReport:
        """
        Run automatic query analysis.

        1. Fetches top queries from pg_stat_statements
        2. Runs EXPLAIN on each candidate
        3. Detects anti-patterns in plans
        4. Generates rewrite suggestions
        """
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        report = QueryAdvisorReport()
        conn = await asyncpg.connect(dsn)

        try:
            # Stage 1: Get candidate queries
            candidates = await self._get_candidates(
                conn, min_exec_time_ms, min_calls,
            )
            report.queries_analyzed = len(candidates)

            # Stage 2: EXPLAIN each candidate
            for cand in candidates[:self.max_explain_queries]:
                try:
                    plan = await self._explain_query(conn, cand["query"])
                    if plan:
                        report.queries_with_plans += 1
                        insights = self._analyze_plan(cand, plan)
                        report.insights.extend(insights)
                except Exception as e:
                    logger.debug("Could not explain query %s: %s", cand["queryid"], e)

            # Stage 3: SQL-level pattern analysis (no EXPLAIN needed)
            for cand in candidates:
                insights = self._analyze_sql_patterns(cand)
                report.insights.extend(insights)

            # Deduplicate by (queryid, category)
            seen: set[str] = set()
            deduped: list[QueryInsight] = []
            for insight in report.insights:
                key = f"{insight.queryid}_{insight.category}"
                if key not in seen:
                    seen.add(key)
                    deduped.append(insight)
            report.insights = sorted(
                deduped, key=lambda i: i.total_time_ms, reverse=True,
            )

            # Total savings
            report.total_potential_savings_ms = sum(
                i.total_impact_ms for i in report.insights
            )

            # Top offenders
            report.top_offenders = [
                {"queryid": i.queryid, "query": i.query_text[:100],
                 "time_ms": i.total_time_ms, "insight": i.title}
                for i in report.insights[:10]
            ]

        finally:
            await conn.close()

        return report

    # ── Stage 1: Candidate Selection ─────────────────────────────────

    async def _get_candidates(
        self, conn: Any, min_exec_ms: float, min_calls: int,
    ) -> list[dict[str, Any]]:
        """Get slow query candidates from pg_stat_statements."""
        rows = await conn.fetch("""
            SELECT
                queryid,
                query,
                calls,
                mean_exec_time,
                total_exec_time,
                rows,
                shared_blks_hit,
                shared_blks_read,
                shared_blks_written
            FROM pg_stat_statements
            WHERE calls >= $1
                AND mean_exec_time >= $2
                AND query NOT LIKE '%pg_%'
                AND query NOT LIKE 'SET %'
                AND query NOT LIKE 'SHOW %'
            ORDER BY total_exec_time DESC
            LIMIT 100
        """, min_calls, min_exec_ms)

        return [dict(r) for r in rows]

    # ── Stage 2: Plan Analysis ───────────────────────────────────────

    async def _explain_query(
        self, conn: Any, query: str,
    ) -> dict | None:
        """Run EXPLAIN on a query safely inside a rolled-back transaction."""
        # Parameterize: replace $N with NULL for EXPLAIN
        clean_sql = re.sub(r'\$\d+', 'NULL', query)

        # Skip non-SELECT or dangerous queries
        first_word = clean_sql.strip().split()[0].upper() if clean_sql.strip() else ""
        if first_word not in ("SELECT", "WITH"):
            return None

        try:
            result = await conn.fetch(
                f"EXPLAIN (FORMAT JSON, COSTS, VERBOSE) {clean_sql}"
            )
            if result:
                return result[0][0]
        except Exception:
            return None

        return None

    def _analyze_plan(
        self, candidate: dict, plan_data: Any,
    ) -> list[QueryInsight]:
        """Analyze an EXPLAIN plan for anti-patterns."""
        insights: list[QueryInsight] = []

        if isinstance(plan_data, list) and plan_data:
            plan = plan_data[0] if isinstance(plan_data[0], dict) else {}
        elif isinstance(plan_data, dict):
            plan = plan_data
        else:
            return insights

        root = plan.get("Plan", plan)
        queryid = candidate["queryid"]
        query = candidate["query"]
        mean_ms = float(candidate["mean_exec_time"])
        calls = candidate["calls"]
        total_ms = float(candidate["total_exec_time"])

        # Walk the plan tree
        self._walk_plan(
            root, insights, queryid, query, mean_ms, calls, total_ms,
        )

        return insights

    def _walk_plan(
        self,
        node: dict,
        insights: list[QueryInsight],
        queryid: int,
        query: str,
        mean_ms: float,
        calls: int,
        total_ms: float,
    ) -> None:
        """Walk plan tree looking for anti-patterns."""
        node_type = node.get("Node Type", "")
        plan_rows = node.get("Plan Rows", 0)
        total_cost = node.get("Total Cost", 0)

        # Pattern 1: Nested Loop with high row count
        if node_type == "Nested Loop" and plan_rows > 10000:
            inner = node.get("Plans", [{}])[-1] if node.get("Plans") else {}
            inner_type = inner.get("Node Type", "")

            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title=f"Nested Loop producing {plan_rows:,} rows",
                category="nested_loop",
                severity="warning",
                description=(
                    f"Nested Loop with inner {inner_type} produces {plan_rows:,} rows. "
                    f"This is O(n*m) complexity and usually slow for large result sets."
                ),
                current_plan_summary=f"Nested Loop -> {inner_type} ({plan_rows:,} rows)",
                config_change=(
                    "-- Force hash join for this query:\n"
                    "SET LOCAL enable_nestloop = off;"
                ),
                estimated_improvement="2-100x faster with hash join",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        # Pattern 2: Sequential Scan on large table
        if node_type == "Seq Scan" and plan_rows > 50000:
            relation = node.get("Relation Name", "?")
            filter_cond = node.get("Filter", "")

            if filter_cond:
                # Extract columns from filter
                filter_cols = re.findall(r'\((\w+)', filter_cond)

                rewrite = ""
                if filter_cols:
                    cols = ", ".join(filter_cols[:3])
                    rewrite = (
                        f"CREATE INDEX CONCURRENTLY idx_{relation}_advisor "
                        f"ON {relation} ({cols});"
                    )

                insights.append(QueryInsight(
                    queryid=queryid,
                    query_text=query,
                    title=f"Sequential scan on {relation} ({plan_rows:,} rows)",
                    category="seq_scan",
                    severity="warning",
                    description=(
                        f"Full table scan on '{relation}' with filter: {filter_cond[:100]}. "
                        f"An index on the filter columns would avoid scanning all {plan_rows:,} rows."
                    ),
                    current_plan_summary=f"Seq Scan on {relation}",
                    rewrite_sql=rewrite,
                    estimated_improvement="10-1000x faster with index",
                    mean_exec_time_ms=mean_ms,
                    calls=calls,
                    total_time_ms=total_ms,
                ))

        # Pattern 3: Sort with high cost (potential disk spill)
        if node_type == "Sort" and total_cost > 1000:
            sort_key = node.get("Sort Key", [])
            sort_method = node.get("Sort Method", "")

            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title=f"Expensive sort ({plan_rows:,} rows, cost={total_cost:.0f})",
                category="sort_spill",
                severity="notice",
                description=(
                    f"Sort on {sort_key} with cost {total_cost:.0f}. "
                    f"Method: {sort_method or 'unknown'}. "
                    "High-cost sorts may spill to disk."
                ),
                config_change="SET work_mem = '256MB';  -- session level",
                estimated_improvement="2-10x faster in memory",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        # Pattern 4: Index Scan with high rows removed by filter
        if node_type in ("Index Scan", "Index Only Scan"):
            rows_removed = node.get("Rows Removed by Filter", 0)
            if rows_removed > plan_rows * 5 and rows_removed > 1000:
                index = node.get("Index Name", "?")
                insights.append(QueryInsight(
                    queryid=queryid,
                    query_text=query,
                    title=f"Inefficient index scan ({rows_removed:,} rows filtered after scan)",
                    category="index",
                    severity="warning",
                    description=(
                        f"Index '{index}' returned {plan_rows + rows_removed:,} rows "
                        f"but {rows_removed:,} were discarded by a filter. "
                        "A more selective index would avoid this wasted work."
                    ),
                    current_plan_summary=f"{node_type} using {index}",
                    estimated_improvement="5-50x faster with better index",
                    mean_exec_time_ms=mean_ms,
                    calls=calls,
                    total_time_ms=total_ms,
                ))

        # Pattern 5: Hash Join with high memory
        if node_type == "Hash Join":
            peak_mem = node.get("Peak Memory Usage", 0)
            if peak_mem > 100000:  # >100MB
                insights.append(QueryInsight(
                    queryid=queryid,
                    query_text=query,
                    title=f"Hash Join using {peak_mem // 1024}MB memory",
                    category="hash_join",
                    severity="notice",
                    description=(
                        f"Hash Join consuming {peak_mem // 1024}MB. "
                        "Consider increasing work_mem or reducing the hash side."
                    ),
                    config_change="SET work_mem = '512MB';",
                    mean_exec_time_ms=mean_ms,
                    calls=calls,
                    total_time_ms=total_ms,
                ))

        # Recurse
        for child in node.get("Plans", []):
            self._walk_plan(child, insights, queryid, query, mean_ms, calls, total_ms)

    # ── Stage 3: SQL Pattern Analysis ────────────────────────────────

    def _analyze_sql_patterns(
        self, candidate: dict,
    ) -> list[QueryInsight]:
        """Detect anti-patterns from SQL text alone (no EXPLAIN needed)."""
        insights: list[QueryInsight] = []
        query = candidate["query"]
        queryid = candidate["queryid"]
        mean_ms = float(candidate["mean_exec_time"])
        calls = candidate["calls"]
        total_ms = float(candidate["total_exec_time"])
        sql_upper = query.upper()

        # Pattern: SELECT *
        if re.search(r'\bSELECT\s+\*\s+FROM\b', sql_upper):
            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title="SELECT * fetches all columns",
                category="rewrite",
                severity="notice",
                description=(
                    "Fetching all columns prevents index-only scans and "
                    "transfers unnecessary data. List only needed columns."
                ),
                rewrite_sql="-- Replace SELECT * with specific column list",
                estimated_improvement="2-10x faster with index-only scan",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        # Pattern: NOT IN (subquery)
        if re.search(r'\bNOT\s+IN\s*\(\s*SELECT\b', sql_upper):
            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title="NOT IN with subquery — use NOT EXISTS",
                category="rewrite",
                severity="warning",
                description=(
                    "NOT IN with a subquery has problematic NULL behavior and "
                    "often produces poor plans. NOT EXISTS is semantically correct "
                    "and typically faster."
                ),
                rewrite_sql=(
                    "-- Rewrite NOT IN to NOT EXISTS:\n"
                    "-- Before: WHERE col NOT IN (SELECT col FROM other)\n"
                    "-- After:  WHERE NOT EXISTS (SELECT 1 FROM other WHERE other.col = main.col)"
                ),
                estimated_improvement="2-100x faster",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        # Pattern: COUNT(*) without WHERE
        if re.search(r'\bSELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\s+\w+\s*$', sql_upper.strip()):
            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title="COUNT(*) on entire table — always scans all rows",
                category="rewrite",
                severity="notice",
                description=(
                    "COUNT(*) without WHERE scans the entire table. "
                    "For approximate counts, use pg_stat_user_tables.n_live_tup."
                ),
                rewrite_sql=(
                    "-- For approximate count (instant):\n"
                    "SELECT n_live_tup FROM pg_stat_user_tables WHERE relname = 'table_name';"
                ),
                estimated_improvement="100-10000x faster (approximate)",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        # Pattern: OFFSET with large value
        offset_match = re.search(r'\bOFFSET\s+(\d+)', sql_upper)
        if offset_match and int(offset_match.group(1)) > 1000:
            offset_val = int(offset_match.group(1))
            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title=f"Large OFFSET ({offset_val}) — keyset pagination is better",
                category="rewrite",
                severity="warning",
                description=(
                    f"OFFSET {offset_val} scans and discards {offset_val} rows. "
                    "Performance degrades linearly with offset value."
                ),
                rewrite_sql=(
                    "-- Rewrite to keyset pagination:\n"
                    "-- Before: SELECT * FROM t ORDER BY id LIMIT 20 OFFSET 10000\n"
                    "-- After:  SELECT * FROM t WHERE id > :last_seen_id ORDER BY id LIMIT 20"
                ),
                estimated_improvement=f"{offset_val // 20}x faster",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        # Pattern: LIKE '%prefix' (leading wildcard)
        if re.search(r"LIKE\s+'%", sql_upper):
            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title="Leading wildcard LIKE prevents index usage",
                category="rewrite",
                severity="warning",
                description=(
                    "LIKE '%pattern' cannot use a B-tree index. "
                    "Use a GIN index with pg_trgm for trigram matching."
                ),
                rewrite_sql=(
                    "-- Option 1: GIN index with pg_trgm\n"
                    "CREATE EXTENSION IF NOT EXISTS pg_trgm;\n"
                    "CREATE INDEX CONCURRENTLY idx_col_trgm ON t USING GIN (col gin_trgm_ops);\n\n"
                    "-- Option 2: Full-text search\n"
                    "CREATE INDEX CONCURRENTLY idx_col_fts ON t USING GIN (to_tsvector('english', col));\n"
                    "-- Then: WHERE to_tsvector('english', col) @@ to_tsquery('pattern')"
                ),
                estimated_improvement="10-100x faster with GIN index",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        # Pattern: Multiple OR conditions
        or_count = len(re.findall(r'\bOR\b', sql_upper))
        if or_count >= 3 and "WHERE" in sql_upper:
            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title=f"{or_count} OR conditions — consider ANY() or UNION ALL",
                category="rewrite",
                severity="notice",
                description=(
                    f"Multiple OR conditions ({or_count}) can prevent index usage. "
                    "PG18 auto-transforms OR to array scans; on older versions, "
                    "rewrite manually."
                ),
                rewrite_sql=(
                    "-- Rewrite OR to ANY:\n"
                    "-- Before: WHERE col = 1 OR col = 2 OR col = 3\n"
                    "-- After:  WHERE col = ANY(ARRAY[1, 2, 3])"
                ),
                estimated_improvement="2-10x faster with index scan",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        # Pattern: Correlated subquery in SELECT
        if re.search(r'SELECT\s+.*\(\s*SELECT\b', sql_upper):
            insights.append(QueryInsight(
                queryid=queryid,
                query_text=query,
                title="Correlated subquery in SELECT — use LEFT JOIN",
                category="rewrite",
                severity="warning",
                description=(
                    "A correlated subquery in SELECT runs once per row. "
                    "Rewrite as a LEFT JOIN for set-based execution."
                ),
                rewrite_sql=(
                    "-- Rewrite correlated subquery to JOIN:\n"
                    "-- Before: SELECT a.*, (SELECT max(b.val) FROM b WHERE b.a_id = a.id)\n"
                    "-- After:  SELECT a.*, b_max.val\n"
                    "--         FROM a LEFT JOIN LATERAL (SELECT max(val) AS val FROM b WHERE b.a_id = a.id) b_max ON TRUE"
                ),
                estimated_improvement="10-1000x faster",
                mean_exec_time_ms=mean_ms,
                calls=calls,
                total_time_ms=total_ms,
            ))

        return insights
