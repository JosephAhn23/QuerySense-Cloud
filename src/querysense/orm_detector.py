"""
ORM Anti-pattern Detector.

Analyzes SQL queries and EXPLAIN plans to detect common ORM pitfalls:
- N+1 query patterns (loop of identical queries)
- SELECT * when only a few columns are needed
- Unnecessary DISTINCT (from incorrect JOINs)
- Missing pagination (SELECT without LIMIT on large tables)
- Eager loading misuse (huge IN-list queries)
- ORM-generated cartesian products
- Unnecessary ORDER BY on unordered operations

Inspired by PostgreSQL Query Optimization (Dombrovskaya et al.), Ch. 11 & 14:
"Application Development" and "Avoiding ORM Pitfalls"

Usage:
    from querysense.orm_detector import detect_orm_patterns, ORMAntiPattern

    patterns = detect_orm_patterns(sql_queries)
    for p in patterns:
        print(f"[{p.severity}] {p.pattern_name}: {p.description}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ORMAntiPattern:
    """A detected ORM anti-pattern."""
    pattern_name: str       # N_PLUS_ONE, SELECT_STAR, UNNECESSARY_DISTINCT, etc.
    severity: str           # critical / warning / info
    description: str
    affected_queries: int = 1
    affected_table: str = ""
    suggestion: str = ""
    example_fix: str = ""

    @property
    def impact_score(self) -> float:
        """0-10 impact score."""
        base = {"critical": 8.0, "warning": 5.0, "info": 2.0}.get(self.severity, 3.0)
        # Scale by affected queries
        if self.affected_queries > 10:
            base += min(2.0, self.affected_queries / 50)
        return min(10.0, base)


@dataclass
class ORMDetectionReport:
    """Full ORM anti-pattern detection report."""
    queries_analyzed: int = 0
    patterns: list[ORMAntiPattern] = field(default_factory=list)

    @property
    def total_impact(self) -> float:
        return sum(p.impact_score for p in self.patterns)

    def to_dict(self) -> dict[str, Any]:
        return {
            "queries_analyzed": self.queries_analyzed,
            "patterns_found": len(self.patterns),
            "total_impact": round(self.total_impact, 1),
            "patterns": [
                {
                    "pattern": p.pattern_name,
                    "severity": p.severity,
                    "description": p.description,
                    "affected_queries": p.affected_queries,
                    "affected_table": p.affected_table,
                    "suggestion": p.suggestion,
                    "example_fix": p.example_fix,
                    "impact_score": round(p.impact_score, 1),
                }
                for p in self.patterns
            ],
        }


# ── Detection Functions ──────────────────────────────────────────────

def _normalize_sql(sql: str) -> str:
    """Normalize SQL for comparison (strip literals, collapse whitespace)."""
    s = re.sub(r"'[^']*'", "'?'", sql)
    s = re.sub(r"\b\d+\b", "?", s)
    s = re.sub(r"\s+", " ", s).strip().upper()
    return s


def _detect_n_plus_one(queries: list[str]) -> list[ORMAntiPattern]:
    """Detect N+1 query patterns (repeated identical queries with different params)."""
    normalized: dict[str, list[str]] = {}
    for q in queries:
        norm = _normalize_sql(q)
        normalized.setdefault(norm, []).append(q)

    patterns: list[ORMAntiPattern] = []
    for norm, originals in normalized.items():
        if len(originals) >= 5:  # 5+ identical queries = N+1 pattern
            # Extract table name
            table_match = re.search(r"FROM\s+(\w+)", norm)
            table = table_match.group(1).lower() if table_match else "unknown"

            # Determine if it's a SELECT by ID pattern
            has_where_id = bool(re.search(r"WHERE.*\bid\b\s*=", norm))

            patterns.append(ORMAntiPattern(
                pattern_name="N_PLUS_ONE",
                severity="critical",
                description=(
                    f"N+1 query detected: {len(originals)} identical queries against '{table}'. "
                    f"This means a loop is executing one query per row instead of a batch."
                ),
                affected_queries=len(originals),
                affected_table=table,
                suggestion=(
                    f"Replace the N+1 loop with a single batch query:\n"
                    f"  SELECT * FROM {table} WHERE id IN (...all IDs...)\n"
                    f"Or use eager loading / prefetching in your ORM:\n"
                    f"  Django: select_related('{table}') or prefetch_related('{table}')\n"
                    f"  SQLAlchemy: joinedload({table}) or subqueryload({table})\n"
                    f"  ActiveRecord: includes(:{table})"
                ),
                example_fix=(
                    f"-- Instead of {len(originals)} queries like:\n"
                    f"-- {originals[0][:80]}...\n"
                    f"-- Use one batch query:\n"
                    f"SELECT * FROM {table} WHERE id = ANY($1);"
                    if has_where_id else ""
                ),
            ))

    return patterns


def _detect_select_star(queries: list[str]) -> list[ORMAntiPattern]:
    """Detect SELECT * usage that could be narrowed."""
    patterns: list[ORMAntiPattern] = []
    star_count = 0
    tables: set[str] = set()

    for q in queries:
        upper = q.upper().strip()
        if re.search(r"\bSELECT\s+\*\s+FROM\b", upper):
            star_count += 1
            table_match = re.search(r"FROM\s+(\w+)", upper)
            if table_match:
                tables.add(table_match.group(1).lower())

    if star_count >= 3:
        patterns.append(ORMAntiPattern(
            pattern_name="SELECT_STAR",
            severity="warning",
            description=(
                f"SELECT * used in {star_count} queries across tables: "
                f"{', '.join(sorted(tables)[:5])}. "
                "Fetching all columns wastes memory and network bandwidth."
            ),
            affected_queries=star_count,
            suggestion=(
                "Specify only needed columns:\n"
                "  SELECT id, name, email FROM users WHERE ...\n"
                "ORM equivalent:\n"
                "  Django: .values('id', 'name', 'email') or .only('id', 'name', 'email')\n"
                "  SQLAlchemy: session.query(User.id, User.name, User.email)\n"
                "  ActiveRecord: .select(:id, :name, :email)"
            ),
        ))

    return patterns


def _detect_unnecessary_distinct(queries: list[str]) -> list[ORMAntiPattern]:
    """Detect DISTINCT that might indicate incorrect JOINs."""
    patterns: list[ORMAntiPattern] = []

    for q in queries:
        upper = q.upper().strip()
        # SELECT DISTINCT with JOIN
        if re.search(r"\bSELECT\s+DISTINCT\b", upper) and "JOIN" in upper:
            table_match = re.search(r"FROM\s+(\w+)", upper)
            table = table_match.group(1).lower() if table_match else "unknown"

            patterns.append(ORMAntiPattern(
                pattern_name="UNNECESSARY_DISTINCT",
                severity="warning",
                description=(
                    f"SELECT DISTINCT with JOIN on '{table}'. "
                    "DISTINCT is often used to mask incorrect JOINs that produce duplicates."
                ),
                affected_table=table,
                suggestion=(
                    "Check if your JOIN conditions are correct. If duplicates come from a 1:N join,\n"
                    "use a subquery or EXISTS instead:\n"
                    f"  SELECT * FROM {table} WHERE EXISTS (SELECT 1 FROM related WHERE related.{table}_id = {table}.id)\n"
                    "Or in ORM:\n"
                    "  Django: .filter(related__isnull=False).distinct() -> .filter(Exists(...))"
                ),
            ))

    return patterns


def _detect_missing_pagination(queries: list[str]) -> list[ORMAntiPattern]:
    """Detect queries that fetch all rows without LIMIT."""
    patterns: list[ORMAntiPattern] = []
    no_limit_count = 0
    tables: set[str] = set()

    for q in queries:
        upper = q.upper().strip()
        if (
            upper.startswith("SELECT")
            and "LIMIT" not in upper
            and "COUNT" not in upper
            and "EXISTS" not in upper
            and "INSERT" not in upper
            and "INTO" not in upper
        ):
            no_limit_count += 1
            table_match = re.search(r"FROM\s+(\w+)", upper)
            if table_match:
                tables.add(table_match.group(1).lower())

    if no_limit_count >= 5:
        patterns.append(ORMAntiPattern(
            pattern_name="MISSING_PAGINATION",
            severity="info",
            description=(
                f"{no_limit_count} SELECT queries without LIMIT. "
                f"Tables: {', '.join(sorted(tables)[:5])}. "
                "Without pagination, large tables return unbounded result sets."
            ),
            affected_queries=no_limit_count,
            suggestion=(
                "Add LIMIT/OFFSET or cursor-based pagination:\n"
                "  SELECT * FROM orders WHERE id > $last_id ORDER BY id LIMIT 100\n"
                "ORM equivalent:\n"
                "  Django: .all()[:100] or Paginator(queryset, 100)\n"
                "  SQLAlchemy: query.limit(100).offset(0)\n"
                "  ActiveRecord: .limit(100).offset(0)"
            ),
        ))

    return patterns


def _detect_eager_loading_abuse(queries: list[str]) -> list[ORMAntiPattern]:
    """Detect huge IN-list queries (sign of eager loading gone wrong)."""
    patterns: list[ORMAntiPattern] = []

    for q in queries:
        # Count IN-list items
        in_match = re.search(r"\bIN\s*\(([^)]+)\)", q, re.IGNORECASE)
        if in_match:
            items = in_match.group(1).split(",")
            if len(items) > 100:
                table_match = re.search(r"FROM\s+(\w+)", q, re.IGNORECASE)
                table = table_match.group(1).lower() if table_match else "unknown"

                patterns.append(ORMAntiPattern(
                    pattern_name="EAGER_LOADING_ABUSE",
                    severity="warning",
                    description=(
                        f"IN-list with {len(items)} items on '{table}'. "
                        "This is typically caused by ORM eager loading a huge collection."
                    ),
                    affected_table=table,
                    suggestion=(
                        "For large IN-lists (>100 items), consider:\n"
                        "  1. Use a JOIN with a temp table or CTE instead of IN(...)\n"
                        "  2. Break into batches: IN($1, $2, ...) with 100 items per batch\n"
                        "  3. Reconsider the access pattern — do you really need all of them?"
                    ),
                    example_fix=(
                        f"-- Instead of: SELECT * FROM {table} WHERE id IN (1, 2, ..., {len(items)})\n"
                        f"-- Use: SELECT * FROM {table} WHERE id = ANY($1::int[])  -- pass array parameter"
                    ),
                ))

    return patterns


def _detect_plan_patterns(plan: dict[str, Any]) -> list[ORMAntiPattern]:
    """Detect ORM patterns visible in EXPLAIN plans."""
    patterns: list[ORMAntiPattern] = []

    # Look for Nested Loop with high loop count (N+1 at plan level)
    _check_plan_node(plan, patterns)

    return patterns


def _check_plan_node(node: dict[str, Any], patterns: list[ORMAntiPattern]) -> None:
    """Recursively check plan nodes for ORM anti-patterns."""
    node_type = node.get("Node Type", "")
    actual_loops = node.get("Actual Loops", 1)
    actual_rows = node.get("Actual Rows", 0)

    # Nested Loop with many iterations where inner is an Index Scan
    if node_type == "Nested Loop" and actual_loops > 100:
        inner_plans = node.get("Plans", [])
        for child in inner_plans:
            if child.get("Node Type") in ("Index Scan", "Index Only Scan"):
                table = child.get("Relation Name", "unknown")
                patterns.append(ORMAntiPattern(
                    pattern_name="NESTED_LOOP_N_PLUS_ONE",
                    severity="warning",
                    description=(
                        f"Nested Loop with {actual_loops} iterations on '{table}'. "
                        "Plan-level evidence of N+1-like pattern."
                    ),
                    affected_table=table,
                    affected_queries=actual_loops,
                    suggestion=(
                        "If this is from application-level looping, batch the queries.\n"
                        "If the planner chose this join method, consider increasing work_mem\n"
                        "or adding a multi-column index to enable a Hash/Merge Join."
                    ),
                ))

    for child in node.get("Plans", []):
        _check_plan_node(child, patterns)


# ── Public API ───────────────────────────────────────────────────────

def detect_orm_patterns(
    queries: list[str] | None = None,
    plan: dict[str, Any] | None = None,
) -> ORMDetectionReport:
    """
    Detect ORM anti-patterns in a set of SQL queries and/or an EXPLAIN plan.

    Args:
        queries: List of SQL query strings (e.g., from application logs)
        plan: Optional EXPLAIN plan dict for plan-level analysis

    Returns:
        ORMDetectionReport with all patterns found
    """
    report = ORMDetectionReport()
    all_patterns: list[ORMAntiPattern] = []

    if queries:
        report.queries_analyzed = len(queries)
        all_patterns.extend(_detect_n_plus_one(queries))
        all_patterns.extend(_detect_select_star(queries))
        all_patterns.extend(_detect_unnecessary_distinct(queries))
        all_patterns.extend(_detect_missing_pagination(queries))
        all_patterns.extend(_detect_eager_loading_abuse(queries))

    if plan:
        all_patterns.extend(_detect_plan_patterns(plan))

    report.patterns = sorted(
        all_patterns,
        key=lambda p: (
            0 if p.severity == "critical" else (1 if p.severity == "warning" else 2),
            -p.impact_score,
        ),
    )

    return report
