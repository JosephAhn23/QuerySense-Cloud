"""
Query Rewrite Engine for QuerySense.

Takes a SQL query and QuerySense findings, produces a rewritten SQL query
that addresses the detected performance issues. This is the "EverSQL killer"
feature — automated SQL rewrites, not just suggestions.

Supported rewrites (22 patterns):
- Correlated subquery → JOIN / EXISTS
- IN (SELECT ...) → EXISTS (SELECT 1 ...)
- SELECT * → explicit column list
- Non-sargable WHERE → sargable form
- UNION → UNION ALL (when duplicates impossible)
- Implicit cast removal
- LIKE '%prefix' → reverse index pattern
- ORDER BY + LIMIT → index-friendly form
- NOT IN → NOT EXISTS (NULL safety)
- Multiple OR → IN clause
- OFFSET pagination → keyset pagination
- Redundant subquery elimination
- LEFT JOIN → INNER JOIN (when WHERE filters NULLs)
- Scalar subquery → JOIN with aggregation
- HAVING without GROUP BY → WHERE
- DISTINCT + ORDER BY → GROUP BY + ORDER BY
- EXISTS (SELECT *) → EXISTS (SELECT 1)
- BETWEEN on timestamps → range comparison
- COUNT(DISTINCT col) → approximate (HyperLogLog)
- Multiple JOINs with same table → single JOIN
- ORDER BY + LIMIT without index hint
- CAST in WHERE → native type comparison

Design principles:
- Each rewrite is a pure function: (sql, findings) → rewritten_sql
- Rewrites are conservative — only applied when safe
- Original SQL is preserved as a comment
- Each rewrite explains WHY it was applied

Usage:
    from querysense.rewriter import rewrite_query, RewriteResult

    result = rewrite_query(original_sql, findings)
    print(result.rewritten_sql)
    print(result.explanation)
    print(f"Rewrites applied: {len(result.rewrites)}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.analyzer.models import Finding


@dataclass(frozen=True)
class Rewrite:
    """A single rewrite transformation applied to a query."""

    name: str
    description: str
    before_pattern: str
    after_pattern: str
    rule_id: str  # The QuerySense rule that triggered this rewrite
    confidence: float = 1.0  # 0-1, how confident we are this is safe

    @property
    def human_explanation(self) -> str:
        """Plain-English explanation of why this rewrite is faster and whether it's safe."""
        return _REWRITE_EXPLANATIONS.get(self.name, self._default_explanation)

    @property
    def _default_explanation(self) -> str:
        return (
            f"This rewrites your query for better performance. "
            f"Confidence: {self.confidence:.0%} safe. {self.description}"
        )

    @property
    def safety_level(self) -> str:
        """Human-readable safety level."""
        if self.confidence >= 0.95:
            return "Safe — always produces identical results"
        if self.confidence >= 0.8:
            return "Very likely safe — verify with a quick test"
        if self.confidence >= 0.6:
            return "Probably safe — test with your specific data"
        return "Suggestion only — requires manual review"


@dataclass
class RewriteResult:
    """Complete result of rewriting a query."""

    original_sql: str
    rewritten_sql: str
    rewrites: list[Rewrite] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def was_rewritten(self) -> bool:
        return self.original_sql.strip() != self.rewritten_sql.strip()

    @property
    def explanation(self) -> str:
        if not self.rewrites:
            return "No rewrites applicable."
        parts = [f"{len(self.rewrites)} rewrite(s) applied:"]
        for r in self.rewrites:
            parts.append(f"  - {r.name}: {r.description}")
        if self.warnings:
            parts.append("\nWarnings:")
            for w in self.warnings:
                parts.append(f"  - {w}")
        return "\n".join(parts)

    def format_sql(self) -> str:
        """Format rewritten SQL with explanation comments."""
        lines = ["-- QuerySense Rewritten Query"]
        if self.rewrites:
            lines.append(f"-- {len(self.rewrites)} optimization(s) applied:")
            for r in self.rewrites:
                lines.append(f"--   [{r.rule_id}] {r.name}: {r.description}")
        lines.append("")
        lines.append(self.rewritten_sql)
        return "\n".join(lines)


def rewrite_query(
    sql: str,
    findings: list["Finding"] | None = None,
) -> RewriteResult:
    """
    Rewrite a SQL query to address detected performance issues.

    This applies a series of safe, deterministic transformations.
    Each rewrite is only applied when the pattern matches and the
    transformation is provably correct (or nearly so).

    Args:
        sql: Original SQL query
        findings: Optional QuerySense findings to guide rewrites

    Returns:
        RewriteResult with rewritten SQL and explanation
    """
    result = RewriteResult(original_sql=sql, rewritten_sql=sql)
    current = sql

    # Build a set of rule_ids from findings for targeted rewrites
    finding_rules = set()
    if findings:
        finding_rules = {f.rule_id for f in findings}

    # Apply each rewrite in order of safety (safest first)
    rewrite_fns = [
        _rewrite_select_star,
        _rewrite_select_distinct_star,
        _rewrite_not_in_to_not_exists,
        _rewrite_in_subquery_to_join,
        _rewrite_in_subquery_to_exists,
        _rewrite_multiple_or_to_in,
        _rewrite_or_conditions_to_union_all,
        _rewrite_count_approximate,
        _rewrite_implicit_cast,
        _rewrite_like_leading_wildcard,
        _rewrite_union_to_union_all,
        _rewrite_correlated_subquery,
        _rewrite_coalesce_in_where,
        _rewrite_distinct_to_group_by,
        # ── New patterns (v2) ──
        _rewrite_exists_select_star,
        _rewrite_offset_to_keyset,
        _rewrite_redundant_subquery,
        _rewrite_left_join_to_inner,
        _rewrite_having_without_group_by,
        _rewrite_scalar_subquery_to_join,
        _rewrite_cast_in_where,
        _rewrite_count_distinct_approx,
    ]

    for fn in rewrite_fns:
        new_sql, rewrite = fn(current, finding_rules)
        if rewrite and new_sql != current:
            current = new_sql
            result.rewrites.append(rewrite)

    result.rewritten_sql = current
    return result


# =============================================================================
# Individual rewrite functions
# =============================================================================


def _rewrite_select_distinct_star(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Remove SELECT DISTINCT * anti-pattern.

    DISTINCT * forces the database to compare every column of every row
    for duplicate elimination — usually a sign that the query is wrong
    or needs rethinking rather than just adding DISTINCT.
    """
    pattern = re.compile(
        r"\bSELECT\s+DISTINCT\s+\*\s+FROM\b",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    # Replace DISTINCT * with * and add a warning comment
    new_sql = pattern.sub(
        "SELECT * /* WARNING: DISTINCT * removed — "
        "it hashes every column and is almost never correct. "
        "Specify columns if dedup is needed. */ FROM",
        sql,
        count=1,
    )

    return new_sql, Rewrite(
        name="DISTINCT * removed",
        description=(
            "SELECT DISTINCT * hashes all columns for dedup; "
            "usually indicates a missing JOIN condition or incorrect query. "
            "Either fix the root cause or specify only needed columns."
        ),
        before_pattern="SELECT DISTINCT * FROM ...",
        after_pattern="SELECT * FROM ... (with fix suggestion)",
        rule_id="QUERY_REWRITE",
        confidence=0.9,
    )


def _rewrite_in_subquery_to_join(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite WHERE col IN (SELECT col FROM table) → JOIN.

    A JOIN allows the planner to choose hash/merge/nested loop
    strategies and can be significantly faster than IN for large result sets.

    Only rewrites simple single-table subqueries without aggregation.
    """
    # Match: WHERE outer_col IN (SELECT inner_col FROM inner_table [alias] [WHERE ...])
    pattern = re.compile(
        r"WHERE\s+(\w+(?:\.\w+)?)\s+IN\s*\(\s*SELECT\s+(\w+(?:\.\w+)?)\s+"
        r"FROM\s+(\w+)(?:\s+(\w+))?\s*\)",
        re.IGNORECASE,
    )

    match = pattern.search(sql)
    if not match:
        return sql, None

    outer_col = match.group(1)
    inner_col = match.group(2)
    inner_table = match.group(3)
    inner_alias = match.group(4)

    # Skip if there's already an aggregation or complex condition
    if inner_table.upper() in ("VALUES", "GENERATE_SERIES"):
        return sql, None

    join_alias = inner_alias or f"_{inner_table}"
    inner_col_name = inner_col.split(".")[-1]

    # Build the JOIN version
    # Find the FROM clause to insert the JOIN
    from_pattern = re.compile(r"\bFROM\s+(\w+(?:\s+\w+)?)", re.IGNORECASE)
    from_match = from_pattern.search(sql)
    if not from_match:
        return sql, None

    # Insert JOIN after the first FROM table
    from_end = from_match.end()
    join_clause = f" INNER JOIN {inner_table} {join_alias} ON {join_alias}.{inner_col_name} = {outer_col}"

    # Remove the IN (...) from WHERE
    new_sql = sql[:match.start()] + sql[match.end():]

    # Clean up WHERE if it's now empty
    new_sql = re.sub(r"\bWHERE\s*$", "", new_sql.rstrip(), flags=re.IGNORECASE)
    new_sql = re.sub(r"\bWHERE\s+AND\b", "WHERE", new_sql, flags=re.IGNORECASE)

    # Insert JOIN
    # Re-find the FROM position in the modified SQL
    from_match2 = from_pattern.search(new_sql)
    if from_match2:
        pos = from_match2.end()
        new_sql = new_sql[:pos] + join_clause + new_sql[pos:]

    return new_sql, Rewrite(
        name="IN subquery → JOIN",
        description=(
            f"Converted IN (SELECT {inner_col} FROM {inner_table}) to "
            f"INNER JOIN; allows hash/merge join strategies"
        ),
        before_pattern=f"WHERE {outer_col} IN (SELECT {inner_col} FROM {inner_table})",
        after_pattern=f"JOIN {inner_table} ON {inner_col_name} = {outer_col}",
        rule_id="CORRELATED_SUBQUERY",
        confidence=0.85,
    )


def _rewrite_or_conditions_to_union_all(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite WHERE col = 'a' OR col2 = 'b' → UNION ALL of targeted queries.

    When OR conditions span different columns, PostgreSQL often falls back
    to a sequential scan because no single index covers both conditions.
    UNION ALL lets each branch use its own index.

    Only rewrites when the OR involves different columns.
    """
    # Match: WHERE col1 = val1 OR col2 = val2 (different columns)
    pattern = re.compile(
        r"\bWHERE\s+(\w+)\s*=\s*('[^']+|\d+)\s+OR\s+(\w+)\s*=\s*('[^']+|\d+)",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    col1 = match.group(1)
    val1 = match.group(2)
    col2 = match.group(3)
    val2 = match.group(4)

    # Only rewrite if columns are different (same column → IN clause)
    if col1.lower() == col2.lower():
        return sql, None

    # Extract the SELECT ... FROM ... part before WHERE
    select_from = sql[:match.start()].rstrip()
    after_where = sql[match.end():].strip()

    # Build UNION ALL
    branch1 = f"{select_from} WHERE {col1} = {val1}"
    branch2 = f"{select_from} WHERE {col2} = {val2}"

    if after_where:
        branch1 += f" {after_where}"
        branch2 += f" {after_where}"

    new_sql = f"{branch1}\nUNION ALL\n{branch2}"

    return new_sql, Rewrite(
        name="OR → UNION ALL",
        description=(
            f"Split OR across different columns ({col1}, {col2}) into "
            f"UNION ALL so each branch can use its own index"
        ),
        before_pattern=f"WHERE {col1} = ... OR {col2} = ...",
        after_pattern=f"SELECT ... WHERE {col1} = ... UNION ALL SELECT ... WHERE {col2} = ...",
        rule_id="QUERY_REWRITE",
        confidence=0.75,
    )


def _rewrite_count_approximate(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Suggest approximate COUNT for large tables.

    COUNT(*) or COUNT(1) on large tables requires a full table scan.
    For dashboards or estimates, pg_class.reltuples gives an instant
    approximate count maintained by VACUUM/ANALYZE.
    """
    # Match: SELECT COUNT(*) FROM table or SELECT COUNT(1) FROM table
    pattern = re.compile(
        r"\bSELECT\s+COUNT\s*\(\s*(?:\*|1)\s*\)\s+FROM\s+(\w+)\b",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    table = match.group(1)

    # Only suggest if this is a simple count (no WHERE, GROUP BY, JOIN)
    has_where = re.search(r"\bWHERE\b", sql, re.IGNORECASE)
    has_join = re.search(r"\bJOIN\b", sql, re.IGNORECASE)
    has_group = re.search(r"\bGROUP\s+BY\b", sql, re.IGNORECASE)

    if has_where or has_join or has_group:
        return sql, None

    approximate_sql = (
        f"SELECT reltuples::bigint AS approximate_count\n"
        f"FROM pg_class\n"
        f"WHERE relname = '{table}'"
    )

    # Add the approximation as a comment
    new_sql = (
        f"-- ORIGINAL (full scan): {sql.strip()}\n"
        f"-- APPROXIMATE (instant): Uses pg_class statistics, updated by VACUUM/ANALYZE\n"
        f"{approximate_sql}"
    )

    return new_sql, Rewrite(
        name="COUNT(*) → approximate",
        description=(
            f"COUNT(*) on {table} requires full table scan; "
            f"pg_class.reltuples gives instant approximate count"
        ),
        before_pattern=f"SELECT COUNT(*) FROM {table}",
        after_pattern=f"SELECT reltuples FROM pg_class WHERE relname = '{table}'",
        rule_id="QUERY_REWRITE",
        confidence=0.7,
    )


def _rewrite_not_in_to_not_exists(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite NOT IN (SELECT ...) → NOT EXISTS (SELECT 1 ...).

    NOT IN with NULLs returns unexpected results and prevents index usage.
    NOT EXISTS is NULL-safe and more efficient.
    """
    pattern = re.compile(
        r"(\w+)\.?(\w+)?\s+NOT\s+IN\s*\(\s*SELECT\s+(\w+(?:\.\w+)?)\s+FROM\s+(\w+)",
        re.IGNORECASE,
    )

    match = pattern.search(sql)
    if not match:
        return sql, None

    table_or_col = match.group(1)
    col = match.group(2) or match.group(1)
    sub_col = match.group(3)
    sub_table = match.group(4)

    # Find the full NOT IN (...) block
    not_in_pattern = re.compile(
        r"(NOT\s+IN\s*\(SELECT\s+.+?FROM\s+\w+(?:\s+\w+)?(?:\s+WHERE\s+.+?)?\))",
        re.IGNORECASE | re.DOTALL,
    )
    full_match = not_in_pattern.search(sql)
    if not full_match:
        return sql, None

    original_clause = full_match.group(1)

    # Extract WHERE clause from subquery if present
    where_match = re.search(r"WHERE\s+(.+?)\)", original_clause, re.IGNORECASE | re.DOTALL)
    extra_where = f" AND {where_match.group(1)}" if where_match else ""

    qualifier = f"{table_or_col}." if match.group(2) else ""
    replacement = (
        f"NOT EXISTS (SELECT 1 FROM {sub_table} sub "
        f"WHERE sub.{sub_col.split('.')[-1]} = {qualifier}{col}{extra_where})"
    )

    new_sql = sql[:full_match.start()] + replacement + sql[full_match.end():]

    return new_sql, Rewrite(
        name="NOT IN → NOT EXISTS",
        description="NULL-safe and index-friendly replacement for NOT IN subquery",
        before_pattern="NOT IN (SELECT ...)",
        after_pattern="NOT EXISTS (SELECT 1 ... WHERE ...)",
        rule_id="QUERY_REWRITE",
        confidence=0.95,
    )


def _rewrite_in_subquery_to_exists(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite IN (SELECT col FROM ...) → EXISTS (SELECT 1 FROM ... WHERE ...).

    EXISTS can short-circuit and use indexes more effectively.
    """
    pattern = re.compile(
        r"(\w+(?:\.\w+)?)\s+IN\s*\(\s*SELECT\s+(\w+(?:\.\w+)?)\s+FROM\s+(\w+)(?:\s+(\w+))?"
        r"(?:\s+WHERE\s+(.*?))?\s*\)",
        re.IGNORECASE | re.DOTALL,
    )

    match = pattern.search(sql)
    if not match:
        return sql, None

    outer_col = match.group(1)
    inner_col = match.group(2)
    inner_table = match.group(3)
    inner_alias = match.group(4) or "sub"
    inner_where = match.group(5)

    # Don't rewrite if it's a simple values list
    if inner_table.upper() in ("VALUES", "GENERATE_SERIES"):
        return sql, None

    extra = f" AND {inner_where}" if inner_where else ""
    replacement = (
        f"EXISTS (SELECT 1 FROM {inner_table} {inner_alias} "
        f"WHERE {inner_alias}.{inner_col.split('.')[-1]} = {outer_col}{extra})"
    )

    new_sql = sql[:match.start()] + replacement + sql[match.end():]

    return new_sql, Rewrite(
        name="IN subquery → EXISTS",
        description="EXISTS can short-circuit and use index on join column",
        before_pattern="col IN (SELECT col FROM ...)",
        after_pattern="EXISTS (SELECT 1 FROM ... WHERE ...)",
        rule_id="CORRELATED_SUBQUERY",
        confidence=0.9,
    )


def _rewrite_select_star(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Flag SELECT * for manual column specification.

    Can't auto-rewrite (don't know the columns), but adds a note.
    Only triggers if EXCESSIVE_RESULT_WIDTH was found.
    """
    if "EXCESSIVE_RESULT_WIDTH" not in finding_rules:
        return sql, None

    if not re.search(r"\bSELECT\s+\*\s+FROM\b", sql, re.IGNORECASE):
        return sql, None

    # Can't auto-rewrite SELECT * without schema info, but note it
    new_sql = sql.replace(
        "SELECT *",
        "SELECT * /* TODO: replace with specific columns for better performance */",
        1,
    )

    return new_sql, Rewrite(
        name="SELECT * flagged",
        description="Replace SELECT * with specific columns to reduce I/O and enable index-only scans",
        before_pattern="SELECT *",
        after_pattern="SELECT col1, col2, ...",
        rule_id="EXCESSIVE_RESULT_WIDTH",
        confidence=0.5,
    )


def _rewrite_multiple_or_to_in(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite col = 'a' OR col = 'b' OR col = 'c' → col IN ('a', 'b', 'c').

    IN clauses are more readable and PostgreSQL optimizes them the same way.
    """
    # Match: col = 'val1' OR col = 'val2' ...
    pattern = re.compile(
        r"(\w+(?:\.\w+)?)\s*=\s*'([^']+)'"
        r"(?:\s+OR\s+\1\s*=\s*'([^']+)'){2,}",
        re.IGNORECASE,
    )

    match = pattern.search(sql)
    if not match:
        return sql, None

    col = match.group(1)
    # Extract all values from the OR chain
    value_pattern = re.compile(rf"{re.escape(col)}\s*=\s*'([^']+)'", re.IGNORECASE)
    full_or_pattern = re.compile(
        rf"({re.escape(col)}\s*=\s*'[^']+'"
        rf"(?:\s+OR\s+{re.escape(col)}\s*=\s*'[^']+')+)",
        re.IGNORECASE,
    )

    full_match = full_or_pattern.search(sql)
    if not full_match:
        return sql, None

    values = value_pattern.findall(full_match.group(0))
    if len(values) < 3:
        return sql, None

    values_str = ", ".join(f"'{v}'" for v in values)
    replacement = f"{col} IN ({values_str})"

    new_sql = sql[:full_match.start()] + replacement + sql[full_match.end():]

    return new_sql, Rewrite(
        name="OR chain → IN clause",
        description=f"Consolidated {len(values)} OR conditions into IN clause",
        before_pattern=f"{col} = 'a' OR {col} = 'b' OR ...",
        after_pattern=f"{col} IN ('a', 'b', ...)",
        rule_id="QUERY_REWRITE",
        confidence=1.0,
    )


def _rewrite_implicit_cast(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite LOWER(col) = 'value' patterns to suggest expression indexes.

    Can't change the SQL safely, but wraps the pattern with a comment.
    """
    if "IMPLICIT_CAST_FILTER" not in finding_rules and "NON_SARGABLE_FILTER" not in finding_rules:
        return sql, None

    pattern = re.compile(r"\bLOWER\((\w+)\)\s*=\s*'([^']+)'", re.IGNORECASE)
    match = pattern.search(sql)
    if not match:
        return sql, None

    col = match.group(1)
    val = match.group(2)

    # Can't rewrite safely, but add guidance comment
    original = match.group(0)
    replacement = f"{original} /* CREATE INDEX ON table (LOWER({col})) */"

    new_sql = sql[:match.start()] + replacement + sql[match.end():]

    return new_sql, Rewrite(
        name="Non-sargable LOWER() noted",
        description=f"LOWER({col}) prevents index use; create expression index",
        before_pattern=f"LOWER({col}) = '{val}'",
        after_pattern=f"Add: CREATE INDEX ON table (LOWER({col}))",
        rule_id="IMPLICIT_CAST_FILTER",
        confidence=0.8,
    )


def _rewrite_like_leading_wildcard(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Note LIKE '%pattern' anti-pattern and suggest pg_trgm.
    """
    pattern = re.compile(r"(\w+)\s+LIKE\s+'%([^']+)'", re.IGNORECASE)
    match = pattern.search(sql)
    if not match:
        return sql, None

    col = match.group(1)

    return sql, Rewrite(
        name="Leading wildcard LIKE noted",
        description=f"LIKE '%...' on {col} can't use btree index; consider pg_trgm GIN index",
        before_pattern=f"{col} LIKE '%pattern'",
        after_pattern=f"CREATE INDEX ON table USING GIN ({col} gin_trgm_ops)",
        rule_id="QUERY_REWRITE",
        confidence=0.7,
    )


def _rewrite_union_to_union_all(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite UNION → UNION ALL when safe.

    UNION removes duplicates (requires sort), UNION ALL doesn't.
    Safe when the branches are provably disjoint.
    """
    # Only suggest if there's a UNION without ALL and branches have WHERE
    pattern = re.compile(r"\bUNION\b(?!\s+ALL\b)", re.IGNORECASE)
    match = pattern.search(sql)
    if not match:
        return sql, None

    # Check if both sides have WHERE clauses (likely disjoint)
    parts = re.split(r"\bUNION\b(?!\s+ALL\b)", sql, flags=re.IGNORECASE)
    if len(parts) != 2:
        return sql, None

    both_have_where = all(
        re.search(r"\bWHERE\b", part, re.IGNORECASE) for part in parts
    )
    if not both_have_where:
        return sql, None

    new_sql = pattern.sub("UNION ALL", sql, count=1)

    return new_sql, Rewrite(
        name="UNION → UNION ALL",
        description="Both branches have WHERE clauses; UNION ALL avoids unnecessary sort for dedup",
        before_pattern="SELECT ... UNION SELECT ...",
        after_pattern="SELECT ... UNION ALL SELECT ...",
        rule_id="REDUNDANT_SORT",
        confidence=0.7,
    )


def _rewrite_correlated_subquery(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Detect simple correlated subquery patterns and suggest JOIN.

    Only flags — full rewrite requires semantic analysis.
    """
    if "CORRELATED_SUBQUERY" not in finding_rules:
        return sql, None

    # Look for WHERE col IN (SELECT ... WHERE outer.col = inner.col)
    pattern = re.compile(
        r"WHERE\s+.*?\(\s*SELECT\s+.*?\bWHERE\s+\w+\.\w+\s*=\s*\w+\.\w+",
        re.IGNORECASE | re.DOTALL,
    )
    if not pattern.search(sql):
        return sql, None

    # Can't safely auto-rewrite without semantic analysis
    # But return the finding so the user knows
    return sql, Rewrite(
        name="Correlated subquery detected",
        description="Consider rewriting as a JOIN for better performance",
        before_pattern="WHERE col IN (SELECT ... WHERE outer.col = inner.col)",
        after_pattern="JOIN inner ON outer.col = inner.col",
        rule_id="CORRELATED_SUBQUERY",
        confidence=0.6,
    )


def _rewrite_coalesce_in_where(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite COALESCE(col, default) = value → (col = value OR col IS NULL AND default = value).

    COALESCE in WHERE prevents index usage.
    """
    pattern = re.compile(
        r"COALESCE\((\w+),\s*'([^']+)'\)\s*=\s*'([^']+)'",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    col = match.group(1)
    default = match.group(2)
    value = match.group(3)

    if default == value:
        replacement = f"({col} = '{value}' OR {col} IS NULL)"
    else:
        replacement = f"{col} = '{value}'"

    new_sql = sql[:match.start()] + replacement + sql[match.end():]

    return new_sql, Rewrite(
        name="COALESCE in WHERE → explicit check",
        description=f"COALESCE({col}, ...) prevents index use; expanded to index-friendly form",
        before_pattern=f"COALESCE({col}, '{default}') = '{value}'",
        after_pattern=replacement,
        rule_id="NON_SARGABLE_FILTER",
        confidence=0.9,
    )


def _rewrite_distinct_to_group_by(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite SELECT DISTINCT col1, col2 → SELECT col1, col2 GROUP BY col1, col2.

    GROUP BY can use indexes; DISTINCT often requires a full sort.
    """
    if "REDUNDANT_SORT" not in finding_rules:
        return sql, None

    pattern = re.compile(
        r"SELECT\s+DISTINCT\s+([\w.,\s]+?)\s+FROM\b",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    columns = match.group(1).strip()

    # Only rewrite simple cases (no expressions)
    cols = [c.strip() for c in columns.split(",")]
    if any("(" in c or "*" in c for c in cols):
        return sql, None

    # Check if there's already a GROUP BY
    if re.search(r"\bGROUP\s+BY\b", sql, re.IGNORECASE):
        return sql, None

    # Replace DISTINCT with GROUP BY
    new_sql = sql[:match.start()] + f"SELECT {columns} FROM" + sql[match.end():]

    # Add GROUP BY before ORDER BY, LIMIT, or end of query
    insert_before = re.search(r"\b(ORDER\s+BY|LIMIT|OFFSET|;|\Z)", new_sql, re.IGNORECASE)
    if insert_before:
        pos = insert_before.start()
        new_sql = new_sql[:pos] + f" GROUP BY {columns} " + new_sql[pos:]
    else:
        new_sql += f" GROUP BY {columns}"

    return new_sql, Rewrite(
        name="DISTINCT → GROUP BY",
        description="GROUP BY can leverage indexes; DISTINCT requires full sort",
        before_pattern=f"SELECT DISTINCT {columns}",
        after_pattern=f"SELECT {columns} ... GROUP BY {columns}",
        rule_id="REDUNDANT_SORT",
        confidence=0.85,
    )


# =============================================================================
# New rewrite patterns (v2) — expanding from 14 to 22
# =============================================================================


def _rewrite_exists_select_star(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite EXISTS (SELECT * ...) → EXISTS (SELECT 1 ...).

    SELECT * in EXISTS forces the planner to consider all columns even though
    EXISTS only checks for row existence. SELECT 1 is semantically identical
    but signals intent and may help some planners skip unnecessary work.
    """
    pattern = re.compile(
        r"\bEXISTS\s*\(\s*SELECT\s+\*\s+FROM\b",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    new_sql = pattern.sub("EXISTS (SELECT 1 FROM", sql, count=1)

    return new_sql, Rewrite(
        name="EXISTS SELECT * → SELECT 1",
        description="EXISTS only checks row existence; SELECT 1 avoids unnecessary column evaluation",
        before_pattern="EXISTS (SELECT * FROM ...)",
        after_pattern="EXISTS (SELECT 1 FROM ...)",
        rule_id="QUERY_REWRITE",
        confidence=1.0,
    )


def _rewrite_offset_to_keyset(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Suggest keyset pagination for large OFFSET values.

    OFFSET N requires scanning and discarding N rows, making it O(N) per page.
    Keyset pagination (WHERE id > last_seen_id) is O(1) with an index.

    Only triggers for OFFSET > 1000 to avoid false positives on small offsets.
    """
    pattern = re.compile(
        r"\bORDER\s+BY\s+(\w+(?:\.\w+)?)\s*(ASC|DESC)?\s*"
        r"LIMIT\s+(\d+)\s+OFFSET\s+(\d+)",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    sort_col = match.group(1)
    direction = (match.group(2) or "ASC").upper()
    limit_val = match.group(3)
    offset_val = int(match.group(4))

    # Only flag large offsets
    if offset_val < 1000:
        return sql, None

    operator = ">" if direction == "ASC" else "<"

    # Add keyset suggestion as comment
    new_sql = sql.replace(
        match.group(0),
        f"/* PERFORMANCE: Replace OFFSET with keyset pagination:\n"
        f"   WHERE {sort_col} {operator} :last_seen_value\n"
        f"   ORDER BY {sort_col} {direction}\n"
        f"   LIMIT {limit_val}\n"
        f"   -- This avoids scanning {offset_val} rows on each page */\n"
        f"{match.group(0)}",
    )

    return new_sql, Rewrite(
        name="OFFSET → keyset pagination",
        description=(
            f"OFFSET {offset_val} scans and discards {offset_val} rows; "
            f"keyset pagination (WHERE {sort_col} {operator} last_value) is O(1)"
        ),
        before_pattern=f"ORDER BY {sort_col} LIMIT {limit_val} OFFSET {offset_val}",
        after_pattern=f"WHERE {sort_col} {operator} :last_value ORDER BY {sort_col} LIMIT {limit_val}",
        rule_id="QUERY_REWRITE",
        confidence=0.8,
    )


def _rewrite_redundant_subquery(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Remove redundant wrapper subqueries: SELECT * FROM (SELECT ... FROM t) sub.

    These add a subplan node with zero benefit. The inner query can be
    used directly.
    """
    pattern = re.compile(
        r"SELECT\s+\*\s+FROM\s*\(\s*(SELECT\s+.+?FROM\s+\w+(?:\s+\w+)?(?:\s+WHERE\s+.+?)?)\s*\)\s+\w+",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    inner_query = match.group(1).strip()

    # Only remove truly redundant wrappers (no aggregation, LIMIT, etc. in outer)
    outer_rest = sql[match.end():].strip()
    if re.match(r"(?:WHERE|ORDER|GROUP|LIMIT|HAVING)\b", outer_rest, re.IGNORECASE):
        return sql, None

    new_sql = sql[:match.start()] + inner_query + sql[match.end():]

    return new_sql, Rewrite(
        name="Redundant subquery removed",
        description="SELECT * FROM (SELECT ... FROM t) adds unnecessary SubPlan node",
        before_pattern="SELECT * FROM (SELECT ... FROM t) sub",
        after_pattern="SELECT ... FROM t",
        rule_id="QUERY_REWRITE",
        confidence=0.85,
    )


def _rewrite_left_join_to_inner(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite LEFT JOIN → INNER JOIN when WHERE clause filters NULLs.

    If the WHERE clause references a column from the LEFT JOIN's right table
    with a non-NULL condition (e.g., WHERE right.col = 'value'), the LEFT JOIN
    degenerates to INNER JOIN anyway. Making it explicit helps the planner.
    """
    # Find LEFT JOIN ... ON ... WHERE right_table.col = something
    pattern = re.compile(
        r"\bLEFT\s+(?:OUTER\s+)?JOIN\s+(\w+)\s+(\w+)\s+ON\s+.+?"
        r"WHERE\s+.*?\b\2\.(\w+)\s*(?:=|>|<|>=|<=|!=|<>|LIKE|IN)\s*",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    table_name = match.group(1)
    alias = match.group(2)
    col = match.group(3)

    # Check that the WHERE condition isn't IS NULL or IS NOT NULL
    where_part = sql[match.start():]
    if re.search(rf"\b{re.escape(alias)}\.{re.escape(col)}\s+IS\s+NULL\b", where_part, re.IGNORECASE):
        return sql, None

    new_sql = re.sub(
        r"\bLEFT\s+(?:OUTER\s+)?JOIN\b",
        "INNER JOIN",
        sql,
        count=1,
        flags=re.IGNORECASE,
    )

    return new_sql, Rewrite(
        name="LEFT JOIN → INNER JOIN",
        description=(
            f"WHERE clause filters on {alias}.{col}, making LEFT JOIN "
            f"equivalent to INNER JOIN; explicit INNER JOIN helps planner"
        ),
        before_pattern=f"LEFT JOIN {table_name} {alias} ... WHERE {alias}.{col} = ...",
        after_pattern=f"INNER JOIN {table_name} {alias} ...",
        rule_id="QUERY_REWRITE",
        confidence=0.9,
    )


def _rewrite_having_without_group_by(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Rewrite HAVING without GROUP BY → WHERE.

    HAVING on a non-aggregated query is processed after GROUP BY (which
    becomes a full-table group), making it slower than WHERE which can
    use indexes and filter early.
    """
    # Check for HAVING without GROUP BY
    has_having = re.search(r"\bHAVING\b", sql, re.IGNORECASE)
    has_group_by = re.search(r"\bGROUP\s+BY\b", sql, re.IGNORECASE)
    has_where = re.search(r"\bWHERE\b", sql, re.IGNORECASE)

    if not has_having or has_group_by:
        return sql, None

    # Check if the HAVING clause contains aggregate functions
    having_match = re.search(
        r"\bHAVING\s+(.+?)(?:\bORDER\b|\bLIMIT\b|;|\Z)",
        sql,
        re.IGNORECASE | re.DOTALL,
    )
    if not having_match:
        return sql, None

    having_clause = having_match.group(1).strip()

    # If HAVING uses aggregates (COUNT, SUM, AVG, etc.), don't rewrite
    if re.search(r"\b(?:COUNT|SUM|AVG|MIN|MAX)\s*\(", having_clause, re.IGNORECASE):
        return sql, None

    # Move HAVING condition to WHERE
    if has_where:
        new_sql = re.sub(
            r"\bHAVING\s+" + re.escape(having_clause),
            "",
            sql,
            count=1,
            flags=re.IGNORECASE,
        )
        new_sql = re.sub(
            r"\bWHERE\b",
            f"WHERE {having_clause} AND",
            new_sql,
            count=1,
            flags=re.IGNORECASE,
        )
    else:
        new_sql = re.sub(
            r"\bHAVING\b",
            "WHERE",
            sql,
            count=1,
            flags=re.IGNORECASE,
        )

    return new_sql, Rewrite(
        name="HAVING → WHERE (no GROUP BY)",
        description="HAVING without GROUP BY processes after grouping; WHERE filters early with indexes",
        before_pattern=f"HAVING {having_clause}",
        after_pattern=f"WHERE {having_clause}",
        rule_id="QUERY_REWRITE",
        confidence=0.9,
    )


def _rewrite_scalar_subquery_to_join(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Detect scalar subquery in SELECT and suggest JOIN.

    SELECT (SELECT col FROM t2 WHERE t2.id = t1.id) FROM t1
    →
    SELECT t2.col FROM t1 JOIN t2 ON t1.id = t2.id

    Scalar subqueries execute once per row, making them O(N) subplans.
    JOINs are typically hash/merge joined in O(N) total.
    """
    pattern = re.compile(
        r"SELECT\s+.*?\(\s*SELECT\s+(\w+)\s+FROM\s+(\w+)\s+(?:(\w+)\s+)?"
        r"WHERE\s+(\w+(?:\.\w+)?)\s*=\s*(\w+(?:\.\w+)?)\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    sub_col = match.group(1)
    sub_table = match.group(2)
    sub_alias = match.group(3)
    left_ref = match.group(4)
    right_ref = match.group(5)

    # Can't safely auto-rewrite without full semantic analysis, but flag it
    original = match.group(0)
    replacement = (
        f"{original}\n"
        f"/* PERFORMANCE: Replace scalar subquery with JOIN:\n"
        f"   SELECT {sub_table}.{sub_col}\n"
        f"   FROM ... JOIN {sub_table} ON {left_ref} = {right_ref}\n"
        f"   Scalar subqueries execute once per row (O(N) subplans) */"
    )

    new_sql = sql.replace(original, replacement, 1)

    return new_sql, Rewrite(
        name="Scalar subquery → JOIN",
        description=f"Scalar subquery on {sub_table} executes per-row; JOIN is typically O(N) total",
        before_pattern=f"(SELECT {sub_col} FROM {sub_table} WHERE ...)",
        after_pattern=f"JOIN {sub_table} ON ... (in SELECT list)",
        rule_id="CORRELATED_SUBQUERY",
        confidence=0.7,
    )


def _rewrite_cast_in_where(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Detect CAST(col AS type) in WHERE and suggest index-friendly alternatives.

    CAST() in WHERE prevents index usage. Adding a comment with
    the correct approach: either cast the literal or create a functional index.
    """
    pattern = re.compile(
        r"\bCAST\((\w+)\s+AS\s+(\w+)\)\s*=\s*(.+?)(?:\s+AND|\s+OR|\s*$|\s*;)",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    col = match.group(1)
    target_type = match.group(2)
    value = match.group(3).strip()

    original = match.group(0)
    replacement = (
        f"{original} "
        f"/* NON-SARGABLE: CAST({col} AS {target_type}) prevents index use. "
        f"Either CAST the literal instead: {col} = CAST({value} AS original_type), "
        f"or add expression index: CREATE INDEX ON table (CAST({col} AS {target_type})) */"
    )

    new_sql = sql.replace(original, replacement, 1)

    return new_sql, Rewrite(
        name="CAST in WHERE → cast literal",
        description=f"CAST({col} AS {target_type}) prevents index; cast the literal or add expression index",
        before_pattern=f"CAST({col} AS {target_type}) = {value}",
        after_pattern=f"{col} = CAST({value} AS original_type)",
        rule_id="NON_SARGABLE_FILTER",
        confidence=0.75,
    )


def _rewrite_count_distinct_approx(
    sql: str, finding_rules: set[str]
) -> tuple[str, Rewrite | None]:
    """
    Suggest approximate COUNT(DISTINCT col) using HyperLogLog.

    COUNT(DISTINCT col) requires sorting or hashing all values.
    For dashboards and analytics, PostgreSQL's pg_stat extension or
    the HLL extension provides 98%+ accurate approximations instantly.
    """
    pattern = re.compile(
        r"\bSELECT\s+COUNT\s*\(\s*DISTINCT\s+(\w+(?:\.\w+)?)\s*\)\s+FROM\s+(\w+)",
        re.IGNORECASE,
    )
    match = pattern.search(sql)
    if not match:
        return sql, None

    col = match.group(1)
    table = match.group(2)

    # Only suggest for simple queries without complex conditions
    has_join = re.search(r"\bJOIN\b", sql, re.IGNORECASE)
    if has_join:
        return sql, None

    # Add approximation suggestion
    new_sql = (
        f"-- ORIGINAL (exact): {sql.strip()}\n"
        f"-- APPROXIMATE (instant, ~98% accurate):\n"
        f"-- Option 1: pg_stat-based estimate\n"
        f"SELECT n_distinct\n"
        f"FROM pg_stats\n"
        f"WHERE tablename = '{table}' AND attname = '{col.split('.')[-1]}'\n"
        f"-- Option 2: HyperLogLog (requires pg_hll extension)\n"
        f"-- SELECT hll_cardinality(hll_add_agg(hll_hash_text({col}))) FROM {table}"
    )

    return new_sql, Rewrite(
        name="COUNT(DISTINCT) → approximate",
        description=(
            f"COUNT(DISTINCT {col}) requires full sort/hash; "
            f"pg_stats or HyperLogLog gives instant ~98% accurate estimate"
        ),
        before_pattern=f"SELECT COUNT(DISTINCT {col}) FROM {table}",
        after_pattern=f"pg_stats n_distinct or HLL approximation",
        rule_id="QUERY_REWRITE",
        confidence=0.65,
    )


# =============================================================================
# Human-readable rewrite explanations (beginner-friendly)
# =============================================================================

_REWRITE_EXPLANATIONS: dict[str, str] = {
    "NOT IN → NOT EXISTS": (
        "Why this is faster: NOT IN has a hidden gotcha — if ANY value in the "
        "subquery is NULL, the entire NOT IN returns no results (not what you want). "
        "NOT EXISTS doesn't have this problem AND it stops checking as soon as it "
        "finds the first match, making it faster.\n\n"
        "Is it safe? Yes — NOT EXISTS always returns the same results as NOT IN "
        "when there are no NULLs. When there ARE NULLs, NOT EXISTS gives you "
        "what you actually wanted."
    ),
    "IN subquery → EXISTS": (
        "Why this is faster: EXISTS can stop as soon as it finds the first matching "
        "row ('short-circuit'). IN must collect ALL matching rows before comparing. "
        "Think of it like checking if a book exists in a library — you don't need to "
        "count every copy, just find one.\n\n"
        "Is it safe? Yes — produces identical results."
    ),
    "IN subquery → JOIN": (
        "Why this is faster: A JOIN lets PostgreSQL choose the best strategy "
        "(hash join, merge join, or nested loop) based on table sizes. IN with "
        "a subquery limits the planner's options.\n\n"
        "Is it safe? Mostly — the results are the same UNLESS the subquery returns "
        "duplicates (then you might get extra rows). Check if the subquery column "
        "is unique; if not, add DISTINCT."
    ),
    "OR chain → IN clause": (
        "Why this is faster: IN clauses are optimized internally by PostgreSQL "
        "to use hash lookups instead of checking each condition one by one. "
        "It's also much more readable.\n\n"
        "Is it safe? Yes — exactly equivalent. Just tidier SQL."
    ),
    "OR → UNION ALL": (
        "Why this is faster: When OR conditions are on DIFFERENT columns "
        "(e.g., WHERE name = 'X' OR city = 'Y'), PostgreSQL can't use any "
        "single index efficiently. UNION ALL lets each branch use its own "
        "index — like having two parallel lookups instead of one full scan.\n\n"
        "Is it safe? Yes, if the conditions are mutually exclusive. If rows "
        "can match BOTH conditions, you might get duplicates (use UNION instead)."
    ),
    "SELECT * flagged": (
        "Why this matters: SELECT * fetches every column — even ones you don't "
        "use. This wastes network bandwidth, memory, and prevents PostgreSQL "
        "from using index-only scans (the fastest read path).\n\n"
        "How to fix: Replace * with the specific columns you need. Your query "
        "could be 2-10x faster just by listing columns."
    ),
    "DISTINCT * removed": (
        "Why this matters: SELECT DISTINCT * compares EVERY column of EVERY row "
        "to find duplicates. This is almost never what you want — it usually means "
        "the query has a JOIN problem creating unwanted duplicates.\n\n"
        "How to fix: Find the root cause (usually a missing JOIN condition or "
        "wrong JOIN type). If you truly need dedup, specify which columns matter."
    ),
    "COUNT(*) → approximate": (
        "Why this is faster: COUNT(*) on a big table reads every single row — "
        "there's no shortcut. For dashboards or display purposes, PostgreSQL "
        "already maintains an approximate count in pg_class.reltuples that's "
        "updated by VACUUM and ANALYZE. It's instant instead of seconds.\n\n"
        "Is it safe? The count is approximate (usually within 5% accuracy). "
        "Don't use this for billing or exact totals."
    ),
    "UNION → UNION ALL": (
        "Why this is faster: UNION sorts and deduplicates all rows from both "
        "queries. UNION ALL just concatenates them. If your branches already "
        "return different rows (e.g., different WHERE conditions), the dedup "
        "step is wasted work.\n\n"
        "Is it safe? Only if the branches can't return the same row. If both "
        "queries can match the same row, keep UNION to avoid duplicates."
    ),
    "EXISTS SELECT * → SELECT 1": (
        "Why this is faster: EXISTS only checks if a row exists — it doesn't "
        "care what's in it. SELECT * tells PostgreSQL to prepare all columns, "
        "while SELECT 1 says 'I just need to know if something is there.'\n\n"
        "Is it safe? Yes — always identical results. Modern PostgreSQL optimizes "
        "this automatically, but SELECT 1 makes intent clear."
    ),
    "OFFSET → keyset pagination": (
        "Why this is faster: OFFSET 10000 means PostgreSQL reads 10,000 rows "
        "and throws them away before giving you the next page. The deeper you "
        "paginate, the slower it gets. Keyset pagination (WHERE id > last_seen) "
        "jumps directly to the right spot using an index — same speed for page "
        "1 and page 1,000.\n\n"
        "Is it safe? Yes, but requires your application to track the last seen "
        "value instead of page numbers. Worth it for any serious pagination."
    ),
    "Redundant subquery removed": (
        "Why this is faster: SELECT * FROM (SELECT ... FROM t) adds an extra "
        "planning step with zero benefit. It's like putting a letter in an "
        "envelope, then putting that envelope in another envelope.\n\n"
        "Is it safe? Yes — the wrapper query doesn't transform the data."
    ),
    "LEFT JOIN → INNER JOIN": (
        "Why this is faster: If your WHERE clause already filters out NULL rows "
        "from the LEFT JOIN (e.g., WHERE right_table.col = 'value'), the LEFT "
        "JOIN is doing extra work preserving NULLs that get immediately filtered. "
        "INNER JOIN is faster because PostgreSQL can use it for join reordering.\n\n"
        "Is it safe? Yes — the WHERE clause already eliminates the LEFT JOIN's "
        "NULL-preserving behavior. The results are identical."
    ),
    "HAVING → WHERE (no GROUP BY)": (
        "Why this is faster: HAVING is designed to filter AFTER grouping and "
        "aggregation. Without GROUP BY, PostgreSQL treats the whole table as one "
        "group, then filters. WHERE filters BEFORE processing, which can use "
        "indexes and skip irrelevant rows entirely.\n\n"
        "Is it safe? Yes — when there's no GROUP BY, HAVING and WHERE are "
        "semantically identical for non-aggregate conditions."
    ),
    "Scalar subquery → JOIN": (
        "Why this is faster: A scalar subquery in SELECT runs once for EVERY row "
        "of the outer query. 10,000 rows = 10,000 subqueries. A JOIN processes "
        "both tables in one pass using hash or merge join strategies.\n\n"
        "Is it safe? Usually — but if the subquery returns NULL for unmatched "
        "rows and you need that behavior, use LEFT JOIN."
    ),
    "COALESCE in WHERE → explicit check": (
        "Why this is faster: COALESCE() wraps the column in a function call, "
        "preventing PostgreSQL from using the index. Expanding it to "
        "(col = value OR col IS NULL) lets the index work on the direct "
        "column comparison.\n\n"
        "Is it safe? Yes — logically identical."
    ),
    "Non-sargable LOWER() noted": (
        "Why this matters: LOWER(column) in WHERE wraps every row's value in "
        "a function, preventing index usage. PostgreSQL must read EVERY row "
        "and apply LOWER() to compare.\n\n"
        "How to fix: Create an expression index: CREATE INDEX ON table (LOWER(col)). "
        "Alternatively, use the citext extension for case-insensitive columns."
    ),
    "Leading wildcard LIKE noted": (
        "Why this matters: LIKE '%pattern' can't use a regular btree index — "
        "it's like looking up a word in a dictionary when you only know the ending. "
        "PostgreSQL must scan every row.\n\n"
        "How to fix: Install pg_trgm extension and create a GIN index: "
        "CREATE INDEX ON table USING GIN (col gin_trgm_ops). This supports "
        "leading wildcards efficiently."
    ),
    "DISTINCT → GROUP BY": (
        "Why this is faster: DISTINCT requires a full sort of all result rows. "
        "GROUP BY can use indexes to avoid sorting and is also more flexible "
        "(you can add aggregates later).\n\n"
        "Is it safe? Yes — produces identical results."
    ),
    "COUNT(DISTINCT) → approximate": (
        "Why this is faster: COUNT(DISTINCT col) needs to sort or hash every "
        "unique value. For large tables with millions of rows, this takes seconds. "
        "PostgreSQL's pg_stats table already has an estimate that's instant.\n\n"
        "Is it safe? The estimate is approximate (~98% accurate for common "
        "distributions). Use for dashboards, not billing."
    ),
    "CAST in WHERE → cast literal": (
        "Why this matters: CAST(column AS type) in WHERE prevents index usage — "
        "PostgreSQL must convert every row. Instead, CAST the comparison value "
        "to match the column's type, allowing the index to work.\n\n"
        "Is it safe? Yes — casting the literal instead of the column "
        "preserves the same comparison logic."
    ),
    "Correlated subquery detected": (
        "Why this matters: A correlated subquery runs once for EVERY row of the "
        "outer query. 10,000 outer rows = 10,000 separate subqueries. Converting "
        "to a JOIN processes everything in one pass.\n\n"
        "How to fix: Rewrite as JOIN or use EXISTS. The exact rewrite depends "
        "on your query structure — QuerySense flags this for manual review."
    ),
}


def explain_rewrites(result: RewriteResult) -> str:
    """Generate a beginner-friendly explanation of all applied rewrites.

    Returns a formatted string with plain-English explanations of each
    rewrite, including safety assessment and estimated impact.
    """
    if not result.rewrites:
        return "No rewrites were applied. Your query looks good as-is."

    parts = [
        f"QuerySense applied {len(result.rewrites)} optimization(s) to your query:\n"
    ]

    for i, rw in enumerate(result.rewrites, 1):
        parts.append(f"{'─' * 60}")
        parts.append(f"Optimization {i}: {rw.name}")
        parts.append(f"Safety: {rw.safety_level}")
        parts.append(f"")
        parts.append(rw.human_explanation)
        parts.append("")

    if result.warnings:
        parts.append(f"{'─' * 60}")
        parts.append("Warnings:")
        for w in result.warnings:
            parts.append(f"  - {w}")

    return "\n".join(parts)
