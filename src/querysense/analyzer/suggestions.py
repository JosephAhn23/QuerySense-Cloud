"""
Deterministic suggestion templates.

Provides actionable SQL fixes for common query performance issues.
No LLM required - just pattern matching and templates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.analyzer.models import Finding, NodeContext


@dataclass(frozen=True)
class Suggestion:
    """
    A deterministic fix suggestion.
    
    Attributes:
        sql: The SQL to run (CREATE INDEX, etc.)
        explanation: Why this helps (1-2 sentences)
        docs_url: Link to PostgreSQL documentation
        confidence: How confident we are this will help (0.0-1.0)
    """
    
    sql: str
    explanation: str
    docs_url: str
    confidence: float = 0.9


# PostgreSQL documentation links
DOCS = {
    "btree": "https://www.postgresql.org/docs/current/indexes-types.html#INDEXES-TYPES-BTREE",
    "partial": "https://www.postgresql.org/docs/current/indexes-partial.html",
    "covering": "https://www.postgresql.org/docs/current/indexes-index-only-scans.html",
    "analyze": "https://www.postgresql.org/docs/current/sql-analyze.html",
    "explain": "https://www.postgresql.org/docs/current/using-explain.html",
    "work_mem": "https://www.postgresql.org/docs/current/runtime-config-resource.html#GUC-WORK-MEM",
}


def suggest_index_for_seq_scan(
    table: str,
    column: str,
    filter_value: str | None = None,
    rows_scanned: int | None = None,
) -> Suggestion:
    """
    Generate index suggestion for a sequential scan with equality filter.
    
    Args:
        table: Table name
        column: Column used in filter
        filter_value: The filter value (for partial index consideration)
        rows_scanned: Number of rows scanned (for explanation)
    
    Returns:
        Suggestion with CREATE INDEX statement
    """
    index_name = f"idx_{table}_{column}"
    
    # Consider partial index if filter value suggests low cardinality
    sql = f"CREATE INDEX {index_name} ON {table}({column});"
    
    explanation = f"Creates a B-tree index on {table}.{column} to avoid scanning"
    if rows_scanned:
        explanation += f" {rows_scanned:,} rows."
    else:
        explanation += " the entire table."
    
    return Suggestion(
        sql=sql,
        explanation=explanation,
        docs_url=DOCS["btree"],
        confidence=0.9,
    )


def suggest_composite_index(
    table: str,
    columns: list[str],
    include_columns: list[str] | None = None,
) -> Suggestion:
    """
    Generate composite index suggestion for multi-column filters.
    
    Args:
        table: Table name
        columns: Columns for the index (order matters!)
        include_columns: Additional columns to include (covering index)
    
    Returns:
        Suggestion with CREATE INDEX statement
    """
    index_name = f"idx_{table}_{'_'.join(columns)}"
    
    cols_str = ", ".join(columns)
    sql = f"CREATE INDEX {index_name} ON {table}({cols_str})"
    
    if include_columns:
        include_str = ", ".join(include_columns)
        sql += f" INCLUDE ({include_str})"
    
    sql += ";"
    
    explanation = f"Composite index on ({cols_str}) supports multi-column lookups."
    if include_columns:
        explanation += " Covering index avoids table lookups for included columns."
    
    return Suggestion(
        sql=sql,
        explanation=explanation,
        docs_url=DOCS["covering"] if include_columns else DOCS["btree"],
        confidence=0.85,
    )


def suggest_analyze(table: str, estimation_error: float) -> Suggestion:
    """
    Suggest running ANALYZE when statistics are stale.
    
    Args:
        table: Table name
        estimation_error: Ratio of actual/estimated rows
    
    Returns:
        Suggestion with ANALYZE statement
    """
    return Suggestion(
        sql=f"ANALYZE {table};",
        explanation=f"PostgreSQL estimated {estimation_error:.0f}x fewer rows than actual. "
                    "Statistics are stale. Run ANALYZE to update.",
        docs_url=DOCS["analyze"],
        confidence=0.95,
    )


def suggest_work_mem_increase(
    sort_space_kb: int,
    current_work_mem_kb: int = 4096,  # Default 4MB
) -> Suggestion:
    """
    Suggest increasing work_mem for sorts spilling to disk.
    
    Args:
        sort_space_kb: Space used by sort (in KB)
        current_work_mem_kb: Current work_mem setting
    
    Returns:
        Suggestion with SET work_mem statement
    """
    # Suggest 2x the sort space, rounded to nice number
    suggested_mb = max(16, (sort_space_kb * 2) // 1024)
    suggested_mb = ((suggested_mb + 15) // 16) * 16  # Round to 16MB increments
    
    return Suggestion(
        sql=f"SET work_mem = '{suggested_mb}MB';  -- For this session only",
        explanation=f"Sort spilled {sort_space_kb // 1024}MB to disk. "
                    f"Increase work_mem to {suggested_mb}MB for in-memory sorting.",
        docs_url=DOCS["work_mem"],
        confidence=0.8,
    )


def format_suggestion_for_finding(finding: "Finding") -> str | None:
    """
    Generate a suggestion string for a finding based on its type.
    
    Returns None if no deterministic suggestion is available.
    """
    ctx = finding.context
    
    # Sequential scan on large table with filter
    if finding.rule_id == "SEQ_SCAN_LARGE_TABLE":
        if ctx.relation_name and ctx.filter:
            # Try to extract column from filter
            column = _extract_column_from_filter(ctx.filter)
            if column:
                suggestion = suggest_index_for_seq_scan(
                    table=ctx.relation_name,
                    column=column,
                    rows_scanned=ctx.actual_rows,
                )
                return f"{suggestion.sql}\n-- {suggestion.explanation}\n-- Docs: {suggestion.docs_url}"
    
    # Bad row estimate
    if ctx.row_estimate_ratio and ctx.row_estimate_ratio > 100:
        if ctx.relation_name:
            suggestion = suggest_analyze(
                table=ctx.relation_name,
                estimation_error=ctx.row_estimate_ratio,
            )
            return f"{suggestion.sql}\n-- {suggestion.explanation}\n-- Docs: {suggestion.docs_url}"
    
    return None


def _extract_column_from_filter(filter_str: str) -> str | None:
    """
    Extract column name from a simple filter string.
    
    Examples:
        "(status = 'active')" -> "status"
        "(age > 18)" -> "age"
        "(name = 'foo' AND status = 'bar')" -> "name" (first one)
    """
    import re
    
    # Match patterns like: column = value, column > value, etc.
    match = re.search(r"\(?\s*(\w+)\s*[=<>!]", filter_str)
    if match:
        return match.group(1)
    
    return None
