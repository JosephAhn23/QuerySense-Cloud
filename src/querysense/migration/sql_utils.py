"""
Shared SQL statement splitting utility for migration modules.

Consolidates the 6 duplicate _split_statements() implementations from:
- migration_safety.py (simple semicolon split)
- safe_migration.py (handles single-quoted strings)
- rollback.py (simple semicolon split)
- migration/analyzer.py (handles dollar-quoted strings)
- lock_analyzer.py (appends semicolons, filters comments)

This unified version handles all edge cases:
- Dollar-quoted strings ($$...$$, $tag$...$tag$)
- Single-quoted strings with escaped quotes
- SQL comments (-- line comments, /* block comments */)
- Preserves trailing semicolons optionally
"""

from __future__ import annotations

import re


def split_statements(
    sql: str,
    *,
    strip_comments: bool = False,
    keep_semicolons: bool = False,
) -> list[str]:
    """
    Split a SQL string into individual statements on semicolons.

    Correctly handles:
    - Dollar-quoted strings: $$ body $$ or $tag$ body $tag$
    - Single-quoted strings: 'it''s escaped'
    - Line comments: -- ignored
    - Block comments: /* ignored */

    Args:
        sql: Raw SQL text, possibly containing multiple statements.
        strip_comments: If True, remove standalone comment-only statements.
        keep_semicolons: If True, append `;` to each returned statement.

    Returns:
        List of non-empty SQL statements in order.
    """
    statements: list[str] = []
    current: list[str] = []
    i = 0
    n = len(sql)

    in_single_quote = False
    in_dollar_quote = False
    dollar_tag = ""
    in_line_comment = False
    in_block_comment = False

    while i < n:
        ch = sql[i]

        # ── Line comment ────────────────────────────────────────────
        if in_line_comment:
            current.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        # ── Block comment ───────────────────────────────────────────
        if in_block_comment:
            current.append(ch)
            if ch == "*" and i + 1 < n and sql[i + 1] == "/":
                current.append("/")
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        # ── Dollar-quoted string ────────────────────────────────────
        if in_dollar_quote:
            current.append(ch)
            if ch == "$":
                # Check if we're at the closing dollar tag
                end_tag = sql[i : i + len(dollar_tag)]
                if end_tag == dollar_tag:
                    current.append(sql[i + 1 : i + len(dollar_tag)])
                    in_dollar_quote = False
                    i += len(dollar_tag)
                else:
                    i += 1
            else:
                i += 1
            continue

        # ── Single-quoted string ────────────────────────────────────
        if in_single_quote:
            current.append(ch)
            if ch == "'" and i + 1 < n and sql[i + 1] == "'":
                # Escaped quote ''
                current.append("'")
                i += 2
            elif ch == "'":
                in_single_quote = False
                i += 1
            else:
                i += 1
            continue

        # ── Normal mode: detect transitions ─────────────────────────

        # Start of line comment
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            in_line_comment = True
            current.append(ch)
            i += 1
            continue

        # Start of block comment
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            in_block_comment = True
            current.append(ch)
            current.append("*")
            i += 2
            continue

        # Start of dollar-quoted string
        if ch == "$":
            tag_match = re.match(r"\$\w*\$", sql[i:])
            if tag_match:
                dollar_tag = tag_match.group()
                in_dollar_quote = True
                current.append(dollar_tag)
                i += len(dollar_tag)
                continue

        # Start of single-quoted string
        if ch == "'":
            in_single_quote = True
            current.append(ch)
            i += 1
            continue

        # ── Statement terminator ────────────────────────────────────
        if ch == ";":
            stmt = "".join(current).strip()
            if stmt:
                if strip_comments and _is_only_comments(stmt):
                    pass
                elif keep_semicolons:
                    statements.append(stmt + ";")
                else:
                    statements.append(stmt)
            current = []
            i += 1
            continue

        current.append(ch)
        i += 1

    # Remaining text after the last semicolon
    remaining = "".join(current).strip()
    if remaining:
        if not (strip_comments and _is_only_comments(remaining)):
            statements.append(remaining)

    return statements if statements else ([sql.strip()] if sql.strip() else [])


def _is_only_comments(sql: str) -> bool:
    """Return True if the string contains only SQL comments (no real SQL)."""
    cleaned = re.sub(r"--[^\n]*", "", sql)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
    return not cleaned.strip()
