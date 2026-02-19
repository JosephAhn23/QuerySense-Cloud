"""
Simple / "Explain Like I'm 5" output mode.

Translates technical query analysis into plain English that beginners
can understand. Shows only the top 3 most impactful issues with
concrete fixes and human-friendly explanations.

This is QuerySense's competitive advantage vs pganalyze's "overwhelming
complexity" — make performance analysis accessible to everyone.

Usage:
    from querysense.output.simple import render_simple

    text = render_simple(result, explain=explain)
    print(text)

CLI:
    querysense analyze plan.json --simple
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding
    from querysense.parser.models import ExplainOutput


# ── ELI5 explanations by rule ID ────────────────────────────────────

_ELI5: dict[str, str] = {
    "SEQ_SCAN_LARGE_TABLE": (
        "Your query is reading the ENTIRE table row by row, like flipping "
        "through every page of a phone book to find one name. An index "
        "would let it jump directly to the right page."
    ),
    "SEQ_SCAN_NO_FILTER": (
        "This query returns every single row from the table. If that's "
        "intentional, consider whether you really need all of them. "
        "If not, add a WHERE clause to filter."
    ),
    "EXCESSIVE_SEQ_SCANS": (
        "Multiple tables are being read row by row. This compounds — "
        "each full scan multiplies the work. Adding indexes on the join "
        "and filter columns would dramatically speed this up."
    ),
    "BAD_ROW_ESTIMATE": (
        "PostgreSQL GUESSED wrong about how many rows this would return. "
        "It thought there'd be {plan_rows} but actually got {actual_rows}. "
        "This bad guess made it pick a slow strategy. Run ANALYZE to fix."
    ),
    "CARDINALITY_DRIFT": (
        "The database's statistics are out of date. It's making decisions "
        "based on old data — like using a 2020 map to navigate a city "
        "that's been rebuilt. Run ANALYZE to refresh the stats."
    ),
    "STALE_STATISTICS": (
        "The table statistics haven't been updated recently. PostgreSQL is "
        "guessing based on stale information. Run ANALYZE on this table."
    ),
    "SPILLING_TO_DISK": (
        "The sort/hash couldn't fit in memory, so it spilled to disk. "
        "Disk is ~100x slower than RAM. Increase work_mem to keep "
        "the data in memory."
    ),
    "HASH_JOIN_BATCHES": (
        "The hash table was too big for memory and had to be split into "
        "multiple batches on disk. This is slow. Increase work_mem."
    ),
    "NESTED_LOOP_LARGE_TABLE": (
        "For EVERY row in the outer table, PostgreSQL is scanning the "
        "inner table. With {outer_rows} outer rows, that's {outer_rows} "
        "separate lookups. An index on the inner table's join column "
        "would fix this."
    ),
    "SORT_AVOIDABLE_WITH_INDEX": (
        "The query sorts results after fetching them. If there were an "
        "index that already keeps the data in the right order, PostgreSQL "
        "could skip the sort entirely."
    ),
    "LIMIT_WITHOUT_INDEX": (
        "The query uses LIMIT but still scans many rows first. With a "
        "matching index, it could grab just the rows it needs without "
        "scanning everything."
    ),
}

_ELI5_GENERIC = {
    "critical": (
        "This is a serious performance issue that's making your query "
        "significantly slower than it needs to be."
    ),
    "warning": (
        "This is worth fixing — it's slowing your query down, though "
        "it's not the most urgent issue."
    ),
    "info": (
        "A minor optimization opportunity. Fix the critical issues first, "
        "then come back to this."
    ),
}

# Severity to emoji
_SEVERITY_EMOJI = {
    "critical": "RED",
    "warning": "YELLOW",
    "info": "BLUE",
}

_SEVERITY_LABEL = {
    "critical": "URGENT",
    "warning": "Good to know",
    "info": "Minor tip",
}


def _explain_finding(finding: "Finding") -> str:
    """Generate a plain-English explanation for a finding."""
    rule_id = finding.rule_id
    explanation = _ELI5.get(rule_id)

    if explanation:
        # Fill in metrics if available
        metrics = finding.metrics
        explanation = explanation.format(
            plan_rows=metrics.get("plan_rows", "?"),
            actual_rows=metrics.get("actual_rows", "?"),
            outer_rows=metrics.get("outer_rows", "?"),
            **{k: v for k, v in metrics.items() if isinstance(v, (int, float, str))},
        )
        return explanation

    # Fallback to generic explanation
    return _ELI5_GENERIC.get(finding.severity.value, finding.description)


def _format_fix(finding: "Finding") -> str:
    """Extract the most actionable fix from a finding."""
    if finding.suggestion:
        # Get the first SQL-like line
        for line in finding.suggestion.split("\n"):
            line = line.strip()
            if line and (
                line.upper().startswith(("CREATE", "ALTER", "ANALYZE", "VACUUM",
                                         "SET ", "SELECT", "DROP", "REINDEX"))
            ):
                return line
        # Otherwise, return the first non-empty line
        for line in finding.suggestion.split("\n"):
            line = line.strip()
            if line:
                return line
    return ""


def render_simple(
    result: "AnalysisResult",
    explain: "ExplainOutput | None" = None,
    max_issues: int = 3,
) -> str:
    """
    Render analysis results in simple, beginner-friendly format.

    Shows only the top N most impactful issues with:
    - Plain English explanations
    - Concrete SQL fixes
    - Why it matters

    Args:
        result: Analysis result
        explain: Optional EXPLAIN output for additional context
        max_issues: Maximum number of issues to show (default 3)

    Returns:
        Multi-line string in simple, friendly format
    """
    lines: list[str] = []

    # Header
    lines.append("")
    lines.append("  QUERYSENSE FOR HUMANS")
    lines.append("  " + "=" * 40)
    lines.append("")

    if not result.findings:
        lines.append("  No performance issues found!")
        lines.append("")
        lines.append("  Your query looks good. It analyzed")
        lines.append(f"  {result.metadata.node_count} plan nodes and")
        lines.append("  found nothing to worry about.")

        if explain and explain.execution_time:
            lines.append(f"\n  Execution time: {explain.execution_time:.1f}ms")

        lines.append("")
        return "\n".join(lines)

    # Sort by impact (critical first, then by impact_score)
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (
            0 if f.severity.value == "critical" else (1 if f.severity.value == "warning" else 2),
            -f.impact_score,
        ),
    )

    # Show top N
    shown = sorted_findings[:max_issues]
    remaining = len(sorted_findings) - max_issues

    for i, finding in enumerate(shown, 1):
        sev = finding.severity.value
        label = _SEVERITY_LABEL.get(sev, sev.upper())
        color_tag = _SEVERITY_EMOJI.get(sev, "")

        # Severity indicator
        if sev == "critical":
            indicator = "[!!!]"
        elif sev == "warning":
            indicator = "[!!]"
        else:
            indicator = "[i]"

        lines.append(f"  {indicator} {label}: {finding.title}")
        lines.append("")

        # Fix (most important — show first)
        fix = _format_fix(finding)
        if fix:
            lines.append(f"     Fix: {fix}")
            lines.append("")

        # Explanation
        explanation = _explain_finding(finding)
        # Word-wrap at ~60 chars
        words = explanation.split()
        current_line: list[str] = []
        current_len = 0
        for word in words:
            if current_len + len(word) + 1 > 58 and current_line:
                lines.append("     " + " ".join(current_line))
                current_line = [word]
                current_len = len(word)
            else:
                current_line.append(word)
                current_len += len(word) + 1
        if current_line:
            lines.append("     " + " ".join(current_line))

        # Speedup estimate
        speedup = finding.metrics.get("estimated_speedup", "")
        if speedup:
            lines.append(f"\n     Expected improvement: {speedup}")

        lines.append("")
        if i < len(shown):
            lines.append("  " + "-" * 40)
            lines.append("")

    # Remaining
    if remaining > 0:
        lines.append(f"  ... and {remaining} more issue(s).")
        lines.append("  Run without --simple to see all findings.")
        lines.append("")

    # Execution context
    if explain and explain.execution_time:
        lines.append(f"  Query execution time: {explain.execution_time:.1f}ms")

    lines.append(f"  Total findings: {len(result.findings)}")
    lines.append("")

    return "\n".join(lines)
