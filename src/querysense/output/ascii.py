"""
ASCII plan tree and findings table renderer.

Produces beautiful terminal output using box-drawing characters and
Rich tables. Zero external dependencies beyond Rich (already required).

Usage:
    from querysense.output.ascii import render_ascii, render_plan_tree_ascii

    # Full analysis report as ASCII
    print(render_ascii(result, explain=explain))

    # Just the plan tree
    print(render_plan_tree_ascii(explain.plan))
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding
    from querysense.parser.models import ExplainOutput, PlanNode


# ─── Box-drawing plan tree ────────────────────────────────────────────

_PIPE = "│   "
_TEE = "├── "
_ELBOW = "└── "
_BLANK = "    "


def _format_node_line(node: "PlanNode") -> str:
    """Format a single plan node into a compact info line."""
    parts: list[str] = [node.node_type]

    if node.relation_name:
        parts.append(f"on {node.relation_name}")
    if node.index_name:
        parts.append(f"using {node.index_name}")
    if node.join_type:
        parts[0] = f"{node.join_type} {parts[0]}"

    # Cost
    cost_str = f"cost={node.total_cost:,.0f}"

    # Rows
    if node.actual_rows is not None:
        rows_str = f"rows={node.actual_rows:,}"
        if node.plan_rows and node.plan_rows > 0:
            ratio = node.actual_rows / node.plan_rows
            if ratio > 10 or ratio < 0.1:
                rows_str += f" (est={node.plan_rows:,} !!)"
            elif ratio > 2 or ratio < 0.5:
                rows_str += f" (est={node.plan_rows:,} !)"
        parts.append(rows_str)
    else:
        parts.append(f"rows={node.plan_rows:,}")

    parts.append(cost_str)

    # Timing
    if node.actual_total_time is not None:
        loops = node.actual_loops or 1
        total_ms = node.actual_total_time * loops
        if total_ms >= 1000:
            parts.append(f"time={total_ms / 1000:.1f}s")
        else:
            parts.append(f"time={total_ms:.1f}ms")

    # Filter
    if node.filter:
        filt = node.filter
        if len(filt) > 50:
            filt = filt[:47] + "..."
        parts.append(f'filter="{filt}"')

    return " ".join(parts)


def _severity_marker(node: "PlanNode") -> str:
    """Return a severity marker for problematic nodes."""
    if node.node_type == "Seq Scan" and node.actual_rows is not None and node.actual_rows > 10_000:
        return " [!]"
    if node.sort_space_type == "Disk":
        return " [!!]"
    if (
        node.actual_rows is not None
        and node.plan_rows is not None
        and node.plan_rows > 0
    ):
        ratio = node.actual_rows / node.plan_rows
        if ratio > 100 or ratio < 0.01:
            return " [!!]"
        if ratio > 10 or ratio < 0.1:
            return " [!]"
    return ""


def render_plan_tree_ascii(node: "PlanNode", prefix: str = "", is_last: bool = True) -> str:
    """
    Render a plan node tree using box-drawing characters.

    Returns a multi-line string like:

        Nested Loop (Inner) rows=1 cost=8
        ├── Index Scan on users using users_pkey rows=1 cost=4
        └── Index Scan on orders using orders_user_id_idx rows=1 cost=4
    """
    lines: list[str] = []

    connector = _ELBOW if is_last else _TEE
    node_line = _format_node_line(node)
    marker = _severity_marker(node)

    if prefix == "":
        # Root node - no connector
        lines.append(f"{node_line}{marker}")
    else:
        lines.append(f"{prefix}{connector}{node_line}{marker}")

    # Recurse into children
    child_prefix = prefix + (_BLANK if is_last else _PIPE) if prefix else ""
    children = node.plans or []
    for i, child in enumerate(children):
        child_is_last = i == len(children) - 1
        child_tree = render_plan_tree_ascii(child, child_prefix, child_is_last)
        lines.append(child_tree)

    return "\n".join(lines)


# ─── Findings table ──────────────────────────────────────────────────

_SEVERITY_SYMBOLS = {
    "critical": "CRIT",
    "warning": "WARN",
    "info": "INFO",
}

_IMPACT_BAR_CHARS = " ▏▎▍▌▋▊▉█"


def _impact_bar(score: float, width: int = 10) -> str:
    """Render a mini impact bar from score 0-10."""
    filled = int(score * width / 10)
    remainder = (score * width / 10) - filled
    idx = int(remainder * (len(_IMPACT_BAR_CHARS) - 1))
    bar = "█" * filled
    if filled < width:
        bar += _IMPACT_BAR_CHARS[idx]
        bar += " " * (width - filled - 1)
    return bar


def _speedup_estimate(finding: "Finding") -> str:
    """
    Generate an estimated speedup string from finding metrics.

    Uses cost ratio, rows removed, and impact band to produce
    human-readable estimates like '~23x faster' or '~3x faster'.
    """
    metrics = finding.metrics

    # If we have explicit cost before/after from verification
    cost_before = metrics.get("cost_before")
    cost_after = metrics.get("cost_after")
    if cost_before and cost_after and cost_after > 0:
        ratio = cost_before / cost_after
        if ratio > 1.5:
            return f"~{ratio:.0f}x faster"

    # Estimate from row count and filter selectivity
    rows = metrics.get("rows_scanned", metrics.get("actual_rows", 0))
    rows_removed = metrics.get("rows_removed_by_filter", 0)
    if rows and rows_removed and rows_removed > rows:
        selectivity = rows / (rows + rows_removed)
        if selectivity < 0.01:
            return f"~{int(1/selectivity)}x faster"
        if selectivity < 0.1:
            return f"~{int(1/selectivity)}x faster"

    # Fall back to impact band
    band = finding.impact_band.value
    if band == "HIGH":
        return ">10x faster"
    if band == "MEDIUM":
        return "2-10x faster"
    if band == "LOW":
        return "<2x faster"

    return ""


def _format_finding_card(i: int, finding: "Finding") -> str:
    """Format a single finding as a compact ASCII card."""
    sev = _SEVERITY_SYMBOLS.get(finding.severity.value, "????")
    lines: list[str] = []

    # Header with severity badge and title
    lines.append(f"  ┌─[{sev}]─{'─' * max(0, 58 - len(sev))}┐")
    # Title
    title = finding.title
    if len(title) > 56:
        title = title[:53] + "..."
    lines.append(f"  │ {i}. {title:<56}│")

    # Impact bar + speedup
    score = finding.impact_score
    speedup = _speedup_estimate(finding)
    if score > 0 or speedup:
        impact_line = f"Impact: {_impact_bar(score)} {score:.1f}/10"
        if speedup:
            impact_line += f"  {speedup}"
        if len(impact_line) > 58:
            impact_line = impact_line[:58]
        lines.append(f"  │ {impact_line:<58}│")

    # Rule ID
    lines.append(f"  │ Rule: {finding.rule_id:<51}│")

    # Description (wrap at ~56 chars)
    desc = finding.description
    desc_lines = _wrap_text(desc, 56)
    for dl in desc_lines[:3]:
        lines.append(f"  │ {dl:<58}│")

    # Suggestion
    if finding.suggestion:
        lines.append(f"  │{'─' * 60}│")
        lines.append(f"  │ {'Fix:':<58}│")
        for sl in finding.suggestion.split("\n")[:4]:
            sl = sl.strip()
            if len(sl) > 56:
                sl = sl[:53] + "..."
            lines.append(f"  │   {sl:<56}│")

    lines.append(f"  └{'─' * 60}┘")
    return "\n".join(lines)


def _wrap_text(text: str, width: int) -> list[str]:
    """Simple word-wrap."""
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    current_len = 0
    for word in words:
        if current_len + len(word) + 1 > width and current:
            lines.append(" ".join(current))
            current = [word]
            current_len = len(word)
        else:
            current.append(word)
            current_len += len(word) + 1
    if current:
        lines.append(" ".join(current))
    return lines or [""]


# ─── Summary bar ─────────────────────────────────────────────────────

def _summary_bar(result: "AnalysisResult") -> str:
    """Render a compact summary header."""
    summary = result.summary()
    lines: list[str] = []

    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║              QuerySense Analysis Report                     ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")

    ev = result.evidence_level.value
    lines.append(f"║  Evidence: {ev:<17} SQL Confidence: {result.sql_confidence.value:<13}║")

    crit = summary["critical"]
    warn = summary["warning"]
    info = summary["info"]
    total = summary["total"]

    status = "CRITICAL" if crit else ("WARNING" if warn else "PASS")
    status_line = f"  Status: {status}    Findings: {total} total"
    lines.append(f"║{status_line:<62}║")

    counts_line = f"  {crit} critical  {warn} warning  {info} info"
    lines.append(f"║{counts_line:<62}║")

    # Rules bar
    passed = summary.get("rules_passed", 0)
    skipped = summary.get("rules_skipped", 0)
    failed = summary.get("rules_failed", 0)
    rules_line = f"  Rules: {passed} passed  {skipped} skipped  {failed} failed"
    lines.append(f"║{rules_line:<62}║")

    lines.append("╚══════════════════════════════════════════════════════════════╝")
    return "\n".join(lines)


# ─── Public API ──────────────────────────────────────────────────────

def render_ascii(
    result: "AnalysisResult",
    explain: "ExplainOutput | None" = None,
) -> str:
    """
    Render a complete analysis report as ASCII art.

    Combines summary box, findings cards, and plan tree.

    Args:
        result: Analysis result with findings
        explain: Optional ExplainOutput for plan tree visualization

    Returns:
        Complete multi-line ASCII report string
    """
    sections: list[str] = []

    # Summary header
    sections.append(_summary_bar(result))
    sections.append("")

    # Plan tree
    if explain:
        sections.append("Plan Tree:")
        sections.append("─" * 64)
        sections.append(render_plan_tree_ascii(explain.plan))
        sections.append("")

    # Findings
    if result.findings:
        sections.append(f"Findings ({len(result.findings)}):")
        sections.append("─" * 64)

        for i, finding in enumerate(result.findings, 1):
            sections.append(_format_finding_card(i, finding))
            sections.append("")
    else:
        sections.append("  No performance issues detected.")
        sections.append("")

    # Footer
    if result.metadata.execution_time_ms:
        sections.append(
            f"Query execution: {result.metadata.execution_time_ms:.1f}ms  "
            f"Nodes analyzed: {result.metadata.node_count}"
        )

    sections.append(f"Analysis ID: {result.reproducibility.analysis_id}")
    sections.append("─" * 64)

    return "\n".join(sections)
