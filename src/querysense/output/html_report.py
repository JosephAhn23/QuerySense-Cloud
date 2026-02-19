"""
Self-contained HTML report generator for QuerySense.

Generates a single HTML file with inline CSS/JS that visualizes the
query plan tree and analysis findings. No external dependencies needed —
the file is fully self-contained and can be shared via Slack, email, or PR.

Usage:
    from querysense.output.html_report import render_html

    html = render_html(result)
    Path("report.html").write_text(html)
"""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding
    from querysense.parser.models import ExplainOutput


def render_html(
    result: "AnalysisResult",
    explain: "ExplainOutput | None" = None,
    title: str = "QuerySense Report",
) -> str:
    """
    Render analysis result as self-contained HTML.

    Args:
        result: Analysis result with findings
        explain: Optional ExplainOutput for plan tree visualization
        title: Page title

    Returns:
        Complete HTML string
    """
    summary = result.summary()

    # Build findings HTML
    findings_html = _render_findings_html(result.findings)

    # Build plan tree HTML
    plan_tree_html = ""
    if explain:
        plan_tree_html = _render_plan_tree_html(explain.plan)

    # Status badge
    if summary["critical"]:
        status_class = "status-critical"
        status_text = "Critical Issues Found"
    elif summary["warning"]:
        status_class = "status-warning"
        status_text = "Warnings Found"
    else:
        status_class = "status-pass"
        status_text = "No Issues Found"

    return _HTML_TEMPLATE.format(
        title=html.escape(title),
        status_class=status_class,
        status_text=html.escape(status_text),
        total_findings=summary["total"],
        critical_count=summary["critical"],
        warning_count=summary["warning"],
        info_count=summary["info"],
        evidence_level=html.escape(str(summary.get("evidence_level", "PLAN"))),
        rules_passed=summary.get("rules_passed", 0),
        rules_skipped=summary.get("rules_skipped", 0),
        rules_failed=summary.get("rules_failed", 0),
        plan_tree=plan_tree_html,
        findings=findings_html,
        findings_json=html.escape(json.dumps(
            [_finding_to_dict(f) for f in result.findings],
            indent=2,
            default=str,
        )),
    )


def _finding_to_dict(finding: "Finding") -> dict[str, Any]:
    """Convert finding to dict for JSON embed."""
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "suggestion": finding.suggestion,
        "table": finding.context.relation_name,
        "node_type": finding.context.node_type,
        "actual_rows": finding.context.actual_rows,
        "total_cost": finding.context.total_cost,
    }


def _render_findings_html(findings: tuple["Finding", ...]) -> str:
    """Render findings as HTML cards."""
    if not findings:
        return '<div class="no-findings">No performance issues detected.</div>'

    parts: list[str] = []
    for i, f in enumerate(findings, 1):
        sev = f.severity.value
        sev_class = f"severity-{sev}"
        icon = {"critical": "&#x1F534;", "warning": "&#x1F7E1;", "info": "&#x1F535;"}.get(sev, "")

        suggestion_html = ""
        if f.suggestion:
            suggestion_html = f"""
            <div class="suggestion">
                <div class="suggestion-label">Suggested Fix:</div>
                <pre><code>{html.escape(f.suggestion)}</code></pre>
            </div>"""

        metrics_html = ""
        if f.metrics:
            metric_items = "".join(
                f"<span class='metric'><strong>{k}:</strong> {v:,}</span>"
                if isinstance(v, int)
                else f"<span class='metric'><strong>{k}:</strong> {v}</span>"
                for k, v in f.metrics.items()
            )
            metrics_html = f'<div class="metrics">{metric_items}</div>'

        parts.append(f"""
        <div class="finding {sev_class}">
            <div class="finding-header">
                <span class="finding-icon">{icon}</span>
                <span class="finding-title">{html.escape(f.title)}</span>
                <span class="finding-badge">{sev.upper()}</span>
            </div>
            <div class="finding-rule">Rule: <code>{html.escape(f.rule_id)}</code></div>
            <div class="finding-description">{html.escape(f.description)}</div>
            {metrics_html}
            {suggestion_html}
        </div>""")

    return "\n".join(parts)


def _render_plan_tree_html(node: Any, depth: int = 0) -> str:
    """Render plan tree as nested HTML."""
    node_type = html.escape(node.node_type)
    relation = f" on <strong>{html.escape(node.relation_name)}</strong>" if node.relation_name else ""

    cost_info = f"cost={node.total_cost:,.0f}"
    rows_info = ""
    if node.actual_rows is not None:
        rows_info = f" rows={node.actual_rows:,}"
    timing_info = ""
    if hasattr(node, "actual_total_time") and node.actual_total_time is not None:
        timing_info = f" time={node.actual_total_time:.1f}ms"

    # Highlight problematic nodes
    node_class = "plan-node"
    if node.node_type == "Seq Scan" and node.actual_rows and node.actual_rows > 10000:
        node_class += " node-warning"
    if node.node_type in ("Sort", "Hash") and hasattr(node, "sort_space_type") and getattr(node, "sort_space_type", "") == "Disk":
        node_class += " node-critical"

    children_html = ""
    if node.plans:
        child_parts = [_render_plan_tree_html(child, depth + 1) for child in node.plans]
        children_html = f'<div class="plan-children">{"".join(child_parts)}</div>'

    return f"""
    <div class="{node_class}" style="margin-left: {depth * 24}px">
        <div class="node-header">
            <span class="node-type">{node_type}</span>{relation}
            <span class="node-stats">{cost_info}{rows_info}{timing_info}</span>
        </div>
        {children_html}
    </div>"""


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
:root {{
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --critical: #f85149;
    --warning: #d29922;
    --info: #58a6ff;
    --success: #3fb950;
    --code-bg: #1c2129;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 24px;
    max-width: 1200px;
    margin: 0 auto;
}}
h1 {{ font-size: 24px; font-weight: 600; margin-bottom: 16px; }}
h2 {{ font-size: 18px; font-weight: 600; margin: 24px 0 12px; color: var(--text-muted); }}

.status-badge {{
    display: inline-block;
    padding: 6px 16px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 14px;
    margin-bottom: 16px;
}}
.status-critical {{ background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }}
.status-warning {{ background: rgba(210,153,34,0.15); color: var(--warning); border: 1px solid var(--warning); }}
.status-pass {{ background: rgba(63,185,80,0.15); color: var(--success); border: 1px solid var(--success); }}

.summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin: 16px 0 24px;
}}
.summary-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}}
.summary-card .value {{ font-size: 28px; font-weight: 700; }}
.summary-card .label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; }}
.summary-card.critical .value {{ color: var(--critical); }}
.summary-card.warning .value {{ color: var(--warning); }}
.summary-card.info .value {{ color: var(--info); }}

.finding {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    margin: 12px 0;
    border-left: 4px solid var(--border);
}}
.finding.severity-critical {{ border-left-color: var(--critical); }}
.finding.severity-warning {{ border-left-color: var(--warning); }}
.finding.severity-info {{ border-left-color: var(--info); }}

.finding-header {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
}}
.finding-title {{ font-weight: 600; flex: 1; }}
.finding-badge {{
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 12px;
    font-weight: 600;
    text-transform: uppercase;
}}
.severity-critical .finding-badge {{ background: rgba(248,81,73,0.15); color: var(--critical); }}
.severity-warning .finding-badge {{ background: rgba(210,153,34,0.15); color: var(--warning); }}
.severity-info .finding-badge {{ background: rgba(88,166,255,0.15); color: var(--info); }}

.finding-rule {{ font-size: 13px; color: var(--text-muted); margin-bottom: 8px; }}
.finding-rule code {{ background: var(--code-bg); padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
.finding-description {{ font-size: 14px; white-space: pre-wrap; margin-bottom: 8px; }}

.suggestion {{
    background: var(--code-bg);
    border-radius: 6px;
    padding: 12px;
    margin-top: 8px;
}}
.suggestion-label {{ font-size: 12px; color: var(--success); font-weight: 600; margin-bottom: 6px; }}
.suggestion pre {{ margin: 0; overflow-x: auto; }}
.suggestion code {{ font-size: 13px; color: var(--success); font-family: 'SF Mono', 'Fira Code', monospace; }}

.metrics {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0; }}
.metric {{ font-size: 12px; color: var(--text-muted); }}
.metric strong {{ color: var(--text); }}

.plan-tree {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; overflow-x: auto; }}
.plan-node {{ padding: 4px 0; font-size: 13px; font-family: 'SF Mono', 'Fira Code', monospace; }}
.node-header {{ padding: 2px 8px; border-radius: 4px; }}
.node-header:hover {{ background: rgba(255,255,255,0.05); }}
.node-type {{ font-weight: 600; }}
.node-stats {{ color: var(--text-muted); font-size: 12px; margin-left: 8px; }}
.node-warning .node-header {{ background: rgba(210,153,34,0.1); }}
.node-critical .node-header {{ background: rgba(248,81,73,0.1); }}

.no-findings {{ padding: 24px; text-align: center; color: var(--success); font-size: 16px; }}

footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 12px; color: var(--text-muted); }}
footer a {{ color: var(--info); text-decoration: none; }}

.collapsible {{ cursor: pointer; }}
.collapsible::before {{ content: "\\25B6 "; font-size: 10px; }}
.collapsible.open::before {{ content: "\\25BC "; }}
.collapsible-content {{ display: none; }}
.collapsible-content.open {{ display: block; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="status-badge {status_class}">{status_text}</div>

<div class="summary-grid">
    <div class="summary-card critical"><div class="value">{critical_count}</div><div class="label">Critical</div></div>
    <div class="summary-card warning"><div class="value">{warning_count}</div><div class="label">Warnings</div></div>
    <div class="summary-card info"><div class="value">{info_count}</div><div class="label">Info</div></div>
    <div class="summary-card"><div class="value">{rules_passed}</div><div class="label">Rules Passed</div></div>
    <div class="summary-card"><div class="value">{evidence_level}</div><div class="label">Evidence</div></div>
</div>

<h2>Findings ({total_findings})</h2>
{findings}

<h2 class="collapsible" onclick="toggleSection(this)">Plan Tree</h2>
<div class="collapsible-content plan-tree">
{plan_tree}
</div>

<footer>
    Generated by <a href="https://github.com/JosephAhn23/Query-Sense">QuerySense</a> &mdash; PostgreSQL query performance analyzer
</footer>

<script>
function toggleSection(el) {{
    el.classList.toggle('open');
    const content = el.nextElementSibling;
    if (content) content.classList.toggle('open');
}}
// Auto-open plan tree if present
document.querySelectorAll('.collapsible').forEach(el => {{
    const content = el.nextElementSibling;
    if (content && content.innerHTML.trim()) {{
        el.classList.add('open');
        content.classList.add('open');
    }}
}});
</script>
</body>
</html>"""
