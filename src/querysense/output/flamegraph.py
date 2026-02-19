"""
D3.js flame graph HTML report generator.

Generates a self-contained HTML report with an interactive D3.js flame
graph visualization of the query plan tree.  Each node's width represents
its cost relative to the total query cost, making it instantly obvious
where time is spent.

This is the "shareable report" format — a single HTML file with
inline D3.js that can be opened in any browser.

Usage:
    from querysense.output.flamegraph import render_flamegraph_html

    html = render_flamegraph_html(result, explain=explain)
    Path("report.html").write_text(html)
"""

from __future__ import annotations

import html as html_mod
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding
    from querysense.parser.models import ExplainOutput, PlanNode


def _plan_to_flamegraph_data(node: "PlanNode", depth: int = 0) -> dict[str, Any]:
    """
    Convert a PlanNode tree to D3 flame graph data format.

    Each node becomes:
    {
        "name": "Seq Scan on orders",
        "value": <total_cost>,
        "children": [...],
        "data": { node metadata }
    }
    """
    label = node.node_type
    if node.relation_name:
        label += f" on {node.relation_name}"
    if node.index_name:
        label += f" ({node.index_name})"

    # Use actual_total_time if available, otherwise total_cost
    if node.actual_total_time is not None:
        loops = node.actual_loops or 1
        value = node.actual_total_time * loops
    else:
        value = node.total_cost

    # Ensure minimum value so nodes are visible
    value = max(value, 0.01)

    data: dict[str, Any] = {
        "node_type": node.node_type,
        "relation": node.relation_name,
        "index": node.index_name,
        "cost": node.total_cost,
        "rows_est": node.plan_rows,
        "rows_actual": node.actual_rows,
        "filter": node.filter,
        "depth": depth,
    }

    if node.actual_total_time is not None:
        data["time_ms"] = node.actual_total_time * (node.actual_loops or 1)
    if node.sort_space_type:
        data["sort_type"] = node.sort_space_type
    if node.rows_removed_by_filter:
        data["rows_removed"] = node.rows_removed_by_filter

    children = [
        _plan_to_flamegraph_data(child, depth + 1)
        for child in (node.plans or [])
    ]

    return {
        "name": label,
        "value": value,
        "children": children,
        "data": data,
    }


def _findings_to_json(findings: tuple["Finding", ...]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dicts."""
    return [
        {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "suggestion": f.suggestion,
            "impact_score": f.impact_score,
            "impact_band": f.impact_band.value,
            "metrics": {k: v for k, v in f.metrics.items()},
            "node_type": f.context.node_type,
            "relation": f.context.relation_name,
            "estimated_speedup": f.metrics.get("estimated_speedup", ""),
        }
        for f in findings
    ]


def render_flamegraph_html(
    result: "AnalysisResult",
    explain: "ExplainOutput | None" = None,
    title: str = "QuerySense Report",
) -> str:
    """
    Render analysis result as HTML with D3.js flame graph.

    Args:
        result: Analysis result with findings
        explain: ExplainOutput for flame graph visualization
        title: Page title

    Returns:
        Complete self-contained HTML string
    """
    summary = result.summary()

    # Flame graph data
    flamegraph_data = "{}"
    if explain:
        flamegraph_data = json.dumps(
            _plan_to_flamegraph_data(explain.plan),
            indent=2,
            default=str,
        )

    # Findings JSON
    findings_json = json.dumps(
        _findings_to_json(result.findings),
        indent=2,
        default=str,
    )

    # Status
    if summary["critical"]:
        status_class = "critical"
        status_text = "Critical Issues Found"
    elif summary["warning"]:
        status_class = "warning"
        status_text = "Warnings Found"
    else:
        status_class = "pass"
        status_text = "No Issues Found"

    return _FLAMEGRAPH_TEMPLATE.format(
        title=html_mod.escape(title),
        status_class=status_class,
        status_text=html_mod.escape(status_text),
        total=summary["total"],
        critical=summary["critical"],
        warning=summary["warning"],
        info=summary["info"],
        evidence=html_mod.escape(str(summary.get("evidence_level", "PLAN"))),
        flamegraph_data=flamegraph_data,
        findings_json=findings_json,
        execution_time=result.metadata.execution_time_ms or 0,
        node_count=result.metadata.node_count,
        analysis_id=html_mod.escape(result.reproducibility.analysis_id),
    )


_FLAMEGRAPH_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
:root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e;
    --crit: #f85149; --warn: #d29922; --info: #58a6ff; --pass: #3fb950;
    --code-bg: #1c2129;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    max-width: 1400px; margin: 0 auto; padding: 20px;
}}
h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 12px; }}
h2 {{ font-size: 16px; color: var(--muted); margin: 20px 0 8px; text-transform: uppercase; letter-spacing: 1px; }}

.header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }}
.badge {{ padding: 4px 14px; border-radius: 16px; font-weight: 600; font-size: 13px; }}
.badge.critical {{ background: rgba(248,81,73,0.15); color: var(--crit); border: 1px solid var(--crit); }}
.badge.warning {{ background: rgba(210,153,34,0.15); color: var(--warn); border: 1px solid var(--warn); }}
.badge.pass {{ background: rgba(63,185,80,0.15); color: var(--pass); border: 1px solid var(--pass); }}

.metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin: 16px 0; }}
.metric-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; text-align: center; }}
.metric-card .val {{ font-size: 26px; font-weight: 700; }}
.metric-card .lbl {{ font-size: 11px; color: var(--muted); text-transform: uppercase; }}
.metric-card.crit .val {{ color: var(--crit); }}
.metric-card.warn .val {{ color: var(--warn); }}
.metric-card.info .val {{ color: var(--info); }}

/* Flame graph */
#flamegraph {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin: 16px 0; overflow: hidden; }}
.flame-row {{ display: flex; width: 100%; margin-bottom: 1px; }}
.flame-cell {{
    height: 24px; line-height: 24px; font-size: 11px; padding: 0 4px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    border-right: 1px solid var(--bg); cursor: pointer;
    transition: filter 0.15s;
}}
.flame-cell:hover {{ filter: brightness(1.3); }}
.flame-tooltip {{
    position: fixed; background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 14px; font-size: 12px;
    pointer-events: none; z-index: 1000; max-width: 400px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
}}
.flame-tooltip .tt-title {{ font-weight: 600; margin-bottom: 4px; }}
.flame-tooltip .tt-row {{ color: var(--muted); }}

/* Findings */
.finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin: 10px 0; border-left: 4px solid var(--border); }}
.finding.sev-critical {{ border-left-color: var(--crit); }}
.finding.sev-warning {{ border-left-color: var(--warn); }}
.finding.sev-info {{ border-left-color: var(--info); }}
.finding-head {{ display: flex; align-items: center; gap: 8px; }}
.finding-title {{ font-weight: 600; flex: 1; font-size: 14px; }}
.finding-sev {{ font-size: 10px; padding: 2px 8px; border-radius: 10px; font-weight: 600; text-transform: uppercase; }}
.sev-critical .finding-sev {{ background: rgba(248,81,73,0.15); color: var(--crit); }}
.sev-warning .finding-sev {{ background: rgba(210,153,34,0.15); color: var(--warn); }}
.sev-info .finding-sev {{ background: rgba(88,166,255,0.15); color: var(--info); }}
.finding-body {{ font-size: 13px; color: var(--muted); margin-top: 6px; }}
.finding-speedup {{ display: inline-block; background: rgba(63,185,80,0.15); color: var(--pass); padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; margin-left: 8px; }}
.finding-fix {{ background: var(--code-bg); border-radius: 6px; padding: 10px; margin-top: 8px; font-size: 12px; }}
.finding-fix pre {{ margin: 0; color: var(--pass); font-family: 'SF Mono', 'Fira Code', monospace; white-space: pre-wrap; }}
.impact-bar {{ display: inline-block; width: 80px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; vertical-align: middle; margin: 0 6px; }}
.impact-fill {{ height: 100%; border-radius: 3px; }}

footer {{ margin-top: 24px; padding: 12px 0; border-top: 1px solid var(--border); font-size: 11px; color: var(--muted); }}
footer a {{ color: var(--info); text-decoration: none; }}
</style>
</head>
<body>
<div class="header">
    <h1>{title}</h1>
    <span class="badge {status_class}">{status_text}</span>
</div>

<div class="metrics">
    <div class="metric-card crit"><div class="val">{critical}</div><div class="lbl">Critical</div></div>
    <div class="metric-card warn"><div class="val">{warning}</div><div class="lbl">Warnings</div></div>
    <div class="metric-card info"><div class="val">{info}</div><div class="lbl">Info</div></div>
    <div class="metric-card"><div class="val">{node_count}</div><div class="lbl">Plan Nodes</div></div>
    <div class="metric-card"><div class="val">{evidence}</div><div class="lbl">Evidence</div></div>
</div>

<h2>Plan Flame Graph</h2>
<div id="flamegraph"></div>

<h2>Findings ({total})</h2>
<div id="findings"></div>

<footer>
    Generated by <a href="https://github.com/JosephAhn23/Query-Sense">QuerySense</a>
    &mdash; Analysis ID: <code>{analysis_id}</code>
</footer>

<div class="flame-tooltip" id="tooltip" style="display:none"></div>

<script>
// ── Flame Graph Data ────────────────────────────────────────────────
const planData = {flamegraph_data};
const findingsData = {findings_json};

// ── Color scheme ────────────────────────────────────────────────────
function nodeColor(d) {{
    const nt = (d.data && d.data.data && d.data.data.node_type) || d.name || '';
    if (nt.includes('Seq Scan')) return '#e06c60';
    if (nt.includes('Index Scan') || nt.includes('Index Only')) return '#58a6ff';
    if (nt.includes('Nested Loop')) return '#d29922';
    if (nt.includes('Hash Join') || nt.includes('Merge Join')) return '#d2a8ff';
    if (nt.includes('Sort')) return '#f0883e';
    if (nt.includes('Aggregate') || nt.includes('Group')) return '#a5d6ff';
    if (nt.includes('Hash')) return '#7ee787';
    if (nt.includes('Bitmap')) return '#79c0ff';
    if (nt.includes('Gather')) return '#ffa657';
    return '#8b949e';
}}

// ── Build flame graph ───────────────────────────────────────────────
function buildFlameGraph(container, data) {{
    if (!data || !data.name) {{
        container.innerHTML = '<div style="padding:20px;color:#8b949e;">No plan data available.</div>';
        return;
    }}

    // Flatten tree into rows by depth
    function flatten(node, depth) {{
        const result = [{{ ...node, depth }}];
        if (node.children) {{
            for (const child of node.children) {{
                result.push(...flatten(child, depth + 1));
            }}
        }}
        return result;
    }}

    const flat = flatten(data, 0);
    const maxDepth = Math.max(...flat.map(n => n.depth));
    const totalValue = data.value || 1;

    // Group by depth for row layout
    const rows = {{}};
    function addToRows(node, depth, startPct, widthPct) {{
        if (!rows[depth]) rows[depth] = [];
        rows[depth].push({{ ...node, startPct, widthPct, depth }});
        let childStart = startPct;
        if (node.children) {{
            for (const child of node.children) {{
                const childWidth = (child.value / totalValue) * 100;
                addToRows(child, depth + 1, childStart, childWidth);
                childStart += childWidth;
            }}
        }}
    }}
    addToRows(data, 0, 0, 100);

    // Render
    let html = '';
    for (let d = 0; d <= maxDepth; d++) {{
        const cells = rows[d] || [];
        html += '<div class="flame-row">';
        let cursor = 0;
        for (const cell of cells) {{
            if (cell.startPct > cursor) {{
                const gap = cell.startPct - cursor;
                html += `<div style="width:${{gap}}%;min-width:0"></div>`;
            }}
            const w = Math.max(cell.widthPct, 0.5);
            const bg = nodeColor({{ data: cell }});
            const meta = cell.data || {{}};
            const dataAttrs = `data-name="${{cell.name}}" data-cost="${{meta.cost||''}}" data-rows="${{meta.rows_actual||meta.rows_est||''}}" data-time="${{meta.time_ms||''}}" data-filter="${{(meta.filter||'').replace(/"/g, '&quot;')}}"`;
            html += `<div class="flame-cell" style="width:${{w}}%;background:${{bg}}" ${{dataAttrs}}>${{cell.name}}</div>`;
            cursor = cell.startPct + cell.widthPct;
        }}
        html += '</div>';
    }}
    container.innerHTML = html;

    // Tooltips
    const tooltip = document.getElementById('tooltip');
    container.addEventListener('mouseover', function(e) {{
        const cell = e.target.closest('.flame-cell');
        if (!cell) {{ tooltip.style.display = 'none'; return; }}
        let ttHtml = `<div class="tt-title">${{cell.dataset.name}}</div>`;
        if (cell.dataset.cost) ttHtml += `<div class="tt-row">Cost: ${{Number(cell.dataset.cost).toLocaleString()}}</div>`;
        if (cell.dataset.rows) ttHtml += `<div class="tt-row">Rows: ${{Number(cell.dataset.rows).toLocaleString()}}</div>`;
        if (cell.dataset.time) ttHtml += `<div class="tt-row">Time: ${{Number(cell.dataset.time).toFixed(1)}}ms</div>`;
        if (cell.dataset.filter) ttHtml += `<div class="tt-row">Filter: ${{cell.dataset.filter}}</div>`;
        tooltip.innerHTML = ttHtml;
        tooltip.style.display = 'block';
    }});
    container.addEventListener('mousemove', function(e) {{
        tooltip.style.left = (e.clientX + 12) + 'px';
        tooltip.style.top = (e.clientY + 12) + 'px';
    }});
    container.addEventListener('mouseout', function(e) {{
        if (!e.target.closest('.flame-cell')) tooltip.style.display = 'none';
    }});
}}

// ── Render findings ─────────────────────────────────────────────────
function renderFindings(container, findings) {{
    if (!findings.length) {{
        container.innerHTML = '<div style="padding:20px;color:#3fb950;">No performance issues detected.</div>';
        return;
    }}
    let html = '';
    for (const f of findings) {{
        const sevClass = 'sev-' + f.severity;
        const speedup = f.estimated_speedup ? `<span class="finding-speedup">${{f.estimated_speedup}}</span>` : '';
        const score = f.impact_score;
        const pct = (score / 10) * 100;
        const barColor = score >= 7 ? '#f85149' : score >= 4 ? '#d29922' : '#58a6ff';
        const impactHtml = score > 0 ? `<span class="impact-bar"><span class="impact-fill" style="width:${{pct}}%;background:${{barColor}}"></span></span>${{score.toFixed(1)}}/10` : '';

        let fixHtml = '';
        if (f.suggestion) {{
            fixHtml = `<div class="finding-fix"><pre>${{f.suggestion.replace(/</g, '&lt;')}}</pre></div>`;
        }}

        html += `
        <div class="finding ${{sevClass}}">
            <div class="finding-head">
                <span class="finding-title">${{f.title}}</span>
                ${{speedup}}
                <span class="finding-sev">${{f.severity}}</span>
            </div>
            <div class="finding-body">
                ${{impactHtml}}
                <p style="margin:6px 0">${{f.description}}</p>
                ${{fixHtml}}
            </div>
        </div>`;
    }}
    container.innerHTML = html;
}}

// ── Init ────────────────────────────────────────────────────────────
buildFlameGraph(document.getElementById('flamegraph'), planData);
renderFindings(document.getElementById('findings'), findingsData);
</script>
</body>
</html>"""
