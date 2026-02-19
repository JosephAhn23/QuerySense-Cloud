"""
Business logic service layer for QuerySense Cloud.

Uses AnalysisService as the single orchestration entry point —
the same service that CLI and CI use. This ensures consistent
behavior across all delivery mechanisms.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import querysense
from querysense.analyzer.comparator import compare_analyses
from querysense.engine import AnalysisService
from querysense.output.renderers import OutputFormat, render

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult

logger = logging.getLogger(__name__)

# Shared AnalysisService instance (thread-safe, stateless)
_service: AnalysisService | None = None


def get_service() -> AnalysisService:
    """Get or create the shared AnalysisService instance."""
    global _service
    if _service is None:
        _service = AnalysisService()
    return _service


def analyze_plan(
    plan_json: str,
    sql_text: str | None = None,
) -> tuple["AnalysisResult", str]:
    """
    Analyze an EXPLAIN plan and return the result.

    Args:
        plan_json: Raw EXPLAIN JSON string.
        sql_text: Optional SQL query text for enhanced analysis.

    Returns:
        (AnalysisResult, result_json_string)
    """
    plan_data = json.loads(plan_json)
    explain = querysense.parse_explain(plan_data)

    service = get_service()
    result = service.analyze(explain, sql=sql_text)

    result_json = render(result, format=OutputFormat.JSON)
    return result, result_json


def analyze_plan_to_dict(
    plan_json: str,
    sql_text: str | None = None,
) -> dict[str, Any]:
    """
    Analyze an EXPLAIN plan and return a JSON-serializable dict.

    Convenience wrapper for API responses.
    """
    _result, result_json = analyze_plan(plan_json, sql_text)
    return json.loads(result_json)


def compare_plans_service(
    before_json: str,
    after_json: str,
    before_sql: str | None = None,
    after_sql: str | None = None,
) -> dict[str, Any]:
    """
    Compare two EXPLAIN plans and return the comparison.

    Args:
        before_json: EXPLAIN JSON for the "before" plan.
        after_json: EXPLAIN JSON for the "after" plan.
        before_sql: Optional SQL for the before plan.
        after_sql: Optional SQL for the after plan.

    Returns:
        Comparison result as a JSON-serializable dict.
    """
    before_result, _ = analyze_plan(before_json, before_sql)
    after_result, _ = analyze_plan(after_json, after_sql)

    comparison = compare_analyses(before_result, after_result)
    return comparison.to_dict()


def get_summary_counts(result_json: str) -> dict[str, int]:
    """
    Extract summary counts from a stored result JSON.

    Returns dict with: findings_count, critical_count, warning_count, info_count
    """
    try:
        data = json.loads(result_json)
        summary = data.get("summary", {})
        return {
            "findings_count": summary.get("total", 0),
            "critical_count": summary.get("critical", 0),
            "warning_count": summary.get("warning", 0),
            "info_count": summary.get("info", 0),
        }
    except (json.JSONDecodeError, KeyError):
        return {
            "findings_count": 0,
            "critical_count": 0,
            "warning_count": 0,
            "info_count": 0,
        }


def compute_plan_insights(plan_json: str) -> dict[str, Any]:
    """
    Compute deep plan insights for the UI: cost distribution, time
    distribution, buffer stats, and auto-generated plan summary.

    This is the key "depth of analysis" enhancement — transforms raw
    EXPLAIN data into actionable visualizations and narratives.

    Returns a dict with:
    - cost_distribution: [{node_type, relation, cost_pct, exclusive_cost}, ...]
    - time_distribution: [{node_type, relation, time_pct, exclusive_time_ms}, ...]
    - buffer_summary: {total_shared_hit, total_shared_read, cache_hit_pct, ...}
    - plan_summary: Human-readable narrative of what the plan does
    - node_count: Total nodes in the plan
    - total_cost: Total plan cost
    - total_time_ms: Total execution time if available
    - bottleneck: {node_type, relation, cost_pct, description}
    """
    try:
        data = json.loads(plan_json)
        if isinstance(data, list):
            data = data[0]
        root = data.get("Plan", data)
    except (json.JSONDecodeError, IndexError, KeyError):
        return {}

    total_cost = root.get("Total Cost", 0)
    total_time = root.get("Actual Total Time")

    # Collect all nodes
    nodes_info: list[dict[str, Any]] = []
    total_shared_hit = 0
    total_shared_read = 0
    total_temp_read = 0
    total_temp_written = 0

    MAX_WALK_DEPTH = 200  # Guard against pathological nesting (DoS)

    def _walk(node: dict, depth: int = 0) -> None:
        nonlocal total_shared_hit, total_shared_read
        nonlocal total_temp_read, total_temp_written

        if depth > MAX_WALK_DEPTH:
            return  # Stop recursion for excessively deep plans

        children = node.get("Plans", [])
        children_cost = sum(c.get("Total Cost", 0) for c in children)
        exclusive_cost = max(0, node.get("Total Cost", 0) - children_cost)
        cost_pct = (exclusive_cost / total_cost * 100) if total_cost > 0 else 0

        children_time = sum(c.get("Actual Total Time", 0) for c in children)
        actual_time = node.get("Actual Total Time")
        exclusive_time = max(0, actual_time - children_time) if actual_time is not None else None
        loops = node.get("Actual Loops", 1) or 1
        time_contribution = exclusive_time * loops if exclusive_time is not None else None
        time_pct = (time_contribution / total_time * 100) if (total_time and time_contribution is not None) else None

        # Buffer data
        sh = node.get("Shared Hit Blocks", 0) or 0
        sr = node.get("Shared Read Blocks", 0) or 0
        tr = node.get("Temp Read Blocks", 0) or 0
        tw = node.get("Temp Written Blocks", 0) or 0
        total_shared_hit += sh
        total_shared_read += sr
        total_temp_read += tr
        total_temp_written += tw

        info: dict[str, Any] = {
            "node_type": node.get("Node Type", "Unknown"),
            "relation": node.get("Relation Name") or node.get("Index Name") or "",
            "exclusive_cost": round(exclusive_cost, 2),
            "cost_pct": round(cost_pct, 1),
            "depth": depth,
            "actual_rows": node.get("Actual Rows"),
            "plan_rows": node.get("Plan Rows"),
            "loops": loops,
            "filter": node.get("Filter"),
            "shared_hit": sh,
            "shared_read": sr,
        }

        if exclusive_time is not None:
            info["exclusive_time_ms"] = round(exclusive_time, 2)
        if time_pct is not None:
            info["time_pct"] = round(time_pct, 1)
        if time_contribution is not None:
            info["time_contribution_ms"] = round(time_contribution, 2)

        nodes_info.append(info)

        for child in children:
            _walk(child, depth + 1)

    _walk(root)

    # Sort for distributions
    cost_dist = sorted(nodes_info, key=lambda n: n["cost_pct"], reverse=True)
    time_dist = sorted(
        [n for n in nodes_info if n.get("time_pct") is not None],
        key=lambda n: n.get("time_pct", 0),
        reverse=True,
    )

    # Buffer summary
    total_blocks = total_shared_hit + total_shared_read
    cache_hit_pct = (total_shared_hit / total_blocks * 100) if total_blocks > 0 else 100.0
    buffer_summary = {
        "total_shared_hit": total_shared_hit,
        "total_shared_read": total_shared_read,
        "total_blocks": total_blocks,
        "cache_hit_pct": round(cache_hit_pct, 1),
        "total_temp_read": total_temp_read,
        "total_temp_written": total_temp_written,
        "has_buffer_data": total_blocks > 0,
        "has_temp_data": (total_temp_read + total_temp_written) > 0,
    }

    # Find bottleneck
    bottleneck = None
    if cost_dist:
        top = cost_dist[0]
        bottleneck = {
            "node_type": top["node_type"],
            "relation": top["relation"],
            "cost_pct": top["cost_pct"],
            "description": f"{top['node_type']}" + (f" on {top['relation']}" if top['relation'] else ""),
        }

    # Auto-generate plan summary
    plan_summary = _generate_plan_summary(root, nodes_info, total_cost, total_time, bottleneck)

    return {
        "cost_distribution": cost_dist[:10],
        "time_distribution": time_dist[:10],
        "buffer_summary": buffer_summary,
        "plan_summary": plan_summary,
        "node_count": len(nodes_info),
        "total_cost": round(total_cost, 2),
        "total_time_ms": round(total_time, 2) if total_time else None,
        "bottleneck": bottleneck,
    }


def _generate_plan_summary(
    root: dict,
    nodes_info: list[dict],
    total_cost: float,
    total_time: float | None,
    bottleneck: dict | None,
) -> str:
    """Generate a human-readable narrative of the query plan."""
    parts: list[str] = []

    # Plan shape
    node_count = len(nodes_info)
    scan_nodes = [n for n in nodes_info if "scan" in n["node_type"].lower()]
    join_nodes = [n for n in nodes_info if "join" in n["node_type"].lower() or "loop" in n["node_type"].lower()]
    sort_nodes = [n for n in nodes_info if "sort" in n["node_type"].lower()]
    agg_nodes = [n for n in nodes_info if "aggregate" in n["node_type"].lower() or "group" in n["node_type"].lower()]

    tables = list({n["relation"] for n in scan_nodes if n["relation"]})

    if tables:
        parts.append(f"This query accesses {len(tables)} table{'s' if len(tables) > 1 else ''}: {', '.join(tables)}.")
    else:
        parts.append(f"This plan has {node_count} nodes.")

    if join_nodes:
        join_types = list({n["node_type"] for n in join_nodes})
        parts.append(f" It uses {len(join_nodes)} join{'s' if len(join_nodes) > 1 else ''} ({', '.join(join_types)}).")

    if sort_nodes:
        parts.append(f" The result is sorted.")

    if agg_nodes:
        parts.append(f" Aggregation is performed.")

    # Performance summary
    if total_time is not None:
        if total_time < 1:
            parts.append(f" Execution time: {total_time:.2f}ms (very fast).")
        elif total_time < 100:
            parts.append(f" Execution time: {total_time:.1f}ms (fast).")
        elif total_time < 1000:
            parts.append(f" Execution time: {total_time:.0f}ms (moderate).")
        else:
            parts.append(f" Execution time: {total_time / 1000:.1f}s (slow).")

    # Bottleneck narrative
    if bottleneck and bottleneck["cost_pct"] > 40:
        parts.append(
            f" The primary bottleneck is {bottleneck['description']} "
            f"({bottleneck['cost_pct']:.0f}% of cost)."
        )

    # Row estimate issues
    bad_estimates = [
        n for n in nodes_info
        if n.get("actual_rows") is not None
        and n.get("plan_rows") is not None
        and n["plan_rows"] > 0
        and (n["actual_rows"] / n["plan_rows"] > 10 or n["actual_rows"] / n["plan_rows"] < 0.1)
    ]
    if bad_estimates:
        parts.append(
            f" {len(bad_estimates)} node{'s have' if len(bad_estimates) > 1 else ' has'} "
            f"significantly inaccurate row estimates — consider running ANALYZE."
        )

    return "".join(parts)


def render_analysis_markdown(result_json: str) -> str:
    """
    Re-render a stored analysis result as Markdown.

    Useful for share pages and PR comments.
    """
    # We stored the JSON output; parse and re-render is not straightforward
    # because we don't re-create the AnalysisResult object.
    # Instead, render a simplified markdown from the JSON dict.
    data = json.loads(result_json)
    lines: list[str] = []

    summary = data.get("summary", {})
    lines.append("# QuerySense Analysis Report")
    lines.append("")

    total = summary.get("total", 0)
    critical = summary.get("critical", 0)
    warning = summary.get("warning", 0)

    if critical:
        lines.append("**Critical issues found**")
    elif warning:
        lines.append("**Warnings found**")
    elif total == 0:
        lines.append("**No issues found**")
    lines.append("")

    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Evidence Level | `{data.get('evidence_level', 'PLAN')}` |")
    lines.append(f"| Total Findings | {total} |")
    lines.append(f"| Critical | {critical} |")
    lines.append(f"| Warnings | {warning} |")
    lines.append(f"| Info | {summary.get('info', 0)} |")
    lines.append("")

    findings = data.get("findings", [])
    if findings:
        lines.append("## Findings")
        lines.append("")
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info")
            icon = {"critical": "!!!", "warning": "!", "info": "i"}.get(sev, "")
            lines.append(f"### {i}. [{icon}] {f.get('title', 'Finding')}")
            lines.append("")
            lines.append(f"**Rule:** `{f.get('rule_id', '')}`  ")
            ctx = f.get("context", {})
            lines.append(f"**Location:** `{ctx.get('path', '')}`  ")
            impact = f.get("impact_band", "UNKNOWN")
            if impact != "UNKNOWN":
                lines.append(f"**Expected Impact:** {impact}")
            lines.append("")
            lines.append(f.get("description", ""))
            lines.append("")
            suggestion = f.get("suggestion")
            if suggestion:
                lines.append("**Suggestion:**")
                lines.append("")
                lines.append("```sql")
                lines.append(suggestion)
                lines.append("```")
                lines.append("")

    return "\n".join(lines)
