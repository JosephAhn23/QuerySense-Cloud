"""
Graphviz DOT format plan graph generator.

Generates professional node-link diagrams of query plans in DOT format
for rendering with Graphviz (dot, neato, fdp) or compatible tools.

Usage:
    from querysense.output.graphviz import render_dot, render_dot_from_result

    # From EXPLAIN plan
    dot = render_dot(explain.plan)
    Path("plan.dot").write_text(dot)
    # Then: dot -Tsvg plan.dot -o plan.svg

    # From analysis result (includes finding annotations)
    dot = render_dot_from_result(result, explain)
    Path("plan.dot").write_text(dot)

CLI:
    querysense graph explain.json --output plan.dot
    querysense graph explain.json --output plan.svg  # auto-renders if dot is installed
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult
    from querysense.parser.models import ExplainOutput, PlanNode


# ── Node styling ─────────────────────────────────────────────────────

_NODE_COLORS: dict[str, tuple[str, str]] = {
    # node_type_prefix: (fill_color, font_color)
    "Seq Scan": ("#FF6B6B", "#FFFFFF"),
    "Index Scan": ("#4ECDC4", "#FFFFFF"),
    "Index Only Scan": ("#45B7D1", "#FFFFFF"),
    "Bitmap": ("#96CEB4", "#333333"),
    "Nested Loop": ("#FFEAA7", "#333333"),
    "Hash Join": ("#DDA0DD", "#333333"),
    "Merge Join": ("#C39BD3", "#FFFFFF"),
    "Sort": ("#F0B27A", "#333333"),
    "Aggregate": ("#85C1E9", "#333333"),
    "Hash": ("#82E0AA", "#333333"),
    "Gather": ("#F8C471", "#333333"),
    "Limit": ("#D5DBDB", "#333333"),
    "Materialize": ("#AEB6BF", "#333333"),
    "Append": ("#F9E79F", "#333333"),
    "Result": ("#D5D8DC", "#333333"),
}

_DEFAULT_COLORS = ("#BDC3C7", "#333333")


def _get_node_colors(node_type: str) -> tuple[str, str]:
    """Get fill and font color for a node type."""
    for prefix, colors in _NODE_COLORS.items():
        if node_type.startswith(prefix):
            return colors
    return _DEFAULT_COLORS


def _escape_dot(s: str) -> str:
    """Escape special characters for DOT labels."""
    return s.replace('"', '\\"').replace("<", "\\<").replace(">", "\\>").replace("\n", "\\n")


def _format_number(n: int | float) -> str:
    """Format a number with comma separators."""
    if isinstance(n, float):
        return f"{n:,.1f}"
    return f"{n:,}"


# ── DOT generation ───────────────────────────────────────────────────

def _node_label(node: "PlanNode") -> str:
    """Build a multi-line label for a plan node."""
    parts: list[str] = [node.node_type]

    if node.relation_name:
        parts.append(f"on {node.relation_name}")
    if node.index_name:
        parts.append(f"idx: {node.index_name}")

    # Metrics line
    metrics: list[str] = []
    if node.actual_rows is not None:
        metrics.append(f"rows={_format_number(node.actual_rows)}")
    else:
        metrics.append(f"est={_format_number(node.plan_rows)}")

    metrics.append(f"cost={_format_number(node.total_cost)}")

    if node.actual_total_time is not None:
        loops = node.actual_loops or 1
        total_ms = node.actual_total_time * loops
        if total_ms >= 1000:
            metrics.append(f"time={total_ms / 1000:.1f}s")
        else:
            metrics.append(f"time={total_ms:.1f}ms")

    parts.append(" | ".join(metrics))

    if node.filter:
        filt = node.filter
        if len(filt) > 40:
            filt = filt[:37] + "..."
        parts.append(f"filter: {filt}")

    return "\\n".join(parts)


def _node_shape(node: "PlanNode") -> str:
    """Determine shape based on node type."""
    if node.is_scan_node:
        return "box"
    if node.is_join_node:
        return "diamond"
    if node.node_type in ("Sort", "Incremental Sort"):
        return "parallelogram"
    if "Aggregate" in node.node_type or node.node_type == "Group":
        return "hexagon"
    return "ellipse"


def _build_dot_nodes(
    node: "PlanNode",
    node_id: int,
    lines: list[str],
    findings_by_table: dict[str, list[str]] | None = None,
) -> int:
    """
    Recursively build DOT node and edge definitions.

    Returns the next available node_id.
    """
    current_id = node_id
    fill_color, font_color = _get_node_colors(node.node_type)
    shape = _node_shape(node)
    label = _node_label(node)

    # Check if this node has findings
    border_color = fill_color
    penwidth = "1"
    if findings_by_table and node.relation_name:
        if node.relation_name in findings_by_table:
            border_color = "#FF0000"
            penwidth = "3"
            # Add finding annotations
            finding_labels = findings_by_table[node.relation_name]
            for fl in finding_labels[:2]:
                label += f"\\n!! {fl}"

    lines.append(
        f'    n{current_id} ['
        f'label="{_escape_dot(label)}", '
        f'shape={shape}, '
        f'style=filled, '
        f'fillcolor="{fill_color}", '
        f'fontcolor="{font_color}", '
        f'color="{border_color}", '
        f'penwidth={penwidth}, '
        f'fontname="Helvetica", '
        f'fontsize=10'
        f'];'
    )

    next_id = current_id + 1

    for child in (node.plans or []):
        child_id = next_id
        next_id = _build_dot_nodes(child, child_id, lines, findings_by_table)

        # Edge with row count label
        edge_label = ""
        if child.actual_rows is not None:
            edge_label = f"{_format_number(child.actual_rows)} rows"
        elif child.plan_rows:
            edge_label = f"~{_format_number(child.plan_rows)} rows"

        lines.append(
            f'    n{child_id} -> n{current_id} '
            f'[label="{_escape_dot(edge_label)}", '
            f'fontsize=8, fontcolor="#666666"];'
        )

    return next_id


# ── Public API ───────────────────────────────────────────────────────

def render_dot(
    plan: "PlanNode",
    title: str = "Query Plan",
) -> str:
    """
    Render a PlanNode tree as Graphviz DOT format.

    Args:
        plan: Root PlanNode from ExplainOutput
        title: Graph title

    Returns:
        DOT format string
    """
    lines: list[str] = [
        f'digraph "{_escape_dot(title)}" {{',
        '    rankdir=BT;',
        '    bgcolor="#0D1117";',
        '    node [margin="0.2,0.1"];',
        '    edge [color="#8B949E", arrowsize=0.7];',
        f'    label="{_escape_dot(title)}";',
        '    labelloc=t;',
        '    fontname="Helvetica";',
        '    fontsize=14;',
        '    fontcolor="#E6EDF3";',
        '',
    ]

    _build_dot_nodes(plan, 0, lines)

    lines.append("}")
    return "\n".join(lines)


def render_dot_from_result(
    result: "AnalysisResult",
    explain: "ExplainOutput",
    title: str = "QuerySense Analysis",
) -> str:
    """
    Render a plan as DOT with finding annotations.

    Nodes with findings are highlighted with red borders and
    include finding summaries in their labels.

    Args:
        result: AnalysisResult with findings
        explain: ExplainOutput with plan tree
        title: Graph title

    Returns:
        DOT format string with finding annotations
    """
    # Build findings-by-table lookup
    findings_by_table: dict[str, list[str]] = {}
    for f in result.findings:
        table = f.context.relation_name
        if table:
            if table not in findings_by_table:
                findings_by_table[table] = []
            findings_by_table[table].append(f.title[:50])

    lines: list[str] = [
        f'digraph "{_escape_dot(title)}" {{',
        '    rankdir=BT;',
        '    bgcolor="#0D1117";',
        '    node [margin="0.2,0.1"];',
        '    edge [color="#8B949E", arrowsize=0.7];',
        f'    label="{_escape_dot(title)}\\n'
        f'{len(result.findings)} finding(s)";',
        '    labelloc=t;',
        '    fontname="Helvetica";',
        '    fontsize=14;',
        '    fontcolor="#E6EDF3";',
        '',
    ]

    _build_dot_nodes(explain.plan, 0, lines, findings_by_table)

    # Add legend
    lines.append("")
    lines.append("    // Legend")
    lines.append('    subgraph cluster_legend {')
    lines.append('        label="Legend"; fontcolor="#8B949E"; fontsize=10;')
    lines.append('        style=dashed; color="#30363D";')
    lines.append('        legend_scan [label="Scan", shape=box, style=filled, fillcolor="#4ECDC4", fontcolor="#FFFFFF", fontsize=9];')
    lines.append('        legend_join [label="Join", shape=diamond, style=filled, fillcolor="#FFEAA7", fontcolor="#333333", fontsize=9];')
    lines.append('        legend_sort [label="Sort", shape=parallelogram, style=filled, fillcolor="#F0B27A", fontcolor="#333333", fontsize=9];')
    lines.append('        legend_issue [label="Issue!", shape=box, style=filled, fillcolor="#FF6B6B", fontcolor="#FFFFFF", color="#FF0000", penwidth=3, fontsize=9];')
    lines.append("    }")

    lines.append("}")
    return "\n".join(lines)
