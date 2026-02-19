"""
SVG Plan Tree Visualization (v2).

Generates a clean SVG diagram of a PostgreSQL EXPLAIN plan tree.
No external dependencies (no Graphviz) — pure Python SVG generation.

v2 upgrades (pgMustard-beating):
- Continuous cost heatmap (green → amber → red gradient)
- Row accuracy badges (actual vs estimated comparison)
- Buffer hit rate indicators
- Interactive data attributes for JS-based tooltips
- Exclusive cost and time calculations
- Collapsible subtree markers
- Filter condition display
- Execution loop warnings
- Improved typography and spacing

Inspired by pgMustard's clarity: each node is a box with type,
cost bar, and row count. Edges show parent-child relationships.

Usage:
    from querysense.viz.svg_plan import render_plan_svg
    svg_string = render_plan_svg(plan_json)
"""

from __future__ import annotations

import html
import json
import math
from dataclasses import dataclass, field


# ── Theme ────────────────────────────────────────────────────────────────

# Operator-specific colors: (bg, text, accent)
NODE_COLORS = {
    # Scans
    "Seq Scan":           ("#fef3c7", "#92400e", "#f59e0b"),  # amber - warning
    "Index Scan":         ("#d1fae5", "#065f46", "#10b981"),  # green - good
    "Index Only Scan":    ("#d1fae5", "#065f46", "#10b981"),
    "Bitmap Heap Scan":   ("#e0e7ff", "#3730a3", "#6366f1"),  # indigo
    "Bitmap Index Scan":  ("#e0e7ff", "#3730a3", "#6366f1"),
    "CTE Scan":           ("#fdf4ff", "#701a75", "#d946ef"),  # fuchsia
    "Subquery Scan":      ("#fdf4ff", "#701a75", "#d946ef"),
    # Joins
    "Hash Join":          ("#fce7f3", "#831843", "#ec4899"),  # pink
    "Merge Join":         ("#fce7f3", "#831843", "#ec4899"),
    "Nested Loop":        ("#fff1f2", "#9f1239", "#fb7185"),  # rose
    # Sort & Aggregate
    "Sort":               ("#fed7aa", "#7c2d12", "#f97316"),  # orange
    "Incremental Sort":   ("#fed7aa", "#7c2d12", "#f97316"),
    "Aggregate":          ("#e9d5ff", "#581c87", "#a855f7"),  # purple
    "HashAggregate":      ("#e9d5ff", "#581c87", "#a855f7"),
    "GroupAggregate":      ("#e9d5ff", "#581c87", "#a855f7"),
    "WindowAgg":          ("#e9d5ff", "#581c87", "#a855f7"),
    # Control
    "Limit":              ("#cffafe", "#155e75", "#06b6d4"),  # cyan
    "Append":             ("#ccfbf1", "#134e4a", "#14b8a6"),  # teal
    "Gather":             ("#ccfbf1", "#134e4a", "#14b8a6"),
    "Gather Merge":       ("#ccfbf1", "#134e4a", "#14b8a6"),
    "Materialize":        ("#dbeafe", "#1e3a8a", "#3b82f6"),  # blue
    "Unique":             ("#dbeafe", "#1e3a8a", "#3b82f6"),
    "Result":             ("#f1f5f9", "#334155", "#94a3b8"),  # slate
    "ModifyTable":        ("#fef2f2", "#991b1b", "#ef4444"),  # red
}

DEFAULT_COLOR = ("#f1f5f9", "#334155", "#94a3b8")  # slate

# Node type icons (Unicode)
NODE_ICONS = {
    "Seq Scan": "⊞", "Index Scan": "⊟", "Index Only Scan": "⊡",
    "Bitmap Heap Scan": "▦", "Bitmap Index Scan": "▥",
    "Hash Join": "⋈", "Merge Join": "⋈", "Nested Loop": "↻",
    "Sort": "↕", "Incremental Sort": "↕↕",
    "Aggregate": "Σ", "HashAggregate": "Σ#", "GroupAggregate": "Σ⊞",
    "WindowAgg": "⊞Σ", "Limit": "⊤", "Gather": "⇶",
    "Gather Merge": "⇶↕", "CTE Scan": "↪", "Materialize": "▣",
    "Append": "⊕", "Result": "⊙", "Subquery Scan": "↳",
}

# Layout constants
NODE_WIDTH = 240
NODE_HEIGHT = 72
H_GAP = 28
V_GAP = 52
PADDING_X = 40
PADDING_Y = 40


# ── Cost heatmap color interpolation ─────────────────────────────────

def _cost_heatmap_color(cost_pct: float) -> str:
    """
    Compute a continuous heatmap color from cost percentage.

    0%   → #22c55e (green)
    25%  → #84cc16 (lime)
    50%  → #f59e0b (amber)
    75%  → #ef4444 (red)
    100% → #991b1b (dark red)
    """
    stops = [
        (0,    (0x22, 0xc5, 0x5e)),
        (25,   (0x84, 0xcc, 0x16)),
        (50,   (0xf5, 0x9e, 0x0b)),
        (75,   (0xef, 0x44, 0x44)),
        (100,  (0x99, 0x1b, 0x1b)),
    ]

    pct = max(0, min(100, cost_pct))

    # Find the two stops to interpolate between
    for i in range(len(stops) - 1):
        p1, c1 = stops[i]
        p2, c2 = stops[i + 1]
        if pct <= p2:
            t = (pct - p1) / (p2 - p1) if p2 > p1 else 0
            r = int(c1[0] + (c2[0] - c1[0]) * t)
            g = int(c1[1] + (c2[1] - c1[1]) * t)
            b = int(c1[2] + (c2[2] - c1[2]) * t)
            return f"#{r:02x}{g:02x}{b:02x}"

    return "#991b1b"


def _row_accuracy_badge(actual: int | None, estimated: int | None) -> tuple[str, str]:
    """
    Return (badge_text, badge_color) for row estimate accuracy.

    Green if within 2×, amber if within 10×, red if worse.
    """
    if actual is None or estimated is None or estimated == 0:
        return ("", "")

    ratio = actual / estimated

    if 0.5 <= ratio <= 2.0:
        return ("✓", "#16a34a")
    if 0.1 <= ratio <= 10.0:
        return (f"{ratio:.1f}×", "#f59e0b")
    return (f"{ratio:.0f}×", "#dc2626")


# ── Layout data structure ────────────────────────────────────────────

@dataclass
class LayoutNode:
    """A positioned node in the plan tree."""

    node_type: str
    relation: str
    index_name: str
    total_cost: float
    startup_cost: float
    exclusive_cost: float
    cost_pct: float
    actual_rows: int | None
    plan_rows: int | None
    loops: int
    actual_time: float | None
    exclusive_time: float | None
    filter_cond: str
    join_type: str
    sort_info: str
    buffer_hit_rate: float | None  # 0-100
    temp_written: int
    row_accuracy_badge: str
    row_accuracy_color: str
    x: float = 0
    y: float = 0
    width: float = NODE_WIDTH
    height: float = NODE_HEIGHT
    children: list["LayoutNode"] = field(default_factory=list)
    subtree_width: float = 0


def _parse_tree(node: dict, total_cost: float, depth: int = 0) -> LayoutNode:
    """Recursively parse a plan dict into a LayoutNode tree."""
    children_cost = sum(c.get("Total Cost", 0) for c in node.get("Plans", []))
    exclusive = max(0, node.get("Total Cost", 0) - children_cost)
    cost_pct = (exclusive / total_cost * 100) if total_cost > 0 else 0

    # Exclusive time
    actual_time = node.get("Actual Total Time")
    children_time = sum(c.get("Actual Total Time", 0) for c in node.get("Plans", []))
    exclusive_time = max(0, actual_time - children_time) if actual_time is not None else None

    # Buffer hit rate
    hits = node.get("Shared Hit Blocks", 0) or 0
    reads = node.get("Shared Read Blocks", 0) or 0
    buffer_hit_rate = None
    if hits + reads > 0:
        buffer_hit_rate = (hits / (hits + reads)) * 100

    # Row accuracy
    actual_rows = node.get("Actual Rows")
    plan_rows = node.get("Plan Rows")
    badge_text, badge_color = _row_accuracy_badge(actual_rows, plan_rows)

    # Filter condition
    filter_cond = node.get("Filter", "") or node.get("Index Cond", "") or node.get("Hash Cond", "")

    # Sort info
    sort_info = ""
    if node.get("Sort Key"):
        keys = node["Sort Key"]
        method = node.get("Sort Method", "Sort")
        sort_info = f"{method}: {', '.join(keys) if isinstance(keys, list) else str(keys)}"

    ln = LayoutNode(
        node_type=node.get("Node Type", "Unknown"),
        relation=node.get("Relation Name") or "",
        index_name=node.get("Index Name") or "",
        total_cost=node.get("Total Cost", 0),
        startup_cost=node.get("Startup Cost", 0),
        exclusive_cost=exclusive,
        cost_pct=cost_pct,
        actual_rows=actual_rows,
        plan_rows=plan_rows,
        loops=node.get("Actual Loops", 1) or 1,
        actual_time=actual_time,
        exclusive_time=exclusive_time,
        filter_cond=filter_cond,
        join_type=node.get("Join Type", ""),
        sort_info=sort_info,
        buffer_hit_rate=buffer_hit_rate,
        temp_written=node.get("Temp Written Blocks", 0) or 0,
        row_accuracy_badge=badge_text,
        row_accuracy_color=badge_color,
    )

    for child in node.get("Plans", []):
        ln.children.append(_parse_tree(child, total_cost, depth + 1))

    return ln


def _layout(node: LayoutNode, x: float, y: float) -> None:
    """Assign x, y coordinates to each node using a simple top-down layout."""
    _compute_widths(node)
    _assign_positions(node, x, y)


def _compute_widths(node: LayoutNode) -> None:
    """Compute the total width needed for each subtree."""
    if not node.children:
        node.subtree_width = node.width
        return

    for child in node.children:
        _compute_widths(child)

    total_children_width = sum(c.subtree_width for c in node.children)
    total_children_width += H_GAP * (len(node.children) - 1)
    node.subtree_width = max(node.width, total_children_width)


def _assign_positions(node: LayoutNode, x: float, y: float) -> None:
    """Assign x, y positions to nodes."""
    node.x = x + (node.subtree_width - node.width) / 2
    node.y = y

    if not node.children:
        return

    total_children_width = sum(c.subtree_width for c in node.children)
    total_children_width += H_GAP * (len(node.children) - 1)
    child_x = x + (node.subtree_width - total_children_width) / 2

    for child in node.children:
        _assign_positions(child, child_x, y + NODE_HEIGHT + V_GAP)
        child_x += child.subtree_width + H_GAP


def _collect_nodes(node: LayoutNode) -> list[LayoutNode]:
    """Flatten the tree into a list of all nodes."""
    result = [node]
    for child in node.children:
        result.extend(_collect_nodes(child))
    return result


# ── SVG rendering ────────────────────────────────────────────────────


def _render_node_svg(node: LayoutNode) -> str:
    """Render a single node as SVG markup with rich detail."""
    bg, text_color, bar_color = NODE_COLORS.get(node.node_type, DEFAULT_COLOR)
    heatmap_color = _cost_heatmap_color(node.cost_pct)
    icon = NODE_ICONS.get(node.node_type, "●")

    lines: list[str] = []

    # Interactive data attributes for JS tooltip hookup
    data_attrs = (
        f'data-node-type="{html.escape(node.node_type)}" '
        f'data-cost="{node.total_cost:.1f}" '
        f'data-exclusive-cost="{node.exclusive_cost:.1f}" '
        f'data-cost-pct="{node.cost_pct:.1f}" '
        f'data-rows="{node.actual_rows or ""}" '
        f'data-plan-rows="{node.plan_rows or ""}" '
        f'data-time="{node.actual_time or ""}" '
        f'data-exclusive-time="{node.exclusive_time or ""}" '
        f'data-loops="{node.loops}" '
        f'data-relation="{html.escape(node.relation)}" '
        f'data-index="{html.escape(node.index_name)}" '
        f'data-filter="{html.escape(node.filter_cond)}"'
    )

    lines.append(
        f'<g transform="translate({node.x:.1f},{node.y:.1f})" '
        f'class="plan-node" style="cursor:pointer;" {data_attrs}>'
    )

    # Drop shadow
    lines.append(
        f'<rect x="2" y="2" width="{node.width}" height="{node.height}" '
        f'rx="10" fill="#00000008" />'
    )

    # Main box
    lines.append(
        f'<rect width="{node.width}" height="{node.height}" rx="10" '
        f'fill="{bg}" stroke="{bar_color}" stroke-width="1.5" />'
    )

    # Cost heatmap bar (top)
    bar_width = max(2, node.cost_pct / 100 * (node.width - 0))
    lines.append(
        f'<rect x="0" y="0" width="{node.width}" height="5" rx="3" '
        f'fill="#e2e8f0" opacity="0.3" />'
    )
    lines.append(
        f'<rect x="0" y="0" width="{bar_width:.1f}" height="5" rx="3" '
        f'fill="{heatmap_color}" opacity="0.85" />'
    )

    # Icon + Node type label
    label = html.escape(node.node_type)
    relation_part = ""
    if node.relation:
        relation_part = f' <tspan fill="{text_color}90" font-size="10">→ {html.escape(node.relation)}</tspan>'
    elif node.index_name:
        relation_part = f' <tspan fill="{text_color}90" font-size="10">({html.escape(node.index_name)})</tspan>'

    lines.append(
        f'<text x="12" y="24" font-family="Inter, system-ui, sans-serif" '
        f'font-size="12" font-weight="600" fill="{text_color}">'
        f'{icon} {label}{relation_part}</text>'
    )

    # Stats line 1: cost + time
    stats1_parts = []
    if node.cost_pct >= 0.5:
        stats1_parts.append(f"{node.cost_pct:.0f}% cost")
    if node.exclusive_time is not None:
        stats1_parts.append(_format_time(node.exclusive_time))
    if node.loops > 1:
        stats1_parts.append(f"×{node.loops}")

    stats1_text = html.escape(" · ".join(stats1_parts))
    lines.append(
        f'<text x="12" y="40" font-family="Inter, system-ui, sans-serif" '
        f'font-size="10" fill="{text_color}90">{stats1_text}</text>'
    )

    # Stats line 2: rows + buffer info
    stats2_parts = []
    if node.actual_rows is not None:
        rows_str = _format_number(node.actual_rows)
        stats2_parts.append(f"{rows_str} rows")
    elif node.plan_rows is not None:
        rows_str = _format_number(node.plan_rows)
        stats2_parts.append(f"~{rows_str} rows")

    if node.buffer_hit_rate is not None:
        stats2_parts.append(f"buf {node.buffer_hit_rate:.0f}%")

    if node.temp_written > 0:
        stats2_parts.append(f"⚠ temp: {_format_number(node.temp_written)} blk")

    stats2_text = html.escape(" · ".join(stats2_parts))
    lines.append(
        f'<text x="12" y="54" font-family="Inter, system-ui, sans-serif" '
        f'font-size="10" fill="{text_color}80">{stats2_text}</text>'
    )

    # Filter condition (truncated)
    if node.filter_cond:
        filter_display = html.escape(node.filter_cond[:35] + ("…" if len(node.filter_cond) > 35 else ""))
        lines.append(
            f'<text x="12" y="66" font-family="monospace" '
            f'font-size="8" fill="{text_color}60">{filter_display}</text>'
        )

    # Row accuracy badge (top-right corner)
    if node.row_accuracy_badge:
        badge_x = node.width - 8
        lines.append(
            f'<circle cx="{badge_x}" cy="12" r="7" fill="{node.row_accuracy_color}" opacity="0.9" />'
        )
        lines.append(
            f'<text x="{badge_x}" y="15" font-family="Inter, system-ui, sans-serif" '
            f'font-size="7" font-weight="700" fill="white" text-anchor="middle">'
            f'{html.escape(node.row_accuracy_badge)}</text>'
        )

    # Loop warning badge (bottom-right)
    if node.loops > 1:
        badge_x = node.width - 8
        badge_y = node.height - 10
        lines.append(
            f'<circle cx="{badge_x}" cy="{badge_y}" r="7" fill="#f59e0b" opacity="0.9" />'
        )
        lines.append(
            f'<text x="{badge_x}" y="{badge_y + 3}" font-family="Inter, system-ui, sans-serif" '
            f'font-size="7" font-weight="700" fill="white" text-anchor="middle">'
            f'×{node.loops}</text>'
        )

    lines.append("</g>")
    return "\n".join(lines)


def _render_edge_svg(parent: LayoutNode, child: LayoutNode) -> str:
    """Render a curved edge with row-count-proportional width."""
    px = parent.x + parent.width / 2
    py = parent.y + parent.height
    cx = child.x + child.width / 2
    cy = child.y

    mid_y = (py + cy) / 2

    # Width proportional to rows flowing
    rows = child.actual_rows or child.plan_rows or 1
    stroke_width = max(1.0, min(4.0, 1.0 + math.log10(max(rows, 1))))

    # Color by child cost
    edge_color = _cost_heatmap_color(child.cost_pct) if child.cost_pct > 10 else "#94a3b8"

    return (
        f'<path d="M {px:.1f} {py:.1f} C {px:.1f} {mid_y:.1f}, '
        f'{cx:.1f} {mid_y:.1f}, {cx:.1f} {cy:.1f}" '
        f'fill="none" stroke="{edge_color}" stroke-width="{stroke_width:.1f}" '
        f'stroke-linecap="round" stroke-opacity="0.6" />'
    )


def _format_number(n: int) -> str:
    """Format large numbers with K/M suffixes."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _format_time(ms: float) -> str:
    """Format milliseconds with appropriate unit."""
    if ms >= 1000:
        return f"{ms / 1000:.2f}s"
    return f"{ms:.1f}ms"


def render_plan_svg(plan_json: str) -> str:
    """
    Generate an SVG visualization of a PostgreSQL EXPLAIN plan.

    Args:
        plan_json: Raw EXPLAIN JSON string.

    Returns:
        SVG string ready for embedding in HTML or saving to file.
    """
    try:
        data = json.loads(plan_json)
        if isinstance(data, list):
            data = data[0]
        root_node = data.get("Plan", data)
    except (json.JSONDecodeError, IndexError, KeyError):
        return (
            '<svg width="400" height="60" xmlns="http://www.w3.org/2000/svg">'
            '<text x="10" y="30" font-size="14" fill="#ef4444">'
            'Invalid plan JSON</text></svg>'
        )

    total_cost = root_node.get("Total Cost", 0)
    tree = _parse_tree(root_node, total_cost)
    _layout(tree, PADDING_X, PADDING_Y)

    all_nodes = _collect_nodes(tree)

    # Compute SVG dimensions
    max_x = max(n.x + n.width for n in all_nodes) + PADDING_X
    max_y = max(n.y + n.height for n in all_nodes) + PADDING_Y
    svg_width = max(max_x, 400)
    svg_height = max(max_y, 120)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_width:.0f}" height="{svg_height:.0f}" '
        f'viewBox="0 0 {svg_width:.0f} {svg_height:.0f}" '
        f'style="font-family: Inter, system-ui, sans-serif; background: transparent;">',
    ]

    # CSS for hover effects
    parts.append("""<style>
        .plan-node:hover rect:first-of-type { filter: brightness(1.05); }
        .plan-node:hover { transform: translateY(-1px); transition: transform 0.1s ease; }
        .plan-node { transition: opacity 0.2s ease; }
    </style>""")

    # Cost heatmap legend
    parts.append(
        f'<g transform="translate({svg_width - 160:.0f}, 8)">'
        f'<text x="0" y="0" font-size="9" fill="#94a3b8" font-weight="500">Cost Heatmap</text>'
        f'<defs><linearGradient id="hm-grad" x1="0%" x2="100%">'
        f'<stop offset="0%" stop-color="#22c55e"/>'
        f'<stop offset="30%" stop-color="#84cc16"/>'
        f'<stop offset="55%" stop-color="#f59e0b"/>'
        f'<stop offset="80%" stop-color="#ef4444"/>'
        f'<stop offset="100%" stop-color="#991b1b"/>'
        f'</linearGradient></defs>'
        f'<rect x="0" y="6" width="120" height="6" rx="3" fill="url(#hm-grad)"/>'
        f'<text x="0" y="22" font-size="8" fill="#94a3b8">Low</text>'
        f'<text x="120" y="22" font-size="8" fill="#94a3b8" text-anchor="end">High</text>'
        f'</g>'
    )

    # Render edges first (behind nodes)
    for node in all_nodes:
        for child in node.children:
            parts.append(_render_edge_svg(node, child))

    # Render nodes
    for node in all_nodes:
        parts.append(_render_node_svg(node))

    parts.append("</svg>")
    return "\n".join(parts)
