"""
Shared plan diff utility for comparing normalized plan trees.

This consolidates the duplicated diff logic from:
- querysense.baseline._diff_normalized_plans()
- querysense.upgrade.UpgradeValidator._diff_nodes()

Both modules now delegate to this shared implementation.

Usage:
    from querysense.plan_diff import diff_plan_nodes

    changes, added, removed = diff_plan_nodes(baseline_nodes, current_nodes)
"""

from __future__ import annotations

from typing import Any


def diff_plan_nodes(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """
    Diff two sets of plan nodes keyed by path.

    Each node dict must contain at least:
    - "node_type": str - The plan operator type (e.g., "Seq Scan")
    - "path": str - The tree path (e.g., "0.0.1") [optional, used in list format]

    May also contain:
    - "relation_name": str | None - Table name

    Args:
        before: Dict of path -> node_dict for the baseline plan.
        after: Dict of path -> node_dict for the current plan.

    Returns:
        Tuple of:
        - node_type_changes: List of {"path", "before", "after", "relation"}
        - nodes_added: List of "path: description" strings
        - nodes_removed: List of "path: description" strings
    """
    node_type_changes: list[dict[str, str]] = []
    nodes_added: list[str] = []
    nodes_removed: list[str] = []

    all_paths = sorted(set(before.keys()) | set(after.keys()))

    for path in all_paths:
        b_node = before.get(path)
        a_node = after.get(path)

        if b_node and a_node:
            # Both exist - check for node type change
            if b_node["node_type"] != a_node["node_type"]:
                node_type_changes.append({
                    "path": path,
                    "before": b_node["node_type"],
                    "after": a_node["node_type"],
                    "relation": (
                        b_node.get("relation_name")
                        or a_node.get("relation_name")
                        or ""
                    ),
                })

        elif b_node:
            # Removed in current plan
            desc = _node_description(b_node)
            nodes_removed.append(f"{path}: {desc}")

        else:
            # Added in current plan
            assert a_node is not None
            desc = _node_description(a_node)
            nodes_added.append(f"{path}: {desc}")

    return node_type_changes, nodes_added, nodes_removed


def _node_description(node: dict[str, Any]) -> str:
    """Build a human-readable description for a node."""
    desc = node["node_type"]
    relation = node.get("relation_name")
    if relation:
        desc += f" on {relation}"
    return desc
