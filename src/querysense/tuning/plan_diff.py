"""
Enhanced EXPLAIN Plan Diff Engine — structural comparison with similarity scoring.

Goes beyond the existing plan_diff.diff_plan_nodes() (path-keyed node comparison)
to provide:
  - Full plan-tree parsing from JSON and text EXPLAIN output
  - Structural normalization that strips costs/timing noise
  - Diff focusing on meaningful shape changes (join reorder, scan swap, etc.)
  - Per-node metric comparison (buffers, rows, time)
  - Similarity score for quick regression detection

Usage:
    from querysense.tuning.plan_diff import EnhancedPlanDiff

    differ = EnhancedPlanDiff()
    result = differ.diff(plan_json_a, plan_json_b)
    print(result.similarity_score)
    print(result.to_markdown())
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlanNode:
    """A single node in an EXPLAIN plan tree."""

    node_type: str
    relation: str | None = None
    alias: str | None = None
    cost_startup: float = 0.0
    cost_total: float = 0.0
    plan_rows: int = 0
    plan_width: int = 0
    actual_rows: int | None = None
    actual_time: float | None = None
    actual_loops: int | None = None
    buffers_hit: int = 0
    buffers_read: int = 0
    index_name: str | None = None
    filter: str | None = None
    join_type: str | None = None
    children: list[PlanNode] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def total_buffers(self) -> int:
        return self.buffers_hit + self.buffers_read

    @property
    def label(self) -> str:
        parts = [self.node_type]
        if self.relation:
            parts.append(f"on {self.relation}")
        if self.index_name:
            parts.append(f"using {self.index_name}")
        return " ".join(parts)


@dataclass
class StructuralChange:
    """A single structural difference between two plans."""

    change_type: str  # "replace", "insert", "delete"
    from_lines: list[str] = field(default_factory=list)
    to_lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.change_type}
        if self.from_lines:
            d["from"] = self.from_lines
        if self.to_lines:
            d["to"] = self.to_lines
        return d


@dataclass
class PlanDiffResult:
    """Complete result of comparing two plans."""

    structural_changes: list[StructuralChange] = field(default_factory=list)
    metric_diffs: dict[str, float] = field(default_factory=dict)
    node_matches: dict[str, str] = field(default_factory=dict)
    similarity_score: float = 0.0
    nodes_a: int = 0
    nodes_b: int = 0

    @property
    def is_same_shape(self) -> bool:
        return len(self.structural_changes) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "similarity_score": self.similarity_score,
            "is_same_shape": self.is_same_shape,
            "metric_diffs": self.metric_diffs,
            "structural_changes": [c.to_dict() for c in self.structural_changes],
            "node_matches": self.node_matches,
            "nodes_a": self.nodes_a,
            "nodes_b": self.nodes_b,
        }

    def to_markdown(self) -> str:
        """Render diff as Markdown suitable for CLI or PR comment."""
        lines: list[str] = []
        lines.append("## Plan Comparison\n")
        lines.append(f"**Similarity:** {self.similarity_score:.1f}%")
        lines.append(f"**Nodes:** {self.nodes_a} vs {self.nodes_b}\n")

        if self.metric_diffs:
            lines.append("### Metric Changes\n")
            for metric, pct in self.metric_diffs.items():
                if abs(pct) < 0.1:
                    continue
                direction = "slower" if pct > 0 else "faster"
                lines.append(f"- **{metric}**: {pct:+.1f}% ({direction})")
            lines.append("")

        if self.structural_changes:
            lines.append("### Structural Changes\n")
            for ch in self.structural_changes:
                if ch.change_type == "replace":
                    lines.append("**Replaced:**")
                    for ln in ch.from_lines:
                        lines.append(f"  - ~~{ln.strip()}~~")
                    for ln in ch.to_lines:
                        lines.append(f"  + **{ln.strip()}**")
                elif ch.change_type == "delete":
                    lines.append("**Removed:**")
                    for ln in ch.from_lines:
                        lines.append(f"  - ~~{ln.strip()}~~")
                elif ch.change_type == "insert":
                    lines.append("**Added:**")
                    for ln in ch.to_lines:
                        lines.append(f"  + **{ln.strip()}**")
            lines.append("")

        return "\n".join(lines)


# Regex for rudimentary text-format EXPLAIN parsing
_NODE_RE = re.compile(r"^(\s*)(->)?\s*(.+?)\s*\(cost=")
_COST_RE = re.compile(r"cost=([\d.]+)\.\.([\d.]+)")
_ROWS_RE = re.compile(r"rows=(\d+)")
_REL_RE = re.compile(r"\bon\s+(\w+)\b", re.IGNORECASE)


class EnhancedPlanDiff:
    """
    Intelligent EXPLAIN plan diff engine.

    Compares two plans structurally (ignoring cost/timing noise) and
    quantifies metric differences at the whole-plan level.
    """

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse(self, plan: str | dict | list) -> PlanNode:
        """Parse a plan from JSON dict, JSON string, or text EXPLAIN output."""
        if isinstance(plan, dict):
            root = plan.get("Plan", plan)
            return self._parse_json_node(root)

        if isinstance(plan, list):
            root = plan[0] if plan else {}
            if isinstance(root, dict):
                return self._parse_json_node(root.get("Plan", root))
            return PlanNode(node_type="Unknown")

        text = str(plan).strip()
        if text.startswith("[") or text.startswith("{"):
            data = json.loads(text)
            if isinstance(data, list):
                data = data[0]
            return self._parse_json_node(data.get("Plan", data))

        return self._parse_text(text)

    def _parse_json_node(self, node: dict[str, Any]) -> PlanNode:
        buffers = node.get("Buffers", {}) if isinstance(node.get("Buffers"), dict) else {}
        shared_hit = node.get("Shared Hit Blocks", buffers.get("shared_hit", 0)) or 0
        shared_read = node.get("Shared Read Blocks", buffers.get("shared_read", 0)) or 0

        pn = PlanNode(
            node_type=node.get("Node Type", "Unknown"),
            relation=node.get("Relation Name"),
            alias=node.get("Alias"),
            cost_startup=node.get("Startup Cost", 0),
            cost_total=node.get("Total Cost", 0),
            plan_rows=node.get("Plan Rows", 0),
            plan_width=node.get("Plan Width", 0),
            actual_rows=node.get("Actual Rows"),
            actual_time=node.get("Actual Total Time"),
            actual_loops=node.get("Actual Loops"),
            buffers_hit=shared_hit,
            buffers_read=shared_read,
            index_name=node.get("Index Name"),
            filter=node.get("Filter"),
            join_type=node.get("Join Type"),
            children=[
                self._parse_json_node(child) for child in node.get("Plans", [])
            ],
            raw=node,
        )
        return pn

    def _parse_text(self, text: str) -> PlanNode:
        """Best-effort parser for text-format EXPLAIN."""
        lines = text.split("\n")
        root, _ = self._parse_text_lines(lines, 0, indent_level=-1)
        return root

    def _parse_text_lines(
        self, lines: list[str], start: int, indent_level: int
    ) -> tuple[PlanNode, int]:
        if start >= len(lines):
            return PlanNode(node_type="Unknown"), start

        line = lines[start]
        stripped = line.lstrip()
        cur_indent = len(line) - len(stripped)

        # Extract node type
        node_type = stripped.lstrip("-> ").split("(")[0].strip()

        cost_m = _COST_RE.search(line)
        rows_m = _ROWS_RE.search(line)
        rel_m = _REL_RE.search(stripped)

        pn = PlanNode(
            node_type=node_type,
            relation=rel_m.group(1) if rel_m else None,
            cost_startup=float(cost_m.group(1)) if cost_m else 0,
            cost_total=float(cost_m.group(2)) if cost_m else 0,
            plan_rows=int(rows_m.group(1)) if rows_m else 0,
        )

        idx = start + 1
        while idx < len(lines):
            child_line = lines[idx]
            child_stripped = child_line.lstrip()
            child_indent = len(child_line) - len(child_stripped)
            if child_indent <= cur_indent and idx > start:
                break
            if "->" in child_stripped:
                child, idx = self._parse_text_lines(lines, idx, cur_indent)
                pn.children.append(child)
            else:
                idx += 1

        return pn, idx

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def normalize(self, node: PlanNode) -> str:
        """
        Normalize plan tree to a deterministic text representation
        that ignores costs, timing, and buffer counts — preserving
        only the structural shape (node types, relations, index names).
        """
        lines: list[str] = []
        self._build_normalized(node, 0, lines)
        return "\n".join(lines)

    def _build_normalized(
        self, node: PlanNode, level: int, lines: list[str]
    ) -> None:
        indent = "  " * level
        label = node.node_type
        if node.relation:
            label += f" on {node.relation}"
        if node.index_name:
            label += f" using {node.index_name}"
        if node.join_type:
            label += f" ({node.join_type})"
        lines.append(f"{indent}-> {label}")

        for child in sorted(node.children, key=lambda c: c.node_type):
            self._build_normalized(child, level + 1, lines)

    def fingerprint(self, node: PlanNode) -> str:
        """SHA-256 fingerprint of the normalized plan structure."""
        norm = self.normalize(node)
        return hashlib.sha256(norm.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff(
        self,
        plan_a: str | dict | list | PlanNode,
        plan_b: str | dict | list | PlanNode,
    ) -> PlanDiffResult:
        """
        Compare two plans and return a PlanDiffResult.

        Accepts JSON dicts, JSON strings, text EXPLAIN, or pre-parsed PlanNodes.
        """
        node_a = plan_a if isinstance(plan_a, PlanNode) else self.parse(plan_a)
        node_b = plan_b if isinstance(plan_b, PlanNode) else self.parse(plan_b)

        norm_a = self.normalize(node_a)
        norm_b = self.normalize(node_b)

        structural = self._structural_diff(norm_a, norm_b)
        metrics = self._compare_metrics(node_a, node_b)
        matches = self._match_nodes(node_a, node_b)

        count_a = self._count_nodes(node_a)
        count_b = self._count_nodes(node_b)
        similarity = self._calc_similarity(count_a, count_b, matches, structural)

        return PlanDiffResult(
            structural_changes=structural,
            metric_diffs=metrics,
            node_matches=matches,
            similarity_score=similarity,
            nodes_a=count_a,
            nodes_b=count_b,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _structural_diff(norm_a: str, norm_b: str) -> list[StructuralChange]:
        a_lines = norm_a.split("\n")
        b_lines = norm_b.split("\n")
        sm = difflib.SequenceMatcher(None, a_lines, b_lines)
        changes: list[StructuralChange] = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "replace":
                changes.append(StructuralChange("replace", a_lines[i1:i2], b_lines[j1:j2]))
            elif tag == "delete":
                changes.append(StructuralChange("delete", from_lines=a_lines[i1:i2]))
            elif tag == "insert":
                changes.append(StructuralChange("insert", to_lines=b_lines[j1:j2]))
        return changes

    @staticmethod
    def _sum_metric(node: PlanNode, attr: str) -> float:
        val = getattr(node, attr, None) or 0
        total = float(val)
        for child in node.children:
            total += EnhancedPlanDiff._sum_metric(child, attr)
        return total

    def _compare_metrics(
        self, node_a: PlanNode, node_b: PlanNode
    ) -> dict[str, float]:
        diffs: dict[str, float] = {}

        for attr, key in [
            ("actual_time", "execution_time_pct"),
            ("actual_rows", "rows_pct"),
        ]:
            a_val = self._sum_metric(node_a, attr)
            b_val = self._sum_metric(node_b, attr)
            if a_val > 0:
                diffs[key] = round((b_val - a_val) / a_val * 100, 2)

        buf_a = self._sum_metric(node_a, "buffers_hit") + self._sum_metric(node_a, "buffers_read")
        buf_b = self._sum_metric(node_b, "buffers_hit") + self._sum_metric(node_b, "buffers_read")
        if buf_a > 0:
            diffs["buffers_pct"] = round((buf_b - buf_a) / buf_a * 100, 2)

        cost_a = node_a.cost_total
        cost_b = node_b.cost_total
        if cost_a > 0:
            diffs["cost_pct"] = round((cost_b - cost_a) / cost_a * 100, 2)

        return diffs

    def _match_nodes(
        self, node_a: PlanNode, node_b: PlanNode
    ) -> dict[str, str]:
        matches: dict[str, str] = {}
        self._match_recursive(node_a, node_b, "", matches)
        return matches

    def _match_recursive(
        self,
        a: PlanNode,
        b: PlanNode,
        path: str,
        matches: dict[str, str],
    ) -> None:
        a_id = f"{path}{a.node_type}"
        if a.relation:
            a_id += f"_{a.relation}"
        b_id = f"{path}{b.node_type}"
        if b.relation:
            b_id += f"_{b.relation}"

        if a.node_type == b.node_type and a.relation == b.relation:
            matches[a_id] = b_id

        for i, (ca, cb) in enumerate(zip(a.children, b.children)):
            self._match_recursive(ca, cb, f"{path}{i}/", matches)

    @staticmethod
    def _count_nodes(node: PlanNode) -> int:
        return 1 + sum(EnhancedPlanDiff._count_nodes(c) for c in node.children)

    @staticmethod
    def _calc_similarity(
        count_a: int,
        count_b: int,
        matches: dict[str, str],
        changes: list[StructuralChange],
    ) -> float:
        if count_a == 0 and count_b == 0:
            return 100.0
        if count_a == 0 or count_b == 0:
            return 0.0

        match_score = len(matches) / max(count_a, count_b)
        change_penalty = min(len(changes) / max(count_a, count_b), 1.0)
        score = (match_score * 0.7 + (1 - change_penalty) * 0.3) * 100
        return round(max(0.0, min(100.0, score)), 1)
