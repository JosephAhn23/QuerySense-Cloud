"""
BUFFERS I/O Heatmap — Deep per-node buffer analysis.

Transforms EXPLAIN (ANALYZE, BUFFERS) output into an actionable I/O heatmap
showing exactly where disk reads dominate, where cache is cold, and how many
megabytes each node is pulling from disk.

This closes the gap with pganalyze's BUFFERS visualization (p.18 of their
Efficient Search guide) and goes further with:
- Per-node hit/read/dirtied breakdown
- I/O savings calculator (what caching would save)
- Aggregated plan-level I/O summary
- Root cause classification (cold cache, oversized table, bloat)
- Actionable fix suggestions per node

Usage:
    from querysense.analysis.buffers import BufferHeatmap
    heatmap = BufferHeatmap()
    report = heatmap.analyze(plan_json)
    for node in report.nodes:
        print(f"{node.label}: {node.cache_miss_pct:.0f}% miss, {node.disk_read_mb:.1f}MB from disk")

References:
    pganalyze "Efficient Search" p.18:
        "6 buffer pages = 48kB... 100 buffer pages read = 800kB"
        "100x performance difference between cached and uncached"
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Constants ────────────────────────────────────────────────────────────

BLOCK_SIZE_KB = 8  # PostgreSQL default block size
CACHE_HIT_NS = 100  # ~100ns for shared buffer hit
DISK_READ_US = 200  # ~200μs for SSD read (2000x slower)


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class BufferNode:
    """Buffer analysis for a single plan node."""

    node_id: int = 0
    node_type: str = ""
    table: str = ""
    depth: int = 0

    # Raw buffer counts
    shared_hit: int = 0
    shared_read: int = 0
    shared_dirtied: int = 0
    shared_written: int = 0
    temp_read: int = 0
    temp_written: int = 0

    # I/O timing (if available)
    io_read_time_ms: float = 0.0
    io_write_time_ms: float = 0.0

    # Row context
    actual_rows: int = 0
    estimated_rows: int = 0
    loops: int = 1

    # Computed fields
    @property
    def total_shared(self) -> int:
        return self.shared_hit + self.shared_read

    @property
    def cache_hit_pct(self) -> float:
        if self.total_shared == 0:
            return 100.0
        return (self.shared_hit / self.total_shared) * 100

    @property
    def cache_miss_pct(self) -> float:
        return 100.0 - self.cache_hit_pct

    @property
    def disk_read_kb(self) -> float:
        return self.shared_read * BLOCK_SIZE_KB

    @property
    def disk_read_mb(self) -> float:
        return self.disk_read_kb / 1024

    @property
    def cache_hit_kb(self) -> float:
        return self.shared_hit * BLOCK_SIZE_KB

    @property
    def total_io_kb(self) -> float:
        return self.total_shared * BLOCK_SIZE_KB

    @property
    def total_io_mb(self) -> float:
        return self.total_io_kb / 1024

    @property
    def temp_spill_kb(self) -> float:
        return (self.temp_read + self.temp_written) * BLOCK_SIZE_KB

    @property
    def temp_spill_mb(self) -> float:
        return self.temp_spill_kb / 1024

    @property
    def io_amplification(self) -> float:
        """Blocks read per row returned."""
        effective_rows = max(self.actual_rows * self.loops, 1)
        return self.shared_read / effective_rows if self.shared_read > 0 else 0.0

    @property
    def severity(self) -> str:
        if self.cache_miss_pct >= 80:
            return "CRITICAL"
        if self.cache_miss_pct >= 50:
            return "HIGH"
        if self.cache_miss_pct >= 20:
            return "MEDIUM"
        return "LOW"

    @property
    def estimated_io_savings_ms(self) -> float:
        """Estimated time savings if all reads were cache hits instead."""
        # Each disk read costs ~200μs; cache hit costs ~0.1μs
        return self.shared_read * (DISK_READ_US - CACHE_HIT_NS / 1000) / 1000

    @property
    def has_buffer_data(self) -> bool:
        return self.total_shared > 0 or self.temp_read > 0 or self.temp_written > 0

    @property
    def label(self) -> str:
        if self.table:
            return f"{self.node_type} on {self.table}"
        return self.node_type

    @property
    def root_cause(self) -> str:
        """Classify the root cause of high cache misses."""
        if self.cache_miss_pct < 20:
            return "well_cached"
        if self.disk_read_mb > 100:
            return "table_too_large"
        if self.io_amplification > 50:
            return "bloated_or_wide_rows"
        if self.shared_read > 0 and self.shared_hit < 10:
            return "cold_cache"
        return "insufficient_shared_buffers"

    def recommendations(self) -> list[str]:
        """Generate per-node fix recommendations."""
        recs: list[str] = []

        if self.cache_miss_pct < 20:
            return recs

        cause = self.root_cause

        if cause == "cold_cache":
            recs.append(
                f"Pre-warm the cache: SELECT pg_prewarm('{self.table or '<table>'}');"
            )
            recs.append("Re-run the query — second execution will use cached pages")

        elif cause == "table_too_large":
            recs.append(
                f"Table data is ~{self.disk_read_mb:.0f}MB — consider partitioning"
            )
            recs.append(
                "Add a covering index to avoid full table scans: "
                "CREATE INDEX ... INCLUDE (<selected_columns>);"
            )
            recs.append(
                f"Increase shared_buffers (needs {self.total_io_mb:.0f}MB+ to fully cache)"
            )

        elif cause == "bloated_or_wide_rows":
            recs.append(
                f"I/O amplification: {self.io_amplification:.0f} blocks per row — check for bloat"
            )
            recs.append(f"Run: VACUUM FULL {self.table or '<table>'}; (locks table)")
            recs.append("Or use pg_repack for online de-bloating")

        elif cause == "insufficient_shared_buffers":
            needed_mb = max(256, int(self.total_io_mb * 1.5))
            recs.append(
                f"Increase shared_buffers to at least {needed_mb}MB: "
                f"ALTER SYSTEM SET shared_buffers = '{needed_mb}MB';"
            )

        if self.temp_spill_mb > 0:
            work_mem_mb = max(64, int(self.temp_spill_mb * 2))
            recs.append(
                f"Temp spill detected ({self.temp_spill_mb:.1f}MB) — "
                f"SET work_mem = '{work_mem_mb}MB';"
            )

        return recs

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "table": self.table,
            "depth": self.depth,
            "shared_hit": self.shared_hit,
            "shared_read": self.shared_read,
            "shared_dirtied": self.shared_dirtied,
            "shared_written": self.shared_written,
            "temp_read": self.temp_read,
            "temp_written": self.temp_written,
            "io_read_time_ms": self.io_read_time_ms,
            "io_write_time_ms": self.io_write_time_ms,
            "actual_rows": self.actual_rows,
            "estimated_rows": self.estimated_rows,
            "loops": self.loops,
            "cache_hit_pct": round(self.cache_hit_pct, 1),
            "cache_miss_pct": round(self.cache_miss_pct, 1),
            "disk_read_mb": round(self.disk_read_mb, 2),
            "total_io_mb": round(self.total_io_mb, 2),
            "temp_spill_mb": round(self.temp_spill_mb, 2),
            "io_amplification": round(self.io_amplification, 1),
            "severity": self.severity,
            "root_cause": self.root_cause,
            "estimated_io_savings_ms": round(self.estimated_io_savings_ms, 2),
            "recommendations": self.recommendations(),
        }


@dataclass
class BufferReport:
    """Complete buffer analysis report for a plan."""

    nodes: list[BufferNode] = field(default_factory=list)
    has_buffer_data: bool = False

    # Plan-level aggregates
    @property
    def total_shared_hit(self) -> int:
        return sum(n.shared_hit for n in self.nodes)

    @property
    def total_shared_read(self) -> int:
        return sum(n.shared_read for n in self.nodes)

    @property
    def total_shared_dirtied(self) -> int:
        return sum(n.shared_dirtied for n in self.nodes)

    @property
    def total_shared_written(self) -> int:
        return sum(n.shared_written for n in self.nodes)

    @property
    def total_temp_spill(self) -> int:
        return sum(n.temp_read + n.temp_written for n in self.nodes)

    @property
    def total_blocks(self) -> int:
        return self.total_shared_hit + self.total_shared_read

    @property
    def overall_hit_pct(self) -> float:
        if self.total_blocks == 0:
            return 100.0
        return (self.total_shared_hit / self.total_blocks) * 100

    @property
    def overall_miss_pct(self) -> float:
        return 100.0 - self.overall_hit_pct

    @property
    def total_disk_read_mb(self) -> float:
        return (self.total_shared_read * BLOCK_SIZE_KB) / 1024

    @property
    def total_io_mb(self) -> float:
        return (self.total_blocks * BLOCK_SIZE_KB) / 1024

    @property
    def io_time_ms(self) -> float:
        return sum(n.io_read_time_ms + n.io_write_time_ms for n in self.nodes)

    @property
    def hotspots(self) -> list[BufferNode]:
        """Nodes sorted by disk reads (most I/O first)."""
        return sorted(
            [n for n in self.nodes if n.has_buffer_data],
            key=lambda n: n.shared_read,
            reverse=True,
        )

    @property
    def critical_nodes(self) -> list[BufferNode]:
        """Nodes with >= 50% cache miss rate."""
        return [n for n in self.nodes if n.cache_miss_pct >= 50 and n.total_shared > 10]

    @property
    def estimated_savings_ms(self) -> float:
        """Total estimated I/O savings if everything was cached."""
        return sum(n.estimated_io_savings_ms for n in self.nodes)

    def summary(self) -> dict[str, Any]:
        return {
            "has_buffer_data": self.has_buffer_data,
            "total_nodes_with_io": len([n for n in self.nodes if n.has_buffer_data]),
            "total_blocks": self.total_blocks,
            "total_shared_hit": self.total_shared_hit,
            "total_shared_read": self.total_shared_read,
            "total_shared_dirtied": self.total_shared_dirtied,
            "total_shared_written": self.total_shared_written,
            "total_temp_spill_blocks": self.total_temp_spill,
            "overall_hit_pct": round(self.overall_hit_pct, 1),
            "total_disk_read_mb": round(self.total_disk_read_mb, 2),
            "total_io_mb": round(self.total_io_mb, 2),
            "io_time_ms": round(self.io_time_ms, 2),
            "estimated_savings_ms": round(self.estimated_savings_ms, 2),
            "critical_nodes": len(self.critical_nodes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "nodes": [n.to_dict() for n in self.hotspots],
        }


# ── Analyzer ─────────────────────────────────────────────────────────────


class BufferHeatmap:
    """
    Analyzes EXPLAIN (ANALYZE, BUFFERS) output to produce a per-node
    I/O heatmap showing cache hit ratios, disk reads, and savings estimates.

    Works with both raw plan JSON dicts and QuerySense's parsed ExplainOutput.
    """

    def analyze(self, plan: dict[str, Any] | list | str | Path) -> BufferReport:
        """
        Analyze a plan for buffer usage.

        Args:
            plan: EXPLAIN JSON output — dict, list, JSON string, or file path.

        Returns:
            BufferReport with per-node buffer analysis.
        """
        data = self._normalize_input(plan)
        nodes: list[BufferNode] = []
        self._walk(data, nodes, depth=0, counter=[0])

        has_data = any(n.has_buffer_data for n in nodes)

        return BufferReport(nodes=nodes, has_buffer_data=has_data)

    def analyze_from_explain(self, explain: Any) -> BufferReport:
        """
        Analyze from a QuerySense ExplainOutput/PlanNode object.

        Falls back to raw plan data if the object has a .raw or .plan attribute.
        """
        # Try raw dict first
        if hasattr(explain, "raw"):
            return self.analyze(explain.raw)
        if hasattr(explain, "plan") and isinstance(explain.plan, dict):
            return self.analyze(explain.plan)
        # If it's a PlanNode tree from the parser
        if hasattr(explain, "plan"):
            plan_node = explain.plan
            return self._analyze_plan_node(plan_node)
        raise TypeError(f"Unsupported input type: {type(explain)}")

    def _analyze_plan_node(self, node: Any, depth: int = 0, counter: list[int] | None = None) -> BufferReport:
        """Walk a PlanNode tree (querysense.parser.models.PlanNode)."""
        if counter is None:
            counter = [0]

        nodes: list[BufferNode] = []
        self._walk_plan_node(node, nodes, depth, counter)
        has_data = any(n.has_buffer_data for n in nodes)
        return BufferReport(nodes=nodes, has_buffer_data=has_data)

    def _walk_plan_node(
        self,
        node: Any,
        result: list[BufferNode],
        depth: int,
        counter: list[int],
    ) -> None:
        """Recursively walk PlanNode objects."""
        counter[0] += 1
        buf = BufferNode(
            node_id=counter[0],
            node_type=getattr(node, "node_type", "") or "",
            table=getattr(node, "relation_name", "") or "",
            depth=depth,
            shared_hit=getattr(node, "shared_hit_blocks", 0) or 0,
            shared_read=getattr(node, "shared_read_blocks", 0) or 0,
            shared_dirtied=getattr(node, "shared_dirtied_blocks", 0) or 0,
            shared_written=getattr(node, "shared_written_blocks", 0) or 0,
            temp_read=getattr(node, "temp_read_blocks", 0) or 0,
            temp_written=getattr(node, "temp_written_blocks", 0) or 0,
            io_read_time_ms=getattr(node, "io_read_time", 0.0) or 0.0,
            io_write_time_ms=getattr(node, "io_write_time", 0.0) or 0.0,
            actual_rows=getattr(node, "actual_rows", 0) or 0,
            estimated_rows=getattr(node, "plan_rows", 0) or 0,
            loops=getattr(node, "actual_loops", 1) or 1,
        )
        result.append(buf)

        for child in getattr(node, "plans", []) or []:
            self._walk_plan_node(child, result, depth + 1, counter)

    # ── Raw dict walking ─────────────────────────────────────────────

    def _normalize_input(self, plan: Any) -> dict[str, Any]:
        """Normalize various input formats to a plan dict."""
        if isinstance(plan, (str, Path)):
            path = Path(plan)
            if path.exists():
                text = path.read_text(encoding="utf-8")
            else:
                text = str(plan)
            data = json.loads(text)
        elif isinstance(plan, (dict, list)):
            data = plan
        else:
            raise TypeError(f"Unsupported plan type: {type(plan)}")

        # Handle various wrapper formats
        if isinstance(data, list):
            if data and isinstance(data[0], dict):
                data = data[0]
            else:
                raise ValueError("Empty or invalid plan array")

        # Unwrap the top-level Plan key if present
        if "Plan" in data:
            return data["Plan"]
        return data

    def _walk(
        self,
        node: dict[str, Any],
        result: list[BufferNode],
        depth: int,
        counter: list[int],
    ) -> None:
        """Recursively walk raw plan JSON nodes."""
        counter[0] += 1

        buf = BufferNode(
            node_id=counter[0],
            node_type=node.get("Node Type", ""),
            table=node.get("Relation Name", "") or node.get("Alias", ""),
            depth=depth,
            shared_hit=node.get("Shared Hit Blocks", 0) or 0,
            shared_read=node.get("Shared Read Blocks", 0) or 0,
            shared_dirtied=node.get("Shared Dirtied Blocks", 0) or 0,
            shared_written=node.get("Shared Written Blocks", 0) or 0,
            temp_read=node.get("Temp Read Blocks", 0) or 0,
            temp_written=node.get("Temp Written Blocks", 0) or 0,
            io_read_time_ms=node.get("I/O Read Time", 0.0) or 0.0,
            io_write_time_ms=node.get("I/O Write Time", 0.0) or 0.0,
            actual_rows=node.get("Actual Rows", 0) or 0,
            estimated_rows=node.get("Plan Rows", 0) or 0,
            loops=node.get("Actual Loops", 1) or 1,
        )
        result.append(buf)

        for child in node.get("Plans", []):
            self._walk(child, result, depth + 1, counter)


# ── Plan diff (before/after BUFFERS comparison) ─────────────────────────


@dataclass
class BufferDiffNode:
    """I/O delta for a single node between two plans."""

    node_type: str = ""
    table: str = ""
    before_hit: int = 0
    before_read: int = 0
    after_hit: int = 0
    after_read: int = 0

    @property
    def read_delta(self) -> int:
        return self.after_read - self.before_read

    @property
    def hit_delta(self) -> int:
        return self.after_hit - self.before_hit

    @property
    def read_delta_mb(self) -> float:
        return (self.read_delta * BLOCK_SIZE_KB) / 1024

    @property
    def before_miss_pct(self) -> float:
        total = self.before_hit + self.before_read
        return (self.before_read / total * 100) if total > 0 else 0.0

    @property
    def after_miss_pct(self) -> float:
        total = self.after_hit + self.after_read
        return (self.after_read / total * 100) if total > 0 else 0.0

    @property
    def improvement(self) -> str:
        if self.read_delta < 0:
            return f"{abs(self.read_delta_mb):.1f}MB fewer disk reads"
        if self.read_delta > 0:
            return f"{self.read_delta_mb:.1f}MB more disk reads"
        return "no change"

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_type": self.node_type,
            "table": self.table,
            "before": {"hit": self.before_hit, "read": self.before_read, "miss_pct": round(self.before_miss_pct, 1)},
            "after": {"hit": self.after_hit, "read": self.after_read, "miss_pct": round(self.after_miss_pct, 1)},
            "delta": {"read": self.read_delta, "read_mb": round(self.read_delta_mb, 2), "hit": self.hit_delta},
            "improvement": self.improvement,
        }


@dataclass
class BufferDiffReport:
    """Before/after comparison of two plans' buffer usage."""

    before: BufferReport | None = None
    after: BufferReport | None = None
    node_diffs: list[BufferDiffNode] = field(default_factory=list)

    @property
    def total_read_delta(self) -> int:
        return sum(n.read_delta for n in self.node_diffs)

    @property
    def total_read_delta_mb(self) -> float:
        return (self.total_read_delta * BLOCK_SIZE_KB) / 1024

    @property
    def overall_improvement(self) -> str:
        if not self.before or not self.after:
            return "incomplete data"
        delta = self.after.total_shared_read - self.before.total_shared_read
        if delta < 0:
            pct = abs(delta) / max(self.before.total_shared_read, 1) * 100
            return f"{pct:.0f}% fewer disk reads ({abs(delta * BLOCK_SIZE_KB / 1024):.1f}MB saved)"
        if delta > 0:
            pct = delta / max(self.before.total_shared_read, 1) * 100
            return f"{pct:.0f}% more disk reads ({delta * BLOCK_SIZE_KB / 1024:.1f}MB added)"
        return "no change in disk reads"

    def to_dict(self) -> dict[str, Any]:
        return {
            "before_summary": self.before.summary() if self.before else None,
            "after_summary": self.after.summary() if self.after else None,
            "node_diffs": [n.to_dict() for n in self.node_diffs],
            "total_read_delta_mb": round(self.total_read_delta_mb, 2),
            "overall_improvement": self.overall_improvement,
        }


class BufferDiff:
    """
    Compare buffer usage between two plan executions.

    Usage:
        diff = BufferDiff()
        report = diff.compare(before_plan, after_plan)
        print(report.overall_improvement)
    """

    def __init__(self) -> None:
        self._heatmap = BufferHeatmap()

    def compare(
        self,
        before: dict[str, Any] | str | Path,
        after: dict[str, Any] | str | Path,
    ) -> BufferDiffReport:
        """Compare two plans' buffer usage."""
        before_report = self._heatmap.analyze(before)
        after_report = self._heatmap.analyze(after)

        # Match nodes by (node_type, table) — best effort
        before_map: dict[tuple[str, str], BufferNode] = {}
        for n in before_report.nodes:
            key = (n.node_type, n.table)
            if key not in before_map:
                before_map[key] = n

        diffs: list[BufferDiffNode] = []
        seen: set[tuple[str, str]] = set()

        for n in after_report.nodes:
            key = (n.node_type, n.table)
            if key in seen:
                continue
            seen.add(key)

            before_node = before_map.get(key)
            if before_node:
                diffs.append(BufferDiffNode(
                    node_type=n.node_type,
                    table=n.table,
                    before_hit=before_node.shared_hit,
                    before_read=before_node.shared_read,
                    after_hit=n.shared_hit,
                    after_read=n.shared_read,
                ))
            else:
                diffs.append(BufferDiffNode(
                    node_type=n.node_type,
                    table=n.table,
                    before_hit=0,
                    before_read=0,
                    after_hit=n.shared_hit,
                    after_read=n.shared_read,
                ))

        # Also include nodes that disappeared
        for key, bn in before_map.items():
            if key not in seen:
                diffs.append(BufferDiffNode(
                    node_type=bn.node_type,
                    table=bn.table,
                    before_hit=bn.shared_hit,
                    before_read=bn.shared_read,
                    after_hit=0,
                    after_read=0,
                ))

        # Sort by absolute read delta (biggest changes first)
        diffs.sort(key=lambda d: abs(d.read_delta), reverse=True)

        return BufferDiffReport(
            before=before_report,
            after=after_report,
            node_diffs=diffs,
        )
