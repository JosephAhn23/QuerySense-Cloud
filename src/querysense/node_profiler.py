"""
Node-Level Profiler -- deep per-node execution analysis.

Goes beyond "this plan is slow" to pinpoint EXACTLY which node spent
the most time, why, and what to do about it. Answers:

1. Which node is the bottleneck? (inclusive vs exclusive time)
2. What fraction of total time does each node consume?
3. Where are the biggest estimation errors?
4. Which nodes have the worst I/O patterns?
5. Where is memory being wasted?

Usage:
    from querysense.node_profiler import NodeProfiler

    profiler = NodeProfiler()
    profile = profiler.profile(plan_json)
    for node in profile.hotspots[:5]:
        print(f"{node.node_type} on {node.table}: {node.exclusive_pct:.1f}% of total time")
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any


@dataclass
class NodeProfile:
    """Detailed profile of a single plan node."""
    node_id: int = 0
    node_type: str = ""
    table: str = ""
    depth: int = 0
    # Timing
    inclusive_time_ms: float = 0.0   # This node + all children
    exclusive_time_ms: float = 0.0   # This node only
    startup_time_ms: float = 0.0
    inclusive_pct: float = 0.0       # % of total plan time
    exclusive_pct: float = 0.0       # % of total plan time (exclusive)
    # Rows
    estimated_rows: int = 0
    actual_rows: int = 0
    loops: int = 1
    total_rows: int = 0              # actual_rows * loops
    estimation_error: float = 0.0    # |actual - estimated| / max(actual, 1)
    # Cost
    estimated_cost: float = 0.0
    cost_pct: float = 0.0           # % of total estimated cost
    # I/O
    shared_hit_blocks: int = 0
    shared_read_blocks: int = 0
    io_read_time_ms: float = 0.0
    cache_hit_ratio: float = 1.0
    # Memory
    peak_memory_kb: int = 0
    sort_space_used_kb: int = 0
    sort_space_type: str = ""        # Memory or Disk
    hash_batches: int = 0
    hash_buckets: int = 0
    # Context
    filter_condition: str = ""
    index_name: str = ""
    join_type: str = ""
    parent_type: str = ""
    # Diagnosis
    bottleneck_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "table": self.table,
            "depth": self.depth,
            "exclusive_time_ms": round(self.exclusive_time_ms, 3),
            "inclusive_time_ms": round(self.inclusive_time_ms, 3),
            "exclusive_pct": round(self.exclusive_pct, 2),
            "inclusive_pct": round(self.inclusive_pct, 2),
            "actual_rows": self.actual_rows,
            "estimated_rows": self.estimated_rows,
            "estimation_error": round(self.estimation_error, 2),
            "cache_hit_ratio": round(self.cache_hit_ratio, 4),
            "sort_space_type": self.sort_space_type,
            "hash_batches": self.hash_batches,
            "bottleneck_reason": self.bottleneck_reason,
        }


@dataclass
class PlanProfile:
    """Complete profiling result for a plan."""
    total_time_ms: float = 0.0
    total_cost: float = 0.0
    node_count: int = 0
    nodes: list[NodeProfile] = field(default_factory=list)
    hotspots: list[NodeProfile] = field(default_factory=list)  # Sorted by exclusive_pct
    bottleneck: NodeProfile | None = None
    io_bound_nodes: list[NodeProfile] = field(default_factory=list)
    memory_bound_nodes: list[NodeProfile] = field(default_factory=list)
    estimation_errors: list[NodeProfile] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_time_ms": round(self.total_time_ms, 3),
            "total_cost": round(self.total_cost, 2),
            "node_count": self.node_count,
            "bottleneck": self.bottleneck.to_dict() if self.bottleneck else None,
            "hotspots": [n.to_dict() for n in self.hotspots[:10]],
            "io_bound_count": len(self.io_bound_nodes),
            "memory_bound_count": len(self.memory_bound_nodes),
            "estimation_error_count": len(self.estimation_errors),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  NODE-LEVEL EXECUTION PROFILE")
        lines.append("  " + "=" * 60)
        lines.append(f"  Total time: {self.total_time_ms:.1f}ms | Nodes: {self.node_count}")
        lines.append("")

        if self.bottleneck:
            bn = self.bottleneck
            lines.append(f"  BOTTLENECK: {bn.node_type} on {bn.table}")
            lines.append(
                f"    Exclusive: {bn.exclusive_time_ms:.1f}ms ({bn.exclusive_pct:.1f}% of total)"
            )
            if bn.bottleneck_reason:
                lines.append(f"    Reason: {bn.bottleneck_reason}")
            lines.append("")

        lines.append(
            f"  {'Node Type':<25} {'Table':<15} {'Excl(ms)':>10} {'Excl%':>8} "
            f"{'Rows':>10} {'Est Err':>8} {'Cache%':>8}"
        )
        lines.append("  " + "-" * 95)

        for n in self.hotspots[:15]:
            err_str = f"{n.estimation_error:.0f}x" if n.estimation_error > 1 else "-"
            cache_str = f"{n.cache_hit_ratio:.0%}" if n.shared_hit_blocks + n.shared_read_blocks > 0 else "-"
            lines.append(
                f"  {n.node_type:<25} {n.table:<15} {n.exclusive_time_ms:>10.1f} "
                f"{n.exclusive_pct:>7.1f}% {n.actual_rows:>10,} {err_str:>8} {cache_str:>8}"
            )

        if self.io_bound_nodes:
            lines.append("")
            lines.append(f"  I/O Bound Nodes ({len(self.io_bound_nodes)}):")
            for n in self.io_bound_nodes[:5]:
                lines.append(
                    f"    {n.node_type} on {n.table}: "
                    f"cache {n.cache_hit_ratio:.0%}, read {n.io_read_time_ms:.1f}ms"
                )

        if self.memory_bound_nodes:
            lines.append("")
            lines.append(f"  Memory Bound Nodes ({len(self.memory_bound_nodes)}):")
            for n in self.memory_bound_nodes[:5]:
                info = f"disk spill" if n.sort_space_type == "Disk" else f"{n.hash_batches} hash batches"
                lines.append(f"    {n.node_type} on {n.table}: {info}")

        if self.estimation_errors:
            lines.append("")
            lines.append(f"  Estimation Errors ({len(self.estimation_errors)}):")
            for n in self.estimation_errors[:5]:
                lines.append(
                    f"    {n.node_type} on {n.table}: "
                    f"estimated {n.estimated_rows:,} vs actual {n.actual_rows:,} "
                    f"({n.estimation_error:.0f}x off)"
                )

        lines.append("")
        return "\n".join(lines)


class NodeProfiler:
    """Deep per-node execution profiler."""

    def profile(self, plan_data: dict[str, Any] | list) -> PlanProfile:
        """Profile all nodes in an EXPLAIN ANALYZE plan."""
        plan = self._extract_plan(plan_data)
        if not plan:
            return PlanProfile()

        total_time = plan.get("Actual Total Time") or 0.0
        total_cost = plan.get("Total Cost", 0.0)

        # Walk tree and build node profiles
        nodes: list[NodeProfile] = []
        self._walk_and_profile(plan, nodes, parent_type="", depth=0, node_counter=[0])

        # Calculate exclusive time (inclusive - sum of children's inclusive)
        self._calculate_exclusive_times(plan, nodes)

        # Calculate percentages
        for n in nodes:
            if total_time > 0:
                n.inclusive_pct = (n.inclusive_time_ms / total_time) * 100
                n.exclusive_pct = (n.exclusive_time_ms / total_time) * 100
            if total_cost > 0:
                n.cost_pct = (n.estimated_cost / total_cost) * 100

        # Classify and sort
        hotspots = sorted(nodes, key=lambda n: -n.exclusive_pct)

        io_bound = [n for n in nodes if n.cache_hit_ratio < 0.95 and (n.shared_hit_blocks + n.shared_read_blocks) > 0]
        memory_bound = [n for n in nodes if n.sort_space_type == "Disk" or n.hash_batches > 1]
        est_errors = sorted(
            [n for n in nodes if n.estimation_error > 5],
            key=lambda n: -n.estimation_error,
        )

        # Identify bottleneck
        bottleneck = hotspots[0] if hotspots else None
        if bottleneck:
            bottleneck.bottleneck_reason = self._diagnose_bottleneck(bottleneck)

        return PlanProfile(
            total_time_ms=total_time,
            total_cost=total_cost,
            node_count=len(nodes),
            nodes=nodes,
            hotspots=hotspots,
            bottleneck=bottleneck,
            io_bound_nodes=io_bound,
            memory_bound_nodes=memory_bound,
            estimation_errors=est_errors,
        )

    def _walk_and_profile(
        self,
        node: dict[str, Any],
        profiles: list[NodeProfile],
        parent_type: str,
        depth: int,
        node_counter: list[int],
    ) -> None:
        """Walk plan tree and create profiles."""
        node_counter[0] += 1

        actual_rows = node.get("Actual Rows") or 0
        est_rows = node.get("Plan Rows", 0)
        loops = node.get("Actual Loops") or 1
        shared_hit = node.get("Shared Hit Blocks") or 0
        shared_read = node.get("Shared Read Blocks") or 0
        total_blocks = shared_hit + shared_read

        est_error = 0.0
        if actual_rows > 0 and est_rows > 0:
            est_error = max(actual_rows, est_rows) / min(actual_rows, est_rows)

        cache_ratio = (shared_hit / total_blocks) if total_blocks > 0 else 1.0

        profile = NodeProfile(
            node_id=node_counter[0],
            node_type=node.get("Node Type", "Unknown"),
            table=node.get("Relation Name", ""),
            depth=depth,
            inclusive_time_ms=(node.get("Actual Total Time") or 0.0) * loops,
            startup_time_ms=(node.get("Actual Startup Time") or 0.0) * loops,
            estimated_rows=est_rows,
            actual_rows=actual_rows,
            loops=loops,
            total_rows=actual_rows * loops,
            estimation_error=est_error,
            estimated_cost=node.get("Total Cost", 0.0),
            shared_hit_blocks=shared_hit,
            shared_read_blocks=shared_read,
            io_read_time_ms=node.get("I/O Read Time") or 0.0,
            cache_hit_ratio=cache_ratio,
            peak_memory_kb=node.get("Peak Memory Usage") or 0,
            sort_space_used_kb=node.get("Sort Space Used") or 0,
            sort_space_type=node.get("Sort Space Type", ""),
            hash_batches=node.get("Hash Batches") or 0,
            hash_buckets=node.get("Hash Buckets") or 0,
            filter_condition=node.get("Filter", ""),
            index_name=node.get("Index Name", ""),
            join_type=node.get("Join Type", ""),
            parent_type=parent_type,
        )
        profiles.append(profile)

        for child in node.get("Plans", []):
            self._walk_and_profile(child, profiles, parent_type=profile.node_type, depth=depth + 1, node_counter=node_counter)

    def _calculate_exclusive_times(
        self, node: dict[str, Any], profiles: list[NodeProfile],
    ) -> None:
        """Calculate exclusive time = inclusive - children's inclusive."""
        # Build a map of node_id -> profile
        profile_map: dict[int, NodeProfile] = {p.node_id: p for p in profiles}

        # For each node, subtract children's inclusive time
        self._calc_exclusive(node, profiles, idx=[0])

    def _calc_exclusive(
        self, node: dict[str, Any], profiles: list[NodeProfile], idx: list[int],
    ) -> float:
        """Recursive exclusive time calculation."""
        current_idx = idx[0]
        idx[0] += 1

        if current_idx >= len(profiles):
            return 0.0

        profile = profiles[current_idx]
        children_time = 0.0

        for child in node.get("Plans", []):
            children_time += self._calc_exclusive(child, profiles, idx)

        profile.exclusive_time_ms = max(0.0, profile.inclusive_time_ms - children_time)
        return profile.inclusive_time_ms

    def _diagnose_bottleneck(self, node: NodeProfile) -> str:
        """Diagnose why a node is the bottleneck."""
        reasons: list[str] = []

        if node.node_type == "Seq Scan" and node.total_rows > 10000:
            reasons.append(f"Sequential scan reading {node.total_rows:,} rows -- add an index")

        if node.estimation_error > 10:
            reasons.append(f"Row estimation {node.estimation_error:.0f}x off -- run ANALYZE")

        if node.sort_space_type == "Disk":
            reasons.append(f"Sorting to disk ({node.sort_space_used_kb}KB) -- increase work_mem")

        if node.hash_batches > 1:
            reasons.append(f"Hash spilling to {node.hash_batches} batches -- increase work_mem")

        if node.cache_hit_ratio < 0.90:
            reasons.append(f"Low cache hit ratio ({node.cache_hit_ratio:.0%}) -- increase shared_buffers")

        if "Nested Loop" in node.node_type and node.total_rows > 50000:
            reasons.append("Nested loop on large dataset -- consider hash join")

        if node.io_read_time_ms > node.exclusive_time_ms * 0.5:
            reasons.append(f"I/O bound -- {node.io_read_time_ms:.0f}ms reading from disk")

        return "; ".join(reasons) if reasons else "High cost operation"

    def _extract_plan(self, data: Any) -> dict[str, Any] | None:
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            return data.get("Plan", data if "Node Type" in data else None)
        return None
