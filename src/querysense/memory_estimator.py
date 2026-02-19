"""
Memory Estimator — predict peak RAM usage of a query before execution.

Addresses: "Memory runs out on large queries — can't increase VM"
(Gartner Peer Insights, tool-agnostic pain point)

Estimates memory consumption from EXPLAIN output by analyzing:
- Sort operations (rows × width × multiplier)
- Hash joins (inner table hash table size)
- Materialization nodes (buffered row count × width)
- CTE materialization (all rows stored)
- Bitmap Heap Scans (bitmap size)
- Gather/Parallel workers (per-worker overhead)

Returns warnings when estimated peak memory exceeds work_mem or
available system memory.

Usage:
    from querysense.memory_estimator import MemoryEstimator

    estimator = MemoryEstimator()
    report = estimator.estimate(plan_json)
    print(report.peak_memory_mb)
    print(report.warnings)
    print(report.recommendation)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MemoryOperation:
    """A single memory-consuming operation in the plan."""

    node_type: str
    relation: str
    estimated_bytes: int
    estimated_rows: int
    width_bytes: int
    description: str

    @property
    def estimated_mb(self) -> float:
        return self.estimated_bytes / (1024 * 1024)


@dataclass
class MemoryReport:
    """Complete memory estimate for a query plan."""

    operations: list[MemoryOperation] = field(default_factory=list)
    peak_memory_bytes: int = 0
    concurrent_memory_bytes: int = 0  # Memory if all ops run simultaneously
    work_mem_setting: str = "4MB"  # Default PostgreSQL work_mem
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def peak_memory_mb(self) -> float:
        return self.peak_memory_bytes / (1024 * 1024)

    @property
    def concurrent_memory_mb(self) -> float:
        return self.concurrent_memory_bytes / (1024 * 1024)

    def summary(self) -> str:
        return (
            f"Estimated peak memory: {self.peak_memory_mb:.1f}MB "
            f"({len(self.operations)} memory-intensive operations). "
            f"Current work_mem: {self.work_mem_setting}."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "concurrent_memory_mb": round(self.concurrent_memory_mb, 2),
            "work_mem": self.work_mem_setting,
            "operations": [
                {
                    "node_type": op.node_type,
                    "relation": op.relation,
                    "estimated_mb": round(op.estimated_mb, 2),
                    "estimated_rows": op.estimated_rows,
                    "description": op.description,
                }
                for op in self.operations
            ],
            "warnings": self.warnings,
            "recommendations": self.recommendations,
        }


class MemoryEstimator:
    """Estimate peak memory consumption from EXPLAIN output."""

    # PostgreSQL tuple overhead (heap tuple header)
    TUPLE_OVERHEAD_BYTES = 23
    # Hash table overhead per entry
    HASH_ENTRY_OVERHEAD = 32
    # Bitmap scan: bytes per page tracked
    BITMAP_PAGE_BYTES = 8
    # Default row width if not specified
    DEFAULT_ROW_WIDTH = 100

    def estimate(
        self,
        plan_json: dict[str, Any] | list[dict[str, Any]],
        work_mem: str = "4MB",
    ) -> MemoryReport:
        """Estimate memory usage from an EXPLAIN JSON output.

        Args:
            plan_json: EXPLAIN (FORMAT JSON) output
            work_mem: Current work_mem setting (e.g., "4MB", "256MB")

        Returns:
            MemoryReport with per-operation estimates and warnings
        """
        root = plan_json[0] if isinstance(plan_json, list) else plan_json
        plan = root.get("Plan", root)

        operations: list[MemoryOperation] = []
        self._walk_plan(plan, operations)

        # Calculate peak memory (max of any single operation)
        peak = max((op.estimated_bytes for op in operations), default=0)

        # Calculate concurrent memory (sum of all operations that could run simultaneously)
        # In practice, PostgreSQL runs operations sequentially within a node,
        # but parallel workers can run simultaneously
        concurrent = sum(op.estimated_bytes for op in operations)

        # Parse work_mem to bytes
        work_mem_bytes = self._parse_memory(work_mem)

        report = MemoryReport(
            operations=sorted(operations, key=lambda x: x.estimated_bytes, reverse=True),
            peak_memory_bytes=peak,
            concurrent_memory_bytes=concurrent,
            work_mem_setting=work_mem,
        )

        # Generate warnings
        if peak > work_mem_bytes:
            report.warnings.append(
                f"Peak memory ({peak / 1024 / 1024:.1f}MB) exceeds work_mem "
                f"({work_mem}). Query will spill to disk, causing 10-100x slowdown."
            )

        if peak > 1024 * 1024 * 1024:  # >1GB
            report.warnings.append(
                f"Query needs {peak / 1024 / 1024 / 1024:.1f}GB RAM. "
                f"Ensure your server has sufficient memory before running."
            )

        # Check concurrent impact at different concurrency levels
        for users in [5, 10, 20]:
            total_mem = concurrent * users
            if total_mem > 4 * 1024 * 1024 * 1024:  # >4GB
                report.warnings.append(
                    f"At {users} concurrent users: {total_mem / 1024 / 1024 / 1024:.1f}GB total. "
                    f"Risk of OOM killer on servers with <{total_mem / 1024 / 1024 / 1024 * 1.5:.0f}GB RAM."
                )
                break

        # Sort operations that would spill
        spilling_ops = [op for op in operations if op.estimated_bytes > work_mem_bytes]
        if spilling_ops:
            for op in spilling_ops[:3]:
                report.warnings.append(
                    f"{op.node_type} on {op.relation or 'subquery'}: "
                    f"needs {op.estimated_mb:.1f}MB but work_mem is only {work_mem}. "
                    f"Will spill to disk."
                )

        # Generate recommendations
        if peak > work_mem_bytes and peak < 256 * 1024 * 1024:
            report.recommendations.append(
                f"SET work_mem = '{max(int(peak / 1024 / 1024 * 1.5), 16)}MB'; "
                f"-- Sufficient for this query without spilling"
            )
        elif peak > work_mem_bytes:
            report.recommendations.append(
                f"SET LOCAL work_mem = '{max(int(peak / 1024 / 1024 * 1.2), 64)}MB'; "
                f"-- Use SET LOCAL to limit to current transaction only"
            )

        if any("Seq Scan" in op.node_type for op in operations if op.estimated_rows > 100000):
            report.recommendations.append(
                "Large sequential scans detected. Add indexes to reduce "
                "memory consumption and avoid full-table reads."
            )

        return report

    def _walk_plan(self, node: dict[str, Any], operations: list[MemoryOperation]) -> None:
        """Walk the plan tree and collect memory-consuming operations."""
        node_type = node.get("Node Type", "")
        relation = node.get("Relation Name", "")
        rows = node.get("Actual Rows", node.get("Plan Rows", 0)) or 0
        width = node.get("Plan Width", self.DEFAULT_ROW_WIDTH) or self.DEFAULT_ROW_WIDTH
        loops = node.get("Actual Loops", 1) or 1

        # Sort nodes: need to hold all rows in memory
        if "Sort" in node_type:
            estimated = rows * (width + self.TUPLE_OVERHEAD_BYTES)
            sort_method = node.get("Sort Method", "")
            if "disk" in sort_method.lower() or "external" in sort_method.lower():
                estimated *= 2  # Already spilling, actual need is higher

            operations.append(MemoryOperation(
                node_type=node_type,
                relation=relation,
                estimated_bytes=estimated,
                estimated_rows=rows,
                width_bytes=width,
                description=f"Sort needs to buffer {rows:,} rows × {width}B width = {estimated / 1024 / 1024:.1f}MB",
            ))

        # Hash Join: inner side builds hash table
        elif "Hash" in node_type and "Join" in node_type:
            children = node.get("Plans", [])
            if len(children) >= 2:
                inner = children[1]
                inner_rows = inner.get("Actual Rows", inner.get("Plan Rows", 0)) or 0
                inner_width = inner.get("Plan Width", width)
                estimated = inner_rows * (inner_width + self.HASH_ENTRY_OVERHEAD)

                operations.append(MemoryOperation(
                    node_type=node_type,
                    relation=inner.get("Relation Name", relation),
                    estimated_bytes=estimated,
                    estimated_rows=inner_rows,
                    width_bytes=inner_width,
                    description=f"Hash table: {inner_rows:,} rows × ({inner_width}B + {self.HASH_ENTRY_OVERHEAD}B overhead) = {estimated / 1024 / 1024:.1f}MB",
                ))

        # Hash Aggregate: groups held in hash table
        elif node_type == "HashAggregate":
            # Estimated groups
            groups = node.get("Actual Rows", node.get("Plan Rows", 0)) or 0
            estimated = groups * (width + self.HASH_ENTRY_OVERHEAD)
            operations.append(MemoryOperation(
                node_type=node_type,
                relation=relation,
                estimated_bytes=estimated,
                estimated_rows=groups,
                width_bytes=width,
                description=f"Hash aggregate: {groups:,} groups × {width + self.HASH_ENTRY_OVERHEAD}B = {estimated / 1024 / 1024:.1f}MB",
            ))

        # Materialize / CTE Scan: all rows buffered
        elif node_type in ("Materialize", "CTE Scan"):
            estimated = rows * (width + self.TUPLE_OVERHEAD_BYTES)
            operations.append(MemoryOperation(
                node_type=node_type,
                relation=relation or node.get("CTE Name", ""),
                estimated_bytes=estimated,
                estimated_rows=rows,
                width_bytes=width,
                description=f"Materialization: {rows:,} rows × {width + self.TUPLE_OVERHEAD_BYTES}B = {estimated / 1024 / 1024:.1f}MB",
            ))

        # Bitmap Heap Scan: bitmap in memory
        elif node_type == "Bitmap Heap Scan":
            # Bitmap size roughly proportional to pages
            pages = max(rows // 100, 1)  # Rough: 100 rows per page
            estimated = pages * self.BITMAP_PAGE_BYTES
            if estimated > 1024:  # Only report if significant
                operations.append(MemoryOperation(
                    node_type=node_type,
                    relation=relation,
                    estimated_bytes=estimated,
                    estimated_rows=rows,
                    width_bytes=width,
                    description=f"Bitmap: ~{pages:,} pages × {self.BITMAP_PAGE_BYTES}B = {estimated / 1024:.1f}KB",
                ))

        # Gather / Parallel: multiply by workers
        elif "Gather" in node_type:
            workers = node.get("Workers Planned", 0) or node.get("Workers Launched", 0)
            if workers > 0:
                # Each worker gets its own work_mem allocation
                operations.append(MemoryOperation(
                    node_type=node_type,
                    relation=f"{workers} workers",
                    estimated_bytes=0,  # Counted in child nodes
                    estimated_rows=rows,
                    width_bytes=0,
                    description=f"Parallel: {workers} workers, each gets own work_mem allocation ({workers}× memory)",
                ))

        # Recurse into children
        for child in node.get("Plans", []):
            self._walk_plan(child, operations)

    @staticmethod
    def _parse_memory(mem_str: str) -> int:
        """Parse PostgreSQL memory string to bytes."""
        import re
        match = re.match(r"(\d+)\s*(B|KB|MB|GB|TB)", mem_str.upper().strip())
        if not match:
            # Try plain integer (PostgreSQL returns KB by default)
            try:
                return int(mem_str) * 1024
            except ValueError:
                return 4 * 1024 * 1024  # Default 4MB
        value = int(match.group(1))
        unit = match.group(2)
        multiplier = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
        return value * multiplier.get(unit, 1)
