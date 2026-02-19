"""
IR Plan model: the unified representation of a query execution plan.

An ``IRPlan`` is a tree of ``IRNode`` objects, each carrying:
- A portable operator (Layer A)
- Portable properties (Layer B)
- Engine-specific annotations (Layer C)

Plus plan-level metadata: engine identity, capabilities, planning/execution
time, and the original plan version string.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterator

from querysense.ir.annotations import (
    IRAnnotations,
    IRCapability,
    derive_capabilities,
)
from querysense.ir.operators import IROperator, is_join, is_scan
from querysense.ir.properties import IRProperties


@dataclass
class IRNode:
    """
    A single node in the IR plan tree.

    Attributes:
        id: Unique identifier within the plan (e.g. "n0", "n1").
        operator: Portable operator category.
        algorithm: Optional sub-classification string (e.g. "HashJoin").
        properties: Portable properties (cardinality, cost, time, memory, ...).
        annotations: Engine-specific metadata.
        children: Child nodes (inputs).
        depth: Depth in the tree (0 = root).
        path: Human-readable path (e.g. "Root -> Hash Join -> Seq Scan").
    """

    id: str
    operator: IROperator
    algorithm: str = ""
    properties: IRProperties = field(default_factory=IRProperties)
    annotations: IRAnnotations = field(default_factory=IRAnnotations)
    children: list[IRNode] = field(default_factory=list)
    depth: int = 0
    path: str = ""

    # ── Tree traversal ────────────────────────────────────────────────

    def iter_depth_first(self) -> Iterator[IRNode]:
        """Yield all nodes in depth-first order (self first)."""
        yield self
        for child in self.children:
            yield from child.iter_depth_first()

    def iter_with_parent(
        self, parent: IRNode | None = None,
    ) -> Iterator[tuple[IRNode, IRNode | None]]:
        """Yield ``(node, parent)`` pairs in depth-first order."""
        yield (self, parent)
        for child in self.children:
            yield from child.iter_with_parent(parent=self)

    @property
    def node_count(self) -> int:
        return sum(1 for _ in self.iter_depth_first())

    @property
    def is_scan(self) -> bool:
        return is_scan(self.operator)

    @property
    def is_join(self) -> bool:
        return is_join(self.operator)

    @property
    def relation(self) -> str | None:
        return self.properties.relation_name

    @property
    def has_actuals(self) -> bool:
        return self.properties.cardinality.has_actuals

    # ── Structural fingerprint ────────────────────────────────────────

    def structure_signature(self) -> str:
        """
        Stable structural signature ignoring volatile fields (costs, times, rows).

        Used for plan regression detection: if the signature changes, the
        plan *structure* changed.
        """
        parts = [self.operator.value, self.algorithm]
        if self.properties.relation_name:
            parts.append(self.properties.relation_name)
        if self.properties.index_name:
            parts.append(self.properties.index_name)
        if self.properties.join_type:
            parts.append(self.properties.join_type)
        child_sigs = [c.structure_signature() for c in self.children]
        parts.append(f"[{','.join(child_sigs)}]")
        return "|".join(parts)

    # ── Serialization ─────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        d: dict[str, Any] = {
            "id": self.id,
            "op": self.operator.value,
        }
        if self.algorithm:
            d["algo"] = self.algorithm
        if self.properties.relation_name:
            d["relation"] = self.properties.relation_name
        if self.properties.index_name:
            d["index"] = self.properties.index_name

        # Cardinality
        c = self.properties.cardinality
        est: dict[str, Any] = {}
        if c.estimated_rows is not None:
            est["rows"] = c.estimated_rows
        cost = self.properties.cost
        if cost.startup_cost is not None or cost.total_cost is not None:
            est["cost"] = {}
            if cost.startup_cost is not None:
                est["cost"]["startup"] = cost.startup_cost
            if cost.total_cost is not None:
                est["cost"]["total"] = cost.total_cost
        if est:
            d["est"] = est

        act: dict[str, Any] = {}
        if c.actual_rows is not None:
            act["rows"] = c.actual_rows
        if c.actual_loops is not None:
            act["loops"] = c.actual_loops
        t = self.properties.time
        if t.total_time_ms is not None:
            act["time_ms"] = t.total_time_ms
        if act:
            d["act"] = act

        if self.children:
            d["inputs"] = [child.to_dict() for child in self.children]

        return d


@dataclass
class IRPlan:
    """
    Complete IR plan: a tree of IRNode objects plus plan-level metadata.

    Attributes:
        engine: Engine identifier ("postgres", "mysql", "sqlserver").
        engine_version: Engine-specific version string.
        root: Root node of the plan tree.
        capabilities: Derived capability set.
        planning_time_ms: Planning time (if reported).
        execution_time_ms: Execution time (if reported).
        query_text: Original SQL (if available).
        ir_version: IR schema version for forward compatibility.
        raw_plan: Original plan data (for debugging / round-trip).
    """

    engine: str
    root: IRNode
    engine_version: str = ""
    capabilities: frozenset[IRCapability] = frozenset()
    planning_time_ms: float | None = None
    execution_time_ms: float | None = None
    query_text: str | None = None
    ir_version: str = "1.0"
    raw_plan: dict[str, Any] | None = None

    # ── Convenience ───────────────────────────────────────────────────

    def all_nodes(self) -> Iterator[IRNode]:
        """Iterate all nodes depth-first."""
        return self.root.iter_depth_first()

    def all_nodes_with_parent(self) -> Iterator[tuple[IRNode, IRNode | None]]:
        """Iterate ``(node, parent)`` pairs depth-first."""
        return self.root.iter_with_parent()

    @property
    def node_count(self) -> int:
        return self.root.node_count

    def has_capability(self, cap: IRCapability) -> bool:
        return cap in self.capabilities

    def derive_and_set_capabilities(self) -> None:
        """Derive capabilities from plan content and store them."""
        self.capabilities = derive_capabilities(self)

    # ── Fingerprinting ────────────────────────────────────────────────

    def structure_hash(self) -> str:
        """SHA-256 of the structural signature (ignoring volatile fields)."""
        sig = self.root.structure_signature()
        return hashlib.sha256(sig.encode()).hexdigest()[:16]

    def full_fingerprint(self) -> dict[str, str]:
        """
        Multi-component fingerprint for caching and regression detection.
        """
        struct = self.structure_hash()
        # Data hash includes cardinality estimates
        data_parts: list[str] = []
        for node in self.all_nodes():
            c = node.properties.cardinality
            if c.estimated_rows is not None:
                data_parts.append(f"{node.id}:{c.estimated_rows}")
        data_hash = hashlib.sha256(
            "|".join(data_parts).encode()
        ).hexdigest()[:16]

        return {
            "structure": struct,
            "data": data_hash,
            "engine": self.engine,
            "node_count": str(self.node_count),
        }

    # ── Cost share computation ────────────────────────────────────────

    def compute_cost_shares(self) -> None:
        """
        Compute cost_share for every node as node.total_cost / root.total_cost.

        Mutates nodes in-place (replaces properties with updated cost signals).
        """
        root_cost = self.root.properties.cost.total_cost
        if not root_cost or root_cost <= 0:
            return

        for node in self.all_nodes():
            nc = node.properties.cost
            if nc.total_cost is not None:
                from querysense.ir.properties import CostSignals

                node.properties = IRProperties(
                    cardinality=node.properties.cardinality,
                    cost=CostSignals(
                        startup_cost=nc.startup_cost,
                        total_cost=nc.total_cost,
                        cost_share=nc.total_cost / root_cost,
                    ),
                    time=node.properties.time,
                    memory=node.properties.memory,
                    parallelism=node.properties.parallelism,
                    predicates=node.properties.predicates,
                    relation_name=node.properties.relation_name,
                    schema_name=node.properties.schema_name,
                    alias=node.properties.alias,
                    index_name=node.properties.index_name,
                    join_type=node.properties.join_type,
                    scan_direction=node.properties.scan_direction,
                    output_ordering=node.properties.output_ordering,
                    extra=node.properties.extra,
                )

    # ── Self-time computation ─────────────────────────────────────────

    def compute_self_times(self) -> None:
        """
        Compute exclusive (self) time for each node as total_time minus
        sum of children's total_times.  Mutates nodes in-place.
        """
        for node in self.all_nodes():
            t = node.properties.time
            if t.total_time_ms is None:
                continue
            children_time = sum(
                c.properties.time.total_time_ms or 0.0
                for c in node.children
            )
            self_time = max(0.0, t.total_time_ms - children_time)
            from querysense.ir.properties import TimeSignals

            node.properties = IRProperties(
                cardinality=node.properties.cardinality,
                cost=node.properties.cost,
                time=TimeSignals(
                    startup_time_ms=t.startup_time_ms,
                    total_time_ms=t.total_time_ms,
                    self_time_ms=self_time,
                ),
                memory=node.properties.memory,
                parallelism=node.properties.parallelism,
                predicates=node.properties.predicates,
                relation_name=node.properties.relation_name,
                schema_name=node.properties.schema_name,
                alias=node.properties.alias,
                index_name=node.properties.index_name,
                join_type=node.properties.join_type,
                scan_direction=node.properties.scan_direction,
                output_ordering=node.properties.output_ordering,
                extra=node.properties.extra,
            )

    # ── Serialization ─────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full IR plan to a JSON-compatible dict."""
        return {
            "ir_version": self.ir_version,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "capabilities": sorted(c.value for c in self.capabilities),
            "planning_time_ms": self.planning_time_ms,
            "execution_time_ms": self.execution_time_ms,
            "fingerprint": self.full_fingerprint(),
            "root": self.root.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
