"""
Engine-agnostic plan node (Intermediate Representation).

IRNode is the central data structure of the plan algebra. It represents
a single operation in a query execution plan, abstracted away from any
specific database engine.

Design principles:
- Immutable (frozen dataclass): Nodes don't change after creation
- Engine-agnostic: Uses Operator taxonomy, not raw strings
- Lossless: Preserves engine-specific data in `engine_specific` dict
- Composable: Recursive tree structure with typed children
- Traversable: Built-in iteration and search methods

Relationship to existing PlanNode:
- PlanNode (parser/models.py) is PostgreSQL-specific with Title Case aliases
- IRNode is the universal abstraction that PlanNode maps into
- Rules targeting IRNode work across all engines
- Rules targeting PlanNode continue to work (backward compatible)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum, unique
from typing import Any, Iterator


from querysense.ir.operators import (
    AggregateStrategy,
    IROperator,
    JoinAlgorithm,
    Operator,
    ScanMethod,
    SetOpKind,
    SortVariant,
)


# ── Backward-compatible enums ──────────────────────────────────────────
#
# The operators module was refactored to use cleaner names and a smaller
# set of strategies.  node.py still references the old enum classes and
# values.  Rather than rewriting the entire node hierarchy in one shot,
# we provide thin compatibility enums that preserve the old API surface
# while delegating to the canonical types where possible.
#
# TODO(IR-migration): Migrate all usages to the canonical names, then
#   delete these stubs.
# -----------------------------------------------------------------------

from enum import Enum as _Enum


class OperatorCategory(str, _Enum):
    """High-level operator category for plan nodes."""
    SCAN = "scan"
    JOIN = "join"
    AGGREGATE = "aggregate"
    SORT = "sort"
    MATERIALIZE = "materialize"
    CONTROL = "control"
    OTHER = "other"
    UNKNOWN = "unknown"


# Legacy Operator alias -- now imported from operators.py
# (The Operator dataclass carries category + strategy fields.)


class ScanStrategy(str, _Enum):
    """Scan sub-strategies used by the PostgreSQL adapter."""
    SEQUENTIAL = ScanMethod.SEQUENTIAL.value
    FULL_TABLE = "full_table"
    INDEX = ScanMethod.INDEX.value
    INDEX_SCAN = "index_scan"
    INDEX_ONLY = ScanMethod.INDEX_ONLY.value
    BITMAP = ScanMethod.BITMAP.value
    BITMAP_SCAN = "bitmap_scan"
    BITMAP_INDEX = "bitmap_index"
    BITMAP_HEAP = ScanMethod.BITMAP_HEAP.value
    TID = ScanMethod.TID.value
    TID_SCAN = "tid_scan"
    FUNCTION = ScanMethod.FUNCTION.value
    SUBQUERY = "subquery"
    VALUES = "values"
    CTE = "cte"
    WORK_TABLE = "work_table"
    FOREIGN = ScanMethod.FOREIGN.value
    CUSTOM = ScanMethod.CUSTOM.value
    UNKNOWN = "unknown"


class JoinStrategy(str, _Enum):
    """Join sub-strategies."""
    NESTED_LOOP = JoinAlgorithm.NESTED_LOOP.value
    HASH = JoinAlgorithm.HASH.value
    HASH_JOIN = "hash_join"
    MERGE = JoinAlgorithm.MERGE.value
    MERGE_JOIN = "merge_join"
    UNKNOWN = "unknown"


class SortStrategy(str, _Enum):
    """Sort sub-strategies."""
    IN_MEMORY = SortVariant.IN_MEMORY.value
    EXTERNAL = SortVariant.EXTERNAL.value
    EXTERNAL_MERGE = "external_merge"
    TOP_N = SortVariant.TOP_N.value
    INCREMENTAL = SortVariant.INCREMENTAL.value
    UNKNOWN = "unknown"


class JoinType(str, _Enum):
    """Join type (inner/outer/semi/anti)."""
    INNER = "inner"
    LEFT = "left"
    RIGHT = "right"
    FULL = "full"
    CROSS = "cross"
    SEMI = "semi"
    ANTI = "anti"
    UNKNOWN = "unknown"


class ScanDirection(str, _Enum):
    """Index scan direction."""
    FORWARD = "forward"
    BACKWARD = "backward"
    UNORDERED = "unordered"
    NO_MOVEMENT = "no_movement"


class ControlStrategy(str, _Enum):
    """Control flow sub-strategies."""
    APPEND = "append"
    MERGE_APPEND = "merge_append"
    RECURSIVE_UNION = "recursive_union"
    BITMAP_AND = "bitmap_and"
    BITMAP_OR = "bitmap_or"
    GATHER = "gather"
    GATHER_MERGE = "gather_merge"
    MODIFY_TABLE = "modify_table"
    UNKNOWN = "unknown"


class MaterializeStrategy(str, _Enum):
    """Materialization sub-strategies."""
    MATERIALIZE = "materialize"
    HASH_TABLE = "hash_table"
    WINDOW = "window"
    LOCK_ROWS = "lock_rows"
    LIMIT = "limit"
    UNIQUE = "unique"
    SETOP = "setop"
    RESULT = "result"
    EAGER = "eager"
    LAZY = "lazy"
    CTE = "cte"
    UNKNOWN = "unknown"


# =============================================================================
# Engine Identifier
# =============================================================================


@unique
class EngineType(str, Enum):
    """Supported database engine types."""

    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLSERVER = "sqlserver"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


# =============================================================================
# Condition Representation
# =============================================================================


@dataclass(frozen=True)
class Condition:
    """
    A filter or join condition in the plan.

    Preserves the raw expression string from the engine while
    classifying the condition type for rule analysis.
    """

    expression: str
    kind: ConditionKind
    columns: tuple[str, ...] = ()

    def __str__(self) -> str:
        return self.expression


@unique
class ConditionKind(str, Enum):
    """Classification of condition types."""

    FILTER = "filter"               # Post-scan filter (WHERE)
    INDEX_CONDITION = "index_cond"  # Pushed to index (WHERE via index)
    JOIN_CONDITION = "join_cond"    # Join predicate
    RECHECK = "recheck"             # Bitmap recheck condition
    HAVING = "having"               # HAVING clause
    ATTACHED = "attached"           # MySQL "attached_condition"
    UNKNOWN = "unknown"


# =============================================================================
# Buffer / IO Statistics
# =============================================================================


@dataclass(frozen=True)
class BufferStats:
    """
    Buffer and I/O statistics for a node.

    Normalized across engines:
    - PostgreSQL: Shared Hit/Read/Dirtied/Written Blocks + I/O timing
    - MySQL: Currently not available from EXPLAIN (requires Performance Schema)
    """

    shared_hit_blocks: int = 0
    shared_read_blocks: int = 0
    shared_dirtied_blocks: int = 0
    shared_written_blocks: int = 0
    io_read_time_ms: float = 0.0
    io_write_time_ms: float = 0.0

    @property
    def total_blocks(self) -> int:
        return self.shared_hit_blocks + self.shared_read_blocks

    @property
    def cache_hit_ratio(self) -> float:
        total = self.total_blocks
        if total == 0:
            return 1.0
        return self.shared_hit_blocks / total

    @property
    def has_data(self) -> bool:
        return self.total_blocks > 0 or self.io_read_time_ms > 0


# =============================================================================
# Sort Metadata
# =============================================================================


@dataclass(frozen=True)
class SortInfo:
    """Sort-specific metadata."""

    keys: tuple[str, ...] = ()
    method: str | None = None
    space_used_kb: int = 0
    space_type: str | None = None          # "Memory" or "Disk"
    strategy: SortStrategy = SortStrategy.UNKNOWN

    @property
    def is_spilling(self) -> bool:
        return self.space_type == "Disk" or self.strategy in (
            SortStrategy.EXTERNAL,
            SortStrategy.EXTERNAL_MERGE,
        )


# =============================================================================
# Hash Metadata
# =============================================================================


@dataclass(frozen=True)
class HashInfo:
    """Hash operation metadata."""

    buckets: int = 0
    batches: int = 1
    peak_memory_kb: int = 0

    @property
    def is_spilling(self) -> bool:
        return self.batches > 1


# =============================================================================
# Parallel Execution Metadata
# =============================================================================


@dataclass(frozen=True)
class ParallelInfo:
    """Parallel execution metadata."""

    aware: bool = False
    workers_planned: int = 0
    workers_launched: int = 0

    @property
    def underutilized(self) -> bool:
        return self.workers_launched < self.workers_planned


# =============================================================================
# IRNode — The Core Abstraction
# =============================================================================


@dataclass(frozen=True)
class IRNode:
    """
    Engine-agnostic query plan node.

    This is the central abstraction of the plan algebra. Each IRNode
    represents a single operation in the execution plan, with typed
    operator classification and normalized metrics.

    Fields:
        operator: What this node does (scan, join, sort, etc.)
        estimated_rows: Planner's row estimate
        estimated_cost: Planner's total cost estimate
        estimated_startup_cost: Cost to produce first row
        estimated_width: Average row width in bytes
        actual_rows: Actual rows (ANALYZE only)
        actual_time_ms: Actual total time per loop in ms (ANALYZE only)
        actual_startup_time_ms: Actual time to first row (ANALYZE only)
        actual_loops: Number of times node was executed
        relation: Table name for scan nodes
        schema: Schema name for the relation
        alias: Table alias used in the query
        index_name: Index used (for index scans)
        scan_direction: Direction of index traversal
        join_type: Logical join type (INNER, LEFT, etc.)
        conditions: All conditions (filters, index conds, join conds)
        sort_info: Sort-specific metadata
        hash_info: Hash-specific metadata
        parallel_info: Parallel execution metadata
        buffers: Buffer/IO statistics
        children: Child nodes in the plan tree
        engine: Source database engine
        engine_specific: Engine-specific data not captured above
        source_node_type: Original engine-specific node type string

    Invariants:
        - operator is always set (never None)
        - estimated_rows >= 0
        - estimated_cost >= 0
        - children is a tuple (immutable)
    """

    # --- Core identity ---
    operator: Operator

    # --- Cost model (planner estimates) ---
    estimated_rows: int = 0
    estimated_cost: float = 0.0
    estimated_startup_cost: float = 0.0
    estimated_width: int = 0

    # --- Runtime stats (ANALYZE only) ---
    actual_rows: int | None = None
    actual_time_ms: float | None = None
    actual_startup_time_ms: float | None = None
    actual_loops: int | None = None

    # --- Relation info ---
    relation: str | None = None
    schema: str | None = None
    alias: str | None = None
    index_name: str | None = None
    scan_direction: ScanDirection = ScanDirection.FORWARD

    # --- Join info ---
    join_type: JoinType = JoinType.UNKNOWN

    # --- Conditions ---
    conditions: tuple[Condition, ...] = ()

    # --- Operation-specific metadata ---
    sort_info: SortInfo | None = None
    hash_info: HashInfo | None = None
    parallel_info: ParallelInfo | None = None
    buffers: BufferStats | None = None

    # --- Tree structure ---
    children: tuple[IRNode, ...] = ()

    # --- Engine provenance ---
    engine: EngineType = EngineType.UNKNOWN
    engine_specific: dict[str, Any] = field(default_factory=dict)
    source_node_type: str = ""

    # =========================================================================
    # Computed Properties
    # =========================================================================

    @property
    def has_analyze_data(self) -> bool:
        """Whether runtime statistics are available."""
        return self.actual_rows is not None

    @property
    def row_estimate_ratio(self) -> float | None:
        """
        Ratio of actual to estimated rows.

        Values far from 1.0 indicate bad statistics:
        - >> 1: Planner underestimated
        - << 1: Planner overestimated
        """
        if self.actual_rows is None or self.estimated_rows == 0:
            return None
        return self.actual_rows / self.estimated_rows

    @property
    def total_actual_time_ms(self) -> float | None:
        """Total time including all loop iterations."""
        if self.actual_time_ms is None or self.actual_loops is None:
            return None
        return self.actual_time_ms * self.actual_loops

    @property
    def is_scan(self) -> bool:
        return self.operator.is_scan

    @property
    def is_full_table_scan(self) -> bool:
        return self.operator.is_full_table_scan

    @property
    def is_index_scan(self) -> bool:
        return self.operator.is_index_scan

    @property
    def is_join(self) -> bool:
        return self.operator.is_join

    @property
    def is_sort(self) -> bool:
        return self.operator.is_sort

    @property
    def is_aggregate(self) -> bool:
        return self.operator.is_aggregate

    @property
    def is_spilling(self) -> bool:
        """Whether this node is spilling to disk."""
        if self.sort_info and self.sort_info.is_spilling:
            return True
        if self.hash_info and self.hash_info.is_spilling:
            return True
        return False

    @property
    def filter_conditions(self) -> tuple[Condition, ...]:
        """Get only filter conditions."""
        return tuple(c for c in self.conditions if c.kind == ConditionKind.FILTER)

    @property
    def index_conditions(self) -> tuple[Condition, ...]:
        """Get only index conditions."""
        return tuple(
            c for c in self.conditions if c.kind == ConditionKind.INDEX_CONDITION
        )

    @property
    def join_conditions(self) -> tuple[Condition, ...]:
        """Get only join conditions."""
        return tuple(
            c for c in self.conditions if c.kind == ConditionKind.JOIN_CONDITION
        )

    # =========================================================================
    # Tree Traversal
    # =========================================================================

    def iter_all(self) -> Iterator[IRNode]:
        """Depth-first iteration over all nodes in the tree."""
        yield self
        for child in self.children:
            yield from child.iter_all()

    def iter_with_parent(
        self, parent: IRNode | None = None
    ) -> Iterator[tuple[IRNode, IRNode | None]]:
        """Depth-first iteration yielding (node, parent) pairs."""
        yield self, parent
        for child in self.children:
            yield from child.iter_with_parent(parent=self)

    def iter_with_depth(
        self, depth: int = 0
    ) -> Iterator[tuple[IRNode, int]]:
        """Depth-first iteration yielding (node, depth) pairs."""
        yield self, depth
        for child in self.children:
            yield from child.iter_with_depth(depth + 1)

    @property
    def node_count(self) -> int:
        """Total number of nodes in this subtree."""
        return 1 + sum(child.node_count for child in self.children)

    @property
    def depth(self) -> int:
        """Maximum depth of this subtree."""
        if not self.children:
            return 0
        return 1 + max(child.depth for child in self.children)

    def find_nodes(
        self, predicate: Any  # Callable[[IRNode], bool]
    ) -> list[IRNode]:
        """Find all nodes matching a predicate."""
        return [node for node in self.iter_all() if predicate(node)]

    def find_scans(self) -> list[IRNode]:
        """Find all scan nodes."""
        return self.find_nodes(lambda n: n.is_scan)

    def find_joins(self) -> list[IRNode]:
        """Find all join nodes."""
        return self.find_nodes(lambda n: n.is_join)

    def find_full_table_scans(self) -> list[IRNode]:
        """Find all full table scans."""
        return self.find_nodes(lambda n: n.is_full_table_scan)

    # =========================================================================
    # Fingerprinting
    # =========================================================================

    def structure_hash(self) -> str:
        """
        Hash of the plan structure (operators + relations).

        Used for plan comparison and caching. Ignores runtime metrics
        so the same logical plan produces the same hash.
        """
        parts: list[str] = []
        for node in self.iter_all():
            op = node.operator
            strategy = (
                op.scan or op.join or op.aggregate
                or op.sort or op.materialize or op.control
            )
            parts.append(
                f"{op.category.value}:"
                f"{strategy.value if strategy else 'none'}:"
                f"{node.relation or ''}"
            )
        content = "|".join(parts)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    # =========================================================================
    # Serialization
    # =========================================================================

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        result: dict[str, Any] = {
            "operator": self.operator.to_dict(),
            "estimated_rows": self.estimated_rows,
            "estimated_cost": self.estimated_cost,
            "engine": self.engine.value,
            "source_node_type": self.source_node_type,
        }

        if self.relation:
            result["relation"] = self.relation
        if self.index_name:
            result["index_name"] = self.index_name
        if self.actual_rows is not None:
            result["actual_rows"] = self.actual_rows
        if self.actual_time_ms is not None:
            result["actual_time_ms"] = self.actual_time_ms
        if self.conditions:
            result["conditions"] = [
                {"expression": c.expression, "kind": c.kind.value}
                for c in self.conditions
            ]
        if self.sort_info:
            result["sort_info"] = {
                "keys": list(self.sort_info.keys),
                "method": self.sort_info.method,
                "is_spilling": self.sort_info.is_spilling,
            }
        if self.hash_info and self.hash_info.batches > 1:
            result["hash_info"] = {
                "batches": self.hash_info.batches,
                "peak_memory_kb": self.hash_info.peak_memory_kb,
            }
        if self.children:
            result["children"] = [child.to_dict() for child in self.children]

        return result

    def __repr__(self) -> str:
        parts = [f"IRNode({self.operator!r}"]
        if self.relation:
            parts.append(f", relation={self.relation!r}")
        if self.actual_rows is not None:
            parts.append(f", actual_rows={self.actual_rows}")
        elif self.estimated_rows:
            parts.append(f", est_rows={self.estimated_rows}")
        if self.children:
            parts.append(f", children={len(self.children)}")
        parts.append(")")
        return "".join(parts)


# =============================================================================
# IRPlan — Top-level plan wrapper
# =============================================================================


@dataclass(frozen=True)
class IRPlan:
    """
    Complete execution plan in IR form.

    Wraps the root IRNode with plan-level metadata like
    planning time, execution time, and engine info.
    """

    root: IRNode
    engine: EngineType
    planning_time_ms: float | None = None
    execution_time_ms: float | None = None
    engine_version: str | None = None

    # Original raw plan data for lossless round-trip
    raw_plan: dict[str, Any] = field(default_factory=dict)

    @property
    def has_analyze_data(self) -> bool:
        return self.execution_time_ms is not None or self.root.has_analyze_data

    @property
    def node_count(self) -> int:
        return self.root.node_count

    @property
    def all_nodes(self) -> list[IRNode]:
        return list(self.root.iter_all())

    def find_full_table_scans(self) -> list[IRNode]:
        return self.root.find_full_table_scans()

    def find_joins(self) -> list[IRNode]:
        return self.root.find_joins()

    def structure_hash(self) -> str:
        return self.root.structure_hash()

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "engine": self.engine.value,
            "root": self.root.to_dict(),
        }
        if self.planning_time_ms is not None:
            result["planning_time_ms"] = self.planning_time_ms
        if self.execution_time_ms is not None:
            result["execution_time_ms"] = self.execution_time_ms
        return result
