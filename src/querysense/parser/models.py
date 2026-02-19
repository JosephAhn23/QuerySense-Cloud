"""
Pydantic models for PostgreSQL EXPLAIN (FORMAT JSON) output.

These models represent the structure of EXPLAIN ANALYZE output. The structure is:
- ExplainOutput: Top-level wrapper containing the plan and timing info
- PlanNode: Recursive structure representing each node in the query plan tree

PostgreSQL EXPLAIN JSON uses "Title Case" keys, which we convert to snake_case
via Pydantic aliases for Pythonic access.

Reference: https://www.postgresql.org/docs/current/using-explain.html
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NodeType(str, Enum):
    """
    Known PostgreSQL plan node types.
    
    Not exhaustive - new node types may be added in future Postgres versions.
    We handle unknown types gracefully via the string fallback in PlanNode.
    """
    # Scan nodes
    SEQ_SCAN = "Seq Scan"
    INDEX_SCAN = "Index Scan"
    INDEX_ONLY_SCAN = "Index Only Scan"
    BITMAP_INDEX_SCAN = "Bitmap Index Scan"
    BITMAP_HEAP_SCAN = "Bitmap Heap Scan"
    TID_SCAN = "Tid Scan"
    SUBQUERY_SCAN = "Subquery Scan"
    FUNCTION_SCAN = "Function Scan"
    VALUES_SCAN = "Values Scan"
    CTE_SCAN = "CTE Scan"
    NAMED_TUPLE_STORE_SCAN = "Named Tuplestore Scan"
    WORK_TABLE_SCAN = "WorkTable Scan"
    FOREIGN_SCAN = "Foreign Scan"
    CUSTOM_SCAN = "Custom Scan"
    
    # Join nodes
    NESTED_LOOP = "Nested Loop"
    MERGE_JOIN = "Merge Join"
    HASH_JOIN = "Hash Join"
    
    # Materialization nodes
    MATERIALIZE = "Materialize"
    SORT = "Sort"
    INCREMENTAL_SORT = "Incremental Sort"
    GROUP = "Group"
    AGGREGATE = "Aggregate"
    GROUP_AGGREGATE = "GroupAggregate"
    HASH_AGGREGATE = "HashAggregate"
    MIXED_AGGREGATE = "MixedAggregate"
    WINDOW_AGG = "WindowAgg"
    UNIQUE = "Unique"
    SETOP = "SetOp"
    LOCK_ROWS = "LockRows"
    LIMIT = "Limit"
    HASH = "Hash"
    
    # Control nodes
    APPEND = "Append"
    MERGE_APPEND = "MergeAppend"
    RECURSIVE_UNION = "Recursive Union"
    BITMAP_AND = "BitmapAnd"
    BITMAP_OR = "BitmapOr"
    GATHER = "Gather"
    GATHER_MERGE = "Gather Merge"
    
    # Modification nodes
    MODIFY_TABLE = "ModifyTable"
    RESULT = "Result"


class JoinType(str, Enum):
    """PostgreSQL join types."""
    INNER = "Inner"
    LEFT = "Left"
    RIGHT = "Right"
    FULL = "Full"
    SEMI = "Semi"
    ANTI = "Anti"


class ScanDirection(str, Enum):
    """Index scan directions."""
    FORWARD = "Forward"
    BACKWARD = "Backward"
    NO_MOVEMENT = "NoMovement"


class SortMethod(str, Enum):
    """Sort methods used by Sort nodes."""
    QUICKSORT = "quicksort"
    TOP_N_HEAPSORT = "top-N heapsort"
    EXTERNAL_SORT = "external sort"
    EXTERNAL_MERGE = "external merge"
    STILL_IN_PROGRESS = "still in progress"


class PlanNode(BaseModel):
    """
    Represents a single node in the PostgreSQL query execution plan.
    
    This is a recursive structure - each node may contain child nodes in the
    `plans` field. The tree represents the execution order (leaves execute first,
    results flow up to the root).
    
    Fields are divided into:
    - Universal fields: Present on all nodes
    - EXPLAIN ANALYZE fields: Only present when ANALYZE was used
    - Node-specific fields: Vary by node type (captured in extras)
    """
    
    model_config = ConfigDict(
        populate_by_name=True,  # Allow both alias and field name
        extra="allow",  # Capture unknown fields in model_extra
    )
    
    # =========================================================================
    # Universal fields (present on all nodes)
    # =========================================================================
    
    node_type: str = Field(
        ...,
        alias="Node Type",
        description="The type of plan node (e.g., 'Seq Scan', 'Index Scan', 'Nested Loop')",
    )
    
    startup_cost: float = Field(
        ...,
        alias="Startup Cost",
        description="Estimated cost to return the first row",
    )
    
    total_cost: float = Field(
        ...,
        alias="Total Cost", 
        description="Estimated cost to return all rows",
    )
    
    plan_rows: int = Field(
        ...,
        alias="Plan Rows",
        description="Estimated number of rows to be returned",
    )
    
    plan_width: int = Field(
        ...,
        alias="Plan Width",
        description="Estimated average width of rows in bytes",
    )
    
    # =========================================================================
    # EXPLAIN ANALYZE fields (only present with ANALYZE option)
    # =========================================================================
    
    actual_startup_time: float | None = Field(
        default=None,
        alias="Actual Startup Time",
        description="Actual time in ms to return first row",
    )
    
    actual_total_time: float | None = Field(
        default=None,
        alias="Actual Total Time",
        description="Actual time in ms to return all rows",
    )
    
    actual_rows: int | None = Field(
        default=None,
        alias="Actual Rows",
        description="Actual number of rows returned",
    )
    
    actual_loops: int | None = Field(
        default=None,
        alias="Actual Loops",
        description="Number of times this node was executed",
    )
    
    # =========================================================================
    # Common optional fields (present on many but not all nodes)
    # =========================================================================
    
    relation_name: str | None = Field(
        default=None,
        alias="Relation Name",
        description="Table name for scan nodes",
    )
    
    schema_name: str | None = Field(
        default=None,
        alias="Schema",
        description="Schema name for the relation",
    )
    
    alias: str | None = Field(
        default=None,
        alias="Alias",
        description="Table alias used in the query",
    )
    
    index_name: str | None = Field(
        default=None,
        alias="Index Name",
        description="Index name for index scan nodes",
    )
    
    scan_direction: str | None = Field(
        default=None,
        alias="Scan Direction",
        description="Direction of index scan (Forward/Backward)",
    )
    
    join_type: str | None = Field(
        default=None,
        alias="Join Type",
        description="Type of join (Inner, Left, Right, Full, Semi, Anti)",
    )
    
    # Filter and condition fields
    filter: str | None = Field(
        default=None,
        alias="Filter",
        description="Filter condition applied to rows",
    )
    
    rows_removed_by_filter: int | None = Field(
        default=None,
        alias="Rows Removed by Filter",
        description="Number of rows removed by the filter",
    )
    
    index_cond: str | None = Field(
        default=None,
        alias="Index Cond",
        description="Index lookup condition",
    )
    
    recheck_cond: str | None = Field(
        default=None,
        alias="Recheck Cond",
        description="Condition rechecked after bitmap scan",
    )
    
    join_filter: str | None = Field(
        default=None,
        alias="Join Filter",
        description="Additional filter applied during join",
    )
    
    hash_cond: str | None = Field(
        default=None,
        alias="Hash Cond",
        description="Hash join condition",
    )
    
    merge_cond: str | None = Field(
        default=None,
        alias="Merge Cond",
        description="Merge join condition",
    )
    
    # Sort-related fields
    sort_key: list[str] | None = Field(
        default=None,
        alias="Sort Key",
        description="Columns used for sorting",
    )
    
    sort_method: str | None = Field(
        default=None,
        alias="Sort Method",
        description="Algorithm used for sorting",
    )
    
    sort_space_used: int | None = Field(
        default=None,
        alias="Sort Space Used",
        description="Memory/disk used for sort in KB",
    )
    
    sort_space_type: str | None = Field(
        default=None,
        alias="Sort Space Type",
        description="Memory or Disk",
    )
    
    # Parallel execution fields
    parallel_aware: bool | None = Field(
        default=None,
        alias="Parallel Aware",
        description="Whether the node is parallel-aware",
    )
    
    workers_planned: int | None = Field(
        default=None,
        alias="Workers Planned",
        description="Number of parallel workers planned",
    )
    
    workers_launched: int | None = Field(
        default=None,
        alias="Workers Launched",
        description="Number of parallel workers actually launched",
    )
    
    # Hash-related fields
    hash_buckets: int | None = Field(
        default=None,
        alias="Hash Buckets",
        description="Number of hash buckets",
    )
    
    hash_batches: int | None = Field(
        default=None,
        alias="Hash Batches",
        description="Number of hash batches (>1 means spilled to disk)",
    )
    
    peak_memory_usage: int | None = Field(
        default=None,
        alias="Peak Memory Usage",
        description="Peak memory used by hash table in KB",
    )
    
    # Buffer statistics (with BUFFERS option)
    shared_hit_blocks: int | None = Field(
        default=None,
        alias="Shared Hit Blocks",
        description="Shared buffer cache hits",
    )
    
    shared_read_blocks: int | None = Field(
        default=None,
        alias="Shared Read Blocks",
        description="Blocks read from disk",
    )
    
    shared_dirtied_blocks: int | None = Field(
        default=None,
        alias="Shared Dirtied Blocks",
        description="Blocks dirtied by this operation",
    )
    
    shared_written_blocks: int | None = Field(
        default=None,
        alias="Shared Written Blocks",
        description="Blocks written to disk",
    )
    
    # I/O timing (with BUFFERS and timing)
    io_read_time: float | None = Field(
        default=None,
        alias="I/O Read Time",
        description="Time spent reading blocks in ms",
    )
    
    io_write_time: float | None = Field(
        default=None,
        alias="I/O Write Time",
        description="Time spent writing blocks in ms",
    )
    
    # =========================================================================
    # Child nodes
    # =========================================================================
    
    plans: list[PlanNode] = Field(
        default_factory=list,
        alias="Plans",
        description="Child plan nodes",
    )
    
    # =========================================================================
    # Computed properties
    # =========================================================================

    @property
    def raw(self) -> dict[str, Any]:
        """Return the original EXPLAIN JSON dict for this node.

        Combines declared fields (using their EXPLAIN aliases like
        ``"Node Type"``) with any extra fields captured by Pydantic's
        ``extra="allow"`` setting.  Rules use this to access fields that
        are not modelled as explicit Pydantic attributes (e.g.
        ``"Workers Planned"``, ``"Hash Batches"``, ``"Sort Key"``).
        """
        data = self.model_dump(by_alias=True, exclude={"plans"})
        if self.model_extra:
            data.update(self.model_extra)
        if self.plans:
            data["Plans"] = [child.raw for child in self.plans]
        return data

    @property
    def is_scan_node(self) -> bool:
        """Check if this is a table/index scan node."""
        scan_types = {
            "Seq Scan", "Index Scan", "Index Only Scan",
            "Bitmap Heap Scan", "Bitmap Index Scan", "Tid Scan",
        }
        return self.node_type in scan_types
    
    @property
    def is_join_node(self) -> bool:
        """Check if this is a join node."""
        return self.node_type in {"Nested Loop", "Merge Join", "Hash Join"}
    
    @property
    def has_analyze_data(self) -> bool:
        """Check if EXPLAIN ANALYZE data is present."""
        return self.actual_rows is not None
    
    @property
    def row_estimate_ratio(self) -> float | None:
        """
        Ratio of actual to estimated rows.
        
        Values far from 1.0 indicate bad statistics:
        - >> 1: Planner underestimated (may choose wrong plan)
        - << 1: Planner overestimated (usually less harmful)
        
        Returns None if ANALYZE data not available.
        """
        if self.actual_rows is None:
            return None
        if self.plan_rows == 0:
            return float('inf') if self.actual_rows > 0 else 1.0
        return self.actual_rows / self.plan_rows
    
    @property
    def total_actual_time(self) -> float | None:
        """
        Total time including all loop iterations.
        
        actual_total_time is per-loop, so multiply by loops for true total.
        """
        if self.actual_total_time is None or self.actual_loops is None:
            return None
        return self.actual_total_time * self.actual_loops
    
    def iter_nodes(self) -> "list[PlanNode]":
        """
        Iterate through all nodes in the plan tree (depth-first).
        
        Useful for finding all nodes of a certain type or property.
        """
        nodes = [self]
        for child in self.plans:
            nodes.extend(child.iter_nodes())
        return nodes


class ExplainOutput(BaseModel):
    """
    Top-level structure for PostgreSQL EXPLAIN (FORMAT JSON) output.
    
    PostgreSQL returns EXPLAIN JSON as a single-element array containing
    an object with 'Plan', 'Planning Time', etc. This model represents
    that inner object.
    
    Usage:
        # Parse from file
        with open("explain.json") as f:
            data = json.load(f)
        output = ExplainOutput.model_validate(data[0])
        
        # Access the plan tree
        for node in output.plan.iter_nodes():
            if node.node_type == "Seq Scan":
                print(f"Sequential scan on {node.relation_name}")
    """
    
    model_config = ConfigDict(
        populate_by_name=True,
        extra="allow",  # Capture any additional fields
    )
    
    plan: PlanNode = Field(
        ...,
        alias="Plan",
        description="Root node of the execution plan tree",
    )
    
    planning_time: float | None = Field(
        default=None,
        alias="Planning Time",
        description="Time spent planning the query in milliseconds",
    )
    
    execution_time: float | None = Field(
        default=None,
        alias="Execution Time",
        description="Total execution time in milliseconds (ANALYZE only)",
    )
    
    # Query text (if VERBOSE option used)
    query_text: str | None = Field(
        default=None,
        alias="Query Text",
        description="Original query text (with VERBOSE option)",
    )
    
    # Trigger information (for queries with triggers)
    triggers: list[dict[str, Any]] | None = Field(
        default=None,
        alias="Triggers",
        description="Trigger execution information",
    )
    
    # JIT compilation info (PostgreSQL 11+)
    jit: dict[str, Any] | None = Field(
        default=None,
        alias="JIT",
        description="JIT compilation statistics",
    )
    
    # =========================================================================
    # Computed properties
    # =========================================================================
    
    @property
    def has_analyze_data(self) -> bool:
        """Check if EXPLAIN ANALYZE data is present."""
        return self.execution_time is not None
    
    @property
    def all_nodes(self) -> list[PlanNode]:
        """Get all nodes in the plan tree as a flat list."""
        return self.plan.iter_nodes()
    
    def find_nodes_by_type(self, node_type: str) -> list[PlanNode]:
        """Find all nodes of a specific type."""
        return [n for n in self.all_nodes if n.node_type == node_type]
    
    def find_slow_nodes(self, threshold_ms: float = 100.0) -> list[PlanNode]:
        """
        Find nodes that took longer than the threshold.
        
        Only works with ANALYZE data. Returns empty list without it.
        """
        if not self.has_analyze_data:
            return []
        return [
            n for n in self.all_nodes
            if n.total_actual_time is not None and n.total_actual_time > threshold_ms
        ]

