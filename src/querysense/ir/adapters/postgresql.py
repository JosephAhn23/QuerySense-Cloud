"""
PostgreSQL EXPLAIN JSON → IR adapter.

Converts PostgreSQL's EXPLAIN (FORMAT JSON) output into the universal
IRNode representation. This is the reference adapter — PostgreSQL is
the primary supported engine and its cost model is the IR baseline.

Mapping strategy:
- Node types → Operator taxonomy (1:1 mapping for most types)
- Cost values → Pass-through (PG costs are the IR baseline)
- Conditions → Condition objects with classified kinds
- Buffer stats → BufferStats objects
- Sort/Hash metadata → SortInfo/HashInfo objects

The adapter can work with either:
1. Raw dict (EXPLAIN JSON parsed from string)
2. Existing PlanNode objects (from querysense.parser.models)
"""

from __future__ import annotations

from typing import Any

from querysense.ir.node import (
    BufferStats,
    Condition,
    ConditionKind,
    EngineType,
    HashInfo,
    IRNode,
    IRPlan,
    ParallelInfo,
    SortInfo,
)
from querysense.ir.operators import AggregateStrategy, Operator
from querysense.ir.node import (
    ControlStrategy,
    JoinStrategy,
    JoinType,
    MaterializeStrategy,
    OperatorCategory,
    ScanDirection,
    ScanStrategy,
    SortStrategy,
)


# =============================================================================
# Node Type → Operator Mapping
# =============================================================================

# Maps PostgreSQL node type strings to (category, strategy) tuples
_PG_NODE_MAP: dict[str, tuple[OperatorCategory, Any]] = {
    # Scan nodes
    "Seq Scan": (OperatorCategory.SCAN, ScanStrategy.FULL_TABLE),
    "Index Scan": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
    "Index Only Scan": (OperatorCategory.SCAN, ScanStrategy.INDEX_ONLY),
    "Bitmap Heap Scan": (OperatorCategory.SCAN, ScanStrategy.BITMAP_SCAN),
    "Bitmap Index Scan": (OperatorCategory.SCAN, ScanStrategy.BITMAP_INDEX),
    "Tid Scan": (OperatorCategory.SCAN, ScanStrategy.TID_SCAN),
    "Subquery Scan": (OperatorCategory.SCAN, ScanStrategy.SUBQUERY),
    "Function Scan": (OperatorCategory.SCAN, ScanStrategy.FUNCTION),
    "Values Scan": (OperatorCategory.SCAN, ScanStrategy.VALUES),
    "CTE Scan": (OperatorCategory.SCAN, ScanStrategy.CTE),
    "Named Tuplestore Scan": (OperatorCategory.SCAN, ScanStrategy.WORK_TABLE),
    "WorkTable Scan": (OperatorCategory.SCAN, ScanStrategy.WORK_TABLE),
    "Foreign Scan": (OperatorCategory.SCAN, ScanStrategy.FOREIGN),
    "Custom Scan": (OperatorCategory.SCAN, ScanStrategy.CUSTOM),
    # Join nodes
    "Nested Loop": (OperatorCategory.JOIN, JoinStrategy.NESTED_LOOP),
    "Hash Join": (OperatorCategory.JOIN, JoinStrategy.HASH_JOIN),
    "Merge Join": (OperatorCategory.JOIN, JoinStrategy.MERGE_JOIN),
    # Aggregate nodes
    "Aggregate": (OperatorCategory.AGGREGATE, AggregateStrategy.PLAIN),
    "GroupAggregate": (OperatorCategory.AGGREGATE, AggregateStrategy.SORT),
    "HashAggregate": (OperatorCategory.AGGREGATE, AggregateStrategy.HASH),
    "MixedAggregate": (OperatorCategory.AGGREGATE, AggregateStrategy.MIXED),
    # Sort nodes
    "Sort": (OperatorCategory.SORT, SortStrategy.UNKNOWN),  # Refined from sort_method
    "Incremental Sort": (OperatorCategory.SORT, SortStrategy.INCREMENTAL),
    # Materialize / buffer nodes
    "Materialize": (OperatorCategory.MATERIALIZE, MaterializeStrategy.MATERIALIZE),
    "Hash": (OperatorCategory.MATERIALIZE, MaterializeStrategy.HASH_TABLE),
    "WindowAgg": (OperatorCategory.MATERIALIZE, MaterializeStrategy.WINDOW),
    "LockRows": (OperatorCategory.MATERIALIZE, MaterializeStrategy.LOCK_ROWS),
    "Limit": (OperatorCategory.MATERIALIZE, MaterializeStrategy.LIMIT),
    "Unique": (OperatorCategory.MATERIALIZE, MaterializeStrategy.UNIQUE),
    "SetOp": (OperatorCategory.MATERIALIZE, MaterializeStrategy.SETOP),
    "Result": (OperatorCategory.MATERIALIZE, MaterializeStrategy.RESULT),
    "Group": (OperatorCategory.AGGREGATE, AggregateStrategy.SORT),
    # Control flow nodes
    "Append": (OperatorCategory.CONTROL, ControlStrategy.APPEND),
    "MergeAppend": (OperatorCategory.CONTROL, ControlStrategy.MERGE_APPEND),
    "Recursive Union": (OperatorCategory.CONTROL, ControlStrategy.RECURSIVE_UNION),
    "BitmapAnd": (OperatorCategory.CONTROL, ControlStrategy.BITMAP_AND),
    "BitmapOr": (OperatorCategory.CONTROL, ControlStrategy.BITMAP_OR),
    "Gather": (OperatorCategory.CONTROL, ControlStrategy.GATHER),
    "Gather Merge": (OperatorCategory.CONTROL, ControlStrategy.GATHER_MERGE),
    "ModifyTable": (OperatorCategory.CONTROL, ControlStrategy.MODIFY_TABLE),
}

# PostgreSQL join type mapping
_PG_JOIN_TYPE_MAP: dict[str, JoinType] = {
    "Inner": JoinType.INNER,
    "Left": JoinType.LEFT,
    "Right": JoinType.RIGHT,
    "Full": JoinType.FULL,
    "Semi": JoinType.SEMI,
    "Anti": JoinType.ANTI,
}

# PostgreSQL scan direction mapping
_PG_SCAN_DIR_MAP: dict[str, ScanDirection] = {
    "Forward": ScanDirection.FORWARD,
    "Backward": ScanDirection.BACKWARD,
    "NoMovement": ScanDirection.UNORDERED,
}


# =============================================================================
# PostgreSQL Adapter
# =============================================================================


class PostgreSQLAdapter:
    """
    Converts PostgreSQL EXPLAIN (FORMAT JSON) to IR.

    Handles both raw dict input and already-parsed PlanNode objects.
    """

    @property
    def engine(self) -> EngineType:
        return EngineType.POSTGRESQL

    def can_handle(self, raw_plan: dict[str, Any]) -> bool:
        """Check if this looks like PostgreSQL EXPLAIN output."""
        if "Plan" not in raw_plan:
            return False
        plan = raw_plan.get("Plan", {})
        return isinstance(plan, dict) and "Node Type" in plan

    def convert(self, raw_plan: dict[str, Any]) -> IRPlan:
        """
        Convert PostgreSQL EXPLAIN JSON to IR.

        Args:
            raw_plan: Parsed PostgreSQL EXPLAIN JSON dict.
                      Expected format: {"Plan": {...}, "Planning Time": ..., ...}

        Returns:
            IRPlan with full plan tree in IR form
        """
        plan_data = raw_plan.get("Plan")
        if not isinstance(plan_data, dict):
            raise ValueError("PostgreSQL EXPLAIN must contain a 'Plan' object")

        root = self._convert_node(plan_data)

        return IRPlan(
            root=root,
            engine=EngineType.POSTGRESQL,
            planning_time_ms=raw_plan.get("Planning Time"),
            execution_time_ms=raw_plan.get("Execution Time"),
            raw_plan=raw_plan,
        )

    def convert_plan_node(self, plan_node: Any) -> IRNode:
        """
        Convert an existing PlanNode object to IRNode.

        This enables gradual migration: existing code can continue
        using PlanNode while new code works with IRNode.

        Args:
            plan_node: A querysense.parser.models.PlanNode instance

        Returns:
            IRNode equivalent
        """
        return self._convert_plan_node_obj(plan_node)

    # =========================================================================
    # Internal Conversion
    # =========================================================================

    def _convert_node(self, data: dict[str, Any]) -> IRNode:
        """Convert a raw plan node dict to IRNode."""
        node_type = data.get("Node Type", "Unknown")

        # Map operator
        operator = self._map_operator(node_type, data)

        # Extract conditions
        conditions = self._extract_conditions(data)

        # Extract sort info
        sort_info = self._extract_sort_info(data, operator)

        # Extract hash info
        hash_info = self._extract_hash_info(data)

        # Extract parallel info
        parallel_info = self._extract_parallel_info(data)

        # Extract buffer stats
        buffers = self._extract_buffers(data)

        # Convert children recursively
        children = tuple(
            self._convert_node(child)
            for child in data.get("Plans", [])
            if isinstance(child, dict)
        )

        # Map join type
        raw_join_type = data.get("Join Type", "")
        join_type = _PG_JOIN_TYPE_MAP.get(raw_join_type, JoinType.UNKNOWN)

        # Map scan direction
        raw_scan_dir = data.get("Scan Direction", "")
        scan_direction = _PG_SCAN_DIR_MAP.get(raw_scan_dir, ScanDirection.FORWARD)

        # Collect engine-specific fields not captured in IR
        engine_specific = self._collect_extras(data)

        return IRNode(
            operator=operator,
            estimated_rows=data.get("Plan Rows", 0),
            estimated_cost=data.get("Total Cost", 0.0),
            estimated_startup_cost=data.get("Startup Cost", 0.0),
            estimated_width=data.get("Plan Width", 0),
            actual_rows=data.get("Actual Rows"),
            actual_time_ms=data.get("Actual Total Time"),
            actual_startup_time_ms=data.get("Actual Startup Time"),
            actual_loops=data.get("Actual Loops"),
            relation=data.get("Relation Name"),
            schema=data.get("Schema"),
            alias=data.get("Alias"),
            index_name=data.get("Index Name"),
            scan_direction=scan_direction,
            join_type=join_type,
            conditions=tuple(conditions),
            sort_info=sort_info,
            hash_info=hash_info,
            parallel_info=parallel_info,
            buffers=buffers,
            children=children,
            engine=EngineType.POSTGRESQL,
            engine_specific=engine_specific,
            source_node_type=node_type,
        )

    def _convert_plan_node_obj(self, node: Any) -> IRNode:
        """Convert a PlanNode object to IRNode."""
        node_type: str = node.node_type
        operator = self._map_operator(node_type, {})

        # Extract conditions from PlanNode fields
        conditions: list[Condition] = []
        if node.filter:
            conditions.append(
                Condition(node.filter, ConditionKind.FILTER)
            )
        if node.index_cond:
            conditions.append(
                Condition(node.index_cond, ConditionKind.INDEX_CONDITION)
            )
        if node.recheck_cond:
            conditions.append(
                Condition(node.recheck_cond, ConditionKind.RECHECK)
            )
        if node.join_filter:
            conditions.append(
                Condition(node.join_filter, ConditionKind.JOIN_CONDITION)
            )
        if node.hash_cond:
            conditions.append(
                Condition(node.hash_cond, ConditionKind.JOIN_CONDITION)
            )
        if node.merge_cond:
            conditions.append(
                Condition(node.merge_cond, ConditionKind.JOIN_CONDITION)
            )

        # Sort info
        sort_info: SortInfo | None = None
        if node.node_type in ("Sort", "Incremental Sort"):
            sort_method = (node.sort_method or "").lower()
            if "external merge" in sort_method:
                strategy = SortStrategy.EXTERNAL_MERGE
            elif "external" in sort_method:
                strategy = SortStrategy.EXTERNAL
            elif sort_method:
                strategy = SortStrategy.IN_MEMORY
            else:
                strategy = SortStrategy.UNKNOWN

            sort_info = SortInfo(
                keys=tuple(node.sort_key or []),
                method=node.sort_method,
                space_used_kb=node.sort_space_used or 0,
                space_type=node.sort_space_type,
                strategy=strategy,
            )

        # Hash info
        hash_info: HashInfo | None = None
        if node.hash_batches is not None:
            hash_info = HashInfo(
                buckets=node.hash_buckets or 0,
                batches=node.hash_batches,
                peak_memory_kb=node.peak_memory_usage or 0,
            )

        # Parallel info
        parallel_info: ParallelInfo | None = None
        if node.parallel_aware is not None or node.workers_planned is not None:
            parallel_info = ParallelInfo(
                aware=node.parallel_aware or False,
                workers_planned=node.workers_planned or 0,
                workers_launched=node.workers_launched or 0,
            )

        # Buffer stats
        buffers: BufferStats | None = None
        if node.shared_hit_blocks is not None or node.shared_read_blocks is not None:
            buffers = BufferStats(
                shared_hit_blocks=node.shared_hit_blocks or 0,
                shared_read_blocks=node.shared_read_blocks or 0,
                shared_dirtied_blocks=node.shared_dirtied_blocks or 0,
                shared_written_blocks=node.shared_written_blocks or 0,
                io_read_time_ms=node.io_read_time or 0.0,
                io_write_time_ms=node.io_write_time or 0.0,
            )

        # Join type
        raw_join_type = node.join_type or ""
        join_type = _PG_JOIN_TYPE_MAP.get(raw_join_type, JoinType.UNKNOWN)

        # Scan direction
        raw_scan_dir = node.scan_direction or ""
        scan_direction = _PG_SCAN_DIR_MAP.get(raw_scan_dir, ScanDirection.FORWARD)

        # Recurse into children
        children = tuple(
            self._convert_plan_node_obj(child)
            for child in (node.plans or [])
        )

        return IRNode(
            operator=operator,
            estimated_rows=node.plan_rows or 0,
            estimated_cost=node.total_cost or 0.0,
            estimated_startup_cost=node.startup_cost or 0.0,
            estimated_width=node.plan_width or 0,
            actual_rows=node.actual_rows,
            actual_time_ms=node.actual_total_time,
            actual_startup_time_ms=node.actual_startup_time,
            actual_loops=node.actual_loops,
            relation=node.relation_name,
            schema=node.schema_name,
            alias=node.alias,
            index_name=node.index_name,
            scan_direction=scan_direction,
            join_type=join_type,
            conditions=tuple(conditions),
            sort_info=sort_info,
            hash_info=hash_info,
            parallel_info=parallel_info,
            buffers=buffers,
            children=children,
            engine=EngineType.POSTGRESQL,
            engine_specific={},
            source_node_type=node_type,
        )

    # =========================================================================
    # Operator Mapping
    # =========================================================================

    def _map_operator(
        self, node_type: str, data: dict[str, Any]
    ) -> Operator:
        """Map PostgreSQL node type string to Operator."""
        mapping = _PG_NODE_MAP.get(node_type)

        if mapping is None:
            # Unknown node type — graceful fallback
            return Operator(
                category=OperatorCategory.UNKNOWN,
                original=node_type,
                engine="postgresql",
            )

        category, strategy = mapping

        # Refine sort strategy from sort_method
        if category == OperatorCategory.SORT and isinstance(strategy, SortStrategy):
            sort_method = (data.get("Sort Method", "") or "").lower()
            if "external merge" in sort_method:
                strategy = SortStrategy.EXTERNAL_MERGE
            elif "external" in sort_method:
                strategy = SortStrategy.EXTERNAL
            elif sort_method:
                strategy = SortStrategy.IN_MEMORY

        # Build operator with the appropriate strategy field
        kwargs: dict[str, Any] = {
            "original": node_type,
            "engine": "postgresql",
        }

        if category == OperatorCategory.SCAN:
            kwargs["scan"] = strategy
        elif category == OperatorCategory.JOIN:
            kwargs["join"] = strategy
        elif category == OperatorCategory.AGGREGATE:
            kwargs["aggregate"] = strategy
        elif category == OperatorCategory.SORT:
            kwargs["sort"] = strategy
        elif category == OperatorCategory.MATERIALIZE:
            kwargs["materialize"] = strategy
        elif category == OperatorCategory.CONTROL:
            kwargs["control"] = strategy

        return Operator(category=category, **kwargs)

    # =========================================================================
    # Condition Extraction
    # =========================================================================

    def _extract_conditions(self, data: dict[str, Any]) -> list[Condition]:
        """Extract all conditions from a plan node."""
        conditions: list[Condition] = []

        if data.get("Filter"):
            conditions.append(
                Condition(data["Filter"], ConditionKind.FILTER)
            )
        if data.get("Index Cond"):
            conditions.append(
                Condition(data["Index Cond"], ConditionKind.INDEX_CONDITION)
            )
        if data.get("Recheck Cond"):
            conditions.append(
                Condition(data["Recheck Cond"], ConditionKind.RECHECK)
            )
        if data.get("Join Filter"):
            conditions.append(
                Condition(data["Join Filter"], ConditionKind.JOIN_CONDITION)
            )
        if data.get("Hash Cond"):
            conditions.append(
                Condition(data["Hash Cond"], ConditionKind.JOIN_CONDITION)
            )
        if data.get("Merge Cond"):
            conditions.append(
                Condition(data["Merge Cond"], ConditionKind.JOIN_CONDITION)
            )

        return conditions

    # =========================================================================
    # Metadata Extraction
    # =========================================================================

    def _extract_sort_info(
        self, data: dict[str, Any], operator: Operator
    ) -> SortInfo | None:
        """Extract sort metadata from a Sort node."""
        if operator.category != OperatorCategory.SORT:
            return None

        sort_method = (data.get("Sort Method", "") or "").lower()
        if "external merge" in sort_method:
            strategy = SortStrategy.EXTERNAL_MERGE
        elif "external" in sort_method:
            strategy = SortStrategy.EXTERNAL
        elif sort_method:
            strategy = SortStrategy.IN_MEMORY
        else:
            strategy = SortStrategy.UNKNOWN

        return SortInfo(
            keys=tuple(data.get("Sort Key", [])),
            method=data.get("Sort Method"),
            space_used_kb=data.get("Sort Space Used", 0),
            space_type=data.get("Sort Space Type"),
            strategy=strategy,
        )

    def _extract_hash_info(self, data: dict[str, Any]) -> HashInfo | None:
        """Extract hash metadata."""
        if data.get("Hash Batches") is None and data.get("Hash Buckets") is None:
            return None
        return HashInfo(
            buckets=data.get("Hash Buckets", 0),
            batches=data.get("Hash Batches", 1),
            peak_memory_kb=data.get("Peak Memory Usage", 0),
        )

    def _extract_parallel_info(self, data: dict[str, Any]) -> ParallelInfo | None:
        """Extract parallel execution metadata."""
        if data.get("Parallel Aware") is None and data.get("Workers Planned") is None:
            return None
        return ParallelInfo(
            aware=data.get("Parallel Aware", False),
            workers_planned=data.get("Workers Planned", 0),
            workers_launched=data.get("Workers Launched", 0),
        )

    def _extract_buffers(self, data: dict[str, Any]) -> BufferStats | None:
        """Extract buffer/IO statistics."""
        has_buffers = any(
            data.get(key) is not None
            for key in (
                "Shared Hit Blocks",
                "Shared Read Blocks",
                "I/O Read Time",
            )
        )
        if not has_buffers:
            return None

        return BufferStats(
            shared_hit_blocks=data.get("Shared Hit Blocks", 0),
            shared_read_blocks=data.get("Shared Read Blocks", 0),
            shared_dirtied_blocks=data.get("Shared Dirtied Blocks", 0),
            shared_written_blocks=data.get("Shared Written Blocks", 0),
            io_read_time_ms=data.get("I/O Read Time", 0.0),
            io_write_time_ms=data.get("I/O Write Time", 0.0),
        )

    def _collect_extras(self, data: dict[str, Any]) -> dict[str, Any]:
        """Collect engine-specific fields not captured in IR."""
        # Fields already mapped to IR
        _MAPPED_KEYS = {
            "Node Type",
            "Plan Rows",
            "Plan Width",
            "Total Cost",
            "Startup Cost",
            "Actual Rows",
            "Actual Total Time",
            "Actual Startup Time",
            "Actual Loops",
            "Relation Name",
            "Schema",
            "Alias",
            "Index Name",
            "Scan Direction",
            "Join Type",
            "Filter",
            "Index Cond",
            "Recheck Cond",
            "Join Filter",
            "Hash Cond",
            "Merge Cond",
            "Sort Key",
            "Sort Method",
            "Sort Space Used",
            "Sort Space Type",
            "Hash Buckets",
            "Hash Batches",
            "Peak Memory Usage",
            "Parallel Aware",
            "Workers Planned",
            "Workers Launched",
            "Shared Hit Blocks",
            "Shared Read Blocks",
            "Shared Dirtied Blocks",
            "Shared Written Blocks",
            "I/O Read Time",
            "I/O Write Time",
            "Plans",
        }

        return {
            key: value
            for key, value in data.items()
            if key not in _MAPPED_KEYS
        }
