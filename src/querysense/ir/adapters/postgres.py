"""
PostgreSQL Adapter: EXPLAIN (FORMAT JSON) -> IR Plan.

Parses the JSON output of ``EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)``
and maps PostgreSQL plan nodes into the portable IR.

Node type mapping follows the PostgreSQL documentation's plan node
taxonomy.  Unknown node types are mapped to ``IROperator.OTHER`` with
the original type preserved in annotations.
"""

from __future__ import annotations

from typing import Any

from querysense.ir.adapters.base import PlanAdapter
from querysense.ir.annotations import (
    IRAnnotations,
    PostgresAnnotations,
)
from querysense.ir.operators import IROperator
from querysense.ir.plan import IRNode, IRPlan
from querysense.ir.properties import (
    CardinalitySignals,
    CostSignals,
    IRProperties,
    MemorySignals,
    ParallelismSignals,
    Predicates,
    TimeSignals,
)

# ── Node type mapping ────────────────────────────────────────────────

_PG_NODE_MAP: dict[str, tuple[IROperator, str]] = {
    # Scans
    "Seq Scan": (IROperator.SCAN_SEQ, "SeqScan"),
    "Parallel Seq Scan": (IROperator.SCAN_SEQ, "ParallelSeqScan"),
    "Index Scan": (IROperator.SCAN_INDEX, "IndexScan"),
    "Index Only Scan": (IROperator.SCAN_INDEX_ONLY, "IndexOnlyScan"),
    "Bitmap Heap Scan": (IROperator.SCAN_BITMAP, "BitmapHeapScan"),
    "Bitmap Index Scan": (IROperator.SCAN_BITMAP, "BitmapIndexScan"),
    "Tid Scan": (IROperator.SCAN_TID, "TidScan"),
    "Tid Range Scan": (IROperator.SCAN_TID, "TidRangeScan"),
    "Function Scan": (IROperator.SCAN_FUNCTION, "FunctionScan"),
    "Table Function Scan": (IROperator.SCAN_FUNCTION, "TableFunctionScan"),
    "Subquery Scan": (IROperator.SCAN_SUBQUERY, "SubqueryScan"),
    "CTE Scan": (IROperator.SCAN_CTE, "CTEScan"),
    "Values Scan": (IROperator.SCAN_VALUES, "ValuesScan"),
    "Foreign Scan": (IROperator.SCAN_FOREIGN, "ForeignScan"),
    "WorkTable Scan": (IROperator.SCAN_WORKTABLE, "WorkTableScan"),
    "Named Tuplestore Scan": (IROperator.SCAN_FUNCTION, "NamedTuplestoreScan"),
    "Sample Scan": (IROperator.SCAN_SEQ, "SampleScan"),
    # Joins
    "Nested Loop": (IROperator.JOIN_NESTED_LOOP, "NestedLoop"),
    "Hash Join": (IROperator.JOIN_HASH, "HashJoin"),
    "Merge Join": (IROperator.JOIN_MERGE, "MergeJoin"),
    # Aggregates
    "Aggregate": (IROperator.AGGREGATE_PLAIN, "Aggregate"),
    "GroupAggregate": (IROperator.AGGREGATE_SORT, "GroupAggregate"),
    "HashAggregate": (IROperator.AGGREGATE_HASH, "HashAggregate"),
    "Partial Aggregate": (IROperator.AGGREGATE_PARTIAL, "PartialAggregate"),
    "Finalize Aggregate": (IROperator.AGGREGATE_FINAL, "FinalizeAggregate"),
    "Mixed Aggregate": (IROperator.AGGREGATE_HASH, "MixedAggregate"),
    # Sort
    "Sort": (IROperator.SORT, "Sort"),
    "Incremental Sort": (IROperator.SORT_TOP_N, "IncrementalSort"),
    # Materialize
    "Materialize": (IROperator.MATERIALIZE, "Materialize"),
    "Memoize": (IROperator.MATERIALIZE, "Memoize"),
    "Hash": (IROperator.MATERIALIZE_HASH, "Hash"),
    # Set ops
    "Append": (IROperator.SETOP_APPEND, "Append"),
    "MergeAppend": (IROperator.SETOP_APPEND, "MergeAppend"),
    "SetOp": (IROperator.SETOP_UNION, "SetOp"),
    "Recursive Union": (IROperator.SETOP_UNION, "RecursiveUnion"),
    # Limit
    "Limit": (IROperator.LIMIT, "Limit"),
    # Compute
    "Result": (IROperator.RESULT, "Result"),
    "ProjectSet": (IROperator.COMPUTE, "ProjectSet"),
    "WindowAgg": (IROperator.WINDOW, "WindowAgg"),
    # Parallelism
    "Gather": (IROperator.GATHER, "Gather"),
    "Gather Merge": (IROperator.GATHER_MERGE, "GatherMerge"),
    # DML
    "ModifyTable": (IROperator.MODIFY, "ModifyTable"),
    "LockRows": (IROperator.LOCK_ROWS, "LockRows"),
    # Unique / dedup
    "Unique": (IROperator.COMPUTE, "Unique"),
    # BitmapAnd / BitmapOr (bitmap combine nodes)
    "BitmapAnd": (IROperator.SCAN_BITMAP, "BitmapAnd"),
    "BitmapOr": (IROperator.SCAN_BITMAP, "BitmapOr"),
}


class PostgresAdapter(PlanAdapter):
    """Translate PostgreSQL EXPLAIN JSON to IR."""

    engine = "postgres"

    def can_handle(self, raw_plan: Any) -> bool:
        """Detect PostgreSQL EXPLAIN JSON format."""
        if isinstance(raw_plan, list) and len(raw_plan) > 0:
            item = raw_plan[0]
            if isinstance(item, dict) and "Plan" in item:
                return True
        if isinstance(raw_plan, dict) and "Plan" in raw_plan:
            return True
        return False

    def translate(self, raw_plan: Any, **kwargs: Any) -> IRPlan:
        """
        Translate PostgreSQL EXPLAIN JSON -> IRPlan.

        Args:
            raw_plan: list[dict] or dict from EXPLAIN (FORMAT JSON).
            **kwargs: Optional ``engine_version``, ``sql``.
        """
        # Normalize: EXPLAIN JSON wraps in a list
        if isinstance(raw_plan, list):
            top = raw_plan[0] if raw_plan else {}
        else:
            top = raw_plan

        plan_data = top.get("Plan", top)
        planning_time = top.get("Planning Time")
        execution_time = top.get("Execution Time")

        counter = _Counter()
        root = self._translate_node(plan_data, counter, depth=0, path="Root")

        ir_plan = IRPlan(
            engine="postgres",
            engine_version=kwargs.get("engine_version", ""),
            root=root,
            planning_time_ms=planning_time,
            execution_time_ms=execution_time,
            query_text=kwargs.get("sql"),
            raw_plan=top,
        )

        # Post-processing
        ir_plan.compute_cost_shares()
        ir_plan.compute_self_times()
        ir_plan.derive_and_set_capabilities()

        return ir_plan

    def _translate_node(
        self,
        node: dict[str, Any],
        counter: _Counter,
        depth: int,
        path: str,
    ) -> IRNode:
        """Recursively translate a PostgreSQL plan node."""
        node_type = node.get("Node Type", "Unknown")
        op, algo = _PG_NODE_MAP.get(node_type, (IROperator.OTHER, node_type))

        node_id = f"n{counter.next()}"

        # ── Properties (Layer B) ──
        cardinality = CardinalitySignals(
            estimated_rows=node.get("Plan Rows"),
            actual_rows=node.get("Actual Rows"),
            actual_loops=node.get("Actual Loops"),
            plan_width=node.get("Plan Width"),
        )

        cost = CostSignals(
            startup_cost=node.get("Startup Cost"),
            total_cost=node.get("Total Cost"),
        )

        time = TimeSignals(
            startup_time_ms=node.get("Actual Startup Time"),
            total_time_ms=node.get("Actual Total Time"),
        )

        memory = MemorySignals(
            shared_hit_blocks=node.get("Shared Hit Blocks"),
            shared_read_blocks=node.get("Shared Read Blocks"),
            shared_written_blocks=node.get("Shared Written Blocks"),
            local_hit_blocks=node.get("Local Hit Blocks"),
            local_read_blocks=node.get("Local Read Blocks"),
            temp_read_blocks=node.get("Temp Read Blocks"),
            temp_written_blocks=node.get("Temp Written Blocks"),
            io_read_time_ms=node.get("I/O Read Time"),
            io_write_time_ms=node.get("I/O Write Time"),
            sort_space_used_kb=node.get("Sort Space Used"),
            sort_space_type=node.get("Sort Space Type"),
            hash_buckets=node.get("Hash Buckets"),
            hash_batches=node.get("Hash Batches"),
            peak_memory_kb=node.get("Peak Memory Usage"),
        )

        workers_planned = node.get("Workers Planned")
        workers_launched = node.get("Workers Launched")
        parallelism = ParallelismSignals(
            planned_workers=workers_planned,
            launched_workers=workers_launched,
            is_parallel=bool(
                workers_planned
                or node_type.startswith("Parallel")
                or node_type in ("Gather", "Gather Merge")
            ),
        )

        predicates = Predicates(
            join_condition=node.get("Join Filter"),
            filter_condition=node.get("Filter"),
            index_condition=node.get("Index Cond"),
            recheck_condition=node.get("Recheck Cond"),
            hash_condition=node.get("Hash Cond"),
            merge_condition=node.get("Merge Cond"),
            sort_keys=tuple(node.get("Sort Key", [])),
            output_columns=tuple(node.get("Output", [])),
            rows_removed_by_filter=node.get("Rows Removed by Filter"),
            rows_removed_by_join_filter=node.get("Rows Removed by Join Filter"),
        )

        properties = IRProperties(
            cardinality=cardinality,
            cost=cost,
            time=time,
            memory=memory,
            parallelism=parallelism,
            predicates=predicates,
            relation_name=node.get("Relation Name"),
            schema_name=node.get("Schema"),
            alias=node.get("Alias"),
            index_name=node.get("Index Name"),
            join_type=node.get("Join Type"),
            scan_direction=node.get("Scan Direction"),
        )

        # ── Annotations (Layer C) ──
        pg_ann = PostgresAnnotations(
            heap_fetches=node.get("Heap Fetches"),
            workers_planned=workers_planned,
            workers_launched=workers_launched,
            cte_name=node.get("CTE Name"),
            is_recursive=node.get("Recursive", False),
            original_node_type=node_type,
            partitions_scanned=node.get("Subplans Removed"),
            extras={
                k: v
                for k, v in node.items()
                if k
                not in _PG_KNOWN_KEYS
                and not isinstance(v, (list, dict))
            },
        )

        annotations = IRAnnotations(postgres=pg_ann)

        # ── Children ──
        children = []
        for child_data in node.get("Plans", []):
            child_path = f"{path} -> {child_data.get('Node Type', '?')}"
            children.append(
                self._translate_node(child_data, counter, depth + 1, child_path)
            )

        return IRNode(
            id=node_id,
            operator=op,
            algorithm=algo,
            properties=properties,
            annotations=annotations,
            children=children,
            depth=depth,
            path=path,
        )


class _Counter:
    """Simple counter for generating node IDs."""

    def __init__(self) -> None:
        self._n = 0

    def next(self) -> int:
        n = self._n
        self._n += 1
        return n


# Keys we explicitly extract; everything else goes to extras
_PG_KNOWN_KEYS = {
    "Node Type", "Plan Rows", "Plan Width",
    "Startup Cost", "Total Cost",
    "Actual Startup Time", "Actual Total Time",
    "Actual Rows", "Actual Loops",
    "Shared Hit Blocks", "Shared Read Blocks", "Shared Written Blocks",
    "Local Hit Blocks", "Local Read Blocks",
    "Temp Read Blocks", "Temp Written Blocks",
    "I/O Read Time", "I/O Write Time",
    "Sort Space Used", "Sort Space Type",
    "Hash Buckets", "Hash Batches", "Peak Memory Usage",
    "Workers Planned", "Workers Launched",
    "Filter", "Join Filter", "Index Cond", "Recheck Cond",
    "Hash Cond", "Merge Cond",
    "Sort Key", "Output",
    "Rows Removed by Filter", "Rows Removed by Join Filter",
    "Relation Name", "Schema", "Alias", "Index Name",
    "Join Type", "Scan Direction",
    "CTE Name", "Recursive", "Subplans Removed",
    "Plans", "Heap Fetches",
    "Parent Relationship", "Subplan Name",
}
