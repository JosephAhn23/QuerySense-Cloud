"""
Bridge between the new Universal IR and the existing analyzer pipeline.

Provides:
- Conversion from legacy IR (node.py) to universal IR (plan.py)
- Unified analysis entry point that runs both legacy rules and causal analysis
- Integration with temporal intelligence and fix verification
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from querysense.ir.operators import IROperator
from querysense.ir.plan import IRNode as UniversalIRNode, IRPlan as UniversalIRPlan
from querysense.ir.properties import (
    CardinalitySignals,
    CostSignals,
    IRProperties,
    MemorySignals,
    ParallelismSignals,
    Predicates,
    TimeSignals,
)
from querysense.ir.annotations import (
    IRAnnotations,
    PostgresAnnotations,
    MySQLAnnotations,
)

if TYPE_CHECKING:
    from querysense.ir.node import IRNode as LegacyIRNode, IRPlan as LegacyIRPlan

logger = logging.getLogger(__name__)

# ── Legacy-to-Universal operator mapping ──────────────────────────────

_LEGACY_OP_MAP: dict[tuple[str, str | None], IROperator] = {
    # Scans
    ("scan", "full_table"): IROperator.SCAN_SEQ,
    ("scan", "sequential"): IROperator.SCAN_SEQ,
    ("scan", "index"): IROperator.SCAN_INDEX,
    ("scan", "index_scan"): IROperator.SCAN_INDEX,
    ("scan", "index_only"): IROperator.SCAN_INDEX_ONLY,
    ("scan", "bitmap"): IROperator.SCAN_BITMAP,
    ("scan", "bitmap_scan"): IROperator.SCAN_BITMAP,
    ("scan", "bitmap_index"): IROperator.SCAN_BITMAP,
    ("scan", "bitmap_heap"): IROperator.SCAN_BITMAP,
    ("scan", "tid"): IROperator.SCAN_TID,
    ("scan", "tid_scan"): IROperator.SCAN_TID,
    ("scan", "function"): IROperator.SCAN_FUNCTION,
    ("scan", "subquery"): IROperator.SCAN_SUBQUERY,
    ("scan", "values"): IROperator.SCAN_VALUES,
    ("scan", "cte"): IROperator.SCAN_CTE,
    ("scan", "work_table"): IROperator.SCAN_WORKTABLE,
    ("scan", "foreign"): IROperator.SCAN_FOREIGN,
    ("scan", "custom"): IROperator.SCAN_SEQ,
    ("scan", "unknown"): IROperator.SCAN_SEQ,
    # Joins
    ("join", "nested_loop"): IROperator.JOIN_NESTED_LOOP,
    ("join", "hash"): IROperator.JOIN_HASH,
    ("join", "hash_join"): IROperator.JOIN_HASH,
    ("join", "merge"): IROperator.JOIN_MERGE,
    ("join", "merge_join"): IROperator.JOIN_MERGE,
    ("join", "unknown"): IROperator.JOIN_NESTED_LOOP,
    # Aggregates
    ("aggregate", "hash"): IROperator.AGGREGATE_HASH,
    ("aggregate", "sort"): IROperator.AGGREGATE_SORT,
    ("aggregate", "mixed"): IROperator.AGGREGATE_HASH,
    ("aggregate", "plain"): IROperator.AGGREGATE_PLAIN,
    ("aggregate", "partial"): IROperator.AGGREGATE_PARTIAL,
    ("aggregate", "final"): IROperator.AGGREGATE_FINAL,
    # Sort
    ("sort", "in_memory"): IROperator.SORT,
    ("sort", "external"): IROperator.SORT_EXTERNAL,
    ("sort", "external_merge"): IROperator.SORT_EXTERNAL,
    ("sort", "top_n"): IROperator.SORT_TOP_N,
    ("sort", "incremental"): IROperator.SORT_TOP_N,
    ("sort", "unknown"): IROperator.SORT,
    # Materialize
    ("materialize", "materialize"): IROperator.MATERIALIZE,
    ("materialize", "hash_table"): IROperator.MATERIALIZE_HASH,
    ("materialize", "window"): IROperator.WINDOW,
    ("materialize", "lock_rows"): IROperator.LOCK_ROWS,
    ("materialize", "limit"): IROperator.LIMIT,
    ("materialize", "unique"): IROperator.COMPUTE,
    ("materialize", "setop"): IROperator.SETOP_UNION,
    ("materialize", "result"): IROperator.RESULT,
    ("materialize", "eager"): IROperator.MATERIALIZE,
    ("materialize", "lazy"): IROperator.MATERIALIZE,
    ("materialize", "cte"): IROperator.MATERIALIZE_CTE,
    ("materialize", "unknown"): IROperator.MATERIALIZE,
    # Control
    ("control", "append"): IROperator.SETOP_APPEND,
    ("control", "merge_append"): IROperator.SETOP_APPEND,
    ("control", "recursive_union"): IROperator.SETOP_UNION,
    ("control", "bitmap_and"): IROperator.SCAN_BITMAP,
    ("control", "bitmap_or"): IROperator.SCAN_BITMAP,
    ("control", "gather"): IROperator.GATHER,
    ("control", "gather_merge"): IROperator.GATHER_MERGE,
    ("control", "modify_table"): IROperator.MODIFY,
    ("control", "unknown"): IROperator.OTHER,
    # Other
    ("other", None): IROperator.OTHER,
    ("unknown", None): IROperator.OTHER,
}


def legacy_to_universal(legacy_plan: "LegacyIRPlan") -> UniversalIRPlan:
    """
    Convert a legacy IRPlan (from node.py) to a universal IRPlan (plan.py).

    This allows the causal engine, temporal intelligence, and fix
    verification to work with plans produced by the existing analyzer
    pipeline.
    """
    counter = _Counter()
    root = _convert_legacy_node(legacy_plan.root, counter, depth=0)

    engine_map = {
        "postgresql": "postgres",
        "mysql": "mysql",
        "sqlserver": "sqlserver",
        "oracle": "oracle",
    }

    plan = UniversalIRPlan(
        engine=engine_map.get(legacy_plan.engine.value, legacy_plan.engine.value),
        root=root,
        engine_version=legacy_plan.engine_version or "",
        planning_time_ms=legacy_plan.planning_time_ms,
        execution_time_ms=legacy_plan.execution_time_ms,
        raw_plan=legacy_plan.raw_plan if legacy_plan.raw_plan else None,
    )

    plan.compute_cost_shares()
    plan.compute_self_times()
    plan.derive_and_set_capabilities()

    return plan


def _convert_legacy_node(
    node: "LegacyIRNode",
    counter: "_Counter",
    depth: int,
) -> UniversalIRNode:
    """Recursively convert a legacy IRNode to universal IRNode."""
    # Map operator
    op_obj = node.operator
    category = op_obj.category
    strategy = (
        op_obj.scan or op_obj.join or op_obj.aggregate
        or op_obj.sort or op_obj.materialize or op_obj.control
    )
    strategy_val = strategy.value if hasattr(strategy, "value") else str(strategy) if strategy else None

    ir_op = _LEGACY_OP_MAP.get(
        (category, strategy_val),
        _LEGACY_OP_MAP.get((category, None), IROperator.OTHER),
    )

    node_id = f"n{counter.next()}"

    # Properties
    cardinality = CardinalitySignals(
        estimated_rows=float(node.estimated_rows) if node.estimated_rows else None,
        actual_rows=float(node.actual_rows) if node.actual_rows is not None else None,
        actual_loops=node.actual_loops,
        plan_width=node.estimated_width if node.estimated_width else None,
    )

    cost = CostSignals(
        startup_cost=node.estimated_startup_cost if node.estimated_startup_cost else None,
        total_cost=node.estimated_cost if node.estimated_cost else None,
    )

    time = TimeSignals(
        startup_time_ms=node.actual_startup_time_ms,
        total_time_ms=node.actual_time_ms,
    )

    # Memory
    buffers = node.buffers
    memory = MemorySignals(
        shared_hit_blocks=buffers.shared_hit_blocks if buffers else None,
        shared_read_blocks=buffers.shared_read_blocks if buffers else None,
        shared_written_blocks=buffers.shared_written_blocks if buffers else None,
        io_read_time_ms=buffers.io_read_time_ms if buffers else None,
        io_write_time_ms=buffers.io_write_time_ms if buffers else None,
        sort_space_used_kb=node.sort_info.space_used_kb if node.sort_info else None,
        sort_space_type=node.sort_info.space_type if node.sort_info else None,
        hash_buckets=node.hash_info.buckets if node.hash_info else None,
        hash_batches=node.hash_info.batches if node.hash_info else None,
        peak_memory_kb=node.hash_info.peak_memory_kb if node.hash_info else None,
    )

    # Parallelism
    par = node.parallel_info
    parallelism = ParallelismSignals(
        planned_workers=par.workers_planned if par else None,
        launched_workers=par.workers_launched if par else None,
        is_parallel=bool(par and par.aware),
    )

    # Predicates
    from querysense.ir.node import ConditionKind
    filter_cond = " AND ".join(
        c.expression for c in node.conditions if c.kind == ConditionKind.FILTER
    ) or None
    index_cond = " AND ".join(
        c.expression for c in node.conditions if c.kind == ConditionKind.INDEX_CONDITION
    ) or None
    join_cond = " AND ".join(
        c.expression for c in node.conditions if c.kind == ConditionKind.JOIN_CONDITION
    ) or None
    recheck_cond = " AND ".join(
        c.expression for c in node.conditions if c.kind == ConditionKind.RECHECK
    ) or None
    sort_keys = tuple(node.sort_info.keys) if node.sort_info else ()

    predicates = Predicates(
        filter_condition=filter_cond,
        index_condition=index_cond,
        join_condition=join_cond,
        recheck_condition=recheck_cond,
        sort_keys=sort_keys,
    )

    properties = IRProperties(
        cardinality=cardinality,
        cost=cost,
        time=time,
        memory=memory,
        parallelism=parallelism,
        predicates=predicates,
        relation_name=node.relation,
        schema_name=node.schema,
        alias=node.alias,
        index_name=node.index_name,
        join_type=node.join_type.value if hasattr(node.join_type, "value") else str(node.join_type),
        scan_direction=node.scan_direction.value if hasattr(node.scan_direction, "value") else None,
    )

    # Annotations
    pg_ann = PostgresAnnotations(
        original_node_type=node.source_node_type,
        extras=node.engine_specific,
    )
    annotations = IRAnnotations(postgres=pg_ann)

    # Children
    children = [
        _convert_legacy_node(child, counter, depth + 1)
        for child in node.children
    ]

    return UniversalIRNode(
        id=node_id,
        operator=ir_op,
        algorithm=node.source_node_type or ir_op.value,
        properties=properties,
        annotations=annotations,
        children=children,
        depth=depth,
        path="",
    )


class _Counter:
    def __init__(self) -> None:
        self._n = 0

    def next(self) -> int:
        n = self._n
        self._n += 1
        return n
