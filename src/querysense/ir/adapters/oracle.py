"""
Oracle Adapter: V$SQL_PLAN / DBMS_XPLAN -> IR Plan.

Converts Oracle execution plan data (JSON export from V$SQL_PLAN
or DBMS_XPLAN output parsed to JSON) into the portable IR.

Oracle plans have a flat list of operations with parent_id references,
which this adapter reconstructs into a tree.  The ~25 operator
categories in the universal taxonomy cover Oracle's row source types.

Operator mapping follows the Oracle Database SQL Tuning Guide's
row source operation taxonomy.
"""

from __future__ import annotations

from typing import Any

from querysense.ir.adapters.base import PlanAdapter
from querysense.ir.annotations import IRAnnotations, OracleAnnotations
from querysense.ir.operators import IROperator
from querysense.ir.plan import IRNode, IRPlan
from querysense.ir.properties import (
    CardinalitySignals,
    CostSignals,
    IRProperties,
    ParallelismSignals,
    Predicates,
)


# ── Operator mapping ────────────────────────────────────────────────────

_ORA_OP_MAP: dict[str, tuple[IROperator, str]] = {
    # Scans
    "TABLE ACCESS FULL": (IROperator.SCAN_SEQ, "TableAccessFull"),
    "TABLE ACCESS BY INDEX ROWID": (IROperator.SCAN_INDEX, "TableAccessByIndexRowid"),
    "TABLE ACCESS BY INDEX ROWID BATCHED": (IROperator.SCAN_INDEX, "TableAccessByIndexRowidBatched"),
    "TABLE ACCESS BY USER ROWID": (IROperator.SCAN_TID, "TableAccessByUserRowid"),
    "INDEX RANGE SCAN": (IROperator.SCAN_INDEX, "IndexRangeScan"),
    "INDEX UNIQUE SCAN": (IROperator.SCAN_INDEX, "IndexUniqueScan"),
    "INDEX FULL SCAN": (IROperator.SCAN_INDEX, "IndexFullScan"),
    "INDEX FAST FULL SCAN": (IROperator.SCAN_INDEX_ONLY, "IndexFastFullScan"),
    "INDEX SKIP SCAN": (IROperator.SCAN_INDEX, "IndexSkipScan"),
    "BITMAP INDEX SINGLE VALUE": (IROperator.SCAN_BITMAP, "BitmapIndexSingleValue"),
    "BITMAP INDEX RANGE SCAN": (IROperator.SCAN_BITMAP, "BitmapIndexRangeScan"),
    "BITMAP INDEX FULL SCAN": (IROperator.SCAN_BITMAP, "BitmapIndexFullScan"),
    "BITMAP CONVERSION TO ROWIDS": (IROperator.SCAN_BITMAP, "BitmapConversion"),
    "BITMAP AND": (IROperator.SCAN_BITMAP, "BitmapAnd"),
    "BITMAP OR": (IROperator.SCAN_BITMAP, "BitmapOr"),
    "MAT_VIEW ACCESS FULL": (IROperator.SCAN_SEQ, "MatViewAccessFull"),
    # Joins
    "NESTED LOOPS": (IROperator.JOIN_NESTED_LOOP, "NestedLoops"),
    "HASH JOIN": (IROperator.JOIN_HASH, "HashJoin"),
    "MERGE JOIN": (IROperator.JOIN_MERGE, "MergeJoin"),
    "MERGE JOIN CARTESIAN": (IROperator.JOIN_MERGE, "MergeJoinCartesian"),
    "HASH JOIN OUTER": (IROperator.JOIN_HASH, "HashJoinOuter"),
    "HASH JOIN ANTI": (IROperator.JOIN_HASH, "HashJoinAnti"),
    "HASH JOIN SEMI": (IROperator.JOIN_HASH, "HashJoinSemi"),
    "HASH JOIN RIGHT OUTER": (IROperator.JOIN_HASH, "HashJoinRightOuter"),
    "NESTED LOOPS OUTER": (IROperator.JOIN_NESTED_LOOP, "NestedLoopsOuter"),
    "NESTED LOOPS ANTI": (IROperator.JOIN_NESTED_LOOP, "NestedLoopsAnti"),
    "NESTED LOOPS SEMI": (IROperator.JOIN_NESTED_LOOP, "NestedLoopsSemi"),
    # Aggregates
    "HASH GROUP BY": (IROperator.AGGREGATE_HASH, "HashGroupBy"),
    "HASH UNIQUE": (IROperator.AGGREGATE_HASH, "HashUnique"),
    "SORT GROUP BY": (IROperator.AGGREGATE_SORT, "SortGroupBy"),
    "SORT GROUP BY NOSORT": (IROperator.AGGREGATE_SORT, "SortGroupByNosort"),
    "SORT UNIQUE": (IROperator.AGGREGATE_SORT, "SortUnique"),
    "SORT AGGREGATE": (IROperator.AGGREGATE_PLAIN, "SortAggregate"),
    # Sorts
    "SORT ORDER BY": (IROperator.SORT, "SortOrderBy"),
    "SORT ORDER BY STOPKEY": (IROperator.SORT_TOP_N, "SortOrderByStopkey"),
    "SORT JOIN": (IROperator.SORT, "SortJoin"),
    # Limit / stopkey
    "COUNT STOPKEY": (IROperator.LIMIT, "CountStopkey"),
    "STOPKEY": (IROperator.LIMIT, "Stopkey"),
    "FIRST ROW": (IROperator.LIMIT, "FirstRow"),
    # Materialize / temp
    "TEMP TABLE TRANSFORMATION": (IROperator.MATERIALIZE, "TempTableTransformation"),
    "VIEW": (IROperator.MATERIALIZE, "View"),
    "LOAD TABLE CONVENTIONAL": (IROperator.MATERIALIZE, "LoadTable"),
    # Set operations
    "UNION-ALL": (IROperator.SETOP_APPEND, "UnionAll"),
    "UNION ALL": (IROperator.SETOP_APPEND, "UnionAll"),
    "MINUS": (IROperator.SETOP_EXCEPT, "Minus"),
    "INTERSECT": (IROperator.SETOP_INTERSECT, "Intersect"),
    "CONCATENATION": (IROperator.SETOP_APPEND, "Concatenation"),
    # Window / analytic
    "WINDOW SORT": (IROperator.WINDOW, "WindowSort"),
    "WINDOW BUFFER": (IROperator.WINDOW, "WindowBuffer"),
    "WINDOW NOSORT": (IROperator.WINDOW, "WindowNosort"),
    # Parallel
    "PX COORDINATOR": (IROperator.GATHER, "PXCoordinator"),
    "PX SEND QC (RANDOM)": (IROperator.GATHER, "PXSendQC"),
    "PX RECEIVE": (IROperator.GATHER, "PXReceive"),
    "PX BLOCK ITERATOR": (IROperator.GATHER, "PXBlockIterator"),
    # Filter
    "FILTER": (IROperator.FILTER, "Filter"),
    # DML
    "INSERT STATEMENT": (IROperator.MODIFY, "InsertStatement"),
    "UPDATE STATEMENT": (IROperator.MODIFY, "UpdateStatement"),
    "DELETE STATEMENT": (IROperator.MODIFY, "DeleteStatement"),
    "MERGE STATEMENT": (IROperator.MODIFY, "MergeStatement"),
    # Misc
    "SELECT STATEMENT": (IROperator.RESULT, "SelectStatement"),
    "CONNECT BY": (IROperator.COMPUTE, "ConnectBy"),
    "INLIST ITERATOR": (IROperator.FILTER, "InlistIterator"),
    "PARTITION RANGE ALL": (IROperator.SCAN_SEQ, "PartitionRangeAll"),
    "PARTITION RANGE SINGLE": (IROperator.SCAN_INDEX, "PartitionRangeSingle"),
    "PARTITION RANGE ITERATOR": (IROperator.SCAN_INDEX, "PartitionRangeIterator"),
    "REMOTE": (IROperator.SCAN_FOREIGN, "Remote"),
}


def _lookup_operator(operation: str, options: str | None) -> tuple[IROperator, str]:
    """Map Oracle operation + options to IR operator."""
    combined = operation.upper()
    if options:
        combined = f"{combined} {options.upper()}"

    # Try exact match first
    if combined in _ORA_OP_MAP:
        return _ORA_OP_MAP[combined]

    # Try operation-only match
    op_upper = operation.upper()
    if op_upper in _ORA_OP_MAP:
        return _ORA_OP_MAP[op_upper]

    # Prefix matching for variations
    for key, val in _ORA_OP_MAP.items():
        if combined.startswith(key):
            return val

    return (IROperator.OTHER, combined)


def _extract_join_type(operation: str, options: str | None) -> str | None:
    """Extract join type from Oracle operation string."""
    combined = f"{operation} {options or ''}".upper()
    if "ANTI" in combined:
        return "Anti"
    if "SEMI" in combined:
        return "Semi"
    if "RIGHT OUTER" in combined:
        return "Right"
    if "OUTER" in combined:
        return "Left"
    if "FULL" in combined and "SCAN" not in combined:
        return "Full"
    if "CARTESIAN" in combined:
        return "Cross"
    if any(j in combined for j in ("NESTED LOOPS", "HASH JOIN", "MERGE JOIN")):
        return "Inner"
    return None


class OracleAdapter(PlanAdapter):
    """Translate Oracle V$SQL_PLAN / DBMS_XPLAN JSON to IR."""

    engine = "oracle"

    def can_handle(self, raw_plan: Any) -> bool:
        """Detect Oracle plan JSON format."""
        if not isinstance(raw_plan, dict):
            return False
        # Structured JSON from V$SQL_PLAN
        if "operations" in raw_plan and isinstance(raw_plan["operations"], list):
            ops = raw_plan["operations"]
            return bool(ops and isinstance(ops[0], dict) and "operation" in ops[0])
        # DBMS_XPLAN text output (not yet supported)
        if "plan_table_output" in raw_plan:
            return True
        return False

    def translate(self, raw_plan: Any, **kwargs: Any) -> IRPlan:
        """
        Translate Oracle plan JSON -> IRPlan.

        Args:
            raw_plan: dict with "operations" list from V$SQL_PLAN.
        """
        if not isinstance(raw_plan, dict):
            raise ValueError("Oracle adapter expects a dict input")

        operations = raw_plan.get("operations", [])

        if not operations and "plan_table_output" in raw_plan:
            raise ValueError(
                "plan_table_output (text format) is not yet supported. "
                "Export as structured JSON from V$SQL_PLAN instead."
            )

        if not operations:
            raise ValueError("No operations found in Oracle plan")

        # Build tree from flat operation list
        counter = _Counter()
        root = self._build_tree(operations, counter)

        ir_plan = IRPlan(
            engine="oracle",
            engine_version=kwargs.get("engine_version", raw_plan.get("db_version", "")),
            root=root,
            planning_time_ms=raw_plan.get("parse_time_ms"),
            execution_time_ms=raw_plan.get("elapsed_time_ms"),
            query_text=kwargs.get("sql"),
            raw_plan=raw_plan,
        )

        ir_plan.compute_cost_shares()
        ir_plan.compute_self_times()
        ir_plan.derive_and_set_capabilities()

        return ir_plan

    def _build_tree(
        self,
        operations: list[dict[str, Any]],
        counter: _Counter,
    ) -> IRNode:
        """Build IR tree from flat Oracle operation list."""
        # Index operations by id
        by_id: dict[int, dict[str, Any]] = {}
        children_map: dict[int | None, list[int]] = {}

        for op in operations:
            op_id = op.get("id", 0)
            parent_id = op.get("parent_id")
            by_id[op_id] = op
            children_map.setdefault(parent_id, []).append(op_id)

        # Find root parent_id (one not in by_id)
        all_ids = set(by_id.keys())
        root_parent = None
        for op in operations:
            pid = op.get("parent_id")
            if pid not in all_ids:
                root_parent = pid
                break

        root_children = children_map.get(root_parent, [])
        if not root_children:
            raise ValueError("Could not identify root operation in Oracle plan")

        # Build recursively
        if len(root_children) == 1:
            return self._translate_operation(
                by_id[root_children[0]], by_id, children_map, counter, 0, "Root"
            )

        # Multiple roots: wrap in RESULT
        children = [
            self._translate_operation(
                by_id[cid], by_id, children_map, counter, 1,
                f"Root -> {by_id[cid].get('operation', '?')}"
            )
            for cid in root_children
        ]
        return IRNode(
            id=f"n{counter.next()}",
            operator=IROperator.RESULT,
            algorithm="MultiStatement",
            children=children,
            depth=0,
            path="Root",
        )

    def _translate_operation(
        self,
        op_data: dict[str, Any],
        by_id: dict[int, dict[str, Any]],
        children_map: dict[int | None, list[int]],
        counter: _Counter,
        depth: int,
        path: str,
    ) -> IRNode:
        """Translate a single Oracle operation to an IR node."""
        op_id = op_data.get("id", 0)
        operation = op_data.get("operation", "UNKNOWN")
        options = op_data.get("options")

        ir_op, algo = _lookup_operator(operation, options)
        node_id = f"n{counter.next()}"

        # Cardinality
        est_rows = op_data.get("cardinality")
        actual_rows = op_data.get("actual_rows")
        starts = op_data.get("starts", 1)

        cardinality = CardinalitySignals(
            estimated_rows=float(est_rows) if est_rows is not None else None,
            actual_rows=float(actual_rows) if actual_rows is not None else None,
            actual_loops=int(starts) if starts and starts > 1 else None,
        )

        # Cost
        cost_val = op_data.get("cost")
        cost = CostSignals(
            total_cost=float(cost_val) if cost_val is not None else None,
        )

        # Predicates
        predicates = Predicates(
            index_condition=op_data.get("access_predicates"),
            filter_condition=op_data.get("filter_predicates"),
        )

        # Relation / index
        relation_name = op_data.get("object_name")
        index_name = None

        # For index operations, the object_name IS the index
        if ir_op in (
            IROperator.SCAN_INDEX, IROperator.SCAN_INDEX_ONLY,
            IROperator.SCAN_BITMAP,
        ) and "INDEX" in operation.upper():
            index_name = relation_name
            # Table name might be on the parent TABLE ACCESS node
            relation_name = op_data.get("table_name") or relation_name

        # Join type
        join_type = _extract_join_type(operation, options)

        # Parallelism
        distribution = op_data.get("distribution") or op_data.get("pq_distribution")
        is_parallel = bool(distribution) or "PX" in operation.upper()

        parallelism = ParallelismSignals(
            is_parallel=is_parallel,
            exchange_type=distribution,
        )

        properties = IRProperties(
            cardinality=cardinality,
            cost=cost,
            predicates=predicates,
            parallelism=parallelism,
            relation_name=relation_name,
            index_name=index_name,
            join_type=join_type,
        )

        # Annotations
        ora_ann = OracleAnnotations(
            operation=operation,
            options=options,
            cpu_cost=op_data.get("cpu_cost"),
            io_cost=op_data.get("io_cost"),
            bytes_estimate=op_data.get("bytes"),
            partition_start=op_data.get("partition_start"),
            partition_stop=op_data.get("partition_stop"),
            distribution=distribution,
            original_operation=f"{operation} {options or ''}".strip(),
            extras={
                k: v for k, v in op_data.items()
                if k not in _ORA_KNOWN_KEYS and not isinstance(v, (list, dict))
            },
        )
        annotations = IRAnnotations(oracle=ora_ann)

        # Children
        child_ids = children_map.get(op_id, [])
        children = []
        for cid in child_ids:
            child_data = by_id[cid]
            child_op = child_data.get("operation", "?")
            child_path = f"{path} -> {child_op}"
            children.append(
                self._translate_operation(
                    child_data, by_id, children_map, counter, depth + 1, child_path
                )
            )

        return IRNode(
            id=node_id,
            operator=ir_op,
            algorithm=algo,
            properties=properties,
            annotations=annotations,
            children=children,
            depth=depth,
            path=path,
        )


class _Counter:
    def __init__(self) -> None:
        self._n = 0

    def next(self) -> int:
        n = self._n
        self._n += 1
        return n


# Keys we explicitly extract; everything else goes to extras
_ORA_KNOWN_KEYS = {
    "id", "parent_id", "operation", "options",
    "object_name", "table_name",
    "cost", "cardinality", "bytes",
    "cpu_cost", "io_cost",
    "actual_rows", "starts",
    "access_predicates", "filter_predicates",
    "distribution", "pq_distribution",
    "partition_start", "partition_stop",
    "db_version",
}
