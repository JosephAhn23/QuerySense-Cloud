"""
MySQL Adapter: EXPLAIN FORMAT=JSON / EXPLAIN ANALYZE -> IR Plan.

MySQL EXPLAIN output differs significantly from PostgreSQL:
- Classic EXPLAIN produces per-table rows with ``type``/``access_type``
  and an ``Extra`` column with flags.
- EXPLAIN FORMAT=JSON adds ``query_block`` with nested structure.
- EXPLAIN ANALYZE (8.0.18+) adds iterator-level timing in TREE format.

This adapter handles the JSON format (most structured) and maps MySQL
concepts into the portable IR.
"""

from __future__ import annotations

from typing import Any

from querysense.ir.adapters.base import PlanAdapter
from querysense.ir.annotations import (
    IRAnnotations,
    MySQLAnnotations,
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

# ── Access type to IR operator mapping ────────────────────────────────

_MYSQL_ACCESS_MAP: dict[str, tuple[IROperator, str]] = {
    "ALL": (IROperator.SCAN_SEQ, "FullTableScan"),
    "index": (IROperator.SCAN_INDEX, "FullIndexScan"),
    "range": (IROperator.SCAN_INDEX, "IndexRangeScan"),
    "ref": (IROperator.SCAN_INDEX, "IndexRef"),
    "eq_ref": (IROperator.SCAN_INDEX, "IndexEqRef"),
    "ref_or_null": (IROperator.SCAN_INDEX, "IndexRefOrNull"),
    "const": (IROperator.SCAN_INDEX, "ConstLookup"),
    "system": (IROperator.RESULT, "SystemConst"),
    "fulltext": (IROperator.SCAN_INDEX, "FulltextIndex"),
    "unique_subquery": (IROperator.SCAN_INDEX, "UniqueSubquery"),
    "index_subquery": (IROperator.SCAN_INDEX, "IndexSubquery"),
    "index_merge": (IROperator.SCAN_BITMAP, "IndexMerge"),
}


_MYSQL_LEGACY_ACCESS_MAP: dict[str, tuple[Any, Any]] = {}


def _init_legacy_map() -> None:
    """Lazy-init to avoid circular imports at module level."""
    global _MYSQL_LEGACY_ACCESS_MAP
    if _MYSQL_LEGACY_ACCESS_MAP:
        return
    from querysense.ir.node import OperatorCategory, ScanStrategy

    _MYSQL_LEGACY_ACCESS_MAP.update({
        "ALL": (OperatorCategory.SCAN, ScanStrategy.FULL_TABLE),
        "index": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
        "range": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
        "ref": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
        "eq_ref": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
        "ref_or_null": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
        "const": (OperatorCategory.SCAN, ScanStrategy.INDEX_ONLY),
        "system": (OperatorCategory.SCAN, ScanStrategy.INDEX_ONLY),
        "fulltext": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
        "unique_subquery": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
        "index_subquery": (OperatorCategory.SCAN, ScanStrategy.INDEX_SCAN),
        "index_merge": (OperatorCategory.SCAN, ScanStrategy.BITMAP_SCAN),
    })


class MySQLAdapter(PlanAdapter):
    """Translate MySQL EXPLAIN JSON to IR."""

    engine = "mysql"

    def can_handle(self, raw_plan: Any) -> bool:
        """Detect MySQL EXPLAIN JSON format."""
        if isinstance(raw_plan, dict):
            return "query_block" in raw_plan
        return False

    # ── Legacy IR conversion (node.py types) ─────────────────────────

    def convert(self, raw_plan: dict[str, Any]) -> Any:
        """
        Convert MySQL EXPLAIN JSON to the legacy IR (node.py IRPlan/IRNode).

        This enables the same API surface as PostgreSQLAdapter.convert().
        """
        from querysense.ir.node import (
            Condition,
            ConditionKind,
            EngineType,
            IRNode as LegacyIRNode,
            IRPlan as LegacyIRPlan,
            JoinStrategy,
            JoinType,
            OperatorCategory,
            ScanStrategy,
            SortInfo,
            SortStrategy,
        )
        from querysense.ir.operators import AggregateStrategy, Operator

        _init_legacy_map()

        def _table_to_node(table: dict[str, Any]) -> LegacyIRNode:
            access_type = table.get("access_type", table.get("type", "ALL"))
            cat, strat = _MYSQL_LEGACY_ACCESS_MAP.get(
                access_type, (OperatorCategory.SCAN, ScanStrategy.FULL_TABLE)
            )
            # Upgrade to INDEX_ONLY when covering index is used
            if access_type in ("index", "ref", "eq_ref", "range"):
                if table.get("using_index", False):
                    strat = ScanStrategy.INDEX_ONLY

            op = Operator(
                category=cat,
                scan=strat if cat == OperatorCategory.SCAN else None,
                original=f"MySQL {access_type}",
                engine="mysql",
            )

            conditions: list[Condition] = []
            attached = table.get("attached_condition")
            if attached:
                conditions.append(Condition(attached, ConditionKind.ATTACHED))

            engine_specific: dict[str, Any] = {"access_type": access_type}
            if table.get("possible_keys"):
                engine_specific["possible_keys"] = table["possible_keys"]

            return LegacyIRNode(
                operator=op,
                estimated_rows=table.get("rows_examined_per_scan", table.get("rows", 0)) or 0,
                estimated_cost=float(
                    (table.get("cost_info") or {}).get("read_cost", 0) or 0
                ),
                relation=table.get("table_name", table.get("table")),
                index_name=table.get("key"),
                conditions=tuple(conditions),
                engine=EngineType.MYSQL,
                engine_specific=engine_specific,
                source_node_type=f"MySQL {access_type}",
            )

        def _convert_block(block: dict[str, Any]) -> LegacyIRNode:
            # Ordering operation → Sort node
            ordering = block.get("ordering_operation")
            if ordering:
                child = _convert_block(ordering)
                sort_op = Operator(
                    category=OperatorCategory.SORT,
                    sort=SortStrategy.EXTERNAL,
                    original="MySQL filesort",
                    engine="mysql",
                )
                return LegacyIRNode(
                    operator=sort_op,
                    sort_info=SortInfo(strategy=SortStrategy.EXTERNAL),
                    children=(child,),
                    engine=EngineType.MYSQL,
                    engine_specific={},
                    source_node_type="MySQL filesort",
                )

            # Grouping operation → Aggregate node
            grouping = block.get("grouping_operation")
            if grouping:
                child = _convert_block(grouping)
                agg_op = Operator(
                    category=OperatorCategory.AGGREGATE,
                    aggregate=AggregateStrategy.HASH,
                    original="MySQL grouping",
                    engine="mysql",
                )
                engine_specific: dict[str, Any] = {}
                if grouping.get("using_temporary_table"):
                    engine_specific["using_temporary_table"] = True
                if grouping.get("using_filesort"):
                    engine_specific["using_filesort"] = True
                return LegacyIRNode(
                    operator=agg_op,
                    children=(child,),
                    engine=EngineType.MYSQL,
                    engine_specific=engine_specific,
                    source_node_type="MySQL grouping",
                )

            # Nested loop join
            nested_loop = block.get("nested_loop")
            if nested_loop and isinstance(nested_loop, list):
                children = [
                    _table_to_node(item.get("table", {}))
                    for item in nested_loop
                ]
                if len(children) >= 2:
                    result = children[0]
                    for i in range(1, len(children)):
                        join_op = Operator(
                            category=OperatorCategory.JOIN,
                            join=JoinStrategy.NESTED_LOOP,
                            original="MySQL nested_loop",
                            engine="mysql",
                        )
                        result = LegacyIRNode(
                            operator=join_op,
                            children=(result, children[i]),
                            engine=EngineType.MYSQL,
                            engine_specific={},
                            source_node_type="MySQL nested_loop",
                        )
                    return result
                elif children:
                    return children[0]

            # Single table
            table = block.get("table")
            if table:
                return _table_to_node(table)

            # Fallback: result node
            op = Operator(
                category=OperatorCategory.OTHER,
                original="MySQL query_block",
                engine="mysql",
            )
            return LegacyIRNode(
                operator=op,
                engine=EngineType.MYSQL,
                engine_specific={},
                source_node_type="MySQL query_block",
            )

        # Handle tabular format ({"rows": [...]})
        if "rows" in raw_plan and isinstance(raw_plan["rows"], list):
            rows = raw_plan["rows"]
            children = [_table_to_node(row) for row in rows]
            if len(children) >= 2:
                result = children[0]
                for i in range(1, len(children)):
                    join_op = Operator(
                        category=OperatorCategory.JOIN,
                        join=JoinStrategy.NESTED_LOOP,
                        original="MySQL nested_loop",
                        engine="mysql",
                    )
                    result = LegacyIRNode(
                        operator=join_op,
                        children=(result, children[i]),
                        engine=EngineType.MYSQL,
                        engine_specific={},
                        source_node_type="MySQL nested_loop",
                    )
                return LegacyIRPlan(
                    root=result,
                    engine=EngineType.MYSQL,
                    raw_plan=raw_plan,
                )
            elif children:
                return LegacyIRPlan(
                    root=children[0],
                    engine=EngineType.MYSQL,
                    raw_plan=raw_plan,
                )

        # JSON format
        query_block = raw_plan.get("query_block", raw_plan)
        root = _convert_block(query_block)

        return LegacyIRPlan(
            root=root,
            engine=EngineType.MYSQL,
            raw_plan=raw_plan,
        )

    # ── Universal IR translation (plan.py types) ────────────────────

    def translate(self, raw_plan: Any, **kwargs: Any) -> IRPlan:
        """Translate MySQL EXPLAIN JSON -> IRPlan."""
        query_block = raw_plan.get("query_block", raw_plan)

        counter = _Counter()
        root = self._translate_query_block(query_block, counter, 0, "Root")

        ir_plan = IRPlan(
            engine="mysql",
            engine_version=kwargs.get("engine_version", ""),
            root=root,
            query_text=kwargs.get("sql"),
            raw_plan=raw_plan,
        )

        ir_plan.compute_cost_shares()
        ir_plan.derive_and_set_capabilities()
        return ir_plan

    def _translate_query_block(
        self,
        block: dict[str, Any],
        counter: _Counter,
        depth: int,
        path: str,
    ) -> IRNode:
        """Translate a MySQL query_block into an IR subtree."""
        children: list[IRNode] = []

        # Handle ordering operations
        ordering = block.get("ordering_operation")
        if ordering:
            child = self._translate_query_block(
                ordering, counter, depth + 1, f"{path} -> Sort"
            )
            sort_node = IRNode(
                id=f"n{counter.next()}",
                operator=IROperator.SORT,
                algorithm="Sort",
                properties=IRProperties(),
                annotations=IRAnnotations(
                    mysql=MySQLAnnotations(
                        using_filesort=True,
                        original_type="ordering_operation",
                    )
                ),
                children=[child],
                depth=depth,
                path=path,
            )
            return sort_node

        # Handle grouping
        grouping = block.get("grouping_operation")
        if grouping:
            child = self._translate_query_block(
                grouping, counter, depth + 1, f"{path} -> GroupBy"
            )
            agg_node = IRNode(
                id=f"n{counter.next()}",
                operator=IROperator.AGGREGATE_HASH,
                algorithm="GroupBy",
                properties=IRProperties(),
                annotations=IRAnnotations(
                    mysql=MySQLAnnotations(
                        using_temporary=grouping.get("using_temporary_table", False),
                        using_filesort=grouping.get("using_filesort", False),
                        original_type="grouping_operation",
                    )
                ),
                children=[child],
                depth=depth,
                path=path,
            )
            return agg_node

        # Handle nested_loop
        nested_loop = block.get("nested_loop")
        if nested_loop and isinstance(nested_loop, list):
            for item in nested_loop:
                table = item.get("table", {})
                child = self._translate_table(table, counter, depth + 1, path)
                children.append(child)

            if len(children) >= 2:
                # Build a left-deep join tree
                result = children[0]
                for i in range(1, len(children)):
                    join_node = IRNode(
                        id=f"n{counter.next()}",
                        operator=IROperator.JOIN_NESTED_LOOP,
                        algorithm="NestedLoop",
                        properties=IRProperties(),
                        annotations=IRAnnotations(
                            mysql=MySQLAnnotations(original_type="nested_loop")
                        ),
                        children=[result, children[i]],
                        depth=depth,
                        path=f"{path} -> Nested Loop",
                    )
                    result = join_node
                return result
            elif children:
                return children[0]

        # Handle single table
        table = block.get("table")
        if table:
            return self._translate_table(table, counter, depth, path)

        # Handle duplicates_removal
        dup = block.get("duplicates_removal")
        if dup:
            return self._translate_query_block(
                dup, counter, depth, f"{path} -> Distinct"
            )

        # Handle subqueries
        subqueries = block.get("optimized_away_subqueries", [])
        for sq in subqueries:
            sub_block = sq.get("query_block", {})
            children.append(
                self._translate_query_block(
                    sub_block, counter, depth + 1, f"{path} -> Subquery"
                )
            )

        # Fallback: result node
        cost_info = block.get("cost_info", {})
        return IRNode(
            id=f"n{counter.next()}",
            operator=IROperator.RESULT,
            algorithm="QueryBlock",
            properties=IRProperties(
                cost=CostSignals(
                    total_cost=_float_or_none(cost_info.get("query_cost")),
                ),
            ),
            annotations=IRAnnotations(
                mysql=MySQLAnnotations(original_type="query_block")
            ),
            children=children,
            depth=depth,
            path=path,
        )

    def _translate_table(
        self,
        table: dict[str, Any],
        counter: _Counter,
        depth: int,
        path: str,
    ) -> IRNode:
        """Translate a MySQL table access into an IR node."""
        access_type = table.get("access_type", "ALL")
        op, algo = _MYSQL_ACCESS_MAP.get(
            access_type, (IROperator.SCAN_SEQ, f"MySQL_{access_type}")
        )

        table_name = table.get("table_name", "")
        index_name = table.get("key")
        cost_info = table.get("cost_info", {})
        rows_examined = table.get("rows_examined_per_scan")
        rows_produced = table.get("rows_produced_per_join")

        # Detect covering index (Using index)
        if access_type in ("index", "ref", "eq_ref", "range"):
            attached = table.get("attached_condition")
            if table.get("using_index", False):
                op = IROperator.SCAN_INDEX_ONLY

        cardinality = CardinalitySignals(
            estimated_rows=_float_or_none(rows_examined),
            actual_rows=_float_or_none(rows_produced),
        )

        cost = CostSignals(
            total_cost=_float_or_none(cost_info.get("read_cost")),
        )

        predicates = Predicates(
            filter_condition=table.get("attached_condition"),
        )

        properties = IRProperties(
            cardinality=cardinality,
            cost=cost,
            predicates=predicates,
            relation_name=table_name,
            index_name=index_name,
        )

        mysql_ann = MySQLAnnotations(
            access_type=access_type,
            possible_keys=tuple(table.get("possible_keys", []) or []),
            key_length=table.get("key_length"),
            ref_columns=tuple(table.get("ref", []) if isinstance(table.get("ref"), list) else []),
            using_index=table.get("using_index", False),
            using_index_condition=table.get("using_index_condition", False),
            using_join_buffer=table.get("using_join_buffer"),
            using_mrr=table.get("using_MRR", False),
            original_type=access_type,
        )

        return IRNode(
            id=f"n{counter.next()}",
            operator=op,
            algorithm=algo,
            properties=properties,
            annotations=IRAnnotations(mysql=mysql_ann),
            children=[],
            depth=depth,
            path=f"{path} -> {table_name}",
        )


class _Counter:
    def __init__(self) -> None:
        self._n = 0

    def next(self) -> int:
        n = self._n
        self._n += 1
        return n


def _float_or_none(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None
