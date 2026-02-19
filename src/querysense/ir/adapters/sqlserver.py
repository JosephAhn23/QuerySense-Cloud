"""
SQL Server Adapter: Showplan XML -> IR Plan.

SQL Server exposes execution plans via ``SET SHOWPLAN_XML ON`` or
``sys.dm_exec_query_plan``.  The Showplan XML format is a well-defined
XML document with a documented operator taxonomy.

This adapter parses Showplan XML and maps operators into the portable IR.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from querysense.ir.adapters.base import PlanAdapter
from querysense.ir.annotations import (
    IRAnnotations,
    SQLServerAnnotations,
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

# Showplan XML namespace
_NS = {"sp": "http://schemas.microsoft.com/sqlserver/2004/07/showplan"}

# ── Operator mapping ─────────────────────────────────────────────────

_SS_OP_MAP: dict[str, tuple[IROperator, str]] = {
    # Scans
    "Table Scan": (IROperator.SCAN_SEQ, "TableScan"),
    "Clustered Index Scan": (IROperator.SCAN_INDEX, "ClusteredIndexScan"),
    "Nonclustered Index Scan": (IROperator.SCAN_INDEX, "NonclusteredIndexScan"),
    "Index Scan": (IROperator.SCAN_INDEX, "IndexScan"),
    "Clustered Index Seek": (IROperator.SCAN_INDEX, "ClusteredIndexSeek"),
    "Nonclustered Index Seek": (IROperator.SCAN_INDEX, "NonclusteredIndexSeek"),
    "Index Seek": (IROperator.SCAN_INDEX, "IndexSeek"),
    "Key Lookup": (IROperator.SCAN_LOOKUP, "KeyLookup"),
    "RID Lookup": (IROperator.SCAN_LOOKUP, "RIDLookup"),
    "Bookmark Lookup": (IROperator.SCAN_LOOKUP, "BookmarkLookup"),
    "Constant Scan": (IROperator.RESULT, "ConstantScan"),
    "Table Valued Function": (IROperator.SCAN_FUNCTION, "TVF"),
    "Remote Query": (IROperator.SCAN_FOREIGN, "RemoteQuery"),
    # Joins
    "Nested Loops": (IROperator.JOIN_NESTED_LOOP, "NestedLoops"),
    "Hash Match": (IROperator.JOIN_HASH, "HashMatch"),
    "Merge Join": (IROperator.JOIN_MERGE, "MergeJoin"),
    "Adaptive Join": (IROperator.JOIN_HASH, "AdaptiveJoin"),
    # Aggregates
    "Hash Match (Aggregate)": (IROperator.AGGREGATE_HASH, "HashAggregate"),
    "Stream Aggregate": (IROperator.AGGREGATE_SORT, "StreamAggregate"),
    # Sort
    "Sort": (IROperator.SORT, "Sort"),
    "Top N Sort": (IROperator.SORT_TOP_N, "TopNSort"),
    "Top": (IROperator.LIMIT, "Top"),
    # Materialize / Spool
    "Table Spool": (IROperator.MATERIALIZE, "TableSpool"),
    "Index Spool": (IROperator.MATERIALIZE, "IndexSpool"),
    "Row Count Spool": (IROperator.MATERIALIZE, "RowCountSpool"),
    "Eager Spool": (IROperator.MATERIALIZE, "EagerSpool"),
    "Lazy Spool": (IROperator.MATERIALIZE, "LazySpool"),
    # Set ops
    "Concatenation": (IROperator.SETOP_APPEND, "Concatenation"),
    "Merge Interval": (IROperator.SETOP_UNION, "MergeInterval"),
    # Compute
    "Compute Scalar": (IROperator.COMPUTE, "ComputeScalar"),
    "Segment": (IROperator.COMPUTE, "Segment"),
    "Sequence Project": (IROperator.WINDOW, "SequenceProject"),
    "Window Aggregate": (IROperator.WINDOW, "WindowAggregate"),
    # Parallelism
    "Parallelism": (IROperator.GATHER, "Parallelism"),
    # Filter
    "Filter": (IROperator.FILTER, "Filter"),
    # DML
    "Table Insert": (IROperator.MODIFY, "TableInsert"),
    "Clustered Index Insert": (IROperator.MODIFY, "ClusteredIndexInsert"),
    "Table Update": (IROperator.MODIFY, "TableUpdate"),
    "Clustered Index Update": (IROperator.MODIFY, "ClusteredIndexUpdate"),
    "Table Delete": (IROperator.MODIFY, "TableDelete"),
    "Clustered Index Delete": (IROperator.MODIFY, "ClusteredIndexDelete"),
    # Assert / misc
    "Assert": (IROperator.FILTER, "Assert"),
    "Collapse": (IROperator.COMPUTE, "Collapse"),
    "Split": (IROperator.COMPUTE, "Split"),
}


class SQLServerAdapter(PlanAdapter):
    """Translate SQL Server Showplan XML to IR."""

    engine = "sqlserver"

    def can_handle(self, raw_plan: Any) -> bool:
        """Detect SQL Server Showplan XML."""
        if isinstance(raw_plan, str):
            return "schemas.microsoft.com/sqlserver" in raw_plan[:500]
        if isinstance(raw_plan, dict):
            return "ShowPlanXML" in str(raw_plan)[:500]
        return False

    def translate(self, raw_plan: Any, **kwargs: Any) -> IRPlan:
        """
        Translate SQL Server Showplan XML -> IRPlan.

        Args:
            raw_plan: XML string of Showplan XML.
        """
        if isinstance(raw_plan, str):
            root_elem = ET.fromstring(raw_plan)
        else:
            raise ValueError("SQL Server adapter expects XML string input")

        # Find the first StmtSimple/StmtCond with a QueryPlan
        query_plan = root_elem.find(".//sp:QueryPlan", _NS)
        if query_plan is None:
            raise ValueError("No QueryPlan element found in Showplan XML")

        # Get statement-level info
        stmt = root_elem.find(".//sp:StmtSimple", _NS)
        stmt_text = stmt.get("StatementText") if stmt is not None else None

        counter = _Counter()
        rel_op = query_plan.find(".//sp:RelOp", _NS)
        if rel_op is None:
            raise ValueError("No RelOp element found in QueryPlan")

        root_node = self._translate_relop(rel_op, counter, 0, "Root")

        ir_plan = IRPlan(
            engine="sqlserver",
            engine_version=kwargs.get("engine_version", ""),
            root=root_node,
            query_text=stmt_text or kwargs.get("sql"),
            raw_plan={"xml": raw_plan[:200] + "..."},
        )

        ir_plan.compute_cost_shares()
        ir_plan.derive_and_set_capabilities()
        return ir_plan

    def _translate_relop(
        self,
        relop: ET.Element,
        counter: _Counter,
        depth: int,
        path: str,
    ) -> IRNode:
        """Translate a SQL Server RelOp element."""
        physical = relop.get("PhysicalOp", "Unknown")
        logical = relop.get("LogicalOp", physical)
        est_rows = _float_attr(relop, "EstimateRows")
        est_cost = _float_attr(relop, "EstimatedTotalSubtreeCost")

        # Map operator
        op, algo = _SS_OP_MAP.get(physical, (IROperator.OTHER, physical))

        # Handle Hash Match that is an aggregate
        if physical == "Hash Match" and logical in (
            "Aggregate", "Flow Distinct", "Partial Aggregate",
        ):
            op = IROperator.AGGREGATE_HASH
            algo = "HashAggregate"

        # Parallelism exchange type
        exchange_type = None
        if physical == "Parallelism":
            exchange_type = logical  # "Gather Streams", "Repartition Streams", etc.

        node_id = f"n{counter.next()}"

        # Properties
        cardinality = CardinalitySignals(
            estimated_rows=est_rows,
        )

        cost = CostSignals(
            total_cost=est_cost,
        )

        # Object reference (table/index)
        relation = None
        index_name = None
        obj_elem = relop.find(".//sp:Object", _NS)
        if obj_elem is not None:
            relation = obj_elem.get("Table", "").strip("[]")
            index_name = obj_elem.get("Index", "").strip("[]") or None

        properties = IRProperties(
            cardinality=cardinality,
            cost=cost,
            relation_name=relation,
            index_name=index_name,
        )

        # Annotations
        dop = _int_attr(relop, "EstimatedDegreeOfParallelism")
        exec_mode = relop.get("EstimatedExecutionMode")

        ss_ann = SQLServerAnnotations(
            physical_op=physical,
            logical_op=logical,
            estimated_subtree_cost=est_cost,
            estimated_execution_mode=exec_mode,
            degree_of_parallelism=dop,
            exchange_type=exchange_type,
            is_adaptive=physical == "Adaptive Join",
            original_operator=physical,
            no_join_predicate=relop.get("NoJoinPredicate", "0") == "1",
        )

        annotations = IRAnnotations(sqlserver=ss_ann)

        # Children (nested RelOp elements)
        children = []
        for child_relop in relop.findall("sp:RelOp", _NS):
            child_path = f"{path} -> {child_relop.get('PhysicalOp', '?')}"
            children.append(
                self._translate_relop(child_relop, counter, depth + 1, child_path)
            )

        # Some operators have children inside sub-elements
        for sub_tag in [
            "sp:NestedLoops", "sp:Hash", "sp:Merge",
            "sp:StreamAggregate", "sp:Sort", "sp:Filter",
            "sp:Top", "sp:Spool", "sp:Parallelism",
            "sp:ComputeScalar", "sp:Concat",
        ]:
            for sub_elem in relop.findall(sub_tag, _NS):
                for child_relop in sub_elem.findall("sp:RelOp", _NS):
                    child_path = f"{path} -> {child_relop.get('PhysicalOp', '?')}"
                    children.append(
                        self._translate_relop(
                            child_relop, counter, depth + 1, child_path
                        )
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
    def __init__(self) -> None:
        self._n = 0

    def next(self) -> int:
        n = self._n
        self._n += 1
        return n


def _float_attr(elem: ET.Element, attr: str) -> float | None:
    v = elem.get(attr)
    if v is None:
        return None
    try:
        return float(v)
    except ValueError:
        return None


def _int_attr(elem: ET.Element, attr: str) -> int | None:
    v = elem.get(attr)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None
