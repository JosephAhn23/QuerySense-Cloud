"""
SQL Server Showplan XML parser — production-ready.

Handles SQL Server execution plan XML output from:
- SET SHOWPLAN_XML ON / OFF
- sys.dm_exec_query_plan()
- sys.dm_exec_text_query_plan()
- Query Store (sys.query_store_plan)
- SQL Server Management Studio (SSMS) .sqlplan files

Converts Showplan XML into typed Pydantic models that flow through
the same IR pipeline as PostgreSQL and MySQL plans.

SQL Server Showplan XML structure:
    <ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan">
      <BatchSequence>
        <Batch>
          <Statements>
            <StmtSimple StatementText="SELECT ..." StatementType="SELECT">
              <QueryPlan CachedPlanSize="48" ...>
                <RelOp NodeId="0" PhysicalOp="Clustered Index Scan" LogicalOp="Clustered Index Scan"
                        EstimateRows="1000" EstimatedTotalSubtreeCost="0.01">
                  ...
                </RelOp>
              </QueryPlan>
            </StmtSimple>
          </Statements>
        </Batch>
      </BatchSequence>
    </ShowPlanXML>

Usage:
    from querysense.parser.sqlserver_parser import parse_sqlserver_plan

    output = parse_sqlserver_plan("showplan.xml")
    print(output.statement_text)
    for op in output.operators:
        print(f"{op.physical_op}: cost={op.estimated_subtree_cost}")
"""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from querysense.parser.parser import ParseError

logger = logging.getLogger(__name__)

# Showplan XML namespace
_NS = {"sp": "http://schemas.microsoft.com/sqlserver/2004/07/showplan"}


# ── SQL Server models ──────────────────────────────────────────────────


class SQLServerCostInfo(BaseModel):
    """SQL Server cost information for an operator."""

    model_config = ConfigDict(extra="allow")

    estimated_total_subtree_cost: float = 0.0
    estimated_operator_cost: float = 0.0
    estimated_io_cost: float = 0.0
    estimated_cpu_cost: float = 0.0
    estimated_rows: float = 0.0
    estimated_row_size: int | None = None
    actual_rows: int | None = None
    actual_executions: int | None = None
    actual_elapsed_ms: float | None = None

    @property
    def total_cost(self) -> float:
        return self.estimated_total_subtree_cost


class SQLServerObjectRef(BaseModel):
    """SQL Server object reference (table, index, etc.)."""

    model_config = ConfigDict(extra="allow")

    database: str = ""
    schema_name: str = ""
    table: str = ""
    index: str = ""
    index_kind: str = ""  # Clustered, NonClustered, Heap, etc.

    @property
    def qualified_name(self) -> str:
        parts = [p for p in [self.database, self.schema_name, self.table] if p]
        return ".".join(parts) or "(unknown)"


class SQLServerWarning(BaseModel):
    """SQL Server query plan warning."""

    model_config = ConfigDict(extra="allow")

    warning_type: str = ""
    message: str = ""

    # Specific warning types
    no_join_predicate: bool = False
    columns_with_no_statistics: list[str] = Field(default_factory=list)
    spill_to_tempdb: bool = False
    implicit_conversion: bool = False
    missing_index: bool = False
    unmatched_indexes: bool = False
    sort_spill_level: int | None = None


class SQLServerMissingIndex(BaseModel):
    """A missing index suggestion from SQL Server."""

    model_config = ConfigDict(extra="allow")

    impact: float = 0.0  # Percentage improvement estimate
    database: str = ""
    schema_name: str = ""
    table: str = ""
    equality_columns: list[str] = Field(default_factory=list)
    inequality_columns: list[str] = Field(default_factory=list)
    include_columns: list[str] = Field(default_factory=list)

    @property
    def create_index_statement(self) -> str:
        """Generate CREATE INDEX DDL."""
        key_cols = self.equality_columns + self.inequality_columns
        if not key_cols:
            return ""

        table_ref = f"[{self.schema_name}].[{self.table}]" if self.schema_name else f"[{self.table}]"
        key_part = ", ".join(f"[{c}]" for c in key_cols)

        statement = f"CREATE NONCLUSTERED INDEX [IX_{self.table}_{'_'.join(key_cols[:3])}]\n"
        statement += f"ON {table_ref} ({key_part})"

        if self.include_columns:
            inc_part = ", ".join(f"[{c}]" for c in self.include_columns)
            statement += f"\nINCLUDE ({inc_part})"

        statement += f"\n-- Estimated improvement: {self.impact:.1f}%"
        return statement


class SQLServerOperator(BaseModel):
    """A single operator (RelOp) in the SQL Server execution plan."""

    model_config = ConfigDict(extra="allow")

    node_id: int = 0
    physical_op: str = ""
    logical_op: str = ""
    execution_mode: str = "Row"  # Row or Batch
    cost: SQLServerCostInfo = Field(default_factory=SQLServerCostInfo)
    object_ref: SQLServerObjectRef | None = None
    warnings: list[SQLServerWarning] = Field(default_factory=list)
    predicates: list[str] = Field(default_factory=list)  # Seek/Scan predicates
    output_columns: list[str] = Field(default_factory=list)
    degree_of_parallelism: int | None = None
    memory_grant_kb: int | None = None
    children: list["SQLServerOperator"] = Field(default_factory=list)

    @property
    def is_scan(self) -> bool:
        return "Scan" in self.physical_op or "Table Scan" == self.physical_op

    @property
    def is_seek(self) -> bool:
        return "Seek" in self.physical_op

    @property
    def is_lookup(self) -> bool:
        return "Lookup" in self.physical_op

    @property
    def is_join(self) -> bool:
        return self.physical_op in ("Nested Loops", "Hash Match", "Merge Join", "Adaptive Join")

    @property
    def is_sort(self) -> bool:
        return "Sort" in self.physical_op

    @property
    def is_parallel(self) -> bool:
        return self.physical_op == "Parallelism" or (self.degree_of_parallelism or 0) > 1

    @property
    def cost_pct(self) -> float:
        """Operator cost as percentage of subtree (exclusive)."""
        if not self.children:
            return 100.0
        children_cost = sum(c.cost.estimated_total_subtree_cost for c in self.children)
        exclusive = max(0, self.cost.estimated_total_subtree_cost - children_cost)
        if self.cost.estimated_total_subtree_cost > 0:
            return (exclusive / self.cost.estimated_total_subtree_cost) * 100
        return 0.0


class SQLServerQueryPlan(BaseModel):
    """Represents a complete SQL Server query execution plan."""

    model_config = ConfigDict(extra="allow")

    cached_plan_size_kb: int = 0
    compile_time_ms: int = 0
    compile_cpu_ms: int = 0
    compile_memory_kb: int = 0
    degree_of_parallelism: int = 0
    memory_grant_kb: int = 0
    requested_memory_kb: int = 0
    optimization_level: str = ""  # FULL, TRIVIAL
    reason_for_early_termination: str = ""
    parameter_list: list[dict[str, str]] = Field(default_factory=list)
    missing_indexes: list[SQLServerMissingIndex] = Field(default_factory=list)
    root_operator: SQLServerOperator | None = None

    @property
    def total_cost(self) -> float:
        if self.root_operator:
            return self.root_operator.cost.estimated_total_subtree_cost
        return 0.0


class SQLServerPlanOutput(BaseModel):
    """Complete parsed output from SQL Server Showplan XML."""

    model_config = ConfigDict(extra="allow")

    engine: str = "sqlserver"
    engine_version: str = ""
    statement_text: str = ""
    statement_type: str = ""  # SELECT, INSERT, UPDATE, DELETE, etc.
    query_hash: str = ""
    query_plan_hash: str = ""
    plans: list[SQLServerQueryPlan] = Field(default_factory=list)

    # Flattened list of all operators for easy iteration
    operators: list[SQLServerOperator] = Field(default_factory=list)

    # Plan-level warnings and suggestions
    warnings: list[SQLServerWarning] = Field(default_factory=list)
    missing_indexes: list[SQLServerMissingIndex] = Field(default_factory=list)

    # Summary
    total_cost: float = 0.0
    operator_count: int = 0
    scan_count: int = 0
    seek_count: int = 0
    lookup_count: int = 0
    sort_count: int = 0
    has_parallelism: bool = False
    has_warnings: bool = False
    has_missing_indexes: bool = False
    has_key_lookups: bool = False
    has_table_scans: bool = False
    has_implicit_conversions: bool = False


# ── Parser ─────────────────────────────────────────────────────────────


def parse_sqlserver_plan(
    source: str | Path,
    *,
    engine_version: str = "",
    validate_structure: bool = True,
) -> SQLServerPlanOutput:
    """
    Parse a SQL Server Showplan XML file or string.

    Args:
        source: Path to .sqlplan/.xml file, or XML string
        engine_version: SQL Server version (e.g., "16.0" for 2022)
        validate_structure: Whether to validate XML structure

    Returns:
        SQLServerPlanOutput with all operators and metadata

    Raises:
        ParseError: If the XML cannot be parsed
    """
    xml_str = _load_source(source)

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        raise ParseError(
            f"Invalid Showplan XML: {e}",
            source="xml_parse",
            detail=str(e),
        )

    # Validate namespace
    if validate_structure:
        if "schemas.microsoft.com/sqlserver" not in (root.tag or ""):
            # Try without namespace prefix
            if not root.findall(".//QueryPlan") and not root.findall(".//sp:QueryPlan", _NS):
                raise ParseError(
                    "Not a valid SQL Server Showplan XML document",
                    source="validation",
                    detail=f"Root tag: {root.tag}",
                )

    # Extract build info
    build_elem = root.find(".//sp:Build", _NS) or root.find(".//Build")
    detected_version = ""
    if build_elem is not None:
        detected_version = build_elem.get("ProductVersion", "")

    output = SQLServerPlanOutput(
        engine_version=engine_version or detected_version,
    )

    # Find all statements
    statements = root.findall(".//sp:StmtSimple", _NS)
    if not statements:
        # Try without namespace
        statements = root.findall(".//StmtSimple")

    for stmt in statements:
        stmt_text = stmt.get("StatementText", "")
        stmt_type = stmt.get("StatementType", "")
        query_hash = stmt.get("QueryHash", "")
        plan_hash = stmt.get("QueryPlanHash", "")

        output.statement_text = stmt_text or output.statement_text
        output.statement_type = stmt_type or output.statement_type
        output.query_hash = query_hash or output.query_hash
        output.query_plan_hash = plan_hash or output.query_plan_hash

        # Parse QueryPlan
        qp_elem = stmt.find("sp:QueryPlan", _NS) or stmt.find("QueryPlan")
        if qp_elem is not None:
            query_plan = _parse_query_plan(qp_elem)
            output.plans.append(query_plan)
            output.missing_indexes.extend(query_plan.missing_indexes)

    # Flatten all operators
    all_ops: list[SQLServerOperator] = []
    for plan in output.plans:
        if plan.root_operator:
            _flatten_operators(plan.root_operator, all_ops)
    output.operators = all_ops

    # Compute summary
    output.operator_count = len(all_ops)
    output.scan_count = sum(1 for op in all_ops if op.is_scan)
    output.seek_count = sum(1 for op in all_ops if op.is_seek)
    output.lookup_count = sum(1 for op in all_ops if op.is_lookup)
    output.sort_count = sum(1 for op in all_ops if op.is_sort)
    output.has_parallelism = any(op.is_parallel for op in all_ops)
    output.has_key_lookups = any(op.is_lookup for op in all_ops)
    output.has_table_scans = any(op.physical_op == "Table Scan" for op in all_ops)

    all_warnings: list[SQLServerWarning] = []
    for op in all_ops:
        all_warnings.extend(op.warnings)
    output.warnings = all_warnings
    output.has_warnings = len(all_warnings) > 0
    output.has_missing_indexes = len(output.missing_indexes) > 0
    output.has_implicit_conversions = any(w.implicit_conversion for w in all_warnings)

    if output.plans:
        output.total_cost = output.plans[0].total_cost

    return output


# ── Internal parsing helpers ───────────────────────────────────────────


def _load_source(source: str | Path) -> str:
    """Load XML from file path or string."""
    if isinstance(source, Path) or (
        isinstance(source, str) and not source.lstrip().startswith("<")
    ):
        path = Path(source)
        if not path.exists():
            raise ParseError(
                f"File not found: {path}",
                source="file_load",
            )
        if path.stat().st_size > 50 * 1024 * 1024:  # 50MB limit
            raise ParseError(
                f"File too large: {path.stat().st_size / 1024 / 1024:.1f}MB (max 50MB)",
                source="file_load",
            )
        return path.read_text(encoding="utf-8-sig")

    return source


def _parse_query_plan(qp_elem: ET.Element) -> SQLServerQueryPlan:
    """Parse a QueryPlan XML element."""
    plan = SQLServerQueryPlan(
        cached_plan_size_kb=_int_attr(qp_elem, "CachedPlanSize") or 0,
        compile_time_ms=_int_attr(qp_elem, "CompileTime") or 0,
        compile_cpu_ms=_int_attr(qp_elem, "CompileCPU") or 0,
        compile_memory_kb=_int_attr(qp_elem, "CompileMemory") or 0,
        degree_of_parallelism=_int_attr(qp_elem, "DegreeOfParallelism") or 0,
        memory_grant_kb=_int_attr(qp_elem, "MemoryGrant") or 0,
        requested_memory_kb=_int_attr(qp_elem, "RequestedMemory") or 0,
        optimization_level=qp_elem.get("StatementOptmLevel", ""),
        reason_for_early_termination=qp_elem.get("StatementOptmEarlyAbortReason", ""),
    )

    # Parameters
    param_list = qp_elem.find("sp:ParameterList", _NS) or qp_elem.find("ParameterList")
    if param_list is not None:
        for param in param_list:
            plan.parameter_list.append({
                "name": param.get("Column", ""),
                "data_type": param.get("ParameterDataType", ""),
                "compiled_value": param.get("ParameterCompiledValue", ""),
                "runtime_value": param.get("ParameterRuntimeValue", ""),
            })

    # Missing indexes
    mi_group = qp_elem.find(".//sp:MissingIndexes", _NS) or qp_elem.find(".//MissingIndexes")
    if mi_group is not None:
        plan.missing_indexes = _parse_missing_indexes(mi_group)

    # Root operator
    relop = qp_elem.find("sp:RelOp", _NS) or qp_elem.find("RelOp")
    if relop is None:
        # Look deeper
        relop = qp_elem.find(".//sp:RelOp", _NS) or qp_elem.find(".//RelOp")

    if relop is not None:
        plan.root_operator = _parse_relop(relop)

    return plan


def _parse_relop(relop: ET.Element) -> SQLServerOperator:
    """Parse a RelOp XML element into an operator."""
    physical_op = relop.get("PhysicalOp", "Unknown")
    logical_op = relop.get("LogicalOp", physical_op)

    cost = SQLServerCostInfo(
        estimated_total_subtree_cost=_float_attr(relop, "EstimatedTotalSubtreeCost") or 0.0,
        estimated_operator_cost=_float_attr(relop, "EstimateOperatorCost") or 0.0,
        estimated_io_cost=_float_attr(relop, "EstimateIO") or 0.0,
        estimated_cpu_cost=_float_attr(relop, "EstimateCPU") or 0.0,
        estimated_rows=_float_attr(relop, "EstimateRows") or 0.0,
        estimated_row_size=_int_attr(relop, "AvgRowSize"),
    )

    # Actual runtime stats (if STATISTICS XML ON or live query stats)
    runtime = relop.find("sp:RunTimeInformation", _NS) or relop.find("RunTimeInformation")
    if runtime is not None:
        thread_stats = runtime.findall("sp:RunTimeCountersPerThread", _NS) or runtime.findall("RunTimeCountersPerThread")
        total_actual_rows = 0
        total_executions = 0
        max_elapsed = 0.0
        for ts in thread_stats:
            total_actual_rows += _int_attr(ts, "ActualRows") or 0
            total_executions += _int_attr(ts, "ActualExecutions") or 0
            elapsed = _float_attr(ts, "ActualElapsedms") or 0
            max_elapsed = max(max_elapsed, elapsed)

        cost.actual_rows = total_actual_rows
        cost.actual_executions = total_executions
        cost.actual_elapsed_ms = max_elapsed

    # Object reference
    obj_ref = None
    obj_elem = relop.find(".//sp:Object", _NS) or relop.find(".//Object")
    if obj_elem is not None:
        obj_ref = SQLServerObjectRef(
            database=_strip_brackets(obj_elem.get("Database", "")),
            schema_name=_strip_brackets(obj_elem.get("Schema", "")),
            table=_strip_brackets(obj_elem.get("Table", "")),
            index=_strip_brackets(obj_elem.get("Index", "")),
            index_kind=obj_elem.get("IndexKind", ""),
        )

    # Warnings
    warnings: list[SQLServerWarning] = []
    warnings_elem = relop.find(".//sp:Warnings", _NS) or relop.find(".//Warnings")
    if warnings_elem is not None:
        warnings = _parse_warnings(warnings_elem)

    # Predicates
    predicates: list[str] = []
    for pred_tag in ["sp:SeekPredicates", "sp:Predicate", "sp:ResidualPredicate"]:
        pred_elem = relop.find(f".//{pred_tag}", _NS)
        if pred_elem is not None:
            pred_text = ET.tostring(pred_elem, encoding="unicode", method="text").strip()
            if pred_text:
                predicates.append(pred_text)

    # Output columns
    output_cols: list[str] = []
    output_list = relop.find("sp:OutputList", _NS) or relop.find("OutputList")
    if output_list is not None:
        for col_ref in output_list:
            col_name = col_ref.get("Column", "")
            table_name = col_ref.get("Table", "")
            if col_name:
                output_cols.append(f"{table_name}.{col_name}" if table_name else col_name)

    op = SQLServerOperator(
        node_id=_int_attr(relop, "NodeId") or 0,
        physical_op=physical_op,
        logical_op=logical_op,
        execution_mode=relop.get("EstimatedExecutionMode", "Row"),
        cost=cost,
        object_ref=obj_ref,
        warnings=warnings,
        predicates=predicates,
        output_columns=output_cols,
        degree_of_parallelism=_int_attr(relop, "EstimatedDegreeOfParallelism"),
        memory_grant_kb=_int_attr(relop, "MemoryGrant"),
    )

    # Children (direct RelOp children)
    for child_relop in relop.findall("sp:RelOp", _NS):
        op.children.append(_parse_relop(child_relop))

    # Children inside sub-elements (NestedLoops, Hash, Merge, etc.)
    for sub_tag in [
        "sp:NestedLoops", "sp:Hash", "sp:Merge", "sp:StreamAggregate",
        "sp:Sort", "sp:Filter", "sp:Top", "sp:Spool", "sp:Parallelism",
        "sp:ComputeScalar", "sp:Concat", "sp:IndexScan", "sp:TableScan",
        "sp:Update", "sp:SimpleUpdate",
    ]:
        for sub_elem in relop.findall(sub_tag, _NS):
            for child_relop in sub_elem.findall("sp:RelOp", _NS):
                op.children.append(_parse_relop(child_relop))

    # Also try without namespace
    for child_relop in relop.findall("RelOp"):
        if child_relop not in [c for c in relop.findall("sp:RelOp", _NS)]:
            op.children.append(_parse_relop(child_relop))

    return op


def _parse_warnings(warnings_elem: ET.Element) -> list[SQLServerWarning]:
    """Parse Warnings element."""
    warnings: list[SQLServerWarning] = []

    # NoJoinPredicate
    if warnings_elem.find("sp:NoJoinPredicate", _NS) is not None or warnings_elem.find("NoJoinPredicate") is not None:
        warnings.append(SQLServerWarning(
            warning_type="NoJoinPredicate",
            message="No join predicate — possible Cartesian product",
            no_join_predicate=True,
        ))

    # SpillToTempDb
    spill = warnings_elem.find("sp:SpillToTempDb", _NS) or warnings_elem.find("SpillToTempDb")
    if spill is not None:
        level = _int_attr(spill, "SpillLevel")
        warnings.append(SQLServerWarning(
            warning_type="SpillToTempDb",
            message=f"Sort/hash spill to tempdb (level {level or '?'})",
            spill_to_tempdb=True,
            sort_spill_level=level,
        ))

    # ColumnsWithNoStatistics
    no_stats = warnings_elem.find("sp:ColumnsWithNoStatistics", _NS) or warnings_elem.find("ColumnsWithNoStatistics")
    if no_stats is not None:
        cols = [c.get("Column", "") for c in no_stats if c.get("Column")]
        warnings.append(SQLServerWarning(
            warning_type="ColumnsWithNoStatistics",
            message=f"No statistics on columns: {', '.join(cols)}",
            columns_with_no_statistics=cols,
        ))

    # PlanAffectingConvert (implicit conversions)
    for convert in warnings_elem.findall(".//sp:PlanAffectingConvert", _NS):
        warnings.append(SQLServerWarning(
            warning_type="ImplicitConversion",
            message=f"Implicit conversion: {convert.get('Expression', '')}",
            implicit_conversion=True,
        ))

    return warnings


def _parse_missing_indexes(mi_group: ET.Element) -> list[SQLServerMissingIndex]:
    """Parse MissingIndexes element."""
    indexes: list[SQLServerMissingIndex] = []

    for mi_elem in mi_group.findall(".//sp:MissingIndex", _NS):
        mi = SQLServerMissingIndex(
            impact=_float_attr(mi_elem.find("..", ), "Impact") or 0,
            database=_strip_brackets(mi_elem.get("Database", "")),
            schema_name=_strip_brackets(mi_elem.get("Schema", "")),
            table=_strip_brackets(mi_elem.get("Table", "")),
        )

        for col_group in mi_elem.findall("sp:ColumnGroup", _NS):
            usage = col_group.get("Usage", "")
            cols = [
                _strip_brackets(c.get("Name", ""))
                for c in col_group.findall("sp:Column", _NS)
            ]
            if usage == "EQUALITY":
                mi.equality_columns = cols
            elif usage == "INEQUALITY":
                mi.inequality_columns = cols
            elif usage == "INCLUDE":
                mi.include_columns = cols

        indexes.append(mi)

    # Also try without namespace
    for mi_elem in mi_group.findall(".//MissingIndex"):
        mi = SQLServerMissingIndex(
            database=_strip_brackets(mi_elem.get("Database", "")),
            schema_name=_strip_brackets(mi_elem.get("Schema", "")),
            table=_strip_brackets(mi_elem.get("Table", "")),
        )

        for col_group in mi_elem.findall("ColumnGroup"):
            usage = col_group.get("Usage", "")
            cols = [_strip_brackets(c.get("Name", "")) for c in col_group.findall("Column")]
            if usage == "EQUALITY":
                mi.equality_columns = cols
            elif usage == "INEQUALITY":
                mi.inequality_columns = cols
            elif usage == "INCLUDE":
                mi.include_columns = cols

        if mi.table:
            indexes.append(mi)

    return indexes


def _flatten_operators(op: SQLServerOperator, result: list[SQLServerOperator]) -> None:
    """Flatten operator tree into a list."""
    result.append(op)
    for child in op.children:
        _flatten_operators(child, result)


def _strip_brackets(s: str) -> str:
    """Remove SQL Server bracket quoting: [dbo] → dbo."""
    return s.strip("[]")


def _float_attr(elem: ET.Element | None, attr: str) -> float | None:
    """Safely extract a float attribute."""
    if elem is None:
        return None
    v = elem.get(attr)
    if v is None:
        return None
    try:
        return float(v)
    except ValueError:
        return None


def _int_attr(elem: ET.Element | None, attr: str) -> int | None:
    """Safely extract an int attribute."""
    if elem is None:
        return None
    v = elem.get(attr)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None
