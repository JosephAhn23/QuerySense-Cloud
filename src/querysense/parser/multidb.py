"""
Multi-database plan translator -- the universal adapter.

Converts execution plans from any supported database engine into the common
ExplainOutput/PlanNode format that the QuerySense analysis engine consumes.

Supported engines:
- PostgreSQL: native (no translation needed)
- MySQL: native via mysql_parser (no translation needed)
- SQL Server: XML SHOWPLAN -> ExplainOutput
- MariaDB: MySQL-compatible JSON -> ExplainOutput
- Oracle: DBMS_XPLAN text -> ExplainOutput (80% coverage)
- DuckDB: JSON EXPLAIN -> ExplainOutput
- SQLite: EXPLAIN QUERY PLAN text -> ExplainOutput
- ClickHouse: JSON EXPLAIN -> ExplainOutput

Architecture:
    Raw plan (any format) -> detect_engine() -> engine-specific parser -> to_explain_output()
                                                                              |
                                                                    ExplainOutput (common)
                                                                              |
                                                                  AnalysisService.analyze()

Usage:
    from querysense.parser.multidb import parse_any, detect_engine

    # Auto-detect engine and parse
    output = parse_any("plan.xml")  # SQL Server
    output = parse_any("plan.json") # PostgreSQL or DuckDB

    # Explicit engine
    output = parse_any("plan.txt", engine="oracle")

    # Then analyze normally
    from querysense.engine import AnalysisService
    result = AnalysisService().analyze(output)
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path
from typing import Any

from querysense.parser.models import ExplainOutput, PlanNode


class DatabaseEngine(str, Enum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"
    SQLSERVER = "sqlserver"
    ORACLE = "oracle"
    DUCKDB = "duckdb"
    SQLITE = "sqlite"
    CLICKHOUSE = "clickhouse"


# ── Engine detection ─────────────────────────────────────────────────


def detect_engine(source: str | Path) -> DatabaseEngine:
    """
    Auto-detect the database engine from plan format.

    Detection heuristics:
    - .sqlplan / .xml with ShowPlanXML -> SQL Server
    - JSON with "Plan" key -> PostgreSQL
    - JSON with "query_block" -> MySQL/MariaDB
    - JSON with "children" + "name" -> DuckDB
    - JSON with "Plan" + "Expression" -> ClickHouse
    - Text with DBMS_XPLAN markers -> Oracle
    - Text with QUERY PLAN markers -> SQLite
    """
    path = Path(source) if isinstance(source, (str, Path)) and not _looks_like_content(str(source)) else None

    if path and path.exists():
        suffix = path.suffix.lower()
        if suffix in (".sqlplan", ".xml"):
            text = path.read_text(encoding="utf-8-sig", errors="replace")[:2000]
            if "schemas.microsoft.com/sqlserver" in text or "ShowPlanXML" in text:
                return DatabaseEngine.SQLSERVER
        content = path.read_text(encoding="utf-8", errors="replace")
    else:
        content = str(source)

    text_start = content[:3000].strip()

    # SQL Server XML
    if text_start.startswith("<?xml") or "<ShowPlanXML" in text_start:
        return DatabaseEngine.SQLSERVER

    # JSON-based formats
    if text_start.startswith(("{", "[")):
        try:
            data = json.loads(content)
            if isinstance(data, list) and data:
                data = data[0]
            if isinstance(data, dict):
                if "Plan" in data:
                    # ClickHouse JSON EXPLAIN has "Expression" under Plan
                    plan = data["Plan"]
                    if isinstance(plan, dict) and "Expression" in plan:
                        return DatabaseEngine.CLICKHOUSE
                    return DatabaseEngine.POSTGRESQL
                if "query_block" in data:
                    return DatabaseEngine.MYSQL
                if "children" in data and "name" in data:
                    return DatabaseEngine.DUCKDB
                if "node_type" in data or "Node Type" in data:
                    return DatabaseEngine.DUCKDB
        except json.JSONDecodeError:
            pass

    # Oracle DBMS_XPLAN text output
    oracle_markers = ["PLAN_TABLE_OUTPUT", "Plan hash value:", "| Id  | Operation"]
    if any(m in text_start for m in oracle_markers):
        return DatabaseEngine.ORACLE

    # SQLite EXPLAIN QUERY PLAN
    if "QUERY PLAN" in text_start or re.search(r"^\|--", text_start, re.MULTILINE):
        return DatabaseEngine.SQLITE

    # Default to PostgreSQL
    return DatabaseEngine.POSTGRESQL


def _looks_like_content(s: str) -> bool:
    """Check if a string looks like plan content rather than a file path."""
    return len(s) > 500 or s.strip().startswith(("{", "[", "<", "|", "-"))


# ── Unified parser ──────────────────────────────────────────────────


def parse_any(
    source: str | Path,
    engine: str | DatabaseEngine | None = None,
    sql: str | None = None,
) -> ExplainOutput:
    """
    Parse an execution plan from any supported database engine.

    Detects the engine automatically or uses the specified one,
    then translates the plan into the common ExplainOutput format
    that the QuerySense analysis engine understands.

    Args:
        source: File path, JSON string, XML string, or text plan
        engine: Explicit engine name (auto-detected if None)
        sql: Optional SQL text associated with the plan

    Returns:
        ExplainOutput compatible with AnalysisService.analyze()
    """
    if engine is not None:
        if isinstance(engine, str):
            engine = DatabaseEngine(engine.lower())
    else:
        engine = detect_engine(source)

    # Load content
    path = None
    if isinstance(source, Path) or (
        isinstance(source, str) and not _looks_like_content(source)
    ):
        path = Path(source)
        if path.exists():
            content = path.read_text(encoding="utf-8-sig", errors="replace")
        else:
            content = source if isinstance(source, str) else ""
    else:
        content = str(source)

    # Dispatch to engine-specific translator
    if engine == DatabaseEngine.POSTGRESQL:
        return _parse_postgresql(content, sql)
    elif engine in (DatabaseEngine.MYSQL, DatabaseEngine.MARIADB):
        return _parse_mysql(content, sql)
    elif engine == DatabaseEngine.SQLSERVER:
        return _translate_sqlserver(content, sql)
    elif engine == DatabaseEngine.ORACLE:
        return _translate_oracle(content, sql)
    elif engine == DatabaseEngine.DUCKDB:
        return _translate_duckdb(content, sql)
    elif engine == DatabaseEngine.SQLITE:
        return _translate_sqlite(content, sql)
    elif engine == DatabaseEngine.CLICKHOUSE:
        return _translate_clickhouse(content, sql)
    else:
        return _parse_postgresql(content, sql)


# ── PostgreSQL (native) ─────────────────────────────────────────────


def _parse_postgresql(content: str, sql: str | None) -> ExplainOutput:
    """Native PostgreSQL -- just delegate to existing parser."""
    from querysense.parser.parser import parse_explain
    return parse_explain(content)


# ── MySQL / MariaDB ─────────────────────────────────────────────────


def _parse_mysql(content: str, sql: str | None) -> ExplainOutput:
    """
    Translate MySQL/MariaDB EXPLAIN JSON to ExplainOutput.

    MySQL's EXPLAIN JSON uses query_block -> nested_loop/ordering_operation etc.
    We flatten this into PlanNode trees.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return _minimal_output("Parse Error", sql)

    if isinstance(data, list) and data:
        data = data[0]

    query_block = data.get("query_block", data)

    root = _mysql_block_to_node(query_block)

    return ExplainOutput(
        plan=root,
        query_text=sql,
    )


def _mysql_block_to_node(block: dict[str, Any]) -> PlanNode:
    """Convert a MySQL query_block into a PlanNode."""
    children: list[PlanNode] = []

    # Detect node type from block structure
    if "ordering_operation" in block:
        op = block["ordering_operation"]
        children = [_mysql_block_to_node(op)]
        return PlanNode(
            node_type="Sort",
            startup_cost=0.0,
            total_cost=float(block.get("cost_info", {}).get("query_cost", 0)),
            plan_rows=int(op.get("rows_examined_per_scan", 0)),
            plan_width=0,
            sort_key=op.get("order_by_subqueries", []),
            plans=children,
        )

    if "nested_loop" in block:
        nl = block["nested_loop"]
        for item in nl:
            table = item.get("table", {})
            children.append(_mysql_table_to_node(table))
        if len(children) >= 2:
            return PlanNode(
                node_type="Nested Loop",
                startup_cost=0.0,
                total_cost=float(block.get("cost_info", {}).get("query_cost", 0)),
                plan_rows=int(block.get("rows_examined_per_scan", 0)),
                plan_width=0,
                join_type="Inner",
                plans=children,
            )

    if "table" in block:
        return _mysql_table_to_node(block["table"])

    cost_info = block.get("cost_info", {})
    return PlanNode(
        node_type="Result",
        startup_cost=0.0,
        total_cost=float(cost_info.get("query_cost", 0)),
        plan_rows=1,
        plan_width=0,
        plans=children,
    )


def _mysql_table_to_node(table: dict[str, Any]) -> PlanNode:
    """Convert a MySQL table access to a PlanNode."""
    access_type = table.get("access_type", "ALL")
    table_name = table.get("table_name", "")
    rows = int(table.get("rows_examined_per_scan", table.get("rows_produced_per_join", 0)))
    cost = float(table.get("cost_info", {}).get("read_cost", 0))

    node_type_map = {
        "ALL": "Seq Scan",
        "full": "Seq Scan",
        "index": "Index Only Scan",
        "range": "Index Scan",
        "ref": "Index Scan",
        "eq_ref": "Index Scan",
        "const": "Index Scan",
        "system": "Result",
        "ref_or_null": "Index Scan",
    }

    node_type = node_type_map.get(access_type, "Seq Scan")
    index_name = table.get("key", None)
    filter_cond = table.get("attached_condition", None)

    return PlanNode(
        node_type=node_type,
        startup_cost=0.0,
        total_cost=cost,
        plan_rows=rows,
        plan_width=0,
        relation_name=table_name,
        index_name=index_name,
        filter=filter_cond,
        actual_rows=int(table.get("rows_produced_per_join", 0)) or None,
    )


# ── SQL Server ──────────────────────────────────────────────────────


def _translate_sqlserver(content: str, sql: str | None) -> ExplainOutput:
    """
    Translate SQL Server Showplan XML to ExplainOutput.

    Uses the existing sqlserver_parser to parse XML, then converts
    the SQLServerOperator tree to PlanNode tree.
    """
    from querysense.parser.sqlserver_parser import parse_sqlserver_plan

    ss_output = parse_sqlserver_plan(content)

    if not ss_output.plans or not ss_output.plans[0].root_operator:
        return _minimal_output("Empty SQL Server plan", sql or ss_output.statement_text)

    root_op = ss_output.plans[0].root_operator
    root_node = _sqlserver_op_to_node(root_op)

    return ExplainOutput(
        plan=root_node,
        planning_time=float(ss_output.plans[0].compile_time_ms) if ss_output.plans else None,
        execution_time=root_op.cost.actual_elapsed_ms,
        query_text=sql or ss_output.statement_text or None,
    )


_SS_NODE_TYPE_MAP: dict[str, str] = {
    "Clustered Index Scan": "Seq Scan",
    "Table Scan": "Seq Scan",
    "Clustered Index Seek": "Index Scan",
    "Index Scan": "Index Only Scan",
    "Index Seek": "Index Scan",
    "Nested Loops": "Nested Loop",
    "Hash Match": "Hash Join",
    "Merge Join": "Merge Join",
    "Adaptive Join": "Hash Join",
    "Sort": "Sort",
    "Stream Aggregate": "Aggregate",
    "Hash Aggregate": "HashAggregate",
    "Compute Scalar": "Result",
    "Filter": "Result",
    "Top": "Limit",
    "Parallelism": "Gather",
    "Table Spool": "Materialize",
    "Index Spool": "Materialize",
    "Key Lookup": "Index Scan",
    "RID Lookup": "Tid Scan",
    "Concatenation": "Append",
    "Constant Scan": "Result",
    "Table Insert": "ModifyTable",
    "Table Update": "ModifyTable",
    "Table Delete": "ModifyTable",
    "Clustered Index Insert": "ModifyTable",
    "Clustered Index Update": "ModifyTable",
    "Clustered Index Delete": "ModifyTable",
    "Bitmap": "BitmapAnd",
    "Window Spool": "WindowAgg",
    "Sequence": "Append",
}


def _sqlserver_op_to_node(op: Any) -> PlanNode:
    """Recursively convert SQLServerOperator to PlanNode."""
    pg_node_type = _SS_NODE_TYPE_MAP.get(op.physical_op, op.physical_op)

    children = [_sqlserver_op_to_node(c) for c in op.children]

    # Determine join type from logical op
    join_type = None
    if op.is_join:
        if "Inner" in op.logical_op:
            join_type = "Inner"
        elif "Left" in op.logical_op:
            join_type = "Left"
        elif "Right" in op.logical_op:
            join_type = "Right"
        elif "Full" in op.logical_op:
            join_type = "Full"
        elif "Semi" in op.logical_op:
            join_type = "Semi"
        elif "Anti" in op.logical_op:
            join_type = "Anti"

    # Build filter string from predicates
    filter_str = "; ".join(op.predicates) if op.predicates else None

    return PlanNode(
        node_type=pg_node_type,
        startup_cost=0.0,
        total_cost=op.cost.estimated_total_subtree_cost * 1000,  # normalize to PG-like scale
        plan_rows=max(1, int(op.cost.estimated_rows)),
        plan_width=op.cost.estimated_row_size or 0,
        actual_rows=op.cost.actual_rows,
        actual_total_time=op.cost.actual_elapsed_ms,
        actual_loops=op.cost.actual_executions,
        relation_name=op.object_ref.table if op.object_ref else None,
        schema_name=op.object_ref.schema_name if op.object_ref else None,
        index_name=op.object_ref.index if op.object_ref else None,
        join_type=join_type,
        filter=filter_str,
        workers_planned=op.degree_of_parallelism,
        plans=children,
    )


# ── Oracle DBMS_XPLAN ──────────────────────────────────────────────


def _translate_oracle(content: str, sql: str | None) -> ExplainOutput:
    """
    Translate Oracle DBMS_XPLAN text output to ExplainOutput.

    Parses the tabular format:
        | Id  | Operation                | Name   | Rows  | Bytes | Cost (%CPU)| Time     |
        |   0 | SELECT STATEMENT         |        |  1000 | 50000 |   123  (5)| 00:00:01 |
        |   1 |  TABLE ACCESS FULL       | ORDERS |  1000 | 50000 |   123  (5)| 00:00:01 |

    Builds a PlanNode tree from indentation levels.
    """
    lines = content.strip().split("\n")
    rows: list[dict[str, Any]] = []

    # Find the header line and data lines
    in_table = False
    for line in lines:
        stripped = line.strip()

        # Detect table start
        if re.match(r"\|\s+Id\s+\|\s+Operation", stripped):
            in_table = True
            continue

        if in_table and stripped.startswith("|") and not stripped.startswith("|-"):
            parsed = _parse_oracle_row(stripped)
            if parsed:
                rows.append(parsed)
        elif in_table and stripped.startswith("--"):
            continue
        elif in_table and not stripped.startswith("|"):
            in_table = False

    if not rows:
        return _minimal_output("Could not parse Oracle plan", sql)

    # Build tree from indentation
    root_node = _build_oracle_tree(rows)

    # Extract plan hash if present
    plan_hash_match = re.search(r"Plan hash value:\s*(\d+)", content)

    return ExplainOutput(
        plan=root_node,
        query_text=sql,
    )


_ORACLE_NODE_MAP: dict[str, str] = {
    "SELECT STATEMENT": "Result",
    "TABLE ACCESS FULL": "Seq Scan",
    "TABLE ACCESS BY INDEX ROWID": "Index Scan",
    "TABLE ACCESS BY INDEX ROWID BATCHED": "Index Scan",
    "INDEX FULL SCAN": "Index Only Scan",
    "INDEX RANGE SCAN": "Index Scan",
    "INDEX UNIQUE SCAN": "Index Scan",
    "INDEX FAST FULL SCAN": "Bitmap Index Scan",
    "INDEX SKIP SCAN": "Index Scan",
    "NESTED LOOPS": "Nested Loop",
    "HASH JOIN": "Hash Join",
    "MERGE JOIN": "Merge Join",
    "SORT JOIN": "Sort",
    "SORT ORDER BY": "Sort",
    "SORT AGGREGATE": "Aggregate",
    "SORT GROUP BY": "HashAggregate",
    "SORT UNIQUE": "Unique",
    "HASH GROUP BY": "HashAggregate",
    "HASH UNIQUE": "Unique",
    "HASH JOIN ANTI": "Hash Join",
    "HASH JOIN SEMI": "Hash Join",
    "FILTER": "Result",
    "VIEW": "Subquery Scan",
    "UNION-ALL": "Append",
    "UNION ALL": "Append",
    "CONCATENATION": "Append",
    "COUNT STOPKEY": "Limit",
    "INLIST ITERATOR": "Result",
    "PARTITION RANGE ALL": "Append",
    "PARTITION RANGE SINGLE": "Result",
    "BITMAP CONVERSION TO ROWIDS": "Bitmap Heap Scan",
    "BITMAP INDEX SINGLE VALUE": "Bitmap Index Scan",
    "BITMAP AND": "BitmapAnd",
    "BITMAP OR": "BitmapOr",
    "MAT_VIEW ACCESS FULL": "Seq Scan",
    "WINDOW SORT": "WindowAgg",
    "PX COORDINATOR": "Gather",
    "PX SEND QC": "Gather",
    "PX BLOCK ITERATOR": "Gather",
}


def _parse_oracle_row(line: str) -> dict[str, Any] | None:
    """Parse a single Oracle DBMS_XPLAN row."""
    # Format: | Id | Operation | Name | Rows | Bytes | Cost (%CPU)| Time |
    parts = [p.strip() for p in line.split("|")]
    parts = [p for p in parts if p != ""]

    if len(parts) < 4:
        return None

    try:
        node_id = int(parts[0])
    except ValueError:
        return None

    operation = parts[1] if len(parts) > 1 else ""
    name = parts[2] if len(parts) > 2 else ""

    rows = 0
    if len(parts) > 3:
        try:
            rows = int(parts[3].replace("K", "000").replace("M", "000000"))
        except ValueError:
            pass

    bytes_est = 0
    if len(parts) > 4:
        try:
            bytes_est = int(parts[4].replace("K", "000").replace("M", "000000"))
        except ValueError:
            pass

    cost = 0.0
    if len(parts) > 5:
        cost_match = re.match(r"(\d+)", parts[5])
        if cost_match:
            cost = float(cost_match.group(1))

    # Indentation indicates tree depth
    indent = len(operation) - len(operation.lstrip())
    operation_clean = operation.strip().rstrip("*")  # Remove asterisk markers

    return {
        "id": node_id,
        "operation": operation_clean,
        "name": name,
        "rows": rows,
        "bytes": bytes_est,
        "cost": cost,
        "indent": indent,
    }


def _build_oracle_tree(rows: list[dict[str, Any]]) -> PlanNode:
    """Build PlanNode tree from Oracle rows using indentation."""
    if not rows:
        return _minimal_node("Empty Plan")

    # Convert each row to a PlanNode
    nodes: list[tuple[int, PlanNode]] = []
    for row in rows:
        op = row["operation"]
        pg_type = _ORACLE_NODE_MAP.get(op.upper(), op)

        node = PlanNode(
            node_type=pg_type,
            startup_cost=0.0,
            total_cost=row["cost"],
            plan_rows=max(1, row["rows"]),
            plan_width=row.get("bytes", 0) // max(1, row["rows"]) if row["rows"] > 0 else 0,
            relation_name=row["name"] if row["name"] else None,
        )
        nodes.append((row["indent"], node))

    # Build tree using indentation levels
    if len(nodes) == 1:
        return nodes[0][1]

    # Stack-based tree building
    stack: list[tuple[int, PlanNode]] = [nodes[0]]
    for indent, node in nodes[1:]:
        # Pop stack until we find the parent (lower indent)
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        # Add as child of current top
        stack[-1][1].plans.append(node)
        stack.append((indent, node))

    return nodes[0][1]


# ── DuckDB ──────────────────────────────────────────────────────────


def _translate_duckdb(content: str, sql: str | None) -> ExplainOutput:
    """
    Translate DuckDB JSON EXPLAIN to ExplainOutput.

    DuckDB's EXPLAIN (FORMAT JSON) produces:
    {
        "name": "HASH_JOIN",
        "timing": 0.001,
        "cardinality": 1000,
        "extra_info": "JOIN condition: ...",
        "children": [...]
    }
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return _minimal_output("DuckDB parse error", sql)

    if isinstance(data, list) and data:
        data = data[0]

    root = _duckdb_node_to_plan(data)

    # Extract total time if available
    exec_time = None
    if hasattr(root, "actual_total_time") and root.actual_total_time is not None:
        exec_time = root.actual_total_time

    return ExplainOutput(
        plan=root,
        execution_time=exec_time,
        query_text=sql,
    )


_DUCKDB_NODE_MAP: dict[str, str] = {
    "SEQ_SCAN": "Seq Scan",
    "TABLE_SCAN": "Seq Scan",
    "INDEX_SCAN": "Index Scan",
    "FILTER": "Result",
    "PROJECTION": "Result",
    "HASH_JOIN": "Hash Join",
    "PIECEWISE_MERGE_JOIN": "Merge Join",
    "NESTED_LOOP_JOIN": "Nested Loop",
    "CROSS_PRODUCT": "Nested Loop",
    "HASH_GROUP_BY": "HashAggregate",
    "PERFECT_HASH_GROUP_BY": "HashAggregate",
    "ORDER_BY": "Sort",
    "TOP_N": "Limit",
    "LIMIT": "Limit",
    "STREAMING_LIMIT": "Limit",
    "UNGROUPED_AGGREGATE": "Aggregate",
    "WINDOW": "WindowAgg",
    "UNION": "Append",
    "RECURSIVE_CTE": "Recursive Union",
    "CTE_SCAN": "CTE Scan",
    "RESULT_COLLECTOR": "Gather",
    "COLUMN_DATA_SCAN": "Seq Scan",  # columnar scan
    "PARQUET_SCAN": "Foreign Scan",
    "CSV_SCAN": "Foreign Scan",
    "READ_CSV": "Foreign Scan",
    "READ_PARQUET": "Foreign Scan",
    "DELIM_SCAN": "Foreign Scan",
    "EMPTY_RESULT": "Result",
    "CHUNK_SCAN": "Seq Scan",
    "CREATE_TABLE_AS": "ModifyTable",
    "INSERT": "ModifyTable",
    "UPDATE": "ModifyTable",
    "DELETE": "ModifyTable",
}


def _duckdb_node_to_plan(data: dict[str, Any]) -> PlanNode:
    """Convert a DuckDB node to PlanNode."""
    name = data.get("name", data.get("node_type", "Unknown"))
    pg_type = _DUCKDB_NODE_MAP.get(name.upper(), name)

    timing = data.get("timing", None)
    cardinality = data.get("cardinality", data.get("estimated_cardinality", 0))
    extra = data.get("extra_info", "")

    children = [
        _duckdb_node_to_plan(c) for c in data.get("children", [])
    ]

    # Extract table name from extra_info
    table_name = None
    table_match = re.search(r"\[([A-Za-z_]\w*)\]", extra)
    if table_match:
        table_name = table_match.group(1)

    # Extract filter from extra_info
    filter_str = None
    if "Filters:" in extra:
        filter_str = extra.split("Filters:")[-1].strip()
    elif "Filter:" in extra:
        filter_str = extra.split("Filter:")[-1].strip()

    # Extract join condition
    join_type = None
    if "JOIN" in name.upper():
        join_type = "Inner"
        if "LEFT" in name.upper():
            join_type = "Left"
        elif "RIGHT" in name.upper():
            join_type = "Right"
        elif "FULL" in name.upper():
            join_type = "Full"
        elif "SEMI" in name.upper():
            join_type = "Semi"
        elif "ANTI" in name.upper():
            join_type = "Anti"
        elif "CROSS" in name.upper():
            join_type = "Inner"

    # Cost estimation (DuckDB doesn't expose costs the same way)
    child_cost = sum(c.total_cost for c in children) if children else 0
    est_cost = child_cost + max(1, cardinality) * 0.01  # rough approximation

    return PlanNode(
        node_type=pg_type,
        startup_cost=0.0,
        total_cost=est_cost,
        plan_rows=max(1, int(cardinality)),
        plan_width=0,
        actual_total_time=timing * 1000 if timing is not None else None,  # sec -> ms
        actual_rows=int(cardinality) if cardinality else None,
        actual_loops=1 if timing is not None else None,
        relation_name=table_name,
        join_type=join_type,
        filter=filter_str,
        plans=children,
    )


# ── SQLite ──────────────────────────────────────────────────────────


def _translate_sqlite(content: str, sql: str | None) -> ExplainOutput:
    """
    Translate SQLite EXPLAIN QUERY PLAN output to ExplainOutput.

    SQLite format:
        QUERY PLAN
        |--SCAN orders
        |--SEARCH users USING INDEX idx_users_email (email=?)
        `--USE TEMP B-TREE FOR ORDER BY
    """
    lines = content.strip().split("\n")
    ops: list[dict[str, Any]] = []

    for line in lines:
        stripped = line.strip()
        if stripped in ("QUERY PLAN", "") or stripped.startswith("--"):
            continue

        # Parse indentation from tree markers
        depth = 0
        clean = stripped
        for marker in ["|--", "`--", "|  ", "   "]:
            while clean.startswith(marker):
                depth += 1
                clean = clean[len(marker):]
        clean = clean.strip()

        if not clean:
            continue

        op_info = _parse_sqlite_op(clean)
        op_info["depth"] = depth
        ops.append(op_info)

    if not ops:
        return _minimal_output("Empty SQLite plan", sql)

    root = _build_sqlite_tree(ops)

    return ExplainOutput(
        plan=root,
        query_text=sql,
    )


_SQLITE_OP_MAP: dict[str, str] = {
    "SCAN": "Seq Scan",
    "SEARCH": "Index Scan",
    "COMPOUND": "Append",
    "MERGE": "Merge Join",
    "MULTI-INDEX OR": "BitmapOr",
    "SUBQUERY": "Subquery Scan",
    "CO-ROUTINE": "CTE Scan",
    "SCALAR SUBQUERY": "Subquery Scan",
}


def _parse_sqlite_op(text: str) -> dict[str, Any]:
    """Parse a single SQLite operation line."""
    # SCAN table_name
    # SEARCH table_name USING INDEX idx (col=?)
    # SEARCH table_name USING COVERING INDEX idx (col=?)
    # USE TEMP B-TREE FOR ORDER BY
    # USE TEMP B-TREE FOR GROUP BY
    # COMPOUND SUBQUERIES n AND m (UNION ALL)

    parts = text.split()
    op_type = parts[0] if parts else "UNKNOWN"

    table_name = None
    index_name = None
    is_covering = False
    filter_str = None

    if op_type in ("SCAN", "SEARCH") and len(parts) > 1:
        table_name = parts[1]

        if "USING INDEX" in text or "USING COVERING INDEX" in text:
            idx_match = re.search(r"USING (?:COVERING )?INDEX\s+(\S+)", text)
            if idx_match:
                index_name = idx_match.group(1)
            is_covering = "COVERING" in text

        # Extract condition
        cond_match = re.search(r"\(([^)]+)\)", text)
        if cond_match:
            filter_str = cond_match.group(1)

    node_type = _SQLITE_OP_MAP.get(op_type, "Result")

    if "TEMP B-TREE" in text:
        if "ORDER BY" in text:
            node_type = "Sort"
        elif "GROUP BY" in text:
            node_type = "HashAggregate"
        elif "DISTINCT" in text:
            node_type = "Unique"

    if is_covering:
        node_type = "Index Only Scan"

    return {
        "node_type": node_type,
        "table_name": table_name,
        "index_name": index_name,
        "filter": filter_str,
        "raw_text": text,
    }


def _build_sqlite_tree(ops: list[dict[str, Any]]) -> PlanNode:
    """Build PlanNode tree from SQLite operations."""
    if not ops:
        return _minimal_node("Empty")

    nodes: list[tuple[int, PlanNode]] = []
    for op in ops:
        node = PlanNode(
            node_type=op["node_type"],
            startup_cost=0.0,
            total_cost=1.0,  # SQLite doesn't expose cost estimates
            plan_rows=1,
            plan_width=0,
            relation_name=op.get("table_name"),
            index_name=op.get("index_name"),
            filter=op.get("filter"),
        )
        nodes.append((op.get("depth", 0), node))

    # If only one node, wrap in a Result
    if len(nodes) == 1:
        return nodes[0][1]

    # Build tree
    root = PlanNode(
        node_type="Result",
        startup_cost=0.0,
        total_cost=1.0,
        plan_rows=1,
        plan_width=0,
        plans=[n for _, n in nodes],
    )
    return root


# ── ClickHouse ──────────────────────────────────────────────────────


def _translate_clickhouse(content: str, sql: str | None) -> ExplainOutput:
    """
    Translate ClickHouse EXPLAIN JSON to ExplainOutput.

    ClickHouse EXPLAIN PLAN output (JSON format):
    {
        "Plan": {
            "Node Type": "Expression",
            "Description": "...",
            "Plans": [
                {"Node Type": "ReadFromMergeTree", ...}
            ]
        }
    }
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return _minimal_output("ClickHouse parse error", sql)

    if isinstance(data, list) and data:
        data = data[0]

    plan_data = data.get("Plan", data)
    root = _clickhouse_node_to_plan(plan_data)

    return ExplainOutput(
        plan=root,
        query_text=sql,
    )


_CH_NODE_MAP: dict[str, str] = {
    "ReadFromMergeTree": "Seq Scan",
    "ReadFromRemote": "Foreign Scan",
    "ReadFromSystemNumbers": "Function Scan",
    "Expression": "Result",
    "Filter": "Result",
    "Aggregating": "HashAggregate",
    "Sorting": "Sort",
    "Limit": "Limit",
    "MergingSorted": "Merge Join",
    "Union": "Append",
    "Join": "Hash Join",
    "CreatingSets": "Materialize",
    "SettingQuotaAndLimits": "Result",
    "ReadFromStorage": "Seq Scan",
    "ReadFromPreparedSource": "CTE Scan",
    "Distinct": "Unique",
    "Window": "WindowAgg",
    "Rollup": "HashAggregate",
    "Cube": "HashAggregate",
    "TotalsHaving": "HashAggregate",
    "FillingRightJoinSide": "Hash",
    "CreatingStreamOnBlock": "Materialize",
}


def _clickhouse_node_to_plan(data: dict[str, Any]) -> PlanNode:
    """Convert a ClickHouse plan node to PlanNode."""
    ch_type = data.get("Node Type", data.get("name", "Unknown"))
    pg_type = _CH_NODE_MAP.get(ch_type, ch_type)

    description = data.get("Description", data.get("description", ""))
    rows = int(data.get("Rows", data.get("estimated_rows", 1)))

    children = [
        _clickhouse_node_to_plan(c) for c in data.get("Plans", data.get("children", []))
    ]

    # Extract table name from description or Node Type
    table_name = None
    if "ReadFrom" in ch_type:
        table_match = re.search(r"(\w+)$", description)
        if table_match:
            table_name = table_match.group(1)

    # Extract filter
    filter_str = None
    if "WHERE" in description:
        filter_str = description.split("WHERE")[-1].strip()
    elif "PREWHERE" in description:
        filter_str = description.split("PREWHERE")[-1].strip()

    child_cost = sum(c.total_cost for c in children)
    est_cost = child_cost + max(1, rows) * 0.01

    return PlanNode(
        node_type=pg_type,
        startup_cost=0.0,
        total_cost=est_cost,
        plan_rows=max(1, rows),
        plan_width=0,
        relation_name=table_name,
        filter=filter_str,
        plans=children,
    )


# ── Helpers ─────────────────────────────────────────────────────────


def _minimal_output(message: str, sql: str | None = None) -> ExplainOutput:
    """Create a minimal ExplainOutput for error/empty cases."""
    return ExplainOutput(
        plan=_minimal_node(message),
        query_text=sql,
    )


def _minimal_node(label: str) -> PlanNode:
    return PlanNode(
        node_type="Result",
        startup_cost=0.0,
        total_cost=0.0,
        plan_rows=0,
        plan_width=0,
    )
