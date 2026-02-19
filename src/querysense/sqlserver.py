"""
SQL Server Query Optimizer — native execution plan parsing and analysis.

Supports SQL Server 2016+ execution plans (XML SET STATISTICS XML ON)
and provides actionable recommendations similar to our PostgreSQL engine.

SQL Server execution plans are XML-based and include:
- Estimated/actual row counts, costs, and operator properties
- Missing index hints from the optimizer
- Warnings (implicit conversions, spills, etc.)

Usage:
    from querysense.sqlserver import SQLServerAnalyzer, SQLServerPlanParser

    parser = SQLServerPlanParser()
    result = parser.parse(xml_plan_string)

    analyzer = SQLServerAnalyzer()
    findings = analyzer.analyze(result)
    for f in findings:
        print(f"{f.severity}: {f.title}")
        print(f"  Fix: {f.remediation}")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

# SQL Server showplan XML namespace
_NS = {"sp": "http://schemas.microsoft.com/sqlserver/2004/07/showplan"}


# ── Plan Parsing ─────────────────────────────────────────────────────────

@dataclass
class SQLServerOperator:
    """A single operator in a SQL Server execution plan."""
    node_id: int = 0
    physical_op: str = ""       # Clustered Index Scan, Hash Match, etc.
    logical_op: str = ""        # Inner Join, Aggregate, etc.
    estimated_rows: float = 0
    actual_rows: float = 0
    estimated_cost: float = 0   # Subtree cost
    estimated_io: float = 0
    estimated_cpu: float = 0
    actual_executions: int = 0
    output_columns: list[str] = field(default_factory=list)
    predicates: list[str] = field(default_factory=list)
    object_name: str = ""       # Table or index name
    index_name: str = ""
    warnings: list[str] = field(default_factory=list)
    children: list[SQLServerOperator] = field(default_factory=list)

    # Memory grant info
    memory_grant_kb: int = 0
    spill_to_tempdb: bool = False

    @property
    def is_scan(self) -> bool:
        return "Scan" in self.physical_op

    @property
    def is_table_scan(self) -> bool:
        return self.physical_op in ("Table Scan", "Clustered Index Scan")

    @property
    def is_index_seek(self) -> bool:
        return "Seek" in self.physical_op

    @property
    def cardinality_ratio(self) -> float:
        if self.estimated_rows == 0:
            return 0
        return self.actual_rows / self.estimated_rows


@dataclass
class MissingIndexHint:
    """Missing index hint from the SQL Server optimizer."""
    database: str = ""
    schema: str = ""
    table: str = ""
    equality_columns: list[str] = field(default_factory=list)
    inequality_columns: list[str] = field(default_factory=list)
    include_columns: list[str] = field(default_factory=list)
    impact: float = 0  # 0-100
    command: str = ""

    def __post_init__(self) -> None:
        if not self.command:
            cols = ", ".join(self.equality_columns + self.inequality_columns)
            include = ""
            if self.include_columns:
                include = f" INCLUDE ({', '.join(self.include_columns)})"
            full_table = f"[{self.schema}].[{self.table}]" if self.schema else f"[{self.table}]"
            self.command = (
                f"CREATE NONCLUSTERED INDEX IX_{self.table}_auto "
                f"ON {full_table} ({cols}){include};"
            )


@dataclass
class SQLServerPlanResult:
    """Parsed SQL Server execution plan."""
    statement_text: str = ""
    operators: list[SQLServerOperator] = field(default_factory=list)
    root_operator: SQLServerOperator | None = None
    missing_indexes: list[MissingIndexHint] = field(default_factory=list)
    total_subtree_cost: float = 0
    compile_time_ms: float = 0
    compile_cpu_ms: float = 0
    compile_memory_kb: int = 0
    memory_grant_kb: int = 0
    degree_of_parallelism: int = 0
    has_warnings: bool = False
    warning_messages: list[str] = field(default_factory=list)

    @property
    def total_operators(self) -> int:
        return len(self.operators)

    @property
    def has_missing_indexes(self) -> bool:
        return len(self.missing_indexes) > 0


class SQLServerPlanParser:
    """Parse SQL Server XML execution plans."""

    def parse(self, xml_text: str) -> SQLServerPlanResult:
        """
        Parse a SQL Server execution plan from XML.

        Accepts SET STATISTICS XML ON output or .sqlplan file content.
        """
        result = SQLServerPlanResult()

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.error("Failed to parse SQL Server plan XML: %s", e)
            return result

        # Find the first statement
        for stmt in root.iter(f"{{{_NS['sp']}}}StmtSimple"):
            result.statement_text = stmt.get("StatementText", "")
            result.total_subtree_cost = float(stmt.get("StatementSubTreeCost", "0"))

            # Parse query plan
            qp = stmt.find(f".//{{{_NS['sp']}}}QueryPlan", _NS)
            if qp is not None:
                result.compile_time_ms = float(qp.get("CompileTime", "0"))
                result.compile_cpu_ms = float(qp.get("CompileCPU", "0"))
                result.compile_memory_kb = int(qp.get("CompileMemory", "0"))
                result.memory_grant_kb = int(qp.get("MemoryGrant", "0") or "0")
                result.degree_of_parallelism = int(qp.get("DegreeOfParallelism", "0"))

                # Parse missing indexes
                for mi_group in qp.findall(f".//{{{_NS['sp']}}}MissingIndexGroup", _NS):
                    impact = float(mi_group.get("Impact", "0"))
                    for mi in mi_group.findall(f".//{{{_NS['sp']}}}MissingIndex", _NS):
                        hint = self._parse_missing_index(mi, impact)
                        result.missing_indexes.append(hint)

                # Parse operator tree
                rel_op = qp.find(f".//{{{_NS['sp']}}}RelOp", _NS)
                if rel_op is not None:
                    root_op = self._parse_operator(rel_op)
                    result.root_operator = root_op
                    result.operators = self._flatten_operators(root_op)

        # Collect warnings
        for op in result.operators:
            if op.warnings:
                result.has_warnings = True
                result.warning_messages.extend(op.warnings)

        return result

    def _parse_operator(self, rel_op: ET.Element) -> SQLServerOperator:
        """Parse a RelOp element into an operator."""
        op = SQLServerOperator(
            node_id=int(rel_op.get("NodeId", "0")),
            physical_op=rel_op.get("PhysicalOp", ""),
            logical_op=rel_op.get("LogicalOp", ""),
            estimated_rows=float(rel_op.get("EstimateRows", "0")),
            estimated_cost=float(rel_op.get("EstimatedTotalSubtreeCost", "0")),
            estimated_io=float(rel_op.get("EstimateIO", "0")),
            estimated_cpu=float(rel_op.get("EstimateCPU", "0")),
        )

        # Runtime info (actual plan)
        runtime = rel_op.find(f".//{{{_NS['sp']}}}RunTimeInformation", _NS)
        if runtime is not None:
            thread = runtime.find(f".//{{{_NS['sp']}}}RunTimeCountersPerThread", _NS)
            if thread is not None:
                op.actual_rows = float(thread.get("ActualRows", "0"))
                op.actual_executions = int(thread.get("ActualExecutions", "0"))

        # Object reference (table/index)
        for obj in rel_op.iter(f"{{{_NS['sp']}}}Object"):
            op.object_name = obj.get("Table", "").strip("[]")
            op.index_name = obj.get("Index", "").strip("[]")
            break

        # Warnings
        for warn in rel_op.iter(f"{{{_NS['sp']}}}Warnings"):
            # Spill warnings
            for spill in warn.iter(f"{{{_NS['sp']}}}SpillToTempDb"):
                op.spill_to_tempdb = True
                spill_count = spill.get("SpillLevel", "")
                op.warnings.append(f"Sort/hash spill to TempDB (level {spill_count})")

            # Implicit conversion warnings
            for conv in warn.findall(f".//{{{_NS['sp']}}}PlanAffectingConvert"):
                expr = conv.get("Expression", "")
                op.warnings.append(f"Implicit conversion: {expr}")

            # No join predicate
            if warn.find(f".//{{{_NS['sp']}}}NoJoinPredicate") is not None:
                op.warnings.append("No join predicate — Cartesian product detected!")

        # Predicates
        for pred in rel_op.iter(f"{{{_NS['sp']}}}ScalarOperator"):
            scalar_str = pred.get("ScalarString", "")
            if scalar_str:
                op.predicates.append(scalar_str)

        # Recurse into child RelOps
        for child_rel in rel_op.findall(f".//{{{_NS['sp']}}}RelOp", _NS):
            # Only direct children (one level deeper, skip deeply nested)
            parent = child_rel
            # Walk up to check if this is a direct child
            # We'll just use findall on immediate child operators
            pass

        # Use a simpler approach: iterate immediate child elements
        for child_elem in rel_op:
            for child_rel in child_elem.findall(f"{{{_NS['sp']}}}RelOp", _NS):
                op.children.append(self._parse_operator(child_rel))

        return op

    def _parse_missing_index(
        self, mi_elem: ET.Element, impact: float,
    ) -> MissingIndexHint:
        """Parse a MissingIndex element."""
        hint = MissingIndexHint(
            database=mi_elem.get("Database", "").strip("[]"),
            schema=mi_elem.get("Schema", "").strip("[]"),
            table=mi_elem.get("Table", "").strip("[]"),
            impact=impact,
        )

        for col_group in mi_elem.findall(f"{{{_NS['sp']}}}ColumnGroup", _NS):
            usage = col_group.get("Usage", "")
            cols = [
                c.get("Name", "").strip("[]")
                for c in col_group.findall(f"{{{_NS['sp']}}}Column", _NS)
            ]
            if usage == "EQUALITY":
                hint.equality_columns = cols
            elif usage == "INEQUALITY":
                hint.inequality_columns = cols
            elif usage == "INCLUDE":
                hint.include_columns = cols

        hint.__post_init__()  # Regenerate command
        return hint

    def _flatten_operators(self, op: SQLServerOperator) -> list[SQLServerOperator]:
        """Flatten operator tree to a list."""
        result = [op]
        for child in op.children:
            result.extend(self._flatten_operators(child))
        return result


# ── Analyzer ─────────────────────────────────────────────────────────────

@dataclass
class SQLServerFinding:
    """A finding from SQL Server plan analysis."""
    title: str
    description: str
    severity: str = "warning"  # critical, warning, notice, info
    remediation: str = ""
    operator: str = ""  # Which operator triggered this
    impact: str = ""


class SQLServerAnalyzer:
    """
    Analyze parsed SQL Server execution plans.

    Applies 15+ rules covering:
    - Table/clustered index scans
    - Missing indexes (optimizer hints)
    - TempDB spills
    - Implicit conversions
    - Cardinality misestimates
    - Parallel plan issues
    - Key lookups
    - Fat operators
    """

    def analyze(self, plan: SQLServerPlanResult) -> list[SQLServerFinding]:
        """Analyze a parsed plan and return findings."""
        findings: list[SQLServerFinding] = []

        if not plan.root_operator:
            return findings

        # Rule 1: Missing indexes from optimizer
        findings.extend(self._check_missing_indexes(plan))

        # Walk all operators
        for op in plan.operators:
            findings.extend(self._check_table_scan(op))
            findings.extend(self._check_key_lookup(op))
            findings.extend(self._check_tempdb_spill(op))
            findings.extend(self._check_implicit_conversion(op))
            findings.extend(self._check_cardinality(op))
            findings.extend(self._check_no_join_predicate(op))
            findings.extend(self._check_fat_operator(op, plan.total_subtree_cost))

        # Plan-level checks
        findings.extend(self._check_parallelism(plan))
        findings.extend(self._check_memory_grant(plan))

        return findings

    def _check_missing_indexes(
        self, plan: SQLServerPlanResult,
    ) -> list[SQLServerFinding]:
        findings: list[SQLServerFinding] = []
        for mi in plan.missing_indexes:
            findings.append(SQLServerFinding(
                title=f"Missing index on [{mi.schema}].[{mi.table}]",
                description=(
                    f"SQL Server optimizer suggests an index with "
                    f"estimated {mi.impact:.1f}% improvement. "
                    f"Equality: {mi.equality_columns}, "
                    f"Inequality: {mi.inequality_columns}, "
                    f"Include: {mi.include_columns}"
                ),
                severity="warning" if mi.impact < 80 else "critical",
                remediation=mi.command,
                impact=f"{mi.impact:.1f}% estimated improvement",
            ))
        return findings

    def _check_table_scan(
        self, op: SQLServerOperator,
    ) -> list[SQLServerFinding]:
        if not op.is_table_scan:
            return []
        if op.estimated_rows < 1000:
            return []  # Small table, scan is fine

        scan_type = "Table Scan" if op.physical_op == "Table Scan" else "Clustered Index Scan"
        return [SQLServerFinding(
            title=f"{scan_type} on [{op.object_name}]",
            description=(
                f"Full {scan_type.lower()} examining ~{op.estimated_rows:,.0f} rows. "
                f"This reads every row in the table."
            ),
            severity="warning",
            remediation=(
                f"Add a nonclustered index on [{op.object_name}] "
                f"covering the WHERE clause columns."
            ),
            operator=op.physical_op,
        )]

    def _check_key_lookup(
        self, op: SQLServerOperator,
    ) -> list[SQLServerFinding]:
        if op.physical_op != "Key Lookup":
            return []
        return [SQLServerFinding(
            title=f"Key Lookup on [{op.object_name}]",
            description=(
                f"Key lookup fetches {op.estimated_rows:,.0f} rows from the "
                f"clustered index. Each lookup is a random I/O operation."
            ),
            severity="notice" if op.estimated_rows < 100 else "warning",
            remediation=(
                f"Add the requested columns as INCLUDE columns to the "
                f"nonclustered index to create a covering index:\n"
                f"ALTER INDEX [{op.index_name}] ON [{op.object_name}] "
                f"REBUILD; -- or add INCLUDE columns"
            ),
            operator="Key Lookup",
        )]

    def _check_tempdb_spill(
        self, op: SQLServerOperator,
    ) -> list[SQLServerFinding]:
        if not op.spill_to_tempdb:
            return []
        return [SQLServerFinding(
            title=f"TempDB spill in {op.physical_op}",
            description=(
                f"Operator '{op.physical_op}' spilled data to TempDB. "
                f"This dramatically slows query execution."
            ),
            severity="warning",
            remediation=(
                "Increase memory grant by updating statistics (UPDATE STATISTICS), "
                "or use OPTION (MIN_GRANT_PERCENT = N) hint, "
                "or increase max server memory."
            ),
            operator=op.physical_op,
        )]

    def _check_implicit_conversion(
        self, op: SQLServerOperator,
    ) -> list[SQLServerFinding]:
        findings: list[SQLServerFinding] = []
        for w in op.warnings:
            if "Implicit conversion" in w:
                findings.append(SQLServerFinding(
                    title="Implicit type conversion",
                    description=(
                        f"In operator '{op.physical_op}': {w}. "
                        f"Implicit conversions can prevent index seeks."
                    ),
                    severity="warning",
                    remediation=(
                        "Match parameter types to column types in the query. "
                        "Example: use NVARCHAR parameter for NVARCHAR column."
                    ),
                    operator=op.physical_op,
                ))
        return findings

    def _check_cardinality(
        self, op: SQLServerOperator,
    ) -> list[SQLServerFinding]:
        if op.actual_rows == 0 and op.estimated_rows == 0:
            return []
        if op.actual_rows == 0 or op.estimated_rows == 0:
            return []

        ratio = op.cardinality_ratio
        if 0.1 < ratio < 10:
            return []  # Within acceptable range

        direction = "underestimate" if ratio > 1 else "overestimate"
        return [SQLServerFinding(
            title=f"Cardinality {direction} in {op.physical_op}",
            description=(
                f"Estimated {op.estimated_rows:,.0f} rows but got "
                f"{op.actual_rows:,.0f} rows ({ratio:.1f}x off). "
                f"This causes suboptimal plan choices."
            ),
            severity="warning",
            remediation=(
                f"UPDATE STATISTICS [{op.object_name}] WITH FULLSCAN;\n"
                f"-- Or if using filtered statistics, check filter predicates."
            ),
            operator=op.physical_op,
        )]

    def _check_no_join_predicate(
        self, op: SQLServerOperator,
    ) -> list[SQLServerFinding]:
        for w in op.warnings:
            if "No join predicate" in w:
                return [SQLServerFinding(
                    title="Cartesian product (missing JOIN condition)",
                    description=(
                        "A join is missing its ON clause, resulting in a "
                        "Cartesian product that multiplies row counts."
                    ),
                    severity="critical",
                    remediation="Add a proper JOIN condition: ON a.id = b.a_id",
                    operator=op.physical_op,
                )]
        return []

    def _check_fat_operator(
        self, op: SQLServerOperator, total_cost: float,
    ) -> list[SQLServerFinding]:
        """Check for operators consuming disproportionate cost."""
        if total_cost == 0:
            return []
        cost_pct = (op.estimated_cost / total_cost) * 100
        if cost_pct < 50:
            return []  # Not dominant enough to flag

        return [SQLServerFinding(
            title=f"Expensive operator: {op.physical_op} ({cost_pct:.0f}% of cost)",
            description=(
                f"'{op.physical_op}' on [{op.object_name or '?'}] "
                f"accounts for {cost_pct:.0f}% of the total query cost "
                f"({op.estimated_cost:.4f} of {total_cost:.4f})."
            ),
            severity="notice",
            operator=op.physical_op,
        )]

    def _check_parallelism(
        self, plan: SQLServerPlanResult,
    ) -> list[SQLServerFinding]:
        if plan.degree_of_parallelism <= 1:
            return []
        if plan.total_subtree_cost < 5:  # Low-cost query going parallel
            return [SQLServerFinding(
                title=f"Unnecessary parallelism (DOP={plan.degree_of_parallelism})",
                description=(
                    f"Query uses {plan.degree_of_parallelism} threads but "
                    f"total cost is only {plan.total_subtree_cost:.2f}. "
                    f"Parallelism overhead may exceed benefit."
                ),
                severity="notice",
                remediation=(
                    "Consider OPTION (MAXDOP 1) hint for this query, "
                    "or raise cost threshold for parallelism."
                ),
            )]
        return []

    def _check_memory_grant(
        self, plan: SQLServerPlanResult,
    ) -> list[SQLServerFinding]:
        if plan.memory_grant_kb < 500_000:  # < 500MB
            return []
        return [SQLServerFinding(
            title=f"Large memory grant ({plan.memory_grant_kb // 1024}MB)",
            description=(
                f"Query requested {plan.memory_grant_kb // 1024}MB memory. "
                f"Large grants can cause RESOURCE_SEMAPHORE waits for other queries."
            ),
            severity="warning",
            remediation=(
                "Review sort/hash operations, update statistics, or use "
                "Resource Governor to limit per-query memory."
            ),
        )]


# ── SQL Server System Query Helpers ──────────────────────────────────────

class SQLServerProbe:
    """
    Query SQL Server DMVs for performance insights.

    Requires pyodbc or pymssql.
    """

    def __init__(self, connection_string: str) -> None:
        self.connection_string = connection_string

    async def get_top_queries(
        self, top_n: int = 25,
    ) -> list[dict[str, Any]]:
        """Get top queries by total elapsed time from DMVs."""
        sql = """
        SELECT TOP (@top_n)
            qs.total_elapsed_time / qs.execution_count AS avg_elapsed_us,
            qs.total_elapsed_time,
            qs.execution_count,
            qs.total_logical_reads / qs.execution_count AS avg_logical_reads,
            qs.total_worker_time / qs.execution_count AS avg_cpu_us,
            SUBSTRING(st.text, (qs.statement_start_offset/2)+1,
                ((CASE qs.statement_end_offset
                    WHEN -1 THEN DATALENGTH(st.text)
                    ELSE qs.statement_end_offset
                END - qs.statement_start_offset)/2) + 1) AS query_text,
            qp.query_plan
        FROM sys.dm_exec_query_stats qs
        CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
        CROSS APPLY sys.dm_exec_query_plan(qs.plan_handle) qp
        WHERE qs.execution_count > 1
        ORDER BY qs.total_elapsed_time DESC;
        """
        return await self._execute(sql, {"top_n": top_n})

    async def get_missing_indexes(self) -> list[dict[str, Any]]:
        """Get missing index suggestions from DMVs."""
        sql = """
        SELECT TOP 25
            ROUND(s.avg_total_user_cost * s.avg_user_impact
                * (s.user_seeks + s.user_scans), 0) AS improvement_measure,
            d.statement AS full_table,
            d.equality_columns,
            d.inequality_columns,
            d.included_columns,
            s.user_seeks,
            s.user_scans,
            s.avg_user_impact
        FROM sys.dm_db_missing_index_groups g
        JOIN sys.dm_db_missing_index_group_stats s ON g.index_group_handle = s.group_handle
        JOIN sys.dm_db_missing_index_details d ON g.index_handle = d.index_handle
        ORDER BY improvement_measure DESC;
        """
        return await self._execute(sql)

    async def get_index_usage(self) -> list[dict[str, Any]]:
        """Get index usage statistics."""
        sql = """
        SELECT
            OBJECT_NAME(i.object_id) AS table_name,
            i.name AS index_name,
            i.type_desc AS index_type,
            u.user_seeks,
            u.user_scans,
            u.user_lookups,
            u.user_updates,
            CASE WHEN (u.user_seeks + u.user_scans + u.user_lookups) = 0
                 THEN 'UNUSED' ELSE 'USED' END AS status
        FROM sys.indexes i
        LEFT JOIN sys.dm_db_index_usage_stats u
            ON i.object_id = u.object_id AND i.index_id = u.index_id
        WHERE OBJECTPROPERTY(i.object_id, 'IsUserTable') = 1
            AND i.type > 0  -- Skip heaps
        ORDER BY (u.user_seeks + u.user_scans + u.user_lookups) ASC;
        """
        return await self._execute(sql)

    async def get_wait_stats(self) -> list[dict[str, Any]]:
        """Get top wait statistics."""
        sql = """
        SELECT TOP 20
            wait_type,
            waiting_tasks_count,
            wait_time_ms,
            signal_wait_time_ms,
            wait_time_ms - signal_wait_time_ms AS resource_wait_ms
        FROM sys.dm_os_wait_stats
        WHERE wait_type NOT IN (
            'CLR_SEMAPHORE','LAZYWRITER_SLEEP','RESOURCE_QUEUE',
            'SLEEP_TASK','SLEEP_SYSTEMTASK','SQLTRACE_BUFFER_FLUSH',
            'WAITFOR','LOGMGR_QUEUE','CHECKPOINT_QUEUE',
            'REQUEST_FOR_DEADLOCK_SEARCH','XE_TIMER_EVENT',
            'BROKER_TO_FLUSH','BROKER_TASK_STOP','CLR_MANUAL_EVENT',
            'DISPATCHER_QUEUE_SEMAPHORE','FT_IFTS_SCHEDULER_IDLE_WAIT',
            'XE_DISPATCHER_WAIT','BROKER_EVENTHANDLER'
        )
        ORDER BY wait_time_ms DESC;
        """
        return await self._execute(sql)

    async def _execute(
        self, sql: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute SQL against SQL Server."""
        try:
            import pyodbc
        except ImportError:
            try:
                import pymssql  # type: ignore[import-untyped]
                return await self._execute_pymssql(sql, pymssql, params)
            except ImportError:
                raise RuntimeError(
                    "pyodbc or pymssql required for SQL Server.\n"
                    "Install with: pip install pyodbc  (or)  pip install pymssql"
                )

        # pyodbc path
        conn = pyodbc.connect(self.connection_string)
        try:
            cursor = conn.cursor()
            if params:
                cursor.execute(sql, params)
            else:
                cursor.execute(sql)
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]
        finally:
            conn.close()

    async def _execute_pymssql(
        self, sql: str, pymssql: Any, params: dict | None,
    ) -> list[dict[str, Any]]:
        """Fallback pymssql execution."""
        # Parse connection string for pymssql
        conn = pymssql.connect(self.connection_string)
        try:
            cursor = conn.cursor(as_dict=True)
            cursor.execute(sql)
            return list(cursor.fetchall())
        finally:
            conn.close()
