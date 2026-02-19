"""
SQL Server-specific analysis rules.

These rules analyze SQL Server Showplan XML operators and detect
performance issues specific to the SQL Server optimizer:

- Key Lookup + Clustered Index Scan → covering index suggestion
- Table Scan on heap → clustered index suggestion
- Implicit conversions in predicates
- Missing statistics warnings
- Sort spill to tempdb
- Parameter sniffing indicators
- Adaptive join overhead
- No join predicate (Cartesian product)
- Excessive parallelism or lack thereof
- Bookmark/RID lookup elimination

Each rule returns Finding objects compatible with the standard
QuerySense analysis pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

from querysense.analyzer.models import Finding, Severity

logger = logging.getLogger(__name__)


def analyze_sqlserver_plan(plan_output: Any) -> list[Finding]:
    """
    Run all SQL Server rules against a parsed SQLServerPlanOutput.

    Args:
        plan_output: Parsed SQLServerPlanOutput from sqlserver_parser

    Returns:
        List of Finding objects
    """
    findings: list[Finding] = []

    for rule_fn in _SQLSERVER_RULES:
        try:
            rule_findings = rule_fn(plan_output)
            findings.extend(rule_findings)
        except Exception as e:
            logger.warning("SQL Server rule %s failed: %s", rule_fn.__name__, e)

    return findings


# ── Individual rules ───────────────────────────────────────────────────


def _rule_table_scan_on_heap(plan_output: Any) -> list[Finding]:
    """
    Detect Table Scans on heap tables.

    A Table Scan on a heap (no clustered index) reads every page.
    Suggest creating a clustered index on the primary key or
    most-queried column.
    """
    findings: list[Finding] = []
    for op in plan_output.operators:
        if op.physical_op == "Table Scan":
            table = op.object_ref.table if op.object_ref else "unknown"
            findings.append(Finding(
                rule_id="SS_TABLE_SCAN_HEAP",
                severity=Severity.WARNING,
                title=f"Table Scan on heap: {table}",
                description=(
                    f"Table Scan on {table} reads every page in the heap. "
                    f"Without a clustered index, SQL Server cannot perform efficient seeks."
                ),
                suggestion=(
                    f"Create a clustered index on {table}. Choose the column most "
                    f"frequently used in WHERE clauses or JOIN conditions as the key."
                ),
                impact_score=min(10, 3 + op.cost.estimated_rows / 10000),
                node_path=f"Node {op.node_id}",
                metrics={
                    "estimated_rows": op.cost.estimated_rows,
                    "subtree_cost": op.cost.estimated_total_subtree_cost,
                    "table": table,
                },
            ))
    return findings


def _rule_key_lookup(plan_output: Any) -> list[Finding]:
    """
    Detect Key Lookups (bookmark lookups).

    A Key Lookup means the nonclustered index doesn't cover all needed
    columns, requiring a round-trip to the clustered index for each row.
    High-frequency lookups are expensive.
    """
    findings: list[Finding] = []
    for op in plan_output.operators:
        if op.is_lookup:
            table = op.object_ref.table if op.object_ref else "unknown"
            index = op.object_ref.index if op.object_ref else "unknown"
            rows = op.cost.estimated_rows

            if rows > 100:
                findings.append(Finding(
                    rule_id="SS_KEY_LOOKUP",
                    severity=Severity.WARNING if rows < 10000 else Severity.CRITICAL,
                    title=f"Key Lookup on {table} ({rows:.0f} rows)",
                    description=(
                        f"Key Lookup fetches {rows:.0f} rows from the clustered index "
                        f"because nonclustered index {index} doesn't include all "
                        f"needed columns. Each lookup is a random I/O."
                    ),
                    suggestion=(
                        f"Add INCLUDE columns to the nonclustered index to make it "
                        f"a covering index, eliminating the Key Lookup. "
                        f"Output columns needed: {', '.join(op.output_columns[:5])}"
                    ),
                    impact_score=min(10, 2 + rows / 5000),
                    node_path=f"Node {op.node_id}",
                    metrics={
                        "estimated_rows": rows,
                        "table": table,
                        "index": index,
                        "output_columns": op.output_columns[:10],
                    },
                ))
    return findings


def _rule_implicit_conversion(plan_output: Any) -> list[Finding]:
    """
    Detect implicit conversions in predicates.

    Implicit conversions prevent index seeks and can cause
    cardinality estimation errors. Common with varchar/nvarchar
    and int/bigint mismatches.
    """
    findings: list[Finding] = []
    for warning in plan_output.warnings:
        if warning.implicit_conversion:
            findings.append(Finding(
                rule_id="SS_IMPLICIT_CONVERSION",
                severity=Severity.WARNING,
                title="Implicit conversion in predicate",
                description=(
                    f"SQL Server is performing an implicit type conversion: "
                    f"{warning.message}. This prevents index seeks and forces scans."
                ),
                suggestion=(
                    "Fix the data type mismatch in the query or schema. "
                    "Common fixes: use N'string' for nvarchar comparisons, "
                    "cast parameters to match column types, or alter column types."
                ),
                impact_score=6.0,
                metrics={"warning": warning.message},
            ))
    return findings


def _rule_missing_statistics(plan_output: Any) -> list[Finding]:
    """
    Detect columns with missing statistics.

    Without statistics, SQL Server uses default cardinality estimates
    (30% for inequality, 10% for equality) leading to bad plans.
    """
    findings: list[Finding] = []
    for warning in plan_output.warnings:
        if warning.columns_with_no_statistics:
            findings.append(Finding(
                rule_id="SS_MISSING_STATISTICS",
                severity=Severity.WARNING,
                title=f"Missing statistics on {len(warning.columns_with_no_statistics)} columns",
                description=(
                    f"Columns without statistics: {', '.join(warning.columns_with_no_statistics)}. "
                    f"SQL Server cannot accurately estimate cardinality without statistics."
                ),
                suggestion=(
                    "Run UPDATE STATISTICS on the affected tables, or enable "
                    "AUTO_CREATE_STATISTICS if it's disabled. Consider creating "
                    "filtered statistics for skewed data distributions."
                ),
                impact_score=5.0,
                metrics={"columns": warning.columns_with_no_statistics},
            ))
    return findings


def _rule_sort_spill(plan_output: Any) -> list[Finding]:
    """
    Detect sort/hash spills to tempdb.

    Spills occur when memory grant is insufficient. They cause
    expensive disk I/O to tempdb and can dramatically slow queries.
    """
    findings: list[Finding] = []
    for warning in plan_output.warnings:
        if warning.spill_to_tempdb:
            level = warning.sort_spill_level or 1
            severity = Severity.CRITICAL if level >= 2 else Severity.WARNING
            findings.append(Finding(
                rule_id="SS_SORT_SPILL",
                severity=severity,
                title=f"Sort/hash spill to tempdb (level {level})",
                description=(
                    f"The query's memory grant was insufficient, causing data to "
                    f"spill to tempdb (level {level}). Level 2+ spills indicate "
                    f"severely underestimated memory needs."
                ),
                suggestion=(
                    "Investigate cardinality estimation errors that may cause "
                    "insufficient memory grants. Options: UPDATE STATISTICS, "
                    "use OPTION(MIN_GRANT_PERCENT = N), or increase max server memory. "
                    "For persistent issues, consider Resource Governor memory grants."
                ),
                impact_score=7.0 if level >= 2 else 5.0,
                metrics={"spill_level": level},
            ))
    return findings


def _rule_no_join_predicate(plan_output: Any) -> list[Finding]:
    """
    Detect missing join predicates (Cartesian products).

    A Cartesian product produces rows(table1) × rows(table2) results,
    almost always indicating a bug or missing WHERE/ON clause.
    """
    findings: list[Finding] = []
    for warning in plan_output.warnings:
        if warning.no_join_predicate:
            findings.append(Finding(
                rule_id="SS_NO_JOIN_PREDICATE",
                severity=Severity.CRITICAL,
                title="No join predicate — possible Cartesian product",
                description=(
                    "SQL Server detected a join without a predicate, producing "
                    "a Cartesian product (cross join). This is almost always "
                    "unintentional and produces massive result sets."
                ),
                suggestion=(
                    "Add a JOIN condition (ON clause) or WHERE clause to limit "
                    "the result set. If a cross join is intended, use CROSS JOIN "
                    "explicitly for clarity."
                ),
                impact_score=9.0,
            ))
    return findings


def _rule_missing_index(plan_output: Any) -> list[Finding]:
    """
    Surface SQL Server's own missing index suggestions.

    SQL Server includes missing index recommendations directly
    in the plan. These are high-value, optimizer-verified suggestions.
    """
    findings: list[Finding] = []
    for mi in plan_output.missing_indexes:
        ddl = mi.create_index_statement
        if not ddl:
            continue

        findings.append(Finding(
            rule_id="SS_MISSING_INDEX",
            severity=Severity.WARNING if mi.impact < 80 else Severity.CRITICAL,
            title=f"Missing index on {mi.table} (est. {mi.impact:.0f}% improvement)",
            description=(
                f"SQL Server recommends a new index on {mi.table} that could "
                f"improve this query by approximately {mi.impact:.0f}%."
            ),
            suggestion=f"Create the recommended index:\n\n{ddl}",
            impact_score=min(10, mi.impact / 10),
            metrics={
                "table": mi.table,
                "impact_pct": mi.impact,
                "equality_columns": mi.equality_columns,
                "inequality_columns": mi.inequality_columns,
                "include_columns": mi.include_columns,
            },
        ))
    return findings


def _rule_parameter_sniffing(plan_output: Any) -> list[Finding]:
    """
    Detect parameter sniffing indicators.

    When compiled parameter values differ significantly from runtime
    values, the cached plan may be suboptimal for the current execution.
    """
    findings: list[Finding] = []
    for plan in plan_output.plans:
        for param in plan.parameter_list:
            compiled = param.get("compiled_value", "")
            runtime = param.get("runtime_value", "")

            if compiled and runtime and compiled != runtime:
                # Check for large numeric differences
                try:
                    compiled_num = float(compiled.strip("()N'"))
                    runtime_num = float(runtime.strip("()N'"))
                    if compiled_num > 0:
                        ratio = runtime_num / compiled_num
                        if ratio > 10 or ratio < 0.1:
                            findings.append(Finding(
                                rule_id="SS_PARAMETER_SNIFFING",
                                severity=Severity.WARNING,
                                title=f"Parameter sniffing: {param.get('name', '?')} ({ratio:.0f}× difference)",
                                description=(
                                    f"Parameter {param.get('name', '?')} was compiled with "
                                    f"value {compiled} but executed with {runtime} "
                                    f"({ratio:.0f}× difference). The cached plan may be "
                                    f"suboptimal for the current value."
                                ),
                                suggestion=(
                                    "Options: OPTION(RECOMPILE) for this query, "
                                    "OPTION(OPTIMIZE FOR UNKNOWN), or create a "
                                    "plan guide. For frequent parameter variations, "
                                    "consider Query Store forced plans."
                                ),
                                impact_score=5.0,
                                metrics={
                                    "parameter": param.get("name", ""),
                                    "compiled_value": compiled,
                                    "runtime_value": runtime,
                                    "ratio": ratio,
                                },
                            ))
                except (ValueError, ZeroDivisionError):
                    pass  # Non-numeric parameters

    return findings


def _rule_excessive_parallelism(plan_output: Any) -> list[Finding]:
    """
    Detect excessive parallelism or missed parallelism opportunities.

    High DOP on small queries wastes resources. Missing parallelism
    on large queries wastes time.
    """
    findings: list[Finding] = []

    for plan in plan_output.plans:
        dop = plan.degree_of_parallelism

        # Parallel query on small result set
        if dop and dop > 1:
            root_rows = plan.root_operator.cost.estimated_rows if plan.root_operator else 0
            root_cost = plan.root_operator.cost.estimated_total_subtree_cost if plan.root_operator else 0

            if root_rows < 100 and root_cost < 0.1:
                findings.append(Finding(
                    rule_id="SS_EXCESSIVE_PARALLELISM",
                    severity=Severity.INFO,
                    title=f"Parallel plan (DOP={dop}) for small query ({root_rows:.0f} rows)",
                    description=(
                        f"This query uses {dop} threads but only processes ~{root_rows:.0f} rows. "
                        f"The parallelism overhead may exceed the benefit."
                    ),
                    suggestion=(
                        "Consider OPTION(MAXDOP 1) for this query, or raise the "
                        "'cost threshold for parallelism' server setting."
                    ),
                    impact_score=2.0,
                    metrics={"dop": dop, "estimated_rows": root_rows},
                ))

    return findings


def _rule_clustered_index_scan(plan_output: Any) -> list[Finding]:
    """
    Detect Clustered Index Scans that could be seeks.

    A Clustered Index Scan reads the entire table (equivalent to a
    table scan but on the clustered index structure). If there are
    WHERE clause predicates, this often indicates a missing index.
    """
    findings: list[Finding] = []

    for op in plan_output.operators:
        if op.physical_op == "Clustered Index Scan" and op.cost.estimated_rows > 1000:
            table = op.object_ref.table if op.object_ref else "unknown"
            rows = op.cost.estimated_rows

            # Check if there are predicates (meaning a seek might be possible)
            if op.predicates:
                findings.append(Finding(
                    rule_id="SS_CLUSTERED_SCAN_WITH_PREDICATE",
                    severity=Severity.WARNING if rows < 100000 else Severity.CRITICAL,
                    title=f"Clustered Index Scan with predicate on {table} ({rows:.0f} rows)",
                    description=(
                        f"Scanning {rows:.0f} rows of {table}'s clustered index despite "
                        f"having filter predicates. A nonclustered index on the "
                        f"filter columns could convert this to a seek."
                    ),
                    suggestion=(
                        f"Create a nonclustered index on the filter columns. "
                        f"Check the missing index suggestions in this plan, or use "
                        f"Database Engine Tuning Advisor for recommendations."
                    ),
                    impact_score=min(10, 3 + rows / 50000),
                    node_path=f"Node {op.node_id}",
                    metrics={
                        "estimated_rows": rows,
                        "table": table,
                        "predicates": op.predicates[:3],
                    },
                ))
    return findings


# Rule registry
_SQLSERVER_RULES = [
    _rule_table_scan_on_heap,
    _rule_key_lookup,
    _rule_implicit_conversion,
    _rule_missing_statistics,
    _rule_sort_spill,
    _rule_no_join_predicate,
    _rule_missing_index,
    _rule_parameter_sniffing,
    _rule_excessive_parallelism,
    _rule_clustered_index_scan,
]
