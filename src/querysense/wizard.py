"""
Optimization Wizard — Step-by-step guided query optimization.

Based on "The Ultimate Optimization Algorithm" from
PostgreSQL Query Optimization (Dombrovskaya et al.), Chapter 16.

The wizard walks through a deterministic decision tree:
1. Classify query (short/long)
2. Check statistics freshness
3. Analyze plan structure
4. Recommend indexes
5. Check configuration
6. Suggest rewrites
7. Validate improvement

This is QuerySense's "killer feature" — not just "what's wrong,"
but a coach that walks you through fixing it, step by step.

Usage:
    from querysense.wizard import run_wizard, WizardResult

    result = run_wizard(plan, findings=analysis.findings, sql=sql)
    for step in result.steps:
        print(f"Step {step.number}: {step.title}")
        print(f"  {step.explanation}")
        if step.action_sql:
            print(f"  Run: {step.action_sql}")

CLI:
    querysense wizard plan.json
    querysense wizard plan.json --sql query.sql
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding


@dataclass(frozen=True)
class WizardStep:
    """A single step in the optimization wizard."""
    number: int
    title: str
    explanation: str
    status: str = "todo"       # todo / done / skipped / blocked
    action_sql: str = ""       # SQL to run
    action_config: str = ""    # Config change to make
    action_manual: str = ""    # Manual action
    expected_improvement: str = ""
    requires_db: bool = False  # Needs DB connection to execute
    category: str = "analyze"  # analyze / index / statistics / config / rewrite / verify


@dataclass
class WizardResult:
    """Complete wizard output."""
    query_class: str = "unknown"    # short / long / mixed
    total_steps: int = 0
    critical_steps: int = 0
    steps: list[WizardStep] = field(default_factory=list)
    summary: str = ""
    estimated_total_improvement: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_class": self.query_class,
            "total_steps": self.total_steps,
            "critical_steps": self.critical_steps,
            "summary": self.summary,
            "estimated_total_improvement": self.estimated_total_improvement,
            "steps": [
                {
                    "number": s.number,
                    "title": s.title,
                    "explanation": s.explanation,
                    "status": s.status,
                    "action_sql": s.action_sql,
                    "action_config": s.action_config,
                    "action_manual": s.action_manual,
                    "expected_improvement": s.expected_improvement,
                    "requires_db": s.requires_db,
                    "category": s.category,
                }
                for s in self.steps
            ],
        }

    def format_text(self) -> str:
        """Format as plain text for terminal output."""
        lines: list[str] = []
        lines.append("")
        lines.append("  QUERYSENSE OPTIMIZATION WIZARD")
        lines.append("  " + "=" * 50)
        lines.append(f"  Query type: {self.query_class.upper()}")
        lines.append(f"  Steps: {self.total_steps} ({self.critical_steps} critical)")
        lines.append("")

        for step in self.steps:
            status_icon = {
                "todo": "[ ]",
                "done": "[x]",
                "skipped": "[-]",
                "blocked": "[!]",
            }.get(step.status, "[ ]")

            lines.append(f"  {status_icon} Step {step.number}: {step.title}")

            # Wrap explanation
            words = step.explanation.split()
            current: list[str] = []
            current_len = 0
            for word in words:
                if current_len + len(word) + 1 > 60 and current:
                    lines.append("      " + " ".join(current))
                    current = [word]
                    current_len = len(word)
                else:
                    current.append(word)
                    current_len += len(word) + 1
            if current:
                lines.append("      " + " ".join(current))

            if step.action_sql:
                lines.append(f"      SQL: {step.action_sql}")
            if step.action_config:
                lines.append(f"      Config: {step.action_config}")
            if step.action_manual:
                lines.append(f"      Action: {step.action_manual}")
            if step.expected_improvement:
                lines.append(f"      Expected: {step.expected_improvement}")

            lines.append("")

        if self.summary:
            lines.append("  " + "-" * 50)
            lines.append(f"  {self.summary}")

        if self.estimated_total_improvement:
            lines.append(f"  Estimated total improvement: {self.estimated_total_improvement}")

        lines.append("")

        return "\n".join(lines)


# ── Helper functions ─────────────────────────────────────────────────

def _has_node_type(plan: dict[str, Any], node_type: str) -> bool:
    """Check if plan tree contains a node of the given type."""
    if plan.get("Node Type") == node_type:
        return True
    return any(_has_node_type(c, node_type) for c in plan.get("Plans", []))


def _has_spill_to_disk(plan: dict[str, Any]) -> bool:
    """Check if any node spills to disk."""
    sort_method = plan.get("Sort Method", "")
    if "external" in sort_method.lower() or "disk" in sort_method.lower():
        return True
    # Hash batches
    if plan.get("Hash Batches", 0) > 1:
        return True
    return any(_has_spill_to_disk(c) for c in plan.get("Plans", []))


def _max_rows(plan: dict[str, Any]) -> int:
    """Get max rows from any node."""
    rows = plan.get("Actual Rows", plan.get("Plan Rows", 0))
    loops = max(plan.get("Actual Loops", 1), 1)
    best = rows * loops
    for child in plan.get("Plans", []):
        best = max(best, _max_rows(child))
    return best


def _has_bad_estimate(plan: dict[str, Any], threshold: float = 10.0) -> bool:
    """Check if any node has a bad row estimate (>10x off)."""
    actual = plan.get("Actual Rows")
    estimated = plan.get("Plan Rows")
    if actual is not None and estimated is not None and estimated > 0:
        ratio = max(actual / estimated, estimated / actual)
        if ratio > threshold:
            return True
    return any(_has_bad_estimate(c, threshold) for c in plan.get("Plans", []))


def _collect_seq_scan_tables(node: dict[str, Any]) -> list[str]:
    """Collect tables with sequential scans."""
    tables: list[str] = []
    if node.get("Node Type") == "Seq Scan":
        rel = node.get("Relation Name", "")
        if rel:
            tables.append(rel)
    for child in node.get("Plans", []):
        tables.extend(_collect_seq_scan_tables(child))
    return tables


# ── Wizard Engine ────────────────────────────────────────────────────

def run_wizard(
    plan: dict[str, Any],
    findings: list[Any] | None = None,
    sql: str | None = None,
) -> WizardResult:
    """
    Run the optimization wizard on an EXPLAIN plan.

    Generates a step-by-step optimization path based on the
    Ultimate Optimization Algorithm (Dombrovskaya Ch. 16):

    1. Is this a short or long query?
    2. Are statistics fresh?
    3. Are there missing indexes?
    4. Is there disk spill?
    5. Can we rewrite the SQL?
    6. Are there configuration issues?
    7. Verify the improvement

    Args:
        plan: EXPLAIN plan dict
        findings: Optional findings from AnalysisService
        sql: Optional SQL text

    Returns:
        WizardResult with ordered optimization steps
    """
    from querysense.query_classifier import classify_query, QueryClass

    classification = classify_query(plan, sql=sql)
    steps: list[WizardStep] = []
    step_num = 1

    execution_time = plan.get("Actual Total Time", 0)
    max_scan = _max_rows(plan)
    seq_tables = _collect_seq_scan_tables(plan)
    has_spill = _has_spill_to_disk(plan)
    bad_estimate = _has_bad_estimate(plan)

    # ── Step 1: Classification Awareness ─────────────────────────

    if classification.query_class == QueryClass.SHORT:
        class_explain = (
            "This is a SHORT query (OLTP-style). Optimization focuses on "
            "index selection and minimizing I/O. Every millisecond matters "
            "because this query likely runs thousands of times per second."
        )
    elif classification.query_class == QueryClass.LONG:
        class_explain = (
            "This is a LONG query (OLAP-style). Optimization focuses on "
            "parallelism, work_mem tuning, and partitioning. Sequential scans "
            "may be acceptable if they use parallel workers."
        )
    else:
        class_explain = (
            "This is a MIXED query with both OLTP and OLAP characteristics. "
            "We'll optimize both the index access pattern and the aggregation/sort "
            "performance."
        )

    steps.append(WizardStep(
        number=step_num,
        title="Identify query type",
        explanation=class_explain,
        status="done",
        category="analyze",
    ))
    step_num += 1

    # ── Step 2: Statistics check (Critical path) ─────────────────

    if bad_estimate:
        steps.append(WizardStep(
            number=step_num,
            title="Fix stale statistics (CRITICAL)",
            explanation=(
                "The planner's row estimates are off by more than 10x. This means PostgreSQL "
                "is choosing the wrong execution strategy. This is the SINGLE MOST IMPACTFUL "
                "fix — bad estimates cascade into bad plan choices everywhere."
            ),
            status="todo",
            action_sql="ANALYZE " + ", ".join(sorted(set(seq_tables))[:5]) + ";" if seq_tables else "ANALYZE;",
            expected_improvement="Often 10-100x improvement when estimates are corrected",
            category="statistics",
        ))
        step_num += 1
    else:
        steps.append(WizardStep(
            number=step_num,
            title="Verify statistics freshness",
            explanation="Row estimates look reasonable (within 10x). Statistics appear current.",
            status="done",
            category="statistics",
        ))
        step_num += 1

    # ── Step 3: Missing indexes (Short query priority) ───────────

    if seq_tables and classification.query_class in (QueryClass.SHORT, QueryClass.MIXED):
        for table in sorted(set(seq_tables))[:3]:
            steps.append(WizardStep(
                number=step_num,
                title=f"Add index on '{table}'",
                explanation=(
                    f"Sequential scan on '{table}' with {max_scan:,} rows scanned. "
                    "For short queries, this should be an index scan. Check the WHERE/JOIN "
                    "columns and create a targeted index."
                ),
                status="todo",
                action_sql=f"CREATE INDEX CONCURRENTLY idx_{table}_<column> ON {table}(<where_columns>);",
                action_manual=(
                    "Look at the query's WHERE clause to identify the right columns. "
                    "Run: querysense analyze plan.json to get specific index recommendations."
                ),
                expected_improvement="10-1000x for point lookups on large tables",
                requires_db=True,
                category="index",
            ))
            step_num += 1

    elif seq_tables and classification.query_class == QueryClass.LONG:
        steps.append(WizardStep(
            number=step_num,
            title="Evaluate sequential scan acceptability",
            explanation=(
                f"Sequential scans on: {', '.join(sorted(set(seq_tables))[:5])}. "
                "For long/OLAP queries, sequential scans may be optimal when reading "
                "a large fraction of the table. Check if parallel scan is being used."
            ),
            status="todo" if not _has_node_type(plan, "Gather") else "done",
            category="analyze",
        ))
        step_num += 1

    # ── Step 4: Disk spill ───────────────────────────────────────

    if has_spill:
        steps.append(WizardStep(
            number=step_num,
            title="Eliminate disk spill (increase work_mem)",
            explanation=(
                "Sort or hash operations are spilling to disk. This is 50-100x slower "
                "than in-memory operations. Increase work_mem for this query."
            ),
            status="todo",
            action_sql="SET LOCAL work_mem = '256MB';  -- then run your query; then RESET work_mem;",
            action_config="ALTER SYSTEM SET work_mem = '64MB';  -- global increase (conservative)",
            expected_improvement="2-10x for queries with large sorts or hash joins",
            category="config",
        ))
        step_num += 1

    # ── Step 5: Parallel query (Long query priority) ─────────────

    if classification.query_class in (QueryClass.LONG, QueryClass.MIXED):
        if not _has_node_type(plan, "Gather") and max_scan > 50000:
            steps.append(WizardStep(
                number=step_num,
                title="Enable parallel query",
                explanation=(
                    "This long query isn't using parallel workers. With parallel query, "
                    "PostgreSQL can divide the work across multiple CPU cores."
                ),
                status="todo",
                action_config=(
                    "SET max_parallel_workers_per_gather = 4;\n"
                    "SET parallel_tuple_cost = 0.01;"
                ),
                expected_improvement="Near-linear speedup with number of workers (e.g., 4 workers = ~3.5x)",
                category="config",
            ))
            step_num += 1

    # ── Step 6: SQL rewrite opportunities ────────────────────────

    if findings:
        rewrite_findings = [
            f for f in findings
            if hasattr(f, "rule_id") and "REWRITE" in getattr(f, "rule_id", "")
        ]
        if rewrite_findings:
            for rf in rewrite_findings[:2]:
                steps.append(WizardStep(
                    number=step_num,
                    title=f"SQL rewrite: {getattr(rf, 'title', 'optimize SQL')}",
                    explanation=getattr(rf, "description", "Rewrite SQL for better performance"),
                    status="todo",
                    action_sql=getattr(rf, "suggestion", ""),
                    category="rewrite",
                ))
                step_num += 1

    # Check for common rewrite patterns from SQL
    if sql:
        upper = sql.upper()
        if "SELECT *" in upper:
            steps.append(WizardStep(
                number=step_num,
                title="Replace SELECT * with specific columns",
                explanation=(
                    "SELECT * fetches all columns, including those you don't need. "
                    "This wastes I/O, memory, and network bandwidth. Specify only needed columns."
                ),
                status="todo",
                action_manual="Replace SELECT * with SELECT col1, col2, col3",
                expected_improvement="10-50% less I/O and memory for wide tables",
                category="rewrite",
            ))
            step_num += 1

        if "NOT IN" in upper:
            steps.append(WizardStep(
                number=step_num,
                title="Replace NOT IN with NOT EXISTS",
                explanation=(
                    "NOT IN has problematic NULL handling and often can't use indexes. "
                    "NOT EXISTS is semantically clearer and usually faster."
                ),
                status="todo",
                action_manual="Replace NOT IN (SELECT ...) with NOT EXISTS (SELECT 1 FROM ... WHERE ...)",
                category="rewrite",
            ))
            step_num += 1

    # ── Step 7: Configuration audit ──────────────────────────────

    steps.append(WizardStep(
        number=step_num,
        title="Run configuration audit",
        explanation=(
            "Check if PostgreSQL configuration is optimized for your workload. "
            "Common issues: default shared_buffers (128MB), "
            "random_page_cost=4.0 on SSDs, disabled parallel workers."
        ),
        status="todo",
        action_manual="Run: querysense audit config --dsn $DSN",
        category="config",
    ))
    step_num += 1

    # ── Step 8: Verify improvement ───────────────────────────────

    steps.append(WizardStep(
        number=step_num,
        title="Verify improvement",
        explanation=(
            "After applying fixes, re-run EXPLAIN ANALYZE and compare with the original. "
            "Use QuerySense check to quantify the improvement."
        ),
        status="todo",
        action_sql='EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) <your query>;',
        action_manual=(
            "querysense check --baseline original.json --current improved.json"
        ),
        category="verify",
    ))

    # ── Build result ─────────────────────────────────────────────

    critical_steps = sum(
        1 for s in steps
        if s.status == "todo" and s.category in ("index", "statistics")
    )

    summary_parts: list[str] = []
    if bad_estimate:
        summary_parts.append("Fix statistics first (most impactful)")
    if seq_tables and classification.query_class != QueryClass.LONG:
        summary_parts.append(f"Add indexes on: {', '.join(sorted(set(seq_tables))[:3])}")
    if has_spill:
        summary_parts.append("Increase work_mem to eliminate disk spill")

    return WizardResult(
        query_class=classification.query_class.value,
        total_steps=len(steps),
        critical_steps=critical_steps,
        steps=steps,
        summary="; ".join(summary_parts) if summary_parts else "Query is well-optimized",
        estimated_total_improvement=(
            f"Current: {execution_time:.0f}ms" if execution_time else ""
        ),
    )
