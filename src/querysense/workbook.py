"""
Query Tuning Workbook — the automated "Ultimate Optimization Algorithm."

Implements Chapter 16 of Dombrovskaya et al. (2024) as code:
the systematic, scientific-method approach to query optimization
that pganalyze does manually via Workbooks, but fully automated.

The flow:
    1. BASELINE: Capture current plan + metrics
    2. DIAGNOSE: Run QuerySense rules → produce ranked findings
    3. HYPOTHESIZE: For each finding, generate optimization hypotheses
    4. PLAN: Create concrete variants (rewrites, planner hints, indexes)
    5. PREDICT: Estimate impact of each variant before execution
    6. TEST: Execute variants and capture new plans (optional, requires DB)
    7. COMPARE: Statistical comparison of baseline vs variant
    8. RECOMMEND: Rank variants by measured improvement, risk, effort
    9. REPORT: Generate human-readable optimization report

pganalyze requires manual variant creation and testing.
QuerySense automates steps 3-8 entirely.

Usage:
    from querysense.workbook import TuningWorkbook, WorkbookResult

    wb = TuningWorkbook()

    # Fully offline (no DB needed)
    result = wb.run(explain_json, sql=original_sql)
    print(result.report())

    # With live database testing
    result = await wb.run_with_db(
        explain_json,
        sql=original_sql,
        dsn="postgresql://localhost/mydb",
    )
    for variant in result.variants:
        print(f"{variant.name}: {variant.improvement_pct:.1f}% faster")
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Enums & Types ──────────────────────────────────────────────────────


class VariantType(str, Enum):
    """Type of optimization variant."""
    REWRITE = "rewrite"          # SQL rewrite (syntactic transformation)
    PLANNER_HINT = "planner_hint"  # SET enable_* or pg_hint_plan
    INDEX = "index"              # CREATE INDEX suggestion
    CONFIG = "config"            # SET work_mem, etc.
    SCHEMA = "schema"            # Schema change (add column, partition)
    COMPOSITE = "composite"      # Multiple changes combined


class VariantRisk(str, Enum):
    """Risk level of applying a variant."""
    NONE = "none"          # Pure SQL rewrite, no side effects
    LOW = "low"            # Planner hint, reversible instantly
    MEDIUM = "medium"      # New index (space cost, write overhead)
    HIGH = "high"          # Schema change, config change requiring restart


class WorkbookPhase(str, Enum):
    """Phases of the optimization workflow."""
    BASELINE = "baseline"
    DIAGNOSE = "diagnose"
    HYPOTHESIZE = "hypothesize"
    PLAN = "plan"
    PREDICT = "predict"
    TEST = "test"
    COMPARE = "compare"
    RECOMMEND = "recommend"


# ── Data Classes ───────────────────────────────────────────────────────


@dataclass
class Baseline:
    """Captured baseline metrics for comparison."""
    plan_json: dict[str, Any]
    sql: str = ""
    total_cost: float = 0.0
    execution_time_ms: float | None = None
    rows_returned: int | None = None
    shared_hit_blocks: int = 0
    shared_read_blocks: int = 0
    temp_written_blocks: int = 0
    node_count: int = 0
    findings_count: int = 0
    critical_count: int = 0
    structure_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_cost": self.total_cost,
            "execution_time_ms": self.execution_time_ms,
            "rows_returned": self.rows_returned,
            "shared_hit_blocks": self.shared_hit_blocks,
            "shared_read_blocks": self.shared_read_blocks,
            "temp_written_blocks": self.temp_written_blocks,
            "node_count": self.node_count,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
        }


@dataclass
class Hypothesis:
    """An optimization hypothesis generated from a finding."""
    finding_rule_id: str
    finding_title: str
    finding_severity: str
    hypothesis: str
    mechanism: str        # WHY this should help (planner behavior)
    expected_impact: str  # qualitative: "major", "moderate", "minor"
    confidence: float     # 0-1: how confident we are this will help
    textbook_ref: str = ""  # Chapter/section reference

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_rule_id": self.finding_rule_id,
            "finding_title": self.finding_title,
            "hypothesis": self.hypothesis,
            "mechanism": self.mechanism,
            "expected_impact": self.expected_impact,
            "confidence": self.confidence,
            "textbook_ref": self.textbook_ref,
        }


@dataclass
class Variant:
    """A concrete optimization variant to test."""
    name: str
    variant_type: VariantType
    risk: VariantRisk
    hypothesis: Hypothesis
    # What to change
    rewritten_sql: str = ""           # For REWRITE variants
    planner_settings: dict[str, str] = field(default_factory=dict)  # For PLANNER_HINT
    index_ddl: str = ""               # For INDEX variants
    config_commands: list[str] = field(default_factory=list)  # For CONFIG
    # Predicted impact (before testing)
    predicted_cost_reduction_pct: float = 0.0
    predicted_mechanism: str = ""
    # Measured results (after testing)
    measured_cost: float | None = None
    measured_time_ms: float | None = None
    measured_plan: dict[str, Any] | None = None
    measured_improvement_pct: float | None = None
    test_error: str | None = None

    @property
    def improvement_pct(self) -> float:
        """Best available improvement estimate."""
        if self.measured_improvement_pct is not None:
            return self.measured_improvement_pct
        return self.predicted_cost_reduction_pct

    @property
    def was_tested(self) -> bool:
        return self.measured_cost is not None or self.test_error is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.variant_type.value,
            "risk": self.risk.value,
            "hypothesis": self.hypothesis.to_dict(),
            "rewritten_sql": self.rewritten_sql or None,
            "index_ddl": self.index_ddl or None,
            "planner_settings": self.planner_settings or None,
            "config_commands": self.config_commands or None,
            "predicted_cost_reduction_pct": round(self.predicted_cost_reduction_pct, 1),
            "measured_improvement_pct": (
                round(self.measured_improvement_pct, 1)
                if self.measured_improvement_pct is not None else None
            ),
            "was_tested": self.was_tested,
            "test_error": self.test_error,
        }


@dataclass
class ComparisonResult:
    """Statistical comparison between baseline and variant."""
    variant_name: str
    baseline_cost: float
    variant_cost: float
    cost_improvement_pct: float
    baseline_time_ms: float | None = None
    variant_time_ms: float | None = None
    time_improvement_pct: float | None = None
    plan_changed: bool = False
    node_count_delta: int = 0
    risk_assessment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_name": self.variant_name,
            "baseline_cost": round(self.baseline_cost, 1),
            "variant_cost": round(self.variant_cost, 1),
            "cost_improvement_pct": round(self.cost_improvement_pct, 1),
            "time_improvement_pct": (
                round(self.time_improvement_pct, 1)
                if self.time_improvement_pct is not None else None
            ),
            "plan_changed": self.plan_changed,
            "risk_assessment": self.risk_assessment,
        }


@dataclass
class WorkbookResult:
    """Complete workbook result with all phases."""
    query_hash: str = ""
    sql: str = ""
    baseline: Baseline | None = None
    hypotheses: list[Hypothesis] = field(default_factory=list)
    variants: list[Variant] = field(default_factory=list)
    comparisons: list[ComparisonResult] = field(default_factory=list)
    recommendations: list[Variant] = field(default_factory=list)  # Sorted by impact
    phases_completed: list[WorkbookPhase] = field(default_factory=list)
    total_time_ms: float = 0.0

    @property
    def best_variant(self) -> Variant | None:
        """The highest-impact recommendation."""
        return self.recommendations[0] if self.recommendations else None

    @property
    def total_potential_improvement(self) -> float:
        """Sum of all recommended improvements (non-overlapping estimate)."""
        if not self.recommendations:
            return 0.0
        # Take the best single improvement (don't sum — they may overlap)
        return max(v.improvement_pct for v in self.recommendations)

    def report(self) -> str:
        """Generate human-readable optimization report."""
        lines = [
            "=" * 72,
            "  QuerySense Tuning Workbook Report",
            "  Automated implementation of the Ultimate Optimization Algorithm",
            "  (Dombrovskaya et al. 2024, Chapter 16)",
            "=" * 72,
            "",
        ]

        # Baseline
        if self.baseline:
            lines.append("── BASELINE ──────────────────────────────────────────────")
            lines.append(f"  Total Cost:      {self.baseline.total_cost:,.1f}")
            if self.baseline.execution_time_ms:
                lines.append(f"  Execution Time:  {self.baseline.execution_time_ms:.2f} ms")
            lines.append(f"  Plan Nodes:      {self.baseline.node_count}")
            lines.append(f"  Findings:        {self.baseline.findings_count} "
                         f"({self.baseline.critical_count} critical)")
            lines.append("")

        # Hypotheses
        if self.hypotheses:
            lines.append("── HYPOTHESES ────────────────────────────────────────────")
            for i, h in enumerate(self.hypotheses, 1):
                lines.append(f"  {i}. [{h.expected_impact.upper()}] {h.hypothesis}")
                lines.append(f"     Mechanism: {h.mechanism}")
                lines.append(f"     Confidence: {h.confidence:.0%}")
                if h.textbook_ref:
                    lines.append(f"     Reference: {h.textbook_ref}")
                lines.append("")

        # Variants & Recommendations
        if self.recommendations:
            lines.append("── RECOMMENDATIONS (ranked by impact) ────────────────────")
            for i, v in enumerate(self.recommendations, 1):
                tested = "✓ TESTED" if v.was_tested else "predicted"
                lines.append(f"  {i}. {v.name}")
                lines.append(f"     Type: {v.variant_type.value} | Risk: {v.risk.value} | {tested}")
                lines.append(f"     Improvement: {v.improvement_pct:+.1f}%")
                lines.append(f"     Why: {v.hypothesis.mechanism}")

                if v.rewritten_sql:
                    lines.append(f"     SQL:")
                    for sql_line in v.rewritten_sql.split("\n")[:5]:
                        lines.append(f"       {sql_line}")
                    if len(v.rewritten_sql.split("\n")) > 5:
                        lines.append("       ...")

                if v.index_ddl:
                    lines.append(f"     DDL: {v.index_ddl}")

                if v.planner_settings:
                    for k, val in v.planner_settings.items():
                        lines.append(f"     SET {k} = {val};")

                if v.config_commands:
                    for cmd in v.config_commands:
                        lines.append(f"     {cmd}")

                lines.append("")

        # Summary
        lines.append("── SUMMARY ───────────────────────────────────────────────")
        lines.append(f"  Hypotheses generated:  {len(self.hypotheses)}")
        lines.append(f"  Variants created:      {len(self.variants)}")
        lines.append(f"  Variants tested:       {sum(1 for v in self.variants if v.was_tested)}")
        lines.append(f"  Recommendations:       {len(self.recommendations)}")
        if self.total_potential_improvement > 0:
            lines.append(f"  Best improvement:      {self.total_potential_improvement:+.1f}%")
        lines.append(f"  Workbook time:         {self.total_time_ms:.0f} ms")
        lines.append("=" * 72)

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_hash": self.query_hash,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "variants": [v.to_dict() for v in self.variants],
            "comparisons": [c.to_dict() for c in self.comparisons],
            "recommendations": [v.to_dict() for v in self.recommendations],
            "phases_completed": [p.value for p in self.phases_completed],
            "total_time_ms": round(self.total_time_ms, 1),
            "best_improvement_pct": round(self.total_potential_improvement, 1),
        }


# ── Hypothesis Generation ─────────────────────────────────────────────
# Maps QuerySense rule IDs to optimization hypotheses with planner behavior explanations.

_HYPOTHESIS_MAP: dict[str, dict[str, Any]] = {
    "SEQ_SCAN_LARGE_TABLE": {
        "hypothesis": "Adding an index on the filter columns will convert Seq Scan to Index Scan",
        "mechanism": (
            "PostgreSQL chooses Seq Scan when: (1) no index exists on the filter column, "
            "(2) the selectivity is too low for existing indexes, or "
            "(3) random_page_cost makes index scans appear more expensive than sequential reads. "
            "An index on the WHERE clause columns gives the planner a cheaper access path."
        ),
        "expected_impact": "major",
        "confidence": 0.85,
        "variant_type": VariantType.INDEX,
        "textbook_ref": "Dombrovskaya Ch. 5: Short Queries and Indexes",
    },
    "BAD_ROW_ESTIMATE": {
        "hypothesis": "Updating statistics or increasing statistics target will fix cardinality misestimate",
        "mechanism": (
            "The planner's cost model depends on pg_statistic for row count estimates. "
            "When statistics are stale or the default_statistics_target is too low for "
            "skewed distributions, the planner makes suboptimal join order and access method choices. "
            "ANALYZE refreshes statistics; increasing the target captures more histogram buckets."
        ),
        "expected_impact": "major",
        "confidence": 0.75,
        "variant_type": VariantType.CONFIG,
        "textbook_ref": "Peng & Peng Ch. 5.5: Cost Estimation; Dombrovskaya Ch. 16",
    },
    "NESTED_LOOP_LARGE_TABLE": {
        "hypothesis": "Disabling nested loop or adding a hash/merge-joinable index will improve join strategy",
        "mechanism": (
            "PostgreSQL chooses Nested Loop when: (1) the inner side has an efficient "
            "index path, (2) the outer side has few rows, or (3) enable_hashjoin/enable_mergejoin "
            "are off. For large joins, Hash Join or Merge Join are typically O(N+M) vs O(N*M). "
            "Adding an index on the join column enables Merge Join; increasing work_mem "
            "allows larger Hash Join build tables."
        ),
        "expected_impact": "major",
        "confidence": 0.80,
        "variant_type": VariantType.PLANNER_HINT,
        "textbook_ref": "Dombrovskaya Ch. 6: Long Queries; Peng & Peng Ch. 6",
    },
    "SPILLING_TO_DISK": {
        "hypothesis": "Increasing work_mem will keep sort/hash operations in memory",
        "mechanism": (
            "When the working dataset exceeds work_mem, PostgreSQL falls back to "
            "external (disk-based) sort or hash. Disk sorts are 10-100x slower. "
            "Increasing work_mem for this session allows the operation to complete in memory."
        ),
        "expected_impact": "moderate",
        "confidence": 0.90,
        "variant_type": VariantType.CONFIG,
        "textbook_ref": "Dombrovskaya Ch. 10: Configuration Parameters",
    },
    "CORRELATED_SUBQUERY": {
        "hypothesis": "Rewriting correlated subquery as JOIN will eliminate per-row re-execution",
        "mechanism": (
            "Correlated subqueries execute the inner query once per outer row (O(N*M)). "
            "The planner cannot always decorrelate them automatically. "
            "Rewriting as a JOIN gives the planner freedom to choose hash/merge strategies."
        ),
        "expected_impact": "major",
        "confidence": 0.85,
        "variant_type": VariantType.REWRITE,
        "textbook_ref": "Dombrovskaya Ch. 6; PostgreSQL Internals (Rogov 2023)",
    },
    "ORM_N_PLUS_ONE": {
        "hypothesis": "Batch loading (JOIN/IN clause) will replace N individual queries with 1",
        "mechanism": (
            "ORMs default to lazy loading: one SELECT per related object. This produces "
            "N+1 queries where N is the parent result count. Each query has TCP round-trip "
            "+ parse + plan + execute overhead. A single JOIN or WHERE id IN (...) "
            "replaces all N queries with one, typically 10-1000x faster."
        ),
        "expected_impact": "major",
        "confidence": 0.95,
        "variant_type": VariantType.REWRITE,
        "textbook_ref": "Dombrovskaya Ch. 14: Avoiding ORM Pitfalls",
    },
    "REDUNDANT_SORT": {
        "hypothesis": "Adding an index matching the ORDER BY will eliminate explicit sort",
        "mechanism": (
            "PostgreSQL must sort when no index provides the required order. "
            "An index on (ORDER BY columns) allows the planner to use Index Scan "
            "which returns rows pre-sorted, eliminating the Sort node entirely."
        ),
        "expected_impact": "moderate",
        "confidence": 0.80,
        "variant_type": VariantType.INDEX,
        "textbook_ref": "Dombrovskaya Ch. 5: Short Queries and Indexes",
    },
    "IMPLICIT_CAST_FILTER": {
        "hypothesis": "Removing implicit cast or adding expression index enables index usage",
        "mechanism": (
            "When a WHERE clause applies a function to a column (LOWER(col), CAST(col AS type)), "
            "the planner cannot use a standard B-tree index because the stored values don't "
            "match the compared values. Either cast the literal instead, or create an "
            "expression index: CREATE INDEX ON table (LOWER(col))."
        ),
        "expected_impact": "moderate",
        "confidence": 0.80,
        "variant_type": VariantType.INDEX,
        "textbook_ref": "Dombrovskaya Ch. 5; PostgreSQL Query Optimization",
    },
    "COST_HOTSPOT": {
        "hypothesis": "The costliest node dominates total cost; optimizing it yields the largest gain",
        "mechanism": (
            "Amdahl's Law applied to query plans: optimizing the node that consumes >50% "
            "of total cost yields proportional improvement. Focus optimization effort "
            "on this node's specific access method and join strategy."
        ),
        "expected_impact": "major",
        "confidence": 0.70,
        "variant_type": VariantType.COMPOSITE,
        "textbook_ref": "Dombrovskaya Ch. 16: The Ultimate Optimization Algorithm",
    },
    "PARALLEL_QUERY_NOT_USED": {
        "hypothesis": "Enabling parallel query will speed up large sequential operations",
        "mechanism": (
            "PostgreSQL can parallelize Seq Scan, Hash Join, and aggregation since v9.6. "
            "Parallel query is governed by max_parallel_workers_per_gather, parallel_tuple_cost, "
            "and the table's parallel_workers setting. If the cost threshold is too high "
            "or workers are unavailable, parallelism is not used."
        ),
        "expected_impact": "moderate",
        "confidence": 0.70,
        "variant_type": VariantType.PLANNER_HINT,
        "textbook_ref": "PostgreSQL Query Optimization (Dombrovskaya 2024)",
    },
    "STALE_STATISTICS": {
        "hypothesis": "Running ANALYZE will update statistics and improve plan quality",
        "mechanism": (
            "PostgreSQL's autovacuum daemon normally updates statistics, but with rapid "
            "data changes or disabled autovacuum, statistics become stale. The planner "
            "then uses outdated row count estimates, leading to wrong join orders "
            "and access methods. ANALYZE forces a statistics refresh."
        ),
        "expected_impact": "moderate",
        "confidence": 0.80,
        "variant_type": VariantType.CONFIG,
        "textbook_ref": "Dombrovskaya Ch. 16; Peng & Peng Ch. 5.5",
    },
    "INDEX_ONLY_HEAP_FETCHES": {
        "hypothesis": "Running VACUUM will reduce heap fetches for index-only scans",
        "mechanism": (
            "Index-only scans consult the visibility map to avoid heap fetches. "
            "If many pages are not all-visible (due to recent updates without VACUUM), "
            "the scan degrades to a regular index scan with heap lookups. "
            "VACUUM marks pages as all-visible."
        ),
        "expected_impact": "moderate",
        "confidence": 0.85,
        "variant_type": VariantType.CONFIG,
        "textbook_ref": "PostgreSQL Internals (Rogov 2023); Dombrovskaya Ch. 5",
    },
    "HASH_JOIN_BATCHES": {
        "hypothesis": "Increasing work_mem will reduce hash join batches and disk spills",
        "mechanism": (
            "Hash Join builds an in-memory hash table from the inner relation. "
            "When work_mem is insufficient, the table is split into batches that "
            "spill to disk. Each additional batch doubles I/O. Increasing work_mem "
            "to fit the hash table in a single batch eliminates disk I/O."
        ),
        "expected_impact": "moderate",
        "confidence": 0.85,
        "variant_type": VariantType.CONFIG,
        "textbook_ref": "Dombrovskaya Ch. 10; Peng & Peng Ch. 6",
    },
}

# Default hypothesis for unmapped rules
_DEFAULT_HYPOTHESIS = {
    "hypothesis": "Addressing this finding will reduce query cost",
    "mechanism": "The planner's current choice indicates a suboptimal access path or join strategy",
    "expected_impact": "minor",
    "confidence": 0.5,
    "variant_type": VariantType.COMPOSITE,
    "textbook_ref": "",
}


# ── Variant Generators ─────────────────────────────────────────────────


def _generate_index_variant(finding: Any, hypothesis: Hypothesis) -> Variant | None:
    """Generate an index creation variant from a finding."""
    metrics = getattr(finding, "metrics", {}) or {}
    suggestion = getattr(finding, "suggestion", "") or ""

    # Try to extract table and column info from metrics or suggestion
    table = metrics.get("relation_name", metrics.get("table", ""))
    columns = metrics.get("filter_columns", metrics.get("columns", []))

    if not table:
        # Try to parse from suggestion
        import re
        idx_match = re.search(r"CREATE\s+INDEX\s+.*?ON\s+(\w+)\s*\((.+?)\)", suggestion, re.IGNORECASE)
        if idx_match:
            table = idx_match.group(1)
            columns = [c.strip() for c in idx_match.group(2).split(",")]

    if not table:
        return None

    col_str = ", ".join(columns) if columns else "/* columns from WHERE clause */"
    idx_name = f"idx_{table}_{'_'.join(columns[:3])}" if columns else f"idx_{table}_querysense"

    return Variant(
        name=f"Add index on {table}({col_str})",
        variant_type=VariantType.INDEX,
        risk=VariantRisk.MEDIUM,
        hypothesis=hypothesis,
        index_ddl=f"CREATE INDEX CONCURRENTLY {idx_name} ON {table} ({col_str});",
        predicted_cost_reduction_pct=50.0,  # Conservative estimate
        predicted_mechanism="Index enables seek instead of sequential scan",
    )


def _generate_rewrite_variant(finding: Any, hypothesis: Hypothesis, sql: str) -> Variant | None:
    """Generate a SQL rewrite variant."""
    if not sql:
        return None

    from querysense.rewriter import rewrite_query

    try:
        result = rewrite_query(sql, [finding] if not isinstance(finding, dict) else None)
        if result.was_rewritten:
            return Variant(
                name=f"SQL rewrite: {result.rewrites[0].name}" if result.rewrites else "SQL rewrite",
                variant_type=VariantType.REWRITE,
                risk=VariantRisk.NONE,
                hypothesis=hypothesis,
                rewritten_sql=result.rewritten_sql,
                predicted_cost_reduction_pct=40.0,
                predicted_mechanism=result.rewrites[0].description if result.rewrites else "SQL optimization",
            )
    except Exception as e:
        logger.debug("Rewrite failed: %s", e)

    return None


def _generate_config_variant(finding: Any, hypothesis: Hypothesis) -> Variant | None:
    """Generate a configuration change variant."""
    rule_id = getattr(finding, "rule_id", "")
    metrics = getattr(finding, "metrics", {}) or {}

    if rule_id == "SPILLING_TO_DISK" or rule_id == "HASH_JOIN_BATCHES":
        spill_kb = metrics.get("peak_memory_kb", metrics.get("sort_space_used", 0))
        recommended_wm = max(int(spill_kb * 2 / 1024), 64)  # 2x the spill in MB
        return Variant(
            name=f"Increase work_mem to {recommended_wm}MB for this query",
            variant_type=VariantType.CONFIG,
            risk=VariantRisk.LOW,
            hypothesis=hypothesis,
            planner_settings={"work_mem": f"'{recommended_wm}MB'"},
            config_commands=[f"SET work_mem = '{recommended_wm}MB';  -- Session-level only"],
            predicted_cost_reduction_pct=30.0,
            predicted_mechanism=f"In-memory sort/hash eliminates disk spill ({spill_kb}kB → RAM)",
        )

    if rule_id == "STALE_STATISTICS" or rule_id == "BAD_ROW_ESTIMATE":
        table = metrics.get("relation_name", metrics.get("table", ""))
        return Variant(
            name=f"Update statistics{' on ' + table if table else ''}",
            variant_type=VariantType.CONFIG,
            risk=VariantRisk.NONE,
            hypothesis=hypothesis,
            config_commands=[
                f"ANALYZE{' ' + table if table else ''};",
                "-- Consider: ALTER TABLE ... ALTER COLUMN ... SET STATISTICS 500;",
            ],
            predicted_cost_reduction_pct=25.0,
            predicted_mechanism="Fresh statistics → accurate cardinality estimates → better plan choices",
        )

    if rule_id == "INDEX_ONLY_HEAP_FETCHES":
        table = metrics.get("relation_name", "")
        return Variant(
            name=f"VACUUM {table or 'table'} to enable index-only scans",
            variant_type=VariantType.CONFIG,
            risk=VariantRisk.NONE,
            hypothesis=hypothesis,
            config_commands=[
                f"VACUUM{' ' + table if table else ''};",
            ],
            predicted_cost_reduction_pct=20.0,
            predicted_mechanism="VACUUM marks pages all-visible, eliminating heap fetches",
        )

    if rule_id == "PARALLEL_QUERY_NOT_USED":
        return Variant(
            name="Enable parallel query for this session",
            variant_type=VariantType.PLANNER_HINT,
            risk=VariantRisk.LOW,
            hypothesis=hypothesis,
            planner_settings={
                "max_parallel_workers_per_gather": "4",
                "parallel_tuple_cost": "0.001",
            },
            predicted_cost_reduction_pct=40.0,
            predicted_mechanism="Parallel workers divide scan work across CPUs",
        )

    return None


def _generate_planner_hint_variant(finding: Any, hypothesis: Hypothesis) -> Variant | None:
    """Generate a planner hint variant (SET enable_*)."""
    rule_id = getattr(finding, "rule_id", "")

    if rule_id == "NESTED_LOOP_LARGE_TABLE":
        return Variant(
            name="Force Hash Join (disable Nested Loop)",
            variant_type=VariantType.PLANNER_HINT,
            risk=VariantRisk.LOW,
            hypothesis=hypothesis,
            planner_settings={"enable_nestloop": "off"},
            predicted_cost_reduction_pct=50.0,
            predicted_mechanism="Hash Join is O(N+M); Nested Loop is O(N*M) without index",
        )

    return None


# ── Core Workbook Engine ───────────────────────────────────────────────


class TuningWorkbook:
    """
    The automated "Ultimate Optimization Algorithm" from Ch. 16.

    Implements the full scientific-method workflow:
    Baseline → Diagnose → Hypothesize → Plan → Predict → Test → Compare → Recommend

    Works offline (predict-only) or with a live database (full testing).
    """

    def __init__(
        self,
        max_variants: int = 10,
        min_confidence: float = 0.3,
    ) -> None:
        self.max_variants = max_variants
        self.min_confidence = min_confidence

    def run(
        self,
        explain_json: str | dict,
        sql: str = "",
    ) -> WorkbookResult:
        """
        Run the full workbook offline (no DB required).

        Performs: Baseline → Diagnose → Hypothesize → Plan → Predict → Recommend
        (skips Test and Compare phases, which require a live database)
        """
        start = time.perf_counter()
        result = WorkbookResult(sql=sql)

        # 1. BASELINE
        baseline = self._capture_baseline(explain_json, sql)
        result.baseline = baseline
        result.phases_completed.append(WorkbookPhase.BASELINE)

        # 2. DIAGNOSE
        findings = self._diagnose(explain_json)
        if baseline:
            baseline.findings_count = len(findings)
            baseline.critical_count = sum(
                1 for f in findings
                if getattr(f, "severity", None) and str(getattr(f.severity, "value", f.severity)) == "critical"
            )
        result.phases_completed.append(WorkbookPhase.DIAGNOSE)

        # 3. HYPOTHESIZE
        hypotheses = self._generate_hypotheses(findings)
        result.hypotheses = hypotheses
        result.phases_completed.append(WorkbookPhase.HYPOTHESIZE)

        # 4. PLAN (generate variants)
        variants = self._generate_variants(findings, hypotheses, sql)
        result.variants = variants
        result.phases_completed.append(WorkbookPhase.PLAN)

        # 5. PREDICT (estimate impact without running)
        self._predict_impacts(variants, baseline)
        result.phases_completed.append(WorkbookPhase.PREDICT)

        # 8. RECOMMEND (rank by predicted impact)
        result.recommendations = sorted(
            [v for v in variants if v.improvement_pct > 0],
            key=lambda v: v.improvement_pct,
            reverse=True,
        )[:self.max_variants]
        result.phases_completed.append(WorkbookPhase.RECOMMEND)

        result.total_time_ms = (time.perf_counter() - start) * 1000
        result.query_hash = hashlib.md5(sql.encode()).hexdigest()[:16] if sql else ""
        return result

    async def run_with_db(
        self,
        explain_json: str | dict,
        sql: str,
        dsn: str,
    ) -> WorkbookResult:
        """
        Run the full workbook with live database testing.

        Performs all 8 phases including EXPLAIN execution of variants.
        """
        # First run offline phases
        result = self.run(explain_json, sql)

        if not sql or not dsn:
            return result

        try:
            import asyncpg
        except ImportError:
            logger.warning("asyncpg not installed — skipping live testing")
            return result

        # 6. TEST
        conn = await asyncpg.connect(dsn)
        try:
            for variant in result.variants:
                await self._test_variant(conn, variant, sql, result.baseline)
            result.phases_completed.append(WorkbookPhase.TEST)

            # 7. COMPARE
            comparisons = self._compare_results(result.baseline, result.variants)
            result.comparisons = comparisons
            result.phases_completed.append(WorkbookPhase.COMPARE)

            # Re-rank with measured data
            result.recommendations = sorted(
                [v for v in result.variants if v.improvement_pct > 0 and not v.test_error],
                key=lambda v: v.improvement_pct,
                reverse=True,
            )[:self.max_variants]

        except Exception as e:
            logger.error("DB testing failed: %s", e)
        finally:
            await conn.close()

        return result

    # ── Phase implementations ─────────────────────────────────────────

    def _capture_baseline(self, explain_json: str | dict, sql: str) -> Baseline:
        """Phase 1: Capture baseline metrics."""
        if isinstance(explain_json, str):
            try:
                data = json.loads(explain_json)
            except json.JSONDecodeError:
                return Baseline(plan_json={}, sql=sql)
        else:
            data = explain_json

        if isinstance(data, list):
            data = data[0]

        plan = data.get("Plan", data)

        return Baseline(
            plan_json=data,
            sql=sql,
            total_cost=plan.get("Total Cost", 0),
            execution_time_ms=plan.get("Actual Total Time"),
            rows_returned=plan.get("Actual Rows"),
            shared_hit_blocks=plan.get("Shared Hit Blocks", 0),
            shared_read_blocks=plan.get("Shared Read Blocks", 0),
            temp_written_blocks=plan.get("Temp Written Blocks", 0),
            node_count=self._count_nodes(plan),
            structure_hash=hashlib.md5(
                json.dumps(plan, sort_keys=True, default=str).encode()
            ).hexdigest()[:16],
        )

    def _diagnose(self, explain_json: str | dict) -> list[Any]:
        """Phase 2: Run QuerySense analysis to get findings."""
        try:
            from querysense.analyzer.analyzer import Analyzer
            from querysense.parser.parser import parse_explain

            if isinstance(explain_json, str):
                explain = parse_explain(explain_json)
            else:
                explain = parse_explain(json.dumps(explain_json))

            analyzer = Analyzer()
            result = analyzer.analyze(explain)
            return list(result.findings)
        except Exception as e:
            logger.warning("Diagnosis failed: %s", e)
            return []

    def _generate_hypotheses(self, findings: list[Any]) -> list[Hypothesis]:
        """Phase 3: Generate optimization hypotheses from findings."""
        hypotheses: list[Hypothesis] = []
        seen_rules: set[str] = set()

        for finding in findings:
            rule_id = getattr(finding, "rule_id", "")
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)

            template = _HYPOTHESIS_MAP.get(rule_id, _DEFAULT_HYPOTHESIS)

            if template["confidence"] < self.min_confidence:
                continue

            severity = getattr(finding, "severity", "info")
            if hasattr(severity, "value"):
                severity = severity.value

            hypotheses.append(Hypothesis(
                finding_rule_id=rule_id,
                finding_title=getattr(finding, "title", rule_id),
                finding_severity=str(severity),
                hypothesis=template["hypothesis"],
                mechanism=template["mechanism"],
                expected_impact=template["expected_impact"],
                confidence=template["confidence"],
                textbook_ref=template.get("textbook_ref", ""),
            ))

        # Sort by confidence * impact weight
        impact_weights = {"major": 3, "moderate": 2, "minor": 1}
        hypotheses.sort(
            key=lambda h: h.confidence * impact_weights.get(h.expected_impact, 1),
            reverse=True,
        )

        return hypotheses

    def _generate_variants(
        self,
        findings: list[Any],
        hypotheses: list[Hypothesis],
        sql: str,
    ) -> list[Variant]:
        """Phase 4: Generate concrete optimization variants."""
        variants: list[Variant] = []
        hypothesis_map = {h.finding_rule_id: h for h in hypotheses}

        for finding in findings:
            rule_id = getattr(finding, "rule_id", "")
            hyp = hypothesis_map.get(rule_id)
            if not hyp:
                continue

            template = _HYPOTHESIS_MAP.get(rule_id, _DEFAULT_HYPOTHESIS)
            vtype = template.get("variant_type", VariantType.COMPOSITE)

            variant = None
            if vtype == VariantType.INDEX:
                variant = _generate_index_variant(finding, hyp)
            elif vtype == VariantType.REWRITE:
                variant = _generate_rewrite_variant(finding, hyp, sql)
            elif vtype == VariantType.CONFIG:
                variant = _generate_config_variant(finding, hyp)
            elif vtype == VariantType.PLANNER_HINT:
                variant = _generate_planner_hint_variant(finding, hyp)

            if variant:
                variants.append(variant)

            # Also try a rewrite variant if the primary isn't a rewrite
            if vtype != VariantType.REWRITE and sql:
                rewrite_var = _generate_rewrite_variant(finding, hyp, sql)
                if rewrite_var:
                    variants.append(rewrite_var)

        return variants[:self.max_variants]

    def _predict_impacts(self, variants: list[Variant], baseline: Baseline | None) -> None:
        """Phase 5: Estimate variant impacts based on heuristics."""
        if not baseline:
            return

        for variant in variants:
            # Adjust predictions based on hypothesis confidence
            variant.predicted_cost_reduction_pct *= variant.hypothesis.confidence

            # Cap optimistic predictions
            variant.predicted_cost_reduction_pct = min(
                variant.predicted_cost_reduction_pct, 90.0
            )

    async def _test_variant(
        self,
        conn: Any,
        variant: Variant,
        original_sql: str,
        baseline: Baseline | None,
    ) -> None:
        """Phase 6: Test a variant against the live database."""
        test_sql = variant.rewritten_sql or original_sql

        try:
            # Apply planner settings in a transaction
            await conn.execute("BEGIN")

            for setting, value in variant.planner_settings.items():
                await conn.execute(f"SET LOCAL {setting} = {value}")

            # Run EXPLAIN ANALYZE in a subtransaction
            await conn.execute("SAVEPOINT variant_test")

            explain_result = await conn.fetchrow(
                f"EXPLAIN (ANALYZE, FORMAT JSON) {test_sql}"
            )

            await conn.execute("ROLLBACK TO SAVEPOINT variant_test")
            await conn.execute("ROLLBACK")

            if explain_result:
                plan_json = json.loads(explain_result[0])
                plan = plan_json[0] if isinstance(plan_json, list) else plan_json
                root = plan.get("Plan", plan)

                variant.measured_cost = root.get("Total Cost", 0)
                variant.measured_time_ms = root.get("Actual Total Time")
                variant.measured_plan = plan_json

                if baseline and baseline.total_cost > 0:
                    variant.measured_improvement_pct = (
                        (baseline.total_cost - variant.measured_cost) / baseline.total_cost
                    ) * 100

        except Exception as e:
            try:
                await conn.execute("ROLLBACK")
            except Exception:
                pass
            variant.test_error = str(e)
            logger.debug("Variant test failed: %s — %s", variant.name, e)

    def _compare_results(
        self,
        baseline: Baseline | None,
        variants: list[Variant],
    ) -> list[ComparisonResult]:
        """Phase 7: Statistical comparison of baseline vs variants."""
        if not baseline:
            return []

        comparisons: list[ComparisonResult] = []
        for variant in variants:
            if variant.measured_cost is None:
                continue

            cost_imp = (
                (baseline.total_cost - variant.measured_cost) / baseline.total_cost * 100
                if baseline.total_cost > 0 else 0
            )

            time_imp = None
            if baseline.execution_time_ms and variant.measured_time_ms:
                time_imp = (
                    (baseline.execution_time_ms - variant.measured_time_ms)
                    / baseline.execution_time_ms * 100
                )

            plan_changed = False
            if variant.measured_plan:
                measured_hash = hashlib.md5(
                    json.dumps(variant.measured_plan, sort_keys=True, default=str).encode()
                ).hexdigest()[:16]
                plan_changed = measured_hash != baseline.structure_hash

            risk_str = "safe" if variant.risk in (VariantRisk.NONE, VariantRisk.LOW) else variant.risk.value

            comparisons.append(ComparisonResult(
                variant_name=variant.name,
                baseline_cost=baseline.total_cost,
                variant_cost=variant.measured_cost,
                cost_improvement_pct=cost_imp,
                baseline_time_ms=baseline.execution_time_ms,
                variant_time_ms=variant.measured_time_ms,
                time_improvement_pct=time_imp,
                plan_changed=plan_changed,
                risk_assessment=risk_str,
            ))

        return sorted(comparisons, key=lambda c: c.cost_improvement_pct, reverse=True)

    @staticmethod
    def _count_nodes(plan: dict) -> int:
        """Count total nodes in a plan tree."""
        count = 1
        for child in plan.get("Plans", []):
            count += TuningWorkbook._count_nodes(child)
        return count
