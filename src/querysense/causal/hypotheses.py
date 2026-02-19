"""
Root-cause hypothesis catalog.

Each hypothesis is a potential root cause of poor query performance.
Hypotheses are engine-portable where possible, with engine-specific
evidence functions separated into the evidence module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HypothesisID(str, Enum):
    """Identifiers for the built-in hypothesis catalog."""

    H1_MISSING_ACCESS_PATH = "H1_missing_access_path"
    H2_BAD_CARDINALITY = "H2_bad_cardinality_estimate"
    H3_STALE_STATISTICS = "H3_stale_statistics"
    H4_INSUFFICIENT_STATS = "H4_insufficient_stats_skew"
    H5_COST_MISCONFIGURATION = "H5_cost_misconfiguration"
    H6_MEMORY_PRESSURE = "H6_memory_pressure_spill"
    H7_JOIN_MISMATCH = "H7_join_strategy_mismatch"
    H8_LOCK_CONTENTION = "H8_lock_contention"
    H9_PLAN_REGRESSION = "H9_plan_regression"
    H10_SUBOPTIMAL_PARALLELISM = "H10_suboptimal_parallelism"


@dataclass(frozen=True)
class CausalHypothesis:
    """
    A root-cause hypothesis definition.

    Attributes:
        id: Unique hypothesis identifier.
        title: Human-readable title.
        description: Detailed explanation of the hypothesis.
        category: Category grouping (e.g. "statistics", "access", "config").
        portable: True if the hypothesis applies across engines.
        required_capabilities: IR capabilities needed to evaluate this hypothesis.
        weight: Base importance weight (0.0-1.0).
        remediation_template: Template for remediation suggestions.
        references: Links to documentation.
    """

    id: HypothesisID
    title: str
    description: str
    category: str
    portable: bool = True
    required_capabilities: tuple[str, ...] = ()
    weight: float = 1.0
    remediation_template: str = ""
    references: tuple[str, ...] = ()


# ── Built-in hypothesis catalog ──────────────────────────────────────

HYPOTHESIS_CATALOG: dict[HypothesisID, CausalHypothesis] = {
    HypothesisID.H1_MISSING_ACCESS_PATH: CausalHypothesis(
        id=HypothesisID.H1_MISSING_ACCESS_PATH,
        title="Missing Access Path",
        description=(
            "No suitable index or access path exists for the predicate(s) "
            "used in this query.  The optimizer is forced to use a sequential "
            "scan because no narrowing index is available."
        ),
        category="access",
        weight=0.9,
        remediation_template=(
            "Consider creating an index: CREATE INDEX idx_{table}_{columns} "
            "ON {table}({columns});"
        ),
    ),
    HypothesisID.H2_BAD_CARDINALITY: CausalHypothesis(
        id=HypothesisID.H2_BAD_CARDINALITY,
        title="Bad Cardinality Estimate",
        description=(
            "The optimizer's row estimate diverges strongly from actual rows.  "
            "This is the single most common cause of poor plan choices: "
            "wrong cardinalities lead to wrong join ordering, wrong join "
            "algorithms, and wrong scan methods."
        ),
        category="statistics",
        required_capabilities=("has_actual_rows", "has_estimated_rows"),
        weight=1.0,
        remediation_template=(
            "Run ANALYZE on affected tables.  If estimates remain off, "
            "increase statistics target or create extended statistics for "
            "correlated columns."
        ),
    ),
    HypothesisID.H3_STALE_STATISTICS: CausalHypothesis(
        id=HypothesisID.H3_STALE_STATISTICS,
        title="Stale Statistics",
        description=(
            "Table statistics are out of date relative to data churn.  "
            "The optimizer uses stale histograms/MCVs, producing incorrect "
            "cardinality estimates and suboptimal plan choices."
        ),
        category="statistics",
        required_capabilities=("has_db_stats",),
        weight=0.85,
        remediation_template=(
            "Run ANALYZE {table}; to refresh statistics.  Consider tuning "
            "autovacuum settings: autovacuum_analyze_threshold and "
            "autovacuum_analyze_scale_factor."
        ),
    ),
    HypothesisID.H4_INSUFFICIENT_STATS: CausalHypothesis(
        id=HypothesisID.H4_INSUFFICIENT_STATS,
        title="Insufficient Statistics for Skew/Correlation",
        description=(
            "Histograms or most-common-values (MCVs) are insufficient to "
            "capture data skew or cross-column correlations.  The default "
            "statistics target may be too low, or extended (multivariate) "
            "statistics may be needed."
        ),
        category="statistics",
        required_capabilities=("has_actual_rows", "has_estimated_rows"),
        weight=0.75,
        remediation_template=(
            "Increase per-column statistics target: "
            "ALTER TABLE {table} ALTER COLUMN {column} SET STATISTICS 1000; "
            "For correlated columns, create extended statistics: "
            "CREATE STATISTICS {table}_ext ON ({columns}) FROM {table};"
        ),
    ),
    HypothesisID.H5_COST_MISCONFIGURATION: CausalHypothesis(
        id=HypothesisID.H5_COST_MISCONFIGURATION,
        title="Misconfigured Planner Cost Constants",
        description=(
            "IO cost assumptions (random_page_cost, seq_page_cost, "
            "effective_cache_size) may be misconfigured for the storage "
            "hardware, pushing the optimizer away from index usage."
        ),
        category="configuration",
        required_capabilities=("has_db_settings",),
        weight=0.5,
        remediation_template=(
            "For SSD storage, set random_page_cost = 1.1 (default 4.0) "
            "and effective_cache_size to ~75%% of available RAM."
        ),
        portable=False,  # cost constants are engine-specific
    ),
    HypothesisID.H6_MEMORY_PRESSURE: CausalHypothesis(
        id=HypothesisID.H6_MEMORY_PRESSURE,
        title="Memory Pressure / Spill to Disk",
        description=(
            "Sorts, hash joins, or hash aggregates are spilling to disk "
            "because work_mem is insufficient.  This causes dramatic "
            "slowdowns as operations move from in-memory to disk-based."
        ),
        category="resource",
        required_capabilities=("has_temp_spill",),
        weight=0.8,
        remediation_template=(
            "Increase work_mem for this session: SET work_mem = '{mem}MB'; "
            "Current sort/hash is using {current_kb}KB with type={spill_type}."
        ),
    ),
    HypothesisID.H7_JOIN_MISMATCH: CausalHypothesis(
        id=HypothesisID.H7_JOIN_MISMATCH,
        title="Join Strategy Mismatch",
        description=(
            "Nested loop join is selected where hash or merge join would "
            "likely dominate, often a downstream consequence of bad "
            "cardinality estimates (H2) or insufficient statistics (H4)."
        ),
        category="join",
        weight=0.7,
        remediation_template=(
            "If this is caused by bad estimates, fix the underlying "
            "statistics issue.  Otherwise, consider SET enable_nestloop = off "
            "as a diagnostic (not production) measure."
        ),
    ),
    HypothesisID.H8_LOCK_CONTENTION: CausalHypothesis(
        id=HypothesisID.H8_LOCK_CONTENTION,
        title="Lock Contention",
        description=(
            "Row-level locking (SELECT FOR UPDATE) or table-level locks "
            "may cause performance degradation under concurrency."
        ),
        category="concurrency",
        weight=0.4,
    ),
    HypothesisID.H9_PLAN_REGRESSION: CausalHypothesis(
        id=HypothesisID.H9_PLAN_REGRESSION,
        title="Plan Regression",
        description=(
            "The plan structure has changed compared to a known baseline, "
            "resulting in degraded performance.  This may be caused by "
            "statistics changes, config changes, or schema changes."
        ),
        category="regression",
        required_capabilities=("has_baseline",),
        weight=0.9,
        remediation_template=(
            "Compare current plan with baseline.  If regression is due to "
            "statistics, refresh with ANALYZE.  If config-related, review "
            "recent configuration changes."
        ),
    ),
    HypothesisID.H10_SUBOPTIMAL_PARALLELISM: CausalHypothesis(
        id=HypothesisID.H10_SUBOPTIMAL_PARALLELISM,
        title="Suboptimal Parallelism",
        description=(
            "The plan requests parallel workers but fewer are launched "
            "than planned, or parallelism is not used where it would help."
        ),
        category="parallelism",
        required_capabilities=("has_parallel_info",),
        weight=0.5,
        remediation_template=(
            "Check max_parallel_workers_per_gather and max_worker_processes. "
            "Launched {launched} of {planned} planned workers."
        ),
    ),
}
