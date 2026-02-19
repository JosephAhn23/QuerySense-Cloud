"""
Engine capability profiles for progressive enhancement.

Defines what analysis features are available for each database engine,
following SQLAlchemy's dialect system and Metabase's database-supports?
pattern. The UI and analysis pipeline adapt based on these profiles.

Design principles:
- Capabilities are declared per-engine, not per-analysis
- Progressive enhancement: all engines get basic analysis, some get more
- Capability flags control which rules run and what output is shown
- Engine versions affect capabilities (e.g., MySQL 8.0.18+ has EXPLAIN ANALYZE)

Based on:
- SQLAlchemy's Requirements/capability decorators
- Metabase's database-supports? multimethod
- UPlan's 80% effort reduction through progressive capability

Usage:
    from querysense.analyzer.engine_profile import get_engine_profile

    profile = get_engine_profile("postgres", version="15.2")
    if profile.supports(EngineFeature.EXPLAIN_ANALYZE):
        # Run estimated-vs-actual comparison
    if profile.supports(EngineFeature.BUFFER_TRACKING):
        # Show I/O analysis
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, unique
from typing import Any


@unique
class EngineFeature(str, Enum):
    """
    Features that may or may not be available on a given engine.

    These map to analysis capabilities — rules and renderers
    check for features before using engine-specific data.
    """

    # Plan analysis features (all engines)
    EXPLAIN_PLAN = "explain_plan"
    OPERATOR_TREE = "operator_tree"

    # Runtime analysis (requires EXPLAIN ANALYZE or equivalent)
    EXPLAIN_ANALYZE = "explain_analyze"
    ACTUAL_TIMING = "actual_timing"
    BUFFER_TRACKING = "buffer_tracking"

    # Advanced plan features
    PARALLEL_QUERY = "parallel_query"
    BITMAP_SCAN = "bitmap_scan"
    MERGE_JOIN = "merge_join"
    HASH_JOIN = "hash_join"
    INDEX_ONLY_SCAN = "index_only_scan"
    CTE_OPTIMIZATION = "cte_optimization"

    # Statistics and metadata
    ROW_ESTIMATES = "row_estimates"
    COST_ESTIMATES = "cost_estimates"
    QUERY_STORE = "query_store"
    EXTENDED_STATISTICS = "extended_statistics"

    # Causal analysis
    CARDINALITY_FEEDBACK = "cardinality_feedback"
    PLAN_HINTS = "plan_hints"
    PLAN_GUIDES = "plan_guides"

    # Cross-engine
    WAIT_TIME_ANALYSIS = "wait_time_analysis"
    QUERY_FINGERPRINT = "query_fingerprint"


@dataclass(frozen=True)
class EngineProfile:
    """
    Capability profile for a specific engine + version.

    Encapsulates what features are available and how to adapt
    analysis behavior accordingly.
    """

    engine: str
    version: str | None
    features: frozenset[EngineFeature]
    operator_count: int
    notes: tuple[str, ...] = ()

    def supports(self, feature: EngineFeature) -> bool:
        return feature in self.features

    def supports_all(self, features: set[EngineFeature]) -> bool:
        return features.issubset(self.features)

    def supports_any(self, features: set[EngineFeature]) -> bool:
        return bool(features & self.features)

    def missing(self, features: set[EngineFeature]) -> set[EngineFeature]:
        return features - self.features

    @property
    def analysis_tier(self) -> str:
        """
        Human-readable analysis tier:
        - "full": EXPLAIN ANALYZE + buffers + timing
        - "estimated": Row/cost estimates but no actuals
        - "basic": Operator tree only
        """
        if self.supports(EngineFeature.EXPLAIN_ANALYZE):
            if self.supports(EngineFeature.BUFFER_TRACKING):
                return "full"
            return "estimated"
        if self.supports(EngineFeature.ROW_ESTIMATES):
            return "estimated"
        return "basic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "version": self.version,
            "analysis_tier": self.analysis_tier,
            "features": sorted(f.value for f in self.features),
            "operator_count": self.operator_count,
            "notes": list(self.notes),
        }


# ── Engine feature sets ──────────────────────────────────────────────────

_PG_FEATURES = frozenset({
    EngineFeature.EXPLAIN_PLAN,
    EngineFeature.OPERATOR_TREE,
    EngineFeature.EXPLAIN_ANALYZE,
    EngineFeature.ACTUAL_TIMING,
    EngineFeature.BUFFER_TRACKING,
    EngineFeature.PARALLEL_QUERY,
    EngineFeature.BITMAP_SCAN,
    EngineFeature.MERGE_JOIN,
    EngineFeature.HASH_JOIN,
    EngineFeature.INDEX_ONLY_SCAN,
    EngineFeature.CTE_OPTIMIZATION,
    EngineFeature.ROW_ESTIMATES,
    EngineFeature.COST_ESTIMATES,
    EngineFeature.EXTENDED_STATISTICS,
    EngineFeature.PLAN_HINTS,
    EngineFeature.WAIT_TIME_ANALYSIS,
    EngineFeature.QUERY_FINGERPRINT,
})

_MYSQL_BASE_FEATURES = frozenset({
    EngineFeature.EXPLAIN_PLAN,
    EngineFeature.OPERATOR_TREE,
    EngineFeature.ROW_ESTIMATES,
    EngineFeature.COST_ESTIMATES,
    EngineFeature.PLAN_HINTS,
    EngineFeature.QUERY_FINGERPRINT,
})

_MYSQL_8018_FEATURES = _MYSQL_BASE_FEATURES | frozenset({
    EngineFeature.EXPLAIN_ANALYZE,
    EngineFeature.ACTUAL_TIMING,
    EngineFeature.HASH_JOIN,
})

_SS_FEATURES = frozenset({
    EngineFeature.EXPLAIN_PLAN,
    EngineFeature.OPERATOR_TREE,
    EngineFeature.EXPLAIN_ANALYZE,
    EngineFeature.ACTUAL_TIMING,
    EngineFeature.PARALLEL_QUERY,
    EngineFeature.MERGE_JOIN,
    EngineFeature.HASH_JOIN,
    EngineFeature.INDEX_ONLY_SCAN,
    EngineFeature.ROW_ESTIMATES,
    EngineFeature.COST_ESTIMATES,
    EngineFeature.QUERY_STORE,
    EngineFeature.EXTENDED_STATISTICS,
    EngineFeature.CARDINALITY_FEEDBACK,
    EngineFeature.PLAN_HINTS,
    EngineFeature.PLAN_GUIDES,
    EngineFeature.WAIT_TIME_ANALYSIS,
    EngineFeature.QUERY_FINGERPRINT,
})

_ORACLE_FEATURES = frozenset({
    EngineFeature.EXPLAIN_PLAN,
    EngineFeature.OPERATOR_TREE,
    EngineFeature.EXPLAIN_ANALYZE,
    EngineFeature.ACTUAL_TIMING,
    EngineFeature.PARALLEL_QUERY,
    EngineFeature.BITMAP_SCAN,
    EngineFeature.MERGE_JOIN,
    EngineFeature.HASH_JOIN,
    EngineFeature.INDEX_ONLY_SCAN,
    EngineFeature.ROW_ESTIMATES,
    EngineFeature.COST_ESTIMATES,
    EngineFeature.EXTENDED_STATISTICS,
    EngineFeature.PLAN_HINTS,
    EngineFeature.PLAN_GUIDES,
    EngineFeature.WAIT_TIME_ANALYSIS,
})


def _parse_version(version: str | None) -> tuple[int, int]:
    """Parse version string into (major, minor)."""
    if not version:
        return (0, 0)
    parts = version.split(".")
    try:
        major = int(parts[0]) if parts else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor)
    except ValueError:
        return (0, 0)


def get_engine_profile(
    engine: str,
    version: str | None = None,
) -> EngineProfile:
    """
    Get the capability profile for an engine + version.

    This is the single source of truth for what analysis features
    are available on each engine.

    Args:
        engine: Engine identifier ("postgres", "mysql", "sqlserver", "oracle")
        version: Optional version string

    Returns:
        EngineProfile with available features
    """
    if engine == "postgres":
        features = _PG_FEATURES
        major, _ = _parse_version(version)
        if 0 < major < 12:
            features = features - {EngineFeature.CTE_OPTIMIZATION}
        return EngineProfile(
            engine=engine,
            version=version,
            features=features,
            operator_count=25,
            notes=(
                "Full EXPLAIN ANALYZE with buffers and timing",
                "Extended statistics via CREATE STATISTICS (PG10+)",
                "CTE inlining control (PG12+)",
            ),
        )

    if engine == "mysql":
        major, minor = _parse_version(version)
        if major >= 8 and minor >= 18:
            features = _MYSQL_8018_FEATURES
        elif major >= 8:
            features = _MYSQL_BASE_FEATURES | frozenset({EngineFeature.HASH_JOIN})
        else:
            features = _MYSQL_BASE_FEATURES
        return EngineProfile(
            engine=engine,
            version=version,
            features=features,
            operator_count=12,
            notes=(
                "EXPLAIN ANALYZE since MySQL 8.0.18",
                "Hash join since MySQL 8.0.18",
                "No merge join, no bitmap scan, no parallel query",
            ),
        )

    if engine == "sqlserver":
        return EngineProfile(
            engine=engine,
            version=version,
            features=_SS_FEATURES,
            operator_count=20,
            notes=(
                "Actual execution plan via SET STATISTICS XML ON",
                "Query Store for regression detection (2016+)",
                "CE Feedback (2022+)",
                "Adaptive joins and batch mode",
            ),
        )

    if engine == "oracle":
        return EngineProfile(
            engine=engine,
            version=version,
            features=_ORACLE_FEATURES,
            operator_count=22,
            notes=(
                "Actual rows via GATHER_PLAN_STATISTICS hint",
                "SQL Profiles for adaptive corrections",
                "Bitmap access paths for star schemas",
                "Parallel execution with PX coordinator",
            ),
        )

    # Unknown engine
    return EngineProfile(
        engine=engine,
        version=version,
        features=frozenset({
            EngineFeature.EXPLAIN_PLAN,
            EngineFeature.OPERATOR_TREE,
        }),
        operator_count=0,
        notes=("Unknown engine — basic operator tree analysis only",),
    )
