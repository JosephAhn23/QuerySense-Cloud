"""
PostgreSQL Version Feature Advisor

Analyzes EXPLAIN plans and detected findings to recommend PostgreSQL
version upgrades that would address specific performance issues.

Sourced from the pganalyze blog series covering PG 14-19 features:
  - PG14: Bottom-up index deletion, Memoize node
  - PG15: Sort performance, server-side backup compression, MERGE
  - PG16: Incremental sort improvements, COPY 300% faster, pg_stat_io
  - PG17: C.UTF-8 builtin locale, streaming I/O, faster B-tree IN scans,
          improved SubPlan EXPLAIN, faster VACUUM with radix trees
  - PG18: Asynchronous I/O, AIO for seq scans
  - PG19: Path generation strategies, better planner hints

Usage:
    from querysense.pg_version_advisor import PGVersionAdvisor

    advisor = PGVersionAdvisor(current_version=15)
    recommendations = advisor.analyze_findings(result.findings)
    print(advisor.format_report(recommendations))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class UpgradeUrgency(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class VersionRecommendation:
    """A single PG version upgrade recommendation."""
    target_version: int
    feature: str
    description: str
    urgency: UpgradeUrgency
    related_rule_ids: tuple[str, ...]
    blog_ref: str = ""

    @property
    def version_label(self) -> str:
        return f"PostgreSQL {self.target_version}"


@dataclass(frozen=True)
class PGFeature:
    """A PostgreSQL version feature that addresses specific plan patterns."""
    min_version: int
    feature_name: str
    description: str
    trigger_rule_ids: tuple[str, ...]
    urgency: UpgradeUrgency = UpgradeUrgency.MEDIUM
    blog_ref: str = ""


_PG_FEATURES: list[PGFeature] = [
    PGFeature(
        min_version=14,
        feature_name="Memoize node for nested loops",
        description=(
            "PG14 added the Memoize node that caches results of "
            "parameterized scans inside nested loops, reducing repeated "
            "index lookups by up to 10x for correlated joins."
        ),
        trigger_rule_ids=("NESTED_LOOP_LARGE_TABLE", "SUBPLAN_HIGH_LOOPS"),
        urgency=UpgradeUrgency.MEDIUM,
        blog_ref="5mins of Postgres E51: Using Memoize to speed up joins",
    ),
    PGFeature(
        min_version=14,
        feature_name="Bottom-up index deletion",
        description=(
            "PG14 proactively removes dead index tuples during page splits, "
            "reducing index bloat without waiting for VACUUM."
        ),
        trigger_rule_ids=("TABLE_BLOAT",),
        urgency=UpgradeUrgency.LOW,
        blog_ref="5mins of Postgres E14: HOT Updates vs Bottom-Up Index Deletion",
    ),
    PGFeature(
        min_version=15,
        feature_name="Faster sort performance",
        description=(
            "PG15 improved sort operations with specialized routines for "
            "common data types, reduced memory consumption, and a better "
            "algorithm for disk-based sorts. Sorts can be 20-40% faster."
        ),
        trigger_rule_ids=("SPILLING_TO_DISK", "COLLATION_SORT_EXPENSIVE", "REDUNDANT_SORT"),
        urgency=UpgradeUrgency.MEDIUM,
        blog_ref="5mins of Postgres E19: Speeding up sort performance in Postgres 15",
    ),
    PGFeature(
        min_version=16,
        feature_name="Incremental Sort improvements",
        description=(
            "PG16 makes better use of existing sort orders, applying "
            "Incremental Sort in more cases and improving anti-JOIN "
            "performance."
        ),
        trigger_rule_ids=(
            "SORT_AVOIDABLE_WITH_INDEX", "REDUNDANT_SORT",
        ),
        urgency=UpgradeUrgency.LOW,
        blog_ref="5mins of Postgres E101: Faster query plans with Postgres 16",
    ),
    PGFeature(
        min_version=16,
        feature_name="BRIN indexes ignore HOT updates",
        description=(
            "PG16 stops BRIN indexes from blocking HOT (Heap-Only Tuple) "
            "updates, reducing table bloat on tables with BRIN indexes."
        ),
        trigger_rule_ids=("TABLE_BLOAT",),
        urgency=UpgradeUrgency.LOW,
        blog_ref="5mins of Postgres E86: HOT Updates and BRIN indexes in Postgres 16",
    ),
    PGFeature(
        min_version=17,
        feature_name="Builtin C.UTF-8 locale (binary sort)",
        description=(
            "PG17 adds a builtin collation provider with C.UTF-8 locale "
            "that provides binary sort speed (2-3x faster) while keeping "
            "Unicode-aware UPPER/LOWER. No glibc dependency."
        ),
        trigger_rule_ids=("COLLATION_SORT_EXPENSIVE",),
        urgency=UpgradeUrgency.HIGH,
        blog_ref="5mins of Postgres E107: The new built-in C.UTF-8 locale",
    ),
    PGFeature(
        min_version=17,
        feature_name="Faster B-tree scans for IN/ANY lists",
        description=(
            "PG17 avoids repeated page access when scanning B-tree "
            "indexes with IN lists or ANY arrays, yielding significant "
            "speedups for multi-value lookups."
        ),
        trigger_rule_ids=("INEFFICIENT_INDEX_SCAN", "SEQ_SCAN_LARGE_TABLE"),
        urgency=UpgradeUrgency.MEDIUM,
        blog_ref="5mins of Postgres E111: Faster B-Tree Index Scans for IN lists",
    ),
    PGFeature(
        min_version=17,
        feature_name="Streaming I/O for sequential scans",
        description=(
            "PG17 uses vectored/streaming I/O for sequential scans and "
            "ANALYZE, pre-fetching pages ahead of the scan cursor for "
            "better I/O throughput."
        ),
        trigger_rule_ids=("SEQ_SCAN_LARGE_TABLE", "SEQ_SCAN_NO_FILTER"),
        urgency=UpgradeUrgency.MEDIUM,
        blog_ref="5mins of Postgres E112: Streaming I/O for sequential scans",
    ),
    PGFeature(
        min_version=17,
        feature_name="Faster VACUUM with Adaptive Radix Trees",
        description=(
            "PG17 replaces the flat dead-tuple array with a radix tree, "
            "reducing autovacuum memory usage and eliminating the need "
            "for multiple index vacuum phases."
        ),
        trigger_rule_ids=("TABLE_BLOAT", "STALE_STATISTICS"),
        urgency=UpgradeUrgency.MEDIUM,
        blog_ref="5mins of Postgres E109: Faster VACUUM with Adaptive Radix Trees",
    ),
    PGFeature(
        min_version=17,
        feature_name="Improved EXPLAIN for SubPlan nodes",
        description=(
            "PG17 shows actual expressions in SubPlan filter output, "
            "making correlated subplans much easier to diagnose."
        ),
        trigger_rule_ids=("SUBPLAN_HIGH_LOOPS", "CORRELATED_SUBQUERY"),
        urgency=UpgradeUrgency.INFO,
        blog_ref="5mins of Postgres E108: Improved EXPLAIN for SubPlan nodes",
    ),
    PGFeature(
        min_version=18,
        feature_name="Asynchronous I/O (AIO)",
        description=(
            "PG18 introduces async I/O infrastructure, allowing Postgres "
            "to issue non-blocking disk reads. Particularly beneficial "
            "in cloud environments where latency is the bottleneck."
        ),
        trigger_rule_ids=(
            "SEQ_SCAN_LARGE_TABLE", "BUFFER_ANALYSIS",
        ),
        urgency=UpgradeUrgency.MEDIUM,
        blog_ref="PG18: Accelerating Disk Reads with Asynchronous I/O",
    ),
    PGFeature(
        min_version=19,
        feature_name="Path generation strategies (planner hints)",
        description=(
            "PG19 improves planner extensibility with path generation "
            "strategies, enabling the pg_plan_advice extension for "
            "better plan management and planner hints."
        ),
        trigger_rule_ids=("COST_HOTSPOT", "PARALLEL_QUERY_NOT_USED"),
        urgency=UpgradeUrgency.LOW,
        blog_ref="PG19: Better Planner Hints with Path Generation Strategies",
    ),
]


class PGVersionAdvisor:
    """Recommends PG version upgrades based on detected plan issues."""

    def __init__(self, current_version: int = 15) -> None:
        self.current_version = current_version

    def analyze_findings(
        self,
        findings: tuple | list,
    ) -> list[VersionRecommendation]:
        detected_rules = {f.rule_id for f in findings}
        recommendations: list[VersionRecommendation] = []
        seen_features: set[str] = set()

        for feature in _PG_FEATURES:
            if feature.min_version <= self.current_version:
                continue

            matching = detected_rules & set(feature.trigger_rule_ids)
            if not matching:
                continue

            if feature.feature_name in seen_features:
                continue
            seen_features.add(feature.feature_name)

            recommendations.append(VersionRecommendation(
                target_version=feature.min_version,
                feature=feature.feature_name,
                description=feature.description,
                urgency=feature.urgency,
                related_rule_ids=tuple(sorted(matching)),
                blog_ref=feature.blog_ref,
            ))

        recommendations.sort(
            key=lambda r: (
                {"high": 0, "medium": 1, "low": 2, "info": 3}[r.urgency.value],
                r.target_version,
            )
        )

        return recommendations

    def format_report(
        self,
        recommendations: list[VersionRecommendation],
    ) -> str:
        lines = [
            "=" * 64,
            f"  PG Version Advisor (current: PostgreSQL {self.current_version})",
            "=" * 64,
            "",
        ]

        if not recommendations:
            lines.append("  No version-specific recommendations found.")
            return "\n".join(lines)

        by_version: dict[int, list[VersionRecommendation]] = {}
        for r in recommendations:
            by_version.setdefault(r.target_version, []).append(r)

        for version in sorted(by_version):
            recs = by_version[version]
            lines.append(f"  PostgreSQL {version}:")
            for r in recs:
                urgency = r.urgency.value.upper()
                lines.append(f"    [{urgency}] {r.feature}")
                lines.append(f"           {r.description[:120]}")
                if r.related_rule_ids:
                    lines.append(f"           Triggered by: {', '.join(r.related_rule_ids)}")
                if r.blog_ref:
                    lines.append(f"           Ref: {r.blog_ref}")
                lines.append("")

        return "\n".join(lines)
