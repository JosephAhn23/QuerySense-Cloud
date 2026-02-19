"""
Analyze performance impact of upgrading PostgreSQL versions.

Based on pganalyze blog posts covering Postgres 17 streaming I/O,
Postgres 16 incremental sort / presorted aggregates, and version-specific
regression patterns.

Usage:
    from querysense.upgrade.version_impact import VersionUpgradeAnalyzer

    analyzer = VersionUpgradeAnalyzer("15", "17")
    impact = analyzer.analyze_upgrade(workload_queries=["SELECT COUNT(*) FROM orders"])
    print(impact)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PostgresVersion(Enum):
    PG12 = "12"
    PG13 = "13"
    PG14 = "14"
    PG15 = "15"
    PG16 = "16"
    PG17 = "17"
    PG18 = "18"


@dataclass
class VersionFeature:
    """Feature introduced in a PostgreSQL version."""
    version: PostgresVersion
    feature_name: str
    description: str
    performance_impact: str  # "positive", "negative", "mixed"
    affected_query_patterns: List[str]
    configuration_required: bool
    default_enabled: bool


@dataclass
class UpgradeImpact:
    """Impact of upgrading between versions."""
    from_version: PostgresVersion
    to_version: PostgresVersion
    expected_speedup_pct: float
    regression_risk: str  # "low", "medium", "high"
    features_gained: List[VersionFeature]
    breaking_changes: List[str]
    recommended_settings: Dict[str, Any]
    test_queries: List[str]


class VersionUpgradeAnalyzer:
    """
    Predict performance impact of upgrading PostgreSQL versions.
    Identifies regressions, new features, and recommended settings.
    """

    VERSION_FEATURES: dict[PostgresVersion, list[VersionFeature]] = {
        PostgresVersion.PG13: [
            VersionFeature(
                version=PostgresVersion.PG13,
                feature_name="incremental_sort",
                description="Incremental Sort for partially sorted data",
                performance_impact="positive",
                affected_query_patterns=[
                    "ORDER BY multiple columns",
                    "DISTINCT",
                    "GROUP BY",
                ],
                configuration_required=False,
                default_enabled=True,
            ),
            VersionFeature(
                version=PostgresVersion.PG13,
                feature_name="deduplication",
                description="B-Tree index deduplication",
                performance_impact="positive",
                affected_query_patterns=[
                    "low cardinality columns",
                    "index heavy workloads",
                ],
                configuration_required=False,
                default_enabled=True,
            ),
        ],
        PostgresVersion.PG14: [
            VersionFeature(
                version=PostgresVersion.PG14,
                feature_name="connection_slot_limit",
                description="Improved connection slot handling under heavy load",
                performance_impact="positive",
                affected_query_patterns=["high connection count"],
                configuration_required=False,
                default_enabled=True,
            ),
        ],
        PostgresVersion.PG15: [
            VersionFeature(
                version=PostgresVersion.PG15,
                feature_name="merge_command",
                description="SQL MERGE command support",
                performance_impact="positive",
                affected_query_patterns=["INSERT ON CONFLICT", "upsert patterns"],
                configuration_required=False,
                default_enabled=True,
            ),
        ],
        PostgresVersion.PG16: [
            VersionFeature(
                version=PostgresVersion.PG16,
                feature_name="presorted_aggregate",
                description="Presorted aggregates with ORDER BY/DISTINCT",
                performance_impact="mixed",
                affected_query_patterns=[
                    "array_agg with ORDER BY",
                    "string_agg with ORDER BY",
                ],
                configuration_required=True,
                default_enabled=True,
            ),
            VersionFeature(
                version=PostgresVersion.PG16,
                feature_name="incremental_sort_improvements",
                description="Better incremental sort for aggregates",
                performance_impact="mixed",
                affected_query_patterns=["GROUP BY with ORDER BY aggregates"],
                configuration_required=False,
                default_enabled=True,
            ),
        ],
        PostgresVersion.PG17: [
            VersionFeature(
                version=PostgresVersion.PG17,
                feature_name="streaming_io",
                description="Streaming I/O for sequential scans and ANALYZE",
                performance_impact="positive",
                affected_query_patterns=[
                    "sequential scans",
                    "ANALYZE",
                    "pg_prewarm",
                ],
                configuration_required=False,
                default_enabled=True,
            ),
            VersionFeature(
                version=PostgresVersion.PG17,
                feature_name="io_combine_limit",
                description="Configurable I/O combine limit (up to 256k reads)",
                performance_impact="positive",
                affected_query_patterns=[
                    "large sequential scans",
                    "btrfs filesystems",
                ],
                configuration_required=True,
                default_enabled=True,
            ),
            VersionFeature(
                version=PostgresVersion.PG17,
                feature_name="vectored_read_buffer",
                description="Vectored ReadBuffer API for async I/O preparation",
                performance_impact="positive",
                affected_query_patterns=["sequential scans", "index scans"],
                configuration_required=False,
                default_enabled=True,
            ),
            VersionFeature(
                version=PostgresVersion.PG17,
                feature_name="saop_pushdown",
                description="ScalarArrayOpExpr pushed into B-tree index scans",
                performance_impact="positive",
                affected_query_patterns=[
                    "IN-list queries",
                    "= ANY() filters",
                    "multi-column SAOP",
                ],
                configuration_required=False,
                default_enabled=True,
            ),
        ],
    }

    REGRESSION_PATTERNS: dict[tuple[str, str], list[dict[str, str]]] = {
        ("15", "16"): [
            {
                "pattern": r"array_agg.*ORDER BY",
                "description": "Presorted aggregates can cause unnecessary sorts",
                "fix": "SET enable_presorted_aggregate = off;",
                "severity": "medium",
            },
            {
                "pattern": r"GROUP BY.*ORDER BY.*LIMIT",
                "description": "Incremental sort may choose wrong index",
                "fix": "SET enable_incremental_sort = off;",
                "severity": "high",
            },
        ],
        ("16", "17"): [
            {
                "pattern": r"SELECT COUNT\(\*\) FROM",
                "description": "Streaming I/O improves sequential scan performance",
                "fix": "No fix needed - this is an improvement",
                "severity": "positive",
            },
        ],
    }

    def __init__(self, current_version: str, target_version: str) -> None:
        self.current_version = PostgresVersion(current_version)
        self.target_version = PostgresVersion(target_version)

    def analyze_upgrade(
        self, workload_queries: Optional[List[str]] = None
    ) -> UpgradeImpact:
        """Analyze the performance impact of upgrading between versions."""
        features_gained: list[VersionFeature] = []
        breaking_changes: list[str] = []
        recommended_settings: dict[str, Any] = {}
        test_queries: list[str] = []

        for version in PostgresVersion:
            if (
                version.value > self.current_version.value
                and version.value <= self.target_version.value
                and version in self.VERSION_FEATURES
            ):
                features_gained.extend(self.VERSION_FEATURES[version])

        # Collect regressions across every intermediate hop
        for (src, dst), patterns in self.REGRESSION_PATTERNS.items():
            if src >= self.current_version.value and dst <= self.target_version.value:
                for p in patterns:
                    if p["severity"] != "positive":
                        breaking_changes.append(
                            f"{p['description']} - {p['fix']}"
                        )
                    if p.get("fix") and "SET" in p["fix"]:
                        m = re.search(r"SET (\w+)", p["fix"])
                        if m:
                            recommended_settings[m.group(1)] = "off"

        # Version-specific test queries
        gained_versions = {f.version for f in features_gained}
        if PostgresVersion.PG17 in gained_versions:
            test_queries.extend([
                "-- Test streaming I/O performance",
                "EXPLAIN (ANALYZE, BUFFERS) SELECT COUNT(*) FROM large_table;",
                "SET io_combine_limit = '256k';",
                "EXPLAIN (ANALYZE, BUFFERS) SELECT COUNT(*) FROM large_table;",
            ])
        if PostgresVersion.PG16 in gained_versions:
            test_queries.extend([
                "-- Test presorted aggregate behavior",
                "EXPLAIN (ANALYZE, BUFFERS) SELECT a, array_agg(c ORDER BY c) FROM t GROUP BY a;",
                "SET enable_presorted_aggregate = off;",
                "EXPLAIN (ANALYZE, BUFFERS) SELECT a, array_agg(c ORDER BY c) FROM t GROUP BY a;",
            ])

        return UpgradeImpact(
            from_version=self.current_version,
            to_version=self.target_version,
            expected_speedup_pct=self._estimate_speedup(workload_queries),
            regression_risk=self._assess_regression_risk(
                breaking_changes, workload_queries
            ),
            features_gained=features_gained,
            breaking_changes=breaking_changes,
            recommended_settings=recommended_settings,
            test_queries=test_queries,
        )

    def _estimate_speedup(
        self, workload_queries: Optional[List[str]]
    ) -> float:
        if not workload_queries:
            if self.target_version == PostgresVersion.PG17:
                return 15.0
            elif self.target_version == PostgresVersion.PG16:
                return 5.0
            return 0.0

        total = len(workload_queries)
        if total == 0:
            return 0.0

        seq_scans = sum(
            1
            for q in workload_queries
            if "COUNT(*)" in q.upper() or "SELECT *" in q.upper()
        )
        aggregates = sum(
            1
            for q in workload_queries
            if "array_agg" in q.lower() or "string_agg" in q.lower()
        )

        speedup = 0.0
        if self.target_version == PostgresVersion.PG17:
            speedup += (seq_scans / total) * 15
        if self.target_version.value >= "16":
            speedup += (aggregates / total) * 10
        return round(speedup, 1)

    def _assess_regression_risk(
        self,
        breaking_changes: List[str],
        workload_queries: Optional[List[str]],
    ) -> str:
        if not breaking_changes:
            return "low"
        if not workload_queries:
            return "medium"

        high_risk = [
            r"array_agg.*ORDER BY",
            r"GROUP BY.*ORDER BY.*LIMIT",
        ]
        for q in workload_queries:
            for pat in high_risk:
                if re.search(pat, q, re.IGNORECASE):
                    return "high"
        return "medium"

    def generate_upgrade_script(self, impact: UpgradeImpact) -> str:
        """Generate a safe upgrade verification script."""
        lines = [
            "-- PostgreSQL Upgrade Verification Script",
            f"-- Upgrading from {impact.from_version.value} to {impact.to_version.value}",
            "",
            "-- Pre-upgrade check",
            "SELECT current_setting('server_version');",
            "",
        ]

        if impact.recommended_settings:
            lines.append("-- Recommended settings for new version")
            for setting, value in impact.recommended_settings.items():
                lines.append(f"ALTER SYSTEM SET {setting} = '{value}';")
            lines.extend(["SELECT pg_reload_conf();", ""])

        if impact.test_queries:
            lines.append("-- Test queries to verify performance")
            lines.extend(impact.test_queries)
            lines.append("")

        if impact.regression_risk == "high":
            lines.extend([
                "-- Rollback if regressions detected",
                "-- ALTER SYSTEM SET enable_incremental_sort = 'on';",
                "-- ALTER SYSTEM SET enable_presorted_aggregate = 'on';",
            ])

        return "\n".join(lines)

    def explain_streaming_io_benefit(self, table_size_mb: int) -> Dict[str, Any]:
        """
        Explain the benefit of streaming I/O in PG17.
        Benchmark baseline: 346 MB table, 476 ms -> 410 ms (66 ms improvement).
        """
        improvement_per_gb = (66 / 346) * 1024  # ~195 ms per GB
        estimated_ms = (table_size_mb / 1024) * improvement_per_gb
        # Rough baseline: ~1.4 ms per MB for a sequential scan
        estimated_pct = (estimated_ms / max(table_size_mb * 1.4, 0.001)) * 100

        return {
            "feature": "Streaming I/O (Postgres 17)",
            "table_size_mb": table_size_mb,
            "estimated_improvement_ms": round(estimated_ms, 1),
            "estimated_improvement_percent": round(estimated_pct, 1),
            "explanation": (
                "Postgres 17 combines multiple 8 kB reads into larger 128 kB "
                "reads, reducing syscall overhead"
            ),
            "configuration": "SET io_combine_limit = '256k';  -- for even larger reads",
            "best_for": [
                "Sequential scans",
                "ANALYZE",
                "pg_prewarm",
                "btrfs filesystems",
            ],
        }
