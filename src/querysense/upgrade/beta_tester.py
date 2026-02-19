"""
PostgreSQL Beta Tester Toolkit.

Based on pganalyze blog:
  - "What's (not) in Postgres 17 beta1, and how to test it" (E116)
  - "Waiting for Postgres 19: Better Planner Hints" (E121)
  - pganalyze coverage of PG 14-19 release cycles

Provides:
  1. Per-version feature catalogues (included, reverted, planned)
  2. Test query generators for new features
  3. Performance comparison helpers
  4. Bug-report templates

Usage:
    from querysense.upgrade.beta_tester import PostgreSQLBetaTester

    tester = PostgreSQLBetaTester()
    summary = tester.whats_new_summary(17)
    tests  = tester.generate_test_suite(17)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any


class FeatureStatus(str, Enum):
    INCLUDED = "included"
    REVERTED = "reverted"
    PLANNED = "planned"


class FeatureCategory(str, Enum):
    PERFORMANCE = "performance"
    OPERATIONAL = "operational"
    DEVELOPER = "developer"
    SECURITY = "security"


@dataclass(frozen=True)
class BetaFeature:
    """A feature in a PostgreSQL release."""
    name: str
    category: FeatureCategory
    description: str
    status: FeatureStatus
    test_query: str = ""
    expected_improvement: str = ""
    commit_url: str = ""


@dataclass(frozen=True)
class VersionInfo:
    """Metadata for a PostgreSQL major version."""
    major: int
    ga_date: date | None
    features: tuple[BetaFeature, ...]
    reverted: tuple[BetaFeature, ...] = ()
    known_issues: tuple[str, ...] = ()


# =====================================================================
# Feature catalogues
# =====================================================================

_PG14 = VersionInfo(
    major=14,
    ga_date=date(2021, 9, 30),
    features=(
        BetaFeature("Memoize node", FeatureCategory.PERFORMANCE,
                    "Caches results of parameterized scans inside nested loops",
                    FeatureStatus.INCLUDED,
                    "EXPLAIN ANALYZE SELECT ... (nested loop with Memoize);",
                    "Up to 10x faster correlated joins"),
        BetaFeature("Bottom-up index deletion", FeatureCategory.PERFORMANCE,
                    "Proactively removes dead index tuples during page splits",
                    FeatureStatus.INCLUDED),
        BetaFeature("Extended statistics on expressions", FeatureCategory.DEVELOPER,
                    "CREATE STATISTICS on arbitrary expressions (PG14+)",
                    FeatureStatus.INCLUDED,
                    "CREATE STATISTICS s ON ((col ->> 'key')) FROM t;"),
        BetaFeature("JSONB subscripting", FeatureCategory.DEVELOPER,
                    "data['key'] syntax for JSONB access",
                    FeatureStatus.INCLUDED,
                    "SELECT data['name'] FROM documents;"),
    ),
)

_PG15 = VersionInfo(
    major=15,
    ga_date=date(2022, 10, 13),
    features=(
        BetaFeature("MERGE statement", FeatureCategory.DEVELOPER,
                    "SQL-standard MERGE for upsert operations",
                    FeatureStatus.INCLUDED,
                    "MERGE INTO t USING src ON t.id = src.id WHEN MATCHED THEN UPDATE ...;"),
        BetaFeature("Faster sort performance", FeatureCategory.PERFORMANCE,
                    "Specialised sort routines for common types, reduced memory, better disk sort",
                    FeatureStatus.INCLUDED,
                    expected_improvement="20-40% faster sorts"),
        BetaFeature("Server-side backup compression", FeatureCategory.OPERATIONAL,
                    "LZ4 and Zstandard for pg_basebackup --compress",
                    FeatureStatus.INCLUDED),
        BetaFeature("work_mem hash_mem_multiplier default change", FeatureCategory.PERFORMANCE,
                    "hash_mem_multiplier default changed from 1.0 to 2.0",
                    FeatureStatus.INCLUDED),
    ),
    reverted=(
        BetaFeature("SQL/JSON (JSON_TABLE)", FeatureCategory.DEVELOPER,
                    "SQL-standard JSON_TABLE — reverted, re-committed in PG17",
                    FeatureStatus.REVERTED),
    ),
)

_PG16 = VersionInfo(
    major=16,
    ga_date=date(2023, 9, 14),
    features=(
        BetaFeature("Incremental Sort improvements", FeatureCategory.PERFORMANCE,
                    "Better use of existing sort orders, more efficient anti-JOINs",
                    FeatureStatus.INCLUDED),
        BetaFeature("COPY 300% faster", FeatureCategory.PERFORMANCE,
                    "Improved relation extension locks speed up bulk loading",
                    FeatureStatus.INCLUDED,
                    "COPY large_table FROM '/data/file.csv';",
                    "Up to 300% faster bulk inserts"),
        BetaFeature("pg_stat_io", FeatureCategory.OPERATIONAL,
                    "New cumulative I/O statistics view",
                    FeatureStatus.INCLUDED,
                    "SELECT * FROM pg_stat_io;"),
        BetaFeature("EXPLAIN (GENERIC_PLAN)", FeatureCategory.DEVELOPER,
                    "Run EXPLAIN on queries with $1 parameters",
                    FeatureStatus.INCLUDED,
                    "EXPLAIN (GENERIC_PLAN) SELECT * FROM t WHERE id = $1;"),
        BetaFeature("BRIN ignores HOT", FeatureCategory.PERFORMANCE,
                    "BRIN indexes no longer block HOT updates",
                    FeatureStatus.INCLUDED),
        BetaFeature("Logical decoding on standby", FeatureCategory.OPERATIONAL,
                    "Logical replication from standbys for failover continuity",
                    FeatureStatus.INCLUDED),
    ),
)

_PG17 = VersionInfo(
    major=17,
    ga_date=date(2024, 9, 26),
    features=(
        BetaFeature("Builtin C.UTF-8 locale", FeatureCategory.PERFORMANCE,
                    "Binary sort speed with Unicode-aware UPPER/LOWER",
                    FeatureStatus.INCLUDED,
                    "CREATE DATABASE db LOCALE_PROVIDER = builtin BUILTIN_LOCALE = 'C.UTF-8';",
                    "2-3x faster text sorts"),
        BetaFeature("Streaming I/O for seq scans", FeatureCategory.PERFORMANCE,
                    "Vectored I/O pre-fetches pages ahead of scan cursor",
                    FeatureStatus.INCLUDED,
                    expected_improvement="10-15% faster sequential scans"),
        BetaFeature("Faster B-tree IN/ANY scans", FeatureCategory.PERFORMANCE,
                    "Avoids repeated page access for multi-value lookups",
                    FeatureStatus.INCLUDED,
                    expected_improvement="Significant speedup for IN lists"),
        BetaFeature("VACUUM Adaptive Radix Trees", FeatureCategory.PERFORMANCE,
                    "Radix tree replaces flat dead-tuple array",
                    FeatureStatus.INCLUDED,
                    expected_improvement="Up to 50% less VACUUM memory"),
        BetaFeature("Improved EXPLAIN for SubPlan", FeatureCategory.DEVELOPER,
                    "Shows actual expressions in SubPlan filter output",
                    FeatureStatus.INCLUDED),
        BetaFeature("SQL/JSON (JSON_TABLE)", FeatureCategory.DEVELOPER,
                    "SQL-standard JSON_TABLE and JSON path expressions",
                    FeatureStatus.INCLUDED,
                    "SELECT * FROM JSON_TABLE(doc, '$.items[*]' COLUMNS(id int PATH '$.id'));"),
        BetaFeature("MERGE with RETURNING", FeatureCategory.DEVELOPER,
                    "RETURNING clause support for MERGE",
                    FeatureStatus.INCLUDED),
        BetaFeature("COPY ON_ERROR", FeatureCategory.DEVELOPER,
                    "Skip bad rows during COPY instead of aborting",
                    FeatureStatus.INCLUDED,
                    "COPY t FROM '/data/file.csv' WITH (ON_ERROR ignore);"),
        BetaFeature("pg_buffercache_evict", FeatureCategory.OPERATIONAL,
                    "Evict individual pages for benchmarking",
                    FeatureStatus.INCLUDED,
                    "SELECT pg_buffercache_evict(bufferid) FROM pg_buffercache WHERE ...;"),
    ),
    reverted=(
        BetaFeature("Temporal primary/foreign keys", FeatureCategory.DEVELOPER,
                    "PERIOD-based temporal tables", FeatureStatus.REVERTED),
        BetaFeature("NOT NULL constraint cataloging", FeatureCategory.DEVELOPER,
                    "Improved catalog representation of NOT NULL", FeatureStatus.REVERTED),
        BetaFeature("Remove useless self joins", FeatureCategory.PERFORMANCE,
                    "Automatic removal of unnecessary self-joins", FeatureStatus.REVERTED),
        BetaFeature("OR to ANY transformation", FeatureCategory.PERFORMANCE,
                    "Transform OR clauses to ANY expressions", FeatureStatus.REVERTED),
    ),
)

_PG18 = VersionInfo(
    major=18,
    ga_date=None,
    features=(
        BetaFeature("Asynchronous I/O (AIO)", FeatureCategory.PERFORMANCE,
                    "Non-blocking disk reads via io_method setting",
                    FeatureStatus.INCLUDED,
                    expected_improvement="Significant I/O throughput in cloud environments"),
        BetaFeature("UUIDv7 generation", FeatureCategory.DEVELOPER,
                    "Built-in uuidv7() function for time-sorted UUIDs",
                    FeatureStatus.PLANNED),
    ),
)

_PG19 = VersionInfo(
    major=19,
    ga_date=None,
    features=(
        BetaFeature("Path generation strategies", FeatureCategory.PERFORMANCE,
                    "Improved planner extensibility for plan hints",
                    FeatureStatus.INCLUDED,
                    expected_improvement="Better pg_plan_advice extension support"),
    ),
)

_ALL_VERSIONS: dict[int, VersionInfo] = {
    v.major: v for v in [_PG14, _PG15, _PG16, _PG17, _PG18, _PG19]
}


class PostgreSQLBetaTester:
    """Toolkit for testing and comparing PostgreSQL releases."""

    def __init__(self) -> None:
        self.versions = _ALL_VERSIONS

    def get_version_info(self, major: int) -> VersionInfo | None:
        return self.versions.get(major)

    def whats_new_summary(self, major: int) -> str:
        """Generate a human-readable release summary."""
        vi = self.versions.get(major)
        if vi is None:
            return f"No information available for PostgreSQL {major}."

        lines = [
            f"PostgreSQL {major} - What's New",
            "=" * 40, "",
        ]

        by_cat: dict[FeatureCategory, list[BetaFeature]] = {}
        for f in vi.features:
            by_cat.setdefault(f.category, []).append(f)

        category_labels = {
            FeatureCategory.PERFORMANCE: "Performance Improvements",
            FeatureCategory.OPERATIONAL: "Operational Improvements",
            FeatureCategory.DEVELOPER: "Developer Experience",
            FeatureCategory.SECURITY: "Security",
        }

        for cat in FeatureCategory:
            feats = by_cat.get(cat)
            if not feats:
                continue
            lines.append(f"  {category_labels[cat]}:")
            for f in feats:
                lines.append(f"    - {f.name}: {f.description}")
                if f.expected_improvement:
                    lines.append(f"      Expected: {f.expected_improvement}")
            lines.append("")

        if vi.reverted:
            lines.append("  Features Reverted Since Feature Freeze:")
            for f in vi.reverted:
                lines.append(f"    - {f.name}: {f.description}")
            lines.append("")

        return "\n".join(lines)

    def generate_test_suite(self, major: int) -> dict[str, list[dict[str, str]]]:
        """Generate test queries for features in *major*."""
        vi = self.versions.get(major)
        if vi is None:
            return {}

        suite: dict[str, list[dict[str, str]]] = {
            "performance": [],
            "operational": [],
            "developer": [],
        }

        for f in vi.features:
            if not f.test_query:
                continue
            suite.setdefault(f.category.value, []).append({
                "name": f.name,
                "query": f.test_query,
                "expected": f.expected_improvement or "Verify behaviour matches documentation",
            })

        return suite

    def get_upgrade_path(
        self,
        from_major: int,
        to_major: int,
    ) -> list[dict[str, Any]]:
        """Return features gained in each version along the upgrade path."""
        gained: list[dict[str, Any]] = []
        for v in range(from_major + 1, to_major + 1):
            vi = self.versions.get(v)
            if vi is None:
                continue
            gained.append({
                "version": v,
                "ga_date": str(vi.ga_date) if vi.ga_date else "TBD",
                "feature_count": len(vi.features),
                "features": [
                    {"name": f.name, "category": f.category.value, "description": f.description}
                    for f in vi.features
                ],
            })
        return gained

    def generate_bug_report_template(self, version: int) -> str:
        """Return a Markdown bug-report template for *version*."""
        return (
            f"## Bug Report - PostgreSQL {version}\n"
            "\n"
            "### System Information\n"
            f"- PostgreSQL Version: {version}\n"
            "- OS: [e.g., Ubuntu 22.04, RHEL 9]\n"
            "- Architecture: [e.g., x86_64, arm64]\n"
            "- Installation Method: [e.g., apt, yum, source, Docker]\n"
            "\n"
            "### Bug Description\n"
            "[Describe what happened and what you expected]\n"
            "\n"
            "### Steps to Reproduce\n"
            "```sql\n"
            "-- Include complete, self-contained SQL\n"
            "```\n"
            "\n"
            "### Expected Behavior\n"
            "[What should happen]\n"
            "\n"
            "### Actual Behavior\n"
            "[Include error messages, EXPLAIN output]\n"
            "\n"
            "---\n"
            "Send to: pgsql-bugs@lists.postgresql.org\n"
        )

    def format_upgrade_report(
        self,
        from_major: int,
        to_major: int,
    ) -> str:
        """Return a formatted upgrade-path report."""
        path = self.get_upgrade_path(from_major, to_major)
        if not path:
            return f"No upgrade path from PG{from_major} to PG{to_major}."

        lines = [
            f"Upgrade Path: PostgreSQL {from_major} -> {to_major}",
            "=" * 50, "",
        ]

        total = 0
        for step in path:
            v = step["version"]
            ga = step["ga_date"]
            n = step["feature_count"]
            total += n
            lines.append(f"  PostgreSQL {v} (GA: {ga}) - {n} features:")
            for f in step["features"]:
                lines.append(f"    [{f['category']}] {f['name']}: {f['description']}")
            lines.append("")

        lines.append(f"  Total features gained: {total}")
        return "\n".join(lines)
