"""
PostgreSQL 16 Planner Upgrade Analyzer.

Analyses queries for 10 planner optimizations introduced in PG 16
(David Rowley et al.) and estimates speedup to help justify upgrades.

Each ``PlannerFeature`` has a SQL-pattern detector and expected speedup.

Usage:
    from querysense.planner.pg16_analyzer import PG16PlannerAnalyzer

    analyzer = PG16PlannerAnalyzer()
    opps = analyzer.analyze_query("SELECT DISTINCT ... ORDER BY ...")
    report = analyzer.estimate_improvement(query, plan_dict)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PlannerFeature(str, Enum):
    INCREMENTAL_SORT_DISTINCT = "incremental_sort_distinct"
    PRESORTED_AGGREGATE = "presorted_aggregate"
    MERGE_JOIN_INCREMENTAL_SORT = "merge_join_incremental_sort"
    RIGHT_ANTI_JOIN = "right_anti_join"
    PARALLEL_HASH_FULL_JOIN = "parallel_hash_full_join"
    JOIN_REMOVAL_PARTITIONED = "join_removal_partitioned"
    WINDOW_FRAME_OPTIMIZATION = "window_frame_optimization"
    WINDOW_FUNCTION_OPTIMIZATION = "window_function_optimization"
    MEMOIZE_UNION_ALL = "memoize_union_all"
    TRIVIAL_DISTINCT = "trivial_distinct"


@dataclass
class PlannerOpportunity:
    """A single PG 16 planner improvement applicable to a query."""

    feature: PlannerFeature
    description: str
    pg16_improvement: str
    expected_speedup: float
    detection_hint: str
    plan_before: str
    plan_after: str
    applicable_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature.value,
            "description": self.description,
            "pg16_improvement": self.pg16_improvement,
            "expected_speedup": self.expected_speedup,
            "detection_hint": self.detection_hint,
            "plan_before": self.plan_before,
            "plan_after": self.plan_after,
            "applicable_patterns": self.applicable_patterns,
        }


# ── Feature catalogue ─────────────────────────────────────────────────

_FEATURES: dict[PlannerFeature, PlannerOpportunity] = {
    PlannerFeature.INCREMENTAL_SORT_DISTINCT: PlannerOpportunity(
        feature=PlannerFeature.INCREMENTAL_SORT_DISTINCT,
        description="Incremental Sort for DISTINCT",
        pg16_improvement="Incremental Sort can now be used with SELECT DISTINCT",
        expected_speedup=2.0,
        detection_hint="SELECT DISTINCT … ORDER BY …",
        plan_before="Unique -> Sort",
        plan_after="Unique -> Incremental Sort",
        applicable_patterns=["SELECT DISTINCT", "DISTINCT with ORDER BY"],
    ),
    PlannerFeature.PRESORTED_AGGREGATE: PlannerOpportunity(
        feature=PlannerFeature.PRESORTED_AGGREGATE,
        description="Faster ORDER BY / DISTINCT aggregates",
        pg16_improvement="Aggregates with ORDER BY/DISTINCT can use pre-sorted data",
        expected_speedup=3.0,
        detection_hint="COUNT(DISTINCT col) or array_agg(col ORDER BY col)",
        plan_before="Sort with temp file (external merge)",
        plan_after="Index Only Scan + Aggregate",
        applicable_patterns=["COUNT(DISTINCT)", "array_agg with ORDER BY", "string_agg with ORDER BY"],
    ),
    PlannerFeature.MERGE_JOIN_INCREMENTAL_SORT: PlannerOpportunity(
        feature=PlannerFeature.MERGE_JOIN_INCREMENTAL_SORT,
        description="Incremental Sort after Merge Join",
        pg16_improvement="Reuse Merge Join sort order for subsequent sorting",
        expected_speedup=1.5,
        detection_hint="JOIN … ORDER BY multiple columns",
        plan_before="Merge Join -> Sort",
        plan_after="Merge Join -> Incremental Sort",
        applicable_patterns=["Complex joins with multi-column ordering"],
    ),
    PlannerFeature.RIGHT_ANTI_JOIN: PlannerOpportunity(
        feature=PlannerFeature.RIGHT_ANTI_JOIN,
        description="Right Anti Join support",
        pg16_improvement="Hash table can be built on either side of NOT EXISTS",
        expected_speedup=2.0,
        detection_hint="NOT EXISTS subqueries",
        plan_before="Hash Anti Join (fixed order)",
        plan_after="Hash Right Anti Join (flexible order)",
        applicable_patterns=["NOT EXISTS", "anti-joins"],
    ),
    PlannerFeature.PARALLEL_HASH_FULL_JOIN: PlannerOpportunity(
        feature=PlannerFeature.PARALLEL_HASH_FULL_JOIN,
        description="Parallel Hash Full / Right Joins",
        pg16_improvement="Parallel workers can build hash tables for FULL/RIGHT joins",
        expected_speedup=3.0,
        detection_hint="FULL OUTER JOIN or RIGHT JOIN on large tables",
        plan_before="Hash Full Join (serial)",
        plan_after="Parallel Hash Full Join",
        applicable_patterns=["FULL OUTER JOIN", "RIGHT JOIN"],
    ),
    PlannerFeature.JOIN_REMOVAL_PARTITIONED: PlannerOpportunity(
        feature=PlannerFeature.JOIN_REMOVAL_PARTITIONED,
        description="Join removal for partitioned tables",
        pg16_improvement="Remove unnecessary LEFT JOINs on partitioned tables",
        expected_speedup=2.0,
        detection_hint="LEFT JOIN on partitioned table where right side is unused",
        plan_before="Nested Loop Left Join -> Append",
        plan_after="Seq Scan only",
        applicable_patterns=["ORM-generated queries with unused joins"],
    ),
    PlannerFeature.WINDOW_FRAME_OPTIMIZATION: PlannerOpportunity(
        feature=PlannerFeature.WINDOW_FRAME_OPTIMIZATION,
        description="Window function frame clause optimization",
        pg16_improvement="Early termination for window functions with LIMIT",
        expected_speedup=4.0,
        detection_hint="row_number() OVER (…) … LIMIT N",
        plan_before="WindowAgg (50,000 rows processed)",
        plan_after="WindowAgg (11 rows processed)",
        applicable_patterns=["row_number()", "rank()", "dense_rank() with LIMIT"],
    ),
    PlannerFeature.WINDOW_FUNCTION_OPTIMIZATION: PlannerOpportunity(
        feature=PlannerFeature.WINDOW_FUNCTION_OPTIMIZATION,
        description="Optimize ntile / cume_dist / percent_rank",
        pg16_improvement="Early termination for ntile, cume_dist, percent_rank",
        expected_speedup=4.0,
        detection_hint="ntile() or cume_dist() with LIMIT",
        plan_before="WindowAgg -> Limit (50,000 rows)",
        plan_after="WindowAgg -> Limit (500 rows)",
        applicable_patterns=["ntile", "cume_dist", "percent_rank"],
    ),
    PlannerFeature.MEMOIZE_UNION_ALL: PlannerOpportunity(
        feature=PlannerFeature.MEMOIZE_UNION_ALL,
        description="Memoize for UNION ALL queries",
        pg16_improvement="Cache results across UNION ALL branches",
        expected_speedup=7.0,
        detection_hint="UNION ALL with repeated subquery patterns",
        plan_before="Append -> Nested Loop (2000 ms)",
        plan_after="Append -> Memoize -> Nested Loop (280 ms)",
        applicable_patterns=["UNION ALL with common subqueries"],
    ),
    PlannerFeature.TRIVIAL_DISTINCT: PlannerOpportunity(
        feature=PlannerFeature.TRIVIAL_DISTINCT,
        description="Short-circuit trivial DISTINCT",
        pg16_improvement="Skip DISTINCT when result is provably unique",
        expected_speedup=2.0,
        detection_hint="SELECT DISTINCT on fixed/unique values",
        plan_before="Unique -> Values Scan",
        plan_after="Values Scan only",
        applicable_patterns=["DISTINCT on constants", "DISTINCT on unique columns"],
    ),
}


# ── Detector ──────────────────────────────────────────────────────────


class PG16PlannerAnalyzer:
    """Detect which PG 16 planner improvements apply to a given query."""

    features = _FEATURES

    def analyze_query(
        self,
        query: str,
        plan: dict[str, Any] | None = None,
    ) -> list[PlannerOpportunity]:
        """Return applicable PG 16 opportunities for *query*."""
        results: list[PlannerOpportunity] = []
        for feature in PlannerFeature:
            if self._matches(query, feature, plan):
                results.append(_FEATURES[feature])
        return results

    def estimate_improvement(
        self,
        query: str,
        plan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Estimate combined improvement from upgrading to PG 16.

        Returns a dict with speedup info suitable for JSON output.
        """
        opps = self.analyze_query(query, plan)
        if not opps:
            return {"improvement": "none", "combined_speedup": 1.0, "features": []}

        combined = 1.0
        for o in opps:
            combined *= o.expected_speedup

        current_ms = 0.0
        if plan:
            current_ms = float(plan.get("Execution Time", 0) or 0)

        return {
            "improvement": "significant" if combined >= 2.0 else "moderate",
            "combined_speedup": round(combined, 1),
            "current_time_ms": current_ms,
            "estimated_time_ms": round(current_ms / combined, 2) if current_ms else 0,
            "features": [o.to_dict() for o in opps],
        }

    def generate_report(self, items: list[dict[str, Any]]) -> str:
        """
        Generate a Markdown upgrade report for multiple queries.

        Each element of *items* should have a ``query`` key and optional
        ``plan`` / ``name`` keys.
        """
        feature_counts: dict[PlannerFeature, int] = {f: 0 for f in PlannerFeature}
        per_query: list[tuple[str, list[PlannerOpportunity]]] = []

        for item in items:
            opps = self.analyze_query(item["query"], item.get("plan"))
            if opps:
                per_query.append((item.get("name", item["query"][:60]), opps))
            for o in opps:
                feature_counts[o.feature] += 1

        lines: list[str] = []
        lines.append("# PostgreSQL 16 Planner Upgrade Analysis\n")

        if not per_query:
            lines.append("No PG 16-specific improvements detected for the supplied queries.\n")
            return "\n".join(lines)

        lines.append("## Detected Opportunities\n")
        lines.append("| Feature | Queries Affected | Expected Speedup |")
        lines.append("|---------|:----------------:|:----------------:|")
        for feat, cnt in feature_counts.items():
            if cnt:
                opp = _FEATURES[feat]
                lines.append(f"| {opp.description} | {cnt} | {opp.expected_speedup}x |")
        lines.append("")

        lines.append("## Per-Query Detail\n")
        for name, opps in per_query:
            combined = 1.0
            for o in opps:
                combined *= o.expected_speedup
            lines.append(f"### {name}")
            for o in opps:
                lines.append(f"- **{o.description}** ({o.expected_speedup}x): {o.pg16_improvement}")
            lines.append(f"- **Combined**: {combined:.1f}x\n")

        return "\n".join(lines)

    # ── Internal matching ─────────────────────────────────────────

    @staticmethod
    def _matches(
        query: str,
        feature: PlannerFeature,
        plan: dict[str, Any] | None,
    ) -> bool:
        up = query.upper()
        lo = query.lower()

        if feature is PlannerFeature.INCREMENTAL_SORT_DISTINCT:
            return "SELECT DISTINCT" in up and "ORDER BY" in up

        if feature is PlannerFeature.PRESORTED_AGGREGATE:
            return (
                "COUNT(DISTINCT" in up
                or ("ORDER BY" in up and "array_agg" in lo)
                or ("ORDER BY" in up and "string_agg" in lo)
            )

        if feature is PlannerFeature.MERGE_JOIN_INCREMENTAL_SORT:
            return "JOIN" in up and "ORDER BY" in up and "," in query.split("ORDER BY")[-1]

        if feature is PlannerFeature.RIGHT_ANTI_JOIN:
            return "NOT EXISTS" in up

        if feature is PlannerFeature.PARALLEL_HASH_FULL_JOIN:
            return "FULL JOIN" in up or "FULL OUTER JOIN" in up or "RIGHT JOIN" in up

        if feature is PlannerFeature.JOIN_REMOVAL_PARTITIONED:
            return "LEFT JOIN" in up

        if feature is PlannerFeature.WINDOW_FRAME_OPTIMIZATION:
            return bool(
                re.search(r"\b(row_number|rank|dense_rank)\s*\(", lo)
                and "LIMIT" in up
            )

        if feature is PlannerFeature.WINDOW_FUNCTION_OPTIMIZATION:
            return bool(
                re.search(r"\b(ntile|cume_dist|percent_rank)\s*\(", lo)
                and "LIMIT" in up
            )

        if feature is PlannerFeature.MEMOIZE_UNION_ALL:
            return "UNION ALL" in up and up.count("SELECT") >= 3

        if feature is PlannerFeature.TRIVIAL_DISTINCT:
            return "SELECT DISTINCT" in up and ("VALUES" in up or "UNIQUE" in up)

        return False  # pragma: no cover
