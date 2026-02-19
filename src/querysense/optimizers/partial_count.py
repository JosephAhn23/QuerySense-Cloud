"""
Partial COUNT Optimizer — LIMIT-based counting.

Detects COUNT(*) queries that can be rewritten with a LIMIT subquery
when the caller only needs to know "at least N" rather than the exact
total.  Based on pganalyze's 35 ms -> 5 ms optimization example.

The pattern:
    -- Before (scans all matching rows):
    SELECT COUNT(*) FROM large_table WHERE status = 'active';

    -- After (stops at 101 rows):
    SELECT COUNT(*) FROM (
        SELECT 1 FROM large_table WHERE status = 'active'
        LIMIT 101
    ) limited_count;

The caller then shows "100+" in the UI when count == 101.

Usage:
    from querysense.optimizers.partial_count import PartialCountOptimizer

    opt = PartialCountOptimizer(threshold=100)
    suggestion = opt.analyze("SELECT COUNT(*) FROM orders WHERE active")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class CountCandidate:
    """Parsed metadata about a COUNT query."""

    original: str
    table: str | None
    where_clause: str | None
    has_group_by: bool
    has_having: bool

    @property
    def is_simple_aggregate(self) -> bool:
        """True when the query is a plain COUNT without GROUP BY."""
        return not self.has_group_by


@dataclass
class CountSuggestion:
    """Suggested rewrite for a COUNT query."""

    original: str
    optimized: str
    threshold: int
    estimated_speedup: float
    current_time_ms: float
    estimated_time_ms: float
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original,
            "optimized": self.optimized,
            "threshold": self.threshold,
            "estimated_speedup": round(self.estimated_speedup, 1),
            "current_time_ms": round(self.current_time_ms, 2),
            "estimated_time_ms": round(self.estimated_time_ms, 2),
            "explanation": self.explanation,
        }


# ── Regex helpers ─────────────────────────────────────────────────────

_COUNT_RE = re.compile(r"\bCOUNT\s*\(", re.IGNORECASE)
_FROM_RE = re.compile(r"\bFROM\s+(\w+)", re.IGNORECASE)
_WHERE_RE = re.compile(
    r"\bWHERE\s+(.+?)(?=\s+(?:GROUP|ORDER|LIMIT|HAVING|$))",
    re.IGNORECASE | re.DOTALL,
)
_GROUP_BY_RE = re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE)
_HAVING_RE = re.compile(r"\bHAVING\b", re.IGNORECASE)
_OUTER_COUNT_RE = re.compile(
    r"^SELECT\s+COUNT\s*\([^)]*\)\s+FROM\b",
    re.IGNORECASE,
)
_LIMIT_RE = re.compile(r"\bLIMIT\s+\d+", re.IGNORECASE)


class PartialCountOptimizer:
    """
    Rewrite COUNT queries with a LIMIT subquery when exact counts
    are unnecessary.
    """

    def __init__(self, threshold: int = 100) -> None:
        self.threshold = threshold

    @property
    def limit_value(self) -> int:
        return self.threshold + 1

    # ── Public API ────────────────────────────────────────────────

    def parse(self, query: str) -> CountCandidate | None:
        """Parse a SQL string; return *None* if it isn't a COUNT query."""
        if not _COUNT_RE.search(query):
            return None

        table_m = _FROM_RE.search(query)
        where_m = _WHERE_RE.search(query)

        return CountCandidate(
            original=query.strip(),
            table=table_m.group(1) if table_m else None,
            where_clause=where_m.group(1).strip() if where_m else None,
            has_group_by=bool(_GROUP_BY_RE.search(query)),
            has_having=bool(_HAVING_RE.search(query)),
        )

    def analyze(
        self,
        query: str,
        plan: dict[str, Any] | None = None,
    ) -> CountSuggestion | None:
        """
        Analyse a query and return a rewrite suggestion if applicable.

        ``plan`` is an optional EXPLAIN (ANALYZE, FORMAT JSON) dict.
        """
        candidate = self.parse(query)
        if candidate is None:
            return None

        if not self._is_candidate(candidate, plan):
            return None

        optimized = self._rewrite(candidate.original)
        speedup = self._estimate_speedup(plan)
        current_ms = _extract_exec_time(plan)
        estimated_ms = current_ms / speedup if current_ms > 0 else 0.0

        return CountSuggestion(
            original=candidate.original,
            optimized=optimized,
            threshold=self.threshold,
            estimated_speedup=speedup,
            current_time_ms=current_ms,
            estimated_time_ms=estimated_ms,
            explanation=(
                f"Wrap inner query with LIMIT {self.limit_value}; "
                f"display '{self.threshold}+' in UI when count equals {self.limit_value}"
            ),
        )

    def batch_analyze(
        self,
        items: list[dict[str, Any]],
    ) -> list[CountSuggestion]:
        """Analyse multiple queries. Each dict needs at least a ``query`` key."""
        results: list[CountSuggestion] = []
        for item in items:
            s = self.analyze(item["query"], item.get("plan"))
            if s is not None:
                results.append(s)
        return results

    def generate_sql_function(self) -> str:
        """Return a CREATE FUNCTION script for server-side partial counting."""
        return (
            "CREATE OR REPLACE FUNCTION partial_count(\n"
            "    _query text,\n"
            f"    _threshold int DEFAULT {self.threshold}\n"
            ") RETURNS int\n"
            "LANGUAGE plpgsql VOLATILE AS $$\n"
            "DECLARE _result int;\n"
            "BEGIN\n"
            "    EXECUTE format(\n"
            "        'SELECT COUNT(*) FROM (%s LIMIT %s) _lim',\n"
            "        _query, _threshold + 1\n"
            "    ) INTO _result;\n"
            "    RETURN _result;\n"
            "END;\n"
            "$$;\n"
        )

    # ── Internals ─────────────────────────────────────────────────

    def _is_candidate(
        self,
        candidate: CountCandidate,
        plan: dict[str, Any] | None,
    ) -> bool:
        if candidate.has_group_by:
            return False

        if plan:
            rows = _sum_plan_rows(plan.get("Plan", plan))
            if rows is not None and rows > self.threshold * 10:
                return True

        return candidate.is_simple_aggregate

    def _rewrite(self, query: str) -> str:
        """Produce the LIMIT-wrapped version of a COUNT query."""
        # Strip the outer COUNT(...) FROM  →  SELECT 1 FROM
        inner = _OUTER_COUNT_RE.sub("SELECT 1 FROM", query, count=1)
        # Remove any pre-existing LIMIT
        inner = _LIMIT_RE.sub("", inner).strip().rstrip(";")
        return (
            "SELECT COUNT(*) FROM (\n"
            f"    {inner}\n"
            f"    LIMIT {self.limit_value}\n"
            ") limited_count"
        )

    def _estimate_speedup(self, plan: dict[str, Any] | None) -> float:
        if plan is None:
            return 7.0
        rows = _sum_plan_rows(plan.get("Plan", plan))
        if rows is None:
            return 7.0
        if rows > 100_000:
            return 20.0
        if rows > 10_000:
            return 10.0
        if rows > 1_000:
            return 5.0
        return 2.0


# ── Utility functions ─────────────────────────────────────────────────


def _extract_exec_time(plan: dict[str, Any] | None) -> float:
    if not plan:
        return 0.0
    return float(plan.get("Execution Time", 0) or 0)


def _sum_plan_rows(node: dict[str, Any] | None) -> int | None:
    if node is None:
        return None
    total = node.get("Actual Rows") or node.get("Plan Rows") or 0
    for child in node.get("Plans", []):
        child_rows = _sum_plan_rows(child)
        if child_rows is not None:
            total += child_rows
    return total
