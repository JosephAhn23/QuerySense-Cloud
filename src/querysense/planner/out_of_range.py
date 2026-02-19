"""
Out-of-Range Statistics Detector.

Detects when query predicates reference values outside the histogram
bounds collected by ANALYZE, causing PostgreSQL to invoke
``get_actual_variable_range()`` at planning time.  This can make
planning slow — especially when indexes contain many dead tuples.

Based on Franck Pachot's analysis and PostgreSQL source commentary.

Usage:
    from querysense.planner.out_of_range import OutOfRangeDetector

    detector = OutOfRangeDetector()

    # Offline mode (no database needed):
    issues = detector.check_query(
        query="SELECT * FROM events WHERE ts > 1700000000",
        plan=plan_dict,
        ranges=[ColumnRange(column="ts", table="events", ...)],
    )

    # Live mode:
    issues = await detector.analyze_live(conn, schema="public", table="events",
                                         query="SELECT * FROM events WHERE ts > ...")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


@dataclass
class ColumnRange:
    """Histogram range for a single column from ``pg_stats``."""

    column: str
    table: str
    min_value: Any = None
    max_value: Any = None
    histogram_bounds: list[Any] = field(default_factory=list)
    null_frac: float = 0.0
    n_distinct: float = 0.0
    last_analyze: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "column": self.column,
            "table": self.table,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "null_frac": self.null_frac,
            "n_distinct": self.n_distinct,
            "last_analyze": self.last_analyze.isoformat() if self.last_analyze else None,
        }


@dataclass
class OutOfRangeIssue:
    """A predicate whose value falls outside histogram bounds."""

    table: str
    column: str
    operator: str
    search_value: Any
    stats_min: Any
    stats_max: Any
    estimated_rows: int = 0
    actual_rows: int | None = None
    misestimate_factor: float = 1.0
    severity: str = "warning"       # "warning" | "critical"
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "column": self.column,
            "operator": self.operator,
            "search_value": self.search_value,
            "stats_min": self.stats_min,
            "stats_max": self.stats_max,
            "estimated_rows": self.estimated_rows,
            "actual_rows": self.actual_rows,
            "misestimate_factor": round(self.misestimate_factor, 2),
            "severity": self.severity,
            "recommendation": self.recommendation,
        }


# ── Regex for range predicates ────────────────────────────────────────

_RANGE_OPS = [">", ">=", "<", "<="]

_WHERE_RE = re.compile(
    r"\bWHERE\s+(.+?)(?=\s+(?:GROUP|ORDER|LIMIT|HAVING)\b|$)",
    re.IGNORECASE | re.DOTALL,
)

_BETWEEN_RE = re.compile(
    r"(\w+)\s+BETWEEN\s+(['\w.+-]+)\s+AND\s+(['\w.+-]+)",
    re.IGNORECASE,
)

_RANGE_RE = re.compile(
    r"(\w+)\s*(>=|<=|>|<)\s*(['\w.+-]+)",
)


def _try_numeric(value: str) -> int | float | str:
    """Attempt to convert a string to int, then float, else return as-is."""
    try:
        return int(value)
    except (ValueError, TypeError):
        pass
    try:
        return float(value)
    except (ValueError, TypeError):
        pass
    return value.strip("'\"")


class OutOfRangeDetector:
    """
    Detect predicates that reference values outside the ANALYZE
    histogram range for a column, causing potential planning slowness.
    """

    # ── Offline analysis ──────────────────────────────────────────

    def check_query(
        self,
        query: str,
        ranges: list[ColumnRange],
        plan: dict[str, Any] | None = None,
    ) -> list[OutOfRangeIssue]:
        """
        Check whether a query's range predicates fall outside the
        histogram bounds supplied in *ranges*.
        """
        conditions = self._extract_conditions(query)
        issues: list[OutOfRangeIssue] = []

        for col, op, raw_val in conditions:
            cr = self._find_range(col, ranges)
            if cr is None:
                continue

            val = _try_numeric(raw_val)
            oor = self._check_out_of_range(val, op, cr)
            if not oor:
                continue

            estimated = self._plan_estimate(plan)
            actual = self._plan_actual(plan)
            factor = self._misestimate(estimated, actual)
            severity = "critical" if factor > 10 or factor < 0.1 else "warning"
            rec = self._recommend(cr)

            issues.append(OutOfRangeIssue(
                table=cr.table,
                column=cr.column,
                operator=op,
                search_value=val,
                stats_min=cr.min_value,
                stats_max=cr.max_value,
                estimated_rows=estimated or 0,
                actual_rows=actual,
                misestimate_factor=factor,
                severity=severity,
                recommendation=rec,
            ))

        return issues

    # ── Live analysis (requires async DB connection) ──────────────

    async def fetch_ranges(
        self,
        conn: Any,
        schema: str,
        table: str,
    ) -> list[ColumnRange]:
        """Fetch column histogram ranges from ``pg_stats``."""
        rows = await conn.fetch(
            "SELECT attname, n_distinct, null_frac, histogram_bounds "
            "FROM pg_stats "
            "WHERE schemaname = $1 AND tablename = $2",
            schema,
            table,
        )

        last_analyze = await conn.fetchval(
            "SELECT last_analyze FROM pg_stat_user_tables "
            "WHERE schemaname = $1 AND relname = $2",
            schema,
            table,
        )

        result: list[ColumnRange] = []
        for row in rows:
            hist = row["histogram_bounds"] or []
            result.append(ColumnRange(
                column=row["attname"],
                table=f"{schema}.{table}",
                min_value=hist[0] if hist else None,
                max_value=hist[-1] if hist else None,
                histogram_bounds=hist,
                null_frac=row["null_frac"],
                n_distinct=row["n_distinct"],
                last_analyze=last_analyze,
            ))
        return result

    async def analyze_live(
        self,
        conn: Any,
        schema: str,
        table: str,
        query: str,
        plan: dict[str, Any] | None = None,
    ) -> list[OutOfRangeIssue]:
        """Fetch live stats, then check the query."""
        ranges = await self.fetch_ranges(conn, schema, table)
        return self.check_query(query, ranges, plan)

    # ── Internal helpers ──────────────────────────────────────────

    @staticmethod
    def _extract_conditions(query: str) -> list[tuple[str, str, str]]:
        where_m = _WHERE_RE.search(query)
        if not where_m:
            return []

        clause = where_m.group(1)
        conditions: list[tuple[str, str, str]] = []

        for m in _BETWEEN_RE.finditer(clause):
            conditions.append((m.group(1), ">=", m.group(2)))
            conditions.append((m.group(1), "<=", m.group(3)))

        for m in _RANGE_RE.finditer(clause):
            conditions.append((m.group(1), m.group(2), m.group(3)))

        return conditions

    @staticmethod
    def _find_range(column: str, ranges: list[ColumnRange]) -> ColumnRange | None:
        col_lower = column.lower()
        return next((r for r in ranges if r.column.lower() == col_lower), None)

    @staticmethod
    def _check_out_of_range(
        val: Any,
        op: str,
        cr: ColumnRange,
    ) -> bool:
        try:
            if op in (">", ">=") and cr.max_value is not None:
                return val > cr.max_value
            if op in ("<", "<=") and cr.min_value is not None:
                return val < cr.min_value
        except TypeError:
            return False
        return False

    @staticmethod
    def _plan_estimate(plan: dict[str, Any] | None) -> int | None:
        if not plan:
            return None
        root = plan.get("Plan", plan)
        return root.get("Plan Rows")

    @staticmethod
    def _plan_actual(plan: dict[str, Any] | None) -> int | None:
        if not plan:
            return None
        root = plan.get("Plan", plan)
        return root.get("Actual Rows")

    @staticmethod
    def _misestimate(estimated: int | None, actual: int | None) -> float:
        if estimated and actual and actual > 0:
            return estimated / actual
        return 1.0

    @staticmethod
    def _recommend(cr: ColumnRange) -> str:
        if cr.last_analyze is None:
            return f"Run ANALYZE {cr.table} — statistics have never been collected"
        days = (datetime.now() - cr.last_analyze).days
        if days > 7:
            return (
                f"Run ANALYZE {cr.table} (last analyzed {days} days ago); "
                "also ensure autovacuum is active"
            )
        return (
            f"Statistics are recent ({days}d ago); consider "
            f"CREATE INDEX on {cr.column} to speed up get_actual_variable_range, "
            "or VACUUM (INDEX_CLEANUP ON) to remove dead index tuples"
        )
