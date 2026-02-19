"""
Rails Query Analyzer — N+1 detection, scope analysis, subquery optimization.

Parses Rails development/production logs to detect N+1 patterns, identifies
queries that could be rewritten as subqueries, and suggests Active Record
optimizations (includes, joins, select).

Usage:
    from querysense.rails.analyzer import RailsAnalyzer

    analyzer = RailsAnalyzer()
    report = analyzer.detect_n_plus_one_from_log("log/development.log")
    for pattern in report.patterns:
        print(f"N+1: {pattern.query} ({pattern.count}x)")
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class QueryPattern:
    """A repeated query pattern indicating N+1."""

    query: str
    fingerprint: str
    count: int = 0
    tables: list[str] = field(default_factory=list)
    parent_query: str = ""
    avg_duration_ms: float = 0.0
    total_duration_ms: float = 0.0

    @property
    def is_n_plus_one(self) -> bool:
        return self.count >= 5

    @property
    def severity(self) -> str:
        if self.count >= 100:
            return "CRITICAL"
        if self.count >= 20:
            return "HIGH"
        if self.count >= 5:
            return "MEDIUM"
        return "LOW"

    @property
    def fix_suggestion(self) -> str:
        if not self.tables:
            return "Add eager loading to avoid N+1 queries."

        assoc = self.tables[0] if self.tables else "association"
        return (
            f"Rails: Model.includes(:{assoc})\n"
            f"  Or use joins for filtering: Model.joins(:{assoc}).where(...)\n"
            f"  Or subquery: Model.where(id: Related.select(:model_id))"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query[:200],
            "fingerprint": self.fingerprint,
            "count": self.count,
            "tables": self.tables,
            "parent_query": self.parent_query[:200],
            "avg_duration_ms": round(self.avg_duration_ms, 2),
            "total_duration_ms": round(self.total_duration_ms, 2),
            "severity": self.severity,
            "fix": self.fix_suggestion,
        }


@dataclass
class ScopeIssue:
    """An issue found in a Rails scope/query pattern."""

    issue_type: str  # n_plus_one, missing_index, select_star, eager_abuse
    description: str
    impact: str
    fix_rails: str
    fix_sql: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_type": self.issue_type,
            "description": self.description,
            "impact": self.impact,
            "fix_rails": self.fix_rails,
            "fix_sql": self.fix_sql,
        }


@dataclass
class NPlusOneReport:
    """Full N+1 detection report from log analysis."""

    log_file: str = ""
    total_queries: int = 0
    unique_fingerprints: int = 0
    n_plus_one_count: int = 0
    patterns: list[QueryPattern] = field(default_factory=list)
    total_wasted_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_file": self.log_file,
            "total_queries": self.total_queries,
            "unique_fingerprints": self.unique_fingerprints,
            "n_plus_one_count": self.n_plus_one_count,
            "patterns": [p.to_dict() for p in self.patterns],
            "total_wasted_ms": round(self.total_wasted_ms, 2),
        }


_RAILS_LOG_RE = re.compile(
    r"(?P<model>\w+)\s+(?:Load|Exists|Count|Pluck)"
    r"\s+\((?P<duration>[\d.]+)ms\)\s+"
    r"(?P<sql>.+)",
)

_DURATION_RE = re.compile(r"\((\d+\.?\d*)ms\)")

_TABLE_RE = re.compile(
    r'\bFROM\s+"?(\w+)"?', re.IGNORECASE
)
_JOIN_RE = re.compile(
    r'\bJOIN\s+"?(\w+)"?', re.IGNORECASE
)
_WHERE_COL_RE = re.compile(
    r'"?(\w+)"?\."?(\w+)"?\s*(?:=|IN|IS|>|<|>=|<=|LIKE|BETWEEN)',
    re.IGNORECASE,
)


class RailsAnalyzer:
    """
    Analyze Rails-generated SQL for optimization opportunities.

    Parses Rails log format to detect N+1 queries, missing indexes,
    and suggests Active Record refactors.
    """

    def __init__(self, n_plus_one_threshold: int = 5) -> None:
        self.threshold = n_plus_one_threshold

    def detect_n_plus_one_from_log(self, log_path: str | Path) -> NPlusOneReport:
        """Parse a Rails log file and detect N+1 query patterns."""
        path = Path(log_path)
        report = NPlusOneReport(log_file=str(path))

        if not path.exists():
            return report

        fingerprints: dict[str, list[dict[str, Any]]] = defaultdict(list)

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = _RAILS_LOG_RE.search(line)
                if not match:
                    continue

                sql = match.group("sql").strip()
                duration = float(match.group("duration"))
                fp = self._fingerprint(sql)

                fingerprints[fp].append({
                    "sql": sql,
                    "duration": duration,
                    "model": match.group("model"),
                })
                report.total_queries += 1

        report.unique_fingerprints = len(fingerprints)

        for fp, entries in fingerprints.items():
            if len(entries) < self.threshold:
                continue

            sample = entries[0]
            total_dur = sum(e["duration"] for e in entries)
            tables = _TABLE_RE.findall(sample["sql"])

            pattern = QueryPattern(
                query=sample["sql"],
                fingerprint=fp,
                count=len(entries),
                tables=tables,
                avg_duration_ms=total_dur / len(entries),
                total_duration_ms=total_dur,
            )
            report.patterns.append(pattern)
            report.n_plus_one_count += 1
            report.total_wasted_ms += total_dur

        report.patterns.sort(key=lambda p: p.total_duration_ms, reverse=True)
        return report

    def detect_n_plus_one_from_queries(self, queries: list[str]) -> NPlusOneReport:
        """Detect N+1 from a list of SQL queries (for non-log sources)."""
        report = NPlusOneReport()
        report.total_queries = len(queries)

        fingerprints: dict[str, list[str]] = defaultdict(list)
        for sql in queries:
            fp = self._fingerprint(sql)
            fingerprints[fp].append(sql)

        report.unique_fingerprints = len(fingerprints)

        for fp, sqls in fingerprints.items():
            if len(sqls) < self.threshold:
                continue

            tables = _TABLE_RE.findall(sqls[0])
            pattern = QueryPattern(
                query=sqls[0],
                fingerprint=fp,
                count=len(sqls),
                tables=tables,
            )
            report.patterns.append(pattern)
            report.n_plus_one_count += 1

        report.patterns.sort(key=lambda p: p.count, reverse=True)
        return report

    def analyze_query(self, sql: str) -> list[ScopeIssue]:
        """Analyze a single SQL query for Rails optimization opportunities."""
        issues: list[ScopeIssue] = []

        tables = _TABLE_RE.findall(sql)
        joins = _JOIN_RE.findall(sql)
        where_cols = _WHERE_COL_RE.findall(sql)

        if "SELECT *" in sql.upper() or 'SELECT "' not in sql.upper():
            if tables:
                issues.append(ScopeIssue(
                    issue_type="select_star",
                    description=f"SELECT * from {tables[0]} loads all columns",
                    impact="Transfers unnecessary data, wastes memory",
                    fix_rails=f"Model.select(:id, :name, :needed_column)",
                    fix_sql="Replace SELECT * with specific columns",
                ))

        if joins and len(joins) > 1:
            issues.append(ScopeIssue(
                issue_type="complex_join",
                description=f"Multi-table join across {', '.join(joins)}",
                impact="May benefit from subquery or materialized view",
                fix_rails=(
                    f"Consider subquery:\n"
                    f"  ids = {joins[0].title()}.where(...).select(:id)\n"
                    f"  {tables[0].title()}.where(id: ids)"
                ),
                fix_sql=(
                    "Rewrite as correlated subquery:\n"
                    "  SELECT t.* FROM table t WHERE t.id IN (SELECT ...)"
                ),
            ))

        for tbl, col in where_cols:
            issues.append(ScopeIssue(
                issue_type="potential_missing_index",
                description=f"Filter on {tbl}.{col} may need an index",
                impact="Seq scan on large tables without index is slow",
                fix_rails=f"add_index :{tbl}, :{col}",
                fix_sql=f"CREATE INDEX CONCURRENTLY idx_{tbl}_{col} ON {tbl}({col});",
            ))

        return issues

    @staticmethod
    def _fingerprint(sql: str) -> str:
        """Normalize SQL for fingerprinting."""
        result = sql.strip()
        result = re.sub(r"'[^']*'", "'?'", result)
        result = re.sub(r"\b\d+\b", "?", result)
        result = re.sub(r"\$\d+", "$?", result)
        result = re.sub(r"\bIN\s*\([^)]+\)", "IN (?)", result, flags=re.IGNORECASE)
        result = re.sub(r"\s+", " ", result)
        return result[:500]
