"""
Advisor Base Classes — The shared interface for all advisory checks.

Every advisor check in QuerySense inherits from AdvisorCheck and produces
Finding / CheckResult objects.  This mirrors Percona PMM's advisor framework
where each check is a self-contained unit with:

    - A unique name and description
    - A severity level and category
    - A configurable execution interval
    - A standard `run()` method returning structured findings

Design principles:
    - Offline-first: No telemetry, no data leaves the server
    - Deterministic: Same input → same output
    - Actionable: Every finding includes fix_sql and rationale
    - Composable: Checks can be combined, filtered, scheduled
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------


class AdvisorCategory(str, Enum):
    """Advisor categories matching Percona's structure."""

    SECURITY = "security"
    CONFIGURATION = "configuration"
    PERFORMANCE = "performance"
    QUERY = "query"
    VACUUM = "vacuum"
    REPLICATION = "replication"
    SCHEMA = "schema"


class CheckSeverity(str, Enum):
    """Severity levels for advisor findings."""

    EMERGENCY = "emergency"   # Immediate action required (data loss risk)
    CRITICAL = "critical"     # Severe issue, fix ASAP
    WARNING = "warning"       # Should be addressed soon
    NOTICE = "notice"         # Informational, best practice
    INFO = "info"             # Observation, no action needed
    PASS = "pass"             # Check passed, no issue found

    @property
    def weight(self) -> int:
        """Numeric weight for scoring (higher = more severe)."""
        return {
            "emergency": 50,
            "critical": 25,
            "warning": 10,
            "notice": 3,
            "info": 1,
            "pass": 0,
        }[self.value]


class CheckInterval(str, Enum):
    """
    How often a check should run automatically.

    Matches Percona's interval tiers:
        - RARE: 78 hours (long-running, expensive checks)
        - STANDARD: 24 hours (default for most checks)
        - FREQUENT: 4 hours (lightweight, fast checks)
        - ON_DEMAND: Only when manually triggered
    """

    RARE = "rare"           # Every 78 hours
    STANDARD = "standard"   # Every 24 hours
    FREQUENT = "frequent"   # Every 4 hours
    ON_DEMAND = "on_demand" # Manual only

    @property
    def hours(self) -> float:
        return {
            "rare": 78.0,
            "standard": 24.0,
            "frequent": 4.0,
            "on_demand": 0.0,
        }[self.value]


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------


@dataclass
class Finding:
    """
    A single advisory finding — the atomic unit of advisor output.

    Every finding is actionable: it tells you what's wrong, why it matters,
    and how to fix it.
    """

    severity: CheckSeverity
    title: str
    description: str
    recommendation: str
    fix_sql: str = ""
    rationale: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "fix_sql": self.fix_sql,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "tags": self.tags,
        }


@dataclass
class CheckResult:
    """
    Complete result from running a single advisor check.

    Contains all findings plus metadata about the check execution.
    """

    check_name: str
    category: AdvisorCategory
    findings: list[Finding] = field(default_factory=list)
    passed: bool = True
    elapsed_ms: float = 0.0
    error: str | None = None
    timestamp: str = ""

    @property
    def severity(self) -> CheckSeverity:
        """Highest severity across all findings."""
        if not self.findings:
            return CheckSeverity.PASS
        return max(self.findings, key=lambda f: f.severity.weight).severity

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def summary(self) -> str:
        """One-line summary for display."""
        if self.error:
            return f"ERROR: {self.error}"
        if not self.findings:
            return "No issues found"
        severities = {}
        for f in self.findings:
            severities[f.severity.value] = severities.get(f.severity.value, 0) + 1
        parts = [f"{count} {sev}" for sev, count in sorted(severities.items())]
        return ", ".join(parts)

    @property
    def score_deduction(self) -> int:
        """Total score deduction from all findings."""
        return sum(f.severity.weight for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_name": self.check_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "passed": self.passed,
            "finding_count": self.finding_count,
            "summary": self.summary,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


# ------------------------------------------------------------------
# Protocol for database connections
# ------------------------------------------------------------------


class AsyncDBConnection(Protocol):
    """Minimal async DB connection protocol."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...
    async def execute(self, query: str, *args: Any) -> str: ...


# ------------------------------------------------------------------
# Base class for all advisor checks
# ------------------------------------------------------------------


class AdvisorCheck(ABC):
    """
    Base class for all advisor checks.

    Subclass this to create a new check. Implement `run()` to perform
    the actual analysis.

    Example::

        class MaxConnectionsCheck(AdvisorCheck):
            name = "postgres_max_connections"
            title = "PostgreSQL max_connections"
            description = "Check if max_connections is set too high"
            category = AdvisorCategory.CONFIGURATION
            interval = CheckInterval.STANDARD

            async def run(self, conn: AsyncDBConnection) -> CheckResult:
                val = await conn.fetchval("SHOW max_connections")
                result = CheckResult(check_name=self.name, category=self.category)
                if int(val) > 500:
                    result.findings.append(Finding(
                        severity=CheckSeverity.WARNING,
                        title="max_connections is too high",
                        description=f"Current value: {val}",
                        recommendation="Reduce to 200 and use PgBouncer",
                        fix_sql="ALTER SYSTEM SET max_connections = 200;",
                    ))
                    result.passed = False
                return result
    """

    # Subclasses must set these
    name: str = ""
    title: str = ""
    description: str = ""
    category: AdvisorCategory = AdvisorCategory.CONFIGURATION
    interval: CheckInterval = CheckInterval.STANDARD

    @abstractmethod
    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        """Execute the check and return results."""
        ...

    async def safe_run(self, conn: AsyncDBConnection) -> CheckResult:
        """Run with error handling and timing."""
        import datetime

        t0 = time.perf_counter()
        try:
            result = await self.run(conn)
        except Exception as exc:
            result = CheckResult(
                check_name=self.name,
                category=self.category,
                error=str(exc),
                passed=False,
            )
        result.elapsed_ms = (time.perf_counter() - t0) * 1000
        result.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return result
