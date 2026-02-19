"""
Advisor Registry — Discover, filter, and run advisory checks.

The registry is the central orchestrator that:
    - Discovers all registered checks (auto-registration via decorators)
    - Filters by category, interval, or specific check name
    - Runs checks sequentially or concurrently
    - Produces aggregate reports with scores

Usage:
    from querysense.advisor import AdvisorRegistry

    registry = AdvisorRegistry()
    registry.auto_discover()  # Load all built-in checks

    # Run everything
    report = await registry.run_all(conn)

    # Run specific category
    report = await registry.run_category(AdvisorCategory.SECURITY, conn)

    # Run single check
    result = await registry.run_check("postgres_ssl_enabled", conn)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from querysense.advisor.base import (
    AdvisorCategory,
    AdvisorCheck,
    AsyncDBConnection,
    CheckInterval,
    CheckResult,
    CheckSeverity,
)


@dataclass
class AdvisorReport:
    """
    Aggregate report from running multiple advisor checks.

    Contains all individual CheckResults plus a health score.
    """

    results: list[CheckResult] = field(default_factory=list)
    elapsed_ms: float = 0.0
    timestamp: str = ""

    @property
    def score(self) -> int:
        """
        Health score from 0-100.

        Starts at 100, deducts points for each finding based on severity.
        """
        total = sum(r.score_deduction for r in self.results)
        return max(0, 100 - total)

    @property
    def grade(self) -> str:
        """Letter grade based on score."""
        s = self.score
        if s >= 95:
            return "A+"
        if s >= 90:
            return "A"
        if s >= 85:
            return "B+"
        if s >= 80:
            return "B"
        if s >= 70:
            return "C"
        if s >= 60:
            return "D"
        return "F"

    @property
    def total_findings(self) -> int:
        return sum(r.finding_count for r in self.results)

    @property
    def critical_count(self) -> int:
        return sum(
            1
            for r in self.results
            for f in r.findings
            if f.severity in (CheckSeverity.CRITICAL, CheckSeverity.EMERGENCY)
        )

    @property
    def warning_count(self) -> int:
        return sum(
            1
            for r in self.results
            for f in r.findings
            if f.severity == CheckSeverity.WARNING
        )

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def checks_run(self) -> int:
        return len(self.results)

    def by_category(self) -> dict[str, list[CheckResult]]:
        """Group results by category."""
        grouped: dict[str, list[CheckResult]] = {}
        for r in self.results:
            grouped.setdefault(r.category.value, []).append(r)
        return grouped

    def by_severity(self) -> dict[str, list[CheckResult]]:
        """Group results by worst severity."""
        grouped: dict[str, list[CheckResult]] = {}
        for r in self.results:
            grouped.setdefault(r.severity.value, []).append(r)
        return grouped

    def summary(self) -> str:
        """One-line summary."""
        return (
            f"Score: {self.score}/100 ({self.grade}) | "
            f"{self.checks_run} checks | "
            f"{self.critical_count} critical | "
            f"{self.warning_count} warnings | "
            f"{self.passed_count} passed | "
            f"{self.elapsed_ms:.0f}ms"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "checks_run": self.checks_run,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "timestamp": self.timestamp,
            "results": [r.to_dict() for r in self.results],
        }


class AdvisorRegistry:
    """
    Central registry for all advisor checks.

    Provides discovery, filtering, and execution of checks.
    """

    def __init__(self) -> None:
        self._checks: dict[str, AdvisorCheck] = {}

    def register(self, check: AdvisorCheck) -> None:
        """Register a single check."""
        self._checks[check.name] = check

    def register_many(self, checks: list[AdvisorCheck]) -> None:
        """Register multiple checks."""
        for c in checks:
            self.register(c)

    def auto_discover(self) -> None:
        """
        Load all built-in advisor checks.

        Imports each advisor module which populates the registry.
        """
        from querysense.advisor.checks_security import get_security_checks
        from querysense.advisor.checks_configuration import get_configuration_checks
        from querysense.advisor.checks_vacuum import get_vacuum_checks
        from querysense.advisor.checks_replication import get_replication_checks
        from querysense.advisor.checks_performance import get_performance_checks

        self.register_many(get_security_checks())
        self.register_many(get_configuration_checks())
        self.register_many(get_vacuum_checks())
        self.register_many(get_replication_checks())
        self.register_many(get_performance_checks())

    @property
    def check_names(self) -> list[str]:
        return sorted(self._checks.keys())

    @property
    def check_count(self) -> int:
        return len(self._checks)

    def get_check(self, name: str) -> AdvisorCheck | None:
        return self._checks.get(name)

    def list_checks(
        self,
        category: AdvisorCategory | None = None,
        interval: CheckInterval | None = None,
    ) -> list[AdvisorCheck]:
        """List checks, optionally filtered."""
        checks = list(self._checks.values())
        if category:
            checks = [c for c in checks if c.category == category]
        if interval:
            checks = [c for c in checks if c.interval == interval]
        return sorted(checks, key=lambda c: (c.category.value, c.name))

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def run_check(
        self, name: str, conn: AsyncDBConnection
    ) -> CheckResult:
        """Run a single check by name."""
        check = self._checks.get(name)
        if not check:
            return CheckResult(
                check_name=name,
                category=AdvisorCategory.CONFIGURATION,
                error=f"Check '{name}' not found",
                passed=False,
            )
        return await check.safe_run(conn)

    async def run_category(
        self,
        category: AdvisorCategory,
        conn: AsyncDBConnection,
    ) -> AdvisorReport:
        """Run all checks in a category."""
        checks = [c for c in self._checks.values() if c.category == category]
        return await self._run_checks(checks, conn)

    async def run_all(
        self,
        conn: AsyncDBConnection,
        interval_filter: CheckInterval | None = None,
    ) -> AdvisorReport:
        """Run all registered checks."""
        checks = list(self._checks.values())
        if interval_filter:
            checks = [c for c in checks if c.interval == interval_filter]
        return await self._run_checks(checks, conn)

    async def _run_checks(
        self,
        checks: list[AdvisorCheck],
        conn: AsyncDBConnection,
    ) -> AdvisorReport:
        """Execute a list of checks and aggregate results."""
        import datetime

        t0 = time.perf_counter()
        results: list[CheckResult] = []

        # Run checks sequentially to avoid connection contention
        for check in checks:
            result = await check.safe_run(conn)
            results.append(result)

        report = AdvisorReport(
            results=results,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        return report
