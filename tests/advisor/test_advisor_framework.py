"""
Tests for the unified advisor framework.

Tests the base classes, registry, individual checks (with mock DB connections),
and the report aggregation logic.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from querysense.advisor.base import (
    AdvisorCategory,
    AdvisorCheck,
    AsyncDBConnection,
    CheckInterval,
    CheckResult,
    CheckSeverity,
    Finding,
)
from querysense.advisor.registry import AdvisorRegistry, AdvisorReport


# ------------------------------------------------------------------
# Mock database connection
# ------------------------------------------------------------------


class MockConn:
    """Mock async database connection for testing."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self._responses = responses or {}
        self._default_responses: dict[str, Any] = {
            "SHOW ssl": "on",
            "SHOW password_encryption": "scram-sha-256",
            "SHOW shared_buffers": "4GB",
            "SHOW work_mem": "64MB",
            "SHOW effective_cache_size": "12GB",
            "SHOW maintenance_work_mem": "1GB",
            "SHOW wal_level": "replica",
            "SHOW checkpoint_completion_target": "0.9",
            "SHOW max_connections": "200",
            "SHOW random_page_cost": "1.1",
            "SHOW jit": "off",
            "SHOW log_min_duration_statement": "1000",
            "SHOW shared_preload_libraries": "'pg_stat_statements,auto_explain'",
            "SHOW log_connections": "on",
            "SHOW log_disconnections": "on",
            "SHOW log_autovacuum_min_duration": "1000",
            "SHOW autovacuum_vacuum_scale_factor": "0.2",
            "SHOW archive_mode": "off",
            "SHOW server_version": "16.1",
        }

    async def fetchval(self, query: str, *args: Any) -> Any:
        # Check user-provided first, then defaults
        for key, val in {**self._default_responses, **self._responses}.items():
            if key.lower() in query.lower():
                return val
        return None

    async def fetch(self, query: str, *args: Any) -> list[Any]:
        for key, val in self._responses.items():
            if key.lower() in query.lower():
                return val if isinstance(val, list) else [val]
        return []

    async def execute(self, query: str, *args: Any) -> str:
        return "OK"


# ------------------------------------------------------------------
# Base class tests
# ------------------------------------------------------------------


class TestFinding:
    def test_finding_to_dict(self) -> None:
        f = Finding(
            severity=CheckSeverity.WARNING,
            title="Test finding",
            description="Test description",
            recommendation="Fix it",
            fix_sql="ALTER SYSTEM SET x = y;",
        )
        d = f.to_dict()
        assert d["severity"] == "warning"
        assert d["title"] == "Test finding"
        assert d["fix_sql"] == "ALTER SYSTEM SET x = y;"

    def test_severity_weights(self) -> None:
        assert CheckSeverity.EMERGENCY.weight > CheckSeverity.CRITICAL.weight
        assert CheckSeverity.CRITICAL.weight > CheckSeverity.WARNING.weight
        assert CheckSeverity.WARNING.weight > CheckSeverity.NOTICE.weight
        assert CheckSeverity.PASS.weight == 0


class TestCheckResult:
    def test_empty_result_passes(self) -> None:
        r = CheckResult(check_name="test", category=AdvisorCategory.SECURITY)
        assert r.passed is True
        assert r.severity == CheckSeverity.PASS
        assert r.finding_count == 0
        assert r.score_deduction == 0

    def test_result_with_findings(self) -> None:
        r = CheckResult(check_name="test", category=AdvisorCategory.SECURITY)
        r.findings.append(Finding(
            severity=CheckSeverity.CRITICAL,
            title="Bad",
            description="Very bad",
            recommendation="Fix",
        ))
        r.passed = False
        assert r.severity == CheckSeverity.CRITICAL
        assert r.score_deduction == 25

    def test_to_dict(self) -> None:
        r = CheckResult(check_name="test", category=AdvisorCategory.VACUUM)
        d = r.to_dict()
        assert d["check_name"] == "test"
        assert d["category"] == "vacuum"


# ------------------------------------------------------------------
# Registry tests
# ------------------------------------------------------------------


class TestAdvisorRegistry:
    def test_auto_discover_loads_all_checks(self) -> None:
        registry = AdvisorRegistry()
        registry.auto_discover()
        assert registry.check_count >= 30  # We have 36

    def test_filter_by_category(self) -> None:
        registry = AdvisorRegistry()
        registry.auto_discover()
        security = registry.list_checks(category=AdvisorCategory.SECURITY)
        assert len(security) >= 5
        for c in security:
            assert c.category == AdvisorCategory.SECURITY

    def test_filter_by_interval(self) -> None:
        registry = AdvisorRegistry()
        registry.auto_discover()
        frequent = registry.list_checks(interval=CheckInterval.FREQUENT)
        assert len(frequent) >= 3
        for c in frequent:
            assert c.interval == CheckInterval.FREQUENT

    def test_get_check_by_name(self) -> None:
        registry = AdvisorRegistry()
        registry.auto_discover()
        check = registry.get_check("postgres_ssl_enabled")
        assert check is not None
        assert check.name == "postgres_ssl_enabled"
        assert check.category == AdvisorCategory.SECURITY

    def test_get_nonexistent_check(self) -> None:
        registry = AdvisorRegistry()
        assert registry.get_check("nonexistent") is None


# ------------------------------------------------------------------
# Report aggregation tests
# ------------------------------------------------------------------


class TestAdvisorReport:
    def test_perfect_score(self) -> None:
        report = AdvisorReport(results=[
            CheckResult(check_name="a", category=AdvisorCategory.SECURITY),
            CheckResult(check_name="b", category=AdvisorCategory.VACUUM),
        ])
        assert report.score == 100
        assert report.grade == "A+"
        assert report.passed_count == 2
        assert report.failed_count == 0

    def test_score_deduction(self) -> None:
        r = CheckResult(check_name="test", category=AdvisorCategory.SECURITY, passed=False)
        r.findings.append(Finding(
            severity=CheckSeverity.CRITICAL,
            title="Bad",
            description="Very bad",
            recommendation="Fix",
        ))
        report = AdvisorReport(results=[r])
        assert report.score == 75  # 100 - 25
        assert report.critical_count == 1

    def test_by_category_grouping(self) -> None:
        report = AdvisorReport(results=[
            CheckResult(check_name="a", category=AdvisorCategory.SECURITY),
            CheckResult(check_name="b", category=AdvisorCategory.VACUUM),
            CheckResult(check_name="c", category=AdvisorCategory.SECURITY),
        ])
        grouped = report.by_category()
        assert len(grouped["security"]) == 2
        assert len(grouped["vacuum"]) == 1

    def test_to_dict(self) -> None:
        report = AdvisorReport(results=[
            CheckResult(check_name="a", category=AdvisorCategory.SECURITY),
        ])
        d = report.to_dict()
        assert "score" in d
        assert "grade" in d
        assert "results" in d


# ------------------------------------------------------------------
# Individual check tests (with mock DB)
# ------------------------------------------------------------------


class TestSecurityChecks:
    """Test security checks against mock DB."""

    def test_ssl_enabled_passes(self) -> None:
        from querysense.advisor.checks_security import SSLEnabledCheck
        check = SSLEnabledCheck()
        conn = MockConn({"SHOW ssl": "on"})
        result = asyncio.run(check.run(conn))
        assert result.passed is True
        assert len(result.findings) == 0

    def test_ssl_disabled_fails(self) -> None:
        from querysense.advisor.checks_security import SSLEnabledCheck
        check = SSLEnabledCheck()
        conn = MockConn({"SHOW ssl": "off"})
        result = asyncio.run(check.run(conn))
        assert result.passed is False
        assert result.findings[0].severity == CheckSeverity.CRITICAL

    def test_password_scram_passes(self) -> None:
        from querysense.advisor.checks_security import PasswordEncryptionCheck
        check = PasswordEncryptionCheck()
        conn = MockConn({"SHOW password_encryption": "scram-sha-256"})
        result = asyncio.run(check.run(conn))
        assert result.passed is True

    def test_password_md5_warns(self) -> None:
        from querysense.advisor.checks_security import PasswordEncryptionCheck
        check = PasswordEncryptionCheck()
        conn = MockConn({"SHOW password_encryption": "md5"})
        result = asyncio.run(check.run(conn))
        assert result.passed is False
        assert result.findings[0].severity == CheckSeverity.WARNING


class TestConfigurationChecks:
    """Test configuration checks against mock DB."""

    def test_shared_buffers_ok(self) -> None:
        from querysense.advisor.checks_configuration import SharedBuffersCheck
        check = SharedBuffersCheck()
        conn = MockConn({"SHOW shared_buffers": "4GB"})
        result = asyncio.run(check.run(conn))
        assert result.passed is True

    def test_shared_buffers_low(self) -> None:
        from querysense.advisor.checks_configuration import SharedBuffersCheck
        check = SharedBuffersCheck()
        conn = MockConn({"SHOW shared_buffers": "64MB"})
        result = asyncio.run(check.run(conn))
        assert result.passed is False
        assert result.findings[0].severity == CheckSeverity.WARNING

    def test_max_connections_ok(self) -> None:
        from querysense.advisor.checks_configuration import MaxConnectionsCheck
        check = MaxConnectionsCheck()
        conn = MockConn({"SHOW max_connections": "200"})
        result = asyncio.run(check.run(conn))
        assert result.passed is True

    def test_max_connections_too_high(self) -> None:
        from querysense.advisor.checks_configuration import MaxConnectionsCheck
        check = MaxConnectionsCheck()
        conn = MockConn({"SHOW max_connections": "1000"})
        result = asyncio.run(check.run(conn))
        assert result.passed is False

    def test_random_page_cost_default(self) -> None:
        from querysense.advisor.checks_configuration import RandomPageCostCheck
        check = RandomPageCostCheck()
        conn = MockConn({"SHOW random_page_cost": "4"})
        result = asyncio.run(check.run(conn))
        assert result.passed is False

    def test_random_page_cost_ssd(self) -> None:
        from querysense.advisor.checks_configuration import RandomPageCostCheck
        check = RandomPageCostCheck()
        conn = MockConn({"SHOW random_page_cost": "1.1"})
        result = asyncio.run(check.run(conn))
        assert result.passed is True

    def test_version_eol(self) -> None:
        from querysense.advisor.checks_configuration import VersionEOLCheck
        check = VersionEOLCheck()
        conn = MockConn({"SHOW server_version": "12.1"})
        result = asyncio.run(check.run(conn))
        assert result.passed is False
        assert result.findings[0].severity == CheckSeverity.CRITICAL

    def test_version_current(self) -> None:
        from querysense.advisor.checks_configuration import VersionEOLCheck
        check = VersionEOLCheck()
        conn = MockConn({"SHOW server_version": "16.2"})
        result = asyncio.run(check.run(conn))
        assert result.passed is True


class TestVacuumChecks:
    """Test vacuum checks against mock DB."""

    def test_autovacuum_logging_disabled(self) -> None:
        from querysense.advisor.checks_vacuum import AutovacuumLoggingCheck
        check = AutovacuumLoggingCheck()
        conn = MockConn({"SHOW log_autovacuum_min_duration": "-1"})
        result = asyncio.run(check.run(conn))
        assert result.passed is False
        assert result.findings[0].severity == CheckSeverity.WARNING

    def test_autovacuum_logging_enabled(self) -> None:
        from querysense.advisor.checks_vacuum import AutovacuumLoggingCheck
        check = AutovacuumLoggingCheck()
        conn = MockConn({"SHOW log_autovacuum_min_duration": "1000"})
        result = asyncio.run(check.run(conn))
        assert result.passed is True


class TestSafeRun:
    """Test the safe_run error handling wrapper."""

    def test_safe_run_catches_errors(self) -> None:
        class FailingCheck(AdvisorCheck):
            name = "failing"
            category = AdvisorCategory.SECURITY
            async def run(self, conn: AsyncDBConnection) -> CheckResult:
                raise ValueError("kaboom")

        check = FailingCheck()
        conn = MockConn()
        result = asyncio.run(check.safe_run(conn))
        assert result.passed is False
        assert "kaboom" in (result.error or "")
        assert result.elapsed_ms > 0

    def test_safe_run_records_timing(self) -> None:
        class SlowCheck(AdvisorCheck):
            name = "slow"
            category = AdvisorCategory.PERFORMANCE
            async def run(self, conn: AsyncDBConnection) -> CheckResult:
                import asyncio as aio
                await aio.sleep(0.05)
                return CheckResult(check_name=self.name, category=self.category)

        check = SlowCheck()
        conn = MockConn()
        result = asyncio.run(check.safe_run(conn))
        assert result.elapsed_ms >= 40  # ~50ms sleep


class TestFullRegistryRun:
    """Test running multiple checks through the registry."""

    def test_run_check_by_name(self) -> None:
        from querysense.advisor.checks_security import SSLEnabledCheck
        registry = AdvisorRegistry()
        registry.register(SSLEnabledCheck())
        conn = MockConn({"SHOW ssl": "on"})
        result = asyncio.run(registry.run_check("postgres_ssl_enabled", conn))
        assert result.passed is True

    def test_run_nonexistent_check(self) -> None:
        registry = AdvisorRegistry()
        conn = MockConn()
        result = asyncio.run(registry.run_check("bogus", conn))
        assert "not found" in (result.error or "")

    def test_run_category(self) -> None:
        registry = AdvisorRegistry()
        registry.auto_discover()
        conn = MockConn({
            "SHOW ssl": "on",
            "SHOW password_encryption": "scram-sha-256",
            "SHOW log_connections": "on",
            "SHOW log_disconnections": "on",
            "pg_user": [],
            "pg_hba_file_rules": [],
            "pg_class": [],
            "pg_extension": [],
        })
        report = asyncio.run(registry.run_category(AdvisorCategory.SECURITY, conn))
        assert report.checks_run >= 5
        assert report.score <= 100
