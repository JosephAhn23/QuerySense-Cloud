"""
Comprehensive tests for the audit suite:
    - LogParser (stderr + CSV parsing)
    - CheckpointAuditor (live DB analysis)
    - DeadlockParser (log-based deadlock detection)
    - ConnectionAuditor (auth failure analysis)
    - TempFileAuditor (temp file detection)
"""

from __future__ import annotations

import asyncio
import json
import textwrap
from datetime import datetime
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Log Parser Tests
# ---------------------------------------------------------------------------

from querysense.audit.log_parser import LogEvent, LogParser, LogSeverity


class TestLogSeverity:
    def test_all_levels_exist(self):
        for lvl in ("DEBUG", "LOG", "INFO", "NOTICE", "WARNING", "ERROR", "FATAL", "PANIC"):
            assert LogSeverity(lvl) is not None

    def test_is_str(self):
        assert isinstance(LogSeverity.ERROR, str)
        assert LogSeverity.ERROR == "ERROR"


class TestLogEvent:
    def test_is_error(self):
        e = LogEvent(severity=LogSeverity.ERROR, message="boom")
        assert e.is_error
        e2 = LogEvent(severity=LogSeverity.LOG, message="ok")
        assert not e2.is_error

    def test_is_deadlock(self):
        e = LogEvent(message="deadlock detected between two processes")
        assert e.is_deadlock
        e2 = LogEvent(message="select * from foo")
        assert not e2.is_deadlock

    def test_is_checkpoint(self):
        e = LogEvent(message="checkpoint starting: xlog")
        assert e.is_checkpoint
        e2 = LogEvent(message="checkpoint complete: wrote 1234 buffers")
        assert e2.is_checkpoint

    def test_is_connection(self):
        assert LogEvent(message="connection authorized: user=test").is_connection
        assert LogEvent(message="password authentication failed for user").is_connection
        assert LogEvent(message="no pg_hba.conf entry for host").is_connection

    def test_is_temp_file(self):
        assert LogEvent(message="temporary file: path /tmp/pgsql.123, size 12345").is_temp_file

    def test_is_autovacuum(self):
        assert LogEvent(message="autovacuum: removing old temp files").is_autovacuum
        assert LogEvent(message="automatic vacuum of table \"foo\"").is_autovacuum

    def test_is_slow_query(self):
        e = LogEvent(duration_ms=1500.0)
        assert e.is_slow_query
        e2 = LogEvent(duration_ms=None)
        assert not e2.is_slow_query

    def test_to_dict(self):
        e = LogEvent(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            pid=12345,
            severity=LogSeverity.ERROR,
            message="boom",
        )
        d = e.to_dict()
        assert d["pid"] == 12345
        assert d["severity"] == "ERROR"
        assert "2024-01-01" in d["timestamp"]


class TestLogParser:
    def test_parse_stderr_basic(self):
        log = textwrap.dedent("""\
            2024-01-15 10:23:45.123 UTC [12345] postgres@mydb LOG:  statement: SELECT 1
            2024-01-15 10:23:46.456 UTC [12346] postgres@mydb ERROR:  relation "foo" does not exist
        """)
        parser = LogParser()
        events = parser._parse_stderr(log)
        assert len(events) == 2
        assert events[0].pid == 12345
        assert events[0].severity == LogSeverity.LOG
        assert events[0].user == "postgres"
        assert events[0].database == "mydb"
        assert events[1].severity == LogSeverity.ERROR
        assert events[1].is_error

    def test_parse_stderr_continuation(self):
        log = textwrap.dedent("""\
            2024-01-15 10:23:45.123 UTC [12345] postgres@mydb ERROR:  deadlock detected
            DETAIL:  Process 3098 waits for ShareLock on relation orders
            STATEMENT:  SELECT * FROM orders WHERE id = 2 FOR UPDATE
        """)
        parser = LogParser()
        events = parser._parse_stderr(log)
        assert len(events) == 1
        assert events[0].is_deadlock
        assert "3098" in events[0].detail
        assert "SELECT * FROM orders" in events[0].statement

    def test_parse_stderr_duration(self):
        log = "2024-01-15 10:23:45 UTC [12345] LOG:  duration: 1234.567 ms  statement: SELECT 1\n"
        parser = LogParser()
        events = parser._parse_stderr(log)
        assert len(events) == 1
        assert events[0].duration_ms == pytest.approx(1234.567)
        assert events[0].is_slow_query

    def test_parse_csv(self):
        csv_data = (
            '"2024-01-15 10:23:45.123 UTC","postgres","mydb","12345","127.0.0.1","","","","","",""'
            ',"ERROR","42P01","relation does not exist","",""'
        )
        parser = LogParser()
        events = parser._parse_csv(csv_data)
        # CSV parsing should succeed
        assert isinstance(events, list)

    def test_since_filter(self):
        log = textwrap.dedent("""\
            2024-01-15 10:00:00 UTC [1] LOG:  old event
            2024-01-15 12:00:00 UTC [2] LOG:  new event
        """)
        parser = LogParser(since=datetime(2024, 1, 15, 11, 0, 0))
        events = parser._parse_stderr(log)
        assert len(events) == 1
        assert events[0].pid == 2

    def test_parse_timestamp_formats(self):
        assert LogParser._parse_timestamp("2024-01-15 10:23:45") is not None
        assert LogParser._parse_timestamp("2024-01-15 10:23:45.123") is not None
        assert LogParser._parse_timestamp("invalid") is None

    def test_parse_severity(self):
        assert LogParser._parse_severity("ERROR") == LogSeverity.ERROR
        assert LogParser._parse_severity("log") == LogSeverity.LOG
        assert LogParser._parse_severity("unknown") == LogSeverity.LOG


# ---------------------------------------------------------------------------
# Checkpoint Auditor Tests
# ---------------------------------------------------------------------------

from querysense.audit.checkpoints import CheckpointAuditor, CheckpointReport, CheckpointFinding


class MockConn:
    """Mock async DB connection for testing."""

    def __init__(self, fetch_results: dict[str, list] | None = None,
                 fetchval_results: dict[str, Any] | None = None):
        self._fetch = fetch_results or {}
        self._fetchval = fetchval_results or {}

    async def fetch(self, query: str, *args: Any) -> list:
        for key, val in self._fetch.items():
            if key in query:
                return val
        return []

    async def fetchval(self, query: str, *args: Any) -> Any:
        for key, val in self._fetchval.items():
            if key in query:
                return val
        return None


class TestCheckpointAuditor:
    def test_healthy_checkpoints(self):
        """Checkpoint every 600s (10 min) = healthy."""
        conn = MockConn(
            fetch_results={
                "pg_stat_bgwriter": [
                    (100, 5, 50000, 3000, 500, 10, "2024-01-01", 60000.0)
                    # 105 total checkpoints in 60000s = 571s/checkpoint
                ],
            },
            fetchval_results={
                "checkpoint_timeout": "15min",
                "max_wal_size": "10GB",
                "min_wal_size": "1GB",
                "checkpoint_completion_target": "0.9",
                "wal_buffers": "64MB",
            },
        )
        auditor = CheckpointAuditor()
        report = asyncio.run(auditor.analyze(conn))

        assert report.total_checkpoints == 105
        assert report.checkpoint_frequency_seconds > 500
        # Should be healthy (>300s)
        assert report.is_healthy

    def test_critical_checkpoints(self):
        """Checkpoint every 30s = critical."""
        conn = MockConn(
            fetch_results={
                "pg_stat_bgwriter": [
                    (100, 900, 50000, 3000, 500, 10, "2024-01-01", 30000.0)
                    # 1000 checkpoints in 30000s = 30s/checkpoint
                ],
            },
            fetchval_results={
                "checkpoint_timeout": "5min",
                "max_wal_size": "1GB",
            },
        )
        auditor = CheckpointAuditor()
        report = asyncio.run(auditor.analyze(conn))

        assert report.checkpoint_frequency_seconds < 60
        assert not report.is_healthy
        assert any("SEVERE" in f.title or "critical" == f.severity for f in report.findings)

    def test_high_requested_ratio(self):
        """90% forced checkpoints = warning."""
        conn = MockConn(
            fetch_results={
                "pg_stat_bgwriter": [
                    (10, 90, 50000, 3000, 500, 10, "2024-01-01", 100000.0)
                    # 90% forced, 100 total in 100000s = 1000s/checkpoint (freq OK)
                ],
            },
            fetchval_results={"checkpoint_timeout": "5min", "max_wal_size": "1GB"},
        )
        auditor = CheckpointAuditor()
        report = asyncio.run(auditor.analyze(conn))

        assert report.pct_requested == 90.0
        assert any("forced" in f.title.lower() or "requested" in f.title.lower()
                    for f in report.findings)

    def test_high_backend_writes(self):
        """Backends writing 50% of buffers = warning."""
        conn = MockConn(
            fetch_results={
                "pg_stat_bgwriter": [
                    (100, 10, 2000, 1000, 7000, 500, "2024-01-01", 100000.0)
                    # backend: 7000 / (2000+1000+7000) = 70%
                ],
            },
            fetchval_results={"checkpoint_timeout": "5min", "max_wal_size": "1GB"},
        )
        auditor = CheckpointAuditor()
        report = asyncio.run(auditor.analyze(conn))

        assert report.buffers_backend_pct > 60
        assert any("backend" in f.title.lower() for f in report.findings)

    def test_report_to_dict(self):
        report = CheckpointReport(
            checkpoint_frequency_seconds=45,
            checkpoints_per_hour=80,
            total_checkpoints=500,
            pct_requested=60,
            findings=[CheckpointFinding(
                severity="critical", title="test",
                description="desc", recommendation="fix",
            )],
        )
        d = report.to_dict()
        assert d["checkpoints_per_hour"] == 80
        assert len(d["findings"]) == 1
        assert not d["is_healthy"]

    def test_summary(self):
        report = CheckpointReport(
            checkpoint_frequency_seconds=300,
            checkpoints_per_hour=12,
            total_checkpoints=100,
            pct_requested=5,
        )
        s = report.summary
        assert "300s" in s
        assert "12.0/hour" in s


# ---------------------------------------------------------------------------
# Deadlock Parser Tests
# ---------------------------------------------------------------------------

from querysense.audit.deadlocks import DeadlockParser, DeadlockEvent, DeadlockProcess, DeadlockReport


class TestDeadlockEvent:
    def test_summary(self):
        dl = DeadlockEvent(
            timestamp=datetime(2024, 1, 15, 10, 23, 45),
            processes=[
                DeadlockProcess(pid=3098, table="orders"),
                DeadlockProcess(pid=3099, table="orders"),
            ],
            tables_involved=["orders"],
        )
        assert "3098" in dl.summary
        assert "orders" in dl.summary

    def test_cycle_description(self):
        dl = DeadlockEvent(
            processes=[
                DeadlockProcess(pid=100),
                DeadlockProcess(pid=200),
            ],
        )
        desc = dl.cycle_description
        assert "PID 100 waiting for PID 200" in desc
        assert "PID 200 waiting for PID 100" in desc

    def test_to_dict(self):
        dl = DeadlockEvent(
            timestamp=datetime(2024, 1, 15),
            processes=[DeadlockProcess(pid=1, query="SELECT 1", table="t")],
            tables_involved=["t"],
        )
        d = dl.to_dict()
        assert d["tables_involved"] == ["t"]
        assert d["processes"][0]["pid"] == 1


class TestDeadlockParser:
    def test_parse_deadlock_from_log(self):
        log = textwrap.dedent("""\
            2024-01-15 10:23:45 UTC [3098] postgres@mydb ERROR:  deadlock detected
            DETAIL:  Process 3098 waits for ShareLock on relation orders; blocked by Process 3099. Process 3099 waits for ShareLock on relation orders; blocked by Process 3098.
            STATEMENT:  SELECT * FROM orders WHERE id = 2 FOR UPDATE
        """)
        parser = DeadlockParser()
        report = parser.analyze_text(log)

        assert report.total_count == 1
        assert len(report.deadlocks) == 1
        dl = report.deadlocks[0]
        assert len(dl.processes) >= 1
        assert "orders" in dl.tables_involved

    def test_no_deadlocks(self):
        log = "2024-01-15 10:23:45 UTC [1] LOG:  all is well\n"
        parser = DeadlockParser()
        report = parser.analyze_text(log)
        assert report.total_count == 0
        assert report.summary == "No deadlocks found"

    def test_pattern_detection_repeated_table(self):
        events = [
            LogEvent(
                timestamp=datetime(2024, 1, 15, 10, 0),
                severity=LogSeverity.ERROR,
                message="deadlock detected",
                detail="Process 1 waits for ShareLock on relation orders; blocked by Process 2",
            ),
            LogEvent(
                timestamp=datetime(2024, 1, 15, 11, 0),
                severity=LogSeverity.ERROR,
                message="deadlock detected",
                detail="Process 3 waits for ShareLock on relation orders; blocked by Process 4",
            ),
        ]
        parser = DeadlockParser()
        report = parser.analyze_events(events)

        assert report.total_count == 2
        assert report.tables_affected.get("orders", 0) >= 2
        # Should detect pattern
        assert len(report.patterns) >= 1

    def test_report_to_dict(self):
        report = DeadlockReport(total_count=5, tables_affected={"orders": 3})
        d = report.to_dict()
        assert d["total_count"] == 5
        assert d["tables_affected"]["orders"] == 3


# ---------------------------------------------------------------------------
# Connection Auditor Tests
# ---------------------------------------------------------------------------

from querysense.audit.connections import ConnectionAuditor, ConnectionReport, AuthFailure


class TestConnectionAuditor:
    def test_detect_auth_failures(self):
        events = [
            LogEvent(
                timestamp=datetime(2024, 1, 15, 10, 0),
                message='password authentication failed for user "hacker"',
                client_addr="10.0.0.99",
                user="hacker",
            ),
            LogEvent(
                timestamp=datetime(2024, 1, 15, 10, 1),
                message="connection authorized: user=admin",
                user="admin",
            ),
        ]
        auditor = ConnectionAuditor()
        report = auditor.analyze_events(events)

        assert report.summary.total_auth_failures == 1
        assert report.summary.total_connections == 1
        assert len(report.auth_failures) == 1
        assert report.auth_failures[0].user == "hacker"

    def test_brute_force_detection(self):
        events = []
        for i in range(15):
            events.append(LogEvent(
                timestamp=datetime(2024, 1, 15, 10, i),
                message='password authentication failed for user "admin"',
                client_addr="10.0.0.99",
                user="admin",
            ))
        auditor = ConnectionAuditor()
        report = auditor.analyze_events(events)

        assert report.summary.total_auth_failures == 15
        # Should trigger brute force finding
        crit = [f for f in report.findings if f.severity == "critical"]
        assert len(crit) >= 1
        assert "brute force" in crit[0].title.lower()

    def test_credential_scanning_detection(self):
        events = []
        for user in ["admin", "postgres", "root", "test", "deploy"]:
            events.append(LogEvent(
                timestamp=datetime(2024, 1, 15, 10, 0),
                message=f'password authentication failed for user "{user}"',
                client_addr="192.168.1.100",
                user=user,
            ))
        auditor = ConnectionAuditor()
        report = auditor.analyze_events(events)

        assert report.summary.total_auth_failures == 5
        crit = [f for f in report.findings if "scanning" in f.title.lower()]
        assert len(crit) >= 1

    def test_clean_report(self):
        events = [
            LogEvent(
                timestamp=datetime(2024, 1, 15, 10, 0),
                message="connection authorized: user=admin",
                user="admin",
            ),
        ]
        auditor = ConnectionAuditor()
        report = auditor.analyze_events(events)
        assert report.is_clean

    def test_live_analysis(self):
        conn = MockConn(
            fetch_results={
                "pg_stat_activity": [
                    ("user1", "db1", "10.0.0.1", "active", "client backend",
                     "myapp", 3600, 60),
                    ("user2", "db2", "10.0.0.2", "idle", "client backend",
                     "myapp", 100000, 5000),  # > 24h
                ],
            },
        )
        auditor = ConnectionAuditor()
        report = asyncio.run(auditor.analyze_live(conn))

        assert report.summary.total_connections == 2
        # Second session is > 24h, should get a finding
        assert len(report.findings) >= 1

    def test_report_to_dict(self):
        report = ConnectionReport()
        report.summary.total_connections = 100
        report.summary.total_auth_failures = 5
        d = report.to_dict()
        assert d["summary"]["total_connections"] == 100
        assert d["is_clean"] is False  # has failures

    def test_extract_user(self):
        assert ConnectionAuditor._extract_user('user "admin"') == "admin"
        assert ConnectionAuditor._extract_user("no user here") == ""

    def test_extract_ip(self):
        assert ConnectionAuditor._extract_ip("host 192.168.1.100") == "192.168.1.100"
        assert ConnectionAuditor._extract_ip("no ip") == ""


# ---------------------------------------------------------------------------
# Temp File Auditor Tests
# ---------------------------------------------------------------------------

from querysense.audit.tempfiles import TempFileAuditor, TempFileReport


class TestTempFileAuditor:
    def test_live_analysis_healthy(self):
        conn = MockConn(
            fetchval_results={"work_mem": "64MB"},
            fetch_results={
                "pg_stat_database": [],  # no temp files
                "pg_stat_statements": [],
            },
        )
        auditor = TempFileAuditor()
        report = asyncio.run(auditor.analyze_live(conn))

        assert report.total_temp_files == 0
        assert report.is_healthy
        assert report.current_work_mem == "64MB"

    def test_live_analysis_with_temp_files(self):
        conn = MockConn(
            fetchval_results={"work_mem": "4MB"},
            fetch_results={
                "pg_stat_database": [
                    ("mydb", 5000, 2 * 1024 * 1024 * 1024, "2GB"),  # 2GB temp
                ],
                "pg_stat_statements": [
                    ("SELECT * FROM big_table ORDER BY col", 100000, 5000, 200),
                ],
            },
        )
        auditor = TempFileAuditor()
        report = asyncio.run(auditor.analyze_live(conn))

        assert report.total_temp_files == 5000
        assert report.total_temp_bytes == 2 * 1024 * 1024 * 1024
        assert not report.is_healthy  # >1GB triggers warning
        assert len(report.findings) >= 1

    def test_log_analysis(self):
        events = [
            LogEvent(
                message="temporary file: path /tmp/pgsql.123, size 104857600",
                statement="SELECT * FROM big ORDER BY col",
            ),
            LogEvent(
                message="temporary file: path /tmp/pgsql.456, size 52428800",
                statement="SELECT DISTINCT x FROM y",
            ),
        ]
        auditor = TempFileAuditor()
        report = auditor.analyze_events(events)

        assert report.total_temp_files == 2
        assert report.total_temp_bytes == 104857600 + 52428800

    def test_critical_threshold(self):
        """Over 10GB of temp files = critical."""
        events = []
        for _ in range(200):
            events.append(LogEvent(
                message="temporary file: path /tmp/pgsql.X, size 104857600",
                statement="SELECT ...",
            ))  # 200 * 100MB = 20GB
        auditor = TempFileAuditor()
        report = auditor.analyze_events(events)

        assert report.total_temp_files == 200
        crit = [f for f in report.findings if f.severity == "critical"]
        assert len(crit) >= 1

    def test_report_to_dict(self):
        report = TempFileReport(
            total_temp_files=100,
            total_temp_bytes=1024 * 1024 * 500,
            current_work_mem="4MB",
        )
        d = report.to_dict()
        assert d["total_temp_files"] == 100
        assert d["total_temp_mb"] == 500.0
        assert d["current_work_mem"] == "4MB"

    def test_summary_healthy(self):
        report = TempFileReport()
        assert "adequate" in report.summary.lower()

    def test_summary_unhealthy(self):
        report = TempFileReport(
            total_temp_files=500,
            total_temp_bytes=1024 * 1024 * 100,
            current_work_mem="4MB",
        )
        assert "500" in report.summary


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestAuditIntegration:
    def test_log_parser_to_deadlock_parser(self):
        """LogParser -> DeadlockParser pipeline."""
        log = textwrap.dedent("""\
            2024-01-15 10:23:45 UTC [3098] postgres@mydb ERROR:  deadlock detected
            DETAIL:  Process 3098 waits for ShareLock on relation orders
            STATEMENT:  SELECT * FROM orders FOR UPDATE
            2024-01-15 10:25:00 UTC [999] LOG:  checkpoint complete: wrote 100 buffers
        """)
        parser = LogParser()
        events = parser._parse_stderr(log)
        assert len(events) == 2

        dl_parser = DeadlockParser()
        report = dl_parser.analyze_events(events)
        assert report.total_count == 1

    def test_log_parser_to_connection_auditor(self):
        """LogParser -> ConnectionAuditor pipeline."""
        log = textwrap.dedent("""\
            2024-01-15 10:00:00 UTC [1] LOG:  connection authorized: user=admin
            2024-01-15 10:01:00 UTC [2] FATAL:  password authentication failed for user "hacker"
        """)
        parser = LogParser()
        events = parser._parse_stderr(log)

        auditor = ConnectionAuditor()
        report = auditor.analyze_events(events)
        assert report.summary.total_connections == 1
        assert report.summary.total_auth_failures == 1

    def test_log_parser_to_temp_auditor(self):
        """LogParser -> TempFileAuditor pipeline."""
        log = textwrap.dedent("""\
            2024-01-15 10:00:00 UTC [1] LOG:  temporary file: path /tmp/pgsql.123, size 50000000
            2024-01-15 10:01:00 UTC [2] LOG:  checkpoint starting: xlog
        """)
        parser = LogParser()
        events = parser._parse_stderr(log)

        auditor = TempFileAuditor()
        report = auditor.analyze_events(events)
        assert report.total_temp_files == 1
        assert report.total_temp_bytes == 50000000
