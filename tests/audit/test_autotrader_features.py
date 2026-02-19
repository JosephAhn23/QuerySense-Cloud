"""
Tests for the Autotrader-inspired features:
    - VacuumTracker (autovacuum threshold analysis)
    - PlanHistoryTracker (EXPLAIN plan regression detection)
    - TableHealthDashboard (per-table health grades)
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Mock DB connection
# ---------------------------------------------------------------------------

class MockConn:
    def __init__(self, fetch_results=None, fetchval_results=None):
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


# ---------------------------------------------------------------------------
# VacuumTracker Tests
# ---------------------------------------------------------------------------

from querysense.audit.vacuum_tracker import (
    VacuumTracker,
    VacuumTrackerReport,
    TableVacuumState,
)


class TestTableVacuumState:
    def test_threshold_calculation(self):
        state = TableVacuumState(
            n_live_tup=100_000_000,
            n_dead_tup=5_000_000,
            vacuum_scale_factor=0.2,
            vacuum_threshold=50,
        )
        VacuumTracker._compute_threshold(state)
        # threshold = 50 + 0.2 * 100M = 20,000,050
        assert state.vacuum_trigger_threshold == 20_000_050
        # 5M / 20M = 25%
        assert 24 < state.pct_to_threshold < 26
        assert not state.will_vacuum_trigger

    def test_threshold_triggers(self):
        state = TableVacuumState(
            n_live_tup=1000,
            n_dead_tup=500,
            vacuum_scale_factor=0.2,
            vacuum_threshold=50,
        )
        VacuumTracker._compute_threshold(state)
        # threshold = 50 + 0.2 * 1000 = 250
        assert state.vacuum_trigger_threshold == 250
        # 500 > 250 -> should trigger
        assert state.will_vacuum_trigger
        assert state.pct_to_threshold == 100.0

    def test_recommended_scale_factor_for_large_table(self):
        state = TableVacuumState(
            n_live_tup=100_000_000,
            vacuum_scale_factor=0.2,
        )
        VacuumTracker._compute_threshold(state)
        # 100M rows -> should recommend 0.01
        assert state.recommended_scale_factor is not None
        assert state.recommended_scale_factor <= 0.02

    def test_no_recommendation_for_small_table(self):
        state = TableVacuumState(
            n_live_tup=10_000,
            vacuum_scale_factor=0.2,
        )
        VacuumTracker._compute_threshold(state)
        assert state.recommended_scale_factor is None

    def test_dead_tuple_ratio(self):
        state = TableVacuumState(n_live_tup=700, n_dead_tup=300)
        assert state.dead_tuple_ratio == pytest.approx(0.3)

    def test_severity_critical(self):
        state = TableVacuumState(pct_to_threshold=95)
        assert state.severity == "critical"

    def test_severity_warning(self):
        state = TableVacuumState(pct_to_threshold=75)
        assert state.severity == "warning"

    def test_severity_ok(self):
        state = TableVacuumState(pct_to_threshold=30)
        assert state.severity == "ok"

    def test_to_dict(self):
        state = TableVacuumState(schema="public", name="orders", n_live_tup=1000)
        d = state.to_dict()
        assert d["table"] == "public.orders"
        assert "n_live_tup" in d


class TestVacuumTracker:
    def test_autotrader_problem(self):
        """Reproduce the Autotrader UK problem: 135M rows, default scale factor."""
        conn = MockConn(
            fetchval_results={
                "autovacuum_vacuum_scale_factor": "0.2",
                "autovacuum_vacuum_threshold": "50",
                "autovacuum_analyze_scale_factor": "0.1",
                "autovacuum_analyze_threshold": "50",
                "autovacuum_max_workers": "3",
                "autovacuum_naptime": "1min",
            },
            fetch_results={
                "pg_stat_user_tables": [
                    # schema, name, live, dead, mod, ins, size, vacuum, autovacuum, analyze
                    ("public", "mot_defect", 135_000_000, 8_885_770, 500000, 1000000,
                     50_000_000_000, None, None, None),
                ],
                "reloptions": [],  # no per-table overrides
            },
        )

        tracker = VacuumTracker()
        report = asyncio.run(tracker.analyze(conn))

        assert len(report.tables) == 1
        t = report.tables[0]
        assert t.name == "mot_defect"
        assert t.n_live_tup == 135_000_000
        assert t.n_dead_tup == 8_885_770

        # Default threshold: 50 + 0.2 * 135M = 27,000,050
        assert t.vacuum_trigger_threshold == 27_000_050
        # 8.8M < 27M, so vacuum WON'T trigger (the problem!)
        assert not t.will_vacuum_trigger
        assert t.pct_to_threshold < 40

        # Should recommend lower scale factor
        assert t.recommended_scale_factor is not None
        assert t.recommended_scale_factor <= 0.02

        # Should generate warning about large table
        warnings = [f for f in report.findings if f.severity == "warning"]
        assert len(warnings) >= 1
        assert report.tables_vacuum_never_triggers >= 1

    def test_healthy_small_tables(self):
        conn = MockConn(
            fetchval_results={
                "autovacuum_vacuum_scale_factor": "0.2",
                "autovacuum_vacuum_threshold": "50",
                "autovacuum_analyze_scale_factor": "0.1",
                "autovacuum_analyze_threshold": "50",
                "autovacuum_max_workers": "3",
                "autovacuum_naptime": "1min",
            },
            fetch_results={
                "pg_stat_user_tables": [
                    ("public", "users", 5000, 100, 50, 20, 1_000_000,
                     "2024-01-15 10:00:00", "2024-01-15 09:00:00", "2024-01-15 10:00:00"),
                ],
                "reloptions": [],
            },
        )

        tracker = VacuumTracker()
        report = asyncio.run(tracker.analyze(conn))

        assert report.is_healthy
        assert report.tables_vacuum_never_triggers == 0

    def test_table_above_threshold(self):
        conn = MockConn(
            fetchval_results={
                "autovacuum_vacuum_scale_factor": "0.2",
                "autovacuum_vacuum_threshold": "50",
                "autovacuum_analyze_scale_factor": "0.1",
                "autovacuum_analyze_threshold": "50",
                "autovacuum_max_workers": "3",
                "autovacuum_naptime": "1min",
            },
            fetch_results={
                "pg_stat_user_tables": [
                    ("public", "orders", 10000, 5000, 4000, 3000, 5_000_000,
                     None, None, None),
                    # threshold = 50 + 0.2*10000 = 2050, dead=5000 > 2050
                ],
                "reloptions": [],
            },
        )

        tracker = VacuumTracker()
        report = asyncio.run(tracker.analyze(conn))

        assert report.tables_needing_vacuum >= 1
        t = report.tables[0]
        assert t.will_vacuum_trigger
        crit = [f for f in report.findings if f.severity == "critical"]
        assert len(crit) >= 1

    def test_report_to_dict(self):
        report = VacuumTrackerReport(
            total_dead_tuples=1000,
            tables_needing_vacuum=2,
        )
        d = report.to_dict()
        assert d["total_dead_tuples"] == 1000


# ---------------------------------------------------------------------------
# PlanHistoryTracker Tests
# ---------------------------------------------------------------------------

from querysense.audit.plan_history import (
    PlanHistoryTracker,
    PlanSnapshot,
    PlanRegression,
    PlanHistoryReport,
)


class TestPlanSnapshot:
    def test_row_estimate_error(self):
        s = PlanSnapshot(rows_estimated=100, rows_actual=10)
        assert s.row_estimate_error == 10.0

    def test_row_estimate_error_zero(self):
        s = PlanSnapshot(rows_estimated=100, rows_actual=0)
        assert s.row_estimate_error == 0.0

    def test_to_dict(self):
        s = PlanSnapshot(query_hash="abc", total_cost=100.5, plan_type="Seq Scan")
        d = s.to_dict()
        assert d["total_cost"] == 100.5
        assert d["plan_type"] == "Seq Scan"


class TestPlanHistoryTracker:
    def test_hash_query(self):
        h1 = PlanHistoryTracker.hash_query("SELECT * FROM foo")
        h2 = PlanHistoryTracker.hash_query("  SELECT  *  FROM  foo  ")
        assert h1 == h2  # whitespace-insensitive

        h3 = PlanHistoryTracker.hash_query("SELECT * FROM bar")
        assert h1 != h3

    def test_record_and_detect(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tracker = PlanHistoryTracker(path)

            # Record baseline (good plan)
            tracker.record("SELECT * FROM orders WHERE id = 1", {
                "Plan": {
                    "Node Type": "Index Scan",
                    "Total Cost": 10.5,
                    "Actual Total Time": 0.5,
                    "Plan Rows": 1,
                    "Actual Rows": 1,
                },
            })

            # Record regression (bad plan)
            tracker.record("SELECT * FROM orders WHERE id = 1", {
                "Plan": {
                    "Node Type": "Seq Scan",
                    "Total Cost": 1500.0,
                    "Actual Total Time": 200.0,
                    "Plan Rows": 1,
                    "Actual Rows": 1,
                },
            })

            report = tracker.detect_regressions(cost_threshold_pct=50)
            assert report.has_regressions
            assert len(report.regressions) == 1

            r = report.regressions[0]
            assert r.plan_changed  # Index Scan -> Seq Scan
            assert r.cost_change_pct > 10000  # massive increase
        finally:
            Path(path).unlink(missing_ok=True)

    def test_no_regression(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tracker = PlanHistoryTracker(path)

            tracker.record("SELECT 1", {
                "Plan": {"Node Type": "Result", "Total Cost": 0.01, "Actual Total Time": 0.001},
            })
            tracker.record("SELECT 1", {
                "Plan": {"Node Type": "Result", "Total Cost": 0.01, "Actual Total Time": 0.001},
            })

            report = tracker.detect_regressions()
            assert not report.has_regressions
        finally:
            Path(path).unlink(missing_ok=True)

    def test_improvement_detected(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tracker = PlanHistoryTracker(path)

            tracker.record("SELECT * FROM users", {
                "Plan": {"Node Type": "Seq Scan", "Total Cost": 1000, "Actual Total Time": 50},
            })
            tracker.record("SELECT * FROM users", {
                "Plan": {"Node Type": "Index Scan", "Total Cost": 10, "Actual Total Time": 0.5},
            })

            report = tracker.detect_regressions()
            assert len(report.improved) == 1
            assert report.improved[0].cost_change_pct < -90
        finally:
            Path(path).unlink(missing_ok=True)

    def test_plan_instability(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tracker = PlanHistoryTracker(path)

            for plan_type in ("Index Scan", "Seq Scan", "Bitmap Heap Scan"):
                tracker.record("SELECT * FROM flaky", {
                    "Plan": {"Node Type": plan_type, "Total Cost": 100, "Actual Total Time": 10},
                })

            report = tracker.detect_regressions()
            assert len(report.unstable) == 1  # 3 different plan types
        finally:
            Path(path).unlink(missing_ok=True)

    def test_get_query_history(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tracker = PlanHistoryTracker(path)
            tracker.record("SELECT 1", {
                "Plan": {"Node Type": "Result", "Total Cost": 0.01},
            })
            tracker.record("SELECT 1", {
                "Plan": {"Node Type": "Result", "Total Cost": 0.02},
            })

            history = tracker.get_query_history("SELECT 1")
            assert len(history) == 2
            assert history[1].total_cost > history[0].total_cost
        finally:
            Path(path).unlink(missing_ok=True)

    def test_report_to_dict(self):
        report = PlanHistoryReport(total_queries=5, total_snapshots=10)
        d = report.to_dict()
        assert d["total_queries"] == 5
        assert d["has_regressions"] is False


# ---------------------------------------------------------------------------
# TableHealthDashboard Tests
# ---------------------------------------------------------------------------

from querysense.audit.table_health import (
    TableHealthDashboard,
    TableHealth,
    TableHealthReport,
)


class TestTableHealth:
    def test_index_usage_ratio_all_index(self):
        t = TableHealth(seq_scan=0, idx_scan=100)
        assert t.index_usage_ratio == 1.0

    def test_index_usage_ratio_all_seq(self):
        t = TableHealth(seq_scan=100, idx_scan=0)
        assert t.index_usage_ratio == 0.0

    def test_index_usage_ratio_no_scans(self):
        t = TableHealth(seq_scan=0, idx_scan=0)
        assert t.index_usage_ratio == 1.0

    def test_hot_update_ratio(self):
        t = TableHealth(n_tup_upd=100, n_tup_hot_upd=80)
        assert t.hot_update_ratio == 0.8

    def test_modifications_per_hour(self):
        t = TableHealth(
            n_tup_ins=3600, n_tup_upd=3600, n_tup_del=3600,
            stats_age_seconds=3600,
        )
        assert t.modifications_per_hour == pytest.approx(10800.0)

    def test_health_grade_a(self):
        t = TableHealth(
            n_live_tup=100000,
            n_dead_tup=100,
            dead_tuple_ratio=0.001,
            idx_scan=1000,
            seq_scan=10,
        )
        assert t.health_grade == "A"

    def test_health_grade_f(self):
        t = TableHealth(
            n_live_tup=100000,
            n_dead_tup=100000,
            dead_tuple_ratio=0.5,
            idx_scan=10,
            seq_scan=1000,
        )
        assert t.health_grade in ("D", "F")

    def test_to_dict(self):
        t = TableHealth(schema="public", name="users", n_live_tup=1000)
        d = t.to_dict()
        assert d["table"] == "public.users"
        assert "health_grade" in d


class TestTableHealthDashboard:
    def test_analyze(self):
        conn = MockConn(
            fetchval_results={
                "stats_reset": 86400.0,  # 24 hours
            },
            fetch_results={
                "pg_stat_user_tables": [
                    ("public", "orders",
                     100_000_000, 500_000_000,  # sizes
                     3,                          # index_count
                     500000, 50000,              # live, dead
                     1000, 500000,               # seq_scan, seq_tup_read
                     50000, 100000,              # idx_scan, idx_tup_fetch
                     10000, 5000, 2000, 4000,    # ins, upd, del, hot_upd
                     "2024-01-15 10:00:00", None, # vacuum, autovacuum
                     "2024-01-15 09:00:00", None), # analyze, autoanalyze
                    ("public", "users",
                     10_000_000, 50_000_000,
                     2,
                     10000, 100,
                     50, 5000,
                     10000, 20000,
                     1000, 500, 100, 400,
                     "2024-01-15 10:00:00", "2024-01-15 09:00:00",
                     "2024-01-15 10:00:00", "2024-01-15 09:00:00"),
                ],
            },
        )

        dashboard = TableHealthDashboard()
        report = asyncio.run(dashboard.analyze(conn))

        assert report.total_tables == 2
        assert report.total_size_mb > 0
        assert len(report.grade_distribution) > 0

    def test_findings_for_unhealthy_table(self):
        conn = MockConn(
            fetchval_results={"stats_reset": 86400.0},
            fetch_results={
                "pg_stat_user_tables": [
                    ("public", "bloated",
                     50_000_000, 200_000_000,
                     1,
                     200000, 100000,  # 33% dead
                     5000, 10000000,  # lots of seq scans
                     100, 500,        # few idx scans
                     50000, 30000, 10000, 5000,
                     None, None,      # never vacuumed
                     None, None),     # never analyzed
                ],
            },
        )

        dashboard = TableHealthDashboard()
        report = asyncio.run(dashboard.analyze(conn))

        # Should have findings for: dead tuples, seq scans, never vacuumed, never analyzed
        assert len(report.findings) >= 3

    def test_report_to_dict(self):
        report = TableHealthReport(total_tables=10, total_size_mb=500)
        d = report.to_dict()
        assert d["total_tables"] == 10

    def test_report_summary(self):
        report = TableHealthReport(
            total_tables=5,
            total_size_mb=1000,
            grade_distribution={"A": 2, "B": 1, "C": 1, "D": 1},
        )
        s = report.summary
        assert "5 tables" in s
        assert "A=2" in s
