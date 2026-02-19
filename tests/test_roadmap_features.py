"""
Tests for pganalyze roadmap features:
1. AsyncIOProfiler — PG18 async I/O detection and recommendations
2. UUIDMigrator — UUIDv4→v7 detection and migration script generation
3. ConnectionPoolTuner — Connection analysis and pool sizing
4. CheckpointPredictor — Predictive checkpoint analysis

All tests are offline (no database required) — they exercise logic,
data models, formatting, and edge cases.
"""

from __future__ import annotations

import math
import pytest

# ─────────────────────────────────────────────────────────────────────
# Async I/O Profiler
# ─────────────────────────────────────────────────────────────────────

from querysense.async_io_profiler import (
    AsyncIOProfiler,
    AsyncIOReport,
    IOWaitQuery,
)


class TestIOWaitQuery:
    def test_defaults(self):
        q = IOWaitQuery()
        assert q.io_wait_pct == 0.0
        assert q.cache_hit_ratio == 1.0

    def test_to_dict_truncates_query(self):
        q = IOWaitQuery(query="x" * 500, calls=10, total_exec_time_ms=100.5)
        d = q.to_dict()
        assert len(d["query"]) == 200
        assert d["calls"] == 10
        assert d["total_exec_time_ms"] == 100.5

    def test_high_io_wait(self):
        q = IOWaitQuery(
            queryid=1,
            query="SELECT * FROM big_table",
            calls=100,
            total_exec_time_ms=10000.0,
            blk_read_time_ms=8500.0,
            io_wait_pct=85.0,
            shared_blks_read=50000,
            shared_blks_hit=10000,
            cache_hit_ratio=0.1667,
        )
        d = q.to_dict()
        assert d["io_wait_pct"] == 85.0
        assert d["blk_read_time_ms"] == 8500.0


class TestAsyncIOReport:
    def _make_report(self, **overrides):
        defaults = {
            "pg_version": 18,
            "is_pg18": True,
            "io_method": "sync",
            "io_combine_limit": 32,
            "track_io_timing": True,
            "effective_io_concurrency": 1,
            "storage_type": "cloud",
            "overall_io_wait_pct": 45.0,
            "total_io_wait_ms": 45000.0,
            "total_exec_time_ms": 100000.0,
        }
        defaults.update(overrides)
        return AsyncIOReport(**defaults)

    def test_to_dict_structure(self):
        r = self._make_report()
        d = r.to_dict()
        assert "current_config" in d
        assert "io_profile" in d
        assert "recommendations" in d
        assert d["pg_version"] == 18
        assert d["is_pg18"] is True

    def test_format_text_pg18_sync(self):
        r = self._make_report()
        profiler = AsyncIOProfiler()
        profiler._compute_recommendations(r)
        text = r.format_text()
        assert "ASYNC I/O ANALYSIS" in text
        assert "sync" in text.lower() or "io_method" in text

    def test_format_text_pg16(self):
        r = self._make_report(pg_version=16, is_pg18=False)
        profiler = AsyncIOProfiler()
        profiler._compute_recommendations(r)
        text = r.format_text()
        assert "Upgrade" in text

    def test_format_text_already_enabled(self):
        r = self._make_report(io_method="worker")
        profiler = AsyncIOProfiler()
        profiler._compute_recommendations(r)
        text = r.format_text()
        assert "already enabled" in text.lower()

    def test_io_queries_in_text(self):
        r = self._make_report()
        r.top_io_queries = [
            IOWaitQuery(query="SELECT 1", io_wait_pct=90.0, total_exec_time_ms=100),
            IOWaitQuery(query="SELECT 2", io_wait_pct=50.0, total_exec_time_ms=200),
        ]
        text = r.format_text()
        assert "SELECT 1" in text
        assert "SELECT 2" in text


class TestAsyncIORecommendations:
    def test_nvme_gets_io_uring(self):
        r = AsyncIOReport(
            pg_version=18, is_pg18=True, io_method="sync",
            storage_type="nvme", overall_io_wait_pct=30.0,
            track_io_timing=True, effective_io_concurrency=200,
        )
        AsyncIOProfiler()._compute_recommendations(r)
        assert r.recommended_io_method == "io_uring"
        assert r.recommended_io_combine_limit == 128

    def test_hdd_gets_worker(self):
        r = AsyncIOReport(
            pg_version=18, is_pg18=True, io_method="sync",
            storage_type="hdd", overall_io_wait_pct=60.0,
            track_io_timing=True, effective_io_concurrency=2,
        )
        AsyncIOProfiler()._compute_recommendations(r)
        assert r.recommended_io_method == "worker"
        assert r.recommended_io_combine_limit == 32
        assert r.recommended_effective_io_concurrency == 4

    def test_improvement_capped_at_50(self):
        r = AsyncIOReport(
            pg_version=18, is_pg18=True, io_method="sync",
            storage_type="ssd", overall_io_wait_pct=99.0,
            track_io_timing=True, effective_io_concurrency=200,
        )
        AsyncIOProfiler()._compute_recommendations(r)
        assert r.estimated_improvement_pct <= 50.0

    def test_pre_pg18_gets_upgrade_finding(self):
        r = AsyncIOReport(
            pg_version=16, is_pg18=False, io_method="sync",
            storage_type="cloud", overall_io_wait_pct=40.0,
            track_io_timing=True, effective_io_concurrency=1,
        )
        AsyncIOProfiler()._compute_recommendations(r)
        assert any("Upgrade" in f["title"] for f in r.findings)

    def test_track_io_timing_off_finding(self):
        r = AsyncIOReport(
            pg_version=18, is_pg18=True, io_method="worker",
            storage_type="ssd", overall_io_wait_pct=0.0,
            track_io_timing=False, effective_io_concurrency=200,
        )
        AsyncIOProfiler()._compute_recommendations(r)
        assert any("track_io_timing" in f["title"] for f in r.findings)


# ─────────────────────────────────────────────────────────────────────
# UUID Migrator
# ─────────────────────────────────────────────────────────────────────

from querysense.uuid_migrator import (
    UUIDMigrator,
    UUIDMigrationPlan,
    UUIDColumn,
)


class TestUUIDColumn:
    def test_size_properties(self):
        col = UUIDColumn(table_size_bytes=10 * 1024 * 1024, index_size_bytes=2 * 1024 * 1024)
        assert col.table_size_mb == 10.0
        assert col.index_size_mb == 2.0

    def test_to_dict(self):
        col = UUIDColumn(
            schema="public", table="users", column="id",
            is_primary_key=True, uuid_version="v4",
            table_size_bytes=5 * 1024 * 1024, row_count=100000,
        )
        d = col.to_dict()
        assert d["schema"] == "public"
        assert d["uuid_version"] == "v4"
        assert d["is_primary_key"] is True

    def test_fk_references_default_empty(self):
        col = UUIDColumn()
        assert col.fk_references == []


class TestUUIDVersionDetection:
    def test_gen_random_uuid(self):
        migrator = UUIDMigrator()
        assert migrator._detect_uuid_version("gen_random_uuid()") == "v4"

    def test_uuid_generate_v4(self):
        migrator = UUIDMigrator()
        assert migrator._detect_uuid_version("uuid_generate_v4()") == "v4"

    def test_uuidv7(self):
        migrator = UUIDMigrator()
        assert migrator._detect_uuid_version("uuidv7()") == "v7"

    def test_uuid_generate_v7(self):
        migrator = UUIDMigrator()
        assert migrator._detect_uuid_version("uuid_generate_v7()") == "v7"

    def test_unknown_default(self):
        migrator = UUIDMigrator()
        assert migrator._detect_uuid_version("nextval('seq')") == "unknown"

    def test_empty_default(self):
        migrator = UUIDMigrator()
        assert migrator._detect_uuid_version("") == "unknown"


class TestUUIDMigrationPlan:
    def _make_plan(self, n_tables=3, version="v4", pg_version=18):
        plan = UUIDMigrationPlan(
            pg_version=pg_version,
            has_native_uuidv7=(pg_version >= 18),
        )
        for i in range(n_tables):
            plan.columns.append(UUIDColumn(
                schema="public",
                table=f"table_{i}",
                column="id",
                is_primary_key=True,
                uuid_version=version,
                table_size_bytes=(i + 1) * 50 * 1024 * 1024,
                index_size_bytes=(i + 1) * 10 * 1024 * 1024,
                row_count=(i + 1) * 100000,
                index_bloat_estimate_pct=25.0 if version == "v4" else 5.0,
            ))
        plan.total_tables_affected = n_tables
        plan.total_size_mb = sum(c.table_size_mb for c in plan.columns)
        plan.total_index_size_mb = sum(c.index_size_mb for c in plan.columns)
        return plan

    def test_to_dict(self):
        plan = self._make_plan()
        d = plan.to_dict()
        assert d["tables_affected"] == 3
        assert d["native_uuidv7"] is True
        assert len(d["columns"]) == 3

    def test_format_text_v4_tables(self):
        plan = self._make_plan()
        text = plan.format_text()
        assert "UUID PRIMARY KEY ANALYSIS" in text
        assert "table_0" in text
        assert "+30%" in text  # INSERT improvement

    def test_format_text_no_v4(self):
        plan = self._make_plan(version="v7")
        text = plan.format_text()
        assert "+30%" not in text

    def test_generate_migration_sql_pg18(self):
        plan = self._make_plan(pg_version=18)
        sql = plan.generate_migration_sql()
        assert "uuidv7()" in sql
        assert "ALTER TABLE" in sql
        assert "REINDEX" in sql
        assert "pg_uuidv7" not in sql  # native, no extension needed

    def test_generate_migration_sql_pg16(self):
        plan = self._make_plan(pg_version=16)
        plan.has_native_uuidv7 = False
        plan.has_pg_uuidv7 = False
        sql = plan.generate_migration_sql()
        assert "pg_uuidv7" in sql
        assert "uuid_generate_v7()" in sql

    def test_generate_migration_sql_skips_v7(self):
        plan = self._make_plan(version="v7")
        sql = plan.generate_migration_sql()
        assert "ALTER TABLE" not in sql

    def test_fk_references_in_sql(self):
        plan = self._make_plan(n_tables=1)
        plan.columns[0].fk_references = [
            {"table": "orders", "column": "user_id"},
            {"table": "sessions", "column": "user_id"},
        ]
        sql = plan.generate_migration_sql()
        assert "2 foreign key references" in sql
        assert "orders" in sql


# ─────────────────────────────────────────────────────────────────────
# Connection Pool Tuner
# ─────────────────────────────────────────────────────────────────────

from querysense.connection_pool_tuner import (
    ConnectionPoolTuner,
    ConnectionPoolReport,
    ConnectionSlot,
    ConnectionProfile,
    PoolRecommendation,
)


class TestConnectionSlot:
    def test_defaults(self):
        slot = ConnectionSlot()
        assert slot.pid == 0
        assert slot.state == ""
        assert slot.idle_seconds == 0.0


class TestConnectionProfile:
    def test_to_dict(self):
        p = ConnectionProfile(
            database="mydb", user="app", application="django",
            total=10, active=3, idle=5, idle_in_txn=2,
            avg_idle_seconds=120.5,
        )
        d = p.to_dict()
        assert d["total"] == 10
        assert d["avg_idle_seconds"] == 120.5


class TestPoolRecommendation:
    def test_to_dict(self):
        r = PoolRecommendation(
            pool_mode="transaction",
            pool_size=25,
            reason="High idle ratio",
        )
        d = r.to_dict()
        assert d["pool_mode"] == "transaction"
        assert d["pool_size"] == 25


class TestConnectionPoolReport:
    def _make_report(
        self, max_conn=100, active=5, idle=30, idle_txn=10,
    ):
        report = ConnectionPoolReport(
            max_connections=max_conn,
            superuser_reserved=3,
        )
        for i in range(active):
            report.connections.append(
                ConnectionSlot(pid=1000 + i, state="active", database="mydb",
                               user="app", application_name="django")
            )
        for i in range(idle):
            report.connections.append(
                ConnectionSlot(pid=2000 + i, state="idle", database="mydb",
                               user="app", application_name="django",
                               idle_seconds=300.0)
            )
        for i in range(idle_txn):
            report.connections.append(
                ConnectionSlot(pid=3000 + i, state="idle in transaction",
                               database="mydb", user="app",
                               application_name="django", idle_seconds=60.0)
            )
        report.current_connections = len(report.connections)
        report.utilization_pct = report.current_connections / max_conn * 100
        report.active_count = active
        report.idle_count = idle
        report.idle_in_txn_count = idle_txn
        report.memory_per_connection_mb = 10.0
        report.total_memory_wasted_mb = idle * 10.0
        return report

    def test_to_dict(self):
        r = self._make_report()
        d = r.to_dict()
        assert d["max_connections"] == 100
        assert d["breakdown"]["active"] == 5
        assert d["breakdown"]["idle"] == 30

    def test_format_text_shows_breakdown(self):
        r = self._make_report()
        tuner = ConnectionPoolTuner()
        tuner._build_profiles(r)
        tuner._compute_recommendation(r)
        tuner._generate_findings(r)
        text = r.format_text()
        assert "CONNECTION POOL ANALYSIS" in text
        assert "Active" in text
        assert "Idle" in text

    def test_pgbouncer_ini_generation(self):
        r = self._make_report()
        tuner = ConnectionPoolTuner()
        tuner._build_profiles(r)
        tuner._compute_recommendation(r)
        r.profiles = [ConnectionProfile(
            key="mydb/app/django", database="mydb",
            user="app", application="django",
            total=45, active=5, idle=30, idle_in_txn=10,
        )]
        ini = r.generate_pgbouncer_ini()
        assert "[databases]" in ini
        assert "[pgbouncer]" in ini
        assert "pool_mode" in ini
        assert "mydb" in ini

    def test_high_utilization_critical_finding(self):
        r = self._make_report(max_conn=50, active=30, idle=10, idle_txn=5)
        tuner = ConnectionPoolTuner()
        tuner._build_profiles(r)
        tuner._compute_recommendation(r)
        tuner._generate_findings(r)
        assert any(f["severity"] == "critical" for f in r.findings)

    def test_idle_in_txn_finding(self):
        r = self._make_report(idle_txn=15)
        tuner = ConnectionPoolTuner()
        tuner._build_profiles(r)
        tuner._compute_recommendation(r)
        tuner._generate_findings(r)
        assert any("idle in transaction" in f["title"] for f in r.findings)


class TestPoolSizing:
    def test_transaction_mode_for_idle_heavy(self):
        r = ConnectionPoolReport(
            max_connections=100, current_connections=50,
            active_count=5, idle_count=40, idle_in_txn_count=5,
        )
        tuner = ConnectionPoolTuner()
        tuner._compute_recommendation(r)
        assert r.recommendation.pool_mode == "transaction"

    def test_session_mode_for_low_utilization(self):
        r = ConnectionPoolReport(
            max_connections=100, current_connections=10,
            utilization_pct=10.0,
            active_count=8, idle_count=2, idle_in_txn_count=0,
        )
        tuner = ConnectionPoolTuner()
        tuner._compute_recommendation(r)
        assert r.recommendation.pool_mode == "session"

    def test_pool_size_bounds(self):
        r = ConnectionPoolReport(
            max_connections=100, current_connections=80,
            active_count=60, idle_count=10, idle_in_txn_count=10,
        )
        tuner = ConnectionPoolTuner()
        tuner._compute_recommendation(r)
        assert r.recommendation.pool_size <= r.max_connections // 2
        assert r.recommendation.pool_size >= 10


class TestHighMaxConnections:
    def test_high_max_no_pgbouncer_finding(self):
        r = ConnectionPoolReport(
            max_connections=500, current_connections=50,
            active_count=5, idle_count=40, idle_in_txn_count=5,
            memory_per_connection_mb=10.0,
            has_pgbouncer=False,
        )
        tuner = ConnectionPoolTuner()
        tuner._generate_findings(r)
        assert any("max_connections=500" in f["title"] for f in r.findings)


# ─────────────────────────────────────────────────────────────────────
# Checkpoint Predictor
# ─────────────────────────────────────────────────────────────────────

from querysense.audit.checkpoint_predictor import (
    CheckpointPredictor,
    CheckpointForecast,
    WALRateSnapshot,
)
from querysense.audit.checkpoints import CheckpointReport, CheckpointStats


class TestWALRateSnapshot:
    def test_defaults(self):
        s = WALRateSnapshot()
        assert s.timestamp == 0.0
        assert s.wal_rate_bytes_per_sec == 0.0


class TestCheckpointForecast:
    def _make_forecast(self, **overrides):
        defaults = {
            "wal_rate_bytes_per_sec": 5 * 1024 * 1024,  # 5 MB/s
            "wal_rate_mb_per_min": 300.0,
            "wal_rate_gb_per_hour": 18.0,
            "max_wal_size_bytes": 1024 * 1024 * 1024,  # 1 GB
            "checkpoint_timeout_sec": 300,
        }
        defaults.update(overrides)
        f = CheckpointForecast(**defaults)
        return f

    def test_to_dict_structure(self):
        f = self._make_forecast()
        d = f.to_dict()
        assert "wal_rate" in d
        assert "capacity" in d
        assert "prediction" in d
        assert "risk_level" in d

    def test_format_text_contains_sections(self):
        f = self._make_forecast()
        f.findings = [{"severity": "info", "title": "OK", "fix": "None"}]
        text = f.format_text()
        assert "CHECKPOINT PREDICTION" in text
        assert "WAL GENERATION RATE" in text
        assert "FORECAST" in text

    def test_format_duration(self):
        assert CheckpointForecast._fmt_duration(30) == "30s"
        assert "min" in CheckpointForecast._fmt_duration(180)
        assert "hours" in CheckpointForecast._fmt_duration(7200)
        assert CheckpointForecast._fmt_duration(0) == "N/A"
        assert CheckpointForecast._fmt_duration(-1) == "N/A"


class TestCapacityComputation:
    def test_fill_ratio_over_one(self):
        f = CheckpointForecast(
            wal_rate_bytes_per_sec=10 * 1024 * 1024,  # 10 MB/s
            max_wal_size_bytes=1024 * 1024 * 1024,  # 1 GB
            checkpoint_timeout_sec=300,
        )
        predictor = CheckpointPredictor()
        predictor._compute_capacity(f)
        # 10 MB/s * 300s = 3 GB > 1 GB → ratio = 3.0
        assert f.fill_ratio > 1.0
        assert f.fill_ratio == pytest.approx(3.0, rel=0.1)

    def test_fill_ratio_healthy(self):
        f = CheckpointForecast(
            wal_rate_bytes_per_sec=0.5 * 1024 * 1024,  # 0.5 MB/s
            max_wal_size_bytes=2 * 1024 * 1024 * 1024,  # 2 GB
            checkpoint_timeout_sec=300,
        )
        predictor = CheckpointPredictor()
        predictor._compute_capacity(f)
        # 0.5 * 300 = 150 MB / 2 GB ≈ 0.073
        assert f.fill_ratio < 1.0

    def test_time_to_full(self):
        f = CheckpointForecast(
            wal_rate_bytes_per_sec=1024 * 1024,  # 1 MB/s
            max_wal_size_bytes=1024 * 1024 * 1024,  # 1 GB
            checkpoint_timeout_sec=300,
        )
        predictor = CheckpointPredictor()
        predictor._compute_capacity(f)
        assert f.time_to_wal_full_sec == pytest.approx(1024, rel=0.01)


class TestCheckpointPrediction:
    def test_forced_checkpoints_rate(self):
        f = CheckpointForecast(
            fill_ratio=2.0,
            time_to_wal_full_sec=200,
            checkpoint_timeout_sec=300,
        )
        predictor = CheckpointPredictor()
        predictor._predict_checkpoints(f)
        assert f.predicted_checkpoints_per_hour == pytest.approx(18.0, rel=0.01)

    def test_timer_driven_checkpoints(self):
        f = CheckpointForecast(
            fill_ratio=0.5,
            checkpoint_timeout_sec=300,
        )
        predictor = CheckpointPredictor()
        predictor._predict_checkpoints(f)
        assert f.predicted_checkpoints_per_hour == pytest.approx(12.0, rel=0.01)


class TestTrendAnalysis:
    def test_increasing_trend(self):
        samples = [
            WALRateSnapshot(timestamp=1000, wal_rate_bytes_per_sec=1_000_000),
            WALRateSnapshot(timestamp=2000, wal_rate_bytes_per_sec=1_100_000),
            WALRateSnapshot(timestamp=3000, wal_rate_bytes_per_sec=1_200_000),
        ]
        f = CheckpointForecast(
            wal_rate_bytes_per_sec=1_200_000,
            max_wal_size_bytes=10 * 1024**3,
            checkpoint_timeout_sec=300,
        )
        predictor = CheckpointPredictor()
        predictor._compute_trend(samples, f)
        assert f.has_trend_data is True
        assert f.wal_rate_trend_pct_per_day > 0

    def test_decreasing_trend(self):
        samples = [
            WALRateSnapshot(timestamp=1000, wal_rate_bytes_per_sec=2_000_000),
            WALRateSnapshot(timestamp=2000, wal_rate_bytes_per_sec=1_500_000),
            WALRateSnapshot(timestamp=3000, wal_rate_bytes_per_sec=1_000_000),
        ]
        f = CheckpointForecast()
        predictor = CheckpointPredictor()
        predictor._compute_trend(samples, f)
        assert f.wal_rate_trend_pct_per_day < 0

    def test_single_sample_no_trend(self):
        samples = [WALRateSnapshot(timestamp=1000, wal_rate_bytes_per_sec=1_000_000)]
        f = CheckpointForecast()
        predictor = CheckpointPredictor()
        predictor._compute_trend(samples, f)
        assert f.has_trend_data is False


class TestRiskAssessment:
    def test_critical_risk(self):
        f = CheckpointForecast(
            fill_ratio=2.5,
            wal_capacity_per_timeout=5 * 1024**3,
            predicted_checkpoints_per_hour=20,
            predicted_io_pct=5.0,
        )
        predictor = CheckpointPredictor()
        predictor._assess_risk(f)
        assert f.risk_level == "critical"
        assert f.is_healthy is False
        assert any(ff["severity"] == "critical" for ff in f.findings)

    def test_high_risk(self):
        f = CheckpointForecast(
            fill_ratio=1.5,
            wal_capacity_per_timeout=3 * 1024**3,
            predicted_checkpoints_per_hour=15,
            predicted_io_pct=5.0,
        )
        predictor = CheckpointPredictor()
        predictor._assess_risk(f)
        assert f.risk_level == "high"
        assert f.is_healthy is False

    def test_medium_risk(self):
        f = CheckpointForecast(
            fill_ratio=0.8,
            predicted_checkpoints_per_hour=10,
            predicted_io_pct=5.0,
        )
        predictor = CheckpointPredictor()
        predictor._assess_risk(f)
        assert f.risk_level == "medium"
        assert f.is_healthy is True

    def test_low_risk(self):
        f = CheckpointForecast(
            fill_ratio=0.3,
            predicted_checkpoints_per_hour=8,
            predicted_io_pct=2.0,
        )
        predictor = CheckpointPredictor()
        predictor._assess_risk(f)
        assert f.risk_level == "low"
        assert f.is_healthy is True
        assert any(ff["severity"] == "info" for ff in f.findings)

    def test_high_io_finding(self):
        f = CheckpointForecast(
            fill_ratio=0.5,
            predicted_checkpoints_per_hour=8,
            predicted_io_pct=25.0,
        )
        predictor = CheckpointPredictor()
        predictor._assess_risk(f)
        assert any("disk bandwidth" in ff["title"] for ff in f.findings)

    def test_high_checkpoint_rate_finding(self):
        f = CheckpointForecast(
            fill_ratio=0.5,
            predicted_checkpoints_per_hour=20,
            predicted_io_pct=5.0,
        )
        predictor = CheckpointPredictor()
        predictor._assess_risk(f)
        assert any("checkpoints/hour" in ff["title"] for ff in f.findings)

    def test_days_until_critical_warning(self):
        f = CheckpointForecast(
            fill_ratio=0.5,
            predicted_checkpoints_per_hour=8,
            predicted_io_pct=5.0,
            has_trend_data=True,
            days_until_critical=15.0,
        )
        predictor = CheckpointPredictor()
        predictor._assess_risk(f)
        assert any("days" in ff["title"] for ff in f.findings)


# ─────────────────────────────────────────────────────────────────────
# Integration: End-to-end data model composition
# ─────────────────────────────────────────────────────────────────────

class TestEndToEnd:
    """Verify that all report types serialize correctly together."""

    def test_all_reports_serialize_to_dict(self):
        reports = {
            "async_io": AsyncIOReport(pg_version=18, is_pg18=True).to_dict(),
            "uuid_migration": UUIDMigrationPlan(pg_version=18).to_dict(),
            "connection_pool": ConnectionPoolReport().to_dict(),
            "checkpoint_forecast": CheckpointForecast().to_dict(),
        }
        for name, d in reports.items():
            assert isinstance(d, dict), f"{name} should serialize to dict"
            assert len(d) > 0, f"{name} should have content"

    def test_all_reports_format_text(self):
        reports = [
            AsyncIOReport(pg_version=18, is_pg18=True, io_method="sync",
                          storage_type="cloud", track_io_timing=True,
                          findings=[{"severity": "info", "title": "test", "fix": "n/a"}]),
            UUIDMigrationPlan(pg_version=18, has_native_uuidv7=True),
            ConnectionPoolReport(max_connections=100, recommendation=PoolRecommendation()),
            CheckpointForecast(findings=[{"severity": "info", "title": "OK", "fix": "none"}]),
        ]
        for r in reports:
            text = r.format_text()
            assert isinstance(text, str)
            assert len(text) > 50
