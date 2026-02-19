"""
Tests for the pganalyze-inspired monitoring suite:

1. ConfigGenerator — postgresql.conf recommendations
2. MonitoringQueries — consolidated monitoring SQL
3. QueryTagging — ORM/driver tagging helpers
4. HealthCheck — automated health check script
"""

from __future__ import annotations

import pytest

from querysense.pg_config_generator import (
    ConfigEntry,
    ConfigGenerator,
    SystemProfile,
)
from querysense.monitoring import MonitoringQueries, MonitoringQuery
from querysense.query_tagging import (
    QueryTag,
    add_query_comment,
    build_application_name,
    django_middleware_class,
    psycopg_pool_configure,
)


# ===================================================================
# 1. ConfigGenerator tests
# ===================================================================


class TestConfigGenerator:
    """Tests for PostgreSQL configuration generation."""

    def test_default_profile(self):
        gen = ConfigGenerator()
        assert gen.profile.ram_gb == 16.0
        assert gen.profile.cpu_cores == 4

    def test_auto_explain_config(self):
        gen = ConfigGenerator()
        entries = gen.generate_auto_explain_config()

        keys = {e.key for e in entries}
        assert "shared_preload_libraries" in keys
        assert "auto_explain.log_min_duration" in keys
        assert "auto_explain.log_analyze" in keys
        assert "auto_explain.log_buffers" in keys
        assert "auto_explain.log_format" in keys
        assert "auto_explain.sample_rate" in keys

    def test_logging_config(self):
        gen = ConfigGenerator()
        entries = gen.generate_logging_config()

        keys = {e.key for e in entries}
        assert "log_min_duration_statement" in keys
        assert "log_line_prefix" in keys
        assert "log_checkpoints" in keys
        assert "log_lock_waits" in keys
        assert "log_temp_files" in keys
        assert "log_autovacuum_min_duration" in keys
        assert "log_statement" in keys

    def test_pgss_config(self):
        gen = ConfigGenerator()
        entries = gen.generate_pgss_config()

        keys = {e.key for e in entries}
        assert "pg_stat_statements.max" in keys
        assert "pg_stat_statements.track" in keys

    def test_performance_config_ssd(self):
        profile = SystemProfile(ram_gb=32, cpu_cores=8, storage="ssd")
        gen = ConfigGenerator(profile)
        entries = gen.generate_performance_config()

        by_key = {e.key: e for e in entries}
        assert "shared_buffers" in by_key
        assert "effective_cache_size" in by_key
        assert "work_mem" in by_key
        assert "random_page_cost" in by_key

        assert by_key["random_page_cost"].value == "1.1"

    def test_performance_config_hdd(self):
        profile = SystemProfile(ram_gb=16, cpu_cores=4, storage="hdd")
        gen = ConfigGenerator(profile)
        entries = gen.generate_performance_config()

        by_key = {e.key: e for e in entries}
        assert by_key["random_page_cost"].value == "4.0"
        assert by_key["effective_io_concurrency"].value == "2"

    def test_shared_buffers_scaling(self):
        small = ConfigGenerator(SystemProfile(ram_gb=4))
        large = ConfigGenerator(SystemProfile(ram_gb=64))

        small_entries = {e.key: e for e in small.generate_performance_config()}
        large_entries = {e.key: e for e in large.generate_performance_config()}

        small_val = int(small_entries["shared_buffers"].value.strip("'").replace("MB", ""))
        large_val = int(large_entries["shared_buffers"].value.strip("'").replace("MB", ""))
        assert large_val > small_val

    def test_replication_config(self):
        profile = SystemProfile(has_replicas=True)
        gen = ConfigGenerator(profile)
        entries = gen.generate_performance_config()

        keys = {e.key for e in entries}
        assert "wal_level" in keys
        assert "max_wal_senders" in keys
        assert "hot_standby" in keys

    def test_no_replication_without_replicas(self):
        profile = SystemProfile(has_replicas=False)
        gen = ConfigGenerator(profile)
        entries = gen.generate_performance_config()

        keys = {e.key for e in entries}
        assert "wal_level" not in keys

    def test_full_config_format(self):
        gen = ConfigGenerator()
        output = gen.generate_full_config()

        assert "QuerySense Recommended" in output
        assert "shared_buffers" in output
        assert "auto_explain" in output
        assert "log_min_duration_statement" in output

    def test_extension_sql(self):
        gen = ConfigGenerator()
        sql = gen.generate_extension_sql()

        assert "CREATE EXTENSION IF NOT EXISTS pg_stat_statements" in sql
        assert "CREATE EXTENSION IF NOT EXISTS pg_buffercache" in sql
        assert "pg_extension" in sql

    def test_requires_restart_flagged(self):
        gen = ConfigGenerator()
        entries = gen.generate_auto_explain_config()

        spl = next(e for e in entries if e.key == "shared_preload_libraries")
        assert spl.requires_restart is True

    def test_full_config_contains_restart_markers(self):
        gen = ConfigGenerator()
        output = gen.generate_full_config()
        assert "REQUIRES RESTART" in output

    def test_olap_workload_higher_work_mem(self):
        olap = ConfigGenerator(SystemProfile(workload="olap", ram_gb=64))
        web = ConfigGenerator(SystemProfile(workload="web", ram_gb=64))

        olap_entries = {e.key: e for e in olap.generate_performance_config()}
        web_entries = {e.key: e for e in web.generate_performance_config()}

        olap_wm = int(olap_entries["work_mem"].value.strip("'").replace("MB", ""))
        web_wm = int(web_entries["work_mem"].value.strip("'").replace("MB", ""))
        assert olap_wm >= web_wm

    def test_high_connection_pgss_max(self):
        high = ConfigGenerator(SystemProfile(max_connections=500))
        low = ConfigGenerator(SystemProfile(max_connections=50))

        high_entries = {e.key: e for e in high.generate_pgss_config()}
        low_entries = {e.key: e for e in low.generate_pgss_config()}

        assert high_entries["pg_stat_statements.max"].value == "10000"
        assert low_entries["pg_stat_statements.max"].value == "5000"

    def test_config_entry_fields(self):
        e = ConfigEntry(
            key="test", value="42", comment="A test entry",
            section="Test", requires_restart=True,
        )
        assert e.key == "test"
        assert e.requires_restart


# ===================================================================
# 2. MonitoringQueries tests
# ===================================================================


class TestMonitoringQueries:
    """Tests for the consolidated monitoring queries module."""

    def test_all_queries_returns_list(self):
        mq = MonitoringQueries()
        queries = mq.all_queries()
        assert len(queries) >= 10
        assert all(isinstance(q, MonitoringQuery) for q in queries)

    def test_top_queries_sql(self):
        q = MonitoringQueries.top_queries_sql(limit=10)
        assert "pg_stat_statements" in q.sql
        assert "LIMIT 10" in q.sql
        assert q.name == "top_queries"
        assert q.requires_extension == "pg_stat_statements"

    def test_top_queries_sort_by(self):
        q = MonitoringQueries.top_queries_sql(sort_by="calls")
        assert "ORDER BY calls DESC" in q.sql

    def test_top_queries_invalid_sort(self):
        q = MonitoringQueries.top_queries_sql(sort_by="invalid")
        assert "ORDER BY total_exec_time DESC" in q.sql

    def test_index_usage_sql(self):
        q = MonitoringQueries.index_usage_sql()
        assert "pg_stat_user_indexes" in q.sql
        assert q.category == "indexes"

    def test_missing_indexes_sql(self):
        q = MonitoringQueries.missing_indexes_sql(min_seq_scans=500)
        assert "seq_scan > 500" in q.sql

    def test_vacuum_status_sql(self):
        q = MonitoringQueries.vacuum_status_sql()
        assert "n_dead_tup" in q.sql
        assert "last_autovacuum" in q.sql

    def test_lock_monitoring_sql(self):
        q = MonitoringQueries.lock_monitoring_sql()
        assert "wait_event" in q.sql

    def test_blocking_chains_sql(self):
        q = MonitoringQueries.blocking_chains_sql()
        assert "pg_locks" in q.sql
        assert q.min_pg_version >= 14

    def test_session_overview_sql(self):
        q = MonitoringQueries.session_overview_sql()
        assert "pg_stat_activity" in q.sql
        assert q.category == "sessions"

    def test_wait_events_sql(self):
        q = MonitoringQueries.wait_events_sql()
        assert "wait_event_type" in q.sql

    def test_cache_hit_ratio_sql(self):
        q = MonitoringQueries.cache_hit_ratio_sql()
        assert "hit_ratio" in q.sql
        assert "pg_statio_user_indexes" in q.sql
        assert "pg_statio_user_tables" in q.sql

    def test_replication_lag_sql(self):
        q = MonitoringQueries.replication_lag_sql()
        assert "pg_stat_replication" in q.sql
        assert "lag_bytes" in q.sql

    def test_long_running_queries_sql(self):
        q = MonitoringQueries.long_running_queries_sql(threshold_minutes=10)
        assert "10 minutes" in q.sql

    def test_database_sizes_sql(self):
        q = MonitoringQueries.database_sizes_sql()
        assert "pg_database_size" in q.sql

    def test_queries_by_category(self):
        mq = MonitoringQueries()
        cats = mq.queries_by_category()

        assert "queries" in cats
        assert "indexes" in cats
        assert "vacuum" in cats
        assert "locks" in cats
        assert "sessions" in cats
        assert "performance" in cats
        assert "replication" in cats

    def test_format_all_sql(self):
        mq = MonitoringQueries()
        output = mq.format_all_sql()

        assert "QuerySense" in output
        assert "pg_stat_statements" in output
        assert "pg_stat_user_indexes" in output
        assert "n_dead_tup" in output

    def test_all_queries_have_required_fields(self):
        mq = MonitoringQueries()
        for q in mq.all_queries():
            assert q.name, f"Query missing name: {q}"
            assert q.description, f"Query missing description: {q.name}"
            assert q.sql.strip(), f"Query missing SQL: {q.name}"
            assert q.category, f"Query missing category: {q.name}"

    def test_no_duplicate_query_names(self):
        mq = MonitoringQueries()
        names = [q.name for q in mq.all_queries()]
        assert len(names) == len(set(names)), f"Duplicate names: {names}"


# ===================================================================
# 3. QueryTagging tests
# ===================================================================


class TestQueryTagging:
    """Tests for the query tagging helpers."""

    def test_add_query_comment_basic(self):
        sql = add_query_comment("SELECT 1", app="web")
        assert sql == "SELECT 1 /* app=web */"

    def test_add_query_comment_multiple_tags(self):
        sql = add_query_comment(
            "SELECT * FROM orders",
            app="api",
            controller="OrdersController",
            action="index",
        )
        assert "/* " in sql
        assert "app=api" in sql
        assert "controller=OrdersController" in sql
        assert "action=index" in sql
        assert "*/" in sql

    def test_add_query_comment_preserves_semicolon(self):
        sql = add_query_comment("SELECT 1;", app="test")
        assert sql.endswith(";")
        assert "/* app=test */" in sql

    def test_add_query_comment_no_tags_returns_original(self):
        sql = add_query_comment("SELECT 1")
        assert sql == "SELECT 1"

    def test_add_query_comment_sanitizes_dangerous_chars(self):
        sql = add_query_comment("SELECT 1", app="test*/DROP TABLE")
        assert "*/" not in sql.split("/*")[1].split("*/")[0]

    def test_build_application_name_basic(self):
        name = build_application_name(app="myapp")
        assert name == "myapp"

    def test_build_application_name_full(self):
        name = build_application_name(
            app="api",
            environment="prod",
            version="2.0",
            host="web-01",
            pid="1234",
        )
        assert name == "api/prod/2.0@web-01:1234"

    def test_build_application_name_truncates(self):
        name = build_application_name(app="a" * 100)
        assert len(name) <= 63

    def test_query_tag_as_comment(self):
        tag = QueryTag("app", "myapp")
        assert tag.as_comment() == "app=myapp"

    def test_query_tag_as_guc(self):
        tag = QueryTag("user_id", "42")
        guc = tag.as_guc("myapp")
        assert guc == "SET myapp.user_id = '42'"

    def test_query_tag_guc_escapes_quotes(self):
        tag = QueryTag("name", "O'Brien")
        guc = tag.as_guc()
        assert "'O''Brien'" in guc

    def test_django_middleware_source(self):
        source = django_middleware_class()
        assert "class QuerySenseTaggingMiddleware" in source
        assert "application_name" in source
        assert "def __call__" in source

    def test_psycopg_pool_source(self):
        source = psycopg_pool_configure()
        assert "ConnectionPool" in source
        assert "configure_conn" in source
        assert "application_name" in source

    def test_add_query_comment_with_whitespace(self):
        sql = add_query_comment("  SELECT 1  ;  ", app="test")
        assert "/* app=test */" in sql


# ===================================================================
# 4. HealthCheck tests (unit tests — no DB connection)
# ===================================================================


class TestHealthCheck:
    """Tests for the health check script's non-DB components."""

    def test_import_health_check_module(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "health_check",
            "scripts/health_check.py",
        )
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert hasattr(mod, "HealthReport")
        assert hasattr(mod, "CheckResult")
        assert hasattr(mod, "ALL_CHECKS")
        assert hasattr(mod, "format_text_report")

    def test_check_result_dataclass(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "health_check",
            "scripts/health_check.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        r = mod.CheckResult("test_check", "ok", "All good")
        assert r.name == "test_check"
        assert r.status == "ok"
        assert r.message == "All good"
        assert r.row_count == 0

    def test_health_report_to_dict(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "health_check",
            "scripts/health_check.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        report = mod.HealthReport(
            timestamp="2026-02-16T00:00:00Z",
            dsn_host="localhost:5432",
        )
        report.checks.append(mod.CheckResult("test", "ok", "Fine"))
        report.overall_status = "ok"

        d = report.to_dict()
        assert d["overall_status"] == "ok"
        assert len(d["checks"]) == 1
        assert d["checks"][0]["name"] == "test"

    def test_format_text_report(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "health_check",
            "scripts/health_check.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        report = mod.HealthReport(
            timestamp="2026-02-16T00:00:00Z",
            dsn_host="db.example.com",
        )
        report.checks.append(mod.CheckResult("vacuum", "warning", "5 tables need vacuum"))
        report.checks.append(mod.CheckResult("locks", "ok", "No lock contention"))
        report.overall_status = "warning"

        text = mod.format_text_report(report)
        assert "QuerySense Health Check" in text
        assert "db.example.com" in text
        assert "[WARN]" in text
        assert "[OK]" in text
        assert "WARNING" in text

    def test_all_checks_registered(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "health_check",
            "scripts/health_check.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        expected = {"queries", "replication", "connections", "vacuum", "locks", "cache", "disk"}
        assert set(mod.ALL_CHECKS.keys()) == expected

    def test_safe_dsn_host(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "health_check",
            "scripts/health_check.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert mod._safe_dsn_host("postgresql://user:secret@db.example.com:5432/mydb") == "db.example.com:5432"
        assert mod._safe_dsn_host("postgresql://localhost/mydb") == "localhost"
