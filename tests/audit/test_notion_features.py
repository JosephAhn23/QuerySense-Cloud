"""
Tests for the Notion-inspired features:
    - GINIndexAdvisor (GIN/JSONB operator class detection)
    - QueryLoadProfiler (pg_stat_statements workload attribution)
    - IndexBloatCalculator (per-index bloat and write overhead)
"""

from __future__ import annotations

import asyncio
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
# GIN Index Advisor Tests
# ---------------------------------------------------------------------------

from querysense.audit.gin_advisor import GINIndexAdvisor, GINIndex, GINReport


class TestGINIndex:
    def test_has_jsonb_columns(self):
        idx = GINIndex(column_types=["jsonb"])
        assert idx.has_jsonb_columns

    def test_no_jsonb_columns(self):
        idx = GINIndex(column_types=["integer", "text"])
        assert not idx.has_jsonb_columns

    def test_uses_default_jsonb_ops(self):
        idx = GINIndex(column_types=["jsonb"], operator_class="default")
        assert idx.uses_default_jsonb_ops

    def test_uses_path_ops(self):
        idx = GINIndex(column_types=["jsonb"], operator_class="jsonb_path_ops")
        assert not idx.uses_default_jsonb_ops

    def test_is_unused(self):
        idx = GINIndex(idx_scan=0)
        assert idx.is_unused
        idx2 = GINIndex(idx_scan=100)
        assert not idx2.is_unused

    def test_to_dict(self):
        idx = GINIndex(schema="public", table="orders", index_name="idx_data")
        d = idx.to_dict()
        assert d["schema"] == "public"
        assert "is_unused" in d


class TestGINIndexAdvisor:
    def test_extract_columns(self):
        cols = GINIndexAdvisor._extract_columns(
            "CREATE INDEX idx ON public.orders USING gin (data jsonb_path_ops)"
        )
        assert cols == ["data"]

    def test_extract_columns_multi(self):
        cols = GINIndexAdvisor._extract_columns(
            "CREATE INDEX idx ON t USING gin (a, b)"
        )
        assert cols == ["a", "b"]

    def test_extract_opclass_path_ops(self):
        assert GINIndexAdvisor._extract_opclass(
            "CREATE INDEX idx ON t USING gin (data jsonb_path_ops)"
        ) == "jsonb_path_ops"

    def test_extract_opclass_default(self):
        assert GINIndexAdvisor._extract_opclass(
            "CREATE INDEX idx ON t USING gin (data)"
        ) == "default"

    def test_extract_opclass_trgm(self):
        assert GINIndexAdvisor._extract_opclass(
            "CREATE INDEX idx ON t USING gin (name gin_trgm_ops)"
        ) == "gin_trgm_ops"

    def test_notion_scenario(self):
        """Reproduce the Notion scenario: default jsonb_ops on containment query."""
        conn = MockConn(
            fetch_results={
                "pg_am": [
                    # schema, table, index_name, indexdef, size, scans, tup_read, tup_fetch, valid, amname
                    ("public", "blocks", "idx_blocks_permissions", 
                     "CREATE INDEX idx_blocks_permissions ON public.blocks USING gin (permissions)",
                     500_000_000, 50000, 100000, 80000, True, "gin"),
                ],
            },
            fetchval_results={
                "information_schema": "jsonb",  # column type
            },
        )
        advisor = GINIndexAdvisor()
        report = asyncio.run(advisor.analyze(conn))

        assert report.total_gin_indexes == 1
        idx = report.indexes[0]
        assert idx.index_name == "idx_blocks_permissions"
        assert idx.has_jsonb_columns
        assert idx.uses_default_jsonb_ops

        # Should recommend switching to jsonb_path_ops
        assert report.suboptimal_opclass_count == 1
        assert len(report.findings) >= 1
        assert any("jsonb_path_ops" in f.fix_sql for f in report.findings)

    def test_healthy_gin_index(self):
        """GIN index already using jsonb_path_ops — no findings."""
        conn = MockConn(
            fetch_results={
                "pg_am": [
                    ("public", "docs", "idx_docs_data",
                     "CREATE INDEX idx_docs_data ON public.docs USING gin (data jsonb_path_ops)",
                     100_000_000, 10000, 50000, 40000, True, "gin"),
                ],
            },
            fetchval_results={
                "information_schema": "jsonb",
            },
        )
        advisor = GINIndexAdvisor()
        report = asyncio.run(advisor.analyze(conn))

        assert report.suboptimal_opclass_count == 0

    def test_unused_gin_detection(self):
        """Unused GIN index should be flagged."""
        conn = MockConn(
            fetch_results={
                "pg_am": [
                    ("public", "logs", "idx_logs_tags",
                     "CREATE INDEX idx_logs_tags ON public.logs USING gin (tags)",
                     50_000_000, 0, 0, 0, True, "gin"),
                ],
            },
            fetchval_results={
                "information_schema": "text[]",
            },
        )
        advisor = GINIndexAdvisor()
        report = asyncio.run(advisor.analyze(conn))

        assert report.unused_count == 1
        assert any("unused" in f.title.lower() for f in report.findings)

    def test_report_to_dict(self):
        report = GINReport(total_gin_indexes=5, total_gin_size_mb=500)
        d = report.to_dict()
        assert d["total_gin_indexes"] == 5


# ---------------------------------------------------------------------------
# Query Load Profiler Tests
# ---------------------------------------------------------------------------

from querysense.audit.query_load import (
    QueryLoadProfiler,
    QueryProfile,
    TableLoadProfile,
    QueryLoadReport,
)


class TestQueryProfile:
    def test_cache_hit_ratio_perfect(self):
        q = QueryProfile(shared_blks_hit=1000, shared_blks_read=0)
        assert q.cache_hit_ratio == 1.0

    def test_cache_hit_ratio_half(self):
        q = QueryProfile(shared_blks_hit=500, shared_blks_read=500)
        assert q.cache_hit_ratio == 0.5

    def test_is_spilling(self):
        assert QueryProfile(temp_blks_written=100).is_spilling
        assert not QueryProfile(temp_blks_written=0).is_spilling

    def test_time_variance(self):
        q = QueryProfile(mean_time_ms=100, stddev_time_ms=500)
        assert q.time_variance == 5.0

    def test_to_dict(self):
        q = QueryProfile(queryid=123, query="SELECT 1", calls=10)
        d = q.to_dict()
        assert d["calls"] == 10


class TestQueryLoadProfiler:
    def test_extract_table_from(self):
        assert QueryLoadProfiler._extract_table("SELECT * FROM orders WHERE id = $1") == "orders"

    def test_extract_table_join(self):
        t = QueryLoadProfiler._extract_table("SELECT * FROM users JOIN orders ON ...")
        assert t == "users"

    def test_extract_table_update(self):
        assert QueryLoadProfiler._extract_table("UPDATE orders SET status = $1") == "orders"

    def test_workload_attribution(self):
        """Test that queries are properly attributed to tables."""
        conn = MockConn(
            fetchval_results={
                "stats_reset": "2024-01-01",
            },
            fetch_results={
                "pg_stat_statements": [
                    # queryid, query, calls, total_time, mean, min, max, stddev,
                    # rows, hit, read, temp_write, blk_read_time, blk_write_time
                    (1, "SELECT * FROM orders WHERE id = $1", 10000,
                     50000, 5.0, 0.1, 100, 10, 10000, 50000, 1000, 0, 100, 0),
                    (2, "UPDATE orders SET status = $1 WHERE id = $2", 5000,
                     30000, 6.0, 0.5, 200, 20, 5000, 20000, 5000, 0, 500, 0),
                    (3, "SELECT * FROM users WHERE email = $1", 2000,
                     10000, 5.0, 0.1, 50, 5, 2000, 10000, 500, 0, 50, 0),
                    (4, "INSERT INTO audit_log VALUES ($1)", 1000,
                     2000, 2.0, 0.5, 10, 1, 1000, 5000, 100, 0, 10, 0),
                ],
            },
        )

        profiler = QueryLoadProfiler()
        report = asyncio.run(profiler.analyze(conn))

        assert report.total_queries == 4
        assert report.total_calls == 18000
        assert report.total_time_ms == pytest.approx(92000)

        # Top query should be orders SELECT (50000ms)
        assert report.top_by_time[0].query.startswith("SELECT * FROM orders")
        assert report.top_by_time[0].pct_total_time > 50

        # Table attribution
        orders_load = next((t for t in report.table_load if t.table == "orders"), None)
        assert orders_load is not None
        assert orders_load.pct_total_time > 80  # orders dominates

    def test_no_pg_stat_statements(self):
        conn = MockConn()  # Empty results -> no extension
        profiler = QueryLoadProfiler()
        report = asyncio.run(profiler.analyze(conn))
        assert report.total_queries == 0
        assert any("pg_stat_statements" in f.title for f in report.findings)

    def test_dominant_query_finding(self):
        """Single query using >30% of time should trigger finding."""
        conn = MockConn(
            fetchval_results={"stats_reset": "2024-01-01"},
            fetch_results={
                "pg_stat_statements": [
                    (1, "SELECT * FROM huge_table", 100, 90000, 900, 100, 5000, 500,
                     10000, 50000, 10000, 0, 1000, 0),
                    (2, "SELECT 1", 10000, 10000, 1.0, 0.1, 5, 0.5,
                     10000, 50000, 0, 0, 0, 0),
                ],
            },
        )

        profiler = QueryLoadProfiler()
        report = asyncio.run(profiler.analyze(conn))

        warnings = [f for f in report.findings if "dominates" in f.title.lower()]
        assert len(warnings) >= 1

    def test_spilling_queries_finding(self):
        conn = MockConn(
            fetchval_results={"stats_reset": "2024-01-01"},
            fetch_results={
                "pg_stat_statements": [
                    (1, "SELECT * FROM big ORDER BY col", 100, 50000, 500, 100, 2000, 200,
                     10000, 50000, 10000, 5000, 1000, 500),  # temp_blks_written=5000
                ],
            },
        )

        profiler = QueryLoadProfiler()
        report = asyncio.run(profiler.analyze(conn))

        spill = [f for f in report.findings if "spilling" in f.title.lower()]
        assert len(spill) >= 1

    def test_report_to_dict(self):
        report = QueryLoadReport(total_queries=10, total_calls=1000)
        d = report.to_dict()
        assert d["total_queries"] == 10


# ---------------------------------------------------------------------------
# Index Bloat Calculator Tests
# ---------------------------------------------------------------------------

from querysense.audit.index_bloat import (
    IndexBloatCalculator,
    IndexBloatEntry,
    IndexBloatReport,
)


class TestIndexBloatEntry:
    def test_is_unused(self):
        assert IndexBloatEntry(idx_scan=0).is_unused
        assert not IndexBloatEntry(idx_scan=100).is_unused

    def test_write_operations(self):
        e = IndexBloatEntry(
            table_inserts=1000,
            table_updates=500,
            table_hot_updates=200,
        )
        # writes = inserts + (updates - hot_updates) = 1000 + 300 = 1300
        assert e.write_operations == 1300

    def test_writes_per_hour(self):
        e = IndexBloatEntry(
            table_inserts=3600,
            table_updates=0,
            table_hot_updates=0,
            stats_age_seconds=3600,
        )
        assert e.writes_per_hour == pytest.approx(3600.0)

    def test_cost_score(self):
        expensive = IndexBloatEntry(
            idx_scan=0,
            index_size_bytes=100 * 1024 * 1024,  # 100MB
            table_inserts=100000,
        )
        cheap = IndexBloatEntry(
            idx_scan=10000,
            index_size_bytes=1 * 1024 * 1024,  # 1MB
            table_inserts=100,
        )
        assert expensive.cost_score > cheap.cost_score

    def test_to_dict(self):
        e = IndexBloatEntry(schema="public", table="orders", index_name="idx_status")
        d = e.to_dict()
        assert d["index_name"] == "idx_status"
        assert "cost_score" in d


class TestIndexBloatCalculator:
    def test_analyze_with_unused_indexes(self):
        conn = MockConn(
            fetchval_results={
                "stats_reset": 86400.0,  # 24 hours
            },
            fetch_results={
                "pg_am am": [
                    # schema, table, index, size, scans, tup_read, tup_fetch,
                    # unique, primary, amname, indexdef, inserts, updates, hot_updates
                    ("public", "orders", "idx_orders_old", 50_000_000,
                     0, 0, 0, False, False, "btree",
                     "CREATE INDEX idx_orders_old ON orders (old_col)",
                     100000, 50000, 40000),
                    ("public", "orders", "orders_pkey", 10_000_000,
                     50000, 100000, 80000, True, True, "btree",
                     "CREATE UNIQUE INDEX orders_pkey ON orders (id)",
                     100000, 50000, 40000),
                ],
                "pg_relation_size(ci.oid) > 0": [
                    ("idx_orders_old", 50_000_000, 100000, 24),
                    ("orders_pkey", 10_000_000, 100000, 8),
                ],
            },
        )

        calc = IndexBloatCalculator()
        report = asyncio.run(calc.analyze(conn))

        assert report.total_indexes == 2
        assert report.unused_count == 1  # idx_orders_old is unused, not PK
        assert report.unused_size_mb > 0

        # Should have finding for unused index
        unused = [f for f in report.findings if "unused" in f.title.lower()]
        assert len(unused) >= 1

    def test_no_findings_for_used_indexes(self):
        conn = MockConn(
            fetchval_results={"stats_reset": 86400.0},
            fetch_results={
                "pg_am am": [
                    ("public", "users", "idx_users_email", 5_000_000,
                     10000, 50000, 40000, False, False, "btree",
                     "CREATE INDEX idx_users_email ON users (email)",
                     1000, 500, 400),
                ],
                "pg_relation_size(ci.oid) > 0": [
                    ("idx_users_email", 5_000_000, 10000, 24),
                ],
            },
        )

        calc = IndexBloatCalculator()
        report = asyncio.run(calc.analyze(conn))

        assert report.unused_count == 0

    def test_report_to_dict(self):
        report = IndexBloatReport(
            total_indexes=10,
            total_index_size_mb=500,
            unused_count=2,
            unused_size_mb=50,
        )
        d = report.to_dict()
        assert d["total_indexes"] == 10
        assert d["unused_count"] == 2

    def test_report_summary(self):
        report = IndexBloatReport(
            total_indexes=10,
            total_index_size_mb=500,
            total_bloat_mb=50,
            unused_count=2,
            unused_size_mb=100,
        )
        s = report.summary
        assert "10 indexes" in s
        assert "500MB" in s
