"""
Tests for querysense.benchmark -- covering SAOPAnalyzer, DoubleBufferProbe,
and BenchmarkResult without requiring a live database connection.
"""

from __future__ import annotations

import pytest
from querysense.benchmark import (
    BenchmarkResult,
    BufferStats,
    CacheMode,
    DoubleBufferProbe,
    SAOPAnalyzer,
    SAOPFinding,
)


# ---------------------------------------------------------------------------
# Fixtures -- realistic EXPLAIN (FORMAT JSON) plan snippets
# ---------------------------------------------------------------------------

PLAN_BITMAP_SAOP_PG16 = [
    {
        "Plan": {
            "Node Type": "Bitmap Heap Scan",
            "Relation Name": "test",
            "Alias": "test",
            "Actual Rows": 7,
            "Actual Loops": 1,
            "Recheck Cond": "(id = ANY ('{1,2,3,4,5,6,7}'::integer[]))",
            "Shared Hit Blocks": 15,
            "Shared Read Blocks": 0,
            "Plans": [
                {
                    "Node Type": "Bitmap Index Scan",
                    "Index Name": "test_pkey",
                    "Actual Rows": 7,
                    "Actual Loops": 1,
                    "Index Cond": "(id = ANY ('{1,2,3,4,5,6,7}'::integer[]))",
                    "Shared Hit Blocks": 14,
                    "Shared Read Blocks": 0,
                }
            ],
        },
        "Planning Time": 0.355,
        "Execution Time": 0.110,
    }
]

PLAN_MULTI_COL_SAOP = [
    {
        "Plan": {
            "Node Type": "Index Scan",
            "Index Name": "docs_sent_at_idx_1",
            "Relation Name": "docs",
            "Actual Rows": 20,
            "Actual Loops": 1,
            "Index Cond": (
                "((docs.sender_reference)::text = ANY ('{Custom/1175,Client/362,Custom/280}'::text[]))"
                " AND ((docs.status)::text = ANY ('{draft,sent}'::text[]))"
            ),
            "Shared Hit Blocks": 281,
            "Shared Read Blocks": 0,
        },
        "Planning Time": 0.282,
        "Execution Time": 62.099,
    }
]

PLAN_FILTER_NOT_INDEX_COND = [
    {
        "Plan": {
            "Node Type": "Index Scan",
            "Index Name": "docs_sent_at_idx_1",
            "Relation Name": "docs",
            "Actual Rows": 20,
            "Actual Loops": 1,
            "Filter": (
                "((docs.status)::text = ANY ('{draft,sent}'::text[]))"
                " AND ((docs.sender_reference)::text = ANY "
                "('{Custom/1175,Client/362,Custom/280}'::text[]))"
            ),
            "Rows Removed by Filter": 52032,
            "Shared Hit Blocks": 1502,
            "Shared Read Blocks": 50857,
        },
        "Planning Time": 0.528,
        "Execution Time": 270.518,
    }
]

PLAN_CLEAN = [
    {
        "Plan": {
            "Node Type": "Index Scan",
            "Index Name": "orders_pkey",
            "Relation Name": "orders",
            "Actual Rows": 1,
            "Actual Loops": 1,
            "Index Cond": "(id = 42)",
            "Shared Hit Blocks": 3,
            "Shared Read Blocks": 0,
        },
        "Planning Time": 0.040,
        "Execution Time": 0.020,
    }
]


# ---------------------------------------------------------------------------
# SAOPAnalyzer tests
# ---------------------------------------------------------------------------

class TestSAOPAnalyzer:
    def setup_method(self):
        self.analyzer = SAOPAnalyzer()

    def test_detects_simple_in_list_in_index_cond(self):
        findings = self.analyzer.analyze(PLAN_BITMAP_SAOP_PG16)
        assert len(findings) >= 1
        titles = [f.title for f in findings]
        assert any("IN" in t or "ANY" in t or "SAOP" in t or "list" in t.lower() for t in titles)

    def test_in_list_finding_has_pg17_win_flag(self):
        findings = self.analyzer.analyze(PLAN_BITMAP_SAOP_PG16)
        assert any(f.pg17_win for f in findings)

    def test_multi_col_saop_detected(self):
        findings = self.analyzer.analyze(PLAN_MULTI_COL_SAOP)
        assert len(findings) >= 1
        assert findings[0].score >= 6.0

    def test_multi_col_saop_score_higher_than_single(self):
        single = self.analyzer.analyze(PLAN_BITMAP_SAOP_PG16)
        multi = self.analyzer.analyze(PLAN_MULTI_COL_SAOP)
        single_max = max((f.score for f in single), default=0)
        multi_max = max((f.score for f in multi), default=0)
        assert multi_max >= single_max

    def test_filter_not_index_cond_is_critical(self):
        findings = self.analyzer.analyze(PLAN_FILTER_NOT_INDEX_COND)
        assert len(findings) >= 1
        severe = [f for f in findings if f.severity in ("CRITICAL", "WARNING")]
        assert len(severe) >= 1
        assert any(f.score >= 5.0 for f in severe)

    def test_filter_finding_mentions_rows_removed(self):
        findings = self.analyzer.analyze(PLAN_FILTER_NOT_INDEX_COND)
        filter_findings = [
            f for f in findings
            if "filter" in f.title.lower() or "filter" in f.detail.lower()
        ]
        assert len(filter_findings) >= 1

    def test_clean_plan_no_findings(self):
        findings = self.analyzer.analyze(PLAN_CLEAN)
        assert findings == []

    def test_accepts_raw_dict_input(self):
        inner = PLAN_BITMAP_SAOP_PG16[0]
        findings_from_list = self.analyzer.analyze(PLAN_BITMAP_SAOP_PG16)
        findings_from_dict = self.analyzer.analyze(inner)
        assert len(findings_from_list) == len(findings_from_dict)

    def test_findings_ordered_by_score_descending(self):
        findings = self.analyzer.analyze(PLAN_FILTER_NOT_INDEX_COND)
        scores = [f.score for f in findings]
        assert scores == sorted(scores, reverse=True)

    def test_pg17_candidate_report_no_findings(self):
        report = SAOPAnalyzer.pg17_candidate_report([])
        assert "No" in report or "no" in report

    def test_pg17_candidate_report_with_findings(self):
        findings = self.analyzer.analyze(PLAN_BITMAP_SAOP_PG16)
        report = SAOPAnalyzer.pg17_candidate_report(findings)
        assert "Postgres 17" in report
        assert "finding" in report.lower()

    def test_get_primitive_scan_sql_contains_relation(self):
        sql = SAOPAnalyzer.get_primitive_scan_sql("orders")
        assert "orders" in sql
        assert "idx_scan" in sql
        assert "pg_stat_user_indexes" in sql

    def test_nested_plans_are_walked(self):
        findings = self.analyzer.analyze(PLAN_BITMAP_SAOP_PG16)
        assert len(findings) >= 1

    def test_score_bounded_between_0_and_10(self):
        findings = self.analyzer.analyze(PLAN_FILTER_NOT_INDEX_COND)
        for f in findings:
            assert 0.0 <= f.score <= 10.0


# ---------------------------------------------------------------------------
# DoubleBufferProbe tests
# ---------------------------------------------------------------------------

class TestDoubleBufferProbe:
    def setup_method(self):
        self.probe = DoubleBufferProbe()

    def _make_result(
        self,
        shared_hit: int,
        shared_read: int,
        execution_ms: float,
        cache_mode: CacheMode = CacheMode.WARM,
    ) -> BenchmarkResult:
        return BenchmarkResult(
            sql="SELECT 1",
            cache_mode=cache_mode,
            planning_time_ms=0.05,
            execution_time_ms=execution_ms,
            buffers=BufferStats(shared_hit=shared_hit, shared_read=shared_read),
            rows=1,
        )

    def test_double_buffer_detected_when_reads_fast(self):
        result = self._make_result(
            shared_hit=0,
            shared_read=4480,
            execution_ms=83.9,
            cache_mode=CacheMode.WARM,
        )
        warnings = self.probe.analyze(result)
        assert len(warnings) >= 1
        assert any("double" in w.lower() or "os page cache" in w.lower() for w in warnings)

    def test_no_warning_when_reads_are_slow(self):
        result = self._make_result(
            shared_hit=0,
            shared_read=4480,
            execution_ms=237.0,
            cache_mode=CacheMode.COLD,
        )
        warnings = [
            w for w in self.probe.analyze(result)
            if "double" in w.lower()
        ]
        assert len(warnings) == 0

    def test_no_warning_when_mostly_shared_hit(self):
        result = self._make_result(
            shared_hit=4480,
            shared_read=0,
            execution_ms=79.0,
            cache_mode=CacheMode.HOT,
        )
        warnings = self.probe.analyze(result)
        double_warnings = [w for w in warnings if "double" in w.lower()]
        assert double_warnings == []

    def test_warm_mode_always_adds_informational_warning(self):
        result = self._make_result(
            shared_hit=0,
            shared_read=4480,
            execution_ms=83.9,
            cache_mode=CacheMode.WARM,
        )
        warnings = self.probe.analyze(result)
        warm_notes = [w for w in warnings if "warm" in w.lower() or "os page cache" in w.lower()]
        assert len(warm_notes) >= 1

    def test_zero_blocks_returns_no_warnings(self):
        result = self._make_result(0, 0, 0.001)
        assert self.probe.analyze(result) == []

    def test_os_evict_commands_contain_dd_and_fincore(self):
        cmds = DoubleBufferProbe.os_evict_commands(
            "/var/lib/postgresql/16/main",
            "base/16384/16422",
        )
        assert "dd" in cmds
        assert "fincore" in cmds
        assert "oflag=nocache" in cmds
        assert "base/16384/16422" in cmds

    def test_os_evict_commands_full_path_assembled(self):
        cmds = DoubleBufferProbe.os_evict_commands("/data", "base/123/456")
        assert "/data/base/123/456" in cmds

    def test_get_filepath_sql_contains_relation(self):
        sql = DoubleBufferProbe.get_filepath_sql("orders")
        assert "orders" in sql
        assert "pg_relation_filepath" in sql

    def test_custom_thresholds_respected(self):
        lenient_probe = DoubleBufferProbe(ms_per_mb_disk_floor=0.1)
        result = self._make_result(0, 4480, 83.9, CacheMode.WARM)
        double_warnings = [w for w in lenient_probe.analyze(result) if "double" in w.lower()]
        assert double_warnings == []


# ---------------------------------------------------------------------------
# BenchmarkResult / BufferStats tests
# ---------------------------------------------------------------------------

class TestBufferStats:
    def test_hit_rate_all_hits(self):
        stats = BufferStats(shared_hit=100, shared_read=0)
        assert stats.hit_rate == 1.0

    def test_hit_rate_all_reads(self):
        stats = BufferStats(shared_hit=0, shared_read=100)
        assert stats.hit_rate == 0.0

    def test_hit_rate_mixed(self):
        stats = BufferStats(shared_hit=75, shared_read=25)
        assert stats.hit_rate == 0.75

    def test_hit_rate_zero_blocks(self):
        stats = BufferStats(shared_hit=0, shared_read=0)
        assert stats.hit_rate == 0.0

    def test_total_blocks(self):
        stats = BufferStats(shared_hit=30, shared_read=70)
        assert stats.total_blocks == 100


class TestBenchmarkResult:
    def test_str_contains_key_metrics(self):
        result = BenchmarkResult(
            sql="SELECT 1",
            cache_mode=CacheMode.HOT,
            planning_time_ms=0.5,
            execution_time_ms=79.1,
            buffers=BufferStats(shared_hit=4480, shared_read=0),
            rows=1000000,
        )
        text = str(result)
        assert "79" in text
        assert "4,480" in text
        assert "100.0%" in text

    def test_str_shows_warnings(self):
        result = BenchmarkResult(
            sql="SELECT 1",
            cache_mode=CacheMode.WARM,
            planning_time_ms=0.1,
            execution_time_ms=83.9,
            buffers=BufferStats(shared_hit=0, shared_read=4480),
            rows=100,
            warnings=["Double-buffering suspected"],
        )
        text = str(result)
        assert "Double-buffering suspected" in text


# ---------------------------------------------------------------------------
# CacheMode tests
# ---------------------------------------------------------------------------

class TestCacheMode:
    def test_values(self):
        assert CacheMode("hot") == CacheMode.HOT
        assert CacheMode("warm") == CacheMode.WARM
        assert CacheMode("cold") == CacheMode.COLD

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            CacheMode("unknown")


# ---------------------------------------------------------------------------
# Integration: full SAOP + DoubleBuffer pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_notion_style_query_detected(self):
        analyzer = SAOPAnalyzer()
        findings = analyzer.analyze(PLAN_FILTER_NOT_INDEX_COND)

        assert len(findings) >= 1
        assert findings[0].score >= 5.0
        assert findings[0].pg17_win

        report = SAOPAnalyzer.pg17_candidate_report(findings)
        assert "Postgres 17" in report

    def test_notion_style_warm_cache_double_buffer(self):
        probe = DoubleBufferProbe()
        result = BenchmarkResult(
            sql="SELECT * FROM docs WHERE status IN ('draft','sent') AND ...",
            cache_mode=CacheMode.WARM,
            planning_time_ms=0.5,
            execution_time_ms=83.9,
            buffers=BufferStats(shared_hit=0, shared_read=4480),
            rows=20,
        )
        warnings = probe.analyze(result)
        assert any("os page cache" in w.lower() or "double" in w.lower() for w in warnings)
