"""
Tests for pganalyze-parity features inspired by the Atlassian case study.

Covers:
1. CPU vs I/O Query Classifier (analyzer rule)
2. RDS/CloudWatch Metrics data models and health logic
3. pg_stat_statements Time-Series Snapshotter (local SQLite)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from querysense.parser import parse_explain
from querysense.analyzer import Analyzer, AnalysisResult


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _make_plan_node(
    node_type: str = "Seq Scan",
    relation: str = "test_table",
    rows: int = 1000,
    cost: float = 100.0,
    actual_time: float = 10.0,
    children: list[dict[str, Any]] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    node: dict[str, Any] = {
        "Node Type": node_type,
        "Relation Name": relation,
        "Schema": "public",
        "Alias": relation,
        "Startup Cost": 0.0,
        "Total Cost": cost,
        "Plan Rows": rows,
        "Plan Width": 64,
        "Actual Startup Time": 0.01,
        "Actual Total Time": actual_time,
        "Actual Rows": rows,
        "Actual Loops": 1,
        "Shared Hit Blocks": max(1, rows // 100),
        "Shared Read Blocks": max(1, rows // 50),
    }
    node.update(extra)
    if children:
        node["Plans"] = children
    return node


def _wrap_plan(plan_node: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"Plan": plan_node, "Planning Time": 0.1, "Execution Time": 100.0}]


# =============================================================================
# SECTION 1: CPU vs I/O Classifier Tests
# =============================================================================


class TestCPUIoClassifier:
    """Test the CPU vs I/O query classification rule."""

    def test_io_bound_plan(self) -> None:
        """Plan with many disk reads and I/O time should be classified I/O-bound."""
        plan = _make_plan_node(
            "Seq Scan", "large_table",
            rows=500_000, cost=50_000.0, actual_time=2000.0,
            **{
                "Shared Hit Blocks": 100,
                "Shared Read Blocks": 50_000,
                "I/O Read Time": 1500.0,
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        classifier_findings = [
            f for f in result.findings if f.rule_id == "CPU_IO_CLASSIFIER"
        ]
        assert len(classifier_findings) == 1

        finding = classifier_findings[0]
        assert "I/O-bound" in finding.title
        assert finding.metrics["io_pct"] > 60
        assert "I/O-bound" in finding.description

    def test_cpu_bound_plan(self) -> None:
        """Plan with high cache hit ratio and no I/O time → CPU-bound."""
        plan = _make_plan_node(
            "Sort", "sorted_table",
            rows=100_000, cost=5000.0, actual_time=500.0,
            **{
                "Shared Hit Blocks": 10_000,
                "Shared Read Blocks": 0,
                "Sort Key": ["id"],
                "Sort Method": "quicksort",
                "Sort Space Used": 50000,
                "Sort Space Type": "Memory",
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        classifier_findings = [
            f for f in result.findings if f.rule_id == "CPU_IO_CLASSIFIER"
        ]
        assert len(classifier_findings) == 1

        finding = classifier_findings[0]
        assert "CPU-bound" in finding.title
        assert finding.metrics["cpu_pct"] > 75
        assert "CPU-bound" in finding.description

    def test_balanced_plan(self) -> None:
        """Plan with moderate I/O and CPU → Balanced."""
        plan = _make_plan_node(
            "Hash Join", "joined",
            rows=50_000, cost=10_000.0, actual_time=800.0,
            **{
                "Shared Hit Blocks": 5_000,
                "Shared Read Blocks": 3_000,
                "I/O Read Time": 300.0,
            },
            children=[
                _make_plan_node(
                    "Seq Scan", "left_table",
                    rows=25_000, cost=5000.0, actual_time=400.0,
                    **{"Shared Hit Blocks": 2500, "Shared Read Blocks": 1500},
                ),
                _make_plan_node(
                    "Hash", "right_table",
                    rows=25_000, cost=5000.0, actual_time=400.0,
                    **{"Shared Hit Blocks": 2500, "Shared Read Blocks": 1500},
                ),
            ],
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        classifier_findings = [
            f for f in result.findings if f.rule_id == "CPU_IO_CLASSIFIER"
        ]
        assert len(classifier_findings) == 1
        assert "metrics" in classifier_findings[0].model_dump()

    def test_skips_fast_queries(self) -> None:
        """Queries under 5ms should not be classified (too little data)."""
        plan = _make_plan_node(
            "Index Scan", "fast_table",
            rows=1, cost=0.5, actual_time=0.01,
            **{
                "Index Name": "idx_id",
                "Shared Hit Blocks": 3,
                "Shared Read Blocks": 0,
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        classifier_findings = [
            f for f in result.findings if f.rule_id == "CPU_IO_CLASSIFIER"
        ]
        assert len(classifier_findings) == 0

    def test_no_io_timing_falls_back_to_estimation(self) -> None:
        """Without track_io_timing, should estimate from block counts."""
        plan = _make_plan_node(
            "Seq Scan", "no_timing",
            rows=100_000, cost=15000.0, actual_time=200.0,
            **{
                "Shared Hit Blocks": 500,
                "Shared Read Blocks": 10_000,
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        classifier_findings = [
            f for f in result.findings if f.rule_id == "CPU_IO_CLASSIFIER"
        ]
        assert len(classifier_findings) == 1
        assert classifier_findings[0].metrics["io_timing_available"] == 0

    def test_all_fixtures_get_classified(self) -> None:
        """Every fixture with sufficient execution time gets a classification."""
        fixture_files = list(FIXTURES_DIR.glob("*.json"))
        assert len(fixture_files) > 0

        for fixture_file in fixture_files:
            data = json.loads(fixture_file.read_text())
            output = parse_explain(data)
            analyzer = Analyzer()
            result = analyzer.analyze(output)
            assert isinstance(result, AnalysisResult)

    def test_classification_determinism(self) -> None:
        """Same input should produce same classification every time."""
        plan = _make_plan_node(
            "Seq Scan", "deterministic",
            rows=200_000, cost=30_000.0, actual_time=1500.0,
            **{
                "Shared Hit Blocks": 1000,
                "Shared Read Blocks": 20_000,
                "I/O Read Time": 1000.0,
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        results = []
        for _ in range(10):
            analyzer = Analyzer()
            result = analyzer.analyze(output)
            cf = [f for f in result.findings if f.rule_id == "CPU_IO_CLASSIFIER"]
            results.append(cf[0].title if cf else None)

        assert len(set(results)) == 1, f"Non-deterministic: {results}"

    def test_metrics_contain_required_fields(self) -> None:
        """Classifier findings must have all expected metric fields."""
        plan = _make_plan_node(
            "Seq Scan", "metrics_check",
            rows=50_000, cost=10_000.0, actual_time=500.0,
            **{
                "Shared Hit Blocks": 2000,
                "Shared Read Blocks": 5000,
                "I/O Read Time": 200.0,
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        cf = [f for f in result.findings if f.rule_id == "CPU_IO_CLASSIFIER"]
        assert len(cf) == 1

        metrics = cf[0].metrics
        required_keys = {
            "cpu_pct", "io_pct", "total_time_ms",
            "io_time_ms", "cpu_time_ms", "shared_hit_blocks",
            "shared_read_blocks", "cache_hit_ratio", "io_timing_available",
        }
        assert required_keys.issubset(set(metrics.keys()))


# =============================================================================
# SECTION 2: RDS/CloudWatch Data Model Tests
# =============================================================================


class TestRDSMetricSnapshot:
    """Test RDS metric data models without actual AWS calls."""

    def test_snapshot_health_healthy(self) -> None:
        from querysense.db.rds_cloudwatch import RDSMetricSnapshot
        snap = RDSMetricSnapshot(
            instance_id="test-db",
            cpu_utilization_pct=30.0,
            freeable_memory_bytes=4 * 1024**3,
            database_connections=50,
            free_storage_bytes=100 * 1024**3,
            read_latency_ms=2.0,
        )
        assert snap.health_status == "healthy"
        assert snap.freeable_memory_gb == 4.0
        assert snap.free_storage_gb == 100.0

    def test_snapshot_health_warning(self) -> None:
        from querysense.db.rds_cloudwatch import RDSMetricSnapshot
        snap = RDSMetricSnapshot(
            instance_id="stressed-db",
            cpu_utilization_pct=85.0,
            freeable_memory_bytes=2 * 1024**3,
            database_connections=100,
            free_storage_bytes=50 * 1024**3,
        )
        assert snap.health_status == "warning"

    def test_snapshot_health_critical_memory(self) -> None:
        from querysense.db.rds_cloudwatch import RDSMetricSnapshot
        snap = RDSMetricSnapshot(
            instance_id="dying-db",
            cpu_utilization_pct=95.0,
            freeable_memory_bytes=int(0.3 * 1024**3),
            database_connections=400,
            free_storage_bytes=2 * 1024**3,
        )
        assert snap.health_status == "warning"

    def test_aurora_specific_fields(self) -> None:
        from querysense.db.rds_cloudwatch import RDSMetricSnapshot
        snap = RDSMetricSnapshot(
            instance_id="aurora-cluster",
            is_aurora=True,
            cpu_utilization_pct=50.0,
            freeable_memory_bytes=8 * 1024**3,
            buffer_cache_hit_ratio=99.5,
            commit_latency_ms=3.5,
            replica_lag_ms=12.0,
            deadlocks=0,
            free_storage_bytes=500 * 1024**3,
        )
        assert snap.health_status == "healthy"
        d = snap.to_dict()
        assert d["aurora_buffer_cache_hit_ratio"] == 99.5
        assert d["aurora_commit_latency_ms"] == 3.5

    def test_snapshot_format_text(self) -> None:
        from querysense.db.rds_cloudwatch import RDSMetricSnapshot
        snap = RDSMetricSnapshot(
            instance_id="format-test",
            cpu_utilization_pct=45.0,
            freeable_memory_bytes=4 * 1024**3,
            read_iops=500.0,
            write_iops=200.0,
            database_connections=75,
            free_storage_bytes=200 * 1024**3,
        )
        text = snap.format_text()
        assert "format-test" in text
        assert "CPU Utilization" in text
        assert "45.0%" in text

    def test_snapshot_to_dict_roundtrip(self) -> None:
        from querysense.db.rds_cloudwatch import RDSMetricSnapshot
        snap = RDSMetricSnapshot(
            instance_id="roundtrip",
            cpu_utilization_pct=55.0,
            freeable_memory_bytes=2 * 1024**3,
            free_storage_bytes=50 * 1024**3,
        )
        d = snap.to_dict()
        serialized = json.dumps(d)
        parsed = json.loads(serialized)
        assert parsed["instance_id"] == "roundtrip"
        assert parsed["cpu_utilization_pct"] == 55.0

    def test_total_iops(self) -> None:
        from querysense.db.rds_cloudwatch import RDSMetricSnapshot
        snap = RDSMetricSnapshot(
            instance_id="iops-test",
            read_iops=300.0,
            write_iops=150.0,
            freeable_memory_bytes=4 * 1024**3,
            free_storage_bytes=50 * 1024**3,
        )
        assert snap.total_iops == 450.0

    def test_metric_data_point(self) -> None:
        from querysense.db.rds_cloudwatch import MetricDataPoint
        from datetime import datetime, timezone
        dp = MetricDataPoint(
            timestamp=datetime(2026, 2, 18, 12, 0, 0, tzinfo=timezone.utc),
            value=75.5,
            unit="%",
        )
        d = dp.to_dict()
        assert d["value"] == 75.5
        assert d["unit"] == "%"

    def test_history_averages(self) -> None:
        from querysense.db.rds_cloudwatch import RDSMetricHistory, MetricDataPoint
        from datetime import datetime, timezone
        history = RDSMetricHistory(
            instance_id="avg-test",
            cpu_utilization=[
                MetricDataPoint(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), value=40.0),
                MetricDataPoint(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), value=60.0),
                MetricDataPoint(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), value=80.0),
            ],
            database_connections=[
                MetricDataPoint(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), value=100.0),
                MetricDataPoint(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), value=200.0),
            ],
        )
        assert history.avg_cpu == 60.0
        assert history.max_cpu == 80.0
        assert history.avg_connections == 150.0

    def test_config_defaults(self) -> None:
        from querysense.db.rds_cloudwatch import RDSConfig
        config = RDSConfig(instance_id="test")
        assert config.region == "us-east-1"
        assert config.is_aurora is False
        assert config.period_seconds == 60


# =============================================================================
# SECTION 3: pg_stat_statements Time-Series Snapshotter Tests
# =============================================================================


class TestPGSSTimeSeriesStore:
    """Test the time-series snapshotter with a real SQLite database."""

    def _make_store(self, tmp_path: Path):
        from querysense.temporal.pgss_timeseries import (
            PGSSTimeSeriesStore,
            PGSSTimeSeriesConfig,
        )
        config = PGSSTimeSeriesConfig(
            db_path=str(tmp_path / "test_pgss.db"),
            retention_days=7,
        )
        store = PGSSTimeSeriesStore(config)
        store.init()
        return store

    def _make_queries(
        self,
        fingerprints: list[str],
        base_calls: int = 100,
        base_time: float = 1000.0,
    ) -> list[dict[str, Any]]:
        queries = []
        for i, fp in enumerate(fingerprints):
            queries.append({
                "queryid": i + 1,
                "query": f"SELECT * FROM table_{i} WHERE id = $1",
                "fingerprint": fp,
                "calls": base_calls * (i + 1),
                "total_exec_time_ms": base_time * (i + 1),
                "mean_exec_time_ms": base_time * (i + 1) / (base_calls * (i + 1)),
                "min_exec_time_ms": 0.5,
                "max_exec_time_ms": 50.0,
                "stddev_exec_time_ms": 5.0,
                "rows": base_calls * 10 * (i + 1),
                "shared_blks_hit": 5000 * (i + 1),
                "shared_blks_read": 500 * (i + 1),
                "temp_blks_written": 0,
                "blk_read_time_ms": 10.0 * (i + 1),
                "blk_write_time_ms": 1.0 * (i + 1),
            })
        return queries

    def test_init_creates_tables(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        assert store.get_snapshot_count() == 0
        assert store.get_unique_queries() == 0
        store.close()

    def test_first_snapshot_records_no_deltas(self, tmp_path: Path) -> None:
        """First snapshot has no previous data, so no deltas are computed."""
        store = self._make_store(tmp_path)
        now = time.time()
        queries = self._make_queries(["fp_a", "fp_b"])
        written = store.record_snapshot(queries, timestamp=now)
        assert written == 0
        assert store.get_snapshot_count() == 1
        store.close()

    def test_second_snapshot_computes_deltas(self, tmp_path: Path) -> None:
        """With two snapshots, deltas are computed for the second."""
        store = self._make_store(tmp_path)
        now = time.time()

        queries_t1 = self._make_queries(["fp_a", "fp_b"], base_calls=100, base_time=1000.0)
        store.record_snapshot(queries_t1, timestamp=now - 60)

        queries_t2 = self._make_queries(["fp_a", "fp_b"], base_calls=200, base_time=2000.0)
        written = store.record_snapshot(queries_t2, timestamp=now)

        assert written == 2
        assert store.get_unique_queries() == 2
        store.close()

    def test_get_query_timeseries(self, tmp_path: Path) -> None:
        """Retrieve time-series for a specific query fingerprint."""
        store = self._make_store(tmp_path)
        now = time.time()

        for i in range(5):
            queries = self._make_queries(
                ["fp_x"], base_calls=100 * (i + 1), base_time=1000.0 * (i + 1)
            )
            store.record_snapshot(queries, timestamp=now - 3600 + (i * 60))

        series = store.get_query_timeseries("fp_x", hours=2)
        assert len(series) == 4
        for point in series:
            assert point.fingerprint == "fp_x"
            assert point.calls > 0
            assert point.calls_per_sec >= 0
        store.close()

    def test_top_queries_by_total_time(self, tmp_path: Path) -> None:
        """Top queries should be ranked by total execution time."""
        store = self._make_store(tmp_path)
        now = time.time()

        def _q(fp: str, calls: int, total_ms: float) -> dict[str, Any]:
            return {
                "queryid": hash(fp) % 10000,
                "query": f"SELECT * FROM {fp}",
                "fingerprint": fp,
                "calls": calls,
                "total_exec_time_ms": total_ms,
                "mean_exec_time_ms": total_ms / max(calls, 1),
                "rows": calls * 10,
                "shared_blks_hit": 1000,
                "shared_blks_read": 100,
            }

        store.record_snapshot(
            [_q("slow", 100, 100.0), _q("fast", 100, 100.0), _q("medium", 100, 100.0)],
            timestamp=now - 120,
        )
        store.record_snapshot(
            [_q("slow", 200, 50100.0), _q("fast", 200, 600.0), _q("medium", 200, 5100.0)],
            timestamp=now - 60,
        )

        top = store.top_queries_in_window(hours=1, limit=10, sort_by="total_time")
        assert len(top) == 3
        assert top[0].fingerprint == "slow"
        store.close()

    def test_top_queries_by_calls(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        now = time.time()

        def _q(fp: str, calls: int, total_ms: float) -> dict[str, Any]:
            return {
                "queryid": hash(fp) % 10000,
                "query": f"SELECT * FROM {fp}",
                "fingerprint": fp,
                "calls": calls,
                "total_exec_time_ms": total_ms,
                "mean_exec_time_ms": total_ms / max(calls, 1),
                "rows": calls * 10,
                "shared_blks_hit": 1000,
                "shared_blks_read": 100,
            }

        store.record_snapshot(
            [_q("hot", 100, 100.0), _q("cold", 100, 100.0)],
            timestamp=now - 120,
        )
        store.record_snapshot(
            [_q("hot", 10200, 300.0), _q("cold", 200, 10100.0)],
            timestamp=now - 60,
        )

        top = store.top_queries_in_window(hours=1, limit=10, sort_by="calls")
        assert len(top) == 2
        assert top[0].fingerprint == "hot"
        store.close()

    def test_detect_regressions(self, tmp_path: Path) -> None:
        """Latency regression should be detected between baseline and recent."""
        store = self._make_store(tmp_path)
        now = time.time()

        for i in range(20):
            queries = [{
                "queryid": 1,
                "query": "SELECT * FROM users WHERE id = $1",
                "fingerprint": "regressed_query",
                "calls": 100 * (i + 1),
                "total_exec_time_ms": 1000.0 * (i + 1),
                "mean_exec_time_ms": 10.0,
                "rows": 100 * (i + 1),
                "shared_blks_hit": 1000,
                "shared_blks_read": 100,
            }]
            store.record_snapshot(queries, timestamp=now - 86400 + (i * 3600))

        for i in range(5):
            queries = [{
                "queryid": 1,
                "query": "SELECT * FROM users WHERE id = $1",
                "fingerprint": "regressed_query",
                "calls": 2100 + 100 * (i + 1),
                "total_exec_time_ms": 21000.0 + 5000.0 * (i + 1),
                "mean_exec_time_ms": 50.0,
                "rows": 2100 + 100 * (i + 1),
                "shared_blks_hit": 1000,
                "shared_blks_read": 100,
            }]
            store.record_snapshot(queries, timestamp=now - 3600 + (i * 600))

        regressions = store.detect_regressions(threshold_pct=50)
        assert len(regressions) >= 1
        assert regressions[0].fingerprint == "regressed_query"
        assert regressions[0].increase_pct > 50
        store.close()

    def test_no_regression_when_stable(self, tmp_path: Path) -> None:
        """Stable query latency should not produce regressions."""
        store = self._make_store(tmp_path)
        now = time.time()

        for i in range(25):
            queries = [{
                "queryid": 1,
                "query": "SELECT 1",
                "fingerprint": "stable_query",
                "calls": 100 * (i + 1),
                "total_exec_time_ms": 1000.0 * (i + 1),
                "mean_exec_time_ms": 10.0,
                "rows": 100 * (i + 1),
                "shared_blks_hit": 1000,
                "shared_blks_read": 0,
            }]
            store.record_snapshot(queries, timestamp=now - 86400 + (i * 3600))

        regressions = store.detect_regressions(threshold_pct=50)
        assert len(regressions) == 0
        store.close()

    def test_data_point_to_dict(self, tmp_path: Path) -> None:
        from querysense.temporal.pgss_timeseries import PGSSDataPoint
        dp = PGSSDataPoint(
            timestamp=time.time(),
            fingerprint="test_fp",
            calls=50,
            calls_per_sec=0.83,
            total_time_ms=500.0,
            mean_time_ms=10.0,
        )
        d = dp.to_dict()
        assert d["fingerprint"] == "test_fp"
        assert d["calls"] == 50
        assert d["calls_per_sec"] == 0.83

    def test_query_window_summary_to_dict(self) -> None:
        from querysense.temporal.pgss_timeseries import QueryWindowSummary
        s = QueryWindowSummary(
            fingerprint="summary_fp",
            total_time_ms=5000.0,
            total_calls=100,
            avg_mean_time_ms=50.0,
        )
        d = s.to_dict()
        assert d["total_time_ms"] == 5000.0
        assert d["total_calls"] == 100

    def test_regression_to_dict(self) -> None:
        from querysense.temporal.pgss_timeseries import QueryRegression
        r = QueryRegression(
            fingerprint="reg_fp",
            baseline_mean_ms=10.0,
            current_mean_ms=25.0,
            increase_pct=150.0,
        )
        d = r.to_dict()
        assert d["increase_pct"] == 150.0
        assert d["regression_type"] == "latency"

    def test_cleanup_respects_retention(self, tmp_path: Path) -> None:
        """Data older than retention_days should be cleaned up."""
        from querysense.temporal.pgss_timeseries import (
            PGSSTimeSeriesStore,
            PGSSTimeSeriesConfig,
        )
        config = PGSSTimeSeriesConfig(
            db_path=str(tmp_path / "retention_test.db"),
            retention_days=1,
        )
        store = PGSSTimeSeriesStore(config)
        store.init()

        old_time = time.time() - 200_000
        queries = self._make_queries(["old_fp"], base_calls=100)
        store.record_snapshot(queries, timestamp=old_time)

        queries2 = self._make_queries(["old_fp"], base_calls=200)
        store.record_snapshot(queries2, timestamp=old_time + 60)

        queries3 = self._make_queries(["old_fp"], base_calls=300)
        store.record_snapshot(queries3, timestamp=time.time())

        series = store.get_query_timeseries("old_fp", hours=24 * 30)
        assert len(series) <= 1

        store.close()

    def test_multiple_queries_tracked(self, tmp_path: Path) -> None:
        """Multiple queries should be tracked independently."""
        store = self._make_store(tmp_path)
        now = time.time()

        fps = ["alpha", "beta", "gamma", "delta"]
        queries_t1 = self._make_queries(fps, base_calls=100)
        store.record_snapshot(queries_t1, timestamp=now - 120)

        queries_t2 = self._make_queries(fps, base_calls=200)
        store.record_snapshot(queries_t2, timestamp=now - 60)

        assert store.get_unique_queries() == 4

        for fp in fps:
            series = store.get_query_timeseries(fp, hours=1)
            assert len(series) == 1

        store.close()
