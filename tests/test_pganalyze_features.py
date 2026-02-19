"""
Tests for features inspired by the CounterPath / pganalyze case study.

Covers:
  1. INDEX_COLUMN_ORDER rule (the account_id leading-column mismatch)
  2. FrequencyScorer (rank findings by calls × duration)
  3. CPUEstimator (estimate CPU reduction potential)
  4. LoadTestComparison (before/after QA comparison)
"""

from __future__ import annotations

import json

import pytest

from querysense.parser.parser import parse_explain
from querysense.analyzer.analyzer import Analyzer
from querysense.analyzer.models import (
    AnalysisResult,
    EvidenceLevel,
    ExecutionMetadata,
    Finding,
    ImpactBand,
    NodeContext,
    ReproducibilityInfo,
    RuleRun,
    RuleRunStatus,
    SQLConfidence,
    Severity,
)
from querysense.analyzer.path import NodePath
from querysense.analyzer.rules.index_column_order import IndexColumnOrder
from querysense.frequency_scorer import (
    FrequencyScorer,
    ImpactTier,
    QueryStats,
    RankedFinding,
)
from querysense.cpu_impact import CPUEstimator, CPUImpact, CPUReductionBand
from querysense.load_test import (
    ChangeStatus,
    ComparisonReport,
    FindingDelta,
    LoadTestComparison,
    PlanSnapshot,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_explain(plan_dict: dict) -> str:
    return json.dumps([plan_dict])


def _counterpath_plan() -> str:
    """
    Simulate the CounterPath scenario:
    Index on (user_id, account_id), query filters only by account_id.
    The Index Scan uses user_id in the Index Cond but has a Filter on
    account_id that discards 95% of rows.
    """
    return _make_explain({
        "Plan": {
            "Node Type": "Index Scan",
            "Relation Name": "accounts",
            "Alias": "accounts",
            "Index Name": "idx_accounts_user_account",
            "Index Cond": "(user_id IS NOT NULL)",
            "Filter": "(account_id = 42)",
            "Rows Removed by Filter": 49000,
            "Scan Direction": "Forward",
            "Startup Cost": 0.43,
            "Total Cost": 8500.0,
            "Plan Rows": 1000,
            "Plan Width": 120,
            "Actual Startup Time": 0.05,
            "Actual Total Time": 450.0,
            "Actual Rows": 1000,
            "Actual Loops": 1,
            "Shared Hit Blocks": 200,
            "Shared Read Blocks": 5000,
        },
        "Execution Time": 455.0,
    })


def _clean_plan() -> str:
    """An optimised plan with no column-order issues."""
    return _make_explain({
        "Plan": {
            "Node Type": "Index Scan",
            "Relation Name": "accounts",
            "Alias": "accounts",
            "Index Name": "idx_accounts_account_id",
            "Index Cond": "(account_id = 42)",
            "Scan Direction": "Forward",
            "Startup Cost": 0.43,
            "Total Cost": 12.5,
            "Plan Rows": 50,
            "Plan Width": 120,
            "Actual Startup Time": 0.02,
            "Actual Total Time": 0.8,
            "Actual Rows": 50,
            "Actual Loops": 1,
            "Shared Hit Blocks": 50,
            "Shared Read Blocks": 0,
        },
        "Execution Time": 1.2,
    })


def _make_finding(
    rule_id: str = "SEQ_SCAN_LARGE_TABLE",
    severity: Severity = Severity.WARNING,
    title: str = "Seq scan on orders (250,000 rows)",
    impact_score: float = 6.0,
    total_cost: float = 5000.0,
    actual_rows: int = 250_000,
    relation_name: str = "orders",
    **extra_metrics: int | float,
) -> Finding:
    ctx = NodeContext(
        path=NodePath.root(),
        node_type="Seq Scan",
        relation_name=relation_name,
        actual_rows=actual_rows,
        plan_rows=actual_rows,
        total_cost=total_cost,
        filter="(status = 'pending')",
    )
    return Finding(
        rule_id=rule_id,
        severity=severity,
        context=ctx,
        title=title,
        description="Test finding",
        suggestion="CREATE INDEX ON orders(status)",
        metrics={"rows_scanned": actual_rows, "total_cost": total_cost, **extra_metrics},
        impact_band=ImpactBand.MEDIUM,
        impact_score=impact_score,
    )


def _make_result(findings: list[Finding]) -> AnalysisResult:
    return AnalysisResult(
        findings=tuple(findings),
        rule_runs=tuple(
            RuleRun(
                rule_id=f.rule_id,
                version="1.0.0",
                status=RuleRunStatus.PASS,
                findings_count=1,
            )
            for f in findings
        ),
        evidence_level=EvidenceLevel.PLAN,
        sql_confidence=SQLConfidence.NONE,
        reproducibility=ReproducibilityInfo(
            analysis_id="test",
            plan_hash="abc",
            config_hash="def",
            rules_hash="ghi",
            querysense_version="2.0.0",
        ),
        metadata=ExecutionMetadata(
            node_count=5,
            execution_time_ms=450.0,
            rules_run=1,
        ),
        degraded=False,
        degraded_reasons=(),
    )


# ===================================================================
# 1. INDEX_COLUMN_ORDER rule tests
# ===================================================================


class TestIndexColumnOrderRule:
    """Tests for the Index Column Order Mismatch detection rule."""

    def test_detects_counterpath_scenario(self):
        """The classic (user_id, account_id) index + WHERE account_id = ?"""
        explain = parse_explain(_counterpath_plan())
        rule = IndexColumnOrder()
        findings = rule.analyze(explain)

        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == "INDEX_COLUMN_ORDER"
        assert "account_id" in f.title
        assert f.severity in (Severity.WARNING, Severity.CRITICAL)
        assert f.metrics["discard_ratio"] >= 0.9

    def test_no_finding_on_clean_plan(self):
        """A well-indexed plan should produce no INDEX_COLUMN_ORDER findings."""
        explain = parse_explain(_clean_plan())
        rule = IndexColumnOrder()
        findings = rule.analyze(explain)

        ico_findings = [f for f in findings if f.rule_id == "INDEX_COLUMN_ORDER"]
        assert len(ico_findings) == 0

    def test_severity_escalates_at_high_discard(self):
        plan = _make_explain({
            "Plan": {
                "Node Type": "Index Scan",
                "Relation Name": "events",
                "Index Name": "idx_events_org_ts",
                "Index Cond": "(org_id = 1)",
                "Filter": "(event_type = 'login')",
                "Rows Removed by Filter": 95000,
                "Scan Direction": "Forward",
                "Startup Cost": 0.5,
                "Total Cost": 12000.0,
                "Plan Rows": 5000,
                "Plan Width": 80,
                "Actual Startup Time": 0.1,
                "Actual Total Time": 800.0,
                "Actual Rows": 5000,
                "Actual Loops": 1,
            },
            "Execution Time": 810.0,
        })
        explain = parse_explain(plan)
        rule = IndexColumnOrder()
        findings = rule.analyze(explain)

        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_suggestion_includes_create_index(self):
        explain = parse_explain(_counterpath_plan())
        rule = IndexColumnOrder()
        findings = rule.analyze(explain)

        assert findings
        assert "CREATE INDEX" in findings[0].suggestion

    def test_metrics_populated(self):
        explain = parse_explain(_counterpath_plan())
        rule = IndexColumnOrder()
        findings = rule.analyze(explain)

        assert findings
        m = findings[0].metrics
        assert "rows_returned" in m
        assert "rows_removed_by_filter" in m
        assert "discard_ratio" in m
        assert "non_leading_columns" in m
        assert m["non_leading_columns"] >= 1

    def test_impact_score_range(self):
        explain = parse_explain(_counterpath_plan())
        rule = IndexColumnOrder()
        findings = rule.analyze(explain)

        assert findings
        assert 0.0 <= findings[0].impact_score <= 10.0

    def test_runs_in_full_analyzer(self):
        """INDEX_COLUMN_ORDER should be registered and run by the full Analyzer."""
        explain = parse_explain(_counterpath_plan())
        analyzer = Analyzer()
        result = analyzer.analyze(explain)

        ico = [f for f in result.findings if f.rule_id == "INDEX_COLUMN_ORDER"]
        assert len(ico) >= 1

    def test_config_min_rows_removed(self):
        """Custom config should change trigger threshold."""
        explain = parse_explain(_counterpath_plan())
        rule = IndexColumnOrder(config={"min_rows_removed": 100_000})
        findings = rule.analyze(explain)

        assert len(findings) == 0

    def test_no_crash_on_missing_filter(self):
        plan = _make_explain({
            "Plan": {
                "Node Type": "Index Scan",
                "Relation Name": "users",
                "Index Name": "idx_users_pk",
                "Index Cond": "(id = 1)",
                "Startup Cost": 0.3,
                "Total Cost": 5.0,
                "Plan Rows": 1,
                "Plan Width": 50,
                "Actual Startup Time": 0.01,
                "Actual Total Time": 0.02,
                "Actual Rows": 1,
                "Actual Loops": 1,
            },
        })
        explain = parse_explain(plan)
        rule = IndexColumnOrder()
        findings = rule.analyze(explain)
        assert isinstance(findings, list)


# ===================================================================
# 2. FrequencyScorer tests
# ===================================================================


class TestFrequencyScorer:
    """Tests for query frequency impact scoring."""

    def test_basic_scoring(self):
        finding = _make_finding(impact_score=6.0)
        stats = QueryStats(calls_per_minute=350, mean_duration_ms=12.5)
        scorer = FrequencyScorer()

        ranked = scorer.score_finding(finding, stats)
        assert ranked.composite_score > 0
        assert ranked.impact_tier != ImpactTier.NEGLIGIBLE

    def test_high_frequency_boosts_score(self):
        finding = _make_finding(impact_score=5.0)
        scorer = FrequencyScorer()

        low = scorer.score_finding(finding, QueryStats(calls_per_minute=1, mean_duration_ms=10))
        high = scorer.score_finding(finding, QueryStats(calls_per_minute=1000, mean_duration_ms=10))

        assert high.composite_score > low.composite_score

    def test_high_duration_boosts_score(self):
        finding = _make_finding(impact_score=5.0)
        scorer = FrequencyScorer()

        fast = scorer.score_finding(finding, QueryStats(calls_per_minute=100, mean_duration_ms=1))
        slow = scorer.score_finding(finding, QueryStats(calls_per_minute=100, mean_duration_ms=1000))

        assert slow.composite_score > fast.composite_score

    def test_rank_findings_sorted_desc(self):
        f1 = _make_finding(rule_id="A", impact_score=2.0, title="Low impact")
        f2 = _make_finding(rule_id="B", impact_score=8.0, title="High impact")
        f3 = _make_finding(rule_id="C", impact_score=5.0, title="Mid impact")

        stats = QueryStats(calls_per_minute=100, mean_duration_ms=50)
        scorer = FrequencyScorer()
        ranked = scorer.rank_findings([f1, f2, f3], stats)

        assert ranked[0].finding.rule_id == "B"
        assert ranked[-1].finding.rule_id == "A"
        assert ranked[0].rank == 1
        assert ranked[2].rank == 3

    def test_severity_multiplier(self):
        f_crit = _make_finding(severity=Severity.CRITICAL, impact_score=5.0, title="Critical")
        f_info = _make_finding(severity=Severity.INFO, impact_score=5.0, title="Info")

        stats = QueryStats(calls_per_minute=100, mean_duration_ms=10)
        scorer = FrequencyScorer()

        r_crit = scorer.score_finding(f_crit, stats)
        r_info = scorer.score_finding(f_info, stats)

        assert r_crit.composite_score > r_info.composite_score

    def test_time_saved_calculation(self):
        finding = _make_finding(impact_score=10.0)
        stats = QueryStats(calls_per_minute=60, mean_duration_ms=100)
        scorer = FrequencyScorer()

        ranked = scorer.score_finding(finding, stats)
        assert ranked.time_saved_per_minute_ms == 6000.0

    def test_query_stats_properties(self):
        stats = QueryStats(
            calls_per_minute=120,
            mean_duration_ms=50,
            shared_blks_hit=900,
            shared_blks_read=100,
        )
        assert stats.calls_per_second == 2.0
        assert stats.cache_hit_ratio == 0.9
        assert stats.total_time_per_minute_ms == 6000.0

    def test_format_report(self):
        findings = [
            _make_finding(rule_id="A", impact_score=7.0, title="Finding A"),
            _make_finding(rule_id="B", impact_score=3.0, title="Finding B"),
        ]
        stats = QueryStats(calls_per_minute=200, mean_duration_ms=25)
        scorer = FrequencyScorer()
        ranked = scorer.rank_findings(findings, stats)
        report = scorer.format_report(ranked)

        assert "FREQUENCY-WEIGHTED" in report
        assert "#1" in report
        assert "Finding A" in report

    def test_zero_frequency_gives_zero_score(self):
        finding = _make_finding(impact_score=5.0)
        stats = QueryStats(calls_per_minute=0, mean_duration_ms=0)
        scorer = FrequencyScorer()
        ranked = scorer.score_finding(finding, stats)
        assert ranked.composite_score == 0.0
        assert ranked.impact_tier == ImpactTier.NEGLIGIBLE

    def test_cpu_minutes_saved(self):
        finding = _make_finding(impact_score=5.0)
        stats = QueryStats(calls_per_minute=60, mean_duration_ms=100)
        scorer = FrequencyScorer()
        ranked = scorer.score_finding(finding, stats)
        assert ranked.cpu_minutes_saved_per_hour >= 0


# ===================================================================
# 3. CPU Impact Estimator tests
# ===================================================================


class TestCPUEstimator:
    """Tests for CPU impact estimation."""

    def test_basic_estimate(self):
        finding = _make_finding(
            impact_score=7.0,
            actual_rows=1000,
            total_fetched=50000,
            rows_removed_by_filter=49000,
            discard_ratio=0.98,
        )
        est = CPUEstimator()
        impact = est.estimate(finding)

        assert impact.reduction_factor > 1.0
        assert impact.cpu_pct_before > impact.cpu_pct_after
        assert impact.tuples_processed > impact.tuples_after_fix

    def test_dramatic_reduction(self):
        finding = _make_finding(
            severity=Severity.CRITICAL,
            impact_score=9.0,
            actual_rows=1000,
            total_fetched=100_000,
            rows_removed_by_filter=99_000,
            discard_ratio=0.99,
        )
        est = CPUEstimator()
        impact = est.estimate(finding)

        assert impact.reduction_band in (
            CPUReductionBand.DRAMATIC,
            CPUReductionBand.SIGNIFICANT,
        )

    def test_no_filter_gives_minor_impact(self):
        ctx = NodeContext(
            path=NodePath.root(),
            node_type="Seq Scan",
            relation_name="small_table",
            actual_rows=100,
            plan_rows=100,
            total_cost=50.0,
        )
        finding = Finding(
            rule_id="TEST",
            severity=Severity.INFO,
            context=ctx,
            title="Small scan",
            description="desc",
            metrics={"rows_scanned": 100},
            impact_score=1.0,
        )
        est = CPUEstimator()
        impact = est.estimate(finding)
        assert impact.reduction_band in (
            CPUReductionBand.MINOR,
            CPUReductionBand.UNKNOWN,
        )

    def test_batch_estimate_sorted(self):
        f1 = _make_finding(rule_id="A", impact_score=2.0, actual_rows=100, title="Low")
        f2 = _make_finding(
            rule_id="B", impact_score=9.0, actual_rows=100_000,
            title="High", total_fetched=100_000,
            rows_removed_by_filter=99_000, discard_ratio=0.99,
        )
        est = CPUEstimator()
        impacts = est.estimate_batch([f1, f2])

        assert impacts[0].reduction_factor >= impacts[1].reduction_factor

    def test_improvement_description(self):
        finding = _make_finding(
            impact_score=8.0,
            total_fetched=50_000,
            rows_removed_by_filter=49_000,
            discard_ratio=0.98,
        )
        est = CPUEstimator()
        impact = est.estimate(finding)
        desc = impact.improvement_description
        assert "reduction" in desc.lower()

    def test_format_report(self):
        findings = [
            _make_finding(
                impact_score=8.0,
                total_fetched=50_000,
                rows_removed_by_filter=49_000,
                discard_ratio=0.98,
                title="Big finding",
            ),
        ]
        est = CPUEstimator()
        impacts = est.estimate_batch(findings)
        report = est.format_report(impacts)
        assert "CPU IMPACT" in report
        assert "#1" in report

    def test_cpu_pct_saved(self):
        finding = _make_finding(
            impact_score=7.0,
            total_fetched=50_000,
            rows_removed_by_filter=49_000,
            discard_ratio=0.98,
        )
        est = CPUEstimator()
        impact = est.estimate(finding)
        assert impact.cpu_pct_saved >= 0.0


# ===================================================================
# 4. Load Test Comparison tests
# ===================================================================


class TestLoadTestComparison:
    """Tests for the before/after QA comparison mode."""

    def test_resolved_findings(self):
        before_findings = [
            _make_finding(rule_id="A", title="Issue A"),
            _make_finding(rule_id="B", title="Issue B"),
        ]
        after_findings = [
            _make_finding(rule_id="A", title="Issue A"),
        ]

        before = PlanSnapshot(
            label="before",
            findings=tuple(before_findings),
            execution_time_ms=500.0,
            critical_count=0,
            warning_count=2,
            info_count=0,
        )
        after = PlanSnapshot(
            label="after",
            findings=tuple(after_findings),
            execution_time_ms=250.0,
            critical_count=0,
            warning_count=1,
            info_count=0,
        )

        comp = LoadTestComparison()
        report = comp.compare(before, after)

        assert report.resolved_count == 1
        assert report.is_improvement

    def test_new_regressions(self):
        before_findings = [_make_finding(rule_id="A", title="Issue A")]
        after_findings = [
            _make_finding(rule_id="A", title="Issue A"),
            _make_finding(rule_id="NEW", title="New regression"),
        ]

        before = PlanSnapshot(label="before", findings=tuple(before_findings))
        after = PlanSnapshot(label="after", findings=tuple(after_findings))

        comp = LoadTestComparison()
        report = comp.compare(before, after)

        assert report.new_count == 1
        assert report.is_regression

    def test_improved_score(self):
        f_before = _make_finding(rule_id="A", impact_score=8.0, title="Slow query")
        f_after = _make_finding(rule_id="A", impact_score=3.0, title="Slow query")

        before = PlanSnapshot(label="before", findings=(f_before,))
        after = PlanSnapshot(label="after", findings=(f_after,))

        comp = LoadTestComparison()
        report = comp.compare(before, after)

        improved = [d for d in report.deltas if d.status == ChangeStatus.IMPROVED]
        assert len(improved) == 1
        assert improved[0].score_delta < 0

    def test_regressed_score(self):
        f_before = _make_finding(rule_id="A", impact_score=3.0, title="Query")
        f_after = _make_finding(rule_id="A", impact_score=8.0, title="Query")

        before = PlanSnapshot(label="before", findings=(f_before,))
        after = PlanSnapshot(label="after", findings=(f_after,))

        comp = LoadTestComparison()
        report = comp.compare(before, after)

        assert report.regressed_count == 1

    def test_persists_unchanged(self):
        f = _make_finding(rule_id="A", impact_score=5.0, title="Stable issue")

        before = PlanSnapshot(label="before", findings=(f,))
        after = PlanSnapshot(label="after", findings=(f,))

        comp = LoadTestComparison()
        report = comp.compare(before, after)

        assert report.persists_count == 1
        assert not report.is_improvement
        assert not report.is_regression

    def test_execution_time_improvement(self):
        before = PlanSnapshot(
            label="before",
            findings=(),
            execution_time_ms=1000.0,
        )
        after = PlanSnapshot(
            label="after",
            findings=(),
            execution_time_ms=1.0,
        )

        comp = LoadTestComparison()
        report = comp.compare(before, after)

        assert report.execution_time_delta_ms == -999.0
        assert report.execution_time_improvement == 1000.0

    def test_format_report(self):
        f = _make_finding(rule_id="A", title="Some issue")
        before = PlanSnapshot(
            label="v1.0 baseline",
            findings=(f,),
            execution_time_ms=500.0,
            warning_count=1,
        )
        after = PlanSnapshot(
            label="v1.1 candidate",
            findings=(),
            execution_time_ms=50.0,
        )

        comp = LoadTestComparison()
        report = comp.compare(before, after)
        text = report.format()

        assert "LOAD TEST COMPARISON" in text
        assert "v1.0 baseline" in text
        assert "RESOLVED" in text

    def test_from_analysis(self):
        findings = [_make_finding()]
        result = _make_result(findings)
        snap = PlanSnapshot.from_analysis(result, label="test snap")

        assert snap.label == "test snap"
        assert snap.execution_time_ms == 450.0
        assert len(snap.findings) == 1

    def test_empty_comparison(self):
        before = PlanSnapshot(label="empty before", findings=())
        after = PlanSnapshot(label="empty after", findings=())

        comp = LoadTestComparison()
        report = comp.compare(before, after)

        assert report.resolved_count == 0
        assert report.new_count == 0
        assert not report.is_improvement
        assert not report.is_regression

    def test_cost_delta(self):
        f1 = _make_finding(total_cost=8000.0)
        f2 = _make_finding(total_cost=200.0)

        before = PlanSnapshot(
            label="before",
            findings=(f1,),
            total_cost=8000.0,
        )
        after = PlanSnapshot(
            label="after",
            findings=(f2,),
            total_cost=200.0,
        )

        comp = LoadTestComparison()
        report = comp.compare(before, after)
        assert report.cost_delta < 0

    def test_finding_delta_properties(self):
        f = _make_finding()
        d_resolved = FindingDelta(
            finding=f, status=ChangeStatus.RESOLVED,
            before_score=5.0, after_score=0.0, score_delta=-5.0,
        )
        assert d_resolved.is_improvement
        assert not d_resolved.is_regression

        d_new = FindingDelta(
            finding=f, status=ChangeStatus.NEW,
            before_score=0.0, after_score=5.0, score_delta=5.0,
        )
        assert d_new.is_regression
        assert not d_new.is_improvement
