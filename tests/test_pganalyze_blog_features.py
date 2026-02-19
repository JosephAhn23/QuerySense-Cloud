"""
Tests for features inspired by the pganalyze blog series.

Covers:
  1. CollationSortAdvisor - from "Waiting for PG17: C.UTF-8 locale" (E107)
  2. SubPlanLoopDetector  - from "Improved EXPLAIN for SubPlan nodes" (E108)
  3. ToastWideRow         - from "JSONB TOAST performance cliffs" (E3)
  4. WALFullPageWrites    - from "max_wal_size, full page writes, UUID vs BIGINT" (E10)
  5. PGVersionAdvisor     - synthesized from all PG 14-19 feature articles
"""

import pytest

from querysense.parser.models import ExplainOutput, PlanNode


def _make_plan(node_dict: dict) -> ExplainOutput:
    return ExplainOutput.model_validate({"Plan": node_dict})


def _make_analyze_plan(node_dict: dict, exec_time: float = 100.0) -> ExplainOutput:
    return ExplainOutput.model_validate({
        "Plan": node_dict,
        "Planning Time": 1.0,
        "Execution Time": exec_time,
    })


# =========================================================================
# Collation Sort Advisor
# =========================================================================

class TestCollationSortAdvisor:

    def test_import(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor()
        assert rule.rule_id == "COLLATION_SORT_EXPENSIVE"

    def test_triggers_on_large_text_sort(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor()

        plan = _make_analyze_plan({
            "Node Type": "Sort",
            "Startup Cost": 1000.0,
            "Total Cost": 5000.0,
            "Plan Rows": 50000,
            "Plan Width": 64,
            "Actual Startup Time": 80.0,
            "Actual Total Time": 150.0,
            "Actual Rows": 50000,
            "Actual Loops": 1,
            "Sort Key": ["name"],
            "Sort Method": "external merge",
            "Sort Space Type": "Disk",
            "Sort Space Used": 8192,
            "Plans": [{
                "Node Type": "Seq Scan",
                "Relation Name": "users",
                "Startup Cost": 0.0,
                "Total Cost": 500.0,
                "Plan Rows": 50000,
                "Plan Width": 64,
                "Actual Startup Time": 0.1,
                "Actual Total Time": 30.0,
                "Actual Rows": 50000,
                "Actual Loops": 1,
            }],
        }, exec_time=200.0)

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == "COLLATION_SORT_EXPENSIVE"
        assert "COLLATE" in f.suggestion
        assert f.metrics["rows_sorted"] == 50000

    def test_skips_small_sort(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor()

        plan = _make_analyze_plan({
            "Node Type": "Sort",
            "Startup Cost": 10.0,
            "Total Cost": 20.0,
            "Plan Rows": 50,
            "Plan Width": 32,
            "Actual Startup Time": 0.1,
            "Actual Total Time": 0.5,
            "Actual Rows": 50,
            "Actual Loops": 1,
            "Sort Key": ["name"],
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_skips_sort_with_explicit_collate(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor()

        plan = _make_analyze_plan({
            "Node Type": "Sort",
            "Startup Cost": 1000.0,
            "Total Cost": 5000.0,
            "Plan Rows": 50000,
            "Plan Width": 64,
            "Actual Startup Time": 50.0,
            "Actual Total Time": 100.0,
            "Actual Rows": 50000,
            "Actual Loops": 1,
            "Sort Key": ['name COLLATE "C"'],
        }, exec_time=120.0)

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_high_sort_pct_warning(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor()

        plan = _make_analyze_plan({
            "Node Type": "Sort",
            "Startup Cost": 0.0,
            "Total Cost": 10000.0,
            "Plan Rows": 200000,
            "Plan Width": 128,
            "Actual Startup Time": 300.0,
            "Actual Total Time": 461.0,
            "Actual Rows": 200000,
            "Actual Loops": 1,
            "Sort Key": ["i::text"],
            "Sort Method": "quicksort",
            "Sort Space Type": "Memory",
            "Sort Space Used": 32768,
        }, exec_time=470.0)

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        f = findings[0]
        assert f.metrics["sort_time_pct"] > 0.5
        assert "C.UTF-8" in f.suggestion

    def test_incremental_sort_also_detected(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor()

        plan = _make_analyze_plan({
            "Node Type": "Incremental Sort",
            "Startup Cost": 500.0,
            "Total Cost": 3000.0,
            "Plan Rows": 20000,
            "Plan Width": 64,
            "Actual Startup Time": 20.0,
            "Actual Total Time": 80.0,
            "Actual Rows": 20000,
            "Actual Loops": 1,
            "Sort Key": ["title"],
        }, exec_time=100.0)

        findings = rule.analyze(plan)
        assert len(findings) >= 1

    def test_config_min_sort_rows(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor(config={"min_sort_rows": 100_000})

        plan = _make_analyze_plan({
            "Node Type": "Sort",
            "Startup Cost": 1000.0,
            "Total Cost": 5000.0,
            "Plan Rows": 50000,
            "Plan Width": 64,
            "Actual Startup Time": 80.0,
            "Actual Total Time": 150.0,
            "Actual Rows": 50000,
            "Actual Loops": 1,
            "Sort Key": ["name"],
        }, exec_time=200.0)

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_suggestion_includes_index_advice(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor()

        plan = _make_analyze_plan({
            "Node Type": "Sort",
            "Startup Cost": 1000.0,
            "Total Cost": 5000.0,
            "Plan Rows": 50000,
            "Plan Width": 64,
            "Actual Startup Time": 80.0,
            "Actual Total Time": 150.0,
            "Actual Rows": 50000,
            "Actual Loops": 1,
            "Sort Key": ["username"],
        }, exec_time=200.0)

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        assert "CREATE INDEX" in findings[0].suggestion


# =========================================================================
# SubPlan Loop Detector
# =========================================================================

class TestSubPlanLoopDetector:

    def test_import(self):
        from querysense.analyzer.rules.subplan_loop_detector import SubPlanLoopDetector
        rule = SubPlanLoopDetector()
        assert rule.rule_id == "SUBPLAN_HIGH_LOOPS"

    def test_detects_high_loop_count(self):
        """Simulates the tenk1 example from the pganalyze article."""
        from querysense.analyzer.rules.subplan_loop_detector import SubPlanLoopDetector
        rule = SubPlanLoopDetector()

        plan = _make_analyze_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "tenk1",
            "Startup Cost": 0.0,
            "Total Cost": 241095.0,
            "Plan Rows": 5000,
            "Plan Width": 4,
            "Actual Startup Time": 24.0,
            "Actual Total Time": 24.8,
            "Actual Rows": 0,
            "Actual Loops": 1,
            "Filter": "(ALL (t.ten < (SubPlan 1).col1))",
            "Rows Removed by Filter": 10000,
            "Plans": [{
                "Node Type": "Seq Scan",
                "Relation Name": "onek",
                "Startup Cost": 0.0,
                "Total Cost": 47.5,
                "Plan Rows": 250,
                "Plan Width": 4,
                "Actual Startup Time": 0.001,
                "Actual Total Time": 0.001,
                "Actual Rows": 2,
                "Actual Loops": 10000,
                "Filter": "(o.four = t.four)",
                "Rows Removed by Filter": 8,
            }],
        }, exec_time=25.0)

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == "SUBPLAN_HIGH_LOOPS"
        assert f.metrics["actual_loops"] == 10000
        assert "10,000" in f.title
        assert "correlated" in f.title.lower()

    def test_critical_severity_for_very_high_loops(self):
        from querysense.analyzer.rules.subplan_loop_detector import SubPlanLoopDetector
        rule = SubPlanLoopDetector()

        plan = _make_analyze_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "big_table",
            "Startup Cost": 0.0,
            "Total Cost": 1000.0,
            "Plan Rows": 100000,
            "Plan Width": 4,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 500.0,
            "Actual Rows": 0,
            "Actual Loops": 1,
            "Filter": "(SubPlan 1)",
            "Plans": [{
                "Node Type": "Index Scan",
                "Relation Name": "lookup",
                "Index Name": "lookup_pkey",
                "Startup Cost": 0.0,
                "Total Cost": 0.5,
                "Plan Rows": 1,
                "Plan Width": 4,
                "Actual Startup Time": 0.001,
                "Actual Total Time": 0.002,
                "Actual Rows": 1,
                "Actual Loops": 100000,
            }],
        }, exec_time=600.0)

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity.value == "critical"

    def test_skips_low_loop_count(self):
        from querysense.analyzer.rules.subplan_loop_detector import SubPlanLoopDetector
        rule = SubPlanLoopDetector()

        plan = _make_analyze_plan({
            "Node Type": "Nested Loop",
            "Startup Cost": 0.0,
            "Total Cost": 100.0,
            "Plan Rows": 10,
            "Plan Width": 8,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 5.0,
            "Actual Rows": 10,
            "Actual Loops": 1,
            "Plans": [{
                "Node Type": "Seq Scan",
                "Relation Name": "small_table",
                "Startup Cost": 0.0,
                "Total Cost": 1.0,
                "Plan Rows": 10,
                "Plan Width": 4,
                "Actual Startup Time": 0.0,
                "Actual Total Time": 0.1,
                "Actual Rows": 10,
                "Actual Loops": 1,
            }, {
                "Node Type": "Index Scan",
                "Relation Name": "other_table",
                "Startup Cost": 0.0,
                "Total Cost": 1.0,
                "Plan Rows": 1,
                "Plan Width": 4,
                "Actual Startup Time": 0.0,
                "Actual Total Time": 0.01,
                "Actual Rows": 1,
                "Actual Loops": 10,
            }],
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_suggestion_mentions_exists_rewrite(self):
        from querysense.analyzer.rules.subplan_loop_detector import SubPlanLoopDetector
        rule = SubPlanLoopDetector()

        plan = _make_analyze_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "parent",
            "Startup Cost": 0.0,
            "Total Cost": 1000.0,
            "Plan Rows": 5000,
            "Plan Width": 4,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 100.0,
            "Actual Rows": 5000,
            "Actual Loops": 1,
            "Filter": "(NOT (hashed SubPlan 1))",
            "Plans": [{
                "Node Type": "Seq Scan",
                "Relation Name": "child",
                "Startup Cost": 0.0,
                "Total Cost": 45.0,
                "Plan Rows": 1000,
                "Plan Width": 4,
                "Actual Startup Time": 0.0,
                "Actual Total Time": 0.5,
                "Actual Rows": 1000,
                "Actual Loops": 5000,
            }],
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        assert "EXISTS" in findings[0].suggestion

    def test_config_custom_min_loops(self):
        from querysense.analyzer.rules.subplan_loop_detector import SubPlanLoopDetector
        rule = SubPlanLoopDetector(config={"min_loops": 50000})

        plan = _make_analyze_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "t1",
            "Startup Cost": 0.0,
            "Total Cost": 100.0,
            "Plan Rows": 10000,
            "Plan Width": 4,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 100.0,
            "Actual Rows": 10000,
            "Actual Loops": 1,
            "Filter": "(SubPlan 1)",
            "Plans": [{
                "Node Type": "Seq Scan",
                "Relation Name": "t2",
                "Startup Cost": 0.0,
                "Total Cost": 10.0,
                "Plan Rows": 100,
                "Plan Width": 4,
                "Actual Startup Time": 0.0,
                "Actual Total Time": 0.01,
                "Actual Rows": 100,
                "Actual Loops": 10000,
            }],
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0


# =========================================================================
# TOAST / Wide Row Detector
# =========================================================================

class TestToastWideRow:

    def test_import(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()
        assert rule.rule_id == "TOAST_WIDE_ROW"

    def test_triggers_on_wide_rows(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()

        plan = _make_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "documents",
            "Startup Cost": 0.0,
            "Total Cost": 5000.0,
            "Plan Rows": 50000,
            "Plan Width": 4096,
            "Actual Rows": 50000,
            "Actual Loops": 1,
            "Shared Hit Blocks": 10000,
            "Shared Read Blocks": 20000,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == "TOAST_WIDE_ROW"
        assert "4,096" in f.title
        assert "TOAST" in f.title

    def test_skips_narrow_rows(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()

        plan = _make_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "events",
            "Startup Cost": 0.0,
            "Total Cost": 1000.0,
            "Plan Rows": 50000,
            "Plan Width": 128,
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_skips_few_rows(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()

        plan = _make_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "config",
            "Startup Cost": 0.0,
            "Total Cost": 10.0,
            "Plan Rows": 5,
            "Plan Width": 8000,
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_critical_width_warning_severity(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()

        plan = _make_plan({
            "Node Type": "Index Scan",
            "Relation Name": "blobs",
            "Index Name": "blobs_pkey",
            "Startup Cost": 0.0,
            "Total Cost": 8000.0,
            "Plan Rows": 10000,
            "Plan Width": 9000,
            "Actual Rows": 10000,
            "Actual Loops": 1,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        assert findings[0].severity.value == "warning"

    def test_suggestion_mentions_select_columns(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()

        plan = _make_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "posts",
            "Startup Cost": 0.0,
            "Total Cost": 3000.0,
            "Plan Rows": 20000,
            "Plan Width": 5000,
            "Actual Rows": 20000,
            "Actual Loops": 1,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        assert "SELECT *" in findings[0].suggestion or "needed columns" in findings[0].suggestion

    def test_io_amplification_metric(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()

        plan = _make_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "jsonb_docs",
            "Startup Cost": 0.0,
            "Total Cost": 10000.0,
            "Plan Rows": 10000,
            "Plan Width": 4000,
            "Actual Rows": 10000,
            "Actual Loops": 1,
            "Shared Hit Blocks": 5000,
            "Shared Read Blocks": 15000,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        assert findings[0].metrics["io_amplification"] > 0

    def test_index_only_scan_not_flagged_for_narrow(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()

        plan = _make_plan({
            "Node Type": "Index Only Scan",
            "Relation Name": "users",
            "Index Name": "users_email_idx",
            "Startup Cost": 0.0,
            "Total Cost": 500.0,
            "Plan Rows": 50000,
            "Plan Width": 64,
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0


# =========================================================================
# WAL Full Page Writes
# =========================================================================

class TestWALFullPageWrites:

    def test_import(self):
        from querysense.analyzer.rules.wal_full_page_writes import WALFullPageWrites
        rule = WALFullPageWrites()
        assert rule.rule_id == "WAL_FULL_PAGE_WRITE"

    def test_triggers_on_high_dirty_blocks(self):
        from querysense.analyzer.rules.wal_full_page_writes import WALFullPageWrites
        rule = WALFullPageWrites()

        plan = _make_analyze_plan({
            "Node Type": "ModifyTable",
            "Relation Name": "orders",
            "Startup Cost": 0.0,
            "Total Cost": 5000.0,
            "Plan Rows": 1000,
            "Plan Width": 128,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 200.0,
            "Actual Rows": 1000,
            "Actual Loops": 1,
            "Shared Dirtied Blocks": 2500,
            "Shared Written Blocks": 500,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == "WAL_FULL_PAGE_WRITE"
        assert f.metrics["blocks_per_row"] >= 2.0

    def test_skips_normal_dirty_ratio(self):
        from querysense.analyzer.rules.wal_full_page_writes import WALFullPageWrites
        rule = WALFullPageWrites()

        plan = _make_analyze_plan({
            "Node Type": "ModifyTable",
            "Relation Name": "events",
            "Startup Cost": 0.0,
            "Total Cost": 100.0,
            "Plan Rows": 1000,
            "Plan Width": 64,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 10.0,
            "Actual Rows": 1000,
            "Actual Loops": 1,
            "Shared Dirtied Blocks": 200,
            "Shared Written Blocks": 50,
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_uuid_like_scatter_pattern(self):
        """Simulates UUID PK insert: each row touches a different page."""
        from querysense.analyzer.rules.wal_full_page_writes import WALFullPageWrites
        rule = WALFullPageWrites()

        plan = _make_analyze_plan({
            "Node Type": "ModifyTable",
            "Relation Name": "uuid_table",
            "Startup Cost": 0.0,
            "Total Cost": 10000.0,
            "Plan Rows": 5000,
            "Plan Width": 200,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 800.0,
            "Actual Rows": 5000,
            "Actual Loops": 1,
            "Shared Dirtied Blocks": 25000,
            "Shared Written Blocks": 5000,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity.value == "warning"
        assert f.metrics["blocks_per_row"] >= 4.0

    def test_suggestion_mentions_bigint(self):
        from querysense.analyzer.rules.wal_full_page_writes import WALFullPageWrites
        rule = WALFullPageWrites()

        plan = _make_analyze_plan({
            "Node Type": "ModifyTable",
            "Relation Name": "items",
            "Startup Cost": 0.0,
            "Total Cost": 5000.0,
            "Plan Rows": 1000,
            "Plan Width": 128,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 100.0,
            "Actual Rows": 1000,
            "Actual Loops": 1,
            "Shared Dirtied Blocks": 4000,
            "Shared Written Blocks": 1000,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        assert "BIGINT" in findings[0].suggestion

    def test_wal_overhead_estimate(self):
        from querysense.analyzer.rules.wal_full_page_writes import WALFullPageWrites
        rule = WALFullPageWrites()

        plan = _make_analyze_plan({
            "Node Type": "ModifyTable",
            "Relation Name": "test_tbl",
            "Startup Cost": 0.0,
            "Total Cost": 1000.0,
            "Plan Rows": 500,
            "Plan Width": 64,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 50.0,
            "Actual Rows": 500,
            "Actual Loops": 1,
            "Shared Dirtied Blocks": 1500,
            "Shared Written Blocks": 500,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1
        assert findings[0].metrics["wal_overhead_estimate_kb"] == (1500 + 500) * 8


# =========================================================================
# PG Version Advisor
# =========================================================================

class TestPGVersionAdvisor:

    def test_import(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        advisor = PGVersionAdvisor(current_version=15)
        assert advisor.current_version == 15

    def test_recommends_pg17_for_collation_finding(self):
        from querysense.pg_version_advisor import PGVersionAdvisor, UpgradeUrgency
        from querysense.analyzer.models import Finding, Severity, NodeContext, ImpactBand
        from querysense.analyzer.path import NodePath

        advisor = PGVersionAdvisor(current_version=16)

        finding = Finding(
            rule_id="COLLATION_SORT_EXPENSIVE",
            severity=Severity.WARNING,
            context=NodeContext(
                node_type="Sort",
                path=NodePath.root(),
            ),
            title="Expensive sort",
            description="...",
            suggestion="...",
            impact_band=ImpactBand.MEDIUM,
            impact_score=5.0,
        )

        recs = advisor.analyze_findings([finding])
        pg17_recs = [r for r in recs if r.target_version == 17]
        assert len(pg17_recs) >= 1
        assert any("C.UTF-8" in r.feature for r in pg17_recs)

    def test_recommends_pg17_for_subplan_finding(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        from querysense.analyzer.models import Finding, Severity, NodeContext, ImpactBand
        from querysense.analyzer.path import NodePath

        advisor = PGVersionAdvisor(current_version=15)

        finding = Finding(
            rule_id="SUBPLAN_HIGH_LOOPS",
            severity=Severity.CRITICAL,
            context=NodeContext(
                node_type="Seq Scan",
                path=NodePath.root(),
            ),
            title="High loops",
            description="...",
            suggestion="...",
            impact_band=ImpactBand.HIGH,
            impact_score=8.0,
        )

        recs = advisor.analyze_findings([finding])
        assert any(r.target_version == 17 for r in recs)

    def test_no_recommendations_for_current_version(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        from querysense.analyzer.models import Finding, Severity, NodeContext, ImpactBand
        from querysense.analyzer.path import NodePath

        advisor = PGVersionAdvisor(current_version=19)

        finding = Finding(
            rule_id="COLLATION_SORT_EXPENSIVE",
            severity=Severity.WARNING,
            context=NodeContext(
                node_type="Sort",
                path=NodePath.root(),
            ),
            title="...",
            description="...",
            suggestion="...",
            impact_band=ImpactBand.LOW,
            impact_score=3.0,
        )

        recs = advisor.analyze_findings([finding])
        assert len(recs) == 0

    def test_format_report_empty(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        advisor = PGVersionAdvisor(current_version=17)
        report = advisor.format_report([])
        assert "No version-specific recommendations" in report

    def test_format_report_with_recommendations(self):
        from querysense.pg_version_advisor import PGVersionAdvisor, VersionRecommendation, UpgradeUrgency

        advisor = PGVersionAdvisor(current_version=15)
        recs = [
            VersionRecommendation(
                target_version=17,
                feature="C.UTF-8 builtin locale",
                description="Fast binary sorts",
                urgency=UpgradeUrgency.HIGH,
                related_rule_ids=("COLLATION_SORT_EXPENSIVE",),
                blog_ref="E107",
            ),
            VersionRecommendation(
                target_version=18,
                feature="Async I/O",
                description="Non-blocking reads",
                urgency=UpgradeUrgency.MEDIUM,
                related_rule_ids=("SEQ_SCAN_LARGE_TABLE",),
            ),
        ]

        report = advisor.format_report(recs)
        assert "PostgreSQL 17" in report
        assert "PostgreSQL 18" in report
        assert "C.UTF-8" in report
        assert "HIGH" in report

    def test_recommendations_sorted_by_urgency(self):
        from querysense.pg_version_advisor import PGVersionAdvisor, UpgradeUrgency
        from querysense.analyzer.models import Finding, Severity, NodeContext, ImpactBand
        from querysense.analyzer.path import NodePath

        advisor = PGVersionAdvisor(current_version=14)

        findings = [
            Finding(
                rule_id="COLLATION_SORT_EXPENSIVE",
                severity=Severity.WARNING,
                context=NodeContext(node_type="Sort", path=NodePath.root()),
                title="...", description="...", suggestion="...",
                impact_band=ImpactBand.MEDIUM, impact_score=5.0,
            ),
            Finding(
                rule_id="SEQ_SCAN_LARGE_TABLE",
                severity=Severity.WARNING,
                context=NodeContext(node_type="Seq Scan", path=NodePath.root()),
                title="...", description="...", suggestion="...",
                impact_band=ImpactBand.MEDIUM, impact_score=5.0,
            ),
        ]

        recs = advisor.analyze_findings(findings)
        assert len(recs) >= 2
        urgencies = [r.urgency for r in recs]
        urgency_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        for i in range(len(urgencies) - 1):
            assert urgency_order[urgencies[i].value] <= urgency_order[urgencies[i + 1].value]

    def test_recommends_pg14_memoize_for_subplan(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        from querysense.analyzer.models import Finding, Severity, NodeContext, ImpactBand
        from querysense.analyzer.path import NodePath

        advisor = PGVersionAdvisor(current_version=13)

        finding = Finding(
            rule_id="SUBPLAN_HIGH_LOOPS",
            severity=Severity.WARNING,
            context=NodeContext(node_type="Seq Scan", path=NodePath.root()),
            title="...", description="...", suggestion="...",
            impact_band=ImpactBand.HIGH, impact_score=8.0,
        )

        recs = advisor.analyze_findings([finding])
        pg14_recs = [r for r in recs if r.target_version == 14]
        assert len(pg14_recs) >= 1
        assert "Memoize" in pg14_recs[0].feature

    def test_version_label_property(self):
        from querysense.pg_version_advisor import VersionRecommendation, UpgradeUrgency

        rec = VersionRecommendation(
            target_version=17,
            feature="test",
            description="test desc",
            urgency=UpgradeUrgency.HIGH,
            related_rule_ids=(),
        )
        assert rec.version_label == "PostgreSQL 17"

    def test_pg18_aio_recommendation(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        from querysense.analyzer.models import Finding, Severity, NodeContext, ImpactBand
        from querysense.analyzer.path import NodePath

        advisor = PGVersionAdvisor(current_version=17)

        finding = Finding(
            rule_id="SEQ_SCAN_LARGE_TABLE",
            severity=Severity.WARNING,
            context=NodeContext(node_type="Seq Scan", path=NodePath.root()),
            title="...", description="...", suggestion="...",
            impact_band=ImpactBand.MEDIUM, impact_score=5.0,
        )

        recs = advisor.analyze_findings([finding])
        pg18_recs = [r for r in recs if r.target_version == 18]
        assert len(pg18_recs) >= 1
        assert "Asynchronous" in pg18_recs[0].feature or "async" in pg18_recs[0].description.lower()

    def test_pg15_sort_recommendation(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        from querysense.analyzer.models import Finding, Severity, NodeContext, ImpactBand
        from querysense.analyzer.path import NodePath

        advisor = PGVersionAdvisor(current_version=14)

        finding = Finding(
            rule_id="SPILLING_TO_DISK",
            severity=Severity.WARNING,
            context=NodeContext(node_type="Sort", path=NodePath.root()),
            title="...", description="...", suggestion="...",
            impact_band=ImpactBand.MEDIUM, impact_score=5.0,
        )

        recs = advisor.analyze_findings([finding])
        pg15_recs = [r for r in recs if r.target_version == 15]
        assert len(pg15_recs) >= 1
        assert "sort" in pg15_recs[0].feature.lower()


# =========================================================================
# Integration: All new rules registered and discoverable
# =========================================================================

class TestNewRulesRegistered:

    def test_collation_sort_in_registry(self):
        from querysense.analyzer.rules import CollationSortAdvisor
        assert CollationSortAdvisor is not None
        assert CollationSortAdvisor.rule_id == "COLLATION_SORT_EXPENSIVE"

    def test_subplan_loop_in_registry(self):
        from querysense.analyzer.rules import SubPlanLoopDetector
        assert SubPlanLoopDetector is not None
        assert SubPlanLoopDetector.rule_id == "SUBPLAN_HIGH_LOOPS"

    def test_toast_wide_row_in_registry(self):
        from querysense.analyzer.rules import ToastWideRow
        assert ToastWideRow is not None
        assert ToastWideRow.rule_id == "TOAST_WIDE_ROW"

    def test_wal_full_page_in_registry(self):
        from querysense.analyzer.rules import WALFullPageWrites
        assert WALFullPageWrites is not None
        assert WALFullPageWrites.rule_id == "WAL_FULL_PAGE_WRITE"

    def test_all_new_rules_in_all_export(self):
        from querysense.analyzer.rules import __all__
        assert "CollationSortAdvisor" in __all__
        assert "SubPlanLoopDetector" in __all__
        assert "ToastWideRow" in __all__
        assert "WALFullPageWrites" in __all__


# =========================================================================
# Edge cases and combined scenarios
# =========================================================================

class TestEdgeCases:

    def test_collation_rule_no_analyze_data(self):
        from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
        rule = CollationSortAdvisor()

        plan = _make_plan({
            "Node Type": "Sort",
            "Startup Cost": 1000.0,
            "Total Cost": 5000.0,
            "Plan Rows": 50000,
            "Plan Width": 64,
            "Sort Key": ["name"],
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1

    def test_subplan_no_analyze_data(self):
        from querysense.analyzer.rules.subplan_loop_detector import SubPlanLoopDetector
        rule = SubPlanLoopDetector()

        plan = _make_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "t1",
            "Startup Cost": 0.0,
            "Total Cost": 100.0,
            "Plan Rows": 1000,
            "Plan Width": 4,
            "Plans": [{
                "Node Type": "Seq Scan",
                "Relation Name": "t2",
                "Startup Cost": 0.0,
                "Total Cost": 10.0,
                "Plan Rows": 100,
                "Plan Width": 4,
            }],
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_toast_on_bitmap_heap_scan(self):
        from querysense.analyzer.rules.toast_wide_row import ToastWideRow
        rule = ToastWideRow()

        plan = _make_plan({
            "Node Type": "Bitmap Heap Scan",
            "Relation Name": "attachments",
            "Startup Cost": 100.0,
            "Total Cost": 5000.0,
            "Plan Rows": 5000,
            "Plan Width": 3000,
            "Actual Rows": 5000,
            "Actual Loops": 1,
        })

        findings = rule.analyze(plan)
        assert len(findings) >= 1

    def test_wal_skips_read_only_scans(self):
        from querysense.analyzer.rules.wal_full_page_writes import WALFullPageWrites
        rule = WALFullPageWrites()

        plan = _make_analyze_plan({
            "Node Type": "Seq Scan",
            "Relation Name": "readonly_table",
            "Startup Cost": 0.0,
            "Total Cost": 100.0,
            "Plan Rows": 1000,
            "Plan Width": 64,
            "Actual Startup Time": 0.0,
            "Actual Total Time": 10.0,
            "Actual Rows": 1000,
            "Actual Loops": 1,
            "Shared Hit Blocks": 50,
            "Shared Read Blocks": 100,
        })

        findings = rule.analyze(plan)
        assert len(findings) == 0

    def test_pg_version_advisor_empty_findings(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        advisor = PGVersionAdvisor(current_version=15)
        recs = advisor.analyze_findings([])
        assert recs == []

    def test_pg_version_advisor_unrelated_finding(self):
        from querysense.pg_version_advisor import PGVersionAdvisor
        from querysense.analyzer.models import Finding, Severity, NodeContext, ImpactBand
        from querysense.analyzer.path import NodePath

        advisor = PGVersionAdvisor(current_version=15)

        finding = Finding(
            rule_id="SOME_UNKNOWN_RULE",
            severity=Severity.INFO,
            context=NodeContext(node_type="Result", path=NodePath.root()),
            title="...", description="...", suggestion="...",
            impact_band=ImpactBand.LOW, impact_score=1.0,
        )

        recs = advisor.analyze_findings([finding])
        assert len(recs) == 0
