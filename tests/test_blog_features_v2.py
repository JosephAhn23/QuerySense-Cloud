"""
Tests for pganalyze blog-inspired features (batch 2).

Covers:
  1. JSONBOptimizer       - JSONB selectivity, statistics, rewrite advice
  2. EquivalenceClassAdvisor - missing JOIN filter propagation
  3. PostgreSQLBetaTester - version catalogues, test suites, upgrade paths
"""

import pytest


# =========================================================================
# JSONB Optimizer
# =========================================================================

class TestJSONBOptimizer:

    def test_import(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        assert opt is not None

    def test_extract_arrow_field(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        fields = opt.extract_jsonb_fields(
            "SELECT * FROM events WHERE data ->> 'type' = 'click'"
        )
        assert len(fields) >= 1
        f = fields[0]
        assert f.column == "data"
        assert f.field_path == ("type",)
        assert f.operator == "->>"

    def test_extract_contains_operator(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        fields = opt.extract_jsonb_fields(
            """SELECT * FROM events WHERE data @> '{"type": "click"}'"""
        )
        assert any(f.operator == "@>" for f in fields)
        contains = [f for f in fields if f.operator == "@>"]
        assert contains[0].comparison_value == "click"

    def test_extract_has_key(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        fields = opt.extract_jsonb_fields(
            "SELECT * FROM docs WHERE metadata ? 'author'"
        )
        assert any(f.operator == "?" for f in fields)

    def test_analyze_contains_without_plan(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        issues = opt.analyze_query(
            """SELECT * FROM events WHERE data @> '{"type": "click"}'"""
        )
        assert len(issues) >= 1
        assert issues[0].issue_type == "contains_selectivity"
        assert "0.1%" in issues[0].description

    def test_analyze_contains_with_misestimate(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()

        plan = {
            "Node Type": "Seq Scan",
            "Plan Rows": 10,
            "Actual Rows": 50000,
            "Total Cost": 100.0,
            "Startup Cost": 0.0,
            "Plan Width": 64,
        }

        issues = opt.analyze_query(
            """SELECT * FROM events WHERE data @> '{"type": "click"}'""",
            plan=plan,
        )
        critical = [i for i in issues if i.severity == "critical"]
        assert len(critical) >= 1
        assert critical[0].estimated_improvement_pct > 90

    def test_analyze_field_extraction_with_equals(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()

        issues = opt.analyze_query(
            "SELECT * FROM events WHERE data ->> 'type' = 'click'"
        )
        expr_idx = [i for i in issues if i.issue_type == "expression_index"]
        assert len(expr_idx) >= 1
        assert "CREATE INDEX" in "\n".join(expr_idx[0].fix_sql)

    def test_analyze_has_key(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()

        issues = opt.analyze_query(
            "SELECT * FROM docs WHERE metadata ? 'author'"
        )
        gin = [i for i in issues if i.issue_type == "has_key_index"]
        assert len(gin) >= 1
        assert "GIN" in "\n".join(gin[0].fix_sql)

    def test_extended_statistics_recommendation(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()

        plan = {
            "Node Type": "Seq Scan",
            "Plan Rows": 1,
            "Actual Rows": 10000,
            "Total Cost": 100.0,
            "Startup Cost": 0.0,
            "Plan Width": 64,
        }

        issues = opt.analyze_query(
            """SELECT * FROM events WHERE data @> '{"service": "web"}'""",
            plan=plan,
        )
        stats = [i for i in issues if i.issue_type == "missing_statistics"]
        assert len(stats) >= 1
        assert "PG14" in stats[0].description or "expression" in stats[0].description.lower()

    def test_suggest_rewrite_contains(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()

        result = opt.suggest_rewrite(
            """SELECT * FROM events WHERE data @> '{"type": "click"}'"""
        )
        assert result["has_contains_operator"] is True
        assert result["recommends_extended_stats"] is True
        assert len(result["suggestions"]) >= 1
        assert result["suggestions"][0]["type"] == "rewrite_contains_to_equality"

    def test_suggest_rewrite_or_contains(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()

        result = opt.suggest_rewrite(
            """SELECT * FROM events WHERE data @> '{"a": 1}' OR data @> '{"b": 2}'"""
        )
        assert len(result["suggestions"]) >= 2
        union_sugg = [s for s in result["suggestions"] if s["type"] == "union_rewrite"]
        assert len(union_sugg) >= 1

    def test_suggest_rewrite_no_jsonb(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()

        result = opt.suggest_rewrite("SELECT * FROM users WHERE id = 1")
        assert result["has_contains_operator"] is False
        assert result["suggestions"] == []

    def test_generate_statistics_sql(self):
        from querysense.optimizers.jsonb_optimizer import generate_jsonb_statistics_sql
        sql = generate_jsonb_statistics_sql("events", "data", ["type", "service_id"])
        assert "CREATE STATISTICS" in sql
        assert "events" in sql
        assert "type" in sql
        assert "service_id" in sql
        assert "ANALYZE events" in sql

    def test_contsel_detected_flag(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        assert opt.contsel_detected is False

        plan = {
            "Node Type": "Seq Scan",
            "Plan Rows": 1,
            "Actual Rows": 50000,
            "Total Cost": 100.0,
            "Startup Cost": 0.0,
            "Plan Width": 64,
        }
        opt.analyze_query(
            """SELECT * FROM t WHERE data @> '{"k": "v"}'""",
            plan=plan,
        )
        assert opt.contsel_detected is True

    def test_no_fields_returns_empty(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        assert opt.analyze_query("SELECT 1") == []


# =========================================================================
# Equivalence Class Advisor
# =========================================================================

class TestEquivalenceClassAdvisor:

    def test_import(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()
        assert adv is not None

    def test_detects_in_not_propagated(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()

        sql = (
            "SELECT t1.a, t2.a FROM t1 "
            "JOIN t2 USING (a) "
            "WHERE t1.a IN (99000, 99001) "
            "ORDER BY t1.a LIMIT 100"
        )
        issues = adv.analyze_query(sql)
        assert len(issues) >= 1
        assert issues[0].operator == "IN"
        assert issues[0].severity == "critical"
        assert issues[0].missing_table == "t2"
        assert "2000x" in issues[0].estimated_speedup

    def test_detects_any_not_propagated(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()

        sql = (
            "SELECT * FROM docs "
            "JOIN tags ON docs.id = tags.doc_id "
            "WHERE docs.id = ANY(ARRAY[1,2,3])"
        )
        issues = adv.analyze_query(sql)
        assert len(issues) >= 1
        any_issues = [i for i in issues if i.operator == "ANY"]
        assert len(any_issues) >= 1
        assert any_issues[0].severity == "critical"

    def test_detects_range_not_propagated(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()

        sql = (
            "SELECT t1.a, t2.a FROM t1 "
            "JOIN t2 USING (a) "
            "WHERE t1.a > 99000 "
            "ORDER BY t1.a LIMIT 100"
        )
        issues = adv.analyze_query(sql)
        range_issues = [i for i in issues if i.operator == ">"]
        assert len(range_issues) >= 1
        assert range_issues[0].severity == "warning"

    def test_no_issue_when_already_duplicated(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()

        sql = (
            "SELECT t1.a, t2.a FROM t1 "
            "JOIN t2 USING (a) "
            "WHERE t1.a IN (99000, 99001) "
            "AND t2.a IN (99000, 99001) "
            "ORDER BY t1.a LIMIT 100"
        )
        issues = adv.analyze_query(sql)
        in_issues = [i for i in issues if i.operator == "IN"]
        assert len(in_issues) == 0

    def test_no_issue_without_where(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()

        sql = "SELECT * FROM t1 JOIN t2 USING (a)"
        issues = adv.analyze_query(sql)
        assert len(issues) == 0

    def test_no_issue_for_plain_equality(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()

        sql = (
            "SELECT * FROM t1 "
            "JOIN t2 ON t1.id = t2.id "
            "WHERE t1.id = 42"
        )
        issues = adv.analyze_query(sql)
        assert len(issues) == 0

    def test_fix_sql_contains_duplicate_filter(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()

        sql = (
            "SELECT * FROM orders "
            "JOIN items ON orders.id = items.id "
            "WHERE orders.id IN (1, 2, 3)"
        )
        issues = adv.analyze_query(sql)
        assert len(issues) >= 1
        assert "items" in issues[0].fix_sql

    def test_generate_test_queries(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()
        tests = adv.generate_test_queries()
        assert len(tests) >= 2
        assert all("slow_query" in t for t in tests)
        assert all("fast_query" in t for t in tests)

    def test_explain_equivalence_classes(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()
        explanation = adv.explain_equivalence_classes()
        assert "Equivalence" in explanation
        assert "NOT propagated" in explanation

    def test_on_join(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()

        sql = (
            "SELECT * FROM a "
            "INNER JOIN b ON a.x = b.x "
            "WHERE a.x IN (10, 20, 30)"
        )
        issues = adv.analyze_query(sql)
        assert len(issues) >= 1
        assert issues[0].join_column == "x"

    def test_issue_type_enum(self):
        from querysense.planner.equivalence_class_advisor import JoinFilterIssueType
        assert JoinFilterIssueType.IN_NOT_PROPAGATED.value == "in_not_propagated"
        assert JoinFilterIssueType.ANY_NOT_PROPAGATED.value == "any_not_propagated"
        assert JoinFilterIssueType.RANGE_NOT_PROPAGATED.value == "range_not_propagated"


# =========================================================================
# PostgreSQL Beta Tester
# =========================================================================

class TestPostgreSQLBetaTester:

    def test_import(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        assert tester is not None

    def test_get_version_info_17(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        vi = tester.get_version_info(17)
        assert vi is not None
        assert vi.major == 17
        assert len(vi.features) >= 5
        names = [f.name for f in vi.features]
        assert "Builtin C.UTF-8 locale" in names
        assert "SQL/JSON (JSON_TABLE)" in names

    def test_get_version_info_unknown(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        assert tester.get_version_info(99) is None

    def test_reverted_features_pg17(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        vi = tester.get_version_info(17)
        assert vi is not None
        assert len(vi.reverted) >= 3
        reverted_names = [f.name for f in vi.reverted]
        assert "OR to ANY transformation" in reverted_names

    def test_whats_new_summary(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        summary = tester.whats_new_summary(17)
        assert "PostgreSQL 17" in summary
        assert "Performance" in summary
        assert "Reverted" in summary

    def test_whats_new_summary_unknown(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        summary = tester.whats_new_summary(99)
        assert "No information" in summary

    def test_generate_test_suite(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        suite = tester.generate_test_suite(17)
        assert "performance" in suite or "developer" in suite
        total = sum(len(v) for v in suite.values())
        assert total >= 3

    def test_generate_test_suite_unknown(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        assert tester.generate_test_suite(99) == {}

    def test_upgrade_path_14_to_17(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        path = tester.get_upgrade_path(14, 17)
        assert len(path) == 3  # PG15, PG16, PG17
        versions = [step["version"] for step in path]
        assert 15 in versions
        assert 16 in versions
        assert 17 in versions

    def test_upgrade_path_same_version(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        path = tester.get_upgrade_path(17, 17)
        assert path == []

    def test_format_upgrade_report(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        report = tester.format_upgrade_report(15, 17)
        assert "Upgrade Path" in report
        assert "PostgreSQL 16" in report
        assert "PostgreSQL 17" in report
        assert "Total features" in report

    def test_format_upgrade_report_same(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        report = tester.format_upgrade_report(17, 17)
        assert "No upgrade" in report

    def test_bug_report_template(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        tmpl = tester.generate_bug_report_template(18)
        assert "PostgreSQL 18" in tmpl
        assert "pgsql-bugs" in tmpl
        assert "Steps to Reproduce" in tmpl

    def test_pg14_features(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        vi = tester.get_version_info(14)
        assert vi is not None
        names = [f.name for f in vi.features]
        assert "Memoize node" in names
        assert "Extended statistics on expressions" in names

    def test_pg15_reverted_json_table(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        vi = tester.get_version_info(15)
        assert vi is not None
        reverted = [f.name for f in vi.reverted]
        assert "SQL/JSON (JSON_TABLE)" in reverted

    def test_pg16_features(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        vi = tester.get_version_info(16)
        assert vi is not None
        names = [f.name for f in vi.features]
        assert "pg_stat_io" in names
        assert "EXPLAIN (GENERIC_PLAN)" in names

    def test_pg18_features(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        vi = tester.get_version_info(18)
        assert vi is not None
        names = [f.name for f in vi.features]
        assert "Asynchronous I/O (AIO)" in names

    def test_feature_status_enum(self):
        from querysense.upgrade.beta_tester import FeatureStatus
        assert FeatureStatus.INCLUDED.value == "included"
        assert FeatureStatus.REVERTED.value == "reverted"
        assert FeatureStatus.PLANNED.value == "planned"

    def test_feature_category_enum(self):
        from querysense.upgrade.beta_tester import FeatureCategory
        assert FeatureCategory.PERFORMANCE.value == "performance"
        assert FeatureCategory.OPERATIONAL.value == "operational"

    def test_upgrade_path_feature_counts(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        path = tester.get_upgrade_path(13, 17)
        assert len(path) == 4  # PG14, PG15, PG16, PG17
        total_features = sum(s["feature_count"] for s in path)
        assert total_features >= 15


# =========================================================================
# Integration: All modules importable from package
# =========================================================================

class TestPackageImports:

    def test_optimizers_package(self):
        from querysense.optimizers import JSONBOptimizer, JSONBField, JSONBOptimization
        assert JSONBOptimizer is not None
        assert JSONBField is not None
        assert JSONBOptimization is not None

    def test_planner_package(self):
        from querysense.planner import (
            EquivalenceClassAdvisor,
            JoinCondition,
            JoinFilterIssue,
            JoinFilterIssueType,
        )
        assert EquivalenceClassAdvisor is not None
        assert JoinCondition is not None

    def test_upgrade_package(self):
        from querysense.upgrade import (
            PostgreSQLBetaTester,
            BetaFeature,
            FeatureCategory,
            FeatureStatus,
            VersionInfo,
        )
        assert PostgreSQLBetaTester is not None
        assert BetaFeature is not None

    def test_generate_jsonb_statistics_sql_from_package(self):
        from querysense.optimizers import generate_jsonb_statistics_sql
        sql = generate_jsonb_statistics_sql("t", "data", ["a", "b"])
        assert "CREATE STATISTICS" in sql


# =========================================================================
# Edge cases
# =========================================================================

class TestEdgeCases:

    def test_jsonb_empty_query(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        assert opt.extract_jsonb_fields("") == []
        assert opt.analyze_query("") == []

    def test_jsonb_malformed_contains(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        fields = opt.extract_jsonb_fields(
            "SELECT * FROM t WHERE data @> '{not valid json'"
        )
        # Should not crash, may return a field with empty path
        assert isinstance(fields, list)

    def test_equivalence_no_join(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()
        issues = adv.analyze_query("SELECT * FROM t1 WHERE t1.id = 1")
        assert issues == []

    def test_equivalence_unrelated_filter_column(self):
        from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor
        adv = EquivalenceClassAdvisor()
        sql = (
            "SELECT * FROM t1 "
            "JOIN t2 USING (a) "
            "WHERE t1.b IN (1, 2, 3)"
        )
        issues = adv.analyze_query(sql)
        assert len(issues) == 0

    def test_beta_tester_all_versions_have_features(self):
        from querysense.upgrade.beta_tester import PostgreSQLBetaTester
        tester = PostgreSQLBetaTester()
        for major in [14, 15, 16, 17, 18, 19]:
            vi = tester.get_version_info(major)
            assert vi is not None, f"PG{major} missing"
            assert len(vi.features) >= 1, f"PG{major} has no features"

    def test_jsonb_plan_no_actual_rows(self):
        from querysense.optimizers.jsonb_optimizer import JSONBOptimizer
        opt = JSONBOptimizer()
        plan = {
            "Node Type": "Seq Scan",
            "Plan Rows": 100,
            "Total Cost": 50.0,
            "Startup Cost": 0.0,
            "Plan Width": 64,
        }
        issues = opt.analyze_query(
            """SELECT * FROM t WHERE data @> '{"k": "v"}'""",
            plan=plan,
        )
        assert len(issues) >= 1
