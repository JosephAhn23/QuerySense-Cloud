"""
Comprehensive tests for the three new pganalyze-inspired features:

1. ParameterExtractor — named parameter extraction + parameter sets
2. OracleHintTranslator — Oracle → pg_hint_plan with confidence scoring
3. EnhancedPlanDiff — structural plan comparison with similarity scoring
"""

from __future__ import annotations

import json
import pytest

# ======================================================================
# 1. Parameter Extraction
# ======================================================================

from querysense.tuning.parameters import (
    ParameterExtractor,
    ParameterSet,
    QueryParameter,
)


class TestQueryParameter:
    def test_to_dict(self):
        p = QueryParameter(name="id", position=1, value=42, pg_type="integer", source="manual")
        d = p.to_dict()
        assert d["name"] == "id"
        assert d["value"] == 42
        assert d["pg_type"] == "integer"

    def test_defaults(self):
        p = QueryParameter(name="x", position=1)
        assert p.value is None
        assert p.pg_type == "text"
        assert p.source == "manual"


class TestParameterSet:
    def test_values_dict(self):
        ps = ParameterSet(
            id="abc",
            name="test",
            parameters=[
                QueryParameter(name="id", position=1, value=42),
                QueryParameter(name="status", position=2, value="active"),
            ],
        )
        assert ps.values_dict() == {"id": 42, "status": "active"}

    def test_to_dict(self):
        ps = ParameterSet(id="abc", name="test", parameters=[], tags=["prod"])
        d = ps.to_dict()
        assert d["id"] == "abc"
        assert d["tags"] == ["prod"]


class TestParameterExtractor:
    def test_extract_named_basic(self):
        ext = ParameterExtractor()
        params = ext.extract_named("SELECT * FROM orders WHERE user_id = $1 AND status = $2")
        assert len(params) == 2
        assert params[0].name == "user_id"
        assert params[0].position == 1
        assert params[1].name == "status"
        assert params[1].position == 2

    def test_extract_named_no_context(self):
        ext = ParameterExtractor()
        params = ext.extract_named("SELECT $1, $2")
        assert len(params) == 2
        assert params[0].name == "param_1"
        assert params[1].name == "param_2"

    def test_extract_named_no_params(self):
        ext = ParameterExtractor()
        assert ext.extract_named("SELECT * FROM t") == []

    def test_normalize_query(self):
        ext = ParameterExtractor()
        norm, params = ext.normalize_query("SELECT * FROM t WHERE id = $1")
        assert "$id" in norm
        assert "$1" not in norm
        assert len(params) == 1

    def test_normalize_preserves_non_params(self):
        ext = ParameterExtractor()
        sql = "SELECT * FROM t WHERE active = true"
        norm, params = ext.normalize_query(sql)
        assert params == []
        assert norm == sql

    def test_from_sample_with_template(self):
        ext = ParameterExtractor()
        ps = ext.from_sample(
            query="SELECT * FROM orders WHERE id = 42 AND status = 'pending'",
            template="SELECT * FROM orders WHERE id = $1 AND status = $2",
        )
        assert isinstance(ps, ParameterSet)
        vals = ps.values_dict()
        assert vals["id"] == 42
        assert vals["status"] == "pending"

    def test_from_sample_inline(self):
        ext = ParameterExtractor()
        ps = ext.from_sample("SELECT * FROM t WHERE name = 'alice' AND age = 30")
        vals = ps.values_dict()
        assert vals["name"] == "alice"
        assert vals["age"] == 30

    def test_from_sample_boolean_and_float(self):
        ext = ParameterExtractor()
        ps = ext.from_sample("SELECT * FROM t WHERE active = true AND score = 3.14")
        vals = ps.values_dict()
        assert vals["active"] is True
        assert vals["score"] == pytest.approx(3.14)

    def test_from_samples(self):
        ext = ParameterExtractor()
        samples = [
            {"parameters": {"id": 1, "name": "a"}, "timestamp": "2026-01-01"},
            {"query": "SELECT * FROM t WHERE x = 99"},
        ]
        results = ext.from_samples(samples)
        assert len(results) == 2
        assert results[0].values_dict()["id"] == 1

    def test_build_query_text(self):
        ext = ParameterExtractor()
        _, params = ext.normalize_query("SELECT * FROM t WHERE name = $1")
        ps = ParameterSet(
            id="t",
            name="test",
            parameters=[QueryParameter(name="name", position=1, value="alice", pg_type="text")],
        )
        result = ext.build_query("SELECT * FROM t WHERE name = $name", ps)
        assert "'alice'" in result

    def test_build_query_integer(self):
        ext = ParameterExtractor()
        ps = ParameterSet(
            id="t",
            name="test",
            parameters=[QueryParameter(name="id", position=1, value=42, pg_type="integer")],
        )
        result = ext.build_query("SELECT * FROM t WHERE id = $1", ps)
        assert "42" in result

    def test_build_query_jsonb(self):
        ext = ParameterExtractor()
        ps = ParameterSet(
            id="t",
            name="test",
            parameters=[QueryParameter(name="data", position=1, value={"key": "val"}, pg_type="jsonb")],
        )
        result = ext.build_query("SELECT * FROM t WHERE data = $1", ps)
        assert "::jsonb" in result

    def test_build_query_null(self):
        ext = ParameterExtractor()
        ps = ParameterSet(
            id="t",
            name="test",
            parameters=[QueryParameter(name="x", position=1, value=None, pg_type="text")],
        )
        result = ext.build_query("SELECT * FROM t WHERE x = $1", ps)
        assert "NULL" in result

    def test_infer_pg_type(self):
        ext = ParameterExtractor()
        assert ext._infer_pg_type(True) == "boolean"
        assert ext._infer_pg_type(42) == "integer"
        assert ext._infer_pg_type(3.14) == "numeric"
        assert ext._infer_pg_type([1, 2]) == "jsonb"
        assert ext._infer_pg_type("hello") == "text"

    def test_comparison_operators(self):
        ext = ParameterExtractor()
        params = ext.extract_named("SELECT * FROM t WHERE price >= $1 AND qty < $2")
        names = [p.name for p in params]
        assert "price" in names
        assert "qty" in names


# ======================================================================
# 2. Oracle Hint Translator
# ======================================================================

from querysense.migration.hint_translator import (
    Confidence,
    HintTranslation,
    HintType,
    OracleHintTranslator,
)


class TestHintTranslation:
    def test_to_dict(self):
        t = HintTranslation(
            original="FULL(t)",
            pg_hint="SeqScan(t)",
            hint_type=HintType.ACCESS_PATH,
            confidence=Confidence.HIGH,
        )
        d = t.to_dict()
        assert d["pg_hint"] == "SeqScan(t)"
        assert d["confidence"] == "high"
        assert d["hint_type"] == "access_path"


class TestOracleHintTranslator:
    def setup_method(self):
        self.t = OracleHintTranslator()

    # ── Access path hints ─────────────────────────────────────────

    def test_full(self):
        r = self.t.translate_hint("FULL(orders)")
        assert r.pg_hint == "SeqScan(orders)"
        assert r.confidence == Confidence.HIGH

    def test_index(self):
        r = self.t.translate_hint("INDEX(t idx_t_col)")
        assert r.pg_hint == "IndexScan(t idx_t_col)"
        assert r.confidence == Confidence.HIGH

    def test_index_ffs(self):
        r = self.t.translate_hint("INDEX_FFS(t idx_cover)")
        assert "IndexOnlyScan" in r.pg_hint
        assert r.confidence == Confidence.MEDIUM

    def test_index_desc_unsupported(self):
        r = self.t.translate_hint("INDEX_DESC(t idx_1)")
        assert r.status == "unsupported"
        assert r.confidence == Confidence.LOW

    def test_no_index_unsupported(self):
        r = self.t.translate_hint("NO_INDEX(t)")
        assert r.status == "unsupported"

    def test_index_join_unsupported(self):
        r = self.t.translate_hint("INDEX_JOIN(t)")
        assert r.status == "unsupported"

    # ── Join operation hints ──────────────────────────────────────

    def test_use_nl(self):
        r = self.t.translate_hint("USE_NL(t u)")
        assert r.pg_hint == "NestLoop(t u)"
        assert r.confidence == Confidence.HIGH

    def test_use_hash(self):
        r = self.t.translate_hint("USE_HASH(t u)")
        assert r.pg_hint == "HashJoin(t u)"

    def test_use_merge(self):
        r = self.t.translate_hint("USE_MERGE(t u)")
        assert r.pg_hint == "MergeJoin(t u)"

    def test_no_use_nl(self):
        r = self.t.translate_hint("NO_USE_NL(t u)")
        assert r.pg_hint == "NoNestLoop(t u)"

    def test_no_use_hash(self):
        r = self.t.translate_hint("NO_USE_HASH(t u)")
        assert r.pg_hint == "NoHashJoin(t u)"

    def test_no_use_merge(self):
        r = self.t.translate_hint("NO_USE_MERGE(t u)")
        assert r.pg_hint == "NoMergeJoin(t u)"

    def test_use_nl_with_index(self):
        r = self.t.translate_hint("USE_NL_WITH_INDEX(orders idx_orders_id)")
        assert "NestLoop" in r.pg_hint
        assert "IndexScan" in r.pg_hint
        assert r.confidence == Confidence.MEDIUM

    # ── Join order hints ──────────────────────────────────────────

    def test_ordered(self):
        r = self.t.translate_hint("ORDERED")
        assert r.pg_hint == "Set(join_collapse_limit 1)"

    def test_leading(self):
        r = self.t.translate_hint("LEADING(a b c)")
        assert r.pg_hint == "Leading(a b c)"

    # ── Parallel hints ────────────────────────────────────────────

    def test_parallel_with_degree(self):
        r = self.t.translate_hint("PARALLEL(t 4)")
        assert "Parallel(t 4 hard)" == r.pg_hint

    def test_parallel_without_degree(self):
        r = self.t.translate_hint("PARALLEL(t)")
        assert r.pg_hint == "Parallel(t)"

    def test_no_parallel(self):
        r = self.t.translate_hint("NO_PARALLEL(t)")
        assert r.pg_hint == "Parallel(t 0)"

    # ── GUC parameter ─────────────────────────────────────────────

    def test_opt_param(self):
        r = self.t.translate_hint("OPT_PARAM(work_mem 256MB)")
        assert r.pg_hint == "Set(work_mem 256MB)"

    # ── Unsupported hints ─────────────────────────────────────────

    def test_unsupported_hints(self):
        for hint in ["UNNEST", "NO_UNNEST", "RESULT_CACHE", "DYNAMIC_SAMPLING", "QB_NAME"]:
            r = self.t.translate_hint(hint)
            assert r.status == "unsupported", f"{hint} should be unsupported"

    def test_unknown_hint(self):
        r = self.t.translate_hint("TOTALLY_MADE_UP(x)")
        assert r.status == "unknown"

    # ── Full query translation ────────────────────────────────────

    def test_translate_query_basic(self):
        sql = "SELECT /*+ FULL(t) USE_HASH(t u) */ * FROM orders t JOIN users u ON t.uid = u.id"
        result = self.t.translate_query(sql)
        assert "SeqScan(t)" in result.translated_query
        assert "HashJoin(t u)" in result.translated_query
        assert result.total == 2
        assert result.high_confidence == 2
        assert result.coverage_pct == 100.0

    def test_translate_query_mixed(self):
        sql = "SELECT /*+ FULL(t) RESULT_CACHE */ * FROM t"
        result = self.t.translate_query(sql)
        assert result.total == 2
        assert result.unsupported == 1
        assert result.high_confidence == 1
        assert result.coverage_pct == 50.0

    def test_translate_query_no_hints(self):
        sql = "SELECT * FROM orders"
        result = self.t.translate_query(sql)
        assert result.translated_query == sql
        assert result.total == 0

    def test_translate_query_all_unsupported(self):
        sql = "SELECT /*+ UNNEST NO_UNNEST */ * FROM t"
        result = self.t.translate_query(sql)
        assert result.unsupported == 2
        assert "/*+" not in result.translated_query

    def test_query_translation_to_dict(self):
        sql = "SELECT /*+ FULL(t) */ * FROM t"
        result = self.t.translate_query(sql)
        d = result.to_dict()
        assert "summary" in d
        assert d["summary"]["total"] == 1

    def test_use_concat_alternative(self):
        r = self.t.translate_hint("USE_CONCAT")
        assert r.status == "unsupported"
        assert any("UNION ALL" in a for a in r.alternatives)


# ======================================================================
# 3. Enhanced Plan Diff
# ======================================================================

from querysense.tuning.plan_diff import (
    EnhancedPlanDiff,
    PlanDiffResult,
    PlanNode,
    StructuralChange,
)


class TestPlanNode:
    def test_label_basic(self):
        n = PlanNode(node_type="Seq Scan", relation="orders")
        assert n.label == "Seq Scan on orders"

    def test_label_with_index(self):
        n = PlanNode(node_type="Index Scan", relation="orders", index_name="idx_orders_id")
        assert "using idx_orders_id" in n.label

    def test_total_buffers(self):
        n = PlanNode(node_type="Seq Scan", buffers_hit=100, buffers_read=20)
        assert n.total_buffers == 120


class TestStructuralChange:
    def test_to_dict_replace(self):
        c = StructuralChange("replace", ["-> Seq Scan"], ["-> Index Scan"])
        d = c.to_dict()
        assert d["type"] == "replace"
        assert "from" in d and "to" in d

    def test_to_dict_insert(self):
        c = StructuralChange("insert", to_lines=["-> Sort"])
        d = c.to_dict()
        assert "from" not in d
        assert d["to"] == ["-> Sort"]


class TestPlanDiffResult:
    def test_is_same_shape(self):
        r = PlanDiffResult()
        assert r.is_same_shape is True
        r.structural_changes.append(StructuralChange("replace"))
        assert r.is_same_shape is False

    def test_to_dict(self):
        r = PlanDiffResult(similarity_score=85.0, nodes_a=5, nodes_b=5)
        d = r.to_dict()
        assert d["similarity_score"] == 85.0

    def test_to_markdown(self):
        r = PlanDiffResult(
            similarity_score=80.0,
            nodes_a=3,
            nodes_b=3,
            metric_diffs={"execution_time_pct": -25.0},
            structural_changes=[StructuralChange("replace", ["-> Seq Scan on t"], ["-> Index Scan on t"])],
        )
        md = r.to_markdown()
        assert "80.0%" in md
        assert "faster" in md
        assert "Replaced" in md


class TestEnhancedPlanDiff:
    def setup_method(self):
        self.d = EnhancedPlanDiff()

    # ── JSON parsing ──────────────────────────────────────────────

    def test_parse_json_dict(self):
        plan = {
            "Plan": {
                "Node Type": "Seq Scan",
                "Relation Name": "orders",
                "Total Cost": 100.0,
                "Plan Rows": 1000,
            }
        }
        node = self.d.parse(plan)
        assert node.node_type == "Seq Scan"
        assert node.relation == "orders"

    def test_parse_json_list(self):
        plan = [{"Plan": {"Node Type": "Hash Join", "Plans": [
            {"Node Type": "Seq Scan", "Relation Name": "a"},
            {"Node Type": "Index Scan", "Relation Name": "b", "Index Name": "idx_b"},
        ]}}]
        node = self.d.parse(plan)
        assert node.node_type == "Hash Join"
        assert len(node.children) == 2

    def test_parse_json_string(self):
        plan_json = json.dumps([{"Plan": {"Node Type": "Seq Scan", "Relation Name": "t"}}])
        node = self.d.parse(plan_json)
        assert node.node_type == "Seq Scan"

    # ── Normalization ─────────────────────────────────────────────

    def test_normalize_strips_costs(self):
        node = PlanNode(
            node_type="Seq Scan",
            relation="t",
            cost_total=999,
            actual_time=50.0,
        )
        norm = self.d.normalize(node)
        assert "999" not in norm
        assert "50" not in norm
        assert "Seq Scan on t" in norm

    def test_normalize_children_sorted(self):
        parent = PlanNode(
            node_type="Merge Join",
            children=[
                PlanNode(node_type="Sort"),
                PlanNode(node_type="Index Scan", relation="b"),
            ],
        )
        norm = self.d.normalize(parent)
        lines = norm.strip().split("\n")
        assert "Index Scan" in lines[1]  # alphabetically first
        assert "Sort" in lines[2]

    # ── Fingerprinting ────────────────────────────────────────────

    def test_fingerprint_same_shape(self):
        a = PlanNode(node_type="Seq Scan", relation="t", cost_total=100)
        b = PlanNode(node_type="Seq Scan", relation="t", cost_total=999)
        assert self.d.fingerprint(a) == self.d.fingerprint(b)

    def test_fingerprint_different_shape(self):
        a = PlanNode(node_type="Seq Scan", relation="t")
        b = PlanNode(node_type="Index Scan", relation="t")
        assert self.d.fingerprint(a) != self.d.fingerprint(b)

    # ── Diff ──────────────────────────────────────────────────────

    def test_diff_identical_plans(self):
        plan = {"Plan": {"Node Type": "Seq Scan", "Relation Name": "t", "Total Cost": 100}}
        result = self.d.diff(plan, plan)
        assert result.is_same_shape
        assert result.similarity_score == 100.0

    def test_diff_different_scan(self):
        a = {"Plan": {"Node Type": "Seq Scan", "Relation Name": "t", "Total Cost": 100}}
        b = {"Plan": {"Node Type": "Index Scan", "Relation Name": "t", "Total Cost": 10, "Index Name": "idx_t"}}
        result = self.d.diff(a, b)
        assert not result.is_same_shape
        assert result.similarity_score < 100
        assert len(result.structural_changes) > 0

    def test_diff_metric_change(self):
        a = {"Plan": {"Node Type": "Seq Scan", "Relation Name": "t", "Total Cost": 100, "Actual Total Time": 50.0}}
        b = {"Plan": {"Node Type": "Seq Scan", "Relation Name": "t", "Total Cost": 50, "Actual Total Time": 25.0}}
        result = self.d.diff(a, b)
        assert result.is_same_shape
        assert result.metric_diffs.get("cost_pct", 0) < 0  # cheaper

    def test_diff_added_node(self):
        a = {"Plan": {"Node Type": "Seq Scan", "Relation Name": "t"}}
        b = {"Plan": {"Node Type": "Sort", "Plans": [
            {"Node Type": "Seq Scan", "Relation Name": "t"},
        ]}}
        result = self.d.diff(a, b)
        assert not result.is_same_shape
        assert result.nodes_b > result.nodes_a

    def test_diff_complex_join_reorder(self):
        a = {"Plan": {"Node Type": "Hash Join", "Plans": [
            {"Node Type": "Seq Scan", "Relation Name": "orders"},
            {"Node Type": "Hash", "Plans": [
                {"Node Type": "Seq Scan", "Relation Name": "users"},
            ]},
        ]}}
        b = {"Plan": {"Node Type": "Merge Join", "Plans": [
            {"Node Type": "Sort", "Plans": [
                {"Node Type": "Seq Scan", "Relation Name": "orders"},
            ]},
            {"Node Type": "Sort", "Plans": [
                {"Node Type": "Seq Scan", "Relation Name": "users"},
            ]},
        ]}}
        result = self.d.diff(a, b)
        assert not result.is_same_shape
        assert result.similarity_score < 80

    def test_diff_with_buffers(self):
        a = {"Plan": {
            "Node Type": "Seq Scan", "Relation Name": "t",
            "Shared Hit Blocks": 100, "Shared Read Blocks": 50,
        }}
        b = {"Plan": {
            "Node Type": "Seq Scan", "Relation Name": "t",
            "Shared Hit Blocks": 80, "Shared Read Blocks": 10,
        }}
        result = self.d.diff(a, b)
        assert "buffers_pct" in result.metric_diffs
        assert result.metric_diffs["buffers_pct"] < 0  # fewer buffers

    def test_diff_to_dict(self):
        a = {"Plan": {"Node Type": "Seq Scan", "Relation Name": "t"}}
        b = {"Plan": {"Node Type": "Index Scan", "Relation Name": "t"}}
        result = self.d.diff(a, b)
        d = result.to_dict()
        assert "similarity_score" in d
        assert "structural_changes" in d

    def test_diff_prebuilt_nodes(self):
        a = PlanNode(node_type="Seq Scan", relation="t")
        b = PlanNode(node_type="Seq Scan", relation="t")
        result = self.d.diff(a, b)
        assert result.is_same_shape

    def test_count_nodes(self):
        root = PlanNode(
            node_type="Hash Join",
            children=[
                PlanNode(node_type="Seq Scan"),
                PlanNode(node_type="Hash", children=[PlanNode(node_type="Seq Scan")]),
            ],
        )
        assert self.d._count_nodes(root) == 4

    def test_empty_plan(self):
        result = self.d.diff({"Plan": {"Node Type": "Result"}}, {"Plan": {"Node Type": "Result"}})
        assert result.similarity_score == 100.0
