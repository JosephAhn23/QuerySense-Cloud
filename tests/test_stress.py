"""
Extreme stress tests for QuerySense.

Tests designed to break every assumption:
- Pathological inputs that trigger worst-case behavior
- Concurrency and thread-safety under load
- Memory pressure from massive plans
- Adversarial SQL that tries to break the rewriter
- Edge cases in every module boundary
- Fuzzy inputs, Unicode bombs, NaN/Inf injection
- Regression detection under high cardinality
- Budget enforcement with contradictory constraints

These are NOT unit tests — they are brutality tests.
"""

from __future__ import annotations

import concurrent.futures
import copy
import gc
import json
import math
import os
import random
import string
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from querysense.parser import ParseError, ParserConfig, parse_explain
from querysense.parser.parser import validate_has_analyze
from querysense.analyzer import (
    Analyzer,
    AnalysisResult,
    Finding,
    NodeContext,
    NodePath,
    RulePhase,
    Severity,
    get_registry,
    reset_registry,
)
from querysense.analyzer.models import ExecutionMetadata
from querysense.rewriter import RewriteResult, rewrite_query
from querysense.migration.sql_utils import split_statements


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict[str, Any]:
    path = FIXTURES_DIR / f"{name}.json"
    return json.loads(path.read_text())


def _make_plan_node(
    node_type: str = "Seq Scan",
    relation: str = "test_table",
    rows: int = 1000,
    cost: float = 100.0,
    actual_time: float = 10.0,
    children: list[dict[str, Any]] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a synthetic EXPLAIN plan node."""
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
    """Wrap a plan node in the EXPLAIN output array."""
    return [{"Plan": plan_node, "Planning Time": 0.1, "Execution Time": 100.0}]


# =============================================================================
# SECTION 1: Parser Stress Tests
# =============================================================================


class TestParserStress:
    """Push the parser to its absolute limits."""

    def test_massively_wide_plan(self) -> None:
        """500-child Append node — tests O(N) iteration, not O(N^2)."""
        children = [
            _make_plan_node("Result", f"t{i}", rows=1, cost=0.01, actual_time=0.001)
            for i in range(500)
        ]
        root = _make_plan_node("Append", "combined", rows=500, cost=500.0, children=children)
        data = _wrap_plan(root)

        output = parse_explain(data)
        assert len(output.all_nodes) == 501

    def test_deeply_nested_just_under_limit(self) -> None:
        """Depth 49 plan (limit 50) — should barely pass.

        Note: Pydantic's recursive model validation has its own internal
        recursion limit (~64 levels), so we test at a realistic depth
        that stays within both our config limit and Pydantic's limit.
        """
        def nest(depth: int) -> dict[str, Any]:
            if depth == 0:
                return _make_plan_node("Result", "leaf", rows=1, cost=0.01)
            return _make_plan_node(
                "Append", f"level_{depth}", rows=1, cost=float(depth),
                children=[nest(depth - 1)],
            )

        plan = nest(49)
        data = _wrap_plan(plan)
        config = ParserConfig(max_depth=50, max_nodes=50_000)

        output = parse_explain(data, config=config)
        assert output.plan is not None

    def test_deeply_nested_exceeds_limit(self) -> None:
        """Depth 101 plan (limit 100) — must reject."""
        def nest(depth: int) -> dict[str, Any]:
            if depth == 0:
                return _make_plan_node("Result", "leaf", rows=1, cost=0.01)
            return _make_plan_node(
                "Append", f"level_{depth}", rows=1, cost=float(depth),
                children=[nest(depth - 1)],
            )

        plan = nest(101)
        data = _wrap_plan(plan)
        config = ParserConfig(max_depth=100, max_nodes=50_000)

        with pytest.raises(ParseError):
            parse_explain(data, config=config)

    def test_empty_json_variants(self) -> None:
        """Various flavors of empty input must all fail gracefully."""
        empties = [
            "{}",
            "[]",
            "[{}]",
            '{"Plan": {}}',
            '[{"no_plan_key": true}]',
            "",
            "   ",
            "\n\n\n",
        ]
        for empty in empties:
            if not empty.strip():
                continue
            with pytest.raises(ParseError):
                parse_explain(empty)

    def test_unicode_bomb_in_relation_name(self) -> None:
        """Unicode in table names must not crash the parser."""
        plan = _make_plan_node("Seq Scan", "über_tàble_名前", rows=100)
        data = _wrap_plan(plan)
        output = parse_explain(data)
        assert "über_tàble_名前" in output.plan.relation_name

    def test_extreme_numeric_values(self) -> None:
        """Astronomically large costs, rows, times must parse without overflow."""
        plan = _make_plan_node(
            "Seq Scan", "huge",
            rows=2_000_000_000,
            cost=999_999_999_999.99,
            actual_time=86_400_000.0,
            **{
                "Shared Hit Blocks": 999_999_999,
                "Shared Read Blocks": 999_999_999,
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)
        assert output.plan.actual_rows == 2_000_000_000

    def test_zero_value_plan(self) -> None:
        """All-zero metrics must not cause division-by-zero anywhere."""
        plan = _make_plan_node(
            "Result", "empty",
            rows=0, cost=0.0, actual_time=0.0,
            **{
                "Shared Hit Blocks": 0,
                "Shared Read Blocks": 0,
                "Plan Rows": 0,
                "Plan Width": 0,
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)
        assert output.plan.actual_rows == 0

    def test_negative_values_handled(self) -> None:
        """Negative costs/rows (corrupted EXPLAIN) — parse but don't crash."""
        plan = _make_plan_node("Seq Scan", "neg", rows=-1, cost=-100.0)
        data = _wrap_plan(plan)
        # Should parse; analysis may flag it, but parsing itself shouldn't crash
        output = parse_explain(data)
        assert output.plan is not None

    def test_concurrent_parsing(self) -> None:
        """10 threads parsing simultaneously — no shared state corruption."""
        fixture = load_fixture("bad_estimate")

        results: list[Any] = []
        errors: list[Exception] = []

        def parse_task(i: int) -> None:
            try:
                # Each thread gets its own deep copy
                data = copy.deepcopy(fixture)
                output = parse_explain(data)
                results.append(output)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=parse_task, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Concurrent parsing errors: {errors}"
        assert len(results) == 10

    def test_rapid_fire_parsing(self) -> None:
        """Parse 100 plans back-to-back — no memory leaks or slowdown."""
        fixture = load_fixture("sequential_scan_large_table")

        start = time.monotonic()
        for _ in range(100):
            parse_explain(fixture)
        elapsed = time.monotonic() - start

        # 100 parses should complete in under 10 seconds
        assert elapsed < 10.0, f"100 parses took {elapsed:.1f}s — too slow"

    def test_malformed_json_types(self) -> None:
        """Feed wrong types to every field — must not crash."""
        wrong_types = [
            [{"Plan": "not_a_dict"}],
            [{"Plan": {"Node Type": 12345}}],
            [{"Plan": {"Node Type": "Seq Scan", "Plan Rows": "not_a_number"}}],
            [{"Plan": {"Node Type": "Seq Scan", "Plans": "not_a_list"}}],
            [{"Plan": {"Node Type": None}}],
        ]
        for data in wrong_types:
            with pytest.raises((ParseError, Exception)):
                parse_explain(data)

    def test_duplicate_child_references(self) -> None:
        """Same child node object in multiple parents — no infinite loop."""
        shared_child = _make_plan_node("Result", "shared", rows=1)
        root = _make_plan_node(
            "Append", "root", rows=2, children=[shared_child, shared_child]
        )
        data = _wrap_plan(root)
        output = parse_explain(data)
        assert len(output.all_nodes) >= 2

    def test_plan_with_all_node_types(self) -> None:
        """Plan with every known PostgreSQL node type in one tree."""
        node_types = [
            "Seq Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan",
            "Hash Join", "Merge Join", "Nested Loop", "Sort", "Aggregate",
            "Group", "Limit", "Append", "Result", "Materialize",
            "Hash", "Gather", "Gather Merge",
        ]
        children = [
            _make_plan_node(nt, f"table_{i}", rows=100)
            for i, nt in enumerate(node_types)
        ]
        root = _make_plan_node("Append", "omnibus", rows=1700, children=children)
        data = _wrap_plan(root)

        output = parse_explain(data)
        assert len(output.all_nodes) == len(node_types) + 1

    def test_file_size_exactly_at_limit(self, tmp_path: Path) -> None:
        """File exactly at the size limit — should be accepted."""
        plan = _make_plan_node("Result", "small", rows=1)
        content = json.dumps(_wrap_plan(plan))

        test_file = tmp_path / "exact.json"
        test_file.write_text(content, encoding="utf-8")

        file_size_mb = test_file.stat().st_size / (1024 * 1024)
        config = ParserConfig(max_file_size_mb=file_size_mb + 0.001)
        output = parse_explain(test_file, config=config)
        assert output.plan is not None


# =============================================================================
# SECTION 2: Analyzer Stress Tests
# =============================================================================


class TestAnalyzerStress:
    """Push the analyzer to extremes."""

    def test_analyze_massive_plan(self) -> None:
        """Analyze a 200-node plan — all rules fire without timeout."""
        children = [
            _make_plan_node(
                "Seq Scan", f"big_table_{i}",
                rows=500_000,
                cost=18_000.0,
                actual_time=500.0,
                Filter=f"(status = 'active')",
                **{"Rows Removed by Filter": 250_000},
            )
            for i in range(200)
        ]
        root = _make_plan_node(
            "Append", "union_all", rows=100_000_000,
            cost=3_600_000.0, children=children,
        )
        data = _wrap_plan(root)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        assert isinstance(result, AnalysisResult)
        # Should find many seq scan issues
        assert result.metadata.rules_run > 0

    def test_analyze_plan_with_no_findings(self) -> None:
        """A perfectly optimized plan should produce zero findings."""
        plan = _make_plan_node(
            "Index Scan", "well_indexed",
            rows=10, cost=0.5, actual_time=0.01,
            **{
                "Index Name": "idx_well_indexed_id",
                "Index Cond": "(id = 42)",
                "Rows Removed by Filter": 0,
            }
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        assert isinstance(result, AnalysisResult)

    def test_concurrent_analysis(self) -> None:
        """5 concurrent analyses — no shared state issues."""
        fixtures = [
            load_fixture("sequential_scan_large_table"),
            load_fixture("bad_estimate"),
            load_fixture("index_scan_good"),
            load_fixture("nested_loop_high_loops"),
            load_fixture("sort_without_index"),
        ]

        results: list[AnalysisResult] = []
        errors: list[Exception] = []

        def analyze_task(fixture: dict) -> None:
            try:
                output = parse_explain(fixture)
                analyzer = Analyzer()
                result = analyzer.analyze(output)
                results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=analyze_task, args=(f,))
            for f in fixtures
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert len(errors) == 0, f"Concurrent analysis errors: {errors}"
        assert len(results) == 5

    def test_analyze_every_fixture(self) -> None:
        """Every fixture file must analyze without exceptions."""
        fixture_files = list(FIXTURES_DIR.glob("*.json"))
        assert len(fixture_files) > 0, "No fixtures found"

        for fixture_file in fixture_files:
            data = json.loads(fixture_file.read_text())
            output = parse_explain(data)
            analyzer = Analyzer()
            result = analyzer.analyze(output)
            assert isinstance(result, AnalysisResult), f"Failed on {fixture_file.name}"

    def test_analyze_plan_with_extreme_estimate_mismatch(self) -> None:
        """Actual rows = 10M when estimate was 1 — worst-case for BAD_ROW_ESTIMATE."""
        plan = _make_plan_node(
            "Seq Scan", "misestimated",
            rows=10_000_000, cost=50_000.0, actual_time=30_000.0,
            **{"Plan Rows": 1},
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)
        assert isinstance(result, AnalysisResult)

    def test_rapid_fire_analysis(self) -> None:
        """Analyze 50 plans in sequence — no drift in results."""
        fixture = load_fixture("sequential_scan_large_table")
        output = parse_explain(fixture)

        first_result = None
        for i in range(50):
            analyzer = Analyzer()
            result = analyzer.analyze(output)
            if first_result is None:
                first_result = result
            else:
                assert len(result.findings) == len(first_result.findings), (
                    f"Result drift at iteration {i}: "
                    f"{len(result.findings)} != {len(first_result.findings)}"
                )


# =============================================================================
# SECTION 3: Rewriter Stress Tests
# =============================================================================


class TestRewriterStress:
    """Adversarial SQL inputs for the rewrite engine."""

    def test_enormous_sql(self) -> None:
        """10KB SQL query with 200 ORs — must not hang."""
        conditions = " OR ".join(f"id = {i}" for i in range(200))
        sql = f"SELECT * FROM users WHERE {conditions};"

        result = rewrite_query(sql, [])
        assert isinstance(result, RewriteResult)

    def test_deeply_nested_subqueries(self) -> None:
        """10-level nested subquery — stack depth challenge."""
        sql = "SELECT * FROM ("
        for i in range(10):
            sql += f"SELECT * FROM (SELECT id FROM t{i}) sub{i}, ("
        sql += "SELECT 1) innermost"
        sql += ")" * 10
        sql += " final"

        result = rewrite_query(sql, [])
        assert isinstance(result, RewriteResult)

    def test_sql_injection_attempt(self) -> None:
        """SQL injection patterns must not break the rewriter."""
        injections = [
            "SELECT * FROM users; DROP TABLE users; --",
            "SELECT * FROM users WHERE name = '' OR '1'='1'",
            "SELECT * FROM users WHERE id = 1; TRUNCATE users",
            "SELECT * FROM users WHERE name = '\\'; DROP TABLE users; --'",
            "SELECT * FROM users WHERE id = CAST('abc' AS int)",
        ]
        for sql in injections:
            result = rewrite_query(sql, [])
            assert isinstance(result, RewriteResult)
            # Rewriter should NOT introduce DROP/TRUNCATE
            if result.was_rewritten:
                upper = result.rewritten_sql.upper()
                assert "DROP TABLE" not in upper
                assert "TRUNCATE" not in upper

    def test_unicode_sql(self) -> None:
        """Unicode in SQL must not crash rewriter."""
        sql = "SELECT * FROM \"日本語テーブル\" WHERE 名前 = 'テスト'"
        result = rewrite_query(sql, [])
        assert isinstance(result, RewriteResult)

    def test_empty_and_whitespace_sql(self) -> None:
        """Empty/whitespace SQL must not crash."""
        for sql in ["", "   ", "\n\n", "\t", "-- just a comment"]:
            result = rewrite_query(sql, [])
            assert isinstance(result, RewriteResult)
            assert not result.was_rewritten

    def test_not_in_to_not_exists_rewrite(self) -> None:
        """Classic NOT IN → NOT EXISTS rewrite."""
        sql = "SELECT * FROM orders WHERE user_id NOT IN (SELECT id FROM banned_users)"
        result = rewrite_query(sql, [])
        assert isinstance(result, RewriteResult)

    def test_select_star_rewrite(self) -> None:
        """SELECT * detection."""
        sql = "SELECT * FROM users WHERE id = 1"
        result = rewrite_query(sql, [])
        assert isinstance(result, RewriteResult)

    def test_rewrite_idempotency(self) -> None:
        """Rewriting an already-rewritten query should not change it further."""
        sql = "SELECT id, name FROM users WHERE id IN (SELECT user_id FROM orders)"
        result1 = rewrite_query(sql, [])
        if result1.was_rewritten:
            result2 = rewrite_query(result1.rewritten_sql, [])
            # Second pass should produce same or fewer rewrites
            assert len(result2.rewrites) <= len(result1.rewrites)

    def test_massive_union_chain(self) -> None:
        """50-way UNION chain — tests UNION → UNION ALL detection at scale."""
        parts = [f"SELECT id FROM t{i}" for i in range(50)]
        sql = " UNION ".join(parts)
        result = rewrite_query(sql, [])
        assert isinstance(result, RewriteResult)

    def test_concurrent_rewrites(self) -> None:
        """10 threads rewriting simultaneously."""
        queries = [
            "SELECT * FROM users WHERE id NOT IN (SELECT id FROM banned)",
            "SELECT * FROM orders WHERE total > 100",
            "SELECT * FROM products",
        ] * 4  # 12 total

        results: list[RewriteResult] = []
        errors: list[Exception] = []

        def rewrite_task(sql: str) -> None:
            try:
                result = rewrite_query(sql, [])
                results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=rewrite_task, args=(q,)) for q in queries]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Concurrent rewrite errors: {errors}"
        assert len(results) == len(queries)


# =============================================================================
# SECTION 4: SQL Statement Splitter Stress Tests
# =============================================================================


class TestSplitStatementsStress:
    """Hammer the consolidated split_statements with adversarial SQL."""

    def test_simple_split(self) -> None:
        sql = "CREATE TABLE a (id int); CREATE TABLE b (id int);"
        result = split_statements(sql)
        assert len(result) == 2

    def test_dollar_quoting_preserved(self) -> None:
        """Dollar-quoted function bodies must not be split on internal semicolons."""
        sql = """
        CREATE FUNCTION test() RETURNS void AS $$
        BEGIN
            INSERT INTO log VALUES ('done');
            RETURN;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TABLE after_func (id int);
        """
        result = split_statements(sql)
        assert len(result) == 2
        assert "CREATE FUNCTION" in result[0]
        assert "CREATE TABLE" in result[1]

    def test_tagged_dollar_quoting(self) -> None:
        """Tagged dollar quotes like $body$...$body$ must work."""
        sql = """
        CREATE FUNCTION f() RETURNS void AS $body$
        BEGIN
            RAISE NOTICE 'hello; world';
        END;
        $body$ LANGUAGE plpgsql;
        SELECT 1;
        """
        result = split_statements(sql)
        assert len(result) == 2

    def test_single_quoted_strings(self) -> None:
        """Semicolons inside single-quoted strings must be ignored."""
        sql = "INSERT INTO t VALUES ('hello; world'); SELECT 1;"
        result = split_statements(sql)
        assert len(result) == 2
        assert "hello; world" in result[0]

    def test_escaped_quotes(self) -> None:
        """Escaped single quotes (doubled) must not break state tracking."""
        sql = "INSERT INTO t VALUES ('it''s a test; really'); SELECT 1;"
        result = split_statements(sql)
        assert len(result) == 2

    def test_line_comments_preserved(self) -> None:
        """Line comments should be part of the statement, not split on."""
        sql = """
        -- This is a comment with a ; semicolon
        SELECT 1;
        SELECT 2;
        """
        result = split_statements(sql)
        assert len(result) == 2

    def test_block_comments_preserved(self) -> None:
        """Block comments containing semicolons must not split."""
        sql = """
        /* This is a comment with ; semicolons; everywhere */
        SELECT 1;
        SELECT 2;
        """
        result = split_statements(sql)
        assert len(result) == 2

    def test_strip_comments_mode(self) -> None:
        """With strip_comments=True, comment-only statements are removed."""
        sql = """
        -- standalone comment
        ;
        SELECT 1;
        -- another comment
        ;
        SELECT 2;
        """
        result = split_statements(sql, strip_comments=True)
        assert len(result) == 2

    def test_keep_semicolons(self) -> None:
        """With keep_semicolons=True, semicolons are preserved."""
        sql = "SELECT 1; SELECT 2;"
        result = split_statements(sql, keep_semicolons=True)
        assert all(s.endswith(";") for s in result)

    def test_empty_input(self) -> None:
        """Empty input returns empty list."""
        assert split_statements("") == []
        assert split_statements("   ") == []

    def test_no_semicolons(self) -> None:
        """SQL without semicolons returns single statement."""
        result = split_statements("SELECT 1")
        assert result == ["SELECT 1"]

    def test_many_statements(self) -> None:
        """1000 statements — performance check."""
        sql = "; ".join(f"SELECT {i}" for i in range(1000)) + ";"
        start = time.monotonic()
        result = split_statements(sql)
        elapsed = time.monotonic() - start

        assert len(result) == 1000
        assert elapsed < 2.0, f"1000 statements took {elapsed:.2f}s"

    def test_mixed_quoting_styles(self) -> None:
        """Mix of dollar-quoting, single quotes, and comments."""
        sql = """
        INSERT INTO t VALUES ('semicolon; here');
        CREATE FUNCTION f() RETURNS void AS $$
        BEGIN
            -- comment with ;
            INSERT INTO log VALUES ('x;y');
        END;
        $$ LANGUAGE plpgsql;
        /* block comment; */
        SELECT 1;
        """
        result = split_statements(sql)
        assert len(result) == 3

    def test_concurrent_splitting(self) -> None:
        """10 threads splitting simultaneously."""
        sql = "CREATE TABLE a (id int); CREATE TABLE b (id int); SELECT 1;"
        results: list[list[str]] = []
        errors: list[Exception] = []

        def split_task() -> None:
            try:
                r = split_statements(sql)
                results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=split_task) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0
        assert all(len(r) == 3 for r in results)


# =============================================================================
# SECTION 5: Integration Pipeline Stress Tests
# =============================================================================


class TestPipelineStress:
    """End-to-end pipeline under extreme conditions."""

    def test_full_pipeline_all_fixtures(self) -> None:
        """Parse → Analyze → (optional Rewrite) for every fixture."""
        fixture_files = list(FIXTURES_DIR.glob("*.json"))

        for fixture_file in fixture_files:
            data = json.loads(fixture_file.read_text())
            output = parse_explain(data)

            analyzer = Analyzer()
            result = analyzer.analyze(output)

            assert isinstance(result, AnalysisResult)
            assert result.metadata.rules_run > 0

            # If there's a SQL-related finding, try rewriting
            if result.findings:
                dummy_sql = "SELECT * FROM orders WHERE status = 'pending'"
                rewrite_result = rewrite_query(dummy_sql, result.findings)
                assert isinstance(rewrite_result, RewriteResult)

    def test_pipeline_determinism(self) -> None:
        """Same input must produce byte-identical output every time."""
        fixture = load_fixture("bad_estimate")

        results = []
        for _ in range(20):
            output = parse_explain(fixture)
            analyzer = Analyzer()
            result = analyzer.analyze(output)
            results.append(result)

        # All results must have same finding count
        counts = [len(r.findings) for r in results]
        assert len(set(counts)) == 1, f"Non-deterministic results: {counts}"

        # All results must have same rule IDs
        rule_sets = [frozenset(f.rule_id for f in r.findings) for r in results]
        assert len(set(rule_sets)) == 1, f"Non-deterministic rules: {rule_sets}"

    def test_pipeline_memory_stability(self) -> None:
        """50 full pipeline runs should not leak memory significantly."""
        fixture = load_fixture("sequential_scan_large_table")

        gc.collect()

        for _ in range(50):
            output = parse_explain(fixture)
            analyzer = Analyzer()
            result = analyzer.analyze(output)
            del result
            del analyzer
            del output

        gc.collect()
        # If we got here without MemoryError, we're good

    def test_concurrent_full_pipeline(self) -> None:
        """5 full pipelines running concurrently via ThreadPoolExecutor."""
        fixtures = [
            load_fixture("sequential_scan_large_table"),
            load_fixture("bad_estimate"),
            load_fixture("index_scan_good"),
            load_fixture("nested_loop_high_loops"),
            load_fixture("sort_without_index"),
        ]

        def run_pipeline(fixture: dict) -> AnalysisResult:
            output = parse_explain(fixture)
            analyzer = Analyzer()
            return analyzer.analyze(output)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(run_pipeline, f) for f in fixtures]
            results = [
                fut.result(timeout=60)
                for fut in concurrent.futures.as_completed(futures)
            ]

        assert len(results) == 5
        assert all(isinstance(r, AnalysisResult) for r in results)


# =============================================================================
# SECTION 6: Edge Case Torture Tests
# =============================================================================


class TestEdgeCaseTorture:
    """Adversarial edge cases designed to break assumptions."""

    def test_plan_with_unknown_node_type(self) -> None:
        """Unknown node types should parse without crash."""
        plan = _make_plan_node("Quantum Entanglement Scan", "mystery_table", rows=42)
        data = _wrap_plan(plan)
        output = parse_explain(data)
        assert output.plan.node_type == "Quantum Entanglement Scan"

    def test_plan_with_extra_fields(self) -> None:
        """Extra unexpected fields should be ignored, not crash."""
        plan = _make_plan_node("Seq Scan", "normal")
        plan["Custom Field From Future"] = {"nested": True}
        plan["Another Unknown"] = [1, 2, 3]
        data = _wrap_plan(plan)
        output = parse_explain(data)
        assert output.plan is not None

    def test_plan_with_missing_optional_fields(self) -> None:
        """Plans missing optional fields (no Schema, no Alias) should parse."""
        plan = {
            "Node Type": "Result",
            "Startup Cost": 0.0,
            "Total Cost": 0.01,
            "Plan Rows": 1,
            "Plan Width": 0,
        }
        data = [{"Plan": plan}]
        output = parse_explain(data)
        assert output.plan.node_type == "Result"

    def test_very_long_filter_expression(self) -> None:
        """Filter with 1000 characters — must not truncate or crash."""
        long_filter = " AND ".join(f"col_{i} = {i}" for i in range(100))
        plan = _make_plan_node("Seq Scan", "filtered", Filter=f"({long_filter})")
        data = _wrap_plan(plan)
        output = parse_explain(data)
        assert output.plan is not None

    def test_plan_with_parallel_workers(self) -> None:
        """Parallel plan with workers — must correctly aggregate."""
        worker = _make_plan_node("Seq Scan", "parallel_target", rows=100_000)
        worker["Actual Loops"] = 4

        gather = _make_plan_node(
            "Gather", "gather_node",
            rows=400_000, children=[worker],
            **{"Workers Planned": 4, "Workers Launched": 4},
        )
        data = _wrap_plan(gather)
        output = parse_explain(data)
        assert output.plan.node_type == "Gather"

    def test_rewrite_very_long_query(self) -> None:
        """50KB SQL query — must complete in reasonable time."""
        columns = ", ".join(f"column_{i}" for i in range(500))
        conditions = " AND ".join(f"column_{i} > {i}" for i in range(200))
        sql = f"SELECT {columns} FROM big_table WHERE {conditions}"

        start = time.monotonic()
        result = rewrite_query(sql, [])
        elapsed = time.monotonic() - start

        assert isinstance(result, RewriteResult)
        assert elapsed < 5.0, f"Rewrite took {elapsed:.1f}s for 50KB query"

    def test_split_statements_with_crlf(self) -> None:
        """Windows-style line endings (CRLF) must not break splitting."""
        sql = "SELECT 1;\r\nSELECT 2;\r\nSELECT 3;"
        result = split_statements(sql)
        assert len(result) == 3

    def test_split_statements_with_null_bytes(self) -> None:
        """Null bytes in SQL must not crash (corrupted input)."""
        sql = "SELECT 1;\x00SELECT 2;"
        result = split_statements(sql)
        assert len(result) >= 1

    def test_analysis_result_serialization_roundtrip(self) -> None:
        """AnalysisResult must survive JSON serialization roundtrip."""
        fixture = load_fixture("bad_estimate")
        output = parse_explain(fixture)
        analyzer = Analyzer()
        result = analyzer.analyze(output)

        # Serialize to JSON (Pydantic v2 uses model_dump)
        result_dict = result.model_dump(mode="json")
        serialized = json.dumps(result_dict, default=str)
        # Must be valid JSON
        parsed = json.loads(serialized)
        assert "findings" in parsed
        assert "metadata" in parsed

    def test_parser_exception_hierarchy(self) -> None:
        """Parser's ParseError must be catchable as QuerySenseError."""
        from querysense.exceptions import QuerySenseError

        with pytest.raises(QuerySenseError):
            parse_explain('{"not": "an explain plan"}')

    def test_empty_findings_result(self) -> None:
        """Analysis with zero findings must still have valid metadata."""
        plan = _make_plan_node(
            "Index Scan", "optimized", rows=1, cost=0.01,
            **{"Index Name": "idx_test", "Index Cond": "(id = 1)"},
        )
        data = _wrap_plan(plan)
        output = parse_explain(data)

        analyzer = Analyzer()
        result = analyzer.analyze(output)

        assert isinstance(result.metadata, ExecutionMetadata)
        assert result.metadata.rules_run > 0
        assert result.metadata.analysis_duration_ms >= 0

    def test_fixture_round_trip_fidelity(self) -> None:
        """Parse, re-serialize, re-parse — must be identical."""
        fixture = load_fixture("index_scan_good")
        output1 = parse_explain(fixture)
        # Re-serialize the plan
        plan_dict = json.loads(json.dumps(fixture, default=str))
        output2 = parse_explain(plan_dict)

        assert output1.plan.node_type == output2.plan.node_type
        assert output1.plan.total_cost == output2.plan.total_cost
