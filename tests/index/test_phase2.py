"""
Tests for Phase 2 features: Scan Extractor, Greedy Solver, Index Consolidation,
HOT Guard integration, and Advisor fallback behavior.
"""

from __future__ import annotations

import pytest

from querysense.index.cp_model import (
    Goal,
    GoalName,
    Index,
    IndexSelectionProblem,
    Rule,
    RuleName,
    Scan,
    SolverSettings,
)

ortools_available = True
try:
    from ortools.sat.python import cp_model  # type: ignore[import-untyped]
except ImportError:
    ortools_available = False


# ---------------------------------------------------------------------------
# Scan Extractor Tests
# ---------------------------------------------------------------------------


class TestScanExtractor:
    """Tests for SQL-to-Scan extraction."""

    def test_extract_from_simple_sql(self) -> None:
        """Extract scans from a simple WHERE clause."""
        from querysense.index.scan_extractor import ScanExtractor

        extractor = ScanExtractor()
        result = extractor.extract_from_sql(
            "SELECT * FROM orders WHERE customer_id = 42 AND status = 'active'",
            table="orders",
        )

        assert len(result.scans) >= 1
        assert len(result.candidates) >= 1
        assert result.table == "orders"

    def test_extract_generates_single_and_composite_candidates(self) -> None:
        """Should generate both single-column and composite indexes."""
        from querysense.index.scan_extractor import ScanExtractor

        extractor = ScanExtractor()
        result = extractor.extract_from_sql(
            "SELECT * FROM orders WHERE customer_id = 42 AND status = 'active'",
            table="orders",
        )

        # Should have single-col (customer_id), (status) and composite (customer_id, status)
        column_sets = [c.columns for c in result.candidates]
        single_cols = [cs for cs in column_sets if len(cs) == 1]
        composite_cols = [cs for cs in column_sets if len(cs) >= 2]

        assert len(single_cols) >= 1
        assert len(composite_cols) >= 1

    def test_extract_from_multiple_queries(self) -> None:
        """Extract and merge scans from multiple queries."""
        from querysense.index.scan_extractor import ScanExtractor

        extractor = ScanExtractor()
        queries = [
            {"sql": "SELECT * FROM orders WHERE customer_id = 42", "frequency": 1000},
            {"sql": "SELECT * FROM orders WHERE status = 'active'", "frequency": 500},
        ]
        result = extractor.extract_from_queries(queries, table="orders")

        assert len(result.scans) >= 2
        # Candidates should be deduplicated
        ids = [c.id for c in result.candidates]
        assert len(ids) == len(set(ids))

    def test_extract_from_explain_plan(self) -> None:
        """Extract scans from EXPLAIN JSON."""
        from querysense.index.scan_extractor import ScanExtractor

        plan = [
            {
                "Plan": {
                    "Node Type": "Seq Scan",
                    "Relation Name": "orders",
                    "Filter": "(customer_id = 42)",
                    "Total Cost": 1500.0,
                    "Plan Rows": 100,
                    "Plans": [],
                }
            }
        ]

        extractor = ScanExtractor()
        result = extractor.extract_from_plan(plan)

        assert len(result.scans) == 1
        assert result.scans[0].sequential_cost == 1500
        assert len(result.candidates) >= 1

    def test_max_composite_width(self) -> None:
        """Respects max composite width."""
        from querysense.index.scan_extractor import ScanExtractor

        extractor = ScanExtractor(max_composite_width=2)
        result = extractor.extract_from_sql(
            "SELECT * FROM orders WHERE a = 1 AND b = 2 AND c = 3",
            table="orders",
        )

        for c in result.candidates:
            assert len(c.columns) <= 2


# ---------------------------------------------------------------------------
# Greedy Solver Tests
# ---------------------------------------------------------------------------


class TestGreedySolver:
    """Tests for the greedy fallback solver."""

    @pytest.fixture
    def simple_problem(self) -> IndexSelectionProblem:
        return IndexSelectionProblem(
            scans=[
                Scan(id="A", sequential_cost=100, index_costs={"idx1": 10, "idx2": 50}),
                Scan(id="B", sequential_cost=200, index_costs={"idx2": 20, "idx3": 30}),
            ],
            indexes=[
                Index(id="idx1", name="idx1", columns=("a",)),
                Index(id="idx2", name="idx2", columns=("b",)),
                Index(id="idx3", name="idx3", columns=("c",)),
            ],
            index_write_overheads={"idx1": 5, "idx2": 10, "idx3": 3},
            settings=SolverSettings.default(),
        )

    def test_greedy_finds_solution(self, simple_problem: IndexSelectionProblem) -> None:
        """Greedy solver should find a feasible solution."""
        from querysense.index.greedy_solver import GreedySolver

        solver = GreedySolver()
        solution = solver.solve(simple_problem)

        assert solution.status == "FEASIBLE"
        assert solution.total_cost < 300  # Less than sum of sequential
        assert len(solution.selected_indexes) >= 1

    def test_greedy_respects_max_indexes(self, simple_problem: IndexSelectionProblem) -> None:
        """Greedy should respect max indexes constraint."""
        from querysense.index.greedy_solver import GreedySolver

        simple_problem.settings.rules = [
            Rule(name=RuleName.MAXIMUM_NUMBER_OF_INDEXES, value=1.0)
        ]

        solver = GreedySolver()
        solution = solver.solve(simple_problem)

        assert solution.total_indexes <= 1

    def test_greedy_selects_best_marginal(self, simple_problem: IndexSelectionProblem) -> None:
        """Greedy should pick the index with highest marginal benefit first."""
        from querysense.index.greedy_solver import GreedySolver

        solver = GreedySolver()
        solution = solver.solve(simple_problem)

        # idx2 covers both scans with reasonable costs
        assert "idx2" in solution.selected_indexes or "idx1" in solution.selected_indexes

    def test_greedy_empty_problem(self) -> None:
        """Handle empty problem gracefully."""
        from querysense.index.greedy_solver import GreedySolver

        problem = IndexSelectionProblem(scans=[], indexes=[])
        solver = GreedySolver()
        solution = solver.solve(problem)

        assert solution.status == "FEASIBLE"
        assert solution.total_cost == 0

    @pytest.mark.skipif(not ortools_available, reason="ortools not installed")
    def test_greedy_vs_cp_quality(self) -> None:
        """Greedy may give worse solution than CP — but should still be valid."""
        from querysense.index.cp_solver import ConstraintProgrammingSolver
        from querysense.index.greedy_solver import GreedySolver

        problem = IndexSelectionProblem(
            scans=[
                Scan(id="A", sequential_cost=35, index_costs={"1": 15, "3": 13, "4": 21}),
                Scan(id="B", sequential_cost=22, index_costs={"2": 14, "3": 11, "4": 11}),
                Scan(id="C", sequential_cost=37, index_costs={"1": 12, "3": 21, "4": 18}),
                Scan(id="D", sequential_cost=42, index_costs={"1": 27, "2": 14}),
            ],
            indexes=[
                Index(id="1", columns=("a",)),
                Index(id="2", columns=("b",)),
                Index(id="3", columns=("c",)),
                Index(id="4", columns=("d",)),
            ],
        )

        cp_solver = ConstraintProgrammingSolver()
        cp_solution = cp_solver.solve_minimal_cost(problem)

        greedy_solver = GreedySolver()
        greedy_solution = greedy_solver.solve(problem)

        # Greedy should find a valid solution
        assert greedy_solution.total_cost > 0
        # CP optimal is 50; greedy should be close (not perfect)
        assert greedy_solution.total_cost >= cp_solution.total_cost
        assert greedy_solution.total_cost <= sum(s.sequential_cost for s in problem.scans)


# ---------------------------------------------------------------------------
# Index Consolidation Tests
# ---------------------------------------------------------------------------


class TestIndexConsolidation:
    """Tests for redundant/duplicate index detection."""

    def test_detect_prefix_redundancy(self) -> None:
        """idx(a) is redundant when idx(a,b) exists."""
        from querysense.index.consolidation import IndexConsolidator
        from querysense.index.stats_collector import ExistingIndex

        consolidator = IndexConsolidator()
        indexes = [
            ExistingIndex(
                name="idx_a", columns=["a"], is_unique=False, is_primary=False,
                index_type="btree", size_bytes=1024 * 1024, definition="",
            ),
            ExistingIndex(
                name="idx_a_b", columns=["a", "b"], is_unique=False, is_primary=False,
                index_type="btree", size_bytes=2 * 1024 * 1024, definition="",
            ),
        ]

        issues = consolidator.find_redundant(indexes)
        assert len(issues) == 1
        assert issues[0].index_name == "idx_a"
        assert issues[0].related_index == "idx_a_b"

    def test_detect_duplicate(self) -> None:
        """Two indexes on same columns are duplicates."""
        from querysense.index.consolidation import IndexConsolidator
        from querysense.index.stats_collector import ExistingIndex

        consolidator = IndexConsolidator()
        indexes = [
            ExistingIndex(
                name="idx_a_v1", columns=["a"], is_unique=False, is_primary=False,
                index_type="btree", size_bytes=1024 * 1024, definition="",
                scans=100,
            ),
            ExistingIndex(
                name="idx_a_v2", columns=["a"], is_unique=False, is_primary=False,
                index_type="btree", size_bytes=1024 * 1024, definition="",
                scans=5,
            ),
        ]

        issues = consolidator.find_duplicates(indexes)
        assert len(issues) == 1
        assert issues[0].issue_type == "duplicate"
        # Should drop the one with fewer scans
        assert issues[0].index_name == "idx_a_v2"

    def test_detect_unused(self) -> None:
        """Zero-scan indexes flagged as unused."""
        from querysense.index.consolidation import IndexConsolidator
        from querysense.index.stats_collector import ExistingIndex

        consolidator = IndexConsolidator()
        indexes = [
            ExistingIndex(
                name="idx_unused", columns=["x"], is_unique=False, is_primary=False,
                index_type="btree", size_bytes=10 * 1024 * 1024, definition="",
                scans=0,
            ),
        ]

        issues = consolidator.find_unused(indexes)
        assert len(issues) == 1
        assert issues[0].issue_type == "unused"

    def test_skip_primary_key(self) -> None:
        """Primary keys should never be flagged as redundant or unused."""
        from querysense.index.consolidation import IndexConsolidator
        from querysense.index.stats_collector import ExistingIndex

        consolidator = IndexConsolidator()
        indexes = [
            ExistingIndex(
                name="pk_orders", columns=["id"], is_unique=True, is_primary=True,
                index_type="btree", size_bytes=1024 * 1024, definition="",
                scans=0,
            ),
        ]

        unused = consolidator.find_unused(indexes)
        redundant = consolidator.find_redundant(indexes)
        assert len(unused) == 0
        assert len(redundant) == 0

    def test_full_analysis_report(self) -> None:
        """Full analyze() produces a ConsolidationReport."""
        from querysense.index.consolidation import IndexConsolidator
        from querysense.index.stats_collector import ExistingIndex

        consolidator = IndexConsolidator()
        indexes = [
            ExistingIndex(
                name="idx_a", columns=["a"], is_unique=False, is_primary=False,
                index_type="btree", size_bytes=1024 * 1024, definition="",
                scans=50,
            ),
            ExistingIndex(
                name="idx_a_b", columns=["a", "b"], is_unique=False, is_primary=False,
                index_type="btree", size_bytes=2 * 1024 * 1024, definition="",
                scans=100,
            ),
        ]

        report = consolidator.analyze(indexes)
        assert len(report.issues) >= 1
        assert report.total_savings_bytes > 0


# ---------------------------------------------------------------------------
# Advisor Fallback Tests
# ---------------------------------------------------------------------------


class TestAdvisorFallback:
    """Tests for advisor with greedy fallback."""

    @pytest.mark.skipif(not ortools_available, reason="ortools not installed")
    def test_advisor_reports_cp_sat_method(self) -> None:
        """When ortools is available, advisor uses CP-SAT."""
        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor

        advisor = ConstraintProgrammingIndexAdvisor()
        assert advisor.solver_method == "CP-SAT"

    @pytest.mark.skipif(not ortools_available, reason="ortools not installed")
    def test_advisor_solve_uses_cp(self) -> None:
        """Advisor should use CP solver when available."""
        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor

        advisor = ConstraintProgrammingIndexAdvisor()
        data = {
            "Scans": [
                {
                    "Name": "A",
                    "Sequential Cost": 100,
                    "Index Costs": [{"Index": "idx1", "Cost": 10}],
                }
            ],
        }
        solution = advisor.solve_from_data(data)
        assert solution.status == "OPTIMAL"


# ---------------------------------------------------------------------------
# HOT Guard Integration Test
# ---------------------------------------------------------------------------


class TestHOTGuardIntegration:
    """Tests for HOT update guard in the advisor pipeline."""

    @pytest.mark.skipif(not ortools_available, reason="ortools not installed")
    def test_hot_guard_blocks_critical_columns(self) -> None:
        """Indexes on heavily-updated columns should be blocked."""
        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor
        from querysense.index.workload_classifier import TableStats

        advisor = ConstraintProgrammingIndexAdvisor()

        # High HOT ratio + frequent updates
        stats = TableStats(
            table_name="orders",
            table_size_bytes=500 * 1024 * 1024,
            n_tup_upd=100000,
            n_tup_hot_upd=90000,  # 90% HOT ratio
            n_tup_ins=1000,
            n_tup_del=100,
            stats_reset_seconds=60,  # Very high writes/min
        )

        # One index on a heavily-updated column, one on a stable column
        indexes = [
            Index(id="idx_status", name="idx_status", columns=("status",), table="orders"),
            Index(id="idx_customer", name="idx_customer", columns=("customer_id",), table="orders"),
        ]

        scans = [
            Scan(id="by_status", sequential_cost=5000, index_costs={"idx_status": 200}),
            Scan(id="by_customer", sequential_cost=3000, index_costs={"idx_customer": 50}),
        ]

        result = advisor.analyze_table("orders", stats, indexes, scans)

        # Should have HOT warnings
        assert len(result.hot_warnings) >= 1
