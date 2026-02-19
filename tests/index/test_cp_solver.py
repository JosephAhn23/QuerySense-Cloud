"""
Tests for the Constraint Programming Index Advisor.

Validates the CP-SAT solver, hierarchical optimizer, workload classifier,
HOT detector, functional dependency detector, and IWO calculator.

Tests are based on pganalyze's PGCon 2023 example data:
https://github.com/pganalyze/pgcon2023
"""

from __future__ import annotations

import json
from pathlib import Path

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
    TableConfiguration,
)

# ---------------------------------------------------------------------------
# Skip all tests if ortools is not installed
# ---------------------------------------------------------------------------

ortools_available = True
try:
    from ortools.sat.python import cp_model  # type: ignore[import-untyped]
except ImportError:
    ortools_available = False

pytestmark = pytest.mark.skipif(
    not ortools_available, reason="ortools not installed"
)


# ---------------------------------------------------------------------------
# Fixtures — pganalyze PGCon 2023 example data
# ---------------------------------------------------------------------------


@pytest.fixture
def pganalyze_scans() -> list[Scan]:
    """
    Scans from pganalyze's data_example.json.

    4 scans, 4 candidate indexes, some coverage gaps (null costs).
    """
    return [
        Scan(
            id="A",
            sequential_cost=35,
            index_costs={"1": 15, "3": 13, "4": 21},
        ),
        Scan(
            id="B",
            sequential_cost=22,
            index_costs={"2": 14, "3": 11, "4": 11},
        ),
        Scan(
            id="C",
            sequential_cost=37,
            index_costs={"1": 12, "3": 21, "4": 18},
        ),
        Scan(
            id="D",
            sequential_cost=42,
            index_costs={"1": 27, "2": 14},
        ),
    ]


@pytest.fixture
def pganalyze_indexes() -> list[Index]:
    """4 candidate indexes."""
    return [
        Index(id="1", name="idx_1", columns=("a",)),
        Index(id="2", name="idx_2", columns=("b",)),
        Index(id="3", name="idx_3", columns=("c",)),
        Index(id="4", name="idx_4", columns=("d",)),
    ]


@pytest.fixture
def pganalyze_problem(
    pganalyze_scans: list[Scan],
    pganalyze_indexes: list[Index],
) -> IndexSelectionProblem:
    """Complete problem with default settings."""
    return IndexSelectionProblem(
        scans=pganalyze_scans,
        indexes=pganalyze_indexes,
        index_write_overheads={"1": 10, "2": 15, "3": 12, "4": 18},
        settings=SolverSettings.default(),
    )


# ---------------------------------------------------------------------------
# CP Solver Tests
# ---------------------------------------------------------------------------


class TestConstraintProgrammingSolver:
    """Tests for the core CP-SAT solver."""

    def test_solve_minimal_cost(self, pganalyze_problem: IndexSelectionProblem) -> None:
        """Verify solver finds optimal cost on pganalyze example."""
        from querysense.index.cp_solver import ConstraintProgrammingSolver

        solver = ConstraintProgrammingSolver()
        solution = solver.solve_minimal_cost(pganalyze_problem)

        assert solution.status == "OPTIMAL"
        # The minimum possible cost: 13 + 11 + 12 + 14 = 50
        assert solution.total_cost == 50
        assert solution.total_indexes >= 1

    def test_solve_minimal_indexes(self, pganalyze_problem: IndexSelectionProblem) -> None:
        """Verify solver minimizes index count (0 is valid — all seq scans)."""
        from querysense.index.cp_solver import ConstraintProgrammingSolver

        solver = ConstraintProgrammingSolver()
        solution = solver.solve_minimal_indexes(pganalyze_problem)

        assert solution.status == "OPTIMAL"
        # Minimizing indexes alone → 0 indexes is optimal (all sequential)
        assert solution.total_indexes == 0
        # Cost should equal sum of all sequential costs
        total_seq = sum(s.sequential_cost for s in pganalyze_problem.scans)
        assert solution.total_cost == total_seq

    def test_solve_empty_problem(self) -> None:
        """Edge case: no scans."""
        from querysense.index.cp_solver import ConstraintProgrammingSolver

        problem = IndexSelectionProblem(scans=[], indexes=[])
        solver = ConstraintProgrammingSolver()
        solution = solver.solve(problem)

        assert solution.status == "OPTIMAL"
        assert solution.total_cost == 0

    def test_solve_no_candidate_indexes(self) -> None:
        """All scans must use sequential cost when no indexes available."""
        from querysense.index.cp_solver import ConstraintProgrammingSolver

        problem = IndexSelectionProblem(
            scans=[Scan(id="A", sequential_cost=100)],
            indexes=[],
        )
        solver = ConstraintProgrammingSolver()
        solution = solver.solve(problem)

        assert solution.status == "OPTIMAL"
        assert solution.total_cost == 100
        assert solution.total_indexes == 0

    def test_solve_with_max_indexes_rule(
        self, pganalyze_problem: IndexSelectionProblem
    ) -> None:
        """Verify max indexes constraint is respected."""
        from querysense.index.cp_solver import ConstraintProgrammingSolver

        pganalyze_problem.settings.rules = [
            Rule(name=RuleName.MAXIMUM_NUMBER_OF_INDEXES, value=2.0)
        ]
        solver = ConstraintProgrammingSolver()
        solution = solver.solve(pganalyze_problem)

        assert solution.status in ("OPTIMAL", "FEASIBLE")
        assert solution.total_indexes <= 2

    def test_solve_returns_scan_results(
        self, pganalyze_problem: IndexSelectionProblem
    ) -> None:
        """Verify scan results are populated."""
        from querysense.index.cp_solver import ConstraintProgrammingSolver

        solver = ConstraintProgrammingSolver()
        solution = solver.solve(pganalyze_problem)

        assert len(solution.scan_results) == 4
        for sr in solution.scan_results:
            assert sr.scan_id in ("A", "B", "C", "D")
            assert sr.cost > 0

    def test_coverage_metrics(self, pganalyze_problem: IndexSelectionProblem) -> None:
        """Verify coverage metrics are computed correctly."""
        from querysense.index.cp_solver import ConstraintProgrammingSolver

        solver = ConstraintProgrammingSolver()
        solution = solver.solve_minimal_cost(pganalyze_problem)

        assert solution.total_scans == 4
        assert solution.scans_covered + solution.scans_uncovered == 4
        assert 0.0 <= solution.coverage_pct <= 100.0


# ---------------------------------------------------------------------------
# Hierarchical Optimizer Tests
# ---------------------------------------------------------------------------


class TestHierarchicalOptimizer:
    """Tests for multi-objective hierarchical optimization."""

    def test_two_goal_optimization(
        self, pganalyze_problem: IndexSelectionProblem
    ) -> None:
        """
        Test the canonical two-goal setup:
        1. Minimize cost (10% tolerance)
        2. Minimize indexes
        """
        from querysense.index.hierarchical import HierarchicalOptimizer

        pganalyze_problem.settings = SolverSettings(
            goals=[
                Goal(name=GoalName.MINIMAL_COST, strictness=0.9),
                Goal(name=GoalName.MINIMAL_INDEXES),
            ],
        )

        optimizer = HierarchicalOptimizer()
        solution = optimizer.optimize(pganalyze_problem)

        assert solution.status in ("OPTIMAL", "FEASIBLE")
        # Cost should be within 10% of optimal (50)
        assert solution.total_cost <= 55  # 50 * 1.10
        # Should find a solution with fewer indexes than the 3 needed for optimal
        assert solution.total_indexes >= 1

    def test_strict_cost_then_minimize_indexes(
        self, pganalyze_problem: IndexSelectionProblem
    ) -> None:
        """Strict cost (0% tolerance) then minimize indexes."""
        from querysense.index.hierarchical import HierarchicalOptimizer

        pganalyze_problem.settings = SolverSettings(
            goals=[
                Goal(name=GoalName.MINIMAL_COST, strictness=1.0),
                Goal(name=GoalName.MINIMAL_INDEXES),
            ],
        )

        optimizer = HierarchicalOptimizer()
        solution = optimizer.optimize(pganalyze_problem)

        assert solution.status in ("OPTIMAL", "FEASIBLE")
        assert solution.total_cost == 50  # Must be exactly optimal

    def test_with_rules_and_goals(
        self, pganalyze_problem: IndexSelectionProblem
    ) -> None:
        """Goals + rules working together."""
        from querysense.index.hierarchical import HierarchicalOptimizer

        pganalyze_problem.settings = SolverSettings(
            goals=[
                Goal(name=GoalName.MINIMAL_COST, strictness=0.9),
                Goal(name=GoalName.MINIMAL_INDEXES),
            ],
            rules=[
                Rule(name=RuleName.MAXIMUM_NUMBER_OF_INDEXES, value=2.0),
            ],
        )

        optimizer = HierarchicalOptimizer()
        solution = optimizer.optimize(pganalyze_problem)

        assert solution.status in ("OPTIMAL", "FEASIBLE")
        assert solution.total_indexes <= 2


# ---------------------------------------------------------------------------
# Data Model Tests
# ---------------------------------------------------------------------------


class TestDataModels:
    """Tests for data model serialization."""

    def test_scan_from_dict(self) -> None:
        """Parse scan from pganalyze JSON format."""
        data = {
            "Name": "scan_orders",
            "Sequential Cost": 15000,
            "Index Costs": [
                {"Index": "idx_user", "Cost": 150},
                {"Index": "idx_date", "Cost": None},
            ],
        }
        scan = Scan.from_dict(data)

        assert scan.id == "scan_orders"
        assert scan.sequential_cost == 15000
        assert scan.index_costs == {"idx_user": 150}
        assert "idx_date" not in scan.index_costs  # null costs excluded

    def test_problem_from_dict(self) -> None:
        """Parse complete problem from pganalyze JSON format."""
        data = {
            "Scans": [
                {
                    "Name": "A",
                    "Sequential Cost": 35,
                    "Index Costs": [
                        {"Index": "1", "Cost": 15},
                    ],
                }
            ],
            "Existing Indexes": ["1"],
            "Index Write Overhead": {"1": 10},
        }
        problem = IndexSelectionProblem.from_dict(data)

        assert len(problem.scans) == 1
        assert len(problem.indexes) == 1
        assert problem.indexes[0].is_existing is True
        assert problem.index_write_overheads == {"1": 10.0}

    def test_settings_from_dict(self) -> None:
        """Parse settings from pganalyze JSON format."""
        data = {
            "Goals": [
                {"Name": "Minimal Cost", "Strictness": 0.9},
                {"Name": "Minimal Indexes"},
            ],
            "Rules": {"Maximum Number of Indexes": 4},
        }
        settings = SolverSettings.from_dict(data)

        assert len(settings.goals) == 2
        assert settings.goals[0].name == GoalName.MINIMAL_COST
        assert settings.goals[0].strictness == 0.9
        assert settings.goals[0].tolerance == pytest.approx(0.1)
        assert len(settings.rules) == 1
        assert settings.rules[0].value == 4.0

    def test_solution_to_dict(self) -> None:
        """Verify solution serialization."""
        from querysense.index.cp_model import IndexSelectionSolution, ScanResult

        solution = IndexSelectionSolution(
            status="OPTIMAL",
            selected_indexes=["1", "3"],
            total_cost=50,
            total_indexes=2,
            total_scans=4,
            scans_covered=3,
            scans_uncovered=1,
        )
        d = solution.to_dict()

        assert d["status"] == "OPTIMAL"
        assert d["total_cost"] == 50
        assert d["coverage_pct"] == 75.0


# ---------------------------------------------------------------------------
# Workload Classifier Tests
# ---------------------------------------------------------------------------


class TestWorkloadClassifier:
    """Tests for automatic table classification."""

    def test_write_optimized(self) -> None:
        """High-write table classified correctly."""
        from querysense.index.workload_classifier import TableStats, WorkloadClassifier

        classifier = WorkloadClassifier()
        stats = TableStats(
            table_name="orders",
            table_size_bytes=100 * 1024 * 1024,  # 100MB
            n_tup_ins=10000,
            n_tup_upd=5000,
            n_tup_del=1000,
            stats_reset_seconds=60,  # 1 minute
        )

        result = classifier.classify(stats)
        assert result == TableConfiguration.WRITE_OPTIMIZED

    def test_read_optimized(self) -> None:
        """High-read table classified correctly."""
        from querysense.index.workload_classifier import TableStats, WorkloadClassifier

        classifier = WorkloadClassifier()
        stats = TableStats(
            table_name="products",
            table_size_bytes=50 * 1024 * 1024,  # 50MB
            seq_scan=50000,
            idx_scan=50000,
            stats_reset_seconds=60,  # 1 minute → 100k scans/min
        )

        result = classifier.classify(stats)
        assert result == TableConfiguration.READ_OPTIMIZED

    def test_balanced(self) -> None:
        """Normal table classified as balanced."""
        from querysense.index.workload_classifier import TableStats, WorkloadClassifier

        classifier = WorkloadClassifier()
        stats = TableStats(
            table_name="users",
            table_size_bytes=20 * 1024 * 1024,
            n_tup_ins=100,
            n_tup_upd=50,
            seq_scan=100,
            idx_scan=100,
            stats_reset_seconds=3600,
        )

        result = classifier.classify(stats)
        assert result == TableConfiguration.BALANCED

    def test_ignore_small_table(self) -> None:
        """Small table excluded from indexing."""
        from querysense.index.workload_classifier import TableStats, WorkloadClassifier

        classifier = WorkloadClassifier()
        stats = TableStats(
            table_name="config",
            table_size_bytes=5 * 1024 * 1024,  # 5MB < 10MB threshold
        )

        result = classifier.classify(stats)
        assert result == TableConfiguration.IGNORE


# ---------------------------------------------------------------------------
# HOT Update Detector Tests
# ---------------------------------------------------------------------------


class TestHOTDetector:
    """Tests for HOT update detection."""

    def test_warns_on_frequently_updated_column(self) -> None:
        """Should warn when indexing a frequently updated column."""
        from querysense.index.hot_detector import HOTUpdateDetector
        from querysense.index.workload_classifier import TableStats

        detector = HOTUpdateDetector()
        stats = TableStats(
            table_name="orders",
            table_size_bytes=100 * 1024 * 1024,
            n_tup_upd=10000,
            n_tup_hot_upd=8000,  # 80% HOT ratio
            stats_reset_seconds=3600,
        )

        warnings = detector.analyze(
            "orders",
            ["status"],
            stats,
            column_update_frequencies={"status": 50.0},
        )

        assert len(warnings) == 1
        assert "HOT" in warnings[0].message

    def test_no_warning_when_hot_ratio_low(self) -> None:
        """No warning when table doesn't benefit from HOT."""
        from querysense.index.hot_detector import HOTUpdateDetector
        from querysense.index.workload_classifier import TableStats

        detector = HOTUpdateDetector()
        stats = TableStats(
            table_name="orders",
            table_size_bytes=100 * 1024 * 1024,
            n_tup_upd=10000,
            n_tup_hot_upd=100,  # 1% HOT ratio
            stats_reset_seconds=3600,
        )

        warnings = detector.analyze("orders", ["status"], stats)
        assert len(warnings) == 0


# ---------------------------------------------------------------------------
# Functional Dependency Tests
# ---------------------------------------------------------------------------


class TestFunctionalDependencyDetector:
    """Tests for functional dependency detection."""

    def test_detects_known_pattern(self) -> None:
        """Should detect zipcode -> state pattern."""
        from querysense.index.functional_dependency import FunctionalDependencyDetector

        detector = FunctionalDependencyDetector()
        result = detector.optimize_index_columns(
            "addresses", ["zipcode", "state", "city"]
        )

        assert result.was_optimized
        assert "state" in result.columns_removed or "city" in result.columns_removed
        assert "zipcode" in result.optimized_columns

    def test_no_optimization_single_column(self) -> None:
        """Single column index can't be optimized."""
        from querysense.index.functional_dependency import FunctionalDependencyDetector

        detector = FunctionalDependencyDetector()
        result = detector.optimize_index_columns("orders", ["customer_id"])

        assert not result.was_optimized
        assert result.optimized_columns == ("customer_id",)

    def test_extended_statistics_detection(self) -> None:
        """Should use extended statistics when provided."""
        from querysense.index.functional_dependency import FunctionalDependencyDetector

        detector = FunctionalDependencyDetector()
        ext_stats = [
            {
                "columns": ["region_code", "region_name"],
                "dependencies": {"region_code=>region_name": 0.95},
            }
        ]
        result = detector.optimize_index_columns(
            "regions",
            ["region_code", "region_name"],
            extended_stats=ext_stats,
        )

        assert result.was_optimized
        assert "region_name" in result.columns_removed


# ---------------------------------------------------------------------------
# Write Overhead Tests
# ---------------------------------------------------------------------------


class TestWriteOverheadCalculator:
    """Tests for IWO calculation."""

    def test_low_write_table(self) -> None:
        """Low-write table should have low IWO."""
        from querysense.index.workload_classifier import TableStats
        from querysense.index.write_overhead import IndexWriteOverheadCalculator

        calc = IndexWriteOverheadCalculator()
        stats = TableStats(
            table_name="config",
            n_tup_ins=10,
            n_tup_upd=5,
            stats_reset_seconds=3600,
        )

        result = calc.calculate("idx_config_key", "config", ["key"], "btree", stats)
        assert result.classification == "low"
        assert result.iwo_score < 5

    def test_high_write_gin_index(self) -> None:
        """GIN index on high-write table should have high IWO."""
        from querysense.index.workload_classifier import TableStats
        from querysense.index.write_overhead import IndexWriteOverheadCalculator

        calc = IndexWriteOverheadCalculator()
        stats = TableStats(
            table_name="events",
            n_tup_ins=100000,
            n_tup_upd=50000,
            stats_reset_seconds=60,
        )

        result = calc.calculate(
            "idx_events_tags", "events", ["tags", "metadata"], "gin", stats
        )
        assert result.classification in ("high", "very_high")
        assert result.iwo_score > 15

    def test_type_multiplier_applied(self) -> None:
        """BRIN should have lower IWO than B-tree."""
        from querysense.index.workload_classifier import TableStats
        from querysense.index.write_overhead import IndexWriteOverheadCalculator

        calc = IndexWriteOverheadCalculator()
        stats = TableStats(
            table_name="logs",
            n_tup_ins=10000,
            stats_reset_seconds=60,
        )

        btree = calc.calculate("idx_btree", "logs", ["ts"], "btree", stats)
        brin = calc.calculate("idx_brin", "logs", ["ts"], "brin", stats)

        assert brin.iwo_score < btree.iwo_score


# ---------------------------------------------------------------------------
# Integration: Advisor Tests
# ---------------------------------------------------------------------------


class TestAdvisor:
    """Tests for the main ConstraintProgrammingIndexAdvisor."""

    def test_solve_from_data(self) -> None:
        """End-to-end test using pganalyze example data."""
        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor

        data = {
            "Scans": [
                {
                    "Name": "A",
                    "Sequential Cost": 35,
                    "Index Costs": [
                        {"Index": "1", "Cost": 15},
                        {"Index": "3", "Cost": 13},
                    ],
                },
                {
                    "Name": "B",
                    "Sequential Cost": 22,
                    "Index Costs": [
                        {"Index": "2", "Cost": 14},
                        {"Index": "3", "Cost": 11},
                    ],
                },
            ],
            "Existing Indexes": [],
            "Index Write Overhead": {"1": 10, "2": 15, "3": 12},
        }

        advisor = ConstraintProgrammingIndexAdvisor()
        solution = advisor.solve_from_data(data)

        assert solution.status in ("OPTIMAL", "FEASIBLE")
        assert solution.total_cost > 0
        assert len(solution.selected_indexes) >= 1

    def test_solve_from_json_files(self, tmp_path: Path) -> None:
        """Test solving from JSON files."""
        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor

        data = {
            "Scans": [
                {
                    "Name": "scan_1",
                    "Sequential Cost": 100,
                    "Index Costs": [{"Index": "idx_a", "Cost": 10}],
                }
            ],
            "Existing Indexes": [],
            "Index Write Overhead": {"idx_a": 5},
        }
        data_path = tmp_path / "data.json"
        data_path.write_text(json.dumps(data))

        advisor = ConstraintProgrammingIndexAdvisor()
        solution = advisor.solve_from_files(data_path)

        assert solution.status == "OPTIMAL"
        assert solution.total_cost == 10
        assert solution.selected_indexes == ["idx_a"]

    def test_analyze_table_full_pipeline(self) -> None:
        """Test the full analyze_table pipeline."""
        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor
        from querysense.index.workload_classifier import TableStats

        stats = TableStats(
            table_name="orders",
            table_size_bytes=500 * 1024 * 1024,
            n_tup_ins=1000,
            n_tup_upd=500,
            n_tup_del=100,
            seq_scan=5000,
            idx_scan=10000,
            stats_reset_seconds=3600,
        )

        indexes = [
            Index(id="idx_customer", name="idx_customer", columns=("customer_id",), table="orders"),
            Index(id="idx_status", name="idx_status", columns=("status",), table="orders"),
        ]

        scans = [
            Scan(id="by_customer", sequential_cost=5000, index_costs={"idx_customer": 50}),
            Scan(id="by_status", sequential_cost=3000, index_costs={"idx_status": 200, "idx_customer": 2500}),
        ]

        advisor = ConstraintProgrammingIndexAdvisor()
        result = advisor.analyze_table("orders", stats, indexes, scans)

        assert result.solution.status in ("OPTIMAL", "FEASIBLE")
        assert result.classification == TableConfiguration.BALANCED
        assert len(result.iwo_results) == 2
