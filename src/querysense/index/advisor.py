"""
Constraint Programming Index Advisor — Main Integration Class.

Combines all CP model components into a single cohesive advisor that
implements pganalyze's full Index Advisor 3.0 pipeline:

    1. Extract scans from workload
    2. Generate candidate indexes
    3. Classify table based on workload (read/write/balanced)
    4. Apply PostgreSQL-specific intelligence (HOT, FD, IWO)
    5. Build and solve CP model with appropriate goals/rules
    6. Return ranked recommendations with explanations

Usage:
    from querysense.index.advisor import ConstraintProgrammingIndexAdvisor

    advisor = ConstraintProgrammingIndexAdvisor()

    # From raw problem data (pganalyze format)
    solution = advisor.solve_from_data(data_dict, settings_dict)

    # From QuerySense workload analysis
    result = advisor.analyze_table("orders", table_stats, candidate_indexes)

    # Explore configurations
    results = advisor.explore_configurations("orders", table_stats, candidates)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from querysense.index.cp_model import (
    Goal,
    GoalName,
    Index,
    IndexSelectionProblem,
    IndexSelectionSolution,
    Rule,
    RuleName,
    Scan,
    SolverSettings,
    TableConfiguration,
)
from querysense.index.functional_dependency import (
    FDAnalysisResult,
    FunctionalDependencyDetector,
)
from querysense.index.hierarchical import HierarchicalOptimizer
from querysense.index.hot_detector import HOTUpdateDetector, HOTWarning
from querysense.index.workload_classifier import (
    CONFIGURATIONS,
    IndexingConfiguration,
    TableStats,
    WorkloadClassifier,
)
from querysense.index.write_overhead import (
    IWOResult,
    IndexWriteOverheadCalculator,
)


@dataclass
class IndexRecommendation:
    """
    A complete index recommendation from the CP advisor.

    Includes the solver's decision, supporting analysis, and warnings.
    """

    # Core solution
    solution: IndexSelectionSolution = field(
        default_factory=IndexSelectionSolution
    )

    # Table classification
    table_name: str = ""
    classification: TableConfiguration = TableConfiguration.BALANCED
    classification_details: dict[str, float] = field(default_factory=dict)

    # Configuration used
    configuration: IndexingConfiguration | None = None

    # PostgreSQL-specific analysis
    hot_warnings: list[HOTWarning] = field(default_factory=list)
    fd_results: list[FDAnalysisResult] = field(default_factory=list)
    iwo_results: list[IWOResult] = field(default_factory=list)

    # CREATE INDEX statements
    create_statements: list[str] = field(default_factory=list)
    drop_statements: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "table_name": self.table_name,
            "classification": self.classification.value,
            "classification_details": self.classification_details,
            "solution": self.solution.to_dict(),
            "hot_warnings": [w.to_dict() for w in self.hot_warnings],
            "fd_optimizations": [
                {
                    "original": list(fd.original_columns),
                    "optimized": list(fd.optimized_columns),
                    "removed": fd.columns_removed,
                    "savings_estimate": round(fd.space_savings_estimate, 2),
                }
                for fd in self.fd_results
                if fd.was_optimized
            ],
            "iwo_scores": [r.to_dict() for r in self.iwo_results],
            "create_statements": self.create_statements,
            "drop_statements": self.drop_statements,
        }

    def format_report(self) -> str:
        """Format a human-readable report."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("  QuerySense CP Index Advisor Report")
        lines.append("=" * 70)
        lines.append("")

        # Table classification
        if self.table_name:
            lines.append(f"Table: {self.table_name}")
            lines.append(f"Classification: {self.classification.value}")
            if self.classification_details:
                writes = self.classification_details.get("writes_per_minute", 0)
                scans = self.classification_details.get("scans_per_minute", 0)
                size = self.classification_details.get("table_size_mb", 0)
                lines.append(f"  Writes/min: {writes:.1f}  |  Scans/min: {scans:.1f}  |  Size: {size:.1f}MB")
            lines.append("")

        # Solution summary
        sol = self.solution
        lines.append(f"Solver status: {sol.status}")
        lines.append(f"Total scan cost: {sol.total_cost}")
        lines.append(f"Indexes selected: {sol.total_indexes}")
        lines.append(f"Coverage: {sol.coverage_pct:.1f}% ({sol.scans_covered}/{sol.total_scans})")
        lines.append(f"Total IWO: {sol.total_write_overhead:.1f}")
        lines.append(f"Solve time: {sol.solve_time_ms:.1f}ms")
        lines.append("")

        # Selected indexes
        if sol.selected_indexes:
            lines.append("Selected Indexes:")
            lines.append("-" * 50)
            for idx_id in sol.selected_indexes:
                iwo = next(
                    (r for r in self.iwo_results if r.index_name == idx_id),
                    None,
                )
                iwo_str = f"  (IWO: {iwo.iwo_score:.1f})" if iwo else ""
                lines.append(f"  + {idx_id}{iwo_str}")
            lines.append("")

        # Scan results
        if sol.scan_results:
            lines.append("Scan Coverage:")
            lines.append("-" * 50)
            for sr in sol.scan_results:
                if sr.is_sequential:
                    lines.append(f"  {sr.scan_id}: seq scan (cost={sr.cost})")
                else:
                    lines.append(
                        f"  {sr.scan_id}: {sr.covering_index} (cost={sr.cost})"
                    )
            lines.append("")

        # HOT warnings
        if self.hot_warnings:
            lines.append("HOT Update Warnings:")
            lines.append("-" * 50)
            for w in self.hot_warnings:
                lines.append(f"  [{w.severity}] {w.message}")
                lines.append(f"    {w.details}")
                lines.append(f"    -> {w.recommendation}")
            lines.append("")

        # Functional dependency optimizations
        fd_optimized = [fd for fd in self.fd_results if fd.was_optimized]
        if fd_optimized:
            lines.append("Functional Dependency Optimizations:")
            lines.append("-" * 50)
            for fd in fd_optimized:
                lines.append(
                    f"  ({', '.join(fd.original_columns)}) -> ({', '.join(fd.optimized_columns)})"
                )
                lines.append(f"    Removed: {', '.join(fd.columns_removed)}")
                lines.append(
                    f"    Space savings: ~{fd.space_savings_estimate:.0%}"
                )
            lines.append("")

        # CREATE statements
        if self.create_statements:
            lines.append("SQL Statements:")
            lines.append("-" * 50)
            for stmt in self.create_statements:
                lines.append(f"  {stmt}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)


class ConstraintProgrammingIndexAdvisor:
    """
    Complete index advisor implementing pganalyze's CP model.

    Features:
    - Automatic table classification (read/write optimized)
    - Constraint programming with CP-SAT (with greedy fallback)
    - Hierarchical multi-objective optimization
    - HOT update detection and guard (penalize/prohibit hot columns)
    - Functional dependency awareness
    - Index write overhead modelling
    - Index consolidation (redundant/duplicate/unused detection)
    - Configuration exploration and overrides
    """

    def __init__(self) -> None:
        self.classifier = WorkloadClassifier()
        self.hot_detector = HOTUpdateDetector()
        self.fd_detector = FunctionalDependencyDetector()
        self.iwo_calculator = IndexWriteOverheadCalculator()

        # Auto-detect OR-Tools; fall back to greedy solver
        self._use_cp = True
        try:
            from ortools.sat.python import cp_model as _cp  # type: ignore[import-untyped]  # noqa: F401
            self.optimizer = HierarchicalOptimizer()
        except ImportError:
            self._use_cp = False
            self.optimizer = None  # type: ignore[assignment]

    @property
    def solver_method(self) -> str:
        """Return the active solver method name."""
        return "CP-SAT" if self._use_cp else "Greedy"

    def _solve(self, problem: IndexSelectionProblem) -> IndexSelectionSolution:
        """Solve using available method (CP-SAT or greedy fallback)."""
        if self._use_cp:
            return self.optimizer.optimize(problem)
        from querysense.index.greedy_solver import GreedySolver
        return GreedySolver().solve(problem)

    # ------------------------------------------------------------------
    # Main entry points
    # ------------------------------------------------------------------

    def solve_from_data(
        self,
        data: dict[str, Any],
        settings: dict[str, Any] | None = None,
        time_limit: float = 10.0,
    ) -> IndexSelectionSolution:
        """
        Solve directly from pganalyze-format JSON data.

        This is the simplest entry point — just provide the problem
        data and optional settings.

        Args:
            data: Problem data in pganalyze format (Scans, Indexes, etc.)
            settings: Optional solver settings (Goals, Rules).
            time_limit: Time limit in seconds.

        Returns:
            IndexSelectionSolution.
        """
        solver_settings = None
        if settings:
            solver_settings = SolverSettings.from_dict(settings)
            solver_settings.time_limit_seconds = time_limit
        else:
            solver_settings = SolverSettings.default()
            solver_settings.time_limit_seconds = time_limit

        problem = IndexSelectionProblem.from_dict(data, solver_settings)
        return self._solve(problem)

    def solve_from_files(
        self,
        data_path: Path,
        settings_path: Path | None = None,
        time_limit: float = 10.0,
    ) -> IndexSelectionSolution:
        """
        Solve from JSON files (pganalyze PGCon format).

        Args:
            data_path: Path to data JSON file.
            settings_path: Optional path to settings JSON file.
            time_limit: Time limit in seconds.
        """
        data = json.loads(data_path.read_text(encoding="utf-8"))
        settings = None
        if settings_path:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        return self.solve_from_data(data, settings, time_limit)

    def analyze_table(
        self,
        table_name: str,
        table_stats: TableStats,
        candidate_indexes: list[Index],
        scans: list[Scan],
        config_override: dict[str, Any] | None = None,
        extended_stats: list[dict[str, Any]] | None = None,
        column_types: dict[str, str] | None = None,
    ) -> IndexRecommendation:
        """
        Full analysis pipeline for a single table.

        Implements pganalyze's complete workflow:
        1. Classify table based on workload
        2. Check HOT update implications
        3. Optimize by functional dependencies
        4. Calculate write overhead
        5. Build and solve CP model
        6. Return comprehensive recommendation

        Args:
            table_name: Target table.
            table_stats: Table-level statistics.
            candidate_indexes: Candidate indexes to consider.
            scans: Scans (query patterns) for this table.
            config_override: Override classification with custom config.
            extended_stats: PostgreSQL extended statistics for FD detection.
            column_types: Column name -> type mapping for IWO calculation.

        Returns:
            IndexRecommendation with full analysis.
        """
        recommendation = IndexRecommendation(table_name=table_name)

        # Step 1: Classify table
        config_type, details = self.classifier.classify_with_details(table_stats)
        recommendation.classification = config_type
        recommendation.classification_details = details

        if config_type == TableConfiguration.IGNORE:
            recommendation.solution = IndexSelectionSolution(
                status="SKIPPED",
                total_scans=len(scans),
            )
            return recommendation

        # Get configuration (override or automatic)
        if config_override:
            config = IndexingConfiguration(
                config_type=TableConfiguration.BALANCED,
                primary_goal=GoalName(config_override.get("primary_goal", "Minimal Cost")),
                secondary_goal=GoalName(config_override.get("secondary_goal", "Minimal Indexes")),
                primary_tolerance=config_override.get("tolerance", 0.1),
                max_indexes=config_override.get("max_indexes"),
                max_iwo=config_override.get("max_iwo"),
            )
        else:
            config = CONFIGURATIONS[config_type]
        recommendation.configuration = config

        # Step 2: Check HOT update implications and apply guard
        hot_penalized_columns: set[str] = set()
        hot_blocked_columns: set[str] = set()
        for idx in candidate_indexes:
            warnings = self.hot_detector.analyze(
                table_name,
                list(idx.columns),
                table_stats,
            )
            recommendation.hot_warnings.extend(warnings)
            for w in warnings:
                if w.severity == "WARNING":
                    hot_blocked_columns.add(w.column)
                else:
                    hot_penalized_columns.add(w.column)

        # HOT Guard: remove candidates that would break HOT on critical columns
        if hot_blocked_columns:
            candidate_indexes = [
                idx for idx in candidate_indexes
                if not any(col in hot_blocked_columns for col in idx.columns)
            ]

        # HOT Penalty: inflate IWO for penalized columns (makes solver prefer
        # alternatives but doesn't block outright)
        hot_iwo_penalty = 5.0  # Add 5 IWO points per hot-penalized column

        # Step 3: Functional dependency optimization
        for idx in candidate_indexes:
            if len(idx.columns) > 1:
                fd_result = self.fd_detector.optimize_index_columns(
                    table_name,
                    list(idx.columns),
                    extended_stats,
                )
                if fd_result.was_optimized:
                    recommendation.fd_results.append(fd_result)

        # Step 4: Calculate IWO for each candidate
        for idx in candidate_indexes:
            iwo = self.iwo_calculator.calculate(
                idx.name or idx.id,
                table_name,
                list(idx.columns),
                idx.index_type,
                table_stats,
                column_types,
            )
            recommendation.iwo_results.append(iwo)

        # Step 5: Build and solve CP model
        # Apply HOT penalty to IWO scores for penalized columns
        iwo_map: dict[str, float] = {}
        for idx, iwo in zip(candidate_indexes, recommendation.iwo_results):
            penalty = sum(
                hot_iwo_penalty for col in idx.columns
                if col in hot_penalized_columns
            )
            iwo_map[idx.id] = iwo.iwo_score + penalty

        problem = IndexSelectionProblem(
            scans=scans,
            indexes=candidate_indexes,
            existing_indexes=[idx.id for idx in candidate_indexes if idx.is_existing],
            index_write_overheads=iwo_map,
            settings=config.to_solver_settings(),
        )

        recommendation.solution = self._solve(problem)

        # Step 6: Generate SQL statements
        for idx_id in recommendation.solution.selected_indexes:
            idx = next((i for i in candidate_indexes if i.id == idx_id), None)
            if idx and idx.definition:
                recommendation.create_statements.append(idx.definition)
            elif idx and idx.columns:
                cols = ", ".join(idx.columns)
                using = f" USING {idx.index_type}" if idx.index_type != "btree" else ""
                name = idx.name or f"idx_{table_name}_{'_'.join(idx.columns[:3])}"
                stmt = f"CREATE INDEX CONCURRENTLY {name} ON {table_name}{using} ({cols});"
                recommendation.create_statements.append(stmt)

        return recommendation

    def explore_configurations(
        self,
        table_name: str,
        table_stats: TableStats,
        candidate_indexes: list[Index],
        scans: list[Scan],
    ) -> dict[str, IndexRecommendation]:
        """
        Explore all configuration types for a table.

        Returns recommendations for each configuration type so users
        can compare and choose. Like pganalyze's configuration explorer.

        Returns:
            Dict mapping config name to IndexRecommendation.
        """
        results: dict[str, IndexRecommendation] = {}

        for config_type in [
            TableConfiguration.READ_OPTIMIZED,
            TableConfiguration.WRITE_OPTIMIZED,
            TableConfiguration.BALANCED,
        ]:
            config = CONFIGURATIONS[config_type]
            override = {
                "primary_goal": config.primary_goal.value,
                "secondary_goal": config.secondary_goal.value,
                "tolerance": config.primary_tolerance,
                "max_indexes": config.max_indexes,
                "max_iwo": config.max_iwo,
            }
            result = self.analyze_table(
                table_name,
                table_stats,
                candidate_indexes,
                scans,
                config_override=override,
            )
            results[config_type.value] = result

        return results

    # ------------------------------------------------------------------
    # Configuration overrides persistence
    # ------------------------------------------------------------------

    @staticmethod
    def save_configuration_override(
        table_name: str,
        config: dict[str, Any],
        user: str = "unknown",
        overrides_path: Path | None = None,
    ) -> Path:
        """
        Save a configuration override for a table.

        Overrides are stored in .querysense/index_overrides.json.

        Args:
            table_name: Target table.
            config: Configuration dict (goals, rules, etc.).
            user: User who set the override.
            overrides_path: Custom path for overrides file.

        Returns:
            Path to the overrides file.
        """
        import datetime

        if overrides_path is None:
            overrides_path = Path(".querysense") / "index_overrides.json"

        overrides_path.parent.mkdir(parents=True, exist_ok=True)

        existing: dict[str, Any] = {}
        if overrides_path.exists():
            existing = json.loads(overrides_path.read_text(encoding="utf-8"))

        existing[table_name] = {
            "config": config,
            "user": user,
            "date": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        }

        overrides_path.write_text(
            json.dumps(existing, indent=2), encoding="utf-8"
        )
        return overrides_path

    @staticmethod
    def load_configuration_overrides(
        overrides_path: Path | None = None,
    ) -> dict[str, Any]:
        """Load all configuration overrides."""
        if overrides_path is None:
            overrides_path = Path(".querysense") / "index_overrides.json"

        if not overrides_path.exists():
            return {}

        return json.loads(overrides_path.read_text(encoding="utf-8"))
