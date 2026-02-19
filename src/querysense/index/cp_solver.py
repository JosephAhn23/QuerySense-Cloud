"""
Constraint Programming Solver using Google OR-Tools CP-SAT.

Implements the core CP model from pganalyze's PGCon 2023 talk:
https://github.com/pganalyze/pgcon2023

The key insight is modelling index selection as a discrete optimization:
- Boolean variables for each candidate index (select or not)
- Integer variables for each scan cost (domain = possible costs)
- add_min_equality constraints linking index selection to scan costs
- Minimize total scan cost subject to rules (max indexes, max IWO)

The solver guarantees a globally optimal solution (not a greedy heuristic).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from querysense.index.cp_model import (
    GoalName,
    IndexSelectionProblem,
    IndexSelectionSolution,
    RuleName,
    ScanResult,
)

if TYPE_CHECKING:
    from ortools.sat.python import cp_model as cp_model_mod


# ---------------------------------------------------------------------------
# Lazy import helper – OR-Tools is an optional heavy dependency
# ---------------------------------------------------------------------------

def _import_ortools() -> "cp_model_mod":
    """Import ortools lazily to keep the package importable without it."""
    try:
        from ortools.sat.python import cp_model as _cp  # type: ignore[import-untyped]
        return _cp
    except ImportError as exc:
        raise ImportError(
            "Google OR-Tools is required for the constraint programming index advisor.\n"
            "Install with: pip install 'querysense[index]' or pip install ortools"
        ) from exc


# ---------------------------------------------------------------------------
# Scaling factor: CP-SAT works with integers, so we scale float costs.
# ---------------------------------------------------------------------------
COST_SCALE = 1  # costs are already integers in pganalyze's format


class ConstraintProgrammingSolver:
    """
    Core CP-SAT solver implementing pganalyze's index selection model.

    The model:
        Variables:
            x[i] ∈ {0, 1}  for each candidate index i
            scan_cost[s] ∈ Domain(possible_costs)  for each scan s

        Constraints:
            For each scan s:
                scan_cost[s] = min over all covering indexes i of:
                    c(s,i) * x[i] + c_read(s) * (1 - x[i])

            Optional rules:
                sum(x) <= max_indexes
                sum(iwo[i] * x[i]) <= max_iwo

        Objective:
            Depends on goal — typically minimize sum(scan_cost)
    """

    def __init__(self) -> None:
        self._cp = _import_ortools()

    def solve(self, problem: IndexSelectionProblem) -> IndexSelectionSolution:
        """
        Build and solve the CP model for the given problem.

        Uses the first goal from settings as the primary objective.
        For multi-goal hierarchical optimization, use HierarchicalOptimizer.

        Args:
            problem: Complete index selection problem definition.

        Returns:
            IndexSelectionSolution with selected indexes, costs, and metrics.
        """
        t0 = time.perf_counter()

        if not problem.scans:
            return IndexSelectionSolution(
                status="OPTIMAL",
                total_cost=0,
                total_indexes=0,
                total_scans=0,
                solve_time_ms=0.0,
            )

        if not problem.indexes:
            # No candidate indexes — all scans use sequential cost
            total_seq = sum(s.sequential_cost for s in problem.scans)
            scan_results = [
                ScanResult(scan_id=s.id, cost=s.sequential_cost, is_sequential=True)
                for s in problem.scans
            ]
            return IndexSelectionSolution(
                status="OPTIMAL",
                total_cost=total_seq,
                total_indexes=0,
                total_scans=len(problem.scans),
                scans_uncovered=len(problem.scans),
                scan_results=scan_results,
                solve_time_ms=(time.perf_counter() - t0) * 1000,
            )

        model = self._cp.CpModel()

        # ----- Decision variables: which indexes to select -----
        num_indexes = len(problem.indexes)
        x = [model.new_bool_var(f"idx_{i}") for i in range(num_indexes)]

        # Build index lookup: index_id -> position
        idx_pos = {idx.id: i for i, idx in enumerate(problem.indexes)}

        # ----- Scan cost variables -----
        scan_vars: list[cp_model_mod.IntVar] = []

        for s_idx, scan in enumerate(problem.scans):
            # Collect all possible costs for this scan
            possible_costs: list[int] = [scan.sequential_cost]
            covering_indexes: list[tuple[int, int]] = []  # (index_pos, cost)

            for idx_id, cost in scan.index_costs.items():
                if idx_id in idx_pos:
                    possible_costs.append(cost)
                    covering_indexes.append((idx_pos[idx_id], cost))

            # Create scan cost variable with restricted domain
            unique_costs = sorted(set(possible_costs))
            domain = self._cp.Domain.from_values(unique_costs)
            scan_var = model.new_int_var_from_domain(domain, f"scan_{s_idx}")
            scan_vars.append(scan_var)

            if not covering_indexes:
                # No index covers this scan — force sequential cost
                model.add(scan_var == scan.sequential_cost)
                continue

            # ----- THE KEY CONSTRAINT from pganalyze -----
            # For each covering index, create an expression:
            #   cost_i * x[i] + sequential_cost * (1 - x[i])
            # Then: scan_cost = min(all expressions)
            #
            # This means:
            #   If x[i]=1 (index selected): expression = index_cost
            #   If x[i]=0 (not selected): expression = sequential_cost
            #   add_min_equality picks the lowest available cost.

            expr_list: list[cp_model_mod.LinearExpr] = []
            for i_pos, i_cost in covering_indexes:
                # Build: i_cost * x[i] + sequential_cost * (1 - x[i])
                # = i_cost * x[i] + sequential_cost - sequential_cost * x[i]
                # = (i_cost - sequential_cost) * x[i] + sequential_cost
                diff = i_cost - scan.sequential_cost
                expr = diff * x[i_pos] + scan.sequential_cost  # type: ignore[operator]
                expr_list.append(expr)

            # Also include the pure sequential cost as a baseline
            # (in case no index is selected)
            seq_const = model.new_constant(scan.sequential_cost)
            expr_list.append(seq_const)

            model.add_min_equality(scan_var, expr_list)

        # ----- Apply rules (hard constraints) -----
        for rule in problem.settings.rules:
            if rule.name == RuleName.MAXIMUM_NUMBER_OF_INDEXES:
                model.add(sum(x) <= int(rule.value))

            elif rule.name == RuleName.MAXIMUM_IWO:
                # Total write overhead <= max
                iwo_terms: list[cp_model_mod.LinearExpr] = []
                for i, idx in enumerate(problem.indexes):
                    overhead = problem.index_write_overheads.get(
                        idx.id, idx.write_overhead
                    )
                    if overhead > 0:
                        # Scale to integer for CP-SAT
                        scaled = int(overhead * 100)
                        iwo_terms.append(scaled * x[i])  # type: ignore[arg-type]
                if iwo_terms:
                    model.add(sum(iwo_terms) <= int(rule.value * 100))

        # ----- Set objective based on primary goal -----
        primary_goal = GoalName.MINIMAL_COST
        if problem.settings.goals:
            primary_goal = problem.settings.goals[0].name

        self._set_objective(model, primary_goal, scan_vars, x, problem)

        # ----- Solve -----
        solver = self._cp.CpSolver()
        solver.parameters.max_time_in_seconds = problem.settings.time_limit_seconds

        status_code = solver.solve(model)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        status_map = {
            self._cp.OPTIMAL: "OPTIMAL",
            self._cp.FEASIBLE: "FEASIBLE",
            self._cp.INFEASIBLE: "INFEASIBLE",
            self._cp.MODEL_INVALID: "MODEL_INVALID",
            self._cp.UNKNOWN: "UNKNOWN",
        }
        status = status_map.get(status_code, "UNKNOWN")

        if status in ("OPTIMAL", "FEASIBLE"):
            return self._extract_solution(
                solver, x, scan_vars, problem, status, elapsed_ms
            )

        return IndexSelectionSolution(
            status=status,
            total_scans=len(problem.scans),
            solve_time_ms=elapsed_ms,
        )

    def solve_minimal_cost(
        self, problem: IndexSelectionProblem
    ) -> IndexSelectionSolution:
        """Solve with a single goal: minimize total scan costs."""
        from querysense.index.cp_model import Goal, SolverSettings

        problem.settings = SolverSettings(
            goals=[Goal(name=GoalName.MINIMAL_COST)],
            rules=problem.settings.rules,
            time_limit_seconds=problem.settings.time_limit_seconds,
        )
        return self.solve(problem)

    def solve_minimal_indexes(
        self, problem: IndexSelectionProblem
    ) -> IndexSelectionSolution:
        """Solve with a single goal: minimize number of indexes."""
        from querysense.index.cp_model import Goal, SolverSettings

        problem.settings = SolverSettings(
            goals=[Goal(name=GoalName.MINIMAL_INDEXES)],
            rules=problem.settings.rules,
            time_limit_seconds=problem.settings.time_limit_seconds,
        )
        return self.solve(problem)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_objective(
        self,
        model: "cp_model_mod.CpModel",
        goal: GoalName,
        scan_vars: list["cp_model_mod.IntVar"],
        index_vars: list["cp_model_mod.IntVar"],
        problem: IndexSelectionProblem,
    ) -> None:
        """Set the model objective based on the goal."""
        if goal == GoalName.MINIMAL_COST:
            model.minimize(sum(scan_vars))

        elif goal == GoalName.MINIMAL_INDEXES:
            model.minimize(sum(index_vars))

        elif goal == GoalName.MAXIMAL_COVERAGE:
            # Maximize the number of scans covered by at least one index.
            # A scan is "covered" if its cost < sequential cost.
            coverage_vars = []
            for s_idx, scan in enumerate(problem.scans):
                has_covering = any(
                    idx_id in {idx.id for idx in problem.indexes}
                    for idx_id in scan.index_costs
                )
                if has_covering:
                    is_covered = model.new_bool_var(f"covered_{s_idx}")
                    model.add(
                        scan_vars[s_idx] < scan.sequential_cost
                    ).only_enforce_if(is_covered)
                    model.add(
                        scan_vars[s_idx] >= scan.sequential_cost
                    ).only_enforce_if(is_covered.negated())
                    coverage_vars.append(is_covered)
            if coverage_vars:
                model.maximize(sum(coverage_vars))

        elif goal == GoalName.MINIMAL_IWO:
            iwo_terms = []
            for i, idx in enumerate(problem.indexes):
                overhead = problem.index_write_overheads.get(
                    idx.id, idx.write_overhead
                )
                scaled = int(overhead * 100)
                if scaled > 0:
                    iwo_terms.append(scaled * index_vars[i])  # type: ignore[arg-type]
            if iwo_terms:
                model.minimize(sum(iwo_terms))
            else:
                model.minimize(sum(index_vars))

    def _extract_solution(
        self,
        solver: "cp_model_mod.CpSolver",
        index_vars: list["cp_model_mod.IntVar"],
        scan_vars: list["cp_model_mod.IntVar"],
        problem: IndexSelectionProblem,
        status: str,
        elapsed_ms: float,
    ) -> IndexSelectionSolution:
        """Extract the solution from a solved model."""
        selected: list[str] = []
        total_iwo = 0.0

        for i, idx in enumerate(problem.indexes):
            if solver.value(index_vars[i]):
                selected.append(idx.id)
                total_iwo += problem.index_write_overheads.get(
                    idx.id, idx.write_overhead
                )

        scan_results: list[ScanResult] = []
        total_cost = 0
        covered = 0
        uncovered = 0

        for s_idx, scan in enumerate(problem.scans):
            cost = solver.value(scan_vars[s_idx])
            total_cost += cost

            is_sequential = cost >= scan.sequential_cost
            covering_idx = None

            if not is_sequential:
                # Find which selected index provides this cost
                for idx_id, idx_cost in scan.index_costs.items():
                    if idx_id in selected and idx_cost == cost:
                        covering_idx = idx_id
                        break
                covered += 1
            else:
                uncovered += 1

            scan_results.append(
                ScanResult(
                    scan_id=scan.id,
                    cost=cost,
                    covering_index=covering_idx,
                    is_sequential=is_sequential,
                )
            )

        return IndexSelectionSolution(
            status=status,
            selected_indexes=selected,
            scan_results=scan_results,
            total_cost=total_cost,
            total_indexes=len(selected),
            total_write_overhead=total_iwo,
            solve_time_ms=elapsed_ms,
            objective_value=int(solver.objective_value),
            scans_covered=covered,
            scans_uncovered=uncovered,
            total_scans=len(problem.scans),
        )
