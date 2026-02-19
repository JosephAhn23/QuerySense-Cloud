"""
Hierarchical Multi-Objective Optimizer with Tolerance Parameters.

Implements pganalyze's hierarchical method for multi-objective optimization:
https://pganalyze.com/blog/index-selection-with-constraint-programming

The idea: solve goals one at a time in priority order. After solving
each goal, pin the result with a tolerance, then optimize the next goal.

Example with two goals:
    Goal 1: Minimize cost (strictness=0.9 → 10% tolerance)
    Goal 2: Minimize indexes

Step 1: Solve for minimal cost → optimal_cost = 50
Step 2: Add constraint: total_cost <= 50 * 1.10 = 55
Step 3: Solve for minimal indexes (within the 55-cost budget)
         → finds solution with cost=53 but only 2 indexes instead of 3

This implements the user's intent: "I want the best possible performance,
but I'm willing to accept slightly worse performance if it means
significantly fewer indexes."
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


def _import_ortools() -> "cp_model_mod":
    """Import ortools lazily."""
    try:
        from ortools.sat.python import cp_model as _cp  # type: ignore[import-untyped]
        return _cp
    except ImportError as exc:
        raise ImportError(
            "Google OR-Tools is required for the constraint programming index advisor.\n"
            "Install with: pip install 'querysense[index]' or pip install ortools"
        ) from exc


class HierarchicalOptimizer:
    """
    Multi-objective optimizer using pganalyze's hierarchical method.

    Solves goals in sequence, pinning each result with a tolerance
    before moving to the next goal.
    """

    def __init__(self) -> None:
        self._cp = _import_ortools()

    def optimize(self, problem: IndexSelectionProblem) -> IndexSelectionSolution:
        """
        Run hierarchical optimization with the goals from problem.settings.

        Each goal is solved in order. After solving, the optimal value is
        pinned with the goal's tolerance, and the next goal becomes the
        new objective.

        Args:
            problem: Complete problem with goals and rules.

        Returns:
            IndexSelectionSolution from the final goal's solve.
        """
        t0 = time.perf_counter()
        goals = problem.settings.goals

        if not goals:
            # Fall back to single-goal: minimal cost
            from querysense.index.cp_solver import ConstraintProgrammingSolver
            return ConstraintProgrammingSolver().solve(problem)

        if not problem.scans or not problem.indexes:
            from querysense.index.cp_solver import ConstraintProgrammingSolver
            return ConstraintProgrammingSolver().solve(problem)

        # Build the base model once — we'll add constraints iteratively
        model = self._cp.CpModel()
        idx_pos = {idx.id: i for i, idx in enumerate(problem.indexes)}
        num_indexes = len(problem.indexes)

        # Decision variables
        x = [model.new_bool_var(f"idx_{i}") for i in range(num_indexes)]

        # Scan cost variables
        scan_vars: list[cp_model_mod.IntVar] = []
        for s_idx, scan in enumerate(problem.scans):
            possible_costs: list[int] = [scan.sequential_cost]
            covering: list[tuple[int, int]] = []

            for idx_id, cost in scan.index_costs.items():
                if idx_id in idx_pos:
                    possible_costs.append(cost)
                    covering.append((idx_pos[idx_id], cost))

            unique_costs = sorted(set(possible_costs))
            domain = self._cp.Domain.from_values(unique_costs)
            scan_var = model.new_int_var_from_domain(domain, f"scan_{s_idx}")
            scan_vars.append(scan_var)

            if not covering:
                model.add(scan_var == scan.sequential_cost)
                continue

            expr_list = []
            for i_pos, i_cost in covering:
                diff = i_cost - scan.sequential_cost
                expr = diff * x[i_pos] + scan.sequential_cost  # type: ignore[operator]
                expr_list.append(expr)
            seq_const = model.new_constant(scan.sequential_cost)
            expr_list.append(seq_const)
            model.add_min_equality(scan_var, expr_list)

        # Apply hard constraints (rules)
        for rule in problem.settings.rules:
            if rule.name == RuleName.MAXIMUM_NUMBER_OF_INDEXES:
                model.add(sum(x) <= int(rule.value))
            elif rule.name == RuleName.MAXIMUM_IWO:
                iwo_terms = []
                for i, idx in enumerate(problem.indexes):
                    overhead = problem.index_write_overheads.get(
                        idx.id, idx.write_overhead
                    )
                    if overhead > 0:
                        scaled = int(overhead * 100)
                        iwo_terms.append(scaled * x[i])  # type: ignore[arg-type]
                if iwo_terms:
                    model.add(sum(iwo_terms) <= int(rule.value * 100))

        # Pre-compute helper expressions
        total_cost_expr = sum(scan_vars)  # type: ignore[arg-type]
        total_indexes_expr = sum(x)  # type: ignore[arg-type]

        def _iwo_expr() -> "cp_model_mod.LinearExpr":
            terms = []
            for i, idx in enumerate(problem.indexes):
                overhead = problem.index_write_overheads.get(
                    idx.id, idx.write_overhead
                )
                if overhead > 0:
                    terms.append(int(overhead * 100) * x[i])  # type: ignore[arg-type]
            return sum(terms) if terms else model.new_constant(0)  # type: ignore[return-value]

        # Coverage variables for MAXIMAL_COVERAGE
        coverage_vars: list[cp_model_mod.IntVar] = []
        for s_idx, scan in enumerate(problem.scans):
            has_covering = any(
                idx_id in idx_pos for idx_id in scan.index_costs
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

        # ----- Hierarchical solve loop -----
        solver = self._cp.CpSolver()
        solver.parameters.max_time_in_seconds = problem.settings.time_limit_seconds

        last_status = self._cp.UNKNOWN

        for goal_idx, goal in enumerate(goals):
            # Set objective for this goal
            if goal.name == GoalName.MINIMAL_COST:
                model.minimize(total_cost_expr)
            elif goal.name == GoalName.MINIMAL_INDEXES:
                model.minimize(total_indexes_expr)
            elif goal.name == GoalName.MAXIMAL_COVERAGE:
                if coverage_vars:
                    model.maximize(sum(coverage_vars))
                else:
                    continue
            elif goal.name == GoalName.MINIMAL_IWO:
                model.minimize(_iwo_expr())

            last_status = solver.solve(model)

            if last_status not in (self._cp.OPTIMAL, self._cp.FEASIBLE):
                break

            best_value = solver.objective_value

            # Pin with tolerance for next goals
            tolerance = goal.tolerance
            if tolerance > 0 and goal_idx < len(goals) - 1:
                if goal.name == GoalName.MINIMAL_COST:
                    max_allowed = int(best_value * (1 + tolerance))
                    model.add(total_cost_expr <= max_allowed)

                elif goal.name == GoalName.MINIMAL_INDEXES:
                    max_allowed = int(best_value * (1 + tolerance))
                    # At least allow the optimal value
                    max_allowed = max(max_allowed, int(best_value))
                    model.add(total_indexes_expr <= max_allowed)

                elif goal.name == GoalName.MAXIMAL_COVERAGE:
                    # For maximization, pin at least (1-tolerance) of best
                    min_allowed = int(best_value * (1 - tolerance))
                    if coverage_vars:
                        model.add(sum(coverage_vars) >= min_allowed)

                elif goal.name == GoalName.MINIMAL_IWO:
                    max_allowed_iwo = int(best_value * (1 + tolerance))
                    model.add(_iwo_expr() <= max_allowed_iwo)
            elif tolerance == 0 and goal_idx < len(goals) - 1:
                # Exact pin: next goal must respect this exact optimum
                if goal.name == GoalName.MINIMAL_COST:
                    model.add(total_cost_expr <= int(best_value))
                elif goal.name == GoalName.MINIMAL_INDEXES:
                    model.add(total_indexes_expr <= int(best_value))
                elif goal.name == GoalName.MAXIMAL_COVERAGE and coverage_vars:
                    model.add(sum(coverage_vars) >= int(best_value))
                elif goal.name == GoalName.MINIMAL_IWO:
                    model.add(_iwo_expr() <= int(best_value))

        elapsed_ms = (time.perf_counter() - t0) * 1000

        status_map = {
            self._cp.OPTIMAL: "OPTIMAL",
            self._cp.FEASIBLE: "FEASIBLE",
            self._cp.INFEASIBLE: "INFEASIBLE",
            self._cp.MODEL_INVALID: "MODEL_INVALID",
            self._cp.UNKNOWN: "UNKNOWN",
        }
        status_str = status_map.get(last_status, "UNKNOWN")

        if status_str in ("OPTIMAL", "FEASIBLE"):
            return self._extract_solution(
                solver, x, scan_vars, problem, status_str, elapsed_ms
            )

        return IndexSelectionSolution(
            status=status_str,
            total_scans=len(problem.scans),
            solve_time_ms=elapsed_ms,
        )

    def _extract_solution(
        self,
        solver: "cp_model_mod.CpSolver",
        index_vars: list["cp_model_mod.IntVar"],
        scan_vars: list["cp_model_mod.IntVar"],
        problem: IndexSelectionProblem,
        status: str,
        elapsed_ms: float,
    ) -> IndexSelectionSolution:
        """Extract solution from a solved model."""
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
