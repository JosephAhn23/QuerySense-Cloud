"""
Greedy Fallback Solver — When OR-Tools is not installed.

Provides a reasonable (but not globally optimal) solution using a greedy
algorithm. pganalyze also mentions having a Greedy fallback method.

The greedy approach:
    1. Start with no indexes selected
    2. Repeatedly pick the index that gives the largest cost reduction
    3. Stop when no index improves cost or constraints are reached

This won't find the globally optimal solution (it can get stuck in local
optima), but it's fast and requires no external dependencies.

Usage:
    from querysense.index.greedy_solver import GreedySolver

    solver = GreedySolver()
    solution = solver.solve(problem)
"""

from __future__ import annotations

import time

from querysense.index.cp_model import (
    IndexSelectionProblem,
    IndexSelectionSolution,
    RuleName,
    ScanResult,
)


class GreedySolver:
    """
    Greedy fallback solver for index selection.

    Iteratively selects the index that provides the maximum marginal
    cost reduction until constraints are reached or no improvement remains.
    """

    def solve(self, problem: IndexSelectionProblem) -> IndexSelectionSolution:
        """
        Solve the index selection problem using a greedy algorithm.

        Args:
            problem: Complete index selection problem.

        Returns:
            IndexSelectionSolution (status will be "FEASIBLE", not "OPTIMAL").
        """
        t0 = time.perf_counter()

        if not problem.scans:
            return IndexSelectionSolution(
                status="FEASIBLE", total_cost=0, total_scans=0,
                solve_time_ms=0.0,
            )

        # Determine constraints
        max_indexes = None
        max_iwo = None
        for rule in problem.settings.rules:
            if rule.name == RuleName.MAXIMUM_NUMBER_OF_INDEXES:
                max_indexes = int(rule.value)
            elif rule.name == RuleName.MAXIMUM_IWO:
                max_iwo = rule.value

        # Build lookup structures
        idx_by_id = {idx.id: idx for idx in problem.indexes}

        # Current state: no indexes selected
        selected: set[str] = set()
        remaining: set[str] = {idx.id for idx in problem.indexes}
        current_iwo = 0.0

        def _compute_cost(sel: set[str]) -> tuple[int, list[ScanResult]]:
            """Compute total cost given selected indexes."""
            total = 0
            results: list[ScanResult] = []
            for scan in problem.scans:
                best_cost = scan.sequential_cost
                best_idx = None
                for idx_id, cost in scan.index_costs.items():
                    if idx_id in sel and cost < best_cost:
                        best_cost = cost
                        best_idx = idx_id
                total += best_cost
                results.append(ScanResult(
                    scan_id=scan.id,
                    cost=best_cost,
                    covering_index=best_idx,
                    is_sequential=best_idx is None,
                ))
            return total, results

        current_cost, _ = _compute_cost(selected)

        # Greedy loop: pick best index each iteration
        while remaining:
            # Check max indexes constraint
            if max_indexes is not None and len(selected) >= max_indexes:
                break

            best_improvement = 0
            best_candidate = None
            best_candidate_iwo = 0.0

            for idx_id in remaining:
                # Check IWO constraint
                iwo = problem.index_write_overheads.get(
                    idx_id, idx_by_id[idx_id].write_overhead
                )
                if max_iwo is not None and (current_iwo + iwo) > max_iwo:
                    continue

                # Measure marginal improvement
                trial = selected | {idx_id}
                trial_cost, _ = _compute_cost(trial)
                improvement = current_cost - trial_cost

                if improvement > best_improvement:
                    best_improvement = improvement
                    best_candidate = idx_id
                    best_candidate_iwo = iwo

            if best_candidate is None or best_improvement <= 0:
                break

            selected.add(best_candidate)
            remaining.discard(best_candidate)
            current_cost -= best_improvement
            current_iwo += best_candidate_iwo

        # Final solution
        final_cost, scan_results = _compute_cost(selected)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        covered = sum(1 for sr in scan_results if not sr.is_sequential)
        uncovered = len(scan_results) - covered

        return IndexSelectionSolution(
            status="FEASIBLE",
            selected_indexes=sorted(selected),
            scan_results=scan_results,
            total_cost=final_cost,
            total_indexes=len(selected),
            total_write_overhead=current_iwo,
            solve_time_ms=elapsed_ms,
            objective_value=final_cost,
            scans_covered=covered,
            scans_uncovered=uncovered,
            total_scans=len(problem.scans),
        )
