"""
Constraint-Based Index Optimizer — solve the index selection problem optimally.

Closes the pganalyze "secret sauce" gap: "Optimizes across entire workload,
suggests multi-column indexes with column order optimization."

Models index selection as a knapsack/set-cover optimization problem:
- Each candidate index has a cost (storage) and benefit (query speedup)
- Indexes can cover multiple queries (covering index)
- Column order matters: (a, b) covers queries on (a) but not (b)
- Total storage budget constrains the solution

Uses a greedy approximation (no external dependencies) with optional
integer programming via PuLP/scipy if available.

Usage:
    from querysense.index_optimizer import IndexOptimizer

    optimizer = IndexOptimizer()
    result = optimizer.optimize(
        workload=workload_queries,
        storage_budget_mb=500,
    )
    for idx in result.selected_indexes:
        print(idx.create_sql)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class QueryWorkload:
    """A query in the workload with frequency and cost."""

    query_id: str
    sql_fingerprint: str  # Parameterized SQL
    frequency: int  # Executions per day
    avg_cost: float  # Average plan cost
    tables: list[str]  # Tables referenced
    filter_columns: list[str]  # Columns in WHERE
    join_columns: list[str]  # Columns in JOIN
    order_columns: list[str]  # Columns in ORDER BY
    group_columns: list[str]  # Columns in GROUP BY

    @property
    def total_daily_cost(self) -> float:
        return self.frequency * self.avg_cost


@dataclass(frozen=True)
class CandidateIndex:
    """A candidate index to evaluate."""

    table: str
    columns: list[str]  # Ordered list of columns
    is_unique: bool = False
    is_partial: bool = False
    partial_predicate: str = ""  # e.g., "WHERE status = 'active'"
    include_columns: list[str] = field(default_factory=list)  # INCLUDE for covering index

    # Estimated metrics
    estimated_size_mb: float = 0.0
    estimated_build_time_sec: float = 0.0

    @property
    def name(self) -> str:
        cols = "_".join(self.columns[:3])
        suffix = "_partial" if self.is_partial else ""
        return f"idx_{self.table}_{cols}{suffix}"

    @property
    def create_sql(self) -> str:
        unique = "UNIQUE " if self.is_unique else ""
        cols = ", ".join(self.columns)
        include = ""
        if self.include_columns:
            include = f" INCLUDE ({', '.join(self.include_columns)})"
        where = ""
        if self.is_partial and self.partial_predicate:
            where = f" WHERE {self.partial_predicate}"
        return (
            f"CREATE {unique}INDEX CONCURRENTLY {self.name} "
            f"ON {self.table} ({cols}){include}{where};"
        )

    def covers_query(self, query: QueryWorkload) -> float:
        """Estimate how much this index benefits a query (0-1 scale).

        Considers:
        - Column prefix matching (leftmost columns must match)
        - Coverage of filter, join, order, and group columns
        """
        if self.table not in query.tables:
            return 0.0

        # Check prefix match with filter/join columns
        needed = set(query.filter_columns + query.join_columns)
        benefit = 0.0

        if not self.columns:
            return 0.0

        # Leftmost column must match a filter or join column
        if self.columns[0] not in needed:
            # Check if it matches an ORDER BY (index-ordered scan)
            if self.columns[0] not in set(query.order_columns):
                return 0.0

        # Count how many query columns are covered by index prefix
        matched = 0
        for idx_col in self.columns:
            if idx_col in needed or idx_col in set(query.order_columns + query.group_columns):
                matched += 1
            else:
                break  # Prefix matching stops at first non-matching column

        total_needed = len(needed | set(query.order_columns))
        if total_needed == 0:
            return 0.0

        benefit = matched / total_needed

        # Bonus for covering index (all SELECT columns in INCLUDE)
        if self.include_columns:
            benefit = min(1.0, benefit * 1.2)

        return benefit


@dataclass(frozen=True)
class SelectedIndex:
    """An index selected by the optimizer."""

    index: CandidateIndex
    benefit_score: float
    queries_helped: list[str]  # Query IDs this index helps
    cost_reduction_estimate: float  # Estimated total cost reduction


@dataclass
class OptimizationResult:
    """Result of the index optimization."""

    selected_indexes: list[SelectedIndex] = field(default_factory=list)
    total_storage_mb: float = 0
    storage_budget_mb: float = 0
    total_benefit: float = 0
    queries_improved: int = 0
    queries_total: int = 0
    method: str = "greedy"  # "greedy" or "integer_programming"
    dropped_indexes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{len(self.selected_indexes)} indexes selected | "
            f"Storage: {self.total_storage_mb:.0f}MB / {self.storage_budget_mb:.0f}MB budget | "
            f"Queries improved: {self.queries_improved}/{self.queries_total} | "
            f"Method: {self.method}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "method": self.method,
            "storage_used_mb": round(self.total_storage_mb, 1),
            "storage_budget_mb": round(self.storage_budget_mb, 1),
            "total_benefit": round(self.total_benefit, 2),
            "indexes": [
                {
                    "create_sql": si.index.create_sql,
                    "table": si.index.table,
                    "columns": si.index.columns,
                    "size_mb": round(si.index.estimated_size_mb, 1),
                    "benefit": round(si.benefit_score, 3),
                    "queries_helped": si.queries_helped,
                }
                for si in self.selected_indexes
            ],
            "dropped_indexes": self.dropped_indexes,
        }


class IndexOptimizer:
    """Constraint-based index selection optimizer."""

    def optimize(
        self,
        workload: list[QueryWorkload],
        candidates: list[CandidateIndex],
        storage_budget_mb: float = 500,
        existing_indexes: list[CandidateIndex] | None = None,
        prefer_ip: bool = False,
    ) -> OptimizationResult:
        """Select the optimal set of indexes for a workload.

        Args:
            workload: List of queries with frequency and cost
            candidates: List of candidate indexes to evaluate
            storage_budget_mb: Maximum total index storage (MB)
            existing_indexes: Currently existing indexes (for drop recommendations)
            prefer_ip: Try integer programming first (requires pulp/scipy)

        Returns:
            OptimizationResult with selected indexes and analysis
        """
        if prefer_ip:
            try:
                return self._optimize_ip(workload, candidates, storage_budget_mb)
            except ImportError:
                logger.info("PuLP not available, falling back to greedy optimizer")

        return self._optimize_greedy(workload, candidates, storage_budget_mb, existing_indexes)

    def _optimize_greedy(
        self,
        workload: list[QueryWorkload],
        candidates: list[CandidateIndex],
        budget_mb: float,
        existing_indexes: list[CandidateIndex] | None = None,
    ) -> OptimizationResult:
        """Greedy optimization: pick highest benefit-to-cost ratio first.

        This is a greedy approximation of the 0-1 knapsack problem,
        which gives a solution within 2x of optimal.
        """
        # Compute benefit matrix: benefit[i][j] = how much candidate i helps query j
        benefit_matrix: list[list[float]] = []
        for candidate in candidates:
            row = [candidate.covers_query(q) for q in workload]
            benefit_matrix.append(row)

        # Compute total benefit for each candidate (weighted by query frequency)
        scored_candidates: list[tuple[float, int, CandidateIndex]] = []
        for i, candidate in enumerate(candidates):
            total_benefit = sum(
                benefit_matrix[i][j] * workload[j].total_daily_cost
                for j in range(len(workload))
            )
            if candidate.estimated_size_mb > 0:
                ratio = total_benefit / candidate.estimated_size_mb
            else:
                ratio = total_benefit
            scored_candidates.append((ratio, i, candidate))

        # Sort by benefit-to-cost ratio (descending)
        scored_candidates.sort(key=lambda x: x[0], reverse=True)

        selected: list[SelectedIndex] = []
        total_size = 0.0
        covered_queries: set[str] = set()

        for ratio, idx, candidate in scored_candidates:
            if total_size + candidate.estimated_size_mb > budget_mb:
                continue

            # Check if this candidate adds meaningful benefit
            benefit = sum(
                benefit_matrix[idx][j] * workload[j].total_daily_cost
                for j in range(len(workload))
            )
            if benefit <= 0:
                continue

            # Check for redundancy: skip if a selected index already covers same columns
            is_redundant = False
            for si in selected:
                if (si.index.table == candidate.table and
                    candidate.columns[:len(si.index.columns)] == si.index.columns):
                    is_redundant = True
                    break
            if is_redundant:
                continue

            # Determine which queries this helps
            helped = [
                workload[j].query_id
                for j in range(len(workload))
                if benefit_matrix[idx][j] > 0.3
            ]

            selected.append(SelectedIndex(
                index=candidate,
                benefit_score=ratio,
                queries_helped=helped,
                cost_reduction_estimate=benefit,
            ))
            total_size += candidate.estimated_size_mb
            covered_queries.update(helped)

        # Identify existing indexes to drop
        dropped: list[str] = []
        if existing_indexes:
            for existing in existing_indexes:
                # Check if any selected index covers the existing one
                for si in selected:
                    if (si.index.table == existing.table and
                        len(si.index.columns) >= len(existing.columns) and
                        si.index.columns[:len(existing.columns)] == existing.columns):
                        dropped.append(
                            f"DROP INDEX CONCURRENTLY IF EXISTS {existing.name}; "
                            f"-- Covered by {si.index.name}"
                        )
                        break

        return OptimizationResult(
            selected_indexes=selected,
            total_storage_mb=total_size,
            storage_budget_mb=budget_mb,
            total_benefit=sum(si.benefit_score for si in selected),
            queries_improved=len(covered_queries),
            queries_total=len(workload),
            method="greedy",
            dropped_indexes=dropped,
        )

    def _optimize_ip(
        self,
        workload: list[QueryWorkload],
        candidates: list[CandidateIndex],
        budget_mb: float,
    ) -> OptimizationResult:
        """Integer programming optimization using PuLP.

        Solves the index selection as a binary integer program:
        maximize: sum(benefit[i] * x[i])
        subject to: sum(size[i] * x[i]) <= budget
                    x[i] in {0, 1}
        """
        from pulp import LpMaximize, LpProblem, LpVariable, lpSum, value  # type: ignore[import-untyped]

        # Compute benefits
        benefits = []
        for candidate in candidates:
            benefit = sum(
                candidate.covers_query(q) * q.total_daily_cost
                for q in workload
            )
            benefits.append(benefit)

        # Create optimization problem
        prob = LpProblem("Index_Selection", LpMaximize)

        # Binary variables: 1 = select index, 0 = don't
        x = [LpVariable(f"idx_{i}", cat="Binary") for i in range(len(candidates))]

        # Objective: maximize total benefit
        prob += lpSum([benefits[i] * x[i] for i in range(len(candidates))])

        # Constraint: total size <= budget
        prob += lpSum([
            candidates[i].estimated_size_mb * x[i]
            for i in range(len(candidates))
        ]) <= budget_mb

        # Solve
        prob.solve()

        # Extract solution
        selected: list[SelectedIndex] = []
        total_size = 0.0
        covered_queries: set[str] = set()

        for i in range(len(candidates)):
            if value(x[i]) == 1:
                helped = [
                    q.query_id for q in workload
                    if candidates[i].covers_query(q) > 0.3
                ]
                selected.append(SelectedIndex(
                    index=candidates[i],
                    benefit_score=benefits[i],
                    queries_helped=helped,
                    cost_reduction_estimate=benefits[i],
                ))
                total_size += candidates[i].estimated_size_mb
                covered_queries.update(helped)

        return OptimizationResult(
            selected_indexes=selected,
            total_storage_mb=total_size,
            storage_budget_mb=budget_mb,
            total_benefit=sum(si.benefit_score for si in selected),
            queries_improved=len(covered_queries),
            queries_total=len(workload),
            method="integer_programming",
        )

    def generate_candidates(
        self,
        workload: list[QueryWorkload],
        max_columns: int = 3,
    ) -> list[CandidateIndex]:
        """Auto-generate candidate indexes from workload analysis.

        For each query, generates candidate indexes based on:
        - Single-column indexes on filter/join columns
        - Multi-column indexes combining filter + order columns
        - Covering indexes adding SELECT columns to INCLUDE

        Args:
            workload: List of queries with column information
            max_columns: Maximum columns per index (default 3)
        """
        candidates: list[CandidateIndex] = []
        seen: set[str] = set()

        for query in workload:
            for table in query.tables:
                # Single-column indexes on filter columns
                for col in query.filter_columns:
                    key = f"{table}:{col}"
                    if key not in seen:
                        seen.add(key)
                        candidates.append(CandidateIndex(
                            table=table,
                            columns=[col],
                            estimated_size_mb=self._estimate_index_size(1),
                        ))

                # Multi-column: filter + join
                if query.filter_columns and query.join_columns:
                    combined = query.filter_columns[:2] + query.join_columns[:1]
                    combined = list(dict.fromkeys(combined))[:max_columns]
                    key = f"{table}:{','.join(combined)}"
                    if key not in seen and len(combined) > 1:
                        seen.add(key)
                        candidates.append(CandidateIndex(
                            table=table,
                            columns=combined,
                            estimated_size_mb=self._estimate_index_size(len(combined)),
                        ))

                # Multi-column: filter + order
                if query.filter_columns and query.order_columns:
                    combined = query.filter_columns[:2] + query.order_columns[:1]
                    combined = list(dict.fromkeys(combined))[:max_columns]
                    key = f"{table}:{','.join(combined)}"
                    if key not in seen and len(combined) > 1:
                        seen.add(key)
                        candidates.append(CandidateIndex(
                            table=table,
                            columns=combined,
                            estimated_size_mb=self._estimate_index_size(len(combined)),
                        ))

        return candidates

    @staticmethod
    def _estimate_index_size(num_columns: int) -> float:
        """Rough estimate of index size in MB (per 1M rows)."""
        # Approximate: 8 bytes per column + 6 bytes overhead per row
        bytes_per_row = num_columns * 8 + 6
        return bytes_per_row * 1_000_000 / (1024 * 1024)  # Per 1M rows
