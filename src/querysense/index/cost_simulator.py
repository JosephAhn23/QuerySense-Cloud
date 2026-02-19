"""
Cost Simulator — Use HypoPG to generate candidate index costs for the CP model.

This is the critical bridge between the real PostgreSQL planner and the abstract
CP-SAT solver. For each (scan, candidate_index) pair, we:

    1. Create a hypothetical index via HypoPG
    2. Run EXPLAIN on the query
    3. Extract the planner's cost estimate
    4. Feed that cost into the CP model's Scan.index_costs

This gives the CP solver *real planner costs* instead of heuristic estimates,
which is how pganalyze achieves mathematically optimal recommendations.

Usage:
    from querysense.index.cost_simulator import CostSimulator

    simulator = CostSimulator(conn)
    problem = await simulator.build_problem(
        table="orders",
        queries=[
            {"sql": "SELECT * FROM orders WHERE customer_id = 42", "frequency": 1000},
        ],
    )
    # problem is now a fully-costed IndexSelectionProblem
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from querysense.index.cp_model import (
    Index,
    IndexSelectionProblem,
    Scan,
    SolverSettings,
)
from querysense.index.scan_extractor import CandidateSet, ScanExtractor


class AsyncDBConnection(Protocol):
    """Protocol for async database connections (asyncpg compatible)."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...
    async def execute(self, query: str, *args: Any) -> str: ...


@dataclass
class CostEstimate:
    """Cost estimate for a (scan, index) pair from the planner."""

    scan_id: str
    index_id: str
    cost_with_index: float
    cost_without_index: float
    plan_uses_index: bool
    estimated_rows: int = 0
    index_size_bytes: int = 0


class CostSimulator:
    """
    Generate real planner costs for candidate indexes using HypoPG.

    This module integrates with querysense's existing HypoPG verifier
    to create hypothetical indexes and measure their impact on query costs.
    """

    def __init__(self, conn: AsyncDBConnection) -> None:
        self.conn = conn
        self._extractor = ScanExtractor()
        self._hypopg_available: bool | None = None

    async def check_hypopg(self) -> bool:
        """Check if HypoPG extension is available."""
        if self._hypopg_available is not None:
            return self._hypopg_available
        try:
            result = await self.conn.fetchval(
                "SELECT EXISTS("
                "  SELECT 1 FROM pg_extension WHERE extname = 'hypopg'"
                ")"
            )
            self._hypopg_available = bool(result)
        except Exception:
            self._hypopg_available = False
        return self._hypopg_available

    async def build_problem(
        self,
        table: str,
        queries: list[dict[str, Any]],
        settings: SolverSettings | None = None,
        existing_indexes: list[str] | None = None,
    ) -> IndexSelectionProblem:
        """
        Build a fully-costed IndexSelectionProblem from queries and HypoPG.

        This is the main entry point. It:
        1. Extracts scans and candidates from SQL queries
        2. Measures sequential scan cost for each query
        3. Creates hypothetical indexes and measures costs
        4. Assembles the complete problem for the CP solver

        Args:
            table: Target table.
            queries: List of {"sql": ..., "frequency": ...} dicts.
            settings: Optional solver settings.
            existing_indexes: Names of indexes that already exist.

        Returns:
            IndexSelectionProblem with real planner costs.
        """
        if not await self.check_hypopg():
            raise RuntimeError(
                "HypoPG extension is not installed. "
                "Install with: CREATE EXTENSION hypopg;"
            )

        # Step 1: Extract scans and candidates
        candidate_set = self._extractor.extract_from_queries(
            queries, table=table
        )

        if not candidate_set.scans or not candidate_set.candidates:
            return IndexSelectionProblem(settings=settings or SolverSettings.default())

        # Step 2: Measure baseline costs (sequential scan)
        for scan_idx, scan_info in enumerate(candidate_set.scans):
            query = queries[scan_idx] if scan_idx < len(queries) else queries[0]
            sql = query.get("sql", "")
            if sql:
                baseline_cost = await self._get_query_cost(sql)
                # Update the scan with the real sequential cost
                candidate_set.scans[scan_idx] = Scan(
                    id=scan_info.id,
                    name=scan_info.name,
                    sequential_cost=int(baseline_cost),
                    index_costs=scan_info.index_costs,
                    frequency=scan_info.frequency,
                )

        # Step 3: For each candidate index, create via HypoPG and measure costs
        for candidate in candidate_set.candidates:
            create_sql = self._build_create_index_sql(candidate)

            try:
                # Create hypothetical index
                result = await self.conn.fetch(
                    "SELECT * FROM hypopg_create_index($1)", create_sql
                )
                if not result:
                    continue

                # Measure cost for each scan's query
                for scan_idx, scan in enumerate(candidate_set.scans):
                    query = queries[scan_idx] if scan_idx < len(queries) else queries[0]
                    sql = query.get("sql", "")
                    if not sql:
                        continue

                    cost_with_index = await self._get_query_cost(sql)
                    int_cost = int(cost_with_index)

                    # Only record if the index actually helps
                    if int_cost < scan.sequential_cost:
                        scan.index_costs[candidate.id] = int_cost

            except Exception:
                continue
            finally:
                # Clean up this hypothetical index
                try:
                    await self.conn.execute("SELECT hypopg_reset()")
                except Exception:
                    pass

        # Step 4: Calculate IWO
        iwo_map = await self._estimate_write_overheads(
            table, candidate_set.candidates
        )

        # Step 5: Assemble problem
        return IndexSelectionProblem(
            scans=candidate_set.scans,
            indexes=candidate_set.candidates,
            existing_indexes=existing_indexes or [],
            index_write_overheads=iwo_map,
            settings=settings or SolverSettings.default(),
        )

    async def cost_single_index(
        self,
        query_sql: str,
        create_index_sql: str,
    ) -> CostEstimate:
        """
        Measure the cost impact of a single index on a single query.

        Args:
            query_sql: The query to measure.
            create_index_sql: CREATE INDEX statement.

        Returns:
            CostEstimate with before/after costs.
        """
        if not await self.check_hypopg():
            raise RuntimeError("HypoPG extension not available")

        baseline = await self._get_query_cost(query_sql)

        try:
            result = await self.conn.fetch(
                "SELECT * FROM hypopg_create_index($1)", create_index_sql
            )
            with_index = await self._get_query_cost(query_sql)

            # Check if the plan actually uses the index
            plan = await self._get_explain_json(query_sql)
            uses_index = self._plan_uses_hypothetical(plan)

            return CostEstimate(
                scan_id="query",
                index_id=create_index_sql,
                cost_with_index=with_index,
                cost_without_index=baseline,
                plan_uses_index=uses_index,
            )
        finally:
            try:
                await self.conn.execute("SELECT hypopg_reset()")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_query_cost(self, sql: str) -> float:
        """Get total cost from EXPLAIN for a query."""
        try:
            explain_sql = f"EXPLAIN (FORMAT JSON, COSTS) {sql}"
            result = await self.conn.fetchval(explain_sql)

            if isinstance(result, str):
                plan_json = json.loads(result)
            else:
                plan_json = result

            if isinstance(plan_json, list) and plan_json:
                plan = plan_json[0].get("Plan", {})
            else:
                plan = plan_json.get("Plan", {}) if isinstance(plan_json, dict) else {}

            return float(plan.get("Total Cost", 0))
        except Exception:
            return 0.0

    async def _get_explain_json(self, sql: str) -> dict[str, Any]:
        """Get full EXPLAIN JSON."""
        try:
            explain_sql = f"EXPLAIN (FORMAT JSON, COSTS) {sql}"
            result = await self.conn.fetchval(explain_sql)
            if isinstance(result, str):
                return json.loads(result)
            return result or {}
        except Exception:
            return {}

    def _plan_uses_hypothetical(self, plan: Any) -> bool:
        """Check if an EXPLAIN plan references a hypothetical index."""
        plan_str = json.dumps(plan) if not isinstance(plan, str) else plan
        return "<hypothetical>" in plan_str.lower() or "hypopg" in plan_str.lower()

    def _build_create_index_sql(self, candidate: Index) -> str:
        """Build CREATE INDEX SQL from a candidate Index."""
        if candidate.definition:
            return candidate.definition
        cols = ", ".join(candidate.columns)
        using = f" USING {candidate.index_type}" if candidate.index_type != "btree" else ""
        return f"CREATE INDEX ON {candidate.table}{using} ({cols})"

    async def _estimate_write_overheads(
        self,
        table: str,
        candidates: list[Index],
    ) -> dict[str, float]:
        """Estimate write overhead using table stats."""
        iwo_map: dict[str, float] = {}
        try:
            stats = await self.conn.fetch(
                "SELECT n_tup_ins + n_tup_upd + n_tup_del AS total_writes "
                "FROM pg_stat_user_tables WHERE relname = $1",
                table,
            )
            total_writes = 0
            if stats:
                row = stats[0]
                total_writes = row[0] if isinstance(row, (list, tuple)) else getattr(row, "total_writes", 0)

            for c in candidates:
                # Simple heuristic: overhead proportional to writes * columns
                base = max(1, total_writes // 10000)
                iwo_map[c.id] = float(base * len(c.columns))
        except Exception:
            # Fallback: uniform overhead
            for c in candidates:
                iwo_map[c.id] = float(len(c.columns))

        return iwo_map
