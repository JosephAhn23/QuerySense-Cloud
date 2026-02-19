"""
Transaction-based hypothetical index testing.

Tests index recommendations by running inside a transaction:
  1. BEGIN
  2. CREATE INDEX (physically creates it, only visible in this txn)
  3. EXPLAIN (captures the new plan)
  4. ROLLBACK (index is never committed)

This gives *real* planner cost estimates without HypoPG, and works on
any PostgreSQL instance without extensions.  The index is never persisted.

Usage:
    from querysense.verification.index_simulator import IndexSimulator

    sim = IndexSimulator(conn)
    result = await sim.simulate(
        create_index_sql="CREATE INDEX ON orders(customer_id)",
        query_sql="SELECT * FROM orders WHERE customer_id = 42",
    )
    print(result.summary)
    # [IMPROVED] Index on orders(customer_id) | Before cost: 45000 | After cost: 12 | 3750x faster
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB connection protocol (asyncpg compatible)."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...
    async def execute(self, query: str, *args: Any) -> str: ...


@dataclass
class SimulationResult:
    """
    Result of an index simulation.

    Captures before/after cost estimates so users can see exactly
    how much an index would help.
    """

    index_sql: str
    query_sql: str

    before_cost: float = 0.0
    after_cost: float = 0.0
    before_plan: dict[str, Any] = field(default_factory=dict)
    after_plan: dict[str, Any] = field(default_factory=dict)

    before_node_type: str = ""
    after_node_type: str = ""

    index_size_estimate: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def improved(self) -> bool:
        """Whether the index improved the query plan."""
        return self.after_cost < self.before_cost and not self.errors

    @property
    def cost_ratio(self) -> float:
        """How many times faster the query would be."""
        if self.after_cost <= 0:
            return 0.0
        return self.before_cost / self.after_cost

    @property
    def cost_reduction_pct(self) -> float:
        """Percentage cost reduction."""
        if self.before_cost <= 0:
            return 0.0
        return ((self.before_cost - self.after_cost) / self.before_cost) * 100

    @property
    def plan_changed(self) -> bool:
        """Whether the plan structure changed (e.g., Seq Scan -> Index Scan)."""
        return self.before_node_type != self.after_node_type

    @property
    def summary(self) -> str:
        """Human-readable one-line summary."""
        if self.errors:
            return f"[ERROR] {self.index_sql} | {', '.join(self.errors)}"

        if not self.improved:
            return (
                f"[NO CHANGE] {self.index_sql} | "
                f"Cost: {self.before_cost:,.0f} -> {self.after_cost:,.0f}"
            )

        parts = [f"[IMPROVED] {self.index_sql}"]
        parts.append(f"Before: {self.before_cost:,.0f}")
        parts.append(f"After: {self.after_cost:,.0f}")

        if self.cost_ratio >= 2:
            parts.append(f"{self.cost_ratio:,.0f}x faster")
        else:
            parts.append(f"{self.cost_reduction_pct:.0f}% faster")

        if self.plan_changed:
            parts.append(f"{self.before_node_type} -> {self.after_node_type}")

        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "index_sql": self.index_sql,
            "query_sql": self.query_sql,
            "before_cost": self.before_cost,
            "after_cost": self.after_cost,
            "cost_ratio": round(self.cost_ratio, 1),
            "cost_reduction_pct": round(self.cost_reduction_pct, 1),
            "improved": self.improved,
            "plan_changed": self.plan_changed,
            "before_node_type": self.before_node_type,
            "after_node_type": self.after_node_type,
            "index_size_estimate": self.index_size_estimate,
            "errors": self.errors,
        }


def _extract_root_cost(plan_json: Any) -> float:
    """Extract root node total cost from EXPLAIN JSON."""
    if isinstance(plan_json, list) and plan_json:
        plan_json = plan_json[0]
    plan = plan_json.get("Plan", plan_json)
    return float(plan.get("Total Cost", 0))


def _extract_root_node_type(plan_json: Any) -> str:
    """Extract root node type from EXPLAIN JSON."""
    if isinstance(plan_json, list) and plan_json:
        plan_json = plan_json[0]
    plan = plan_json.get("Plan", plan_json)
    return plan.get("Node Type", "")


def _normalize_create_index(sql: str) -> str:
    """Ensure CREATE INDEX has IF NOT EXISTS for safety."""
    sql = sql.strip().rstrip(";")
    pattern = re.compile(r"CREATE\s+INDEX\b", re.IGNORECASE)
    if "IF NOT EXISTS" not in sql.upper():
        sql = pattern.sub("CREATE INDEX IF NOT EXISTS", sql, count=1)
    return sql


class IndexSimulator:
    """
    Simulate index creation inside a transaction.

    Works on any PostgreSQL >= 9.5.  No extensions needed.
    The index is created inside BEGIN/ROLLBACK so it never persists.

    This is the simple, safe alternative to HypoPG.  Trade-offs:
    - Pro: Works everywhere, gives real planner estimates
    - Pro: No extensions required
    - Con: Actually builds the index (takes time for large tables)
    - Con: Acquires locks inside the transaction

    For large production databases, prefer HypoPGVerifier instead.
    For development and CI testing, IndexSimulator is ideal.
    """

    def __init__(self, conn: AsyncDBConnection) -> None:
        self.conn = conn

    async def simulate(
        self,
        create_index_sql: str,
        query_sql: str,
    ) -> SimulationResult:
        """
        Test an index recommendation by creating it in a transaction.

        Steps:
            1. EXPLAIN the query (capture before-plan)
            2. BEGIN transaction
            3. CREATE INDEX IF NOT EXISTS
            4. EXPLAIN the query again (capture after-plan)
            5. ROLLBACK (index is never committed)

        Args:
            create_index_sql: CREATE INDEX statement to test
            query_sql: SELECT query to measure

        Returns:
            SimulationResult with before/after cost comparison
        """
        result = SimulationResult(
            index_sql=create_index_sql,
            query_sql=query_sql,
        )

        try:
            # Step 1: Capture before plan (outside transaction)
            before_json = await self._explain(query_sql)
            result.before_cost = _extract_root_cost(before_json)
            result.before_node_type = _extract_root_node_type(before_json)
            result.before_plan = before_json

            # Step 2-4: Create index in transaction, re-explain, rollback
            safe_sql = _normalize_create_index(create_index_sql)

            await self.conn.execute("BEGIN")
            try:
                await self.conn.execute(safe_sql)
                after_json = await self._explain(query_sql)
                result.after_cost = _extract_root_cost(after_json)
                result.after_node_type = _extract_root_node_type(after_json)
                result.after_plan = after_json
            finally:
                # Always rollback - index must never persist
                await self.conn.execute("ROLLBACK")

        except Exception as exc:
            result.errors.append(str(exc))

        return result

    async def simulate_batch(
        self,
        recommendations: list[tuple[str, str]],
    ) -> list[SimulationResult]:
        """
        Simulate multiple index recommendations.

        Args:
            recommendations: List of (create_index_sql, query_sql) pairs

        Returns:
            List of SimulationResults, one per recommendation
        """
        results: list[SimulationResult] = []
        for create_sql, query_sql in recommendations:
            result = await self.simulate(create_sql, query_sql)
            results.append(result)
        return results

    async def simulate_from_findings(
        self,
        findings: list[Any],
        query_sql: str,
    ) -> list[SimulationResult]:
        """
        Simulate index recommendations from analysis findings.

        Extracts CREATE INDEX suggestions from findings and simulates each.

        Args:
            findings: List of Finding objects with suggestions
            query_sql: The query to test against

        Returns:
            List of SimulationResults for suggestions that contain CREATE INDEX
        """
        results: list[SimulationResult] = []
        for finding in findings:
            if not finding.suggestion:
                continue
            # Extract CREATE INDEX from suggestion
            for line in finding.suggestion.split("\n"):
                line = line.strip()
                if line.upper().startswith("CREATE INDEX"):
                    result = await self.simulate(line, query_sql)
                    results.append(result)
        return results

    async def _explain(self, sql: str) -> dict[str, Any]:
        """Run EXPLAIN (FORMAT JSON, COSTS) and parse result."""
        explain_sql = f"EXPLAIN (FORMAT JSON, COSTS) {sql}"
        raw = await self.conn.fetchval(explain_sql)
        if isinstance(raw, str):
            return json.loads(raw)
        return raw


def format_simulation_results(results: list[SimulationResult]) -> str:
    """
    Format simulation results as a readable ASCII report.

    Returns a multi-line string suitable for terminal output.
    """
    if not results:
        return "No index simulations to report."

    lines: list[str] = []
    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║             Index Simulation Results                        ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")

    improved = [r for r in results if r.improved]
    unchanged = [r for r in results if not r.improved and not r.errors]
    errored = [r for r in results if r.errors]

    lines.append(
        f"║  {len(improved)} improved  {len(unchanged)} unchanged  "
        f"{len(errored)} errors{' ' * 24}║"
    )
    lines.append("╚══════════════════════════════════════════════════════════════╝")
    lines.append("")

    for i, r in enumerate(results, 1):
        if r.improved:
            marker = "✓"
        elif r.errors:
            marker = "✗"
        else:
            marker = "─"

        lines.append(f"  {marker} [{i}] {r.summary}")

        if r.improved and r.plan_changed:
            lines.append(
                f"        Plan: {r.before_node_type} → {r.after_node_type}"
            )
        lines.append("")

    return "\n".join(lines)
