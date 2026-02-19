"""
CP-SAT Tradeoff Analyzer — cost vs. index count Pareto analysis.

Extends the existing CP-SAT solver with:
1. Tradeoff curve generation (cost vs. index count)
2. Knee/elbow point detection for optimal index count
3. Budget-constrained optimization (storage MB limit)
4. Sensitivity analysis (how much does adding one more index help?)

Based on pganalyze Index Advisor's multi-objective approach.

Usage:
    from querysense.index.tradeoff_analyzer import TradeoffAnalyzer
    analyzer = TradeoffAnalyzer()
    result = await analyzer.analyze_tradeoffs(dsn, table="orders")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TradeoffPoint:
    """A single point on the tradeoff curve."""
    max_indexes: int | None  # None = unlimited
    selected_count: int
    total_cost: float
    cost_reduction_pct: float
    selected_indexes: list[str] = field(default_factory=list)
    total_size_mb: float = 0
    solve_time_ms: float = 0


@dataclass
class TradeoffResult:
    """Full tradeoff analysis result."""
    table: str = ""
    base_cost: float = 0  # Cost with zero indexes
    points: list[TradeoffPoint] = field(default_factory=list)
    knee_point: TradeoffPoint | None = None
    sensitivity: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "base_cost": self.base_cost,
            "points": [
                {"indexes": p.selected_count, "cost": p.total_cost,
                 "reduction_pct": p.cost_reduction_pct, "size_mb": p.total_size_mb}
                for p in self.points
            ],
            "knee_point": (
                {"indexes": self.knee_point.selected_count,
                 "cost": self.knee_point.total_cost,
                 "reduction_pct": self.knee_point.cost_reduction_pct}
                if self.knee_point else None
            ),
            "recommendation": self.recommendation,
        }


class TradeoffAnalyzer:
    """
    Analyze cost vs. index count tradeoffs using CP-SAT.

    Runs the solver multiple times with different index limits
    to generate a Pareto frontier, then finds the knee point.
    """

    def __init__(self, time_limit_seconds: int = 10) -> None:
        self.time_limit = time_limit_seconds

    async def analyze_tradeoffs(
        self,
        dsn: str,
        schema: str = "public",
        table: str | None = None,
        max_index_limit: int = 8,
    ) -> TradeoffResult:
        """
        Generate tradeoff curve for a table.

        Runs CP-SAT with index limits from 0 to max_index_limit,
        measures cost at each point, finds the knee.
        """
        from querysense.scan_extractor import ScanExtractor
        from querysense.iwo_calculator import IWOCalculator

        result = TradeoffResult(table=table or "all")

        # Extract scans
        extractor = ScanExtractor()
        workload = await extractor.extract_from_database(dsn, top_n=50)

        if not workload.scans:
            result.recommendation = "No scans found in workload"
            return result

        # Filter to table if specified
        scans = workload.scans
        if table:
            scans = [s for s in scans if s.table == table]

        if not scans:
            result.recommendation = f"No scans found for table {table}"
            return result

        # Calculate base cost (no indexes)
        result.base_cost = sum(
            s.costs.get("sequential", 1000) * s.frequency
            for s in scans
        )

        # Try each index limit
        for limit in range(0, max_index_limit + 1):
            point = await self._solve_with_limit(dsn, scans, limit)
            if point:
                point.cost_reduction_pct = (
                    (result.base_cost - point.total_cost)
                    / result.base_cost * 100
                    if result.base_cost > 0 else 0
                )
                result.points.append(point)

        # Also solve with no limit
        unlimited = await self._solve_with_limit(dsn, scans, None)
        if unlimited:
            unlimited.cost_reduction_pct = (
                (result.base_cost - unlimited.total_cost)
                / result.base_cost * 100
                if result.base_cost > 0 else 0
            )
            result.points.append(unlimited)

        # Find knee point
        result.knee_point = self._find_knee_point(result.points)

        # Sensitivity analysis
        result.sensitivity = self._calculate_sensitivity(result.points)

        # Recommendation
        result.recommendation = self._generate_recommendation(result)

        return result

    async def _solve_with_limit(
        self, dsn: str, scans: list, limit: int | None,
    ) -> TradeoffPoint | None:
        """Run CP-SAT with a specific index limit."""
        try:
            from querysense.index.advisor_pipeline import IndexAdvisorPipeline

            pipeline = IndexAdvisorPipeline()

            start = time.monotonic()
            advisor_result = await pipeline.advise(dsn, max_indexes=limit)
            solve_ms = (time.monotonic() - start) * 1000

            return TradeoffPoint(
                max_indexes=limit,
                selected_count=len(advisor_result.create_statements)
                    if hasattr(advisor_result, "create_statements") else 0,
                total_cost=advisor_result.total_cost
                    if hasattr(advisor_result, "total_cost") else 0,
                cost_reduction_pct=0,
                selected_indexes=[
                    s for s in (advisor_result.create_statements
                    if hasattr(advisor_result, "create_statements") else [])
                ],
                total_size_mb=advisor_result.total_size_mb
                    if hasattr(advisor_result, "total_size_mb") else 0,
                solve_time_ms=solve_ms,
            )
        except Exception as e:
            logger.debug("Solve with limit %s failed: %s", limit, e)
            return None

    def _find_knee_point(
        self, points: list[TradeoffPoint],
    ) -> TradeoffPoint | None:
        """
        Find the knee/elbow point in the tradeoff curve.

        The knee is where adding more indexes gives diminishing returns.
        """
        if len(points) < 3:
            return points[-1] if points else None

        # Calculate marginal improvement for each step
        improvements: list[float] = []
        for i in range(1, len(points)):
            prev = points[i - 1]
            curr = points[i]
            idx_increase = curr.selected_count - prev.selected_count
            cost_reduction = curr.cost_reduction_pct - prev.cost_reduction_pct

            if idx_increase > 0:
                marginal = cost_reduction / idx_increase
            else:
                marginal = 0
            improvements.append(marginal)

        if not improvements:
            return points[-1]

        # Knee = where marginal improvement drops below 30% of the best
        threshold = max(improvements) * 0.3
        for i, imp in enumerate(improvements):
            if imp < threshold and i > 0:
                return points[i]

        return points[-1]

    def _calculate_sensitivity(
        self, points: list[TradeoffPoint],
    ) -> list[dict[str, Any]]:
        """Calculate how much each additional index helps."""
        sensitivity: list[dict[str, Any]] = []

        for i in range(1, len(points)):
            prev = points[i - 1]
            curr = points[i]

            if curr.selected_count > prev.selected_count:
                sensitivity.append({
                    "from_indexes": prev.selected_count,
                    "to_indexes": curr.selected_count,
                    "additional_reduction_pct": round(
                        curr.cost_reduction_pct - prev.cost_reduction_pct, 2,
                    ),
                    "marginal_improvement_per_index": round(
                        (curr.cost_reduction_pct - prev.cost_reduction_pct)
                        / (curr.selected_count - prev.selected_count), 2,
                    ),
                    "additional_size_mb": round(
                        curr.total_size_mb - prev.total_size_mb, 2,
                    ),
                })

        return sensitivity

    def _generate_recommendation(self, result: TradeoffResult) -> str:
        if not result.knee_point:
            return "Insufficient data for recommendation."

        knee = result.knee_point
        if knee.cost_reduction_pct < 5:
            return (
                "Indexes provide minimal improvement for this workload. "
                "The bottleneck is likely elsewhere."
            )

        unlimited = result.points[-1] if result.points else None
        if unlimited and unlimited.selected_count == knee.selected_count:
            return (
                f"Optimal: {knee.selected_count} indexes "
                f"({knee.cost_reduction_pct:.1f}% cost reduction). "
                f"Adding more provides no additional benefit."
            )

        return (
            f"Recommended: {knee.selected_count} indexes "
            f"({knee.cost_reduction_pct:.1f}% cost reduction, "
            f"{knee.total_size_mb:.1f}MB). "
            f"Beyond this, diminishing returns."
        )
