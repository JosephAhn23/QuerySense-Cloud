"""
Cost normalization for cross-engine plan comparison.

Different engines use different cost models:
- PostgreSQL: Arbitrary cost units (default: seq_page_cost=1.0)
- MySQL: Cost in "read operations" (varies by engine, version)

This module provides tools to normalize costs into comparable units,
enabling cross-engine plan comparison and regression detection.

Design principles:
- Normalization is approximate, not exact (different models are incommensurable)
- Raw costs are always preserved alongside normalized costs
- Normalization factors are explicit and auditable
- No false precision: use bands, not exact values
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, unique
from typing import Any

from querysense.ir.node import EngineType


# =============================================================================
# Cost Bands (cross-engine comparable)
# =============================================================================


@unique
class CostBand(str, Enum):
    """
    Relative cost classification for cross-engine comparison.

    Instead of comparing raw costs (which are incommensurable across
    engines), we classify into bands that enable meaningful comparison.

    TRIVIAL:  Nearly instant (single-row lookups, cached results)
    LOW:      Fast operations (small index scans, limited sorts)
    MEDIUM:   Moderate operations (medium table scans, joins)
    HIGH:     Expensive operations (large table scans, complex joins)
    EXTREME:  Very expensive (full scans on huge tables, cartesian joins)
    """

    TRIVIAL = "trivial"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXTREME = "extreme"


# =============================================================================
# Normalized Cost
# =============================================================================


@dataclass(frozen=True)
class NormalizedCost:
    """
    Cost with both raw and normalized representations.

    The raw cost is engine-specific. The normalized cost is a
    best-effort mapping to a common scale for comparison.
    """

    raw_cost: float
    normalized_cost: float
    band: CostBand
    engine: EngineType

    @property
    def is_expensive(self) -> bool:
        return self.band in (CostBand.HIGH, CostBand.EXTREME)


# =============================================================================
# Cost Normalizer
# =============================================================================


class CostNormalizer:
    """
    Normalizes engine-specific costs into comparable units.

    Strategy:
    - PostgreSQL costs are used as the baseline (pass-through)
    - MySQL costs are scaled based on empirical calibration
    - Other engines use conservative estimates

    The normalization is intentionally coarse. We optimize for
    correct band classification (LOW vs HIGH), not precise values.
    """

    # PostgreSQL default cost constants
    PG_SEQ_PAGE_COST = 1.0
    PG_RANDOM_PAGE_COST = 4.0

    # MySQL cost calibration factors (empirical, approximate)
    # MySQL costs are roughly 0.25x PostgreSQL costs for equivalent operations
    MYSQL_TO_PG_FACTOR = 4.0

    # SQL Server: relative percentage of batch (0-100), scale to PG range
    # A 50% batch cost on a typical query ≈ 25,000 PG cost units
    SQLSERVER_TO_PG_FACTOR = 500.0

    # Oracle: internal cost units are comparable in magnitude to PG
    # Oracle's optimizer_index_cost_adj (default 100) makes units similar
    ORACLE_TO_PG_FACTOR = 1.0

    # Band thresholds (in PostgreSQL cost units)
    BAND_THRESHOLDS: dict[CostBand, float] = {
        CostBand.TRIVIAL: 10.0,
        CostBand.LOW: 1_000.0,
        CostBand.MEDIUM: 50_000.0,
        CostBand.HIGH: 500_000.0,
        # Everything above HIGH is EXTREME
    }

    def normalize(
        self,
        raw_cost: float,
        engine: EngineType,
        *,
        row_count: int | None = None,
    ) -> NormalizedCost:
        """
        Normalize an engine-specific cost.

        Args:
            raw_cost: The raw cost value from the engine
            engine: The source database engine
            row_count: Optional row count for calibration

        Returns:
            NormalizedCost with raw, normalized, and band classification
        """
        if engine == EngineType.POSTGRESQL:
            normalized = raw_cost  # PG is the baseline
        elif engine == EngineType.MYSQL:
            normalized = raw_cost * self.MYSQL_TO_PG_FACTOR
        elif engine == EngineType.SQLSERVER:
            normalized = raw_cost * self.SQLSERVER_TO_PG_FACTOR
        elif engine == EngineType.ORACLE:
            normalized = raw_cost * self.ORACLE_TO_PG_FACTOR
        else:
            # Conservative: assume similar to PostgreSQL
            normalized = raw_cost

        band = self._classify_band(normalized)

        return NormalizedCost(
            raw_cost=raw_cost,
            normalized_cost=normalized,
            band=band,
            engine=engine,
        )

    def _classify_band(self, normalized_cost: float) -> CostBand:
        """Classify a normalized cost into a band."""
        if normalized_cost <= self.BAND_THRESHOLDS[CostBand.TRIVIAL]:
            return CostBand.TRIVIAL
        if normalized_cost <= self.BAND_THRESHOLDS[CostBand.LOW]:
            return CostBand.LOW
        if normalized_cost <= self.BAND_THRESHOLDS[CostBand.MEDIUM]:
            return CostBand.MEDIUM
        if normalized_cost <= self.BAND_THRESHOLDS[CostBand.HIGH]:
            return CostBand.HIGH
        return CostBand.EXTREME

    def compare_costs(
        self,
        before: NormalizedCost,
        after: NormalizedCost,
    ) -> CostDelta:
        """
        Compare two normalized costs for regression detection.

        Args:
            before: Cost before the change
            after: Cost after the change

        Returns:
            CostDelta with regression/improvement analysis
        """
        if before.normalized_cost == 0:
            ratio = float("inf") if after.normalized_cost > 0 else 1.0
        else:
            ratio = after.normalized_cost / before.normalized_cost

        return CostDelta(
            before=before,
            after=after,
            ratio=ratio,
            band_changed=before.band != after.band,
            is_regression=ratio > 1.1,  # 10% threshold
            is_improvement=ratio < 0.9,  # 10% threshold
        )


@dataclass(frozen=True)
class CostDelta:
    """Result of comparing two costs."""

    before: NormalizedCost
    after: NormalizedCost
    ratio: float
    band_changed: bool
    is_regression: bool
    is_improvement: bool

    @property
    def percentage_change(self) -> float:
        """Percentage change (positive = regression, negative = improvement)."""
        return (self.ratio - 1.0) * 100
