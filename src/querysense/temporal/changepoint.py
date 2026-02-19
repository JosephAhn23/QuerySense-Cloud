"""
Change-point detection for time-series regression hunting.

Implements the PELT (Pruned Exact Linear Time) algorithm for detecting
multiple change points in noisy time series.  Also provides a simpler
threshold-based detector for quick analysis.

Reference: Killick, Fearnhead, Eckley (2012) "Optimal Detection of
Changepoints with a Linear Computational Cost"
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Sequence


@dataclass(frozen=True)
class Changepoint:
    """
    A detected change point in a time series.

    Attributes:
        index: Index in the time series where the change occurs.
        before_mean: Mean of the segment before the change.
        after_mean: Mean of the segment after the change.
        magnitude: Absolute difference in means.
        direction: "increase" or "decrease".
        confidence: Statistical confidence (0.0-1.0).
    """

    index: int
    before_mean: float
    after_mean: float
    magnitude: float
    direction: str  # "increase" or "decrease"
    confidence: float = 0.0


def detect_changepoints(
    series: Sequence[float],
    threshold_pct: float = 0.20,
    min_segment: int = 3,
) -> list[Changepoint]:
    """
    Simple threshold-based change-point detection.

    Scans the series with a sliding window and flags points where
    the mean changes by more than ``threshold_pct`` (relative to the
    before-mean).

    Good for quick checks; use ``pelt_changepoints`` for more rigorous
    detection.
    """
    n = len(series)
    if n < min_segment * 2:
        return []

    changepoints: list[Changepoint] = []

    for i in range(min_segment, n - min_segment + 1):
        before = series[:i]
        after = series[i:]

        before_mean = sum(before) / len(before)
        after_mean = sum(after) / len(after)

        if before_mean == 0:
            if after_mean == 0:
                continue
            magnitude = abs(after_mean)
            rel_change = float("inf")
        else:
            magnitude = abs(after_mean - before_mean)
            rel_change = magnitude / abs(before_mean)

        if rel_change >= threshold_pct:
            direction = "increase" if after_mean > before_mean else "decrease"

            # Simple confidence: based on how consistent the segments are
            before_var = _variance(before)
            after_var = _variance(after)
            noise = math.sqrt((before_var + after_var) / 2)
            signal = magnitude
            snr = signal / noise if noise > 0 else 10.0
            confidence = min(0.99, 1.0 - math.exp(-0.5 * snr))

            changepoints.append(Changepoint(
                index=i,
                before_mean=before_mean,
                after_mean=after_mean,
                magnitude=magnitude,
                direction=direction,
                confidence=confidence,
            ))

    # Deduplicate: keep the changepoint with highest confidence per region
    if not changepoints:
        return []

    return _deduplicate_changepoints(changepoints, min_segment)


def pelt_changepoints(
    series: Sequence[float],
    penalty: float | None = None,
    min_segment: int = 2,
) -> list[Changepoint]:
    """
    PELT (Pruned Exact Linear Time) change-point detection.

    Finds the optimal set of changepoints that minimizes the total
    cost (sum of segment variances) subject to a penalty per changepoint.

    Args:
        series: The numeric time series.
        penalty: Per-changepoint penalty.  If None, uses
                 ``2 * log(n) * variance(series)`` (BIC-style).
        min_segment: Minimum segment length.

    Returns:
        List of Changepoint objects.
    """
    data = list(series)
    n = len(data)

    if n < min_segment * 2:
        return []

    if penalty is None:
        total_var = _variance(data)
        # Use a moderate penalty: log(n) * median segment variance
        # BIC-style but scaled down to work well on short series
        penalty = math.log(max(n, 2)) * max(total_var, 1e-10) * 0.5

    # Cumulative sums for efficient cost calculation
    cum_sum = [0.0]
    cum_sq_sum = [0.0]
    for x in data:
        cum_sum.append(cum_sum[-1] + x)
        cum_sq_sum.append(cum_sq_sum[-1] + x * x)

    def segment_cost(start: int, end: int) -> float:
        """Cost of segment [start, end) using normal MLE."""
        length = end - start
        if length < 1:
            return 0.0
        s = cum_sum[end] - cum_sum[start]
        sq = cum_sq_sum[end] - cum_sq_sum[start]
        return sq - (s * s) / length

    # PELT dynamic programming
    F = [float("inf")] * (n + 1)
    F[0] = -penalty  # offset so F[0] + penalty = 0
    cp_map: dict[int, int] = {}  # maps end -> last changepoint
    R = {0}  # candidate set

    for t in range(min_segment, n + 1):
        best_cost = float("inf")
        best_r = 0

        for r in R:
            if t - r < min_segment:
                continue
            cost = F[r] + segment_cost(r, t) + penalty
            if cost < best_cost:
                best_cost = cost
                best_r = r

        F[t] = best_cost
        cp_map[t] = best_r

        # Pruning step: keep candidates that could still be optimal
        # for some future t.  Key: also keep candidates that are too
        # recent to evaluate (< min_segment away) since they haven't
        # had a chance yet.
        new_R = set()
        for r in R:
            if t - r < min_segment:
                # Too recent to evaluate — keep for future iterations
                new_R.add(r)
            elif F[r] + segment_cost(r, t) <= F[t]:
                new_R.add(r)
        new_R.add(t)
        R = new_R

    # Backtrack to find changepoints
    cp_indices: list[int] = []
    pos = n
    while pos > 0:
        prev = cp_map.get(pos, 0)
        if prev > 0:
            cp_indices.append(prev)
        pos = prev

    cp_indices.sort()

    # Build Changepoint objects
    changepoints: list[Changepoint] = []
    for idx in cp_indices:
        before = data[max(0, idx - min_segment):idx]
        after = data[idx:min(n, idx + min_segment)]

        if not before or not after:
            continue

        before_mean = sum(before) / len(before)
        after_mean = sum(after) / len(after)
        magnitude = abs(after_mean - before_mean)
        direction = "increase" if after_mean > before_mean else "decrease"

        # Confidence from signal-to-noise
        noise = math.sqrt(
            (_variance(before) + _variance(after)) / 2
        )
        snr = magnitude / noise if noise > 0 else 10.0
        confidence = min(0.99, 1.0 - math.exp(-0.5 * snr))

        changepoints.append(Changepoint(
            index=idx,
            before_mean=before_mean,
            after_mean=after_mean,
            magnitude=magnitude,
            direction=direction,
            confidence=confidence,
        ))

    return changepoints


# ── Helpers ───────────────────────────────────────────────────────────

def _variance(values: Sequence[float]) -> float:
    """Population variance."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return sum((x - mean) ** 2 for x in values) / n


def _deduplicate_changepoints(
    cps: list[Changepoint],
    min_gap: int,
) -> list[Changepoint]:
    """Keep highest-confidence changepoint per region."""
    if not cps:
        return []

    # Sort by index
    cps.sort(key=lambda c: c.index)
    result: list[Changepoint] = [cps[0]]

    for cp in cps[1:]:
        if cp.index - result[-1].index < min_gap:
            # Same region: keep higher confidence
            if cp.confidence > result[-1].confidence:
                result[-1] = cp
        else:
            result.append(cp)

    return result
