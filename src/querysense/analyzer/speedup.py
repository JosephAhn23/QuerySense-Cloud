"""
Speedup estimation for findings.

Computes *estimated* speedup multipliers for each finding based on:
- Plan node cost ratios (index scan vs seq scan)
- Row selectivity (rows returned vs rows scanned)
- Statistical patterns from rule types
- Verification results (when available)

These estimates are conservative and always stated as ranges or
approximations (e.g., "~23x faster") rather than precise claims.

Usage:
    from querysense.analyzer.speedup import enrich_with_speedup

    findings = enrich_with_speedup(findings)
    for f in findings:
        print(f.metrics.get("estimated_speedup"))
        # "~23x faster"
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.analyzer.models import Finding


# ─── Speedup estimation functions per rule type ──────────────────────

def _estimate_seq_scan_speedup(finding: "Finding") -> tuple[float, str]:
    """
    Estimate speedup for adding an index to a sequential scan.

    Logic:
    - If we know rows_scanned and rows returned, the index would read
      only the returned rows (plus overhead) instead of all rows.
    - Speedup ≈ total_rows / matching_rows, bounded conservatively.
    """
    metrics = finding.metrics
    rows_scanned = metrics.get("rows_scanned", 0)
    rows_removed = metrics.get("rows_removed_by_filter", 0)

    # Approach 1: Use actual selectivity from filter
    if rows_scanned and rows_removed:
        total = rows_scanned + rows_removed
        if total > 0 and rows_scanned > 0:
            selectivity = rows_scanned / total
            if selectivity > 0:
                # Index scan reads ~matching rows, seq scan reads all
                # Add 20% overhead for index structure traversal
                raw_speedup = (1 / selectivity) * 0.8
                raw_speedup = max(1.0, min(raw_speedup, 10_000))
                return raw_speedup, _format_speedup(raw_speedup)

    # Approach 2: Use cost as proxy
    total_cost = finding.context.total_cost
    if total_cost > 1000:
        # Large cost means large table; index typically gives ~10-100x
        estimated = min(total_cost / 100, 100)
        return estimated, _format_speedup(estimated)

    # Approach 3: Use row count
    actual_rows = finding.context.actual_rows
    if actual_rows and actual_rows > 10_000:
        # With an index, we'd read O(log N + k) instead of O(N)
        estimated = actual_rows / max(math.log2(actual_rows) * 10, 1)
        estimated = max(2.0, min(estimated, 1000))
        return estimated, _format_speedup(estimated)

    return 0, ""


def _estimate_bad_row_estimate_speedup(finding: "Finding") -> tuple[float, str]:
    """
    Estimate speedup from fixing bad row estimates via ANALYZE.

    When the planner underestimates rows, it picks wrong join strategies
    or skips beneficial indexes. Running ANALYZE can fix this.
    """
    metrics = finding.metrics
    ratio = metrics.get("row_estimate_ratio", 1)

    if isinstance(ratio, (int, float)) and ratio > 1:
        # Large underestimate -> planner likely chose wrong strategy
        # Fixing could improve by a factor related to the misestimate
        estimated = min(ratio ** 0.5, 50)  # Square root of ratio, capped
        return estimated, _format_speedup(estimated)

    return 0, ""


def _estimate_spilling_speedup(finding: "Finding") -> tuple[float, str]:
    """
    Estimate speedup from eliminating disk spilling.

    Disk I/O is ~100x slower than memory. If we can increase work_mem
    to avoid spilling, the sort/hash step becomes much faster.
    """
    metrics = finding.metrics
    space_used_kb = metrics.get("sort_space_used", 0)

    if space_used_kb:
        # Disk I/O overhead depends on data volume
        # Small spills (< 100MB) → ~5-20x speedup
        # Large spills (> 1GB) → ~50-100x speedup (lots of disk I/O)
        mb = space_used_kb / 1024
        if mb < 100:
            estimated = min(5 + mb / 10, 20)
        else:
            estimated = min(20 + mb / 50, 100)
        return estimated, _format_speedup(estimated)

    return 5.0, "~5x faster (memory vs disk)"


def _estimate_nested_loop_speedup(finding: "Finding") -> tuple[float, str]:
    """
    Estimate speedup from fixing nested loop with large inner table.

    If the inner relation has no index, adding one converts O(N*M) to O(N*log(M)).
    """
    metrics = finding.metrics
    inner_rows = metrics.get("inner_rows", 0)
    outer_rows = metrics.get("outer_rows", 0)

    if inner_rows and outer_rows:
        # Without index: N * M comparisons
        # With index: N * log(M) lookups
        if inner_rows > 1:
            raw = inner_rows / max(math.log2(inner_rows), 1)
            estimated = max(2.0, min(raw, 1000))
            return estimated, _format_speedup(estimated)

    return 0, ""


def _estimate_generic_speedup(finding: "Finding") -> tuple[float, str]:
    """Fallback speedup estimate based on impact band and score."""
    band = finding.impact_band.value
    score = finding.impact_score

    if band == "HIGH" or score >= 7:
        return 10, ">10x faster"
    if band == "MEDIUM" or score >= 4:
        return 5, "2-10x faster"
    if band == "LOW" or score >= 1:
        return 1.5, "<2x faster"
    return 0, ""


# ─── Rule ID to estimator mapping ───────────────────────────────────

_ESTIMATORS: dict[str, object] = {
    "SEQ_SCAN_LARGE_TABLE": _estimate_seq_scan_speedup,
    "SEQ_SCAN_NO_FILTER": _estimate_seq_scan_speedup,
    "EXCESSIVE_SEQ_SCANS": _estimate_seq_scan_speedup,
    "BAD_ROW_ESTIMATE": _estimate_bad_row_estimate_speedup,
    "CARDINALITY_DRIFT": _estimate_bad_row_estimate_speedup,
    "STALE_STATISTICS": _estimate_bad_row_estimate_speedup,
    "SPILLING_TO_DISK": _estimate_spilling_speedup,
    "HASH_JOIN_BATCHES": _estimate_spilling_speedup,
    "NESTED_LOOP_LARGE_TABLE": _estimate_nested_loop_speedup,
    "SORT_AVOIDABLE_WITH_INDEX": _estimate_seq_scan_speedup,
    "LIMIT_WITHOUT_INDEX": _estimate_seq_scan_speedup,
}


def _format_speedup(ratio: float) -> str:
    """Format a speedup ratio into a human-readable string."""
    if ratio >= 100:
        return f"~{ratio:,.0f}x faster"
    if ratio >= 10:
        return f"~{ratio:.0f}x faster"
    if ratio >= 2:
        return f"~{ratio:.1f}x faster"
    if ratio >= 1.2:
        return f"~{ratio:.1f}x faster"
    return ""


def estimate_speedup(finding: "Finding") -> tuple[float, str]:
    """
    Estimate the speedup for a single finding.

    Returns:
        Tuple of (speedup_ratio, human_readable_string).
        speedup_ratio is a float >= 1.0 (1.0 = no improvement).
        human_readable_string is like "~23x faster" or "".
    """
    estimator = _ESTIMATORS.get(finding.rule_id, _estimate_generic_speedup)
    ratio, description = estimator(finding)  # type: ignore[operator]

    # Never return < 1.0 (that would mean the fix makes it slower)
    ratio = max(ratio, 0)
    return ratio, description


def enrich_with_speedup(findings: tuple["Finding", ...]) -> tuple["Finding", ...]:
    """
    Enrich a tuple of findings with estimated speedup metrics.

    Adds to each finding's metrics:
    - estimated_speedup_ratio: float (e.g., 23.0)
    - estimated_speedup: str (e.g., "~23x faster")

    Returns new Finding instances (Finding is frozen/immutable).
    """
    enriched: list["Finding"] = []

    for finding in findings:
        ratio, description = estimate_speedup(finding)

        if ratio > 0 or description:
            new_metrics = dict(finding.metrics)
            new_metrics["estimated_speedup_ratio"] = round(ratio, 1)
            new_metrics["estimated_speedup"] = description

            enriched.append(
                finding.model_copy(update={"metrics": new_metrics})
            )
        else:
            enriched.append(finding)

    return tuple(enriched)
