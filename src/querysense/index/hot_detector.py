"""
HOT (Heap-Only Tuple) Update Detection for PostgreSQL.

HOT updates are a critical PostgreSQL optimization that allows UPDATEs to
avoid creating new index entries — but only if the updated columns are NOT
indexed. Adding an index on a frequently updated column can silently
disable HOT updates and degrade write performance.

This module detects when a candidate index would break HOT updates on
columns that are frequently updated, following pganalyze's approach:
https://pganalyze.com/blog/index-advisor-v3

Key concept:
    If column C receives frequent UPDATEs and there is no index on C,
    PostgreSQL can use HOT to update in-place. Adding an index on C
    forces a full-tuple update for every UPDATE, significantly increasing
    write I/O and autovacuum load.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from querysense.index.workload_classifier import TableStats


@dataclass(frozen=True)
class HOTWarning:
    """Warning that a candidate index would break HOT updates."""

    table: str
    column: str
    severity: str  # "WARNING" or "INFO"
    message: str
    details: str
    recommendation: str
    updates_per_minute: float
    current_hot_ratio: float

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "table": self.table,
            "column": self.column,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "recommendation": self.recommendation,
            "updates_per_minute": round(self.updates_per_minute, 1),
            "current_hot_ratio": round(self.current_hot_ratio, 3),
        }


@dataclass
class ColumnUpdateFrequency:
    """Tracks update frequency for individual columns."""

    column_name: str
    updates_per_minute: float = 0.0
    is_indexed: bool = False


class HOTUpdateDetector:
    """
    Detect columns where adding an index would break HOT updates.

    The detector checks each column in a candidate index against the
    table's update statistics. If a column receives frequent updates
    and the table currently benefits from HOT updates, a warning is issued.

    Thresholds:
        hot_update_threshold: updates/min above which a warning is issued (default 10)
        hot_ratio_threshold: current HOT ratio above which breaking HOT is significant
    """

    def __init__(
        self,
        hot_update_threshold: float = 10.0,
        hot_ratio_threshold: float = 0.3,
    ) -> None:
        self.hot_update_threshold = hot_update_threshold
        self.hot_ratio_threshold = hot_ratio_threshold

    def analyze(
        self,
        table_name: str,
        candidate_columns: list[str],
        table_stats: TableStats,
        column_update_frequencies: dict[str, float] | None = None,
    ) -> list[HOTWarning]:
        """
        Check if candidate index columns would break HOT updates.

        Args:
            table_name: Target table.
            candidate_columns: Columns in the proposed index.
            table_stats: Table-level statistics.
            column_update_frequencies: Per-column update rates (updates/min).
                If not provided, distributes table-level updates uniformly.

        Returns:
            List of HOTWarning objects for problematic columns.
        """
        warnings: list[HOTWarning] = []

        # If the table doesn't have significant HOT updates, no concern
        if table_stats.hot_update_ratio < self.hot_ratio_threshold:
            return warnings

        # Get per-column update frequencies
        col_freqs = column_update_frequencies or {}

        for column in candidate_columns:
            updates_pm = col_freqs.get(column, 0.0)

            # If we don't have per-column data, use a heuristic:
            # assume updates are distributed across columns
            if not col_freqs and table_stats.writes_per_minute > 0:
                # Rough estimate: if column is updated, assume it gets
                # a fraction of total writes
                updates_pm = table_stats.writes_per_minute * 0.3

            if updates_pm > self.hot_update_threshold:
                severity = "WARNING" if updates_pm > self.hot_update_threshold * 3 else "INFO"

                warnings.append(
                    HOTWarning(
                        table=table_name,
                        column=column,
                        severity=severity,
                        message=f"Index on {column} would disable HOT updates",
                        details=(
                            f"Column receives ~{updates_pm:.1f} updates/minute. "
                            f"Current HOT update ratio: {table_stats.hot_update_ratio:.1%}. "
                            f"Adding an index on this column will force full-tuple updates "
                            f"instead of HOT updates, increasing write I/O by "
                            f"~{self._estimate_write_increase(table_stats):.0f}%."
                        ),
                        recommendation=(
                            f"Consider whether column '{column}' needs indexing. "
                            f"If read performance on this column is critical, accept "
                            f"the HOT update trade-off. Otherwise, exclude '{column}' "
                            f"from the index to preserve HOT update efficiency."
                        ),
                        updates_per_minute=updates_pm,
                        current_hot_ratio=table_stats.hot_update_ratio,
                    )
                )

        return warnings

    def _estimate_write_increase(self, stats: TableStats) -> float:
        """
        Estimate the percentage increase in write I/O from losing HOT.

        When HOT is disabled, each UPDATE must:
        1. Write a new tuple version to a potentially different page
        2. Update every index entry for the row
        3. Leave dead tuples for vacuum to clean up

        The overhead is roughly proportional to the number of indexes
        and the current HOT ratio.
        """
        # If 80% of updates are HOT, losing HOT increases write load significantly
        # Rough model: overhead = hot_ratio * (1 + n_indexes * 0.3) * 100
        n_indexes = max(1, stats.idx_scan // max(1, stats.seq_scan + stats.idx_scan) * 5)
        return stats.hot_update_ratio * (1.0 + n_indexes * 0.3) * 100
