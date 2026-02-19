"""
Index Write Overhead (IWO) Calculator.

Every index has a write cost: each INSERT, UPDATE, and DELETE must update
every index on the table. This module models that overhead explicitly,
following pganalyze's IWO metric from PGCon 2023.

The IWO score considers:
    - Table write rate (INSERT/UPDATE/DELETE per minute)
    - Number of columns indexed
    - Index type (B-tree vs GIN vs GiST)
    - Column data types and widths
    - Autovacuum impact

Higher IWO = more expensive to maintain the index during writes.

Reference:
    https://github.com/pganalyze/pgcon2023
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from querysense.index.workload_classifier import TableStats


# Relative write cost multipliers by index type.
# B-tree is the baseline (1.0); others are more expensive.
INDEX_TYPE_MULTIPLIERS: dict[str, float] = {
    "btree": 1.0,
    "hash": 0.8,     # Slightly cheaper for equality-only
    "gin": 1.5,      # GIN is expensive (multi-entry per row)
    "gist": 1.3,     # GiST is moderately expensive
    "brin": 0.2,     # BRIN is very cheap (only updates on page boundaries)
    "spgist": 1.2,   # SP-GiST is moderate
}

# Column type width estimates (bytes) for overhead calculation
COLUMN_WIDTH_ESTIMATES: dict[str, int] = {
    "integer": 4,
    "int": 4,
    "bigint": 8,
    "smallint": 2,
    "boolean": 1,
    "date": 4,
    "timestamp": 8,
    "timestamptz": 8,
    "uuid": 16,
    "text": 32,       # Average text column
    "varchar": 24,    # Average varchar
    "jsonb": 64,      # Average JSONB
    "json": 64,
    "float": 8,
    "double": 8,
    "numeric": 16,
    "inet": 16,
    "cidr": 16,
    "macaddr": 6,
}


@dataclass
class IWOResult:
    """Result of index write overhead calculation."""

    index_name: str
    table_name: str
    columns: list[str]
    index_type: str

    # Raw components
    base_overhead: float
    write_frequency_multiplier: float
    column_count_multiplier: float
    type_multiplier: float
    width_multiplier: float

    # Final score
    iwo_score: float

    # Classification
    classification: str  # "low", "medium", "high", "very_high"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "index_name": self.index_name,
            "table_name": self.table_name,
            "columns": self.columns,
            "index_type": self.index_type,
            "iwo_score": round(self.iwo_score, 2),
            "classification": self.classification,
            "components": {
                "base": self.base_overhead,
                "write_freq": round(self.write_frequency_multiplier, 2),
                "column_count": round(self.column_count_multiplier, 2),
                "type": self.type_multiplier,
                "width": round(self.width_multiplier, 2),
            },
        }


class IndexWriteOverheadCalculator:
    """
    Calculate the write overhead score for candidate indexes.

    The IWO score is a dimensionless value representing relative
    write cost. It can be used:
    1. As a constraint in the CP model (max total IWO)
    2. As a secondary optimization goal (minimize total IWO)
    3. For display/comparison in recommendations

    Score ranges:
        0-5:    Low overhead (safe to add)
        5-15:   Medium overhead (consider trade-off)
        15-30:  High overhead (only add if read benefit is significant)
        30+:    Very high overhead (likely not worth it)
    """

    def calculate(
        self,
        index_name: str,
        table_name: str,
        columns: list[str],
        index_type: str,
        table_stats: TableStats,
        column_types: dict[str, str] | None = None,
    ) -> IWOResult:
        """
        Calculate IWO score for a candidate index.

        Args:
            index_name: Name of the index.
            table_name: Target table.
            columns: Columns in the index.
            index_type: Index type (btree, gin, gist, etc.).
            table_stats: Table write statistics.
            column_types: Optional mapping of column name -> PostgreSQL type.

        Returns:
            IWOResult with the overhead score and components.
        """
        base_overhead = 1.0

        # 1. Write frequency multiplier
        #    More writes/min = higher overhead from maintaining the index
        writes_pm = table_stats.writes_per_minute
        if writes_pm <= 1:
            write_freq_mult = 0.1
        elif writes_pm <= 10:
            write_freq_mult = 0.5
        elif writes_pm <= 60:
            write_freq_mult = 1.0
        elif writes_pm <= 300:
            write_freq_mult = 2.0
        elif writes_pm <= 1000:
            write_freq_mult = 5.0
        else:
            write_freq_mult = min(writes_pm / 100, 10.0)

        # 2. Column count multiplier
        #    More columns = larger index entries = more I/O per write
        num_cols = len(columns)
        col_count_mult = 1.0 + (num_cols - 1) * 0.25

        # 3. Index type multiplier
        type_mult = INDEX_TYPE_MULTIPLIERS.get(index_type.lower(), 1.0)

        # 4. Column width multiplier
        #    Wider columns = larger index = more I/O
        total_width = 0
        for col in columns:
            col_type = (column_types or {}).get(col, "integer")
            total_width += COLUMN_WIDTH_ESTIMATES.get(col_type.lower(), 8)
        # Normalize: 8 bytes (one int) = 1.0x
        width_mult = max(0.5, total_width / 8.0)

        # Final score
        iwo_score = base_overhead * write_freq_mult * col_count_mult * type_mult * width_mult

        # Classification
        if iwo_score < 5:
            classification = "low"
        elif iwo_score < 15:
            classification = "medium"
        elif iwo_score < 30:
            classification = "high"
        else:
            classification = "very_high"

        return IWOResult(
            index_name=index_name,
            table_name=table_name,
            columns=columns,
            index_type=index_type,
            base_overhead=base_overhead,
            write_frequency_multiplier=write_freq_mult,
            column_count_multiplier=col_count_mult,
            type_multiplier=type_mult,
            width_multiplier=width_mult,
            iwo_score=round(iwo_score, 2),
            classification=classification,
        )

    def calculate_total_iwo(
        self,
        results: list[IWOResult],
    ) -> float:
        """Calculate total IWO across all indexes."""
        return sum(r.iwo_score for r in results)

    def format_summary(self, results: list[IWOResult]) -> str:
        """Format IWO results as a human-readable summary."""
        if not results:
            return "No indexes to evaluate."

        lines: list[str] = []
        lines.append("Index Write Overhead Analysis")
        lines.append("=" * 60)

        total = 0.0
        for r in sorted(results, key=lambda x: -x.iwo_score):
            total += r.iwo_score
            marker = ""
            if r.classification == "high":
                marker = " [!]"
            elif r.classification == "very_high":
                marker = " [!!]"
            lines.append(
                f"  {r.index_name:<40s} IWO: {r.iwo_score:>6.1f}  "
                f"({r.classification}){marker}"
            )

        lines.append("-" * 60)
        lines.append(f"  {'Total IWO:':<40s} {total:>6.1f}")
        return "\n".join(lines)
