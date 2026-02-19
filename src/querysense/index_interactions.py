"""
Index Interaction Analyzer -- detect when indexes conflict, supersede, or synergize.

pganalyze's CP model considers interactions between indexes: some indexes are
redundant (covered by a wider index), some conflict (IWO accumulates), and
some synergize (bitmap AND scans, covering index eliminates heap access).

This module analyzes a set of existing and proposed indexes to detect:
1. Redundancy: Index A is a prefix of Index B (A is redundant)
2. Overlap: Indexes share leading columns (partial redundancy)
3. Conflict: Multiple indexes on write-heavy columns (IWO accumulates)
4. Synergy: Indexes that enable bitmap AND/OR scans together
5. Supersession: A proposed index makes existing indexes unnecessary

Usage:
    from querysense.index_interactions import IndexInteractionAnalyzer

    analyzer = IndexInteractionAnalyzer()
    result = analyzer.analyze(existing_indexes, proposed_indexes)
    for issue in result.redundancies:
        print(f"Drop {issue.redundant_index}: covered by {issue.covering_index}")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class IndexInfo:
    """Information about an index (existing or proposed)."""
    name: str
    table: str
    columns: tuple[str, ...]
    index_type: str = "btree"
    is_unique: bool = False
    is_partial: bool = False
    predicate: str = ""
    include_columns: tuple[str, ...] = ()
    is_proposed: bool = False    # True for candidates, False for existing
    size_bytes: int = 0
    scans_per_minute: float = 0.0  # How often it's used

    @property
    def all_columns(self) -> tuple[str, ...]:
        return self.columns + self.include_columns


@dataclass
class Redundancy:
    """A detected index redundancy."""
    redundant_index: str
    covering_index: str
    table: str
    reason: str
    space_saved_bytes: int = 0
    drop_sql: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "redundant": self.redundant_index,
            "covered_by": self.covering_index,
            "table": self.table,
            "reason": self.reason,
            "space_saved_mb": round(self.space_saved_bytes / 1024 / 1024, 2),
            "drop_sql": self.drop_sql,
        }


@dataclass
class Overlap:
    """Partially overlapping indexes."""
    index_a: str
    index_b: str
    table: str
    shared_columns: tuple[str, ...]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_a": self.index_a,
            "index_b": self.index_b,
            "shared_columns": list(self.shared_columns),
            "recommendation": self.recommendation,
        }


@dataclass
class Conflict:
    """Conflicting indexes (high write overhead)."""
    table: str
    indexes: list[str]
    total_iwo_score: float
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "indexes": self.indexes,
            "total_iwo_score": round(self.total_iwo_score, 2),
            "recommendation": self.recommendation,
        }


@dataclass
class Synergy:
    """Synergistic indexes (better together)."""
    index_a: str
    index_b: str
    table: str
    synergy_type: str  # bitmap_and, covering, partition_aware
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_a": self.index_a,
            "index_b": self.index_b,
            "type": self.synergy_type,
            "description": self.description,
        }


@dataclass
class InteractionReport:
    """Full index interaction analysis."""
    redundancies: list[Redundancy] = field(default_factory=list)
    overlaps: list[Overlap] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    synergies: list[Synergy] = field(default_factory=list)
    total_indexes: int = 0
    droppable_count: int = 0
    total_space_saved_mb: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_indexes": self.total_indexes,
            "droppable": self.droppable_count,
            "space_saved_mb": round(self.total_space_saved_mb, 2),
            "redundancies": [r.to_dict() for r in self.redundancies],
            "overlaps": [o.to_dict() for o in self.overlaps],
            "conflicts": [c.to_dict() for c in self.conflicts],
            "synergies": [s.to_dict() for s in self.synergies],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  INDEX INTERACTION ANALYSIS")
        lines.append("  " + "=" * 60)
        lines.append(f"  Total indexes: {self.total_indexes}")
        lines.append(f"  Redundant (droppable): {self.droppable_count}")
        lines.append(f"  Space reclaimable: {self.total_space_saved_mb:.1f}MB")
        lines.append("")

        if self.redundancies:
            lines.append("  Redundancies:")
            for r in self.redundancies:
                lines.append(f"    DROP: {r.redundant_index}")
                lines.append(f"      Covered by: {r.covering_index}")
                lines.append(f"      Reason: {r.reason}")
                lines.append(f"      SQL: {r.drop_sql}")
            lines.append("")

        if self.overlaps:
            lines.append("  Overlaps:")
            for o in self.overlaps:
                lines.append(f"    {o.index_a} ~ {o.index_b}")
                lines.append(f"      Shared: {', '.join(o.shared_columns)}")
                lines.append(f"      Action: {o.recommendation}")
            lines.append("")

        if self.conflicts:
            lines.append("  Write Conflicts:")
            for c in self.conflicts:
                lines.append(f"    Table {c.table}: {len(c.indexes)} indexes (IWO: {c.total_iwo_score:.1f})")
                lines.append(f"      Action: {c.recommendation}")
            lines.append("")

        if self.synergies:
            lines.append("  Synergies:")
            for s in self.synergies:
                lines.append(f"    {s.index_a} + {s.index_b}: {s.synergy_type}")
                lines.append(f"      {s.description}")
            lines.append("")

        return "\n".join(lines)


class IndexInteractionAnalyzer:
    """Analyze interactions between existing and proposed indexes."""

    def __init__(self, max_iwo_per_table: float = 30.0):
        self.max_iwo_per_table = max_iwo_per_table

    def analyze(
        self,
        existing: list[IndexInfo],
        proposed: list[IndexInfo] | None = None,
    ) -> InteractionReport:
        """Analyze index interactions."""
        all_indexes = list(existing) + list(proposed or [])
        report = InteractionReport(total_indexes=len(all_indexes))

        # Group by table
        by_table: dict[str, list[IndexInfo]] = {}
        for idx in all_indexes:
            by_table.setdefault(idx.table, []).append(idx)

        for table, indexes in by_table.items():
            # Detect redundancies
            report.redundancies.extend(self._find_redundancies(indexes))

            # Detect overlaps
            report.overlaps.extend(self._find_overlaps(indexes))

            # Detect write conflicts
            conflict = self._check_write_conflict(table, indexes)
            if conflict:
                report.conflicts.append(conflict)

            # Detect synergies
            report.synergies.extend(self._find_synergies(indexes))

        report.droppable_count = len(report.redundancies)
        report.total_space_saved_mb = sum(
            r.space_saved_bytes / 1024 / 1024 for r in report.redundancies
        )

        return report

    def _find_redundancies(self, indexes: list[IndexInfo]) -> list[Redundancy]:
        """Find indexes that are redundant (covered by another)."""
        redundancies: list[Redundancy] = []

        for i, a in enumerate(indexes):
            for j, b in enumerate(indexes):
                if i == j:
                    continue
                # Skip if A is unique (unique indexes serve a constraint purpose)
                if a.is_unique:
                    continue

                # Check if A is a prefix of B (same type)
                if a.index_type == b.index_type and self._is_prefix(a.columns, b.columns):
                    # A is covered by B
                    redundancies.append(Redundancy(
                        redundant_index=a.name,
                        covering_index=b.name,
                        table=a.table,
                        reason=(
                            f"Index {a.name}({', '.join(a.columns)}) is a prefix of "
                            f"{b.name}({', '.join(b.columns)})"
                        ),
                        space_saved_bytes=a.size_bytes,
                        drop_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {a.name};",
                    ))

                # Check if A's columns are a subset of B's INCLUDE columns
                if self._is_subset(a.columns, b.all_columns) and len(b.all_columns) > len(a.columns):
                    if a.name not in [r.redundant_index for r in redundancies]:
                        redundancies.append(Redundancy(
                            redundant_index=a.name,
                            covering_index=b.name,
                            table=a.table,
                            reason=f"Columns of {a.name} are covered by {b.name} (including INCLUDE columns)",
                            space_saved_bytes=a.size_bytes,
                            drop_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {a.name};",
                        ))

        return redundancies

    def _find_overlaps(self, indexes: list[IndexInfo]) -> list[Overlap]:
        """Find partially overlapping indexes."""
        overlaps: list[Overlap] = []
        seen: set[tuple[str, str]] = set()

        for i, a in enumerate(indexes):
            for j, b in enumerate(indexes):
                if j <= i:
                    continue
                key = (min(a.name, b.name), max(a.name, b.name))
                if key in seen:
                    continue

                shared = tuple(c for c in a.columns if c in b.columns)
                if shared and len(shared) < min(len(a.columns), len(b.columns)):
                    seen.add(key)
                    overlaps.append(Overlap(
                        index_a=a.name,
                        index_b=b.name,
                        table=a.table,
                        shared_columns=shared,
                        recommendation=(
                            f"Consider consolidating into a single index "
                            f"on ({', '.join(set(a.columns + b.columns))}) "
                            f"if query patterns allow"
                        ),
                    ))

        return overlaps

    def _check_write_conflict(self, table: str, indexes: list[IndexInfo]) -> Conflict | None:
        """Check if too many indexes cause write overhead conflicts."""
        if len(indexes) <= 3:
            return None

        # Simple IWO approximation: each index adds ~1-2 IWO points
        total_iwo = sum(
            1.0 + len(idx.columns) * 0.25 + (0.5 if idx.index_type != "btree" else 0)
            for idx in indexes
        )

        if total_iwo > self.max_iwo_per_table:
            return Conflict(
                table=table,
                indexes=[idx.name for idx in indexes],
                total_iwo_score=total_iwo,
                recommendation=(
                    f"Table has {len(indexes)} indexes with total IWO {total_iwo:.1f}. "
                    f"Consider dropping unused indexes to reduce write overhead."
                ),
            )

        return None

    def _find_synergies(self, indexes: list[IndexInfo]) -> list[Synergy]:
        """Find synergistic index combinations."""
        synergies: list[Synergy] = []

        for i, a in enumerate(indexes):
            for j, b in enumerate(indexes):
                if j <= i:
                    continue

                # Bitmap AND synergy: different leading columns on same table
                if (
                    a.columns and b.columns
                    and a.columns[0] != b.columns[0]
                    and not self._has_overlap(a.columns, b.columns)
                ):
                    synergies.append(Synergy(
                        index_a=a.name,
                        index_b=b.name,
                        table=a.table,
                        synergy_type="bitmap_and",
                        description=(
                            f"BitmapAnd scan possible: {a.name}({a.columns[0]}) AND "
                            f"{b.name}({b.columns[0]}) for multi-column filtering"
                        ),
                    ))

                # Covering index synergy: one index's columns are another's INCLUDE
                if a.include_columns and set(a.include_columns) & set(b.columns):
                    synergies.append(Synergy(
                        index_a=a.name,
                        index_b=b.name,
                        table=a.table,
                        synergy_type="covering",
                        description=(
                            f"Index-only scan: {a.name} covers columns needed by "
                            f"queries that would otherwise need {b.name}"
                        ),
                    ))

        return synergies

    @staticmethod
    def _is_prefix(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
        """Check if A is a prefix of B (same leading columns)."""
        if len(a) >= len(b):
            return False
        return b[:len(a)] == a

    @staticmethod
    def _is_subset(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
        """Check if all columns of A are in B."""
        return set(a).issubset(set(b))

    @staticmethod
    def _has_overlap(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
        """Check if any columns overlap."""
        return bool(set(a) & set(b))
