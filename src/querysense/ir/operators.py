"""
Layer A: Core Physical Operator Algebra (portable).

This module contains:
1. The new universal IR operator types (IROperator, ScanMethod, JoinAlgorithm, etc.)
2. The backward-compatible Operator class used by node.py and postgresql.py

Design principle: keep the portable operator set intentionally small.
New operators are added only when at least two engines share the concept
*and* rules need to distinguish it from existing categories.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ══════════════════════════════════════════════════════════════════════
# Universal IR Operator Types (new)
# ══════════════════════════════════════════════════════════════════════


class IROperator(str, Enum):
    """Portable physical operator categories."""

    # Scan family
    SCAN_SEQ = "scan_seq"
    SCAN_INDEX = "scan_index"
    SCAN_INDEX_ONLY = "scan_index_only"
    SCAN_BITMAP = "scan_bitmap"
    SCAN_LOOKUP = "scan_lookup"
    SCAN_TID = "scan_tid"
    SCAN_FUNCTION = "scan_function"
    SCAN_SUBQUERY = "scan_subquery"
    SCAN_CTE = "scan_cte"
    SCAN_VALUES = "scan_values"
    SCAN_FOREIGN = "scan_foreign"
    SCAN_WORKTABLE = "scan_worktable"

    # Filter
    FILTER = "filter"

    # Join family
    JOIN_NESTED_LOOP = "join_nested_loop"
    JOIN_HASH = "join_hash"
    JOIN_MERGE = "join_merge"

    # Aggregate family
    AGGREGATE_HASH = "agg_hash"
    AGGREGATE_SORT = "agg_sort"
    AGGREGATE_PARTIAL = "agg_partial"
    AGGREGATE_FINAL = "agg_final"
    AGGREGATE_PLAIN = "agg_plain"

    # Sort family
    SORT = "sort"
    SORT_TOP_N = "sort_top_n"
    SORT_EXTERNAL = "sort_external"

    # Materialize family
    MATERIALIZE = "materialize"
    MATERIALIZE_CTE = "materialize_cte"
    MATERIALIZE_HASH = "materialize_hash"

    # Set operations
    SETOP_UNION = "setop_union"
    SETOP_INTERSECT = "setop_intersect"
    SETOP_EXCEPT = "setop_except"
    SETOP_APPEND = "setop_append"

    # Limit / top
    LIMIT = "limit"

    # Compute / project
    COMPUTE = "compute"
    WINDOW = "window"

    # Parallelism
    GATHER = "gather"
    GATHER_MERGE = "gather_merge"

    # Result / constant
    RESULT = "result"

    # DML
    MODIFY = "modify"
    LOCK_ROWS = "lock_rows"

    # Catch-all
    OTHER = "other"


# ── Algorithm / method sub-classifications ────────────────────────────


class ScanMethod(str, Enum):
    """Sub-classification for scan operators."""
    SEQUENTIAL = "sequential"
    INDEX = "index"
    INDEX_ONLY = "index_only"
    BITMAP = "bitmap"
    BITMAP_HEAP = "bitmap_heap"
    TID = "tid"
    FUNCTION = "function"
    FOREIGN = "foreign"
    CUSTOM = "custom"


class JoinAlgorithm(str, Enum):
    """Sub-classification for join operators."""
    NESTED_LOOP = "nested_loop"
    HASH = "hash"
    MERGE = "merge"
    INDEXED_LOOKUP = "indexed_lookup"


class AggregateStrategy(str, Enum):
    """Sub-classification for aggregate operators."""
    HASH = "hash"
    SORT = "sort"
    MIXED = "mixed"
    PLAIN = "plain"
    PARTIAL = "partial"
    FINAL = "final"


class SortVariant(str, Enum):
    """Sub-classification for sort operators."""
    IN_MEMORY = "in_memory"
    EXTERNAL = "external"
    TOP_N = "top_n"
    INCREMENTAL = "incremental"


class SetOpKind(str, Enum):
    """Sub-classification for set operations."""
    UNION_ALL = "union_all"
    UNION = "union"
    INTERSECT = "intersect"
    INTERSECT_ALL = "intersect_all"
    EXCEPT = "except"
    EXCEPT_ALL = "except_all"
    APPEND = "append"


# ── Operator metadata helpers ─────────────────────────────────────────


def is_scan(op: IROperator) -> bool:
    """True if operator is in the scan family."""
    return op.value.startswith("scan_")


def is_join(op: IROperator) -> bool:
    """True if operator is in the join family."""
    return op.value.startswith("join_")


def is_aggregate(op: IROperator) -> bool:
    """True if operator is in the aggregate family."""
    return op.value.startswith("agg_")


def is_sort(op: IROperator) -> bool:
    """True if operator is in the sort family."""
    return op.value.startswith("sort")


def scan_danger_rank(op: IROperator) -> int:
    """Higher number = more dangerous scan method (for regression scoring)."""
    _RANK = {
        IROperator.SCAN_INDEX_ONLY: 0,
        IROperator.SCAN_INDEX: 1,
        IROperator.SCAN_BITMAP: 2,
        IROperator.SCAN_TID: 2,
        IROperator.SCAN_SEQ: 4,
    }
    return _RANK.get(op, 3)


# ══════════════════════════════════════════════════════════════════════
# Backward-compatible Operator class (used by node.py, postgresql.py)
# ══════════════════════════════════════════════════════════════════════


@dataclass(frozen=True, eq=False)
class Operator:
    """
    Backward-compatible operator classification for the existing IR.

    Carries a category and an optional strategy for each category,
    plus provenance info (original node type string and engine).

    Used by ``node.py`` (``IRNode.operator``) and ``postgresql.py``.
    New code should prefer ``IROperator`` for portable analysis.

    Equality and hashing consider only the semantic fields (category +
    strategy), **not** ``original`` or ``engine``, so that a PostgreSQL
    Seq Scan and a MySQL ALL compare as the same operation.
    """

    category: str = "unknown"
    scan: Any = None
    join: Any = None
    aggregate: Any = None
    sort: Any = None
    materialize: Any = None
    control: Any = None
    original: str = ""
    engine: str = ""

    # ── Semantic equality (ignores provenance) ─────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Operator):
            return NotImplemented
        return (
            self.category == other.category
            and self.scan == other.scan
            and self.join == other.join
            and self.aggregate == other.aggregate
            and self.sort == other.sort
            and self.materialize == other.materialize
            and self.control == other.control
        )

    def __hash__(self) -> int:
        return hash((
            self.category,
            self.scan,
            self.join,
            self.aggregate,
            self.sort,
            self.materialize,
            self.control,
        ))

    # ── Convenience properties ────────────────────────────────────────

    @property
    def is_scan(self) -> bool:
        return self.category == "scan"

    @property
    def is_full_table_scan(self) -> bool:
        if not self.is_scan:
            return False
        if self.scan is None:
            return False
        val = self.scan.value if hasattr(self.scan, "value") else str(self.scan)
        return val in ("full_table", "sequential")

    @property
    def is_index_scan(self) -> bool:
        if not self.is_scan:
            return False
        if self.scan is None:
            return False
        val = self.scan.value if hasattr(self.scan, "value") else str(self.scan)
        return val in ("index", "index_scan", "index_only")

    @property
    def is_join(self) -> bool:
        return self.category == "join"

    @property
    def is_hash_join(self) -> bool:
        if not self.is_join or self.join is None:
            return False
        val = self.join.value if hasattr(self.join, "value") else str(self.join)
        return val in ("hash", "hash_join")

    @property
    def is_nested_loop(self) -> bool:
        if not self.is_join or self.join is None:
            return False
        val = self.join.value if hasattr(self.join, "value") else str(self.join)
        return val in ("nested_loop",)

    @property
    def is_merge_join(self) -> bool:
        if not self.is_join or self.join is None:
            return False
        val = self.join.value if hasattr(self.join, "value") else str(self.join)
        return val in ("merge", "merge_join")

    @property
    def is_sort(self) -> bool:
        return self.category == "sort"

    @property
    def is_aggregate(self) -> bool:
        return self.category == "aggregate"

    @property
    def is_materialize(self) -> bool:
        return self.category == "materialize"

    @property
    def is_control(self) -> bool:
        return self.category == "control"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON output."""
        strategy = (
            self.scan or self.join or self.aggregate
            or self.sort or self.materialize or self.control
        )
        strategy_value = (
            strategy.value if hasattr(strategy, "value") else str(strategy)
        ) if strategy else None
        d: dict[str, Any] = {
            "category": self.category,
            "strategy": strategy_value,
            "original": self.original,
        }
        if self.engine:
            d["engine"] = self.engine
        return d

    def __repr__(self) -> str:
        strategy = (
            self.scan or self.join or self.aggregate
            or self.sort or self.materialize or self.control
        )
        strategy_str = (
            f", {strategy.value if hasattr(strategy, 'value') else strategy}"
            if strategy
            else ""
        )
        return f"Operator({self.category}{strategy_str})"
