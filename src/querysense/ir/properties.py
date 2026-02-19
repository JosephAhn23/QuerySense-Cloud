"""
Layer B: Properties (portable fields with optional presence).

These are the "facts" that rules and causal scoring consume.  Every field
is optional -- the capability system tracks which fields are populated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CardinalitySignals:
    """Estimated vs actual row counts and loop information."""

    estimated_rows: float | None = None
    actual_rows: float | None = None
    actual_loops: int | None = None
    plan_width: int | None = None  # average output row width in bytes

    @property
    def has_actuals(self) -> bool:
        return self.actual_rows is not None

    @property
    def estimate_ratio(self) -> float | None:
        """actual / estimated.  >1 means under-estimate, <1 over-estimate."""
        if (
            self.actual_rows is not None
            and self.estimated_rows is not None
            and self.estimated_rows > 0
        ):
            return self.actual_rows / self.estimated_rows
        return None

    @property
    def estimate_error_factor(self) -> float | None:
        """max(actual/est, est/actual) -- symmetric error factor."""
        ratio = self.estimate_ratio
        if ratio is None:
            return None
        return max(ratio, 1.0 / ratio) if ratio > 0 else None

    @property
    def total_rows(self) -> float | None:
        """actual_rows * loops (total rows processed)."""
        if self.actual_rows is not None and self.actual_loops is not None:
            return self.actual_rows * self.actual_loops
        return self.actual_rows


@dataclass(frozen=True)
class CostSignals:
    """Engine cost numbers (arbitrary units, relative within a plan)."""

    startup_cost: float | None = None
    total_cost: float | None = None
    cost_share: float | None = None  # this node's cost / root total cost

    @property
    def has_cost(self) -> bool:
        return self.total_cost is not None


@dataclass(frozen=True)
class TimeSignals:
    """Per-operator elapsed time when provided by the engine."""

    startup_time_ms: float | None = None
    total_time_ms: float | None = None
    self_time_ms: float | None = None  # exclusive time (total - children)

    @property
    def has_timing(self) -> bool:
        return self.total_time_ms is not None


@dataclass(frozen=True)
class MemorySignals:
    """Spills, temp usage, buffers / IO counts."""

    # Buffer / page IO
    shared_hit_blocks: int | None = None
    shared_read_blocks: int | None = None
    shared_written_blocks: int | None = None
    local_hit_blocks: int | None = None
    local_read_blocks: int | None = None
    temp_read_blocks: int | None = None
    temp_written_blocks: int | None = None

    # IO timing
    io_read_time_ms: float | None = None
    io_write_time_ms: float | None = None

    # Sort / hash memory
    sort_space_used_kb: int | None = None
    sort_space_type: str | None = None  # "Memory" or "Disk"
    hash_buckets: int | None = None
    hash_batches: int | None = None
    peak_memory_kb: int | None = None

    @property
    def has_buffers(self) -> bool:
        return self.shared_hit_blocks is not None

    @property
    def is_spilling(self) -> bool:
        """True if sort/hash is spilling to disk."""
        if self.sort_space_type and self.sort_space_type.lower() == "disk":
            return True
        if self.temp_written_blocks and self.temp_written_blocks > 0:
            return True
        if self.hash_batches and self.hash_batches > 1:
            return True
        return False

    @property
    def buffer_hit_ratio(self) -> float | None:
        """shared_hit / (shared_hit + shared_read).  1.0 = perfect caching."""
        hit = self.shared_hit_blocks or 0
        read = self.shared_read_blocks or 0
        total = hit + read
        if total == 0:
            return None
        return hit / total


@dataclass(frozen=True)
class ParallelismSignals:
    """Planned/used workers and exchange/redistribution data."""

    planned_workers: int | None = None
    launched_workers: int | None = None
    is_parallel: bool = False
    exchange_type: str | None = None  # "hash", "broadcast", "range", etc.

    @property
    def worker_launch_ratio(self) -> float | None:
        if self.planned_workers and self.launched_workers is not None:
            return self.launched_workers / self.planned_workers
        return None


@dataclass(frozen=True)
class Predicates:
    """Predicate expressions attached to a node."""

    join_condition: str | None = None
    filter_condition: str | None = None
    index_condition: str | None = None
    recheck_condition: str | None = None
    hash_condition: str | None = None
    merge_condition: str | None = None
    sort_keys: tuple[str, ...] = ()
    output_columns: tuple[str, ...] = ()
    rows_removed_by_filter: int | None = None
    rows_removed_by_join_filter: int | None = None


@dataclass(frozen=True)
class IRProperties:
    """
    All portable properties for an IR node.

    Every sub-object is optional; the capability system tracks what is
    populated.
    """

    cardinality: CardinalitySignals = field(
        default_factory=CardinalitySignals,
    )
    cost: CostSignals = field(default_factory=CostSignals)
    time: TimeSignals = field(default_factory=TimeSignals)
    memory: MemorySignals = field(default_factory=MemorySignals)
    parallelism: ParallelismSignals = field(
        default_factory=ParallelismSignals,
    )
    predicates: Predicates = field(default_factory=Predicates)

    # Relation / object metadata
    relation_name: str | None = None
    schema_name: str | None = None
    alias: str | None = None
    index_name: str | None = None
    join_type: str | None = None  # "Inner", "Left", "Semi", etc.
    scan_direction: str | None = None  # "Forward", "Backward"
    output_ordering: str | None = None  # known sort order if any

    # Raw engine key-value pairs for anything not explicitly modelled
    extra: dict[str, Any] = field(default_factory=dict)
