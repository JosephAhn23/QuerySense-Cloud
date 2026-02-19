"""
Layer C: Annotation + Capability System (engine-specific but structured).

Annotations carry engine-specific detail that the portable core should not
depend on, but that engine-specific rules or deep-dive UIs may need.

Capabilities are derived mechanically from the plan: if the plan contains
per-node actual rows, set HAS_ACTUAL_ROWS, etc.  Rules declare required
capabilities, and the system skips rules whose requirements are unmet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Capabilities ──────────────────────────────────────────────────────


class IRCapability(str, Enum):
    """
    Capability tags derived from plan evidence.

    Rules and causal hypotheses declare required capabilities; the analysis
    engine skips any rule whose requirements are not satisfied.
    """

    # Cardinality
    HAS_ACTUAL_ROWS = "has_actual_rows"
    HAS_ESTIMATED_ROWS = "has_estimated_rows"
    HAS_LOOPS = "has_loops"

    # Cost
    HAS_COST = "has_cost"
    HAS_COST_SHARE = "has_cost_share"

    # Timing
    HAS_TIMING = "has_timing"
    HAS_SELF_TIME = "has_self_time"

    # Memory / IO
    HAS_BUFFERS = "has_buffers"
    HAS_IO_TIMING = "has_io_timing"
    HAS_TEMP_SPILL = "has_temp_spill"
    HAS_SORT_DETAIL = "has_sort_detail"
    HAS_HASH_DETAIL = "has_hash_detail"

    # Parallelism
    HAS_PARALLEL_INFO = "has_parallel_info"

    # Engine identity
    ENGINE_POSTGRES = "engine_postgres"
    ENGINE_MYSQL = "engine_mysql"
    ENGINE_SQLSERVER = "engine_sqlserver"
    ENGINE_ORACLE = "engine_oracle"

    # Plan structure
    HAS_PREDICATES = "has_predicates"
    HAS_OUTPUT_COLUMNS = "has_output_columns"
    HAS_SUBPLANS = "has_subplans"
    HAS_CTE_NODES = "has_cte_nodes"

    # DB probe
    HAS_DB_STATS = "has_db_stats"
    HAS_DB_INDEXES = "has_db_indexes"
    HAS_DB_SETTINGS = "has_db_settings"

    # Temporal
    HAS_BASELINE = "has_baseline"
    HAS_HISTORY = "has_history"

    # Causal
    HAS_OPTIMIZER_TRACE = "has_optimizer_trace"  # MySQL only


# ── Engine-specific annotation structures ─────────────────────────────


@dataclass(frozen=True)
class PostgresAnnotations:
    """Postgres-specific plan metadata."""

    # Index-only scan specifics
    heap_fetches: int | None = None
    index_only_rows_by_idx: int | None = None

    # Parallel specifics
    workers_planned: int | None = None
    workers_launched: int | None = None

    # CTE details
    cte_name: str | None = None
    is_recursive: bool = False

    # Partitioning
    partitions_scanned: int | None = None
    partitions_total: int | None = None

    # Original node type string from EXPLAIN JSON
    original_node_type: str | None = None

    # WAL / JIT
    wal_records: int | None = None
    jit_functions: int | None = None
    jit_generation_time_ms: float | None = None
    jit_optimization_time_ms: float | None = None

    # Trigger info
    trigger_name: str | None = None
    trigger_time_ms: float | None = None

    # Raw extras
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MySQLAnnotations:
    """MySQL-specific plan metadata."""

    # Access type taxonomy
    access_type: str | None = None  # ALL, range, ref, eq_ref, const, ...
    possible_keys: tuple[str, ...] = ()
    key_length: str | None = None
    ref_columns: tuple[str, ...] = ()

    # Extra flags
    using_filesort: bool = False
    using_temporary: bool = False
    using_index: bool = False  # covering index
    using_index_condition: bool = False  # ICP
    using_join_buffer: str | None = None  # "Block Nested Loop", "hash join"
    using_mrr: bool = False

    # Optimizer trace hints
    optimizer_trace_decision: str | None = None
    optimizer_trace_cost: float | None = None

    # Partition pruning
    partitions_hit: tuple[str, ...] = ()
    partitions_total: int | None = None

    # Subquery strategy
    subquery_strategy: str | None = None  # MATERIALIZED, EXISTS->IN, etc.

    # Original type string
    original_type: str | None = None

    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SQLServerAnnotations:
    """SQL Server-specific plan metadata."""

    # Showplan operator details
    physical_op: str | None = None
    logical_op: str | None = None
    estimated_subtree_cost: float | None = None
    estimated_execution_mode: str | None = None  # Row / Batch
    memory_grant_kb: int | None = None

    # Key Lookup details
    lookup_predicate: str | None = None
    output_list: tuple[str, ...] = ()

    # Parallelism
    degree_of_parallelism: int | None = None
    exchange_type: str | None = None  # Repartition, Gather, etc.

    # Adaptive join
    is_adaptive: bool = False
    adaptive_threshold: float | None = None

    # Query Store link
    query_id: int | None = None
    plan_id: int | None = None

    # Warnings
    no_join_predicate: bool = False
    columns_with_no_statistics: tuple[str, ...] = ()
    spill_to_tempdb: bool = False

    # Original operator name
    original_operator: str | None = None

    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OracleAnnotations:
    """Oracle-specific plan metadata."""

    # Operation details
    operation: str | None = None
    options: str | None = None
    cpu_cost: float | None = None
    io_cost: float | None = None
    bytes_estimate: int | None = None

    # Partition pruning
    partition_start: str | None = None  # "1", "KEY", etc.
    partition_stop: str | None = None

    # Parallel distribution
    distribution: str | None = None  # "HASH", "BROADCAST", "RANGE", etc.

    # SQL Profile / Baseline
    sql_profile: str | None = None
    sql_plan_baseline: str | None = None

    # Original operation string
    original_operation: str | None = None

    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IRAnnotations:
    """
    Container for all engine-specific annotations on a node.

    At most one of ``postgres``, ``mysql``, ``sqlserver``, ``oracle``
    will be populated, matching the engine that produced the plan.
    """

    postgres: PostgresAnnotations | None = None
    mysql: MySQLAnnotations | None = None
    sqlserver: SQLServerAnnotations | None = None
    oracle: OracleAnnotations | None = None

    @property
    def engine(self) -> str | None:
        if self.postgres is not None:
            return "postgres"
        if self.mysql is not None:
            return "mysql"
        if self.sqlserver is not None:
            return "sqlserver"
        if self.oracle is not None:
            return "oracle"
        return None


# ── Capability derivation ─────────────────────────────────────────────


def derive_capabilities(
    plan: Any,  # IRPlan -- forward reference to avoid circular import
) -> frozenset[IRCapability]:
    """
    Walk an IR plan and derive the set of capabilities from its content.

    Called once after adapter translation to populate ``plan.capabilities``.
    """
    caps: set[IRCapability] = set()

    # Engine identity
    engine = plan.engine
    if engine == "postgres":
        caps.add(IRCapability.ENGINE_POSTGRES)
    elif engine == "mysql":
        caps.add(IRCapability.ENGINE_MYSQL)
    elif engine == "sqlserver":
        caps.add(IRCapability.ENGINE_SQLSERVER)
    elif engine == "oracle":
        caps.add(IRCapability.ENGINE_ORACLE)

    for node in plan.all_nodes():
        props = node.properties

        # Cardinality
        if props.cardinality.actual_rows is not None:
            caps.add(IRCapability.HAS_ACTUAL_ROWS)
        if props.cardinality.estimated_rows is not None:
            caps.add(IRCapability.HAS_ESTIMATED_ROWS)
        if props.cardinality.actual_loops is not None:
            caps.add(IRCapability.HAS_LOOPS)

        # Cost
        if props.cost.has_cost:
            caps.add(IRCapability.HAS_COST)
        if props.cost.cost_share is not None:
            caps.add(IRCapability.HAS_COST_SHARE)

        # Timing
        if props.time.has_timing:
            caps.add(IRCapability.HAS_TIMING)
        if props.time.self_time_ms is not None:
            caps.add(IRCapability.HAS_SELF_TIME)

        # Memory / IO
        if props.memory.has_buffers:
            caps.add(IRCapability.HAS_BUFFERS)
        if props.memory.io_read_time_ms is not None:
            caps.add(IRCapability.HAS_IO_TIMING)
        if props.memory.is_spilling:
            caps.add(IRCapability.HAS_TEMP_SPILL)
        if props.memory.sort_space_used_kb is not None:
            caps.add(IRCapability.HAS_SORT_DETAIL)
        if props.memory.hash_buckets is not None:
            caps.add(IRCapability.HAS_HASH_DETAIL)

        # Parallelism
        if props.parallelism.is_parallel:
            caps.add(IRCapability.HAS_PARALLEL_INFO)

        # Predicates
        p = props.predicates
        if any([p.join_condition, p.filter_condition, p.index_condition]):
            caps.add(IRCapability.HAS_PREDICATES)
        if p.output_columns:
            caps.add(IRCapability.HAS_OUTPUT_COLUMNS)

        # Annotations
        ann = node.annotations
        if ann.postgres and ann.postgres.cte_name:
            caps.add(IRCapability.HAS_CTE_NODES)
        if ann.mysql and ann.mysql.optimizer_trace_decision:
            caps.add(IRCapability.HAS_OPTIMIZER_TRACE)

    return frozenset(caps)
