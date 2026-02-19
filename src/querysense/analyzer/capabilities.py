"""
Typed capabilities and fact store for the analyzer.

Capabilities are typed interfaces (not freeform strings) that rules can
require and provide. This enables:
- Compile-time checking of capability names
- DAG validation at startup
- Explicit SKIP reasons with missing capabilities

Facts are typed values with provenance that rules produce and consume.
Each fact includes:
- The value itself
- Source rule that produced it
- Evidence level
- Timestamp
- Optional DB query used (for debugging)

Design principles:
- Single source of truth: Capabilities are interfaces, not vibes
- Explicit contracts: Rules declare what they need and provide
- Provenance tracking: Every fact knows where it came from

Note: DAG construction and cycle detection have been consolidated
into querysense.analyzer.dag. Use build_rule_dag() from there.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from querysense.analyzer.models import EvidenceLevel
    from querysense.analyzer.rules.base import Rule


class Capability(str, Enum):
    """
    Typed capability keys that rules can require and provide.

    Capabilities are interfaces - they represent what data/functionality
    is available for rule execution. Using an enum instead of freeform
    strings prevents typos and enables static analysis.

    Categories:
    - SQL_*: SQL parsing capabilities
    - DB_*: Database probe capabilities
    - PLAN_*: Plan analysis capabilities
    - RULE_*: Capabilities provided by other rules
    """

    # SQL parsing capabilities
    SQL_AST = "sql_ast"                    # SQL AST available (pglast or sqlparse)
    SQL_AST_HIGH = "sql_ast_high"          # SQL AST with HIGH confidence (pglast only)
    SQL_AST_MEDIUM = "sql_ast_medium"      # SQL AST with MEDIUM+ confidence
    SQL_NORMALIZED = "sql_normalized"      # Normalized SQL for fingerprinting
    SQL_TABLES = "sql_tables"              # Table list extracted from SQL
    SQL_COLUMNS = "sql_columns"            # Column usage info from SQL
    SQL_PREDICATES = "sql_predicates"      # WHERE/JOIN predicates from SQL
    SQL_JOINS = "sql_joins"                # JOIN info from SQL
    SQL_TEXT = "sql_text"                  # Raw SQL text available

    # Database probe capabilities
    DB_CONNECTED = "db_connected"          # Database connection available
    DB_SCHEMA = "db_schema"                # Schema information available
    DB_STATS = "db_stats"                  # Table statistics available
    DB_INDEXES = "db_indexes"              # Index information available
    DB_SETTINGS = "db_settings"            # PostgreSQL settings available
    DB_PG_STAT = "db_pg_stat"              # pg_stat_statements available

    # Plan analysis capabilities
    EXPLAIN_PLAN = "explain_plan"          # EXPLAIN plan available (always true)
    EXPLAIN_ANALYZE = "explain_analyze"    # EXPLAIN ANALYZE data available
    EXPLAIN_BUFFERS = "explain_buffers"    # Buffer statistics available

    # Cross-phase capabilities
    PRIOR_FINDINGS = "prior_findings"      # Findings from PER_NODE phase (auto for AGGREGATE)

    # Rule-provided capabilities (examples - rules can define their own)
    SEQ_SCAN_FINDINGS = "seq_scan_findings"
    JOIN_FINDINGS = "join_findings"
    INDEX_RECOMMENDATIONS = "index_recommendations"
    VALIDATED_INDEXES = "validated_indexes"

    # Engine identification capabilities
    ENGINE_POSTGRESQL = "engine_postgresql"
    ENGINE_MYSQL = "engine_mysql"
    ENGINE_SQLSERVER = "engine_sqlserver"
    ENGINE_ORACLE = "engine_oracle"

    # IR availability
    IR_PLAN = "ir_plan"                    # IR plan representation available

    # Causal analysis capabilities
    CAUSAL_DIAGNOSIS = "causal_diagnosis"  # Causal diagnosis available
    HAS_ACTUALS = "has_actuals"            # Plan has actual row counts

    # Engine-specific feature capabilities
    PG_BITMAP_SCAN = "pg_bitmap_scan"      # PostgreSQL bitmap scan available
    PG_INDEX_ONLY = "pg_index_only"        # PostgreSQL index-only scan available
    PG_PARALLEL = "pg_parallel"            # PostgreSQL parallel query available
    PG_CTE_INLINE = "pg_cte_inline"        # PostgreSQL 12+ CTE inlining
    MYSQL_FILESORT = "mysql_filesort"      # MySQL filesort detected
    MYSQL_TEMPORARY = "mysql_temporary"    # MySQL temporary table detected
    MYSQL_INDEX_MERGE = "mysql_index_merge"  # MySQL index merge used
    SS_BATCH_MODE = "ss_batch_mode"        # SQL Server batch mode execution
    SS_COLUMNSTORE = "ss_columnstore"      # SQL Server columnstore index
    SS_ADAPTIVE_JOIN = "ss_adaptive_join"  # SQL Server adaptive join
    ORA_PARALLEL = "ora_parallel"          # Oracle parallel execution
    ORA_BITMAP = "ora_bitmap"              # Oracle bitmap access path
    ORA_PARTITION_PRUNING = "ora_partition_pruning"  # Oracle partition pruning

    def __str__(self) -> str:
        return self.value


class FactKey(str, Enum):
    """
    Typed keys for facts stored in the analysis context.

    Facts are values with provenance that rules produce and consume.
    Using typed keys prevents typos and enables autocomplete.

    This is the single authoritative FactKey enum for the entire system.
    """

    # Core inputs
    EXPLAIN_OUTPUT = "explain_output"       # The EXPLAIN JSON
    SQL_TEXT = "sql_text"                   # Raw SQL query text
    SQL_PARSE_RESULT = "sql_parse_result"   # SQLParseResult from parser

    # SQL-derived facts
    SQL_AST = "sql_ast"
    SQL_HASH = "sql_hash"
    SQL_CONFIDENCE = "sql_confidence"
    SQL_TABLES = "sql_tables"
    SQL_FILTER_COLUMNS = "sql_filter_columns"
    SQL_JOIN_COLUMNS = "sql_join_columns"
    SQL_ORDER_BY_COLUMNS = "sql_order_by_columns"
    SQL_PREDICATES = "sql_predicates"
    SQL_COLUMNS = "sql_columns"
    SQL_JOINS = "sql_joins"
    NORMALIZED_SQL = "normalized_sql"

    # Plan facts
    PLAN_FINGERPRINT = "plan_fingerprint"
    PLAN_NODE_COUNT = "plan_node_count"
    PLAN_TOTAL_COST = "plan_total_cost"
    PLAN_EXECUTION_TIME = "plan_execution_time"

    # Database facts (keyed by table name)
    TABLE_STATS = "table_stats"            # Dict[table_name, TableStats]
    TABLE_INDEXES = "table_indexes"        # Dict[table_name, List[IndexInfo]]
    TABLE_ROWCOUNT = "table_rowcount"      # Dict[table_name, int]
    ESTIMATED_SELECTIVITY = "estimated_selectivity"  # Dict[predicate, float]
    DB_CONNECTED = "db_connected"          # Boolean: DB available
    DB_SETTINGS = "db_settings"
    PG_STAT_STATEMENTS = "pg_stat_statements"

    # Analysis-derived facts
    PRIOR_FINDINGS = "prior_findings"
    SLOW_NODES = "slow_nodes"
    SEQ_SCAN_NODES = "seq_scan_nodes"
    SEQ_SCAN_TABLES = "seq_scan_tables"    # Tables with sequential scans
    JOIN_PAIRS = "join_pairs"              # Table pairs being joined
    MISSING_INDEXES = "missing_indexes"    # Recommended indexes

    # Config
    CONFIG = "config"

    # IR (Intermediate Representation) facts
    IR_PLAN = "ir_plan"                    # IRPlan object
    IR_ENGINE = "ir_engine"                # EngineType enum value
    IR_ROOT = "ir_root"                    # Root IRNode

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class FactProvenance:
    """
    Provenance information for a fact.

    Tracks where a fact came from for debugging and auditing.
    """

    source_rule: str | None = None         # Rule that produced this fact (None = system)
    evidence_level: str | None = None      # Evidence level when fact was produced
    timestamp: float = field(default_factory=time.time)
    db_query: str | None = None            # DB query used (redacted for security)

    def __repr__(self) -> str:
        source = self.source_rule or "system"
        return f"FactProvenance(source={source}, evidence={self.evidence_level})"


T = TypeVar("T")


@dataclass
class Fact(Generic[T]):
    """
    A fact with its value and provenance.

    Facts are the typed values that flow through the analysis pipeline.
    Each fact knows where it came from (provenance) for debugging.
    """

    key: FactKey
    value: T
    provenance: FactProvenance = field(default_factory=FactProvenance)

    def __repr__(self) -> str:
        return f"Fact({self.key.value}={self.value!r}, {self.provenance})"


class FactStore:
    """
    Typed fact registry for analysis context.

    The single authoritative store for analysis state. Combines:
    - Typed fact storage with provenance (from original FactStore)
    - Capability management and derivation (from AnalysisContext)
    - Type-safe retrieval with error handling

    Usage:
        store = FactStore()
        store.set(FactKey.SQL_HASH, "abc123", source_rule="sql_parser")

        if store.has(FactKey.SQL_HASH):
            sql_hash = store.get(FactKey.SQL_HASH)
    """

    def __init__(self) -> None:
        self._facts: dict[FactKey, Fact[Any]] = {}
        self._capabilities: set[Capability] = set()

    def set(
        self,
        key: FactKey,
        value: Any,
        *,
        source_rule: str | None = None,
        evidence_level: str | None = None,
        db_query: str | None = None,
    ) -> None:
        """
        Set a fact with provenance tracking.

        Args:
            key: The fact key (from FactKey enum)
            value: The fact value
            source_rule: Rule that produced this fact (None = system)
            evidence_level: Evidence level when fact was produced
            db_query: DB query used (will be stored for debugging)
        """
        provenance = FactProvenance(
            source_rule=source_rule,
            evidence_level=evidence_level,
            db_query=db_query,
        )
        self._facts[key] = Fact(key=key, value=value, provenance=provenance)
        # Auto-derive capabilities from facts
        self._update_capabilities_for_fact(key)

    def get(self, key: FactKey, default: T | None = None) -> T | None:
        """
        Get a fact value.

        Args:
            key: The fact key
            default: Default value if fact doesn't exist

        Returns:
            The fact value, or default if not found
        """
        fact = self._facts.get(key)
        if fact is None:
            return default
        return fact.value

    def get_required(self, key: FactKey) -> Any:
        """
        Get a required fact value.

        Raises:
            KeyError: If fact doesn't exist
        """
        fact = self._facts.get(key)
        if fact is None:
            raise KeyError(f"Required fact not found: {key.value}")
        return fact.value

    def get_typed(self, key: FactKey, expected_type: type) -> Any:
        """
        Get a fact with type checking.

        Raises:
            KeyError: If fact doesn't exist
            TypeError: If fact has wrong type
        """
        value = self.get_required(key)
        if not isinstance(value, expected_type):
            raise TypeError(
                f"Fact {key.value} type mismatch: expected {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )
        return value

    def get_fact(self, key: FactKey) -> Fact[Any] | None:
        """Get the full Fact object including provenance."""
        return self._facts.get(key)

    def has(self, key: FactKey) -> bool:
        """Check if a fact exists."""
        return key in self._facts

    def keys(self) -> set[FactKey]:
        """Get all fact keys."""
        return set(self._facts.keys())

    # Capability management

    def add_capability(self, capability: Capability) -> None:
        """Add a capability to the store."""
        self._capabilities.add(capability)

    def add_capabilities(self, capabilities: set[Capability]) -> None:
        """Add multiple capabilities."""
        self._capabilities.update(capabilities)

    def has_capability(self, capability: Capability) -> bool:
        """Check if a capability is available."""
        return capability in self._capabilities

    def has_capabilities(self, capabilities: set[Capability]) -> bool:
        """Check if all capabilities are available."""
        return capabilities.issubset(self._capabilities)

    def missing_capabilities(self, required: set[Capability]) -> set[Capability]:
        """Get capabilities that are required but missing."""
        return required - self._capabilities

    @property
    def capabilities(self) -> frozenset[Capability]:
        """Get all available capabilities."""
        return frozenset(self._capabilities)

    def _update_capabilities_for_fact(self, key: FactKey) -> None:
        """Update capabilities when a fact is added."""
        capability_map: dict[FactKey, list[Capability]] = {
            FactKey.SQL_PARSE_RESULT: [Capability.SQL_AST],
            FactKey.SQL_AST: [Capability.SQL_AST],
            FactKey.SQL_TABLES: [Capability.SQL_TABLES],
            FactKey.SQL_PREDICATES: [Capability.SQL_PREDICATES],
            FactKey.SQL_COLUMNS: [Capability.SQL_COLUMNS],
            FactKey.SQL_JOINS: [Capability.SQL_JOINS],
            FactKey.TABLE_STATS: [Capability.DB_STATS],
            FactKey.TABLE_INDEXES: [Capability.DB_INDEXES],
            FactKey.DB_SETTINGS: [Capability.DB_SETTINGS, Capability.DB_CONNECTED],
            FactKey.PG_STAT_STATEMENTS: [Capability.DB_PG_STAT],
            FactKey.PRIOR_FINDINGS: [Capability.PRIOR_FINDINGS],
            FactKey.NORMALIZED_SQL: [Capability.SQL_NORMALIZED],
            FactKey.EXPLAIN_OUTPUT: [Capability.EXPLAIN_PLAN],
            FactKey.SQL_TEXT: [Capability.SQL_TEXT],
            FactKey.IR_PLAN: [Capability.IR_PLAN],
        }
        if key in capability_map:
            for cap in capability_map[key]:
                self._capabilities.add(cap)

    def derive_capabilities_from_facts(self) -> None:
        """
        Derive capabilities from facts present.

        Implements the principle that capabilities should be
        derived from facts + environment, not set manually.
        """
        # SQL capabilities
        if self.has(FactKey.SQL_AST):
            self.add_capability(Capability.SQL_AST)
            confidence = self.get(FactKey.SQL_CONFIDENCE)
            if confidence == "high":
                self.add_capability(Capability.SQL_AST_HIGH)

        if self.has(FactKey.NORMALIZED_SQL):
            self.add_capability(Capability.SQL_NORMALIZED)

        if self.has(FactKey.SQL_TABLES):
            self.add_capability(Capability.SQL_TABLES)

        # Database capabilities
        if self.has(FactKey.DB_SETTINGS):
            self.add_capability(Capability.DB_CONNECTED)
            self.add_capability(Capability.DB_SETTINGS)

        if self.has(FactKey.TABLE_STATS):
            self.add_capability(Capability.DB_STATS)

        if self.has(FactKey.TABLE_INDEXES):
            self.add_capability(Capability.DB_INDEXES)

    def to_dict(self) -> dict[str, Any]:
        """Export facts as dictionary for debugging/serialization."""
        return {
            "facts": {
                key.value: {
                    "value": str(fact.value)[:100],  # Truncate for display
                    "source": fact.provenance.source_rule,
                    "evidence": fact.provenance.evidence_level,
                }
                for key, fact in self._facts.items()
            },
            "capabilities": sorted(c.value for c in self._capabilities),
        }


# =============================================================================
# Capability Conversion Utilities
# =============================================================================


def capabilities_from_strings(strings: tuple[str, ...] | set[str]) -> set[Capability]:
    """
    Convert string capability names to Capability enum values.

    For backward compatibility with existing rules that use string capabilities.
    Unknown strings are logged and ignored.
    """
    result: set[Capability] = set()
    for s in strings:
        try:
            result.add(Capability(s))
        except ValueError:
            # Unknown capability - could be a custom rule-provided capability
            # Log but don't fail (allows extensibility)
            pass
    return result


def capability_to_string(capability: Capability) -> str:
    """Convert Capability enum to string for backward compatibility."""
    return capability.value


def check_requirements(
    rule: "Rule",
    available: set[Capability] | frozenset[Capability],
) -> tuple[bool, list[str]]:
    """
    Check if a rule's requirements are satisfied.

    This is the single authoritative requirements checker. It converts
    a rule's string-based requires to Capability enums and checks against
    the available set.

    Args:
        rule: The rule to check (must have .requires attribute)
        available: Set of available Capability enums

    Returns:
        Tuple of (can_run, missing_capabilities_as_strings)
    """
    if not hasattr(rule, 'requires') or not rule.requires:
        return True, []

    # Convert available to string set for comparison
    available_strings = {cap.value for cap in available}

    # Check each requirement
    missing: list[str] = []
    for cap in rule.requires:
        cap_str = cap.value if isinstance(cap, Capability) else str(cap)
        if cap_str not in available_strings:
            missing.append(cap_str)

    if missing:
        return False, missing

    return True, []


# =============================================================================
# Capability Errors
# =============================================================================


class CapabilityError(Exception):
    """Base class for capability-related errors."""
    pass


class UnknownCapabilityError(CapabilityError):
    """Raised when a rule requires an unknown capability."""

    def __init__(self, rule_id: str, capability: str) -> None:
        self.rule_id = rule_id
        self.capability = capability
        super().__init__(f"Rule {rule_id} requires unknown capability: {capability}")
