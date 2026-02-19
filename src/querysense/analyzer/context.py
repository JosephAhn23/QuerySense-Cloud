"""
AnalysisContext - high-level analysis context built on the unified FactStore.

Provides a convenient interface for the analyzer by wrapping FactStore
with domain-specific helpers (evidence level computation, DB probe
integration, budget tracking).

This module re-exports FactKey and FactStore from capabilities.py
for backward compatibility. All fact keys are defined in capabilities.py
as the single source of truth.

Example:
    ctx = AnalysisContext()
    ctx.set_fact(
        FactKey.TABLE_STATS,
        TableStats(...),
        source="db_probe",
        evidence=EvidenceLevel.PLAN_SQL_DB,
    )

    if ctx.has_fact(FactKey.TABLE_STATS):
        stats = ctx.get_fact(FactKey.TABLE_STATS)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar, overload

from querysense.analyzer.capabilities import (
    Capability,
    FactKey,
    FactProvenance,
    FactStore,
)
from querysense.analyzer.models import EvidenceLevel, SQLConfidence

if TYPE_CHECKING:
    from querysense.analyzer.sql_ast import QueryInfo
    from querysense.db.probe import DBProbe
    from querysense.parser.models import ExplainOutput

_T = TypeVar("_T")

# Re-export for backward compatibility
__all__ = [
    "AnalysisContext",
    "FactKey",
    "FactStore",
    "FactNotFoundError",
    "FactTypeMismatchError",
]


class FactNotFoundError(Exception):
    """Requested fact is not present in context."""

    def __init__(self, key: FactKey) -> None:
        self.key = key
        super().__init__(f"Fact not found: {key.value}")


class FactTypeMismatchError(Exception):
    """Fact exists but has unexpected type."""

    def __init__(self, key: FactKey, expected: type, actual: type) -> None:
        self.key = key
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Fact {key.value} type mismatch: expected {expected.__name__}, got {actual.__name__}"
        )


class AnalysisContext:
    """
    High-level analysis context wrapping the unified FactStore.

    Provides:
    - Domain-specific fact storage with EvidenceLevel tracking
    - Capability derivation from facts
    - Type-safe fact retrieval
    - DB probe integration with budget tracking

    Thread Safety:
        This class is NOT thread-safe. Create one context per analysis.
    """

    def __init__(
        self,
        explain: "ExplainOutput | None" = None,
        sql: str | None = None,
        db_probe: "DBProbe | None" = None,
    ) -> None:
        """
        Initialize analysis context.

        Args:
            explain: The EXPLAIN output being analyzed
            sql: Optional SQL query text
            db_probe: Optional database probe for live queries
        """
        self._store = FactStore()
        self._db_probe = db_probe
        self._db_queries_run = 0
        self._db_time_ms = 0.0

        # Set core facts if provided
        if explain is not None:
            self.set_fact(
                FactKey.EXPLAIN_OUTPUT,
                explain,
                source="analyzer",
                evidence=EvidenceLevel.PLAN,
            )

        if sql is not None:
            self.set_fact(
                FactKey.SQL_TEXT,
                sql,
                source="analyzer",
                evidence=EvidenceLevel.PLAN,
            )

        if db_probe is not None:
            self._store.add_capability(Capability.DB_CONNECTED)

    @property
    def fact_store(self) -> FactStore:
        """Access the underlying FactStore directly."""
        return self._store

    def set_fact(
        self,
        key: FactKey,
        value: Any,
        source: str,
        evidence: EvidenceLevel,
        db_query: str | None = None,
    ) -> None:
        """
        Store a fact with provenance.

        Args:
            key: The fact key
            value: The fact value
            source: Source rule ID or "analyzer" or "db_probe"
            evidence: Evidence level backing this fact
            db_query: SQL query used to fetch (for DB-derived facts)
        """
        self._store.set(
            key,
            value,
            source_rule=source,
            evidence_level=evidence.value,
            db_query=db_query,
        )

    def has_fact(self, key: FactKey) -> bool:
        """Check if a fact exists."""
        return self._store.has(key)

    def get_fact(self, key: FactKey) -> Any:
        """
        Get a fact value.

        Raises:
            FactNotFoundError: If fact doesn't exist
        """
        if not self._store.has(key):
            raise FactNotFoundError(key)
        return self._store.get(key)

    def get_fact_or_none(self, key: FactKey) -> Any | None:
        """Get a fact value or None if not present."""
        return self._store.get(key)

    def get_fact_entry(self, key: FactKey) -> Any | None:
        """Get full fact entry with provenance."""
        return self._store.get_fact(key)

    def get_fact_typed(self, key: FactKey, expected_type: type[_T]) -> _T:
        """
        Get a fact with type checking.

        Raises:
            FactNotFoundError: If fact doesn't exist
            FactTypeMismatchError: If fact has wrong type
        """
        value = self.get_fact(key)
        if not isinstance(value, expected_type):
            raise FactTypeMismatchError(key, expected_type, type(value))
        return value

    @property
    def capabilities(self) -> frozenset[Capability]:
        """Get immutable set of available capabilities."""
        return self._store.capabilities

    def has_capability(self, cap: Capability) -> bool:
        """Check if a capability is available."""
        return self._store.has_capability(cap)

    def add_capability(self, cap: Capability) -> None:
        """Manually add a capability (e.g., from environment)."""
        self._store.add_capability(cap)

    @property
    def db_probe(self) -> "DBProbe | None":
        """Get the database probe if available."""
        return self._db_probe

    @property
    def db_queries_run(self) -> int:
        """Number of DB queries executed during analysis."""
        return self._db_queries_run

    @property
    def db_time_ms(self) -> float:
        """Total time spent on DB queries."""
        return self._db_time_ms

    def record_db_query(self, duration_ms: float) -> None:
        """Record a DB query execution for budgeting."""
        self._db_queries_run += 1
        self._db_time_ms += duration_ms

    def compute_evidence_level(self, sql_confidence: SQLConfidence) -> EvidenceLevel:
        """
        Compute the evidence level based on available facts.

        Evidence Level is computed, not set by hand:
        - PLAN: Have EXPLAIN output
        - PLAN+SQL: Have EXPLAIN + SQL with confidence >= MEDIUM
        - PLAN+SQL+DB: Have EXPLAIN + SQL + DBProbe facts
        """
        has_plan = self.has_fact(FactKey.EXPLAIN_OUTPUT)
        has_sql = sql_confidence in (SQLConfidence.HIGH, SQLConfidence.MEDIUM)
        has_db = any([
            self.has_fact(FactKey.TABLE_STATS),
            self.has_fact(FactKey.TABLE_INDEXES),
            self.has_fact(FactKey.DB_SETTINGS),
        ])

        if has_plan and has_sql and has_db:
            return EvidenceLevel.PLAN_SQL_DB
        elif has_plan and has_sql:
            return EvidenceLevel.PLAN_SQL
        else:
            return EvidenceLevel.PLAN

    def all_facts(self) -> dict[str, Any]:
        """Get all facts with their provenance (for debugging)."""
        return self._store.to_dict()

    def to_dict(self) -> dict[str, Any]:
        """Serialize context state for debugging."""
        result = self._store.to_dict()
        result["db_queries_run"] = self._db_queries_run
        result["db_time_ms"] = self._db_time_ms
        return result
