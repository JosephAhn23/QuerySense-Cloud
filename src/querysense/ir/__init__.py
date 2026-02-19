"""
Universal Query Plan Intermediate Representation (IR).

A three-layer plan model for portable, cross-engine query plan analysis:

- **Layer A (operators.py)**: Core physical operator algebra -- a small,
  stable set of operator categories that every engine maps into.
- **Layer B (properties.py)**: Properties -- portable numeric/structural
  fields that rules and causal hypotheses consume.
- **Layer C (annotations.py)**: Annotations & capabilities -- engine-specific
  metadata that remains structured but does not pollute the portable core.

The ``plan.py`` module provides the new ``UniversalIRPlan``/``UniversalIRNode``
that uses the three-layer model.  The ``node.py`` module provides the existing
backward-compatible ``IRNode``/``IRPlan`` used by current rules.
"""

# ── Backward-compatible exports (node.py) ─────────────────────────────
from querysense.ir.node import (
    IRNode,
    IRPlan,
    EngineType,
    OperatorCategory,
    ScanStrategy,
    JoinStrategy,
    JoinType,
    SortStrategy,
    ScanDirection,
    ControlStrategy,
    MaterializeStrategy,
    Condition,
    ConditionKind,
    BufferStats,
    SortInfo,
    HashInfo,
    ParallelInfo,
)

# ── New universal IR exports ──────────────────────────────────────────
from querysense.ir.operators import (
    IROperator,
    JoinAlgorithm,
    ScanMethod,
    SortVariant,
    AggregateStrategy,
    SetOpKind,
    Operator,
    is_scan,
    is_join,
    is_aggregate,
    is_sort,
    scan_danger_rank,
)
from querysense.ir.properties import (
    CardinalitySignals,
    CostSignals,
    TimeSignals,
    MemorySignals,
    ParallelismSignals,
    Predicates,
    IRProperties,
)
from querysense.ir.annotations import (
    IRAnnotations,
    IRCapability,
    PostgresAnnotations,
    MySQLAnnotations,
    SQLServerAnnotations,
    OracleAnnotations,
    derive_capabilities,
)
from querysense.ir.plan import (
    IRNode as UniversalIRNode,
    IRPlan as UniversalIRPlan,
)
from querysense.ir.cost import CostNormalizer, NormalizedCost, CostBand, CostDelta

# ── Backward-compatible utility functions ─────────────────────────────

from querysense.ir.adapters.base import auto_detect_adapter as _auto_detect


def detect_engine(raw_plan: dict) -> EngineType:
    """
    Detect the database engine from a raw EXPLAIN plan.

    Returns an EngineType enum value.
    """
    if isinstance(raw_plan, dict):
        if "Plan" in raw_plan and isinstance(raw_plan.get("Plan"), dict):
            plan = raw_plan["Plan"]
            if "Node Type" in plan:
                return EngineType.POSTGRESQL
        if "query_block" in raw_plan:
            return EngineType.MYSQL
    if isinstance(raw_plan, list) and raw_plan:
        first = raw_plan[0]
        if isinstance(first, dict) and "Plan" in first:
            return EngineType.POSTGRESQL
        if isinstance(first, dict) and "select_type" in first:
            return EngineType.MYSQL
    if isinstance(raw_plan, str) and "schemas.microsoft.com/sqlserver" in raw_plan[:500]:
        return EngineType.SQLSERVER
    return EngineType.UNKNOWN


def auto_convert(raw_plan: dict) -> IRPlan:
    """
    Auto-detect engine and convert a raw plan to the legacy IR.

    Uses the PostgreSQLAdapter (the primary adapter) for Postgres plans.
    Uses the MySQLAdapter for MySQL plans.
    """
    engine = detect_engine(raw_plan)

    if engine == EngineType.POSTGRESQL:
        from querysense.ir.adapters.postgresql import PostgreSQLAdapter
        adapter = PostgreSQLAdapter()
        if isinstance(raw_plan, list):
            raw_plan = raw_plan[0]
        return adapter.convert(raw_plan)

    if engine == EngineType.MYSQL:
        from querysense.ir.adapters.mysql import MySQLAdapter
        mysql_adapter = MySQLAdapter()
        return mysql_adapter.convert(raw_plan)

    raise ValueError(
        "Cannot detect engine from plan format. "
        "Pass engine explicitly or use a specific adapter."
    )


__all__ = [
    # Legacy node.py (backward-compatible)
    "IRNode",
    "IRPlan",
    "EngineType",
    "OperatorCategory",
    "ScanStrategy",
    "JoinStrategy",
    "JoinType",
    "SortStrategy",
    "ScanDirection",
    "ControlStrategy",
    "MaterializeStrategy",
    "Condition",
    "ConditionKind",
    "BufferStats",
    "SortInfo",
    "HashInfo",
    "ParallelInfo",
    # Utility functions (backward-compatible)
    "detect_engine",
    "auto_convert",
    # Operators
    "IROperator",
    "JoinAlgorithm",
    "ScanMethod",
    "SortVariant",
    "AggregateStrategy",
    "SetOpKind",
    "Operator",
    "is_scan",
    "is_join",
    "is_aggregate",
    "is_sort",
    "scan_danger_rank",
    # Properties
    "CardinalitySignals",
    "CostSignals",
    "TimeSignals",
    "MemorySignals",
    "ParallelismSignals",
    "Predicates",
    "IRProperties",
    # Annotations
    "IRAnnotations",
    "IRCapability",
    "PostgresAnnotations",
    "MySQLAnnotations",
    "SQLServerAnnotations",
    "OracleAnnotations",
    "derive_capabilities",
    # Universal plan
    "UniversalIRNode",
    "UniversalIRPlan",
    # Cost
    "CostNormalizer",
    "NormalizedCost",
    "CostBand",
    "CostDelta",
]
