"""
Query Tuning Toolkit — parameter extraction, plan diff, and safe testing.

    - ParameterExtractor: Named parameter extraction from SQL + samples
    - EnhancedPlanDiff:   Structural plan comparison with similarity scoring
"""

from querysense.tuning.parameters import (
    ParameterExtractor,
    ParameterSet,
    QueryParameter,
)
from querysense.tuning.plan_diff import (
    EnhancedPlanDiff,
    PlanDiffResult,
    PlanNode as DiffPlanNode,
    StructuralChange,
)

__all__ = [
    "DiffPlanNode",
    "EnhancedPlanDiff",
    "ParameterExtractor",
    "ParameterSet",
    "PlanDiffResult",
    "QueryParameter",
    "StructuralChange",
]
