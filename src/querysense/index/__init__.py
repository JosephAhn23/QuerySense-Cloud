"""
Constraint Programming Index Advisor for QuerySense.

Implements pganalyze's Index Advisor 3.0 approach using Google OR-Tools CP-SAT
solver for globally optimal index selection. Based on the open-source model
presented at PGCon 2023 (https://github.com/pganalyze/pgcon2023).

Key modules:
    cp_model           - Core data models (Scan, Index, Problem, Solution)
    cp_solver          - CP-SAT solver with OR-Tools integration
    hierarchical       - Multi-objective optimization with tolerance parameters
    workload_classifier- Automatic table classification (read/write optimized)
    hot_detector       - HOT update detection for PostgreSQL
    functional_dependency - Functional dependency detection via extended statistics
    write_overhead     - Index write overhead (IWO) calculation
    advisor            - Main integration class combining all components

Usage:
    from querysense.index import ConstraintProgrammingIndexAdvisor

    advisor = ConstraintProgrammingIndexAdvisor()
    result = advisor.recommend(problem)
"""

from __future__ import annotations

from querysense.index.cp_model import (
    Goal,
    GoalName,
    Index,
    IndexSelectionProblem,
    IndexSelectionSolution,
    Rule,
    RuleName,
    Scan,
    SolverSettings,
    TableConfiguration,
)
from querysense.index.scan_extractor import CandidateSet, ScanExtractor

__all__ = [
    "CandidateSet",
    "Goal",
    "GoalName",
    "Index",
    "IndexSelectionProblem",
    "IndexSelectionSolution",
    "Rule",
    "RuleName",
    "Scan",
    "ScanExtractor",
    "SolverSettings",
    "TableConfiguration",
]
