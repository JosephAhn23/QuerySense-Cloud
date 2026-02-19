"""
Rails + PostgreSQL Optimization Toolkit.

Automates what pganalyze teaches in "Advanced Database Programming with Rails"
and "Efficient Search in Rails with PostgreSQL":

- N+1 query detection from Rails logs
- Materialized view generation with model + migration + refresh schedule
- Custom PostgreSQL type detection (enums, composites, domains)
- Raw SQL optimization with Active Record equivalents

Every Rails app using PostgreSQL benefits from these patterns. pganalyze
sells ebooks teaching them. QuerySense automates them.
"""

from querysense.rails.analyzer import RailsAnalyzer, NPlusOneReport, QueryPattern
from querysense.rails.materialize import MaterializedViewGenerator, MaterializedViewSpec
from querysense.rails.types import TypeDetector, EnumCandidate, CompositeCandidate
from querysense.rails.optimize import RailsOptimizer, OptimizationReport

__all__ = [
    "CompositeCandidate",
    "EnumCandidate",
    "MaterializedViewGenerator",
    "MaterializedViewSpec",
    "NPlusOneReport",
    "OptimizationReport",
    "QueryPattern",
    "RailsAnalyzer",
    "RailsOptimizer",
    "TypeDetector",
]
