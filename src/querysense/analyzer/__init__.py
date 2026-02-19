"""
Query plan analyzer module - rule engine with consolidated architecture.

Module responsibilities (one concept, one module):
- capabilities.py: Capability types, FactKey, FactStore, requirement checking
- context.py: AnalysisContext (high-level wrapper around FactStore)
- dag.py: Rule dependency DAG (build_rule_dag, RuleDAG, DAGExecutor)
- observability.py: Tracer, AnalyzerMetrics, exporters
- analyzer.py: Main Analyzer orchestrator
- models.py: Immutable domain models (Finding, AnalysisResult, etc.)
- rules/base.py: Rule base class and protocols
- registry.py: Rule registration and discovery
- sql_ast.py: SQL parsing port (pglast + sqlparse adapters)
- sql_parser.py: Internal sqlparse adapter (data models: QueryInfo, ColumnInfo)
"""

from querysense.analyzer.analyzer import Analyzer
from querysense.analyzer.capabilities import (
    Capability,
    FactKey,
    FactStore,
    check_requirements,
)
from querysense.analyzer.comparator import (
    AnalysisComparison,
    FindingDelta,
    compare_analyses,
    compare_explains,
)
from querysense.analyzer.dag import (
    CycleDetectedError,
    DAGExecutor,
    DAGValidationError,
    ExecutionPlan,
    RuleDAG,
    RuleNode,
    build_rule_dag,
)
from querysense.analyzer.errors import AnalyzerError, ConfigurationError, RuleError
from querysense.analyzer.fingerprint import (
    AnalysisCache,
    CachedAnalysis,
    PlanDiff,
    PlanFingerprint,
)
from querysense.analyzer.index_advisor import (
    CostEstimator,
    IndexRecommendation,
    IndexRecommender,
    recommend_indexes,
)
from querysense.analyzer.models import (
    AnalysisResult,
    EvidenceLevel,
    ExecutionMetadata,
    Finding,
    ImpactBand,
    NodeContext,
    ReproducibilityInfo,
    RulePhase,
    RuleRun,
    RuleRunStatus,
    Severity,
    SQLConfidence,
    compute_evidence_level,
)
from querysense.analyzer.observability import (
    AnalyzerMetrics,
    Tracer,
    TraceSpan,
)
from querysense.analyzer.sql_ast import (
    ColumnInfo,
    QueryInfo,
    SQLASTParser,
    SQLParseResult,
    SQLQueryAnalyzer,
    get_sql_parser,
    is_pglast_available,
)
from querysense.analyzer.sql_parser import (  # noqa: F401 – kept for backwards compat
    analyze_sql,
    suggest_indexes_for_query,
)
from querysense.analyzer.path import NodePath, traverse_with_path
from querysense.analyzer.registry import (
    RuleRegistry,
    get_registry,
    register_rule,
    reset_registry,
)
from querysense.analyzer.rules.base import Rule, RuleConfig
from querysense.analyzer.safety import (
    QuerySafetyChecker,
    QueryType,
    SafetyCheckResult,
    UnsafeQueryError,
)

# Import rules to register them
from querysense.analyzer.rules import bad_row_estimate as _bad_estimate  # noqa: F401
from querysense.analyzer.rules import correlated_subquery as _subquery  # noqa: F401
from querysense.analyzer.rules import excessive_seq_scans as _excessive  # noqa: F401
from querysense.analyzer.rules import missing_buffers as _buffers  # noqa: F401
from querysense.analyzer.rules import nested_loop_large_table as _nested_loop  # noqa: F401
from querysense.analyzer.rules import parallel_query_not_used as _parallel  # noqa: F401
from querysense.analyzer.rules import partition_pruning as _partition  # noqa: F401
from querysense.analyzer.rules import seq_scan_large_table as _seq_scan  # noqa: F401
from querysense.analyzer.rules import spilling_to_disk as _spilling  # noqa: F401

__all__ = [
    # Main orchestrator
    "Analyzer",
    # Capabilities (typed interfaces) - single authoritative source
    "Capability",
    "FactKey",
    "FactStore",
    "check_requirements",
    # DAG (single authoritative module)
    "RuleDAG",
    "RuleNode",
    "ExecutionPlan",
    "DAGExecutor",
    "CycleDetectedError",
    "DAGValidationError",
    "build_rule_dag",
    # Models
    "Finding",
    "Severity",
    "AnalysisResult",
    "ExecutionMetadata",
    "NodeContext",
    "RulePhase",
    "RuleRun",
    "RuleRunStatus",
    "EvidenceLevel",
    "SQLConfidence",
    "ImpactBand",
    "ReproducibilityInfo",
    "compute_evidence_level",
    # Path handling
    "NodePath",
    "traverse_with_path",
    # Registry
    "RuleRegistry",
    "get_registry",
    "register_rule",
    "reset_registry",
    # Rules
    "Rule",
    "RuleConfig",
    # Errors
    "AnalyzerError",
    "RuleError",
    "ConfigurationError",
    # Fingerprinting and caching
    "PlanFingerprint",
    "PlanDiff",
    "AnalysisCache",
    "CachedAnalysis",
    # Safety
    "QuerySafetyChecker",
    "SafetyCheckResult",
    "QueryType",
    "UnsafeQueryError",
    # Comparison
    "AnalysisComparison",
    "FindingDelta",
    "compare_analyses",
    "compare_explains",
    # Index Advisor
    "IndexRecommender",
    "IndexRecommendation",
    "CostEstimator",
    "recommend_indexes",
    # SQL Parser (single port: sql_ast.py)
    "SQLASTParser",
    "SQLParseResult",
    "SQLQueryAnalyzer",
    "QueryInfo",
    "ColumnInfo",
    "get_sql_parser",
    "is_pglast_available",
    "analyze_sql",
    "suggest_indexes_for_query",
    # Observability (consolidated)
    "AnalyzerMetrics",
    "Tracer",
    "TraceSpan",
]
