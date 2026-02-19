"""QuerySense - Database query performance analyzer for PostgreSQL and MySQL."""

__version__ = "2.3.0"
__license__ = "MIT"

# Exception hierarchy (import first so other modules can use it)
from querysense.exceptions import (
    QuerySenseError,
    AnalyzerError,
    RuleError,
    ConfigurationError,
    ParseError,
    IRConversionError,
    BaselineError,
    PolicyError,
    CloudError,
)

# Plan IR (Intermediate Representation) - engine-agnostic plan algebra
from querysense.ir import (
    IRNode,
    IRPlan,
    IROperator,
    AggregateStrategy,
    ScanMethod,
    JoinAlgorithm,
    SortVariant,
)
from querysense.ir.node import EngineType

# Public API exports
from querysense.analyzer.analyzer import (
    Analyzer,
    get_current_query_info,
)
from querysense.analyzer.comparator import (
    AnalysisComparison,
    PlanComparison,
    compare_analyses,
    compare_plans,
)
from querysense.analyzer.models import (
    AnalysisResult,
    EvidenceLevel,
    ExecutionMetadata,
    Finding,
    ImpactBand,
    NodeContext,
    RulePhase,
    RuleRun,
    RuleRunStatus,
    Severity,
    SQLConfidence,
)
from querysense.analyzer.observability import AnalyzerMetrics
from querysense.baseline import (
    BaselineDiff,
    BaselineStore,
    RegressionSeverity,
    RegressionVerdict,
)
from querysense.config import (
    Config,
    Environment,
    get_config,
)
from querysense.engine import (
    AnalysisReport,
    AnalysisService,
    BatchReport,
    UpgradeReport,
)
from querysense.parser.parser import parse_explain
from querysense.policy import (
    Policy,
    PolicyViolation,
    load_policy,
)
from querysense.analyzer.speedup import enrich_with_speedup, estimate_speedup
from querysense.profile import Profile, ProfileStore, CheckResult as ProfileCheckResult
from querysense.rewriter import RewriteResult, Rewrite, rewrite_query
from querysense.migration_safety import (
    check_migration,
    generate_rollback,
    check_and_report,
    MigrationRisk,
    MigrationReport,
)
from querysense.schema import (
    SchemaSnapshot,
    SchemaDrift,
    detect_drift,
    compare_schemas,
)
from querysense.alerting import WebhookAlert
from querysense.scorecard import (
    LeverageScorecard,
    score_problem,
)
from querysense.migration_gen import MigrationGenerator, MigrationFormat
from querysense.fix_tracker import FixTracker, FixStatus, TrackedFix
from querysense.budget import BudgetEngine, BudgetViolation, QueryBudget, load_budgets
from querysense.app_context import AppContextCorrelator, EnrichedFinding, create_otel_span_processor
from querysense.rewrite_sandbox import RewriteSandbox, SandboxResult
from querysense.github_app import GitHubAppConfig, analyze_pr_files, PRAnalysisResult
from querysense.cost_compare import calculate_savings, SavingsReport
from querysense.budgets import (
    BudgetConfig,
    BudgetCheckResult,
    check_budget,
    load_budget_config,
)
from querysense.competitor_import import import_from, ImportResult

# Textbook-based features (v0.8.0)
from querysense.config_auditor import ConfigAuditor, AuditResult, ConfigFinding
from querysense.autovacuum_monitor import AutovacuumMonitor, VacuumHealth, VacuumAlert
from querysense.txn_monitor import TransactionMonitor, TxnHealth, LongTransaction
from querysense.index_manager import IndexManager, IndexAuditResult, IndexFinding
from querysense.workload_advisor import DynamicWorkloadAdvisor, WorkloadAnalysisResult
from querysense.replication_analyzer import ReplicationAnalyzer, ReplicationHealth
from querysense.safe_migration import SafeMigrationPlanner, MigrationPlan
from querysense.coach import Coach, CoachSession
from querysense.orm_detector import detect_orm_patterns, ORMDetectionReport
from querysense.query_classifier import QueryClassifier, ClassificationResult, QueryClass
from querysense.wizard import run_wizard, WizardResult

# Enterprise features (v0.9.0)
from querysense.audit import AuditLogger, AuditEvent, AuditEventType
from querysense.auth import Permission, Role, RBACChecker, AuthorizationError
from querysense.learning import Lesson, LearningPath, generate_learning_path
from querysense.bench import ConcurrencyTester, ConcurrencyResult, BenchmarkReport
from querysense.migration import ZeroDowntimePlanner, ZeroDowntimePlan, MigrationPhase as ZDTPhase
from querysense.rewrite_patterns import RewritePatternLibrary, RewritePattern, SafetyReport
from querysense.otel import QuerySenseTracer, SpanContext

# pganalyze-parity features (v1.1.0)
from querysense.scan_extractor import ScanExtractor, ExtractedScan, WorkloadScans, ColumnAccess
from querysense.hot_update_detector import HOTDetector, HOTAnalysis, HOTFinding
from querysense.iwo_calculator import IWOCalculator, TableIWO, IndexIWO, IWOReport

# Cross-database index comparison (v2.2.0)
from querysense.index.cross_db_comparison import (
    CrossDBIndexAdvisor,
    MigrationRecommendation,
    IndexCapability as CrossDBIndexCapability,
    DatabaseEngine as CrossDBDatabaseEngine,
    IndexType as CrossDBIndexType,
)

# Deduplication-aware index advisor (v2.2.0)
from querysense.index.deduplication_advisor import (
    DeduplicationAdvisor,
    DeduplicationReport,
    DedupSavings,
    DedupIndexRecommendation,
    ColumnStats as DedupColumnStats,
)

# CP-SAT tradeoff analyzer (v2.2.0)
from querysense.index.tradeoff_analyzer import (
    TradeoffAnalyzer,
    TradeoffResult,
    TradeoffPoint,
)
# Incremental Sort Detector (v2.3.0)
from querysense.planner.incremental_sort_detector import (
    IncrementalSortDetector,
    IncrementalSortReport,
    SortIssue,
    SortIssueType,
)

# Plan Statistics Collector — Aurora + pg_store_plans (v2.3.0)
from querysense.collectors.plan_statistics import (
    PlanStatisticsCollector,
    CollectionReport,
    PlanSnapshot,
    PlanFlip,
)

# Buffer Cache Tracker (v2.3.0)
from querysense.buffer_cache_tracker import (
    BufferCacheTracker,
    BufferCacheSnapshot,
    CacheDashboard,
    TableCacheStats,
)

# Buffer Cache Visualizer (v2.3.0)
from querysense.buffer_cache_viz import BufferCacheVisualizer

from querysense.functional_deps import FunctionalDepDetector, FDAnalysis, StatsRecommendation
from querysense.vacuum_advisor import (
    VacuumAdvisor, VacuumReport, VacuumRecommendation,
    BloatEstimate, FreezeRisk, TOASTBloat, CostThrottlingInfo,
)
from querysense.index.advisor_pipeline import IndexAdvisorPipeline, PipelineResult, RecommendedIndex
from querysense.index_optimizer import CandidateIndex
from querysense.cluster import ClusterDetector, ClusterTopology, ServerInfo
from querysense.index.cluster_advisor import ClusterIndexAdvisor, ClusterAdvisorResult
from querysense.advisor_framework import AdvisorRunner as AdvisorEngine, AdvisorReport, CheckResult as AdvisorCheckResult, AdvisorCheck as CheckDefinition, Severity as CheckSeverity, Interval as CheckInterval
from querysense.log_parser import PostgresLogParser, MySQLSlowLogParser, ParsedQuery, LogParseResult
from querysense.patroni import PatroniClient, PatroniCluster, PatroniMember, PatroniHealth

# Next-level analysis (v1.0.0)
from querysense.predictive import PredictiveOptimizer, WorkloadFingerprint, OptimizationPlan
from querysense.holistic_tuner import HolisticTuner, HolisticTuningResult
from querysense.geqo_analyzer import GEQOAnalyzer, GEQOAnalysisResult
from querysense.tdigest_stats import TDigest, PerformanceTracker, PerformanceReport
from querysense.node_profiler import NodeProfiler, PlanProfile
from querysense.cost_calibrator import CostCalibrator, CalibrationReport, PlanStabilityAnalyzer, StabilityResult
from querysense.semantic_translator import SemanticTranslator, TranslationResult

# pganalyze deep parity (v1.1.0)
from querysense.planner_whatif import PlannerWhatIf, WhatIfResult, WhatIfBatchResult, CostConstants, TableStatistics
from querysense.xmin_horizon import XminHorizonTracker, XminHorizonReport, XminBlocker
from querysense.bloat_estimator import IdealSizeBloatEstimator, BloatReport, TableBloatEstimate
from querysense.index_interactions import IndexInteractionAnalyzer, InteractionReport, IndexInfo
from querysense.autovacuum_utilization import AutovacuumAnalyzer, AutovacuumReport
from querysense.validation_hub import ValidationHub, ValidationReport
from querysense.competitor_import import SwitchReport, import_and_compare
from querysense.parser.multidb import parse_any, detect_engine, DatabaseEngine

# MongoDB optimizer (v2.0.0)
from querysense.mongodb import (
    MongoDBAnalyzer,
    MongoExplainParser,
    MongoExplainResult,
    MongoIndexRecommendation,
    MongoIndexAudit,
    MongoSchemaFinding,
    MongoAnalysisReport,
    MongoScanInfo,
)

# SQL Server native optimizer (v2.0.0)
from querysense.sqlserver import (
    SQLServerPlanParser,
    SQLServerPlanResult,
    SQLServerAnalyzer,
    SQLServerFinding,
    SQLServerOperator,
    MissingIndexHint,
    SQLServerProbe,
)

# AI/LLM explainer layer (v2.0.0)
from querysense.explainer.nlq import NLQueryExplainer, QueryExplanation
from querysense.explainer.openai_explainer import OpenAIExplainer
from querysense.explainer.ollama_explainer import OllamaExplainer

# PostgreSQL 18 Advisor (v2.1.0)
from querysense.pg18_advisor import PG18Advisor, PG18Report, PG18Finding

# pg_stat_plans Integration (v2.1.0)
from querysense.pg_stat_plans import PlanTracker, PlanTrackerReport, PlanMetrics, PlanChange

# Cloud Cost Advisor (v2.1.0)
from querysense.cloud_cost_advisor import CloudCostAdvisor, CostComparisonReport, DeploymentCost

# Query Advisor (v2.1.0) — pganalyze Query Advisor parity
from querysense.query_advisor import QueryAdvisor, QueryAdvisorReport, QueryInsight

__all__ = [
    # Exception hierarchy
    "QuerySenseError",
    "AnalyzerError",
    "RuleError",
    "ConfigurationError",
    "ParseError",
    "IRConversionError",
    "BaselineError",
    "PolicyError",
    "CloudError",
    # Core
    "Analyzer",
    "AnalysisService",
    "parse_explain",
    # Models
    "AnalysisResult",
    "ExecutionMetadata",
    "Finding",
    "NodeContext",
    "RulePhase",
    "RuleRun",
    "RuleRunStatus",
    "Severity",
    # Evidence & Impact
    "EvidenceLevel",
    "ImpactBand",
    "SQLConfidence",
    # Comparison
    "AnalysisComparison",
    "PlanComparison",
    "compare_analyses",
    "compare_plans",
    # Baseline & Regression Prevention (primary product surface)
    "BaselineDiff",
    "BaselineStore",
    "RegressionSeverity",
    "RegressionVerdict",
    # Engine & Orchestration
    "AnalysisReport",
    "BatchReport",
    "UpgradeReport",
    # Policy Enforcement (CI gating distribution channel)
    "Policy",
    "PolicyViolation",
    "load_policy",
    # Domain Leverage Scorecard
    "LeverageScorecard",
    "score_problem",
    # Configuration
    "Config",
    "Environment",
    "get_config",
    # Observability
    "AnalyzerMetrics",
    # Speedup Estimation
    "enrich_with_speedup",
    "estimate_speedup",
    # Profiles (git diff for database performance)
    "Profile",
    "ProfileStore",
    "ProfileCheckResult",
    # Query Rewriting
    "RewriteResult",
    "Rewrite",
    "rewrite_query",
    # Migration Safety
    "check_migration",
    "generate_rollback",
    "check_and_report",
    "MigrationRisk",
    "MigrationReport",
    # Schema Drift Detection
    "SchemaSnapshot",
    "SchemaDrift",
    "detect_drift",
    "compare_schemas",
    # Alerting
    "WebhookAlert",
    # Migration Generation & Fix Tracking
    "MigrationGenerator",
    "MigrationFormat",
    "FixTracker",
    "FixStatus",
    "TrackedFix",
    # Performance Budgets
    "BudgetEngine",
    "BudgetViolation",
    "QueryBudget",
    "load_budgets",
    # Application Context & Tracing
    "AppContextCorrelator",
    "EnrichedFinding",
    "create_otel_span_processor",
    # Rewrite Sandbox
    "RewriteSandbox",
    "SandboxResult",
    # GitHub App
    "GitHubAppConfig",
    "analyze_pr_files",
    "PRAnalysisResult",
    # Utilities
    "get_current_query_info",
    # Plan IR (Intermediate Representation)
    "IRNode",
    "IRPlan",
    "IROperator",
    "EngineType",
    "AggregateStrategy",
    "ScanMethod",
    "JoinAlgorithm",
    "SortVariant",
    # Cost Comparison
    "calculate_savings",
    "SavingsReport",
    # Performance Budgets
    "BudgetConfig",
    "BudgetCheckResult",
    "check_budget",
    "load_budget_config",
    # Competitor Import
    "import_from",
    "ImportResult",
    # ORM Anti-pattern Detection
    "detect_orm_patterns",
    "ORMDetectionReport",
    # Query Classification
    "QueryClassifier",
    "ClassificationResult",
    "QueryClass",
    # Optimization Wizard
    "run_wizard",
    "WizardResult",
    # Server Configuration Auditor
    "ConfigAuditor",
    "AuditResult",
    "ConfigFinding",
    # Autovacuum Health Monitor
    "AutovacuumMonitor",
    "VacuumHealth",
    "VacuumAlert",
    # Transaction Monitor
    "TransactionMonitor",
    "TxnHealth",
    "LongTransaction",
    # Holistic Index Manager
    "IndexManager",
    "IndexAuditResult",
    "IndexFinding",
    # Dynamic Workload Advisor
    "DynamicWorkloadAdvisor",
    "WorkloadAnalysisResult",
    # Replication Impact Analyzer
    "ReplicationAnalyzer",
    "ReplicationHealth",
    # Safe Migration Planner
    "SafeMigrationPlanner",
    "MigrationPlan",
    # QuerySense Coach
    "Coach",
    "CoachSession",
    # Enterprise features (v0.9.0)
    # Audit Logging
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    # RBAC
    "Permission",
    "Role",
    "RBACChecker",
    "AuthorizationError",
    # Learning Path
    "Lesson",
    "LearningPath",
    "generate_learning_path",
    # Concurrency Benchmark
    "ConcurrencyTester",
    "ConcurrencyResult",
    "BenchmarkReport",
    # Zero-Downtime Migration
    "ZeroDowntimePlanner",
    "ZeroDowntimePlan",
    "ZDTPhase",
    # Rewrite Pattern Library
    "RewritePatternLibrary",
    "RewritePattern",
    "SafetyReport",
    # OpenTelemetry
    "QuerySenseTracer",
    "SpanContext",
    # Next-level analysis (v1.0.0)
    "PredictiveOptimizer",
    "WorkloadFingerprint",
    "OptimizationPlan",
    "HolisticTuner",
    "HolisticTuningResult",
    "GEQOAnalyzer",
    "GEQOAnalysisResult",
    "TDigest",
    "PerformanceTracker",
    "PerformanceReport",
    "NodeProfiler",
    "PlanProfile",
    "CostCalibrator",
    "CalibrationReport",
    "PlanStabilityAnalyzer",
    "StabilityResult",
    "SemanticTranslator",
    "TranslationResult",
    # pganalyze-parity (v1.1.0)
    "ScanExtractor",
    "ExtractedScan",
    "WorkloadScans",
    "ColumnAccess",
    "HOTDetector",
    "HOTAnalysis",
    "HOTFinding",
    "IWOCalculator",
    "TableIWO",
    "IndexIWO",
    "IWOReport",
    "FunctionalDepDetector",
    "FDAnalysis",
    "StatsRecommendation",
    "VacuumAdvisor",
    "VacuumReport",
    "VacuumRecommendation",
    "BloatEstimate",
    "FreezeRisk",
    "TOASTBloat",
    "CostThrottlingInfo",
    "HOTDetector",
    "HOTAnalysis",
    "HOTFinding",
    "XminHorizonTracker",
    "XminHorizonReport",
    "XminBlocker",
    "IndexAdvisorPipeline",
    "PipelineResult",
    "RecommendedIndex",
    "CandidateIndex",
    # Cluster-aware (v1.1.0)
    "ClusterDetector",
    "ClusterTopology",
    "ServerInfo",
    "ClusterIndexAdvisor",
    "ClusterAdvisorResult",
    # pganalyze deep parity (v1.2.0)
    "PlannerWhatIf",
    "WhatIfResult",
    "WhatIfBatchResult",
    "CostConstants",
    "TableStatistics",
    "XminHorizonTracker",
    "XminHorizonReport",
    "IdealSizeBloatEstimator",
    "BloatReport",
    "TableBloatEstimate",
    "IndexInteractionAnalyzer",
    "InteractionReport",
    "IndexInfo",
    "AutovacuumAnalyzer",
    "AutovacuumReport",
    # Advisor Framework (Percona PMM parity)
    "AdvisorEngine",
    "AdvisorReport",
    "AdvisorCheckResult",
    "CheckDefinition",
    "CheckSeverity",
    "CheckInterval",
    # Log Parser (zero-connection)
    "PostgresLogParser",
    "MySQLSlowLogParser",
    "ParsedQuery",
    "LogParseResult",
    # Patroni HA
    "PatroniClient",
    "PatroniCluster",
    "PatroniMember",
    "PatroniHealth",
    # Validation Hub (v1.3.0)
    "ValidationHub",
    "ValidationReport",
    # Import toolkit (v1.3.0 enhancements)
    "SwitchReport",
    "import_and_compare",
    # Multi-database support (v1.3.0)
    "parse_any",
    "detect_engine",
    "DatabaseEngine",
    # MongoDB optimizer (v2.0.0)
    "MongoDBAnalyzer",
    "MongoExplainParser",
    "MongoExplainResult",
    "MongoIndexRecommendation",
    "MongoIndexAudit",
    "MongoSchemaFinding",
    "MongoAnalysisReport",
    "MongoScanInfo",
    # SQL Server native optimizer (v2.0.0)
    "SQLServerPlanParser",
    "SQLServerPlanResult",
    "SQLServerAnalyzer",
    "SQLServerFinding",
    "SQLServerOperator",
    "MissingIndexHint",
    "SQLServerProbe",
    # AI/LLM explainer layer (v2.0.0)
    "NLQueryExplainer",
    "QueryExplanation",
    "OpenAIExplainer",
    "OllamaExplainer",
    # PostgreSQL 18 Advisor (v2.1.0)
    "PG18Advisor",
    "PG18Report",
    "PG18Finding",
    # pg_stat_plans Integration (v2.1.0)
    "PlanTracker",
    "PlanTrackerReport",
    "PlanMetrics",
    "PlanChange",
    # Cloud Cost Advisor (v2.1.0)
    "CloudCostAdvisor",
    "CostComparisonReport",
    "DeploymentCost",
    # Query Advisor (v2.1.0)
    "QueryAdvisor",
    "QueryAdvisorReport",
    "QueryInsight",
    # Cross-database index comparison (v2.2.0)
    "CrossDBIndexAdvisor",
    "MigrationRecommendation",
    "CrossDBIndexCapability",
    "CrossDBDatabaseEngine",
    "CrossDBIndexType",
    # Deduplication-aware index advisor (v2.2.0)
    "DeduplicationAdvisor",
    "DeduplicationReport",
    "DedupSavings",
    "DedupIndexRecommendation",
    "DedupColumnStats",
    # CP-SAT tradeoff analyzer (v2.2.0)
    "TradeoffAnalyzer",
    "TradeoffResult",
    "TradeoffPoint",
    # Incremental Sort Detector (v2.3.0)
    "IncrementalSortDetector",
    "IncrementalSortReport",
    "SortIssue",
    "SortIssueType",
    # Plan Statistics Collector — Aurora (v2.3.0)
    "PlanStatisticsCollector",
    "CollectionReport",
    "PlanSnapshot",
    "PlanFlip",
    # Buffer Cache Tracker (v2.3.0)
    "BufferCacheTracker",
    "BufferCacheSnapshot",
    "CacheDashboard",
    "TableCacheStats",
    # Buffer Cache Visualizer (v2.3.0)
    "BufferCacheVisualizer",
    # Metadata
    "__version__",
    "__license__",
]