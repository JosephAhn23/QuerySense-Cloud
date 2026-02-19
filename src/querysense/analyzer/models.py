"""
Data models for the analyzer module.

These models represent the output of analysis rules - the issues detected
in query plans. They're designed to be:
- Immutable (frozen=True): Findings don't change after creation
- Serializable: Easy JSON output for --json flag
- Hashable: Can be used in sets for deduplication
- Observable: Explicit status for PASS/SKIP/FAIL distinction
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from querysense.analyzer.path import NodePath

if TYPE_CHECKING:
    from querysense.analyzer.errors import RuleError
    from querysense.parser.models import PlanNode


class RulePhase(IntEnum):
    """
    Execution phases for rules.
    
    PER_NODE: Analyze individual nodes (default, runs first)
    AGGREGATE: Analyze patterns across entire query (runs second, sees prior findings)
    """
    PER_NODE = 1
    AGGREGATE = 2


class RuleRunStatus(str, Enum):
    """
    Status of a rule execution - distinguishes PASS vs SKIP vs FAIL.
    
    This is critical for observability: users must understand why
    a rule didn't produce findings (no issues vs preconditions not met vs crash).
    """
    
    PASS = "pass"      # Rule executed normally
    SKIP = "skip"      # Preconditions not met (e.g., no SQL AST, no DBProbe)
    FAIL = "fail"      # Rule crashed with an error


class EvidenceLevel(str, Enum):
    """
    Evidence level for analysis - explicitly tracks data sources.
    
    Makes the design contract explicit:
    - Level 1 (PLAN): EXPLAIN JSON only → findings are plan-evidenced
    - Level 2 (PLAN_SQL): EXPLAIN JSON + SQL → findings include SQL-derived hypotheses
    - Level 3 (PLAN_SQL_DB): EXPLAIN + SQL + DB facts → validated recommendations
    """
    
    PLAN = "PLAN"
    PLAN_SQL = "PLAN+SQL"
    PLAN_SQL_DB = "PLAN+SQL+DB"


class ImpactBand(str, Enum):
    """
    Impact band for recommendations - replaces specific multiplier claims.
    
    Never overclaim with "57x faster". Instead use impact bands with
    explicit assumptions and verification steps.
    """
    
    LOW = "LOW"          # Minor improvement expected (< 2x)
    MEDIUM = "MEDIUM"    # Moderate improvement expected (2-10x)
    HIGH = "HIGH"        # Significant improvement expected (> 10x)
    UNKNOWN = "UNKNOWN"  # Cannot estimate without more data


class SQLConfidence(str, Enum):
    """
    Confidence level in SQL parsing results.
    
    When AST parse fails, disable index advice or mark as heuristic.
    """
    
    HIGH = "high"        # Parsed with pglast (real Postgres parser)
    MEDIUM = "medium"    # Parsed with sqlparse (heuristic tokenizer)
    LOW = "low"          # Parse failed, heuristic extraction only
    NONE = "none"        # No SQL provided


class Severity(str, Enum):
    """
    Severity levels for findings.
    
    CRITICAL: Query will fail, cause outage, or has severe performance impact
    WARNING: Significant performance issue that should be addressed
    INFO: Optimization opportunity, nice-to-have improvement
    """
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    
    def __lt__(self, other: object) -> bool:
        """Enable sorting by severity (CRITICAL > WARNING > INFO)."""
        if not isinstance(other, Severity):
            return NotImplemented
        order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        return order[self] < order[other]


@dataclass(frozen=True)
class NodeContext:
    """
    Complete context about a problematic node.
    
    Captures all relevant information from a PlanNode so that:
    - The explainer has full context for generating explanations
    - We avoid storing the entire PlanNode (circular refs, size)
    - Findings remain serializable and hashable
    
    Attributes:
        path: Location in the plan tree
        node_type: The PostgreSQL node type (e.g., "Seq Scan")
        relation_name: Table being accessed, if applicable
        actual_rows: Actual rows processed (from ANALYZE)
        plan_rows: Estimated rows (planner's guess)
        total_cost: Total cost estimate
        filter: Filter condition if present
        index_name: Index being used, if applicable
        parent_node_type: Parent node's type for context
        depth: Depth in the plan tree (0 = root)
    """
    
    path: NodePath
    node_type: str
    relation_name: str | None = None
    actual_rows: int | None = None
    plan_rows: int | None = None
    total_cost: float = 0.0
    startup_cost: float = 0.0
    filter: str | None = None
    index_name: str | None = None
    index_cond: str | None = None
    parent_node_type: str | None = None
    depth: int = 0
    rows_removed_by_filter: int | None = None
    
    @classmethod
    def from_node(
        cls,
        node: "PlanNode",
        path: NodePath,
        parent: "PlanNode | None" = None,
    ) -> "NodeContext":
        """
        Extract relevant context from a PlanNode.
        
        Args:
            node: The plan node to extract context from
            path: Path to this node in the tree
            parent: Parent node for additional context
            
        Returns:
            NodeContext with all relevant fields populated
        """
        return cls(
            path=path,
            node_type=node.node_type,
            relation_name=node.relation_name,
            actual_rows=node.actual_rows,
            plan_rows=node.plan_rows,
            total_cost=node.total_cost,
            startup_cost=node.startup_cost,
            filter=node.filter,
            index_name=node.index_name,
            index_cond=node.index_cond,
            parent_node_type=parent.node_type if parent else None,
            depth=path.depth,
            rows_removed_by_filter=node.rows_removed_by_filter,
        )
    
    @classmethod
    def root(cls, node_type: str = "Query") -> "NodeContext":
        """Create a root context for aggregate findings."""
        return cls(path=NodePath.root(), node_type=node_type)
    
    @property
    def row_estimate_ratio(self) -> float | None:
        """Ratio of actual to estimated rows (indicates statistics accuracy)."""
        if self.actual_rows is None or self.plan_rows is None or self.plan_rows == 0:
            return None
        return self.actual_rows / self.plan_rows
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "path": list(self.path.segments),
            "node_type": self.node_type,
            "relation_name": self.relation_name,
            "actual_rows": self.actual_rows,
            "plan_rows": self.plan_rows,
            "total_cost": self.total_cost,
            "filter": self.filter,
            "index_name": self.index_name,
            "parent_node_type": self.parent_node_type,
            "depth": self.depth,
        }


class Finding(BaseModel):
    """
    A single issue detected in a query plan.
    
    Findings are the output of analyzer rules. Each finding represents
    a specific performance issue at a specific location in the plan tree.
    
    Attributes:
        rule_id: Unique identifier for the rule that generated this finding.
            Convention: UPPER_SNAKE_CASE (e.g., "SEQ_SCAN_LARGE_TABLE").
        severity: How serious the issue is.
        context: Full context about the problematic node (type, rows, filter, etc.)
        title: Human-readable one-line summary.
        description: Detailed explanation of why this is a problem.
        suggestion: Actionable fix recommendation, if applicable.
        metrics: Quantitative data about the issue for programmatic use.
        explanation: LLM-generated explanation (populated by explainer).
        explanation_error: Error message if explanation generation failed.
    
    Example:
        Finding(
            rule_id="SEQ_SCAN_LARGE_TABLE",
            severity=Severity.WARNING,
            context=NodeContext.from_node(node, path),
            title="Sequential scan on orders (1,234,567 rows)",
            description="Scanning over 1M rows sequentially is expensive...",
            suggestion="Consider adding an index on orders(status)",
            metrics={"rows_scanned": 1234567, "total_cost": 45000.0},
        )
    """
    
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    
    rule_id: str = Field(
        ...,
        description="Unique identifier for the rule (UPPER_SNAKE_CASE)",
    )
    
    severity: Severity = Field(
        ...,
        description="Severity level of the finding",
    )
    
    context: NodeContext = Field(
        ...,
        description="Full context about the problematic node",
    )
    
    title: str = Field(
        ...,
        min_length=1,
        description="Human-readable one-line summary",
    )
    
    description: str = Field(
        ...,
        min_length=1,
        description="Detailed explanation of the issue",
    )
    
    suggestion: str | None = Field(
        default=None,
        description="Actionable fix recommendation",
    )
    
    metrics: dict[str, int | float] = Field(
        default_factory=dict,
        description="Quantitative data about the issue",
    )
    
    # Impact estimation - never overclaim
    impact_band: ImpactBand = Field(
        default=ImpactBand.UNKNOWN,
        description="Expected improvement band (LOW/MEDIUM/HIGH/UNKNOWN)",
    )
    
    # Numeric impact score (0-10) for prioritization and CI gating.
    # 0 = negligible, 1-3 = minor optimization, 4-6 = meaningful gain,
    # 7-9 = significant improvement, 10 = critical fix.
    # Comparable to pgMustard's 0-5 tip scoring but more granular.
    impact_score: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Numeric impact score (0-10) for prioritization",
    )
    
    assumptions: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Assumptions underlying the recommendation",
    )
    
    verification_steps: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Steps to verify the recommendation's effectiveness",
    )
    
    # LLM explanation (populated by explainer if enabled)
    explanation: str | None = Field(
        default=None,
        description="LLM-generated explanation of the issue",
    )
    
    explanation_error: str | None = Field(
        default=None,
        description="Error message if explanation generation failed",
    )
    
    # Backward compatibility: expose path from context
    @property
    def node_path(self) -> NodePath:
        """Path to the node (for backward compatibility)."""
        return self.context.path
    
    def cache_key(self, model: str, rule_version: str) -> str:
        """
        Generate a deterministic cache key for LLM explanations.
        
        The key includes:
        - LLM model name (explanations differ by model quality)
        - Rule ID and version (logic changes invalidate cache)
        - Context details (filter, rows, etc.)
        
        Args:
            model: The LLM model name (e.g., "claude-sonnet-4-20250514")
            rule_version: Version of the rule that generated this finding
            
        Returns:
            16-character hex string suitable as a cache key
        """
        context_data = {
            "node_type": self.context.node_type,
            "relation_name": self.context.relation_name,
            "actual_rows": self.context.actual_rows,
            "plan_rows": self.context.plan_rows,
            "filter": self.context.filter,
        }
        context_json = json.dumps(context_data, sort_keys=True)
        metrics_json = json.dumps(self.metrics, sort_keys=True)
        content = f"{model}:{self.rule_id}:{rule_version}:{context_json}:{metrics_json}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def with_explanation(
        self,
        explanation: str | None,
        error: str | None = None,
    ) -> "Finding":
        """
        Create a copy of this finding with explanation added.
        
        Since Finding is frozen, this returns a new instance.
        
        Args:
            explanation: The LLM-generated explanation
            error: Error message if explanation failed
            
        Returns:
            New Finding with explanation populated
        """
        return self.model_copy(update={
            "explanation": explanation,
            "explanation_error": error,
        })
    
    def __lt__(self, other: "Finding") -> bool:
        """
        Enable deterministic sorting of findings.
        
        Sort order: severity (CRITICAL first), then rule_id, then path.
        This ensures consistent output across runs.
        """
        return (self.severity, self.rule_id, self.context.path.segments) < (
            other.severity, other.rule_id, other.context.path.segments
        )
    
    def __hash__(self) -> int:
        """Enable use in sets for deduplication."""
        return hash((
            self.rule_id,
            self.severity,
            self.context.path.segments,
            self.context.node_type,
            self.context.relation_name,
            tuple(sorted(self.metrics.items())),
            self.impact_score,
        ))


class RuleRun(BaseModel):
    """
    Record of a single rule execution.
    
    Enables explicit observability: users can distinguish PASS vs SKIP vs FAIL
    and understand exactly what happened during analysis.
    """
    
    model_config = ConfigDict(frozen=True)
    
    rule_id: str = Field(..., description="Unique rule identifier")
    version: str = Field(..., description="Rule version for cache invalidation")
    status: RuleRunStatus = Field(..., description="Execution status")
    runtime_ms: float = Field(default=0.0, description="Execution time in milliseconds")
    findings_count: int = Field(default=0, description="Number of findings generated")
    error_summary: str | None = Field(default=None, description="Error message if FAIL")
    skip_reason: str | None = Field(default=None, description="Reason if SKIP")


class ExecutionMetadata(BaseModel):
    """
    Metadata about analysis execution.
    
    Separated from AnalysisResult to keep the results clean and allow
    execution metadata to grow independently (timing, caching stats, etc.)
    """
    
    model_config = ConfigDict(frozen=True)
    
    node_count: int = Field(
        default=0,
        description="Total number of nodes in the plan",
    )
    
    execution_time_ms: float | None = Field(
        default=None,
        description="Query execution time from EXPLAIN ANALYZE",
    )
    
    rules_run: int = Field(
        default=0,
        description="Number of rules that were executed",
    )
    
    rules_failed: int = Field(
        default=0,
        description="Number of rules that failed with errors",
    )
    
    rules_skipped: int = Field(
        default=0,
        description="Number of rules that were skipped (preconditions not met)",
    )
    
    analysis_duration_ms: float | None = Field(
        default=None,
        description="Total analysis duration in milliseconds",
    )
    
    cache_hit: bool = Field(
        default=False,
        description="Whether result was served from cache",
    )
    
    @property
    def success_rate(self) -> float:
        """Fraction of rules that completed successfully."""
        if self.rules_run == 0:
            return 1.0
        return (self.rules_run - self.rules_failed) / self.rules_run


class ReproducibilityInfo(BaseModel):
    """
    Hashes for reproducible analysis - enables bug reports.
    
    All inputs that affect output are hashed and exposed.
    Cache keys must include every input that can affect outputs.
    """
    
    model_config = ConfigDict(frozen=True)
    
    analysis_id: str = Field(..., description="Unique analysis identifier")
    plan_hash: str = Field(..., description="Hash of the EXPLAIN plan structure")
    sql_hash: str | None = Field(default=None, description="Hash of normalized SQL")
    config_hash: str = Field(..., description="Hash of configuration")
    rules_hash: str = Field(..., description="Hash of ruleset versions")
    querysense_version: str = Field(..., description="QuerySense version")
    engine_version: str = Field(default="1.0.0", description="Analyzer engine version")
    
    @property
    def cache_key(self) -> str:
        """
        Compute canonical cache key from all components.
        
        Includes: plan_hash, sql_hash, config_hash, rules_hash, engine_version
        """
        parts = [
            self.plan_hash,
            self.sql_hash or "no-sql",
            self.config_hash,
            self.rules_hash,
            self.engine_version,
        ]
        return hashlib.sha256(":".join(parts).encode()).hexdigest()[:32]


def compute_evidence_level(
    has_plan: bool,
    has_sql: bool,
    sql_confidence: "SQLConfidence",
    has_db_probe: bool,
    db_probe_succeeded: bool = False,
) -> "EvidenceLevel":
    """
    Compute evidence level based on available data sources.
    
    Evidence levels are computed, not set by hand:
    - PLAN: Plan exists (even without SQL)
    - PLAN+SQL: Plan exists AND SQL confidence >= MEDIUM (or AST exists)
    - PLAN+SQL+DB: DBProbe executed at least one successful validation query
    
    Args:
        has_plan: Whether EXPLAIN plan is available
        has_sql: Whether SQL query was provided
        sql_confidence: Confidence level of SQL parsing
        has_db_probe: Whether DB probe is configured
        db_probe_succeeded: Whether DB probe executed at least one query
        
    Returns:
        Computed EvidenceLevel
    """
    if not has_plan:
        return EvidenceLevel.PLAN  # Fallback, should never happen
    
    # Check for Level 3: PLAN+SQL+DB
    if has_db_probe and db_probe_succeeded:
        if has_sql and sql_confidence in (SQLConfidence.HIGH, SQLConfidence.MEDIUM):
            return EvidenceLevel.PLAN_SQL_DB
    
    # Check for Level 2: PLAN+SQL
    if has_sql and sql_confidence in (SQLConfidence.HIGH, SQLConfidence.MEDIUM):
        return EvidenceLevel.PLAN_SQL
    
    # Level 1: PLAN only
    return EvidenceLevel.PLAN


class AnalysisResult(BaseModel):
    """
    Complete result of analyzing an EXPLAIN output.
    
    Contains:
    - findings: All detected issues, sorted by severity
    - rule_runs: Detailed status of each rule execution (PASS/SKIP/FAIL)
    - errors: Any rule execution errors (analysis continues despite errors)
    - metadata: Execution statistics (node count, timing, etc.)
    - evidence_level: What data sources informed the analysis
    - reproducibility: Hashes for bug reports and cache validation
    - degraded: Whether analysis ran in degraded mode
    
    Invariant: All fields are non-optional and must be populated.
    Use AnalysisResult.create() factory for construction.
    """
    
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    
    # Required fields - MUST be populated
    findings: tuple[Finding, ...] = Field(
        ...,  # Required, no default
        description="All findings, sorted by severity",
    )
    
    rule_runs: tuple[RuleRun, ...] = Field(
        ...,  # Required, no default
        description="Detailed status of each rule execution",
    )
    
    evidence_level: EvidenceLevel = Field(
        ...,  # Required, no default
        description="What data sources informed the analysis",
    )
    
    sql_confidence: SQLConfidence = Field(
        ...,  # Required, no default
        description="Confidence level in SQL parsing",
    )
    
    reproducibility: ReproducibilityInfo = Field(
        ...,  # Required, no default (was Optional, now mandatory)
        description="Hashes for reproducible bug reports",
    )
    
    metadata: ExecutionMetadata = Field(
        ...,  # Required, no default
        description="Execution metadata (timing, counts)",
    )
    
    degraded: bool = Field(
        ...,  # Required, no default
        description="Whether analysis ran in degraded mode (some rules skipped/failed)",
    )
    
    degraded_reasons: tuple[str, ...] = Field(
        ...,  # Required, no default
        description="Reasons for degraded mode",
    )
    
    # Optional backward-compat field
    errors: tuple[Any, ...] = Field(
        default_factory=tuple,
        description="Errors from rules that failed (derived from rule_runs)",
    )
    
    @classmethod
    def create(
        cls,
        *,
        findings: list[Finding],
        rule_runs: list[RuleRun],
        evidence_level: EvidenceLevel,
        sql_confidence: SQLConfidence,
        reproducibility: ReproducibilityInfo,
        metadata: ExecutionMetadata,
        degraded_reasons: list[str] | None = None,
    ) -> "AnalysisResult":
        """
        Factory method to create an AnalysisResult with proper defaults.
        
        Use this instead of direct construction to ensure invariants.
        """
        if degraded_reasons is None:
            degraded_reasons = []
        
        # Compute degraded flag
        failed = [r for r in rule_runs if r.status == RuleRunStatus.FAIL]
        skipped = [r for r in rule_runs if r.status == RuleRunStatus.SKIP]
        
        degraded = bool(failed or skipped or degraded_reasons)
        
        # Add automatic degraded reasons
        all_reasons = list(degraded_reasons)
        if failed:
            all_reasons.append(f"{len(failed)} rules failed")
        if skipped:
            all_reasons.append(f"{len(skipped)} rules skipped (missing capabilities)")
        
        # Build errors tuple from failed rule runs
        errors = tuple(r.error_summary for r in failed if r.error_summary)
        
        return cls(
            findings=tuple(sorted(findings, key=lambda f: (f.severity, f.rule_id))),
            rule_runs=tuple(rule_runs),
            evidence_level=evidence_level,
            sql_confidence=sql_confidence,
            reproducibility=reproducibility,
            metadata=metadata,
            degraded=degraded,
            degraded_reasons=tuple(all_reasons),
            errors=errors,
        )
    
    @classmethod
    def empty(cls, analysis_id: str = "test") -> "AnalysisResult":
        """
        Create an empty AnalysisResult for testing.
        
        This is provided for backward compatibility with tests that
        expect to be able to create AnalysisResult() with no args.
        Production code should use the create() factory.
        """
        return cls(
            findings=(),
            rule_runs=(),
            evidence_level=EvidenceLevel.PLAN,
            sql_confidence=SQLConfidence.NONE,
            reproducibility=ReproducibilityInfo(
                analysis_id=analysis_id,
                plan_hash="test",
                sql_hash=None,
                config_hash="test",
                rules_hash="test",
                querysense_version="0.5.2",
            ),
            metadata=ExecutionMetadata(),
            degraded=False,
            degraded_reasons=(),
            errors=(),
        )
    
    # Convenience properties that delegate to metadata
    @property
    def node_count(self) -> int:
        """Total number of nodes in the plan."""
        return self.metadata.node_count
    
    @property
    def rules_run(self) -> int:
        """Number of rules executed."""
        return self.metadata.rules_run
    
    @property
    def rules_failed(self) -> int:
        """Number of rules that failed."""
        return self.metadata.rules_failed
    
    @property
    def rules_skipped(self) -> int:
        """Number of rules that were skipped."""
        return self.metadata.rules_skipped
    
    @property
    def has_critical(self) -> bool:
        """Check if any critical issues were found."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)
    
    @property
    def has_warnings(self) -> bool:
        """Check if any warnings were found."""
        return any(f.severity == Severity.WARNING for f in self.findings)
    
    @property
    def has_errors(self) -> bool:
        """Check if any rules failed during analysis."""
        return len(self.errors) > 0
    
    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def rule_runs_by_status(self, status: RuleRunStatus) -> list[RuleRun]:
        """Get all rule runs with a specific status."""
        return [r for r in self.rule_runs if r.status == status]
    
    def summary(self) -> dict[str, int | float | str | bool]:
        """Get a summary count by severity and success rate."""
        errors = len(self.rule_runs_by_status(RuleRunStatus.FAIL))
        return {
            "total": len(self.findings),
            "critical": len(self.findings_by_severity(Severity.CRITICAL)),
            "warning": len(self.findings_by_severity(Severity.WARNING)),
            "info": len(self.findings_by_severity(Severity.INFO)),
            "errors": errors,  # Backward compat: alias for rules_failed
            "rules_passed": len(self.rule_runs_by_status(RuleRunStatus.PASS)),
            "rules_skipped": len(self.rule_runs_by_status(RuleRunStatus.SKIP)),
            "rules_failed": errors,
            "evidence_level": self.evidence_level.value,
            "sql_confidence": self.sql_confidence.value,
            "degraded": self.degraded,
            "success_rate": self.metadata.success_rate,
        }
