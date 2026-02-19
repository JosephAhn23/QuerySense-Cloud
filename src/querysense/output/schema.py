"""
JSON Schema definitions for stable API output.

Provides versioned schema for:
- API responses
- CI/CD integration
- Documentation generation

The schema is stable across minor versions.
Breaking changes only in major versions.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NodeContextSchema(BaseModel):
    """Schema for node context in findings."""
    
    model_config = ConfigDict(frozen=True)
    
    path: str = Field(..., description="Path to the node in the plan tree")
    node_type: str = Field(..., description="PostgreSQL node type")
    relation_name: str | None = Field(None, description="Table name if applicable")
    actual_rows: int | None = Field(None, description="Actual rows from EXPLAIN ANALYZE")
    plan_rows: int | None = Field(None, description="Estimated rows from planner")
    total_cost: float = Field(0.0, description="Total cost estimate")
    filter: str | None = Field(None, description="Filter condition if present")


class FindingSchema(BaseModel):
    """Schema for a single finding."""
    
    model_config = ConfigDict(frozen=True)
    
    rule_id: str = Field(..., description="Unique rule identifier")
    severity: str = Field(..., description="Severity level (critical/warning/info)")
    title: str = Field(..., description="One-line summary")
    description: str = Field(..., description="Detailed explanation")
    suggestion: str | None = Field(None, description="Actionable fix recommendation")
    impact_band: str = Field("UNKNOWN", description="Expected impact (LOW/MEDIUM/HIGH/UNKNOWN)")
    impact_score: float = Field(0.0, description="Numeric impact score (0-10) for prioritization")
    assumptions: list[str] = Field(default_factory=list, description="Assumptions for recommendation")
    verification_steps: list[str] = Field(default_factory=list, description="Steps to verify effectiveness")
    metrics: dict[str, float] = Field(default_factory=dict, description="Quantitative data")
    context: NodeContextSchema = Field(..., description="Node context")


class RuleRunSchema(BaseModel):
    """Schema for rule execution record."""
    
    model_config = ConfigDict(frozen=True)
    
    rule_id: str = Field(..., description="Rule identifier")
    version: str = Field(..., description="Rule version")
    status: str = Field(..., description="Execution status (pass/skip/fail)")
    runtime_ms: float = Field(0.0, description="Execution time in milliseconds")
    findings_count: int = Field(0, description="Number of findings generated")
    error_summary: str | None = Field(None, description="Error message if failed")
    skip_reason: str | None = Field(None, description="Reason if skipped")


class MetadataSchema(BaseModel):
    """Schema for execution metadata."""
    
    model_config = ConfigDict(frozen=True)
    
    node_count: int = Field(0, description="Total nodes in plan")
    execution_time_ms: float | None = Field(None, description="Query execution time")
    analysis_duration_ms: float | None = Field(None, description="Analysis duration")
    cache_hit: bool = Field(False, description="Whether result was cached")
    rules_run: int = Field(0, description="Rules executed")
    rules_failed: int = Field(0, description="Rules that failed")
    rules_skipped: int = Field(0, description="Rules that were skipped")


class ReproducibilitySchema(BaseModel):
    """Schema for reproducibility information."""
    
    model_config = ConfigDict(frozen=True)
    
    analysis_id: str = Field(..., description="Unique analysis identifier")
    plan_hash: str = Field(..., description="Hash of EXPLAIN plan")
    sql_hash: str | None = Field(None, description="Hash of normalized SQL")
    config_hash: str = Field(..., description="Hash of configuration")
    rules_hash: str = Field(..., description="Hash of ruleset versions")
    querysense_version: str = Field(..., description="QuerySense version")


class SummarySchema(BaseModel):
    """Schema for result summary."""
    
    model_config = ConfigDict(frozen=True)
    
    total: int = Field(0, description="Total findings count")
    critical: int = Field(0, description="Critical findings count")
    warning: int = Field(0, description="Warning findings count")
    info: int = Field(0, description="Info findings count")
    rules_passed: int = Field(0, description="Rules that passed")
    rules_skipped: int = Field(0, description="Rules that were skipped")
    rules_failed: int = Field(0, description="Rules that failed")
    evidence_level: str = Field("PLAN", description="Evidence level")
    sql_confidence: str = Field("none", description="SQL parsing confidence")
    degraded: bool = Field(False, description="Whether analysis was degraded")
    success_rate: float = Field(1.0, description="Rule success rate")


class AnalysisResultSchema(BaseModel):
    """
    Top-level schema for analysis results.
    
    This schema is stable across minor versions.
    Breaking changes require major version bump.
    """
    
    model_config = ConfigDict(frozen=True)
    
    version: str = Field("1.0", description="Schema version")
    evidence_level: str = Field(..., description="Analysis evidence level")
    sql_confidence: str = Field("none", description="SQL parsing confidence")
    degraded: bool = Field(False, description="Whether analysis ran degraded")
    degraded_reasons: list[str] = Field(default_factory=list, description="Reasons for degradation")
    summary: SummarySchema = Field(..., description="Result summary")
    findings: list[FindingSchema] = Field(default_factory=list, description="All findings")
    rule_runs: list[RuleRunSchema] = Field(default_factory=list, description="Rule execution records")
    metadata: MetadataSchema = Field(..., description="Execution metadata")
    reproducibility: ReproducibilitySchema | None = Field(None, description="Reproducibility info")


def get_json_schema() -> dict[str, Any]:
    """
    Get the JSON Schema for API documentation.
    
    Suitable for OpenAPI/Swagger integration.
    """
    return AnalysisResultSchema.model_json_schema()


# Schema version - increment on breaking changes
SCHEMA_VERSION = "1.0"
