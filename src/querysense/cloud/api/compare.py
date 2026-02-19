"""
Stateless plan comparison API endpoint.

POST /api/v1/compare — compare two EXPLAIN plans without storing either.

This is the programmatic version of `querysense check`. Designed for
CI/CD pipelines where you want to compare baseline vs current plan
and get a structured diff.

Usage:
    curl -X POST https://querysense.dev/api/v1/compare \
         -H "Content-Type: application/json" \
         -d '{"baseline_json": "[{...}]", "current_json": "[{...}]"}'
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, status

router = APIRouter()


class CompareRequest(BaseModel):
    """Request body for stateless plan comparison."""

    baseline_json: str = Field(
        ..., description="EXPLAIN JSON for the baseline plan (e.g. main branch)"
    )
    current_json: str = Field(
        ..., description="EXPLAIN JSON for the current plan (e.g. PR branch)"
    )
    baseline_sql: str | None = Field(
        default=None, description="Optional SQL for the baseline plan"
    )
    current_sql: str | None = Field(
        default=None, description="Optional SQL for the current plan"
    )


class CompareIssueSummary(BaseModel):
    """Summary of a finding in the comparison."""

    rule_id: str
    severity: str
    title: str
    suggestion: str | None = None


class CompareSummary(BaseModel):
    """High-level comparison summary."""

    fixed_count: int
    new_count: int
    unchanged_count: int
    net_improvement: int = Field(
        description="Positive = fewer issues (better), negative = more issues (worse)"
    )
    is_regression: bool
    is_improvement: bool
    cost_delta_pct: float = Field(
        description="Cost change percentage. Positive = higher cost (worse)"
    )
    time_delta_pct: float | None = Field(
        default=None,
        description="Time change percentage (if ANALYZE data available)",
    )


class CompareResponse(BaseModel):
    """Full comparison result."""

    verdict: str = Field(description="PASS, REGRESSION, or IMPROVED")
    summary: CompareSummary
    new_issues: list[CompareIssueSummary]
    fixed_issues: list[CompareIssueSummary]
    severity_changes: dict[str, int]


@router.post(
    "/compare",
    summary="Compare two EXPLAIN plans (stateless)",
    response_model=CompareResponse,
)
async def compare(body: CompareRequest) -> CompareResponse:
    """
    Compare a baseline EXPLAIN plan against a current one.

    Returns a structured diff showing:
    - Fixed issues (in baseline but not current)
    - New issues (in current but not baseline)
    - Cost and time deltas
    - Overall verdict: PASS, REGRESSION, or IMPROVED

    No authentication required. No data stored.
    Designed for CI/CD integration.
    """
    import json

    from querysense.cloud.services import analyze_plan
    from querysense.analyzer.comparator import compare_analyses

    # Enforce size limits (DoS protection)
    from querysense.cloud.api.analyze import _enforce_plan_size
    _enforce_plan_size(body.baseline_json, label="baseline_json")
    _enforce_plan_size(body.current_json, label="current_json")

    # Parse and analyze both plans
    try:
        baseline_result, _ = analyze_plan(body.baseline_json, body.baseline_sql)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Failed to parse baseline plan. Ensure the input is valid EXPLAIN JSON.",
        ) from exc

    try:
        current_result, _ = analyze_plan(body.current_json, body.current_sql)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Failed to parse current plan. Ensure the input is valid EXPLAIN JSON.",
        ) from exc

    # Compare
    diff = compare_analyses(baseline_result, current_result)

    # Calculate cost delta from raw plans
    try:
        b_data = json.loads(body.baseline_json)
        c_data = json.loads(body.current_json)
        if isinstance(b_data, list):
            b_data = b_data[0]
        if isinstance(c_data, list):
            c_data = c_data[0]
        b_cost = b_data.get("Plan", b_data).get("Total Cost", 0)
        c_cost = c_data.get("Plan", c_data).get("Total Cost", 0)
        cost_pct = ((c_cost - b_cost) / b_cost * 100) if b_cost > 0 else 0

        b_time = b_data.get("Plan", b_data).get("Actual Total Time")
        c_time = c_data.get("Plan", c_data).get("Actual Total Time")
        time_pct = None
        if b_time is not None and c_time is not None and b_time > 0:
            time_pct = (c_time - b_time) / b_time * 100
    except Exception:
        cost_pct = 0
        time_pct = None

    # Determine verdict
    is_regression = diff.is_regression or cost_pct > 20
    if is_regression:
        verdict = "REGRESSION"
    elif diff.is_improvement:
        verdict = "IMPROVED"
    else:
        verdict = "PASS"

    return CompareResponse(
        verdict=verdict,
        summary=CompareSummary(
            fixed_count=len(diff.fixed_issues),
            new_count=len(diff.new_issues),
            unchanged_count=len(diff.unchanged_issues),
            net_improvement=diff.net_improvement,
            is_regression=is_regression,
            is_improvement=diff.is_improvement,
            cost_delta_pct=round(cost_pct, 1),
            time_delta_pct=round(time_pct, 1) if time_pct is not None else None,
        ),
        new_issues=[
            CompareIssueSummary(
                rule_id=f.rule_id,
                severity=f.severity.value,
                title=f.title,
                suggestion=f.suggestion,
            )
            for f in diff.new_issues
        ],
        fixed_issues=[
            CompareIssueSummary(
                rule_id=f.rule_id,
                severity=f.severity.value,
                title=f.title,
            )
            for f in diff.fixed_issues
        ],
        severity_changes=diff.severity_improvement,
    )
