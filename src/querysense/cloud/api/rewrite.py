"""
SQL Rewrite API endpoint.

POST /api/v1/rewrite — optimize SQL queries programmatically.

This is the API that pgMustard doesn't have and EverSQL can't run offline.
Designed for CI/CD pipelines, IDE plugins, and automation scripts.

Usage:
    curl -X POST https://querysense.dev/api/v1/rewrite \
         -H "Content-Type: application/json" \
         -d '{"sql": "SELECT * FROM orders WHERE id NOT IN (SELECT ...)"}'
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, status

router = APIRouter()


class RewriteRequest(BaseModel):
    """Request body for SQL rewriting."""

    sql: str = Field(..., description="SQL query to optimize")
    plan_json: str | None = Field(
        default=None,
        description="Optional EXPLAIN JSON for finding-guided rewrites",
    )


class RewriteTransform(BaseModel):
    """A single rewrite transformation."""

    name: str
    description: str
    before_pattern: str
    after_pattern: str
    rule_id: str
    confidence: float = Field(ge=0, le=1)


class RewriteResponse(BaseModel):
    """Rewrite result."""

    original_sql: str
    rewritten_sql: str
    was_rewritten: bool
    rewrites: list[RewriteTransform]
    warnings: list[str]
    explanation: str


@router.post(
    "/rewrite",
    summary="Optimize a SQL query (stateless)",
    response_model=RewriteResponse,
)
async def rewrite(body: RewriteRequest) -> RewriteResponse:
    """
    Rewrite a SQL query for better performance.

    Applies 14 safe, deterministic rewrite patterns:
    - NOT IN → NOT EXISTS (NULL-safe)
    - IN subquery → JOIN / EXISTS
    - OR chain → IN clause
    - OR across columns → UNION ALL
    - DISTINCT → GROUP BY
    - UNION → UNION ALL
    - COUNT(*) → approximate count
    - COALESCE in WHERE → explicit check
    - Non-sargable LOWER() → expression index hint
    - And more...

    Optionally provide EXPLAIN JSON for finding-guided optimizations.
    No authentication required. No data stored.
    """
    from querysense.rewriter import rewrite_query

    findings = None
    if body.plan_json:
        try:
            from querysense.cloud.services import analyze_plan

            result_obj, _ = analyze_plan(body.plan_json, body.sql)
            findings = list(result_obj.findings)
        except Exception:
            # Proceed without findings — plan is optional
            pass

    try:
        result = rewrite_query(body.sql, findings)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to rewrite SQL: {exc}",
        ) from exc

    return RewriteResponse(
        original_sql=result.original_sql,
        rewritten_sql=result.rewritten_sql,
        was_rewritten=result.was_rewritten,
        rewrites=[
            RewriteTransform(
                name=r.name,
                description=r.description,
                before_pattern=r.before_pattern,
                after_pattern=r.after_pattern,
                rule_id=r.rule_id,
                confidence=r.confidence,
            )
            for r in result.rewrites
        ],
        warnings=result.warnings,
        explanation=result.explanation,
    )
