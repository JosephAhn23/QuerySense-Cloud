"""
Stateless analysis endpoint.

POST /api/v1/analyze — analyze a plan without storing it.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, status

from querysense.cloud.services import analyze_plan_to_dict
from querysense.cloud.settings import get_cloud_settings

logger = logging.getLogger(__name__)

router = APIRouter()


def _enforce_plan_size(plan_json: str, label: str = "plan_json") -> None:
    """Reject plan JSON exceeding the configured max size (DoS protection)."""
    max_bytes = get_cloud_settings().max_plan_size_bytes
    size = len(plan_json.encode("utf-8"))
    if size > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{label} exceeds maximum allowed size ({size:,} bytes > {max_bytes:,} bytes)",
        )


class AnalyzeRequest(BaseModel):
    """Request body for stateless analysis."""

    plan_json: str = Field(..., description="EXPLAIN (FORMAT JSON) output as a string")
    sql: str | None = Field(default=None, description="Optional SQL query text")


@router.post("/analyze", summary="Analyze an EXPLAIN plan (stateless)")
async def analyze(body: AnalyzeRequest) -> dict:
    """
    Analyze an EXPLAIN JSON plan and return the findings.

    This endpoint does NOT store the plan or result.
    Useful for one-off analysis or CI integration.
    """
    _enforce_plan_size(body.plan_json)

    try:
        result = analyze_plan_to_dict(body.plan_json, body.sql)
    except Exception as exc:
        logger.warning("Analysis failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Failed to parse or analyze plan. Ensure the input is valid EXPLAIN JSON.",
        ) from exc

    return result
