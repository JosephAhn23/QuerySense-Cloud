"""
Plan CRUD and analysis endpoints.

POST   /api/v1/plans            — upload + analyze + store
GET    /api/v1/plans            — list plans in workspace
GET    /api/v1/plans/{id}       — get plan + latest analysis
POST   /api/v1/plans/{id}/compare — compare with another plan
DELETE /api/v1/plans/{id}       — delete a plan
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

import querysense as qs
from querysense.cloud.api.deps import get_current_user
from querysense.cloud.database import get_session
from querysense.cloud.models import Analysis, Plan, User
from querysense.cloud.services import analyze_plan, compare_plans_service, get_summary_counts
from querysense.cloud.usage import check_api_limit, check_plan_limit, increment_api_calls, increment_plan_count

router = APIRouter(prefix="/plans")


# ── Request / Response schemas ─────────────────────────────────────────


class PlanCreateRequest(BaseModel):
    """Request to upload and analyze a plan."""

    plan_json: str = Field(..., description="EXPLAIN JSON output")
    sql: str | None = Field(default=None, description="Optional SQL query text")
    title: str = Field(default="Untitled Plan", max_length=300)
    tags: list[str] = Field(default_factory=list)


class PlanCompareRequest(BaseModel):
    """Request to compare with another plan."""

    other_plan_id: str = Field(..., description="ID of the plan to compare against")


class PlanSummary(BaseModel):
    """Compact plan representation for list views."""

    id: str
    title: str
    created_at: str
    findings_count: int = 0
    critical_count: int = 0
    warning_count: int = 0
    tags: list[str] = Field(default_factory=list)


class PlanDetail(BaseModel):
    """Full plan + analysis detail."""

    id: str
    title: str
    plan_json: str
    sql_text: str | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: str
    analysis: dict[str, Any] | None = None


# ── Endpoints ──────────────────────────────────────────────────────────


@router.post("", status_code=status.HTTP_201_CREATED, summary="Upload and analyze a plan")
async def create_plan(
    body: PlanCreateRequest,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> PlanDetail:
    """Upload an EXPLAIN plan, analyze it, and store both."""
    user, workspace_id = auth

    # Enforce tier limits
    await check_plan_limit(db, workspace_id)
    await check_api_limit(db, workspace_id)

    # Enforce size limits (DoS protection)
    from querysense.cloud.api.analyze import _enforce_plan_size
    _enforce_plan_size(body.plan_json)

    # Analyze
    try:
        result, result_json = analyze_plan(body.plan_json, body.sql)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Failed to analyze plan. Ensure the input is valid EXPLAIN JSON.",
        ) from exc

    counts = get_summary_counts(result_json)

    # Store plan
    plan = Plan(
        workspace_id=workspace_id,
        title=body.title,
        plan_json=body.plan_json,
        sql_text=body.sql,
        tags=json.dumps(body.tags) if body.tags else None,
        uploaded_by=user.id,
    )
    db.add(plan)
    await db.flush()

    # Store analysis
    analysis = Analysis(
        plan_id=plan.id,
        result_json=result_json,
        evidence_level=result.evidence_level.value,
        findings_count=counts["findings_count"],
        critical_count=counts["critical_count"],
        warning_count=counts["warning_count"],
        info_count=counts["info_count"],
        querysense_version=qs.__version__,
    )
    db.add(analysis)
    await db.flush()

    # Track usage
    await increment_plan_count(db, workspace_id)
    await increment_api_calls(db, workspace_id)

    return PlanDetail(
        id=plan.id,
        title=plan.title,
        plan_json=plan.plan_json,
        sql_text=plan.sql_text,
        tags=body.tags,
        created_at=plan.created_at.isoformat(),
        analysis=json.loads(result_json),
    )


@router.get("", summary="List plans in workspace")
async def list_plans(
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    search: str | None = Query(default=None),
) -> dict[str, Any]:
    """List plans in the current workspace, newest first."""
    _user, workspace_id = auth

    await increment_api_calls(db, workspace_id)

    query = select(Plan).where(Plan.workspace_id == workspace_id)

    if search:
        query = query.where(Plan.title.ilike(f"%{search}%"))

    # Total count
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # Fetch page
    query = query.order_by(Plan.created_at.desc()).offset(offset).limit(limit)
    query = query.options(selectinload(Plan.analyses))
    rows = (await db.execute(query)).scalars().all()

    items = []
    for plan in rows:
        latest = max(plan.analyses, key=lambda a: a.analyzed_at) if plan.analyses else None
        tags = json.loads(plan.tags) if plan.tags else []
        items.append(
            PlanSummary(
                id=plan.id,
                title=plan.title,
                created_at=plan.created_at.isoformat(),
                findings_count=latest.findings_count if latest else 0,
                critical_count=latest.critical_count if latest else 0,
                warning_count=latest.warning_count if latest else 0,
                tags=tags,
            )
        )

    return {"items": [i.model_dump() for i in items], "total": total, "offset": offset, "limit": limit}


@router.get("/{plan_id}", summary="Get plan detail with latest analysis")
async def get_plan(
    plan_id: str,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> PlanDetail:
    """Get a plan and its latest analysis."""
    _user, workspace_id = auth

    result = await db.execute(
        select(Plan)
        .where(Plan.id == plan_id, Plan.workspace_id == workspace_id)
        .options(selectinload(Plan.analyses))
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    latest = max(plan.analyses, key=lambda a: a.analyzed_at) if plan.analyses else None
    analysis_dict = json.loads(latest.result_json) if latest else None
    tags = json.loads(plan.tags) if plan.tags else []

    return PlanDetail(
        id=plan.id,
        title=plan.title,
        plan_json=plan.plan_json,
        sql_text=plan.sql_text,
        tags=tags,
        created_at=plan.created_at.isoformat(),
        analysis=analysis_dict,
    )


@router.post("/{plan_id}/compare", summary="Compare two plans")
async def compare_with_plan(
    plan_id: str,
    body: PlanCompareRequest,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> dict[str, Any]:
    """Compare this plan (before) with another plan (after)."""
    _user, workspace_id = auth

    # Fetch both plans
    before_result = await db.execute(
        select(Plan).where(Plan.id == plan_id, Plan.workspace_id == workspace_id)
    )
    before_plan = before_result.scalar_one_or_none()
    if before_plan is None:
        raise HTTPException(status_code=404, detail="Before plan not found")

    after_result = await db.execute(
        select(Plan).where(Plan.id == body.other_plan_id, Plan.workspace_id == workspace_id)
    )
    after_plan = after_result.scalar_one_or_none()
    if after_plan is None:
        raise HTTPException(status_code=404, detail="After plan not found")

    try:
        comparison = compare_plans_service(
            before_plan.plan_json,
            after_plan.plan_json,
            before_plan.sql_text,
            after_plan.sql_text,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Comparison failed: {exc}",
        ) from exc

    return {
        "before_plan_id": plan_id,
        "after_plan_id": body.other_plan_id,
        "comparison": comparison,
    }


@router.delete("/{plan_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a plan")
async def delete_plan(
    plan_id: str,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> None:
    """Delete a plan and all its analyses."""
    _user, workspace_id = auth

    result = await db.execute(
        select(Plan).where(Plan.id == plan_id, Plan.workspace_id == workspace_id)
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    await db.delete(plan)
