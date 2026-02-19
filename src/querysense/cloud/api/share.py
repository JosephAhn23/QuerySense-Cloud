"""
Share link endpoints.

POST /api/v1/share        — create a share link
GET  /api/v1/share/{token} — get shared plan analysis (public, no auth)
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from querysense.cloud.api.deps import get_current_user
from querysense.cloud.database import get_session
from querysense.cloud.models import Plan, ShareLink, User
from querysense.cloud.usage import get_workspace_tier, require_tier_feature

router = APIRouter(prefix="/share")


class ShareCreateRequest(BaseModel):
    """Request to create a share link."""

    plan_id: str = Field(..., description="Plan ID to share")
    expires_in_days: int | None = Field(
        default=None,
        description="Optional expiration in days (1-365, None = never expires)",
        ge=1,
        le=365,
    )


class ShareResponse(BaseModel):
    """Created share link."""

    token: str
    url: str
    expires_at: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create a share link")
async def create_share_link(
    body: ShareCreateRequest,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> ShareResponse:
    """Create a shareable link for a plan and its analysis."""
    user, workspace_id = auth

    # Enforce tier feature gate
    tier, limits = await get_workspace_tier(db, workspace_id)
    require_tier_feature(limits, "share_links", tier)

    # Verify plan belongs to workspace
    result = await db.execute(
        select(Plan).where(Plan.id == body.plan_id, Plan.workspace_id == workspace_id)
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    token = secrets.token_urlsafe(24)

    expires_at = None
    if body.expires_in_days is not None:
        from datetime import timedelta

        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    link = ShareLink(
        plan_id=body.plan_id,
        token=token,
        created_by=user.id,
        expires_at=expires_at,
    )
    db.add(link)
    await db.flush()

    from querysense.cloud.settings import get_cloud_settings

    settings = get_cloud_settings()

    return ShareResponse(
        token=token,
        url=f"{settings.base_url}/share/{token}",
        expires_at=expires_at.isoformat() if expires_at else None,
    )


@router.get("/{token}", summary="Get shared analysis (public)")
async def get_shared(
    token: str,
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """
    Get a shared plan analysis by token.

    This endpoint is PUBLIC — no authentication required.
    """
    result = await db.execute(
        select(ShareLink)
        .where(ShareLink.token == token)
        .options(selectinload(ShareLink.plan).selectinload(Plan.analyses))
    )
    link = result.scalar_one_or_none()
    if link is None:
        raise HTTPException(status_code=404, detail="Share link not found")

    # Check expiration
    if link.expires_at is not None:
        if datetime.now(timezone.utc) > link.expires_at:
            raise HTTPException(status_code=410, detail="Share link has expired")

    plan = link.plan
    latest = max(plan.analyses, key=lambda a: a.analyzed_at) if plan.analyses else None

    return {
        "plan_title": plan.title,
        "created_at": plan.created_at.isoformat(),
        "analysis": json.loads(latest.result_json) if latest else None,
        "sql_text": plan.sql_text,
    }
