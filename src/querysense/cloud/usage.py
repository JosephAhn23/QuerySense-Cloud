"""
Usage tracking and tier enforcement.

Tracks daily plan analysis counts and API calls per workspace.
Enforces tier limits by raising HTTP 429 when exceeded.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from querysense.cloud.database import get_session
from querysense.cloud.models import UsageRecord, Workspace
from querysense.cloud.tiers import Tier, TierLimits, get_limits, tier_from_string

if TYPE_CHECKING:
    from querysense.cloud.models import User


async def get_or_create_usage(
    db: AsyncSession,
    workspace_id: str,
    for_date: date | None = None,
) -> UsageRecord:
    """Get or create today's usage record for a workspace."""
    today = for_date or datetime.now(timezone.utc).date()

    result = await db.execute(
        select(UsageRecord).where(
            UsageRecord.workspace_id == workspace_id,
            UsageRecord.record_date == today,
        )
    )
    record = result.scalar_one_or_none()

    if record is None:
        record = UsageRecord(
            workspace_id=workspace_id,
            record_date=today,
            plans_analyzed=0,
            api_calls=0,
        )
        db.add(record)
        await db.flush()

    return record


async def increment_plan_count(db: AsyncSession, workspace_id: str) -> int:
    """Increment the daily plan analysis count. Returns new count."""
    record = await get_or_create_usage(db, workspace_id)
    record.plans_analyzed += 1
    db.add(record)
    await db.flush()
    return record.plans_analyzed


async def increment_api_calls(db: AsyncSession, workspace_id: str) -> int:
    """Increment the monthly API call count. Returns count for the month."""
    record = await get_or_create_usage(db, workspace_id)
    record.api_calls += 1
    db.add(record)
    await db.flush()

    # Sum all api_calls for this month
    today = datetime.now(timezone.utc).date()
    first_of_month = today.replace(day=1)
    result = await db.execute(
        select(UsageRecord).where(
            UsageRecord.workspace_id == workspace_id,
            UsageRecord.record_date >= first_of_month,
        )
    )
    records = result.scalars().all()
    return sum(r.api_calls for r in records)


async def get_workspace_tier(db: AsyncSession, workspace_id: str) -> tuple[Tier, TierLimits]:
    """Get the tier and limits for a workspace."""
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    ws = result.scalar_one_or_none()
    if ws is None:
        return Tier.COMMUNITY, get_limits(Tier.COMMUNITY)

    tier = tier_from_string(ws.tier)
    return tier, get_limits(tier)


async def get_monthly_api_calls(db: AsyncSession, workspace_id: str) -> int:
    """Get total API calls for the current month."""
    today = datetime.now(timezone.utc).date()
    first_of_month = today.replace(day=1)
    result = await db.execute(
        select(UsageRecord).where(
            UsageRecord.workspace_id == workspace_id,
            UsageRecord.record_date >= first_of_month,
        )
    )
    records = result.scalars().all()
    return sum(r.api_calls for r in records)


async def get_today_plan_count(db: AsyncSession, workspace_id: str) -> int:
    """Get plans analyzed today."""
    today = datetime.now(timezone.utc).date()
    result = await db.execute(
        select(UsageRecord).where(
            UsageRecord.workspace_id == workspace_id,
            UsageRecord.record_date == today,
        )
    )
    record = result.scalar_one_or_none()
    return record.plans_analyzed if record else 0


# ── FastAPI dependencies for tier enforcement ──────────────────────────


async def check_plan_limit(
    db: AsyncSession,
    workspace_id: str,
) -> None:
    """
    Check if the workspace can analyze another plan today.

    Raises HTTP 429 if the daily limit is exceeded.
    """
    tier, limits = await get_workspace_tier(db, workspace_id)

    if limits.plans_per_day == 0:
        return  # unlimited

    count = await get_today_plan_count(db, workspace_id)
    if count >= limits.plans_per_day:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Daily plan limit exceeded",
                "limit": limits.plans_per_day,
                "used": count,
                "tier": tier.value,
                "upgrade_url": "/pricing",
            },
        )


async def check_api_limit(
    db: AsyncSession,
    workspace_id: str,
) -> None:
    """
    Check if the workspace has API calls remaining this month.

    Raises HTTP 429 if the monthly limit is exceeded.
    """
    tier, limits = await get_workspace_tier(db, workspace_id)

    if limits.api_calls_per_month == 0:
        return  # unlimited

    count = await get_monthly_api_calls(db, workspace_id)
    if count >= limits.api_calls_per_month:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Monthly API call limit exceeded",
                "limit": limits.api_calls_per_month,
                "used": count,
                "tier": tier.value,
                "upgrade_url": "/pricing",
            },
        )


def require_feature(feature_name: str) -> None:
    """
    Check if a feature is available on the workspace's tier.

    Usage in route:
        tier, limits = await get_workspace_tier(db, workspace_id)
        require_tier_feature(limits, "share_links")
    """
    pass  # Implemented inline via require_tier_feature


def require_tier_feature(limits: TierLimits, feature: str, tier: Tier) -> None:
    """
    Check if a boolean feature is enabled on this tier.

    Args:
        limits: The tier's limits
        feature: Name of the boolean field on TierLimits
        tier: Current tier (for error message)

    Raises:
        HTTPException 403 if the feature is not available
    """
    if not getattr(limits, feature, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": f"Feature '{feature}' requires a higher tier",
                "current_tier": tier.value,
                "upgrade_url": "/pricing",
            },
        )
