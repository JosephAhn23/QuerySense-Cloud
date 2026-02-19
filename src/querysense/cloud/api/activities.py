"""
Activity feed endpoints — team awareness and audit trail.

GET /api/v1/workspaces/{workspace_id}/activity — paginated activity feed
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from querysense.cloud.api.deps import get_current_user
from querysense.cloud.database import get_session
from querysense.cloud.models import Activity, User

router = APIRouter()


@router.get(
    "/workspaces/{workspace_id}/activity",
    summary="Get workspace activity feed",
)
async def get_activity_feed(
    workspace_id: str,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    action_filter: str | None = Query(
        default=None,
        description="Filter by action type (e.g. plan_uploaded, comment_added)",
    ),
) -> dict[str, Any]:
    """
    Get paginated activity feed for a workspace.

    Returns recent activities with actor information, newest first.
    Useful for team dashboards and audit trails.
    """
    _user, auth_workspace_id = auth
    # User can only see their own workspace's activity
    if auth_workspace_id != workspace_id:
        workspace_id = auth_workspace_id

    query = (
        select(Activity, User.display_name)
        .outerjoin(User, Activity.user_id == User.id)
        .where(Activity.workspace_id == workspace_id)
    )

    if action_filter:
        query = query.where(Activity.action == action_filter)

    # Total count
    count_q = (
        select(func.count(Activity.id))
        .where(Activity.workspace_id == workspace_id)
    )
    if action_filter:
        count_q = count_q.where(Activity.action == action_filter)
    total = (await db.execute(count_q)).scalar_one()

    # Fetch page
    query = query.order_by(Activity.created_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(query)).all()

    items = []
    for activity, user_name in rows:
        metadata = json.loads(activity.metadata_json) if activity.metadata_json else None
        items.append({
            "id": activity.id,
            "action": activity.action,
            "target_type": activity.target_type,
            "target_id": activity.target_id,
            "user_id": activity.user_id,
            "user_name": user_name or "System",
            "metadata": metadata,
            "created_at": activity.created_at.isoformat(),
        })

    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
    }
