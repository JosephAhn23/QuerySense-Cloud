"""
Event system for QuerySense Cloud.

Provides a unified way to:
1. Record activities in the database
2. Broadcast events via Redis pub/sub → WebSocket
3. Track workspace-level events for the activity feed

All user-facing actions should go through record_activity() which
handles both persistence and real-time notification in one call.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def record_activity(
    db: Any,
    *,
    workspace_id: str,
    user_id: str | None,
    action: str,
    target_type: str,
    target_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    broadcast: bool = True,
) -> str:
    """
    Record a workspace activity and optionally broadcast via WebSocket.

    Args:
        db: AsyncSession
        workspace_id: Workspace this event belongs to
        user_id: User who performed the action (None for system events)
        action: Event type (plan_uploaded, comment_added, analysis_run, etc.)
        target_type: Entity type (plan, comment, share, workspace)
        target_id: Entity ID
        metadata: Extra data to store as JSON
        broadcast: Whether to also publish via Redis pub/sub

    Returns:
        The activity ID.
    """
    from querysense.cloud.models import Activity

    activity = Activity(
        workspace_id=workspace_id,
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        metadata_json=json.dumps(metadata) if metadata else None,
    )
    db.add(activity)
    await db.flush()

    if broadcast:
        try:
            from querysense.cloud.cache import publish_event

            await publish_event(
                f"workspace:{workspace_id}",
                {
                    "type": "activity",
                    "action": action,
                    "target_type": target_type,
                    "target_id": target_id,
                    "user_id": user_id,
                    "activity_id": activity.id,
                    "metadata": metadata,
                },
            )
        except Exception as e:
            logger.debug("Failed to broadcast activity: %s", e)

    return activity.id
