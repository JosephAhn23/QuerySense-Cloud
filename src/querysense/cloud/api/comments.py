"""
Plan comment endpoints — threaded collaboration on EXPLAIN plans.

POST   /api/v1/plans/{plan_id}/comments          — add a comment
GET    /api/v1/plans/{plan_id}/comments          — list comments
PATCH  /api/v1/comments/{comment_id}              — edit/resolve a comment
DELETE /api/v1/comments/{comment_id}              — delete a comment
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from querysense.cloud.api.deps import get_current_user
from querysense.cloud.database import get_session
from querysense.cloud.events import record_activity
from querysense.cloud.models import Comment, Plan, User

router = APIRouter()


# ── Request / Response schemas ─────────────────────────────────────────


class CommentCreateRequest(BaseModel):
    """Request to add a comment."""

    content: str = Field(..., min_length=1, max_length=5000)
    parent_id: str | None = Field(default=None, description="Reply to this comment")
    node_path: str | None = Field(
        default=None, description="Link comment to a specific plan node path"
    )


class CommentUpdateRequest(BaseModel):
    """Request to update a comment."""

    content: str | None = Field(default=None, min_length=1, max_length=5000)
    resolved: bool | None = None


class CommentResponse(BaseModel):
    """Single comment."""

    id: str
    plan_id: str
    user_id: str
    user_name: str
    parent_id: str | None = None
    content: str
    resolved: bool = False
    node_path: str | None = None
    created_at: str
    updated_at: str | None = None
    reply_count: int = 0


# ── Endpoints ──────────────────────────────────────────────────────────


@router.post(
    "/plans/{plan_id}/comments",
    status_code=status.HTTP_201_CREATED,
    summary="Add a comment to a plan",
)
async def create_comment(
    plan_id: str,
    body: CommentCreateRequest,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> CommentResponse:
    """Add a threaded comment to a plan. Supports replies via parent_id."""
    user, workspace_id = auth

    # Verify plan belongs to workspace
    result = await db.execute(
        select(Plan).where(Plan.id == plan_id, Plan.workspace_id == workspace_id)
    )
    plan = result.scalar_one_or_none()
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    # Verify parent comment exists if given
    if body.parent_id is not None:
        parent = await db.execute(
            select(Comment).where(Comment.id == body.parent_id, Comment.plan_id == plan_id)
        )
        if parent.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Parent comment not found")

    comment = Comment(
        plan_id=plan_id,
        user_id=user.id,
        parent_id=body.parent_id,
        content=body.content,
        node_path=body.node_path,
    )
    db.add(comment)
    await db.flush()

    # Record activity
    await record_activity(
        db,
        workspace_id=workspace_id,
        user_id=user.id,
        action="comment_added",
        target_type="plan",
        target_id=plan_id,
        metadata={"comment_id": comment.id, "plan_title": plan.title},
    )

    return CommentResponse(
        id=comment.id,
        plan_id=plan_id,
        user_id=user.id,
        user_name=user.display_name,
        parent_id=body.parent_id,
        content=comment.content,
        node_path=comment.node_path,
        created_at=comment.created_at.isoformat(),
    )


@router.get("/plans/{plan_id}/comments", summary="List comments on a plan")
async def list_comments(
    plan_id: str,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
    include_resolved: bool = Query(default=True),
) -> dict[str, Any]:
    """List all comments on a plan, newest first. Includes reply counts."""
    _user, workspace_id = auth

    # Verify plan
    plan_result = await db.execute(
        select(Plan).where(Plan.id == plan_id, Plan.workspace_id == workspace_id)
    )
    if plan_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    query = (
        select(Comment, User.display_name)
        .join(User, Comment.user_id == User.id)
        .where(Comment.plan_id == plan_id)
    )

    if not include_resolved:
        query = query.where(Comment.resolved.is_(False))

    query = query.order_by(Comment.created_at.asc())
    rows = (await db.execute(query)).all()

    # Count replies per comment
    reply_counts_q = (
        select(Comment.parent_id, func.count(Comment.id))
        .where(Comment.plan_id == plan_id, Comment.parent_id.isnot(None))
        .group_by(Comment.parent_id)
    )
    reply_rows = (await db.execute(reply_counts_q)).all()
    reply_map = {parent_id: cnt for parent_id, cnt in reply_rows}

    items = []
    for comment, user_name in rows:
        items.append(
            CommentResponse(
                id=comment.id,
                plan_id=plan_id,
                user_id=comment.user_id,
                user_name=user_name,
                parent_id=comment.parent_id,
                content=comment.content,
                resolved=comment.resolved,
                node_path=comment.node_path,
                created_at=comment.created_at.isoformat(),
                updated_at=comment.updated_at.isoformat() if comment.updated_at else None,
                reply_count=reply_map.get(comment.id, 0),
            )
        )

    return {"items": [i.model_dump() for i in items], "total": len(items)}


@router.patch("/comments/{comment_id}", summary="Edit or resolve a comment")
async def update_comment(
    comment_id: str,
    body: CommentUpdateRequest,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> CommentResponse:
    """Edit comment content or mark as resolved."""
    user, workspace_id = auth
    from datetime import datetime, timezone

    result = await db.execute(select(Comment).where(Comment.id == comment_id))
    comment = result.scalar_one_or_none()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Only author can edit content; any team member can resolve
    if body.content is not None and comment.user_id != user.id:
        raise HTTPException(status_code=403, detail="Only the author can edit comment content")

    if body.content is not None:
        comment.content = body.content
        comment.updated_at = datetime.now(timezone.utc)
    if body.resolved is not None:
        comment.resolved = body.resolved

    await db.flush()

    return CommentResponse(
        id=comment.id,
        plan_id=comment.plan_id,
        user_id=comment.user_id,
        user_name=user.display_name,
        parent_id=comment.parent_id,
        content=comment.content,
        resolved=comment.resolved,
        node_path=comment.node_path,
        created_at=comment.created_at.isoformat(),
        updated_at=comment.updated_at.isoformat() if comment.updated_at else None,
    )


@router.delete(
    "/comments/{comment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a comment",
)
async def delete_comment(
    comment_id: str,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> None:
    """Delete a comment. Only the author can delete."""
    user, _workspace_id = auth

    result = await db.execute(select(Comment).where(Comment.id == comment_id))
    comment = result.scalar_one_or_none()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if comment.user_id != user.id:
        raise HTTPException(status_code=403, detail="Only the author can delete a comment")

    await db.delete(comment)
