"""
API key management endpoints.

POST   /api/v1/keys       — create an API key
GET    /api/v1/keys        — list API keys
DELETE /api/v1/keys/{id}   — revoke an API key
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from querysense.cloud.api.deps import get_current_user
from querysense.cloud.auth import generate_api_key
from querysense.cloud.database import get_session
from querysense.cloud.models import APIKey, User

router = APIRouter(prefix="/keys")


class KeyCreateRequest(BaseModel):
    """Request to create an API key."""

    name: str = Field(..., min_length=1, max_length=100, description="Human-readable key name")


class KeyCreateResponse(BaseModel):
    """Response with the raw key (shown only once)."""

    id: str
    name: str
    prefix: str
    raw_key: str = Field(..., description="Full API key — store securely, shown only once")
    created_at: str


class KeyInfo(BaseModel):
    """API key info (without the raw key)."""

    id: str
    name: str
    prefix: str
    is_active: bool
    created_at: str
    last_used_at: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create an API key")
async def create_key(
    body: KeyCreateRequest,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> KeyCreateResponse:
    """Create a new API key for the current workspace."""
    user, workspace_id = auth

    # Check limit
    from querysense.cloud.settings import get_cloud_settings

    settings = get_cloud_settings()
    count_result = await db.execute(
        select(APIKey)
        .where(APIKey.workspace_id == workspace_id, APIKey.is_active.is_(True))
    )
    existing = len(count_result.scalars().all())
    if existing >= settings.api_keys_per_workspace:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Maximum of {settings.api_keys_per_workspace} active API keys per workspace",
        )

    raw_key, key_hash, prefix = generate_api_key()

    api_key = APIKey(
        workspace_id=workspace_id,
        key_hash=key_hash,
        prefix=prefix,
        name=body.name,
        created_by=user.id,
    )
    db.add(api_key)
    await db.flush()

    return KeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        prefix=api_key.prefix,
        raw_key=raw_key,
        created_at=api_key.created_at.isoformat(),
    )


@router.get("", summary="List API keys")
async def list_keys(
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> list[KeyInfo]:
    """List all API keys in the current workspace."""
    _user, workspace_id = auth

    result = await db.execute(
        select(APIKey)
        .where(APIKey.workspace_id == workspace_id)
        .order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()

    return [
        KeyInfo(
            id=k.id,
            name=k.name,
            prefix=k.prefix,
            is_active=k.is_active,
            created_at=k.created_at.isoformat(),
            last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
        )
        for k in keys
    ]


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke an API key")
async def revoke_key(
    key_id: str,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> None:
    """Revoke (soft-delete) an API key."""
    _user, workspace_id = auth

    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.workspace_id == workspace_id)
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_active = False
    db.add(api_key)
