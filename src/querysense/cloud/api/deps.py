"""
Shared FastAPI dependencies for API routes.

Provides current-user resolution from either:
- Cookie session (browser)
- Bearer API key (programmatic)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from querysense.cloud.auth import SessionData, validate_api_key
from querysense.cloud.database import get_session

if TYPE_CHECKING:
    from querysense.cloud.models import User


def _get_session_manager() -> "SessionManager":  # noqa: F821
    """Lazy import to avoid circular dependency."""
    from querysense.cloud.app import get_session_manager

    return get_session_manager()


async def get_current_user(
    db: AsyncSession = Depends(get_session),
    authorization: str | None = Header(default=None),
    session_token: str | None = Cookie(default=None, alias="qs_session"),
) -> tuple["User", str]:
    """
    Resolve the current user and workspace from auth credentials.

    Checks Bearer token first, then cookie session.

    Returns:
        (user, workspace_id)

    Raises:
        HTTPException 401 if not authenticated.
    """
    from querysense.cloud.auth import get_user_by_id

    # 1. Try Bearer API key
    if authorization and authorization.startswith("Bearer "):
        raw_key = authorization[7:]
        result = await validate_api_key(db, raw_key)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked API key",
            )
        api_key, user = result
        return user, api_key.workspace_id

    # 2. Try cookie session
    if session_token:
        sm = _get_session_manager()
        session = sm.verify_session(session_token)
        if session is not None:
            user = await get_user_by_id(db, session.user_id)
            if user is not None and user.is_active:
                return user, session.workspace_id

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_optional_user(
    db: AsyncSession = Depends(get_session),
    authorization: str | None = Header(default=None),
    session_token: str | None = Cookie(default=None, alias="qs_session"),
) -> tuple["User", str] | None:
    """
    Like get_current_user but returns None instead of raising.

    Useful for pages that work with or without auth (e.g. share pages).
    """
    try:
        return await get_current_user(db, authorization, session_token)
    except HTTPException:
        return None
