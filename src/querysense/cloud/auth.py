"""
Authentication for QuerySense Cloud.

Supports two auth mechanisms:
- Cookie-based sessions (browser, signed with itsdangerous)
- Bearer API keys (programmatic access)

Share links bypass authentication entirely.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

import bcrypt as _bcrypt
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select, update

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from querysense.cloud.models import APIKey, User

# ── Password hashing ───────────────────────────────────────────────────


def hash_password(plain: str) -> str:
    """Hash a password with bcrypt."""
    pwd_bytes = plain.encode("utf-8")[:72]  # bcrypt max 72 bytes
    salt = _bcrypt.gensalt()
    return _bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash."""
    pwd_bytes = plain.encode("utf-8")[:72]
    hashed_bytes = hashed.encode("utf-8")
    return _bcrypt.checkpw(pwd_bytes, hashed_bytes)


# ── Session management (cookie-based) ─────────────────────────────────


@dataclass
class SessionData:
    """Decoded session payload."""

    user_id: str
    workspace_id: str


class SessionManager:
    """
    Create and verify signed session cookies.

    Uses itsdangerous URLSafeTimedSerializer so sessions
    are tamper-proof and expire after max_age seconds.
    """

    def __init__(self, secret_key: str, max_age: int = 86400 * 7) -> None:
        self._serializer = URLSafeTimedSerializer(secret_key)
        self._max_age = max_age

    def create_session(self, user_id: str, workspace_id: str) -> str:
        """Create a signed session token."""
        return self._serializer.dumps({"uid": user_id, "wid": workspace_id})

    def verify_session(self, token: str) -> SessionData | None:
        """
        Verify and decode a session token.

        Returns None if invalid or expired.
        """
        try:
            data = self._serializer.loads(token, max_age=self._max_age)
            return SessionData(user_id=data["uid"], workspace_id=data["wid"])
        except (BadSignature, KeyError):
            return None


# ── API key management ─────────────────────────────────────────────────

API_KEY_PREFIX = "qs_"


def _hash_api_key(raw_key: str) -> str:
    """SHA-256 hash an API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns:
        (raw_key, key_hash, prefix) - raw_key is shown once to the user.
    """
    random_part = secrets.token_urlsafe(32)
    raw_key = f"{API_KEY_PREFIX}{random_part}"
    key_hash = _hash_api_key(raw_key)
    prefix = raw_key[:12]
    return raw_key, key_hash, prefix


async def validate_api_key(
    db: "AsyncSession", raw_key: str
) -> tuple["APIKey", "User"] | None:
    """
    Validate an API key and return the key + owning user.

    Also updates last_used_at on the key.
    Returns None if the key is invalid or inactive.
    """
    from datetime import datetime, timezone

    from querysense.cloud.models import APIKey, User, Workspace

    key_hash = _hash_api_key(raw_key)

    result = await db.execute(
        select(APIKey, Workspace, User)
        .join(Workspace, APIKey.workspace_id == Workspace.id)
        .join(User, Workspace.owner_id == User.id)
        .where(APIKey.key_hash == key_hash, APIKey.is_active.is_(True))
    )
    row = result.first()
    if row is None:
        return None

    api_key, _workspace, user = row

    # Update last_used_at
    await db.execute(
        update(APIKey)
        .where(APIKey.id == api_key.id)
        .values(last_used_at=datetime.now(timezone.utc))
    )

    return api_key, user


# ── User lookup helpers ────────────────────────────────────────────────


async def get_user_by_email(db: "AsyncSession", email: str) -> "User | None":
    """Look up a user by email address."""
    from querysense.cloud.models import User

    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: "AsyncSession", user_id: str) -> "User | None":
    """Look up a user by ID."""
    from querysense.cloud.models import User

    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()
