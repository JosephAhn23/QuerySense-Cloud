"""
Cloud settings for QuerySense SaaS.

Uses environment variables with sensible defaults for local development.

Settings are loaded from environment variables with the QUERYSENSE_CLOUD_
prefix (consistent with the core QUERYSENSE_ prefix). The legacy QS_ prefix
is still accepted for backward compatibility.

Examples:
    QUERYSENSE_CLOUD_SECRET_KEY=...
    QUERYSENSE_CLOUD_DATABASE_URL=sqlite+aiosqlite:///./querysense_cloud.db
    QUERYSENSE_CLOUD_DEBUG=true

    # Legacy (still accepted):
    QS_SECRET_KEY=...
"""

from __future__ import annotations

import logging
import secrets
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

CLOUD_ROOT = Path(__file__).resolve().parent

# Canonical prefix for cloud settings
_ENV_PREFIX = "QUERYSENSE_CLOUD_"
# Legacy prefix (accepted for backward compatibility)
_LEGACY_PREFIX = "QS_"


class CloudSettings(BaseModel):
    """Configuration for QuerySense Cloud."""

    # ── Server ──────────────────────────────────────────────────────────
    host: str = Field(default="127.0.0.1", description="Bind address")
    port: int = Field(default=8000, description="Bind port")
    debug: bool = Field(default=False, description="Enable debug mode")
    base_url: str = Field(default="http://localhost:8000", description="Public base URL")

    # ── Security ────────────────────────────────────────────────────────
    secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for session signing",
    )
    session_max_age: int = Field(
        default=86400 * 7, description="Session cookie max age in seconds (7 days)"
    )

    # ── Database ────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./querysense_cloud.db",
        description="SQLAlchemy async database URL",
    )
    database_echo: bool = Field(default=False, description="Echo SQL statements")

    # ── Paths ───────────────────────────────────────────────────────────
    templates_dir: Path = Field(
        default=CLOUD_ROOT / "templates",
        description="Jinja2 templates directory",
    )
    static_dir: Path = Field(
        default=CLOUD_ROOT / "static",
        description="Static files directory",
    )

    # ── Redis (optional) ─────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL for caching and pub/sub (optional)",
    )

    # ── Limits ──────────────────────────────────────────────────────────
    max_plan_size_bytes: int = Field(
        default=10 * 1024 * 1024, description="Max plan JSON size (10 MB)"
    )
    max_plans_per_workspace: int = Field(
        default=10_000, description="Max plans stored per workspace"
    )
    api_keys_per_workspace: int = Field(
        default=10, description="Max API keys per workspace"
    )


def get_cloud_settings() -> CloudSettings:
    """
    Load cloud settings from environment variables.

    Lookup order per field:
    1. QUERYSENSE_CLOUD_<FIELD> (canonical prefix)
    2. QS_<FIELD> (legacy prefix, for backward compatibility)

    If both are set, the canonical prefix wins.
    """
    import os

    overrides: dict[str, str] = {}
    for field_name in CloudSettings.model_fields:
        upper_field = field_name.upper()
        canonical_key = f"{_ENV_PREFIX}{upper_field}"
        legacy_key = f"{_LEGACY_PREFIX}{upper_field}"

        if canonical_key in os.environ:
            overrides[field_name] = os.environ[canonical_key]
        elif legacy_key in os.environ:
            logger.info(
                "Using legacy env var %s; prefer %s",
                legacy_key,
                canonical_key,
            )
            overrides[field_name] = os.environ[legacy_key]

    return CloudSettings(**overrides)  # type: ignore[arg-type]
