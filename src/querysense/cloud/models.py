"""
SQLAlchemy ORM models for QuerySense Cloud.

Tables: User, Workspace, Plan, Analysis, APIKey, ShareLink,
        Comment, Activity, QueryMetric
All use UUID primary keys for share-safety.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from querysense.cloud.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return uuid.uuid4().hex


class User(Base):
    """Registered user."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    owned_workspaces: Mapped[list[Workspace]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class Workspace(Base):
    """Isolated workspace (team boundary)."""

    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    owner_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    tier: Mapped[str] = mapped_column(
        String(20), nullable=False, default="community"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    owner: Mapped[User] = relationship(back_populates="owned_workspaces")
    plans: Mapped[list[Plan]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )
    api_keys: Mapped[list[APIKey]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )
    usage_records: Mapped[list[UsageRecord]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )


class Plan(Base):
    """Stored EXPLAIN plan JSON."""

    __tablename__ = "plans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    workspace_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False, default="Untitled Plan")
    plan_json: Mapped[str] = mapped_column(Text, nullable=False)
    sql_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON-encoded list
    uploaded_by: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )

    # Relationships
    workspace: Mapped[Workspace] = relationship(back_populates="plans")
    uploader: Mapped[User | None] = relationship()
    analyses: Mapped[list[Analysis]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )
    share_links: Mapped[list[ShareLink]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )


class Analysis(Base):
    """Stored analysis result for a plan."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    plan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("plans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_level: Mapped[str] = mapped_column(String(20), nullable=False, default="PLAN")
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    info_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    querysense_version: Mapped[str] = mapped_column(String(20), nullable=False)
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    plan: Mapped[Plan] = relationship(back_populates="analyses")


class APIKey(Base):
    """API key for programmatic access to a workspace."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    workspace_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_by: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    workspace: Mapped[Workspace] = relationship(back_populates="api_keys")
    creator: Mapped[User | None] = relationship()


class ShareLink(Base):
    """Shareable link for a plan analysis."""

    __tablename__ = "share_links"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    plan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("plans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    created_by: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    plan: Mapped[Plan] = relationship(back_populates="share_links")
    creator: Mapped[User | None] = relationship()

    __table_args__ = (
        UniqueConstraint("token", name="uq_share_links_token"),
    )


class UsageRecord(Base):
    """Daily usage tracking per workspace for tier enforcement."""

    __tablename__ = "usage_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    workspace_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    record_date: Mapped[datetime] = mapped_column(Date, nullable=False)
    plans_analyzed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    api_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Relationships
    workspace: Mapped[Workspace] = relationship(back_populates="usage_records")

    __table_args__ = (
        UniqueConstraint("workspace_id", "record_date", name="uq_usage_workspace_date"),
    )


# ── Collaboration Models ────────────────────────────────────────────────


class Comment(Base):
    """Threaded comments on a plan (collaboration)."""

    __tablename__ = "comments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    plan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("plans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    parent_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("comments.id", ondelete="CASCADE"), nullable=True
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    node_path: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )  # Optional: links comment to a specific plan node
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    plan: Mapped[Plan] = relationship()
    author: Mapped[User] = relationship()
    parent: Mapped[Comment | None] = relationship(remote_side="Comment.id")
    replies: Mapped[list[Comment]] = relationship(
        cascade="all, delete-orphan",
    )


class Activity(Base):
    """Workspace activity feed — tracks all user actions for team awareness."""

    __tablename__ = "activities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    workspace_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # plan_uploaded, comment_added, analysis_run, share_created, ...
    target_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # plan, comment, share, workspace, ...
    target_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON extra data
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )

    # Relationships
    workspace: Mapped[Workspace] = relationship()
    actor: Mapped[User | None] = relationship()

    __table_args__ = (
        Index("idx_activities_workspace_time", "workspace_id", "created_at"),
    )


class QueryMetric(Base):
    """
    Time-series query performance metrics.

    Designed for TimescaleDB hypertable conversion in production.
    Works on regular PostgreSQL/SQLite as a plain table for dev.
    """

    __tablename__ = "query_metrics"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_uuid)
    workspace_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("plans.id", ondelete="SET NULL"), nullable=True
    )
    query_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    execution_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    rows_scanned: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rows_returned: Mapped[int | None] = mapped_column(Integer, nullable=True)
    index_usage_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    cost: Mapped[float | None] = mapped_column(Float, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )

    # Relationships
    workspace: Mapped[Workspace] = relationship()

    __table_args__ = (
        Index("idx_metrics_workspace_time", "workspace_id", "recorded_at"),
        Index("idx_metrics_query_hash_time", "query_hash", "recorded_at"),
    )
