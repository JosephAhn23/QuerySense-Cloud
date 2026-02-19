"""
Query performance trend endpoints — time-series analytics.

GET  /api/v1/workspaces/{workspace_id}/trends           — workspace trends overview
GET  /api/v1/workspaces/{workspace_id}/trends/{hash}    — per-query trends
POST /api/v1/workspaces/{workspace_id}/metrics           — record a metric

Designed for TimescaleDB in production; works on regular PostgreSQL/SQLite.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from querysense.cloud.api.deps import get_current_user
from querysense.cloud.database import get_session
from querysense.cloud.models import QueryMetric, User

router = APIRouter()


# ── Schemas ────────────────────────────────────────────────────────────


class MetricRecordRequest(BaseModel):
    """Request to record a query metric data point."""

    query_hash: str = Field(..., min_length=1, max_length=64)
    plan_id: str | None = None
    execution_time_ms: float | None = None
    rows_scanned: int | None = None
    rows_returned: int | None = None
    index_usage_pct: float | None = Field(default=None, ge=0, le=100)
    cost: float | None = None
    findings_count: int = 0
    critical_count: int = 0
    metadata: dict[str, Any] | None = None


class TrendPoint(BaseModel):
    """A single data point in a trend."""

    timestamp: str
    avg_execution_time_ms: float | None = None
    max_execution_time_ms: float | None = None
    avg_cost: float | None = None
    avg_index_usage_pct: float | None = None
    sample_count: int = 0
    anomaly: bool = False


# ── Time range helpers ─────────────────────────────────────────────────


_RANGE_MAP = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}


def _parse_range(time_range: str) -> timedelta:
    delta = _RANGE_MAP.get(time_range)
    if delta is None:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid time_range. Must be one of: {', '.join(_RANGE_MAP)}",
        )
    return delta


# ── Endpoints ──────────────────────────────────────────────────────────


@router.post(
    "/workspaces/{workspace_id}/metrics",
    status_code=201,
    summary="Record a query metric",
)
async def record_metric(
    workspace_id: str,
    body: MetricRecordRequest,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
) -> dict[str, str]:
    """Record a query performance metric data point."""
    import json as _json

    _user, auth_ws = auth
    if auth_ws != workspace_id:
        raise HTTPException(status_code=403, detail="Workspace mismatch")

    metric = QueryMetric(
        workspace_id=workspace_id,
        plan_id=body.plan_id,
        query_hash=body.query_hash,
        execution_time_ms=body.execution_time_ms,
        rows_scanned=body.rows_scanned,
        rows_returned=body.rows_returned,
        index_usage_pct=body.index_usage_pct,
        cost=body.cost,
        findings_count=body.findings_count,
        critical_count=body.critical_count,
        metadata_json=_json.dumps(body.metadata) if body.metadata else None,
    )
    db.add(metric)
    await db.flush()

    return {"id": metric.id, "status": "recorded"}


@router.get(
    "/workspaces/{workspace_id}/trends",
    summary="Get workspace trends overview",
)
async def get_workspace_trends(
    workspace_id: str,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
    time_range: str = Query(default="7d", description="Time range: 1h, 6h, 24h, 7d, 30d, 90d"),
    metric: str = Query(
        default="execution_time_ms",
        description="Metric to trend: execution_time_ms, cost, index_usage_pct, findings_count",
    ),
) -> dict[str, Any]:
    """
    Get workspace-wide performance trends.

    Aggregates query metrics over the given time range with
    hourly or daily buckets depending on the range.
    """
    _user, auth_ws = auth
    if auth_ws != workspace_id:
        raise HTTPException(status_code=403, detail="Workspace mismatch")

    delta = _parse_range(time_range)
    since = datetime.now(timezone.utc) - delta

    # Determine bucket size: hourly for <= 7d, daily for longer
    bucket_hours = 1 if delta <= timedelta(days=7) else 24

    # Fetch aggregated metrics
    # Use portable SQL that works on SQLite, PostgreSQL, and TimescaleDB
    query = (
        select(
            QueryMetric.recorded_at,
            func.avg(QueryMetric.execution_time_ms).label("avg_time"),
            func.max(QueryMetric.execution_time_ms).label("max_time"),
            func.avg(QueryMetric.cost).label("avg_cost"),
            func.avg(QueryMetric.index_usage_pct).label("avg_index"),
            func.count(QueryMetric.id).label("samples"),
        )
        .where(
            QueryMetric.workspace_id == workspace_id,
            QueryMetric.recorded_at >= since,
        )
        .group_by(QueryMetric.recorded_at)
        .order_by(QueryMetric.recorded_at.desc())
        .limit(500)
    )

    rows = (await db.execute(query)).all()

    # Build trend points
    points: list[dict[str, Any]] = []
    all_times: list[float] = []

    for row in rows:
        avg_time = float(row.avg_time) if row.avg_time is not None else None
        if avg_time is not None:
            all_times.append(avg_time)

        points.append({
            "timestamp": row.recorded_at.isoformat() if hasattr(row.recorded_at, "isoformat") else str(row.recorded_at),
            "avg_execution_time_ms": round(avg_time, 2) if avg_time is not None else None,
            "max_execution_time_ms": round(float(row.max_time), 2) if row.max_time is not None else None,
            "avg_cost": round(float(row.avg_cost), 2) if row.avg_cost is not None else None,
            "avg_index_usage_pct": round(float(row.avg_index), 1) if row.avg_index is not None else None,
            "sample_count": row.samples,
            "anomaly": False,
        })

    # Simple anomaly detection: 3-sigma on execution time
    if len(all_times) > 5:
        import statistics

        mean = statistics.mean(all_times)
        stdev = statistics.stdev(all_times)
        if stdev > 0:
            for point in points:
                t = point.get("avg_execution_time_ms")
                if t is not None and abs(t - mean) > 3 * stdev:
                    point["anomaly"] = True

    # Summary
    summary: dict[str, Any] = {"total_samples": sum(p["sample_count"] for p in points)}
    if all_times:
        import statistics

        summary["mean_ms"] = round(statistics.mean(all_times), 2)
        summary["p95_ms"] = round(
            sorted(all_times)[int(len(all_times) * 0.95)] if len(all_times) > 1 else all_times[0],
            2,
        )
        # Trend direction: compare first half vs second half
        mid = len(all_times) // 2
        if mid > 0:
            first_half = statistics.mean(all_times[:mid])
            second_half = statistics.mean(all_times[mid:])
            if first_half > 0:
                trend_pct = ((second_half - first_half) / first_half) * 100
                summary["trend_pct"] = round(trend_pct, 1)
                summary["trend"] = (
                    "improving" if trend_pct < -5 else ("degrading" if trend_pct > 5 else "stable")
                )

    return {
        "workspace_id": workspace_id,
        "time_range": time_range,
        "metric": metric,
        "points": points,
        "anomalies": [p for p in points if p.get("anomaly")],
        "summary": summary,
    }


@router.get(
    "/workspaces/{workspace_id}/trends/{query_hash}",
    summary="Get per-query trends",
)
async def get_query_trends(
    workspace_id: str,
    query_hash: str,
    db: AsyncSession = Depends(get_session),
    auth: tuple[User, str] = Depends(get_current_user),
    time_range: str = Query(default="7d"),
) -> dict[str, Any]:
    """Get trends for a specific query by hash."""
    _user, auth_ws = auth
    if auth_ws != workspace_id:
        raise HTTPException(status_code=403, detail="Workspace mismatch")

    delta = _parse_range(time_range)
    since = datetime.now(timezone.utc) - delta

    query = (
        select(QueryMetric)
        .where(
            QueryMetric.workspace_id == workspace_id,
            QueryMetric.query_hash == query_hash,
            QueryMetric.recorded_at >= since,
        )
        .order_by(QueryMetric.recorded_at.desc())
        .limit(1000)
    )

    rows = (await db.execute(query)).scalars().all()

    points = []
    for m in rows:
        points.append({
            "timestamp": m.recorded_at.isoformat(),
            "execution_time_ms": m.execution_time_ms,
            "cost": m.cost,
            "rows_scanned": m.rows_scanned,
            "index_usage_pct": m.index_usage_pct,
            "findings_count": m.findings_count,
        })

    return {
        "query_hash": query_hash,
        "time_range": time_range,
        "points": points,
        "total": len(points),
    }
