"""
TimescaleDB-backed temporal store for production-grade historical analysis.

Upgrades from SQLite to TimescaleDB for:
- Continuous aggregates (automatic hourly/daily rollups)
- 90-day+ retention with compression
- Advanced anomaly detection using statistical functions
- Proactive regression alerts with configurable thresholds
- Time-bucketed queries for visualization (time_bucket)

Architecture:
    Extends the TemporalStore interface. Falls back gracefully to plain
    PostgreSQL when TimescaleDB extension is not installed.

Usage:
    from querysense.temporal.timescale_store import TimescaleTemporalStore

    store = TimescaleTemporalStore("postgresql://localhost/querysense")
    store.store(snapshot)

    # Advanced anomaly detection with EWMA
    anomalies = store.detect_anomalies("query_id", sensitivity=2.5)

    # Regression alerts
    regressions = store.regression_alerts(threshold_pct=15.0)

    # Time-bucketed trends for visualization
    buckets = store.time_series("query_id", bucket="1 hour", days=30)
"""

from __future__ import annotations

import json
import logging
import math
import statistics
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Sequence

from querysense.temporal.store import PlanSnapshot, TemporalStore

logger = logging.getLogger(__name__)


# ── Schema ──────────────────────────────────────────────────────────────

_TIMESCALE_SCHEMA = """\
-- Core hypertable for plan snapshots (TimescaleDB time-series)
CREATE TABLE IF NOT EXISTS plan_snapshots (
    time           TIMESTAMPTZ   NOT NULL,
    query_id       TEXT          NOT NULL,
    structure_hash TEXT          NOT NULL,
    latency_p50_ms DOUBLE PRECISION,
    latency_p95_ms DOUBLE PRECISION,
    rows_processed DOUBLE PRECISION,
    cost_total     DOUBLE PRECISION,
    node_count     INTEGER       DEFAULT 0,
    plan_features  JSONB         DEFAULT '{}',
    metadata       JSONB         DEFAULT '{}'
);

-- Convert to hypertable (TimescaleDB); no-op if already converted
SELECT create_hypertable('plan_snapshots', 'time', if_not_exists => TRUE);

-- Enable compression after 7 days
ALTER TABLE plan_snapshots SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'query_id',
    timescaledb.compress_orderby = 'time DESC'
);

SELECT add_compression_policy('plan_snapshots', INTERVAL '7 days', if_not_exists => TRUE);

-- Retention policy: keep 90 days of raw data
SELECT add_retention_policy('plan_snapshots', INTERVAL '90 days', if_not_exists => TRUE);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_snapshots_query_time
    ON plan_snapshots (query_id, time DESC);

-- Continuous aggregate: hourly rollups
CREATE MATERIALIZED VIEW IF NOT EXISTS plan_snapshots_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    query_id,
    AVG(latency_p50_ms)   AS avg_latency_p50,
    AVG(latency_p95_ms)   AS avg_latency_p95,
    MAX(latency_p95_ms)   AS max_latency_p95,
    AVG(cost_total)        AS avg_cost,
    MAX(cost_total)        AS max_cost,
    AVG(rows_processed)    AS avg_rows,
    COUNT(*)               AS sample_count,
    STDDEV(latency_p50_ms) AS stddev_latency,
    STDDEV(cost_total)     AS stddev_cost
FROM plan_snapshots
GROUP BY bucket, query_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('plan_snapshots_hourly',
    start_offset    => INTERVAL '3 hours',
    end_offset      => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists   => TRUE
);

-- Continuous aggregate: daily rollups
CREATE MATERIALIZED VIEW IF NOT EXISTS plan_snapshots_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) AS bucket,
    query_id,
    AVG(latency_p50_ms)    AS avg_latency_p50,
    AVG(latency_p95_ms)    AS avg_latency_p95,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_p50_ms)
                            AS p99_latency,
    AVG(cost_total)         AS avg_cost,
    MAX(cost_total)         AS max_cost,
    MIN(cost_total)         AS min_cost,
    AVG(rows_processed)     AS avg_rows,
    COUNT(*)                AS sample_count,
    STDDEV(latency_p50_ms)  AS stddev_latency,
    STDDEV(cost_total)      AS stddev_cost
FROM plan_snapshots
GROUP BY bucket, query_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('plan_snapshots_daily',
    start_offset    => INTERVAL '3 days',
    end_offset      => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day',
    if_not_exists   => TRUE
);

-- Regression alerts table
CREATE TABLE IF NOT EXISTS regression_alerts (
    id             SERIAL        PRIMARY KEY,
    query_id       TEXT          NOT NULL,
    detected_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    alert_type     TEXT          NOT NULL,  -- 'cost_regression', 'latency_spike', 'plan_change', 'anomaly'
    severity       TEXT          NOT NULL DEFAULT 'warning',  -- 'info', 'warning', 'critical'
    current_value  DOUBLE PRECISION,
    baseline_value DOUBLE PRECISION,
    change_pct     DOUBLE PRECISION,
    details        JSONB         DEFAULT '{}',
    acknowledged   BOOLEAN       DEFAULT FALSE,
    resolved_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_query_time
    ON regression_alerts (query_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_unacked
    ON regression_alerts (acknowledged, detected_at DESC)
    WHERE acknowledged = FALSE;
"""

_PLAIN_PG_SCHEMA = """\
-- Fallback schema for plain PostgreSQL (no TimescaleDB)
CREATE TABLE IF NOT EXISTS plan_snapshots (
    id             SERIAL        PRIMARY KEY,
    time           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    query_id       TEXT          NOT NULL,
    structure_hash TEXT          NOT NULL,
    latency_p50_ms DOUBLE PRECISION,
    latency_p95_ms DOUBLE PRECISION,
    rows_processed DOUBLE PRECISION,
    cost_total     DOUBLE PRECISION,
    node_count     INTEGER       DEFAULT 0,
    plan_features  JSONB         DEFAULT '{}',
    metadata       JSONB         DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_snapshots_query_time
    ON plan_snapshots (query_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_snapshots_time
    ON plan_snapshots (time DESC);

CREATE TABLE IF NOT EXISTS regression_alerts (
    id             SERIAL        PRIMARY KEY,
    query_id       TEXT          NOT NULL,
    detected_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    alert_type     TEXT          NOT NULL,
    severity       TEXT          NOT NULL DEFAULT 'warning',
    current_value  DOUBLE PRECISION,
    baseline_value DOUBLE PRECISION,
    change_pct     DOUBLE PRECISION,
    details        JSONB         DEFAULT '{}',
    acknowledged   BOOLEAN       DEFAULT FALSE,
    resolved_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_query_time
    ON regression_alerts (query_id, detected_at DESC);
"""


# ── Data classes ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TimeSeriesBucket:
    """A single time-bucketed data point for visualization."""

    bucket: datetime
    query_id: str
    avg_latency_p50: float | None = None
    avg_latency_p95: float | None = None
    max_latency_p95: float | None = None
    avg_cost: float | None = None
    max_cost: float | None = None
    avg_rows: float | None = None
    sample_count: int = 0
    stddev_latency: float | None = None
    stddev_cost: float | None = None
    anomaly_score: float = 0.0  # >1.0 = anomaly

    def to_dict(self) -> dict[str, Any]:
        return {
            "bucket": self.bucket.isoformat(),
            "query_id": self.query_id,
            "avg_latency_p50": self.avg_latency_p50,
            "avg_latency_p95": self.avg_latency_p95,
            "max_latency_p95": self.max_latency_p95,
            "avg_cost": self.avg_cost,
            "max_cost": self.max_cost,
            "avg_rows": self.avg_rows,
            "sample_count": self.sample_count,
            "stddev_latency": self.stddev_latency,
            "stddev_cost": self.stddev_cost,
            "anomaly_score": round(self.anomaly_score, 3),
        }


@dataclass(frozen=True)
class RegressionAlert:
    """A proactive regression alert."""

    query_id: str
    detected_at: datetime
    alert_type: str  # cost_regression, latency_spike, plan_change, anomaly
    severity: str  # info, warning, critical
    current_value: float
    baseline_value: float
    change_pct: float
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def message(self) -> str:
        direction = "increased" if self.change_pct > 0 else "decreased"
        return (
            f"[{self.severity.upper()}] {self.alert_type}: "
            f"{self.query_id[:12]}... {direction} {abs(self.change_pct):.1f}% "
            f"({self.baseline_value:.1f} → {self.current_value:.1f})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "detected_at": self.detected_at.isoformat(),
            "alert_type": self.alert_type,
            "severity": self.severity,
            "current_value": self.current_value,
            "baseline_value": self.baseline_value,
            "change_pct": round(self.change_pct, 1),
            "message": self.message,
            "details": self.details,
        }


@dataclass
class TrendSummary:
    """Summary statistics for a query's historical trends."""

    query_id: str
    total_samples: int = 0
    time_range_days: int = 0
    avg_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    p99_latency_ms: float | None = None
    avg_cost: float | None = None
    trend_direction: str = "stable"  # improving, degrading, stable
    trend_pct: float = 0.0
    anomaly_count: int = 0
    regression_count: int = 0
    plan_changes: int = 0
    last_seen: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "total_samples": self.total_samples,
            "time_range_days": self.time_range_days,
            "avg_latency_ms": round(self.avg_latency_ms, 2) if self.avg_latency_ms else None,
            "p95_latency_ms": round(self.p95_latency_ms, 2) if self.p95_latency_ms else None,
            "p99_latency_ms": round(self.p99_latency_ms, 2) if self.p99_latency_ms else None,
            "avg_cost": round(self.avg_cost, 2) if self.avg_cost else None,
            "trend_direction": self.trend_direction,
            "trend_pct": round(self.trend_pct, 1),
            "anomaly_count": self.anomaly_count,
            "regression_count": self.regression_count,
            "plan_changes": self.plan_changes,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


# ── EWMA Anomaly Detector ─────────────────────────────────────────────


class EWMADetector:
    """
    Exponentially Weighted Moving Average anomaly detector.

    Better than simple 3-sigma for time-series data because it adapts
    to gradual trends and is more sensitive to recent changes.

    Parameters:
        alpha: Smoothing factor (0-1). Higher = more weight on recent data.
        sensitivity: Number of standard deviations for anomaly threshold.
    """

    def __init__(self, alpha: float = 0.3, sensitivity: float = 2.5) -> None:
        self.alpha = alpha
        self.sensitivity = sensitivity
        self._ewma: float | None = None
        self._ewma_var: float = 0.0

    def update(self, value: float) -> float:
        """
        Update EWMA with new value and return anomaly score.

        Returns:
            Anomaly score: abs(deviation) / threshold.
            Score > 1.0 indicates anomaly.
        """
        if self._ewma is None:
            self._ewma = value
            return 0.0

        # Update EWMA
        prev_ewma = self._ewma
        self._ewma = self.alpha * value + (1 - self.alpha) * self._ewma

        # Update variance estimate
        diff = value - prev_ewma
        self._ewma_var = (1 - self.alpha) * (self._ewma_var + self.alpha * diff * diff)

        # Calculate anomaly score
        std = math.sqrt(self._ewma_var) if self._ewma_var > 0 else 0
        threshold = self.sensitivity * std

        if threshold <= 0:
            return 0.0

        return abs(diff) / threshold

    def reset(self) -> None:
        """Reset detector state."""
        self._ewma = None
        self._ewma_var = 0.0


# ── TimescaleDB Store ──────────────────────────────────────────────────


class TimescaleTemporalStore(TemporalStore):
    """
    TimescaleDB-backed temporal store for production deployments.

    Features beyond SQLite:
    - Hypertable with automatic partitioning by time
    - Continuous aggregates for instant hourly/daily rollups
    - 90-day retention with transparent compression
    - EWMA-based anomaly detection
    - Proactive regression alerts
    - Time-bucketed queries for rich visualizations

    Falls back to plain PostgreSQL if TimescaleDB extension unavailable.
    """

    def __init__(
        self,
        dsn: str = "postgresql://localhost/querysense",
        pool_size: int = 5,
    ) -> None:
        self.dsn = dsn
        self.pool_size = pool_size
        self._pool: Any = None
        self._has_timescale: bool = False
        self._ewma_detectors: dict[str, EWMADetector] = {}

    async def initialize(self) -> None:
        """Initialize connection pool and create schema."""
        try:
            import asyncpg
        except ImportError:
            raise ImportError(
                "asyncpg required for TimescaleDB store: "
                "pip install asyncpg"
            )

        self._pool = await asyncpg.create_pool(
            self.dsn,
            min_size=1,
            max_size=self.pool_size,
        )

        # Check for TimescaleDB
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')"
            )
            self._has_timescale = bool(row and row[0])

            if self._has_timescale:
                logger.info("TimescaleDB detected — using hypertables and continuous aggregates")
                await conn.execute(_TIMESCALE_SCHEMA)
            else:
                logger.info("TimescaleDB not found — using plain PostgreSQL schema")
                await conn.execute(_PLAIN_PG_SCHEMA)

    async def close(self) -> None:
        """Close connection pool."""
        if self._pool:
            await self._pool.close()

    # ── TemporalStore interface (sync wrappers) ───────────────────────

    def store(self, snapshot: PlanSnapshot) -> None:
        """Sync wrapper — prefer store_async in async contexts."""
        import asyncio

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.store_async(snapshot))
        except RuntimeError:
            asyncio.run(self.store_async(snapshot))

    def query(
        self,
        query_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 1000,
    ) -> list[PlanSnapshot]:
        """Sync wrapper — prefer query_async in async contexts."""
        import asyncio
        return asyncio.run(self.query_async(query_id, since, until, limit))

    def latest(self, query_id: str) -> PlanSnapshot | None:
        """Sync wrapper."""
        import asyncio
        return asyncio.run(self.latest_async(query_id))

    def all_query_ids(self) -> list[str]:
        """Sync wrapper."""
        import asyncio
        return asyncio.run(self.all_query_ids_async())

    # ── Async implementations ─────────────────────────────────────────

    async def store_async(self, snapshot: PlanSnapshot) -> None:
        """Store a plan snapshot with anomaly detection."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO plan_snapshots
                   (time, query_id, structure_hash,
                    latency_p50_ms, latency_p95_ms, rows_processed,
                    cost_total, node_count, plan_features, metadata)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb)""",
                snapshot.timestamp,
                snapshot.query_id,
                snapshot.structure_hash,
                snapshot.latency_p50_ms,
                snapshot.latency_p95_ms,
                snapshot.rows_processed,
                snapshot.cost_total,
                snapshot.node_count,
                json.dumps(snapshot.plan_features),
                json.dumps(snapshot.metadata),
            )

        # Run anomaly detection on the new data point
        if snapshot.cost_total is not None:
            detector = self._get_detector(snapshot.query_id, "cost")
            score = detector.update(snapshot.cost_total)
            if score > 1.0:
                await self._create_alert(
                    query_id=snapshot.query_id,
                    alert_type="anomaly",
                    severity="warning" if score < 2.0 else "critical",
                    current_value=snapshot.cost_total,
                    baseline_value=detector._ewma or 0,
                    change_pct=((snapshot.cost_total - (detector._ewma or 0)) / max(detector._ewma or 1, 1)) * 100,
                    details={"anomaly_score": round(score, 3), "metric": "cost_total"},
                )

        if snapshot.latency_p50_ms is not None:
            detector = self._get_detector(snapshot.query_id, "latency")
            score = detector.update(snapshot.latency_p50_ms)
            if score > 1.0:
                await self._create_alert(
                    query_id=snapshot.query_id,
                    alert_type="latency_spike",
                    severity="warning" if score < 2.0 else "critical",
                    current_value=snapshot.latency_p50_ms,
                    baseline_value=detector._ewma or 0,
                    change_pct=((snapshot.latency_p50_ms - (detector._ewma or 0)) / max(detector._ewma or 1, 1)) * 100,
                    details={"anomaly_score": round(score, 3), "metric": "latency_p50_ms"},
                )

    async def query_async(
        self,
        query_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 1000,
    ) -> list[PlanSnapshot]:
        """Retrieve snapshots for a query ordered by time."""
        conditions = ["query_id = $1"]
        params: list[Any] = [query_id]
        idx = 2

        if since:
            conditions.append(f"time >= ${idx}")
            params.append(since)
            idx += 1
        if until:
            conditions.append(f"time <= ${idx}")
            params.append(until)
            idx += 1

        where = " AND ".join(conditions)
        sql = f"""
            SELECT time, query_id, structure_hash,
                   latency_p50_ms, latency_p95_ms, rows_processed,
                   cost_total, node_count, plan_features, metadata
            FROM plan_snapshots
            WHERE {where}
            ORDER BY time ASC
            LIMIT ${idx}
        """
        params.append(limit)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)

        return [self._row_to_snapshot(row) for row in rows]

    async def latest_async(self, query_id: str) -> PlanSnapshot | None:
        """Get the most recent snapshot for a query."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT time, query_id, structure_hash,
                          latency_p50_ms, latency_p95_ms, rows_processed,
                          cost_total, node_count, plan_features, metadata
                   FROM plan_snapshots
                   WHERE query_id = $1
                   ORDER BY time DESC
                   LIMIT 1""",
                query_id,
            )
        return self._row_to_snapshot(row) if row else None

    async def all_query_ids_async(self) -> list[str]:
        """List all unique query IDs."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT DISTINCT query_id FROM plan_snapshots ORDER BY query_id"
            )
        return [row["query_id"] for row in rows]

    # ── Advanced time-series queries ──────────────────────────────────

    async def time_series(
        self,
        query_id: str,
        bucket: str = "1 hour",
        days: int = 30,
        metric: str = "latency_p50_ms",
    ) -> list[TimeSeriesBucket]:
        """
        Get time-bucketed data for rich visualization.

        Uses continuous aggregates when available for instant results.

        Args:
            query_id: Query identifier
            bucket: Time bucket size ('1 hour', '1 day', '15 minutes')
            days: How many days of history
            metric: Primary metric to analyze

        Returns:
            List of TimeSeriesBucket with anomaly scores
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)

        # Use continuous aggregate if available and bucket matches
        if self._has_timescale and bucket == "1 hour":
            sql = """
                SELECT bucket, query_id,
                       avg_latency_p50, avg_latency_p95, max_latency_p95,
                       avg_cost, max_cost, avg_rows, sample_count,
                       stddev_latency, stddev_cost
                FROM plan_snapshots_hourly
                WHERE query_id = $1 AND bucket >= $2
                ORDER BY bucket ASC
            """
        elif self._has_timescale and bucket == "1 day":
            sql = """
                SELECT bucket, query_id,
                       avg_latency_p50, avg_latency_p95,
                       NULL AS max_latency_p95,
                       avg_cost, max_cost, avg_rows, sample_count,
                       stddev_latency, stddev_cost
                FROM plan_snapshots_daily
                WHERE query_id = $1 AND bucket >= $2
                ORDER BY bucket ASC
            """
        elif self._has_timescale:
            sql = f"""
                SELECT time_bucket('{bucket}', time) AS bucket,
                       query_id,
                       AVG(latency_p50_ms) AS avg_latency_p50,
                       AVG(latency_p95_ms) AS avg_latency_p95,
                       MAX(latency_p95_ms) AS max_latency_p95,
                       AVG(cost_total) AS avg_cost,
                       MAX(cost_total) AS max_cost,
                       AVG(rows_processed) AS avg_rows,
                       COUNT(*) AS sample_count,
                       STDDEV(latency_p50_ms) AS stddev_latency,
                       STDDEV(cost_total) AS stddev_cost
                FROM plan_snapshots
                WHERE query_id = $1 AND time >= $2
                GROUP BY bucket, query_id
                ORDER BY bucket ASC
            """
        else:
            # Plain PostgreSQL fallback: truncate to hour or day
            trunc_unit = "hour" if "hour" in bucket or "min" in bucket else "day"
            sql = f"""
                SELECT date_trunc('{trunc_unit}', time) AS bucket,
                       query_id,
                       AVG(latency_p50_ms) AS avg_latency_p50,
                       AVG(latency_p95_ms) AS avg_latency_p95,
                       MAX(latency_p95_ms) AS max_latency_p95,
                       AVG(cost_total) AS avg_cost,
                       MAX(cost_total) AS max_cost,
                       AVG(rows_processed) AS avg_rows,
                       COUNT(*) AS sample_count,
                       STDDEV(latency_p50_ms) AS stddev_latency,
                       STDDEV(cost_total) AS stddev_cost
                FROM plan_snapshots
                WHERE query_id = $1 AND time >= $2
                GROUP BY bucket, query_id
                ORDER BY bucket ASC
            """

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, query_id, since)

        # Build buckets with anomaly detection
        detector = EWMADetector(alpha=0.2, sensitivity=2.5)
        buckets: list[TimeSeriesBucket] = []

        for row in rows:
            # Calculate anomaly score on the primary metric
            value = float(row["avg_cost"] or 0) if metric == "cost" else float(row["avg_latency_p50"] or 0)
            anomaly_score = detector.update(value) if value > 0 else 0.0

            buckets.append(TimeSeriesBucket(
                bucket=row["bucket"],
                query_id=row["query_id"],
                avg_latency_p50=_safe_float(row["avg_latency_p50"]),
                avg_latency_p95=_safe_float(row["avg_latency_p95"]),
                max_latency_p95=_safe_float(row.get("max_latency_p95")),
                avg_cost=_safe_float(row["avg_cost"]),
                max_cost=_safe_float(row["max_cost"]),
                avg_rows=_safe_float(row["avg_rows"]),
                sample_count=int(row["sample_count"]),
                stddev_latency=_safe_float(row.get("stddev_latency")),
                stddev_cost=_safe_float(row.get("stddev_cost")),
                anomaly_score=anomaly_score,
            ))

        return buckets

    async def trend_summary(
        self,
        query_id: str,
        days: int = 30,
    ) -> TrendSummary:
        """
        Compute comprehensive trend summary for a query.

        Includes trend direction, anomaly count, and plan change detection.
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)

        async with self._pool.acquire() as conn:
            # Aggregate statistics
            stats = await conn.fetchrow(
                """SELECT COUNT(*) AS cnt,
                          AVG(latency_p50_ms) AS avg_lat,
                          PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_p50_ms) AS p95_lat,
                          PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_p50_ms) AS p99_lat,
                          AVG(cost_total) AS avg_cost,
                          MAX(time) AS last_seen,
                          COUNT(DISTINCT structure_hash) AS plan_changes
                   FROM plan_snapshots
                   WHERE query_id = $1 AND time >= $2""",
                query_id,
                since,
            )

            # Trend direction: compare first half vs second half
            midpoint = since + timedelta(days=days / 2)
            first_half = await conn.fetchrow(
                """SELECT AVG(cost_total) AS avg_cost, AVG(latency_p50_ms) AS avg_lat
                   FROM plan_snapshots
                   WHERE query_id = $1 AND time >= $2 AND time < $3""",
                query_id, since, midpoint,
            )
            second_half = await conn.fetchrow(
                """SELECT AVG(cost_total) AS avg_cost, AVG(latency_p50_ms) AS avg_lat
                   FROM plan_snapshots
                   WHERE query_id = $1 AND time >= $2""",
                query_id, midpoint,
            )

            # Count anomalies
            anomaly_count = await conn.fetchval(
                """SELECT COUNT(*) FROM regression_alerts
                   WHERE query_id = $1 AND detected_at >= $2
                   AND alert_type = 'anomaly'""",
                query_id, since,
            )

            # Count regressions
            regression_count = await conn.fetchval(
                """SELECT COUNT(*) FROM regression_alerts
                   WHERE query_id = $1 AND detected_at >= $2
                   AND alert_type IN ('cost_regression', 'latency_spike')""",
                query_id, since,
            )

        # Compute trend direction
        trend_direction = "stable"
        trend_pct = 0.0
        if first_half and second_half and first_half["avg_cost"] and second_half["avg_cost"]:
            baseline = float(first_half["avg_cost"])
            current = float(second_half["avg_cost"])
            if baseline > 0:
                trend_pct = ((current - baseline) / baseline) * 100
                if trend_pct < -5:
                    trend_direction = "improving"
                elif trend_pct > 5:
                    trend_direction = "degrading"

        return TrendSummary(
            query_id=query_id,
            total_samples=int(stats["cnt"] or 0),
            time_range_days=days,
            avg_latency_ms=_safe_float(stats["avg_lat"]),
            p95_latency_ms=_safe_float(stats["p95_lat"]),
            p99_latency_ms=_safe_float(stats["p99_lat"]),
            avg_cost=_safe_float(stats["avg_cost"]),
            trend_direction=trend_direction,
            trend_pct=trend_pct,
            anomaly_count=int(anomaly_count or 0),
            regression_count=int(regression_count or 0),
            plan_changes=int(stats["plan_changes"] or 0) - 1,  # -1 for initial plan
            last_seen=stats["last_seen"],
        )

    # ── Regression alerts ─────────────────────────────────────────────

    async def regression_alerts(
        self,
        threshold_pct: float = 15.0,
        lookback_days: int = 7,
    ) -> list[RegressionAlert]:
        """
        Detect cost/latency regressions across all tracked queries.

        Compares the most recent hour against the baseline (7-day average).
        Returns alerts for queries that exceed the threshold.
        """
        since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

        async with self._pool.acquire() as conn:
            # Get queries with recent data
            rows = await conn.fetch(
                """WITH baseline AS (
                       SELECT query_id,
                              AVG(cost_total) AS avg_cost,
                              AVG(latency_p50_ms) AS avg_latency
                       FROM plan_snapshots
                       WHERE time >= $1 AND time < $2
                       GROUP BY query_id
                   ),
                   recent AS (
                       SELECT query_id,
                              AVG(cost_total) AS avg_cost,
                              AVG(latency_p50_ms) AS avg_latency
                       FROM plan_snapshots
                       WHERE time >= $2
                       GROUP BY query_id
                   )
                   SELECT r.query_id,
                          r.avg_cost AS recent_cost,
                          b.avg_cost AS baseline_cost,
                          r.avg_latency AS recent_latency,
                          b.avg_latency AS baseline_latency
                   FROM recent r
                   JOIN baseline b ON r.query_id = b.query_id
                   WHERE b.avg_cost > 0 OR b.avg_latency > 0""",
                since, recent_cutoff,
            )

        alerts: list[RegressionAlert] = []
        now = datetime.now(timezone.utc)

        for row in rows:
            # Check cost regression
            if row["baseline_cost"] and row["recent_cost"]:
                pct = ((float(row["recent_cost"]) - float(row["baseline_cost"])) / float(row["baseline_cost"])) * 100
                if pct > threshold_pct:
                    severity = "critical" if pct > threshold_pct * 2 else "warning"
                    alert = RegressionAlert(
                        query_id=row["query_id"],
                        detected_at=now,
                        alert_type="cost_regression",
                        severity=severity,
                        current_value=float(row["recent_cost"]),
                        baseline_value=float(row["baseline_cost"]),
                        change_pct=pct,
                        details={"lookback_days": lookback_days, "metric": "cost_total"},
                    )
                    alerts.append(alert)
                    await self._create_alert_from_obj(alert)

            # Check latency regression
            if row["baseline_latency"] and row["recent_latency"]:
                pct = ((float(row["recent_latency"]) - float(row["baseline_latency"])) / float(row["baseline_latency"])) * 100
                if pct > threshold_pct:
                    severity = "critical" if pct > threshold_pct * 2 else "warning"
                    alert = RegressionAlert(
                        query_id=row["query_id"],
                        detected_at=now,
                        alert_type="latency_spike",
                        severity=severity,
                        current_value=float(row["recent_latency"]),
                        baseline_value=float(row["baseline_latency"]),
                        change_pct=pct,
                        details={"lookback_days": lookback_days, "metric": "latency_p50_ms"},
                    )
                    alerts.append(alert)
                    await self._create_alert_from_obj(alert)

        return sorted(alerts, key=lambda a: abs(a.change_pct), reverse=True)

    async def get_alerts(
        self,
        query_id: str | None = None,
        unacknowledged_only: bool = True,
        limit: int = 50,
    ) -> list[RegressionAlert]:
        """Get regression alerts, optionally filtered by query."""
        conditions = []
        params: list[Any] = []
        idx = 1

        if query_id:
            conditions.append(f"query_id = ${idx}")
            params.append(query_id)
            idx += 1

        if unacknowledged_only:
            conditions.append("acknowledged = FALSE")

        where = " AND ".join(conditions) if conditions else "TRUE"

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT query_id, detected_at, alert_type, severity,
                           current_value, baseline_value, change_pct, details
                    FROM regression_alerts
                    WHERE {where}
                    ORDER BY detected_at DESC
                    LIMIT ${idx}""",
                *params, limit,
            )

        return [
            RegressionAlert(
                query_id=row["query_id"],
                detected_at=row["detected_at"],
                alert_type=row["alert_type"],
                severity=row["severity"],
                current_value=float(row["current_value"] or 0),
                baseline_value=float(row["baseline_value"] or 0),
                change_pct=float(row["change_pct"] or 0),
                details=json.loads(row["details"]) if isinstance(row["details"], str) else (row["details"] or {}),
            )
            for row in rows
        ]

    async def acknowledge_alert(self, alert_id: int) -> None:
        """Mark an alert as acknowledged."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE regression_alerts SET acknowledged = TRUE WHERE id = $1",
                alert_id,
            )

    # ── Plan change detection ─────────────────────────────────────────

    async def detect_plan_changes(
        self,
        query_id: str,
        days: int = 7,
    ) -> list[dict[str, Any]]:
        """
        Detect when a query's execution plan structure changed.

        Plan changes often cause performance regressions — this surfaces
        the exact moments when plans changed.
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT time, structure_hash, cost_total, latency_p50_ms,
                          plan_features
                   FROM plan_snapshots
                   WHERE query_id = $1 AND time >= $2
                   ORDER BY time ASC""",
                query_id, since,
            )

        changes: list[dict[str, Any]] = []
        prev_hash: str | None = None

        for row in rows:
            current_hash = row["structure_hash"]
            if prev_hash is not None and current_hash != prev_hash:
                changes.append({
                    "time": row["time"].isoformat(),
                    "old_hash": prev_hash,
                    "new_hash": current_hash,
                    "cost_after": float(row["cost_total"] or 0),
                    "latency_after": float(row["latency_p50_ms"] or 0),
                    "features": json.loads(row["plan_features"]) if isinstance(row["plan_features"], str) else (row["plan_features"] or {}),
                })
            prev_hash = current_hash

        # Create alerts for plan changes with cost increases
        if len(changes) > 0:
            for change in changes:
                await self._create_alert(
                    query_id=query_id,
                    alert_type="plan_change",
                    severity="info",
                    current_value=change["cost_after"],
                    baseline_value=0,
                    change_pct=0,
                    details={"old_hash": change["old_hash"], "new_hash": change["new_hash"]},
                )

        return changes

    # ── Helpers ────────────────────────────────────────────────────────

    def _get_detector(self, query_id: str, metric: str) -> EWMADetector:
        """Get or create an EWMA detector for a query+metric pair."""
        key = f"{query_id}:{metric}"
        if key not in self._ewma_detectors:
            self._ewma_detectors[key] = EWMADetector()
        return self._ewma_detectors[key]

    async def _create_alert(
        self,
        query_id: str,
        alert_type: str,
        severity: str,
        current_value: float,
        baseline_value: float,
        change_pct: float,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Create a regression alert in the database."""
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO regression_alerts
                       (query_id, alert_type, severity, current_value,
                        baseline_value, change_pct, details)
                       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)""",
                    query_id, alert_type, severity,
                    current_value, baseline_value, change_pct,
                    json.dumps(details or {}),
                )
        except Exception as e:
            logger.warning("Failed to create alert: %s", e)

    async def _create_alert_from_obj(self, alert: RegressionAlert) -> None:
        """Create an alert from a RegressionAlert object."""
        await self._create_alert(
            query_id=alert.query_id,
            alert_type=alert.alert_type,
            severity=alert.severity,
            current_value=alert.current_value,
            baseline_value=alert.baseline_value,
            change_pct=alert.change_pct,
            details=alert.details,
        )

    @staticmethod
    def _row_to_snapshot(row: Any) -> PlanSnapshot:
        """Convert a database row to a PlanSnapshot."""
        features = row["plan_features"]
        if isinstance(features, str):
            features = json.loads(features)
        meta = row["metadata"]
        if isinstance(meta, str):
            meta = json.loads(meta)

        return PlanSnapshot(
            query_id=row["query_id"],
            timestamp=row["time"],
            structure_hash=row["structure_hash"],
            latency_p50_ms=_safe_float(row.get("latency_p50_ms")),
            latency_p95_ms=_safe_float(row.get("latency_p95_ms")),
            rows_processed=_safe_float(row.get("rows_processed")),
            cost_total=_safe_float(row.get("cost_total")),
            node_count=int(row.get("node_count") or 0),
            plan_features=features or {},
            metadata=meta or {},
        )


def _safe_float(val: Any) -> float | None:
    """Safely convert a value to float, returning None for invalid values."""
    if val is None:
        return None
    try:
        result = float(val)
        return result if not math.isnan(result) and not math.isinf(result) else None
    except (TypeError, ValueError):
        return None
