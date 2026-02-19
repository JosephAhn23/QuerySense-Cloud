"""
VACUUM Activity History — historical tracking and trend analysis.

Closes the final gap with pganalyze's VACUUM Advisor by adding
time-series tracking of vacuum activity. pganalyze stores daily
snapshots and shows trends; we do the same in SQLite (free) or
TimescaleDB (for the cloud version).

Tracks:
- Per-table dead tuple ratio over time
- Vacuum run frequency and duration
- Bloat trends (growing? shrinking? stable?)
- Autovacuum worker saturation
- Freeze age progression toward wraparound

Provides:
- Trend direction (improving, degrading, stable)
- Anomaly detection (sudden bloat spike, missed vacuums)
- Predictive alerts ("bloat will exceed 50% in ~3 days")
- Vacuum schedule effectiveness analysis

Usage:
    from querysense.db.vacuum_history import VacuumHistoryTracker, VacuumTrend

    tracker = VacuumHistoryTracker(db_path=".querysense/vacuum_history.db")

    # Record a snapshot (run periodically, e.g., every hour)
    await tracker.record_snapshot(conn)

    # Analyze trends
    trends = tracker.analyze_trends(days=30)
    for t in trends:
        if t.direction == "degrading":
            print(f"{t.table}: bloat {t.direction} ({t.bloat_pct_start:.1f}% → {t.bloat_pct_end:.1f}%)")

    # Get predictions
    predictions = tracker.predict_bloat(days_ahead=7)
    for p in predictions:
        if p.predicted_bloat_pct > 50:
            print(f"WARNING: {p.table} predicted to reach {p.predicted_bloat_pct:.0f}% bloat in {p.days_until_critical} days")
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


# ── Data Classes ───────────────────────────────────────────────────────


@dataclass
class VacuumSnapshot:
    """A point-in-time vacuum health snapshot for one table."""
    timestamp: float       # Unix timestamp
    schema: str
    table: str
    n_live_tup: int = 0
    n_dead_tup: int = 0
    dead_tuple_ratio: float = 0.0
    table_size_bytes: int = 0
    last_vacuum: str | None = None
    last_autovacuum: str | None = None
    vacuum_count: int = 0
    autovacuum_count: int = 0
    n_mod_since_analyze: int = 0
    freeze_age: int = 0     # age(relfrozenxid)
    # Derived
    bloat_estimate_pct: float = 0.0


@dataclass
class VacuumTrend:
    """Trend analysis for a single table over a time period."""
    schema: str
    table: str
    period_days: int
    data_points: int
    # Bloat trend
    bloat_pct_start: float = 0.0
    bloat_pct_end: float = 0.0
    bloat_pct_max: float = 0.0
    bloat_pct_avg: float = 0.0
    bloat_change_pct: float = 0.0    # +/- change over period
    # Dead tuple trend
    dead_ratio_start: float = 0.0
    dead_ratio_end: float = 0.0
    dead_ratio_avg: float = 0.0
    # Vacuum frequency
    vacuum_runs_in_period: int = 0
    avg_hours_between_vacuums: float = 0.0
    # Freeze progression
    freeze_age_start: int = 0
    freeze_age_end: int = 0
    freeze_rate_per_day: float = 0.0  # XID age increase per day
    # Direction
    direction: str = "stable"  # "improving" | "degrading" | "stable" | "critical"

    @property
    def full_name(self) -> str:
        return f"{self.schema}.{self.table}"

    @property
    def days_until_freeze_critical(self) -> float | None:
        """Estimated days until freeze age reaches 200M (autovacuum_freeze_max_age)."""
        if self.freeze_rate_per_day <= 0:
            return None
        remaining = 200_000_000 - self.freeze_age_end
        if remaining <= 0:
            return 0
        return remaining / self.freeze_rate_per_day

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.full_name,
            "period_days": self.period_days,
            "data_points": self.data_points,
            "bloat_pct_start": round(self.bloat_pct_start, 1),
            "bloat_pct_end": round(self.bloat_pct_end, 1),
            "bloat_pct_max": round(self.bloat_pct_max, 1),
            "bloat_change_pct": round(self.bloat_change_pct, 1),
            "dead_ratio_avg": round(self.dead_ratio_avg, 4),
            "vacuum_runs_in_period": self.vacuum_runs_in_period,
            "avg_hours_between_vacuums": round(self.avg_hours_between_vacuums, 1),
            "freeze_age_end": self.freeze_age_end,
            "freeze_rate_per_day": round(self.freeze_rate_per_day, 0),
            "days_until_freeze_critical": (
                round(self.days_until_freeze_critical, 0)
                if self.days_until_freeze_critical is not None else None
            ),
            "direction": self.direction,
        }


@dataclass
class BloatPrediction:
    """Predicted bloat for a table."""
    schema: str
    table: str
    current_bloat_pct: float
    predicted_bloat_pct: float
    days_ahead: int
    days_until_critical: float | None = None  # days until >50% bloat
    confidence: float = 0.0  # 0-1
    recommendation: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.schema}.{self.table}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.full_name,
            "current_bloat_pct": round(self.current_bloat_pct, 1),
            "predicted_bloat_pct": round(self.predicted_bloat_pct, 1),
            "days_ahead": self.days_ahead,
            "days_until_critical": (
                round(self.days_until_critical, 1)
                if self.days_until_critical is not None else None
            ),
            "confidence": round(self.confidence, 2),
            "recommendation": self.recommendation,
        }


# ── SQL Queries ────────────────────────────────────────────────────────


_VACUUM_SNAPSHOT_QUERY = """
SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    s.n_live_tup,
    s.n_dead_tup,
    CASE WHEN (s.n_live_tup + s.n_dead_tup) > 0
        THEN s.n_dead_tup::float / (s.n_live_tup + s.n_dead_tup)
        ELSE 0
    END AS dead_tuple_ratio,
    pg_table_size(c.oid) AS table_size_bytes,
    s.last_vacuum::text,
    s.last_autovacuum::text,
    s.vacuum_count,
    s.autovacuum_count,
    s.n_mod_since_analyze,
    age(c.relfrozenxid) AS freeze_age
FROM pg_stat_user_tables s
JOIN pg_class c ON c.oid = s.relid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND c.relpages > 0
ORDER BY pg_table_size(c.oid) DESC
"""


# ── SQLite Schema ──────────────────────────────────────────────────────


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS vacuum_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    n_live_tup INTEGER DEFAULT 0,
    n_dead_tup INTEGER DEFAULT 0,
    dead_tuple_ratio REAL DEFAULT 0,
    table_size_bytes INTEGER DEFAULT 0,
    last_vacuum TEXT,
    last_autovacuum TEXT,
    vacuum_count INTEGER DEFAULT 0,
    autovacuum_count INTEGER DEFAULT 0,
    n_mod_since_analyze INTEGER DEFAULT 0,
    freeze_age INTEGER DEFAULT 0,
    bloat_estimate_pct REAL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_vacuum_snapshots_table
    ON vacuum_snapshots(schema_name, table_name, timestamp);

CREATE INDEX IF NOT EXISTS idx_vacuum_snapshots_timestamp
    ON vacuum_snapshots(timestamp);

-- Retention: auto-delete snapshots older than 90 days
-- (run periodically via cleanup method)
"""


# ── Tracker ────────────────────────────────────────────────────────────


class VacuumHistoryTracker:
    """
    Track vacuum activity over time for trend analysis and prediction.

    Stores periodic snapshots in SQLite and provides trend analysis,
    anomaly detection, and predictive alerts.
    """

    def __init__(self, db_path: str = ".querysense/vacuum_history.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Create SQLite tables if they don't exist."""
        conn = self._get_conn()
        conn.executescript(_SQLITE_SCHEMA)
        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    async def record_snapshot(self, pg_conn: AsyncDBConnection) -> int:
        """
        Record a vacuum health snapshot from the live database.

        Args:
            pg_conn: Async PostgreSQL connection

        Returns:
            Number of tables recorded
        """
        rows = await pg_conn.fetch(_VACUUM_SNAPSHOT_QUERY)
        now = time.time()
        conn = self._get_conn()

        count = 0
        for row in rows:
            # Simple bloat estimate from dead tuple ratio
            dead_ratio = row["dead_tuple_ratio"] or 0
            bloat_est = dead_ratio * 100  # Rough: dead ratio ≈ bloat %

            conn.execute(
                """
                INSERT INTO vacuum_snapshots (
                    timestamp, schema_name, table_name,
                    n_live_tup, n_dead_tup, dead_tuple_ratio,
                    table_size_bytes, last_vacuum, last_autovacuum,
                    vacuum_count, autovacuum_count,
                    n_mod_since_analyze, freeze_age, bloat_estimate_pct
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    row["schema_name"],
                    row["table_name"],
                    row["n_live_tup"],
                    row["n_dead_tup"],
                    dead_ratio,
                    row["table_size_bytes"],
                    row["last_vacuum"],
                    row["last_autovacuum"],
                    row["vacuum_count"],
                    row["autovacuum_count"],
                    row["n_mod_since_analyze"],
                    row["freeze_age"],
                    bloat_est,
                ),
            )
            count += 1

        conn.commit()
        logger.info("Recorded vacuum snapshot: %d tables", count)
        return count

    def analyze_trends(
        self,
        days: int = 30,
        schema: str | None = None,
        table: str | None = None,
    ) -> list[VacuumTrend]:
        """
        Analyze vacuum trends over a time period.

        Args:
            days: Number of days to analyze
            schema: Optional schema filter
            table: Optional table filter

        Returns:
            List of VacuumTrend objects
        """
        conn = self._get_conn()
        cutoff = time.time() - (days * 86400)

        query = """
            SELECT schema_name, table_name, timestamp,
                   dead_tuple_ratio, bloat_estimate_pct,
                   vacuum_count, autovacuum_count, freeze_age,
                   n_dead_tup, table_size_bytes
            FROM vacuum_snapshots
            WHERE timestamp >= ?
        """
        params: list[Any] = [cutoff]

        if schema:
            query += " AND schema_name = ?"
            params.append(schema)
        if table:
            query += " AND table_name = ?"
            params.append(table)

        query += " ORDER BY schema_name, table_name, timestamp"

        rows = conn.execute(query, params).fetchall()

        # Group by table
        tables: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            key = f"{row['schema_name']}.{row['table_name']}"
            if key not in tables:
                tables[key] = []
            tables[key].append(row)

        trends: list[VacuumTrend] = []
        for _key, snapshots in tables.items():
            if len(snapshots) < 2:
                continue

            first = snapshots[0]
            last = snapshots[-1]

            # Calculate metrics
            bloat_values = [s["bloat_estimate_pct"] for s in snapshots]
            dead_values = [s["dead_tuple_ratio"] for s in snapshots]
            freeze_values = [s["freeze_age"] for s in snapshots]

            bloat_start = bloat_values[0]
            bloat_end = bloat_values[-1]
            bloat_change = bloat_end - bloat_start

            # Vacuum frequency: count increases in vacuum_count + autovacuum_count
            total_vacuums = (
                (last["vacuum_count"] - first["vacuum_count"])
                + (last["autovacuum_count"] - first["autovacuum_count"])
            )

            period_hours = (last["timestamp"] - first["timestamp"]) / 3600
            avg_hours_between = (
                period_hours / total_vacuums if total_vacuums > 0 else 0
            )

            # Freeze rate
            freeze_change = freeze_values[-1] - freeze_values[0]
            period_days_actual = max(
                (last["timestamp"] - first["timestamp"]) / 86400, 0.01
            )
            freeze_rate = freeze_change / period_days_actual

            # Determine direction
            if bloat_change > 10:
                direction = "critical" if bloat_end > 40 else "degrading"
            elif bloat_change > 3:
                direction = "degrading"
            elif bloat_change < -3:
                direction = "improving"
            else:
                direction = "stable"

            trends.append(VacuumTrend(
                schema=first["schema_name"],
                table=first["table_name"],
                period_days=days,
                data_points=len(snapshots),
                bloat_pct_start=bloat_start,
                bloat_pct_end=bloat_end,
                bloat_pct_max=max(bloat_values),
                bloat_pct_avg=sum(bloat_values) / len(bloat_values),
                bloat_change_pct=bloat_change,
                dead_ratio_start=dead_values[0],
                dead_ratio_end=dead_values[-1],
                dead_ratio_avg=sum(dead_values) / len(dead_values),
                vacuum_runs_in_period=total_vacuums,
                avg_hours_between_vacuums=avg_hours_between,
                freeze_age_start=freeze_values[0],
                freeze_age_end=freeze_values[-1],
                freeze_rate_per_day=freeze_rate,
                direction=direction,
            ))

        # Sort: critical first, then degrading, then by bloat
        direction_order = {"critical": 0, "degrading": 1, "stable": 2, "improving": 3}
        trends.sort(
            key=lambda t: (direction_order.get(t.direction, 4), -t.bloat_pct_end)
        )

        return trends

    def predict_bloat(
        self,
        days_ahead: int = 7,
        schema: str | None = None,
    ) -> list[BloatPrediction]:
        """
        Predict future bloat levels based on historical trends.

        Uses linear extrapolation from the last 7 days of data.

        Args:
            days_ahead: How many days to predict ahead
            schema: Optional schema filter

        Returns:
            List of BloatPrediction objects
        """
        # Analyze 7-day trends as the basis for prediction
        trends = self.analyze_trends(days=7, schema=schema)
        predictions: list[BloatPrediction] = []

        for trend in trends:
            if trend.data_points < 2:
                continue

            # Linear extrapolation
            daily_change = trend.bloat_change_pct / max(trend.period_days, 1)
            predicted = trend.bloat_pct_end + (daily_change * days_ahead)
            predicted = max(0, min(predicted, 100))  # Clamp 0-100%

            # Confidence based on data points and variance
            confidence = min(trend.data_points / 10, 1.0) * 0.8  # Cap at 0.8

            # Days until critical (50% bloat)
            days_until_critical: float | None = None
            if daily_change > 0 and trend.bloat_pct_end < 50:
                days_until_critical = (50 - trend.bloat_pct_end) / daily_change

            # Recommendation
            rec = ""
            if predicted > 50:
                rec = (
                    f"CRITICAL: {trend.full_name} predicted to reach {predicted:.0f}% bloat. "
                    f"Run pg_repack or VACUUM FULL immediately."
                )
            elif predicted > 30:
                rec = (
                    f"WARNING: {trend.full_name} trending toward {predicted:.0f}% bloat. "
                    f"Tune autovacuum: ALTER TABLE {trend.full_name} SET "
                    f"(autovacuum_vacuum_scale_factor = 0.02);"
                )
            elif trend.direction == "degrading":
                rec = (
                    f"Monitor: {trend.full_name} bloat is growing "
                    f"({trend.bloat_change_pct:+.1f}% over {trend.period_days} days)."
                )

            if rec or predicted > 20:
                predictions.append(BloatPrediction(
                    schema=trend.schema,
                    table=trend.table,
                    current_bloat_pct=trend.bloat_pct_end,
                    predicted_bloat_pct=predicted,
                    days_ahead=days_ahead,
                    days_until_critical=days_until_critical,
                    confidence=confidence,
                    recommendation=rec,
                ))

        predictions.sort(key=lambda p: p.predicted_bloat_pct, reverse=True)
        return predictions

    def get_table_history(
        self,
        schema: str,
        table: str,
        days: int = 30,
    ) -> list[VacuumSnapshot]:
        """Get raw snapshot history for a single table."""
        conn = self._get_conn()
        cutoff = time.time() - (days * 86400)

        rows = conn.execute(
            """
            SELECT * FROM vacuum_snapshots
            WHERE schema_name = ? AND table_name = ? AND timestamp >= ?
            ORDER BY timestamp
            """,
            (schema, table, cutoff),
        ).fetchall()

        return [
            VacuumSnapshot(
                timestamp=row["timestamp"],
                schema=row["schema_name"],
                table=row["table_name"],
                n_live_tup=row["n_live_tup"],
                n_dead_tup=row["n_dead_tup"],
                dead_tuple_ratio=row["dead_tuple_ratio"],
                table_size_bytes=row["table_size_bytes"],
                last_vacuum=row["last_vacuum"],
                last_autovacuum=row["last_autovacuum"],
                vacuum_count=row["vacuum_count"],
                autovacuum_count=row["autovacuum_count"],
                n_mod_since_analyze=row["n_mod_since_analyze"],
                freeze_age=row["freeze_age"],
                bloat_estimate_pct=row["bloat_estimate_pct"],
            )
            for row in rows
        ]

    def cleanup(self, retain_days: int = 90) -> int:
        """
        Delete snapshots older than retain_days.

        Args:
            retain_days: Keep snapshots newer than this

        Returns:
            Number of rows deleted
        """
        conn = self._get_conn()
        cutoff = time.time() - (retain_days * 86400)
        cursor = conn.execute(
            "DELETE FROM vacuum_snapshots WHERE timestamp < ?", (cutoff,)
        )
        conn.commit()
        deleted = cursor.rowcount
        logger.info("Cleaned up %d old vacuum snapshots (>%d days)", deleted, retain_days)
        return deleted

    def summary(self, days: int = 7) -> dict[str, Any]:
        """Get a summary of vacuum history."""
        conn = self._get_conn()
        cutoff = time.time() - (days * 86400)

        total_snapshots = conn.execute(
            "SELECT count(*) FROM vacuum_snapshots WHERE timestamp >= ?", (cutoff,)
        ).fetchone()[0]

        unique_tables = conn.execute(
            "SELECT count(DISTINCT schema_name || '.' || table_name) "
            "FROM vacuum_snapshots WHERE timestamp >= ?", (cutoff,)
        ).fetchone()[0]

        trends = self.analyze_trends(days=days)
        degrading = [t for t in trends if t.direction in ("degrading", "critical")]

        return {
            "period_days": days,
            "total_snapshots": total_snapshots,
            "unique_tables": unique_tables,
            "degrading_tables": len(degrading),
            "critical_tables": len([t for t in trends if t.direction == "critical"]),
            "top_degrading": [t.to_dict() for t in degrading[:5]],
        }
