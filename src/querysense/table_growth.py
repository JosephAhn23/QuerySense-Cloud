"""
Table Growth Tracker — monitor size trends and predict capacity needs.

Closes the pganalyze gap: "Table growth trends — size over time, bloat estimates."

Stores snapshots in local SQLite and provides:
1. Size over time (MB/GB per table, daily/weekly)
2. Growth rate calculation (MB/day, rows/day)
3. Capacity projection (when will disk run out?)
4. Bloat trend tracking (bloat ratio over time)
5. Anomaly detection (sudden size changes after deployments)

All data stored locally — no cloud, no egress.

Usage:
    from querysense.table_growth import TableGrowthTracker

    tracker = TableGrowthTracker(db_path="~/.querysense/growth.db")
    tracker.record_snapshot(snapshot_data)
    trends = tracker.get_trends("orders", days=30)
    projection = tracker.project_growth("orders", days=90)
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TableSnapshot:
    """A point-in-time snapshot of a table's size and health."""

    schema: str
    table: str
    timestamp: str  # ISO 8601
    total_size_bytes: int
    table_size_bytes: int
    index_size_bytes: int
    toast_size_bytes: int
    n_live_tup: int
    n_dead_tup: int
    bloat_ratio: float  # dead / (live + dead)
    seq_scan_count: int = 0
    idx_scan_count: int = 0


@dataclass(frozen=True)
class GrowthTrend:
    """Growth trend for a single table over a time period."""

    schema: str
    table: str
    period_days: int
    snapshots: int

    # Size metrics
    start_size_mb: float
    current_size_mb: float
    size_change_mb: float
    growth_rate_mb_per_day: float

    # Row metrics
    start_rows: int
    current_rows: int
    row_change: int
    growth_rate_rows_per_day: float

    # Bloat metrics
    current_bloat_ratio: float
    avg_bloat_ratio: float
    bloat_trend: str  # "increasing", "decreasing", "stable"

    @property
    def growth_pct(self) -> float:
        if self.start_size_mb <= 0:
            return 0
        return (self.size_change_mb / self.start_size_mb) * 100


@dataclass(frozen=True)
class GrowthProjection:
    """Future growth projection for capacity planning."""

    schema: str
    table: str
    current_size_mb: float
    projected_size_mb_30d: float
    projected_size_mb_90d: float
    projected_size_mb_365d: float
    growth_rate_mb_per_day: float
    days_until_1gb: int | None  # None if already >1GB or negative growth
    days_until_10gb: int | None
    days_until_100gb: int | None
    warning: str | None = None


@dataclass
class GrowthReport:
    """Complete growth tracking report."""

    trends: list[GrowthTrend] = field(default_factory=list)
    projections: list[GrowthProjection] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    total_database_size_mb: float = 0

    def summary(self) -> str:
        growing = [t for t in self.trends if t.growth_rate_mb_per_day > 0]
        return (
            f"{len(self.trends)} tables tracked | "
            f"{len(growing)} growing | "
            f"Total: {self.total_database_size_mb:.0f}MB | "
            f"{len(self.anomalies)} anomalies"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "total_db_size_mb": round(self.total_database_size_mb, 1),
            "trends": [
                {
                    "table": f"{t.schema}.{t.table}",
                    "period_days": t.period_days,
                    "current_size_mb": round(t.current_size_mb, 1),
                    "growth_rate_mb_day": round(t.growth_rate_mb_per_day, 2),
                    "growth_pct": round(t.growth_pct, 1),
                    "current_rows": t.current_rows,
                    "bloat_ratio": round(t.current_bloat_ratio, 3),
                    "bloat_trend": t.bloat_trend,
                }
                for t in self.trends
            ],
            "projections": [
                {
                    "table": f"{p.schema}.{p.table}",
                    "current_mb": round(p.current_size_mb, 1),
                    "30d_mb": round(p.projected_size_mb_30d, 1),
                    "90d_mb": round(p.projected_size_mb_90d, 1),
                    "365d_mb": round(p.projected_size_mb_365d, 1),
                    "warning": p.warning,
                }
                for p in self.projections
            ],
            "anomalies": self.anomalies,
        }


# ── Catalog query for snapshots ──────────────────────────────────────

SNAPSHOT_QUERY = """
SELECT
    schemaname,
    relname AS tablename,
    pg_total_relation_size(relid) AS total_size_bytes,
    pg_relation_size(relid) AS table_size_bytes,
    pg_indexes_size(relid) AS index_size_bytes,
    COALESCE(pg_total_relation_size(reltoastrelid), 0) AS toast_size_bytes,
    n_live_tup,
    n_dead_tup,
    seq_scan,
    idx_scan
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
"""


class TableGrowthTracker:
    """Track table growth over time using local SQLite storage."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            db_path = Path.home() / ".querysense" / "growth.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database schema."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema_name TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_size_bytes INTEGER NOT NULL,
                    table_size_bytes INTEGER NOT NULL DEFAULT 0,
                    index_size_bytes INTEGER NOT NULL DEFAULT 0,
                    toast_size_bytes INTEGER NOT NULL DEFAULT 0,
                    n_live_tup INTEGER NOT NULL DEFAULT 0,
                    n_dead_tup INTEGER NOT NULL DEFAULT 0,
                    bloat_ratio REAL NOT NULL DEFAULT 0,
                    seq_scan_count INTEGER NOT NULL DEFAULT 0,
                    idx_scan_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_snapshots_table_time
                ON snapshots (schema_name, table_name, timestamp)
            """)

    def record_snapshot(self, data: list[dict[str, Any]]) -> int:
        """Record a set of table snapshots.

        Args:
            data: Results from SNAPSHOT_QUERY

        Returns:
            Number of snapshots recorded
        """
        now = datetime.now(timezone.utc).isoformat()
        count = 0

        with sqlite3.connect(str(self.db_path)) as conn:
            for row in data:
                schema = row.get("schemaname", "public")
                table = row.get("tablename", "")
                live = row.get("n_live_tup", 0)
                dead = row.get("n_dead_tup", 0)
                total = live + dead
                bloat = dead / total if total > 0 else 0

                conn.execute(
                    """INSERT INTO snapshots
                    (schema_name, table_name, timestamp, total_size_bytes,
                     table_size_bytes, index_size_bytes, toast_size_bytes,
                     n_live_tup, n_dead_tup, bloat_ratio, seq_scan_count, idx_scan_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        schema, table, now,
                        row.get("total_size_bytes", 0),
                        row.get("table_size_bytes", 0),
                        row.get("index_size_bytes", 0),
                        row.get("toast_size_bytes", 0),
                        live, dead, bloat,
                        row.get("seq_scan", 0),
                        row.get("idx_scan", 0),
                    ),
                )
                count += 1

        return count

    def get_trends(self, table: str | None = None, days: int = 30) -> list[GrowthTrend]:
        """Get growth trends for one or all tables.

        Args:
            table: Table name (or None for all tables)
            days: Number of days to analyze
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row

            if table:
                rows = conn.execute(
                    """SELECT * FROM snapshots
                    WHERE table_name = ? AND timestamp >= ?
                    ORDER BY timestamp""",
                    (table, cutoff),
                ).fetchall()
                tables = {table: rows}
            else:
                all_rows = conn.execute(
                    """SELECT * FROM snapshots
                    WHERE timestamp >= ?
                    ORDER BY schema_name, table_name, timestamp""",
                    (cutoff,),
                ).fetchall()
                tables: dict[str, list] = {}
                for row in all_rows:
                    key = row["table_name"]
                    tables.setdefault(key, []).append(row)

        trends = []
        for tbl, snapshots in tables.items():
            if len(snapshots) < 2:
                continue

            first = snapshots[0]
            last = snapshots[-1]

            # Time span
            try:
                t0 = datetime.fromisoformat(first["timestamp"].replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(last["timestamp"].replace("Z", "+00:00"))
                span_days = max((t1 - t0).total_seconds() / 86400, 1)
            except (ValueError, TypeError):
                span_days = days

            start_size_mb = first["total_size_bytes"] / (1024 * 1024)
            current_size_mb = last["total_size_bytes"] / (1024 * 1024)
            size_change = current_size_mb - start_size_mb

            start_rows = first["n_live_tup"]
            current_rows = last["n_live_tup"]
            row_change = current_rows - start_rows

            # Bloat trend
            bloat_values = [s["bloat_ratio"] for s in snapshots]
            avg_bloat = sum(bloat_values) / len(bloat_values) if bloat_values else 0
            if len(bloat_values) >= 3:
                first_half_avg = sum(bloat_values[:len(bloat_values)//2]) / (len(bloat_values)//2)
                second_half_avg = sum(bloat_values[len(bloat_values)//2:]) / (len(bloat_values) - len(bloat_values)//2)
                if second_half_avg > first_half_avg * 1.2:
                    bloat_trend = "increasing"
                elif second_half_avg < first_half_avg * 0.8:
                    bloat_trend = "decreasing"
                else:
                    bloat_trend = "stable"
            else:
                bloat_trend = "stable"

            trends.append(GrowthTrend(
                schema=last["schema_name"],
                table=tbl,
                period_days=days,
                snapshots=len(snapshots),
                start_size_mb=round(start_size_mb, 2),
                current_size_mb=round(current_size_mb, 2),
                size_change_mb=round(size_change, 2),
                growth_rate_mb_per_day=round(size_change / span_days, 3),
                start_rows=start_rows,
                current_rows=current_rows,
                row_change=row_change,
                growth_rate_rows_per_day=round(row_change / span_days, 1),
                current_bloat_ratio=round(last["bloat_ratio"], 4),
                avg_bloat_ratio=round(avg_bloat, 4),
                bloat_trend=bloat_trend,
            ))

        # Sort by growth rate (fastest growing first)
        trends.sort(key=lambda t: t.growth_rate_mb_per_day, reverse=True)
        return trends

    def project_growth(self, days: int = 90) -> list[GrowthProjection]:
        """Project future growth for all tracked tables."""
        trends = self.get_trends(days=30)  # Use last 30 days for projection
        projections = []

        for trend in trends:
            rate = trend.growth_rate_mb_per_day
            current = trend.current_size_mb

            proj_30d = current + rate * 30
            proj_90d = current + rate * 90
            proj_365d = current + rate * 365

            # Calculate days until milestones
            def _days_until(target_mb: float) -> int | None:
                if current >= target_mb:
                    return None
                if rate <= 0:
                    return None
                return int((target_mb - current) / rate)

            warning = None
            if rate > 10:  # >10MB/day
                warning = f"Fast growth: {rate:.1f}MB/day. Will reach {proj_90d:.0f}MB in 90 days."
            elif proj_365d > 100_000:  # >100GB in a year
                warning = f"Will exceed 100GB in ~{_days_until(100_000) or '?'} days."

            projections.append(GrowthProjection(
                schema=trend.schema,
                table=trend.table,
                current_size_mb=current,
                projected_size_mb_30d=round(proj_30d, 1),
                projected_size_mb_90d=round(proj_90d, 1),
                projected_size_mb_365d=round(proj_365d, 1),
                growth_rate_mb_per_day=rate,
                days_until_1gb=_days_until(1024),
                days_until_10gb=_days_until(10240),
                days_until_100gb=_days_until(102400),
                warning=warning,
            ))

        return projections

    def detect_anomalies(self, threshold_pct: float = 20) -> list[dict[str, Any]]:
        """Detect sudden size changes (possible deployment impact).

        Args:
            threshold_pct: Percentage change to consider anomalous (default 20%)
        """
        anomalies = []

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row

            # Get unique tables
            tables = conn.execute(
                "SELECT DISTINCT schema_name, table_name FROM snapshots"
            ).fetchall()

            for tbl in tables:
                snapshots = conn.execute(
                    """SELECT timestamp, total_size_bytes, n_live_tup, bloat_ratio
                    FROM snapshots
                    WHERE schema_name = ? AND table_name = ?
                    ORDER BY timestamp""",
                    (tbl["schema_name"], tbl["table_name"]),
                ).fetchall()

                for i in range(1, len(snapshots)):
                    prev = snapshots[i - 1]
                    curr = snapshots[i]

                    prev_size = prev["total_size_bytes"]
                    curr_size = curr["total_size_bytes"]

                    if prev_size <= 0:
                        continue

                    change_pct = ((curr_size - prev_size) / prev_size) * 100

                    if abs(change_pct) >= threshold_pct:
                        anomalies.append({
                            "table": f"{tbl['schema_name']}.{tbl['table_name']}",
                            "timestamp": curr["timestamp"],
                            "previous_size_mb": round(prev_size / 1024 / 1024, 1),
                            "current_size_mb": round(curr_size / 1024 / 1024, 1),
                            "change_pct": round(change_pct, 1),
                            "type": "growth_spike" if change_pct > 0 else "size_drop",
                            "suggestion": (
                                "Check recent migrations or bulk operations"
                                if change_pct > 0
                                else "Check for TRUNCATE, DELETE, or partition detach"
                            ),
                        })

        return anomalies

    def generate_report(self, days: int = 30) -> GrowthReport:
        """Generate a complete growth tracking report."""
        trends = self.get_trends(days=days)
        projections = self.project_growth(days=90)
        anomalies = self.detect_anomalies()

        total_size = sum(t.current_size_mb for t in trends)

        return GrowthReport(
            trends=trends,
            projections=projections,
            anomalies=anomalies,
            total_database_size_mb=total_size,
        )

    @staticmethod
    def get_catalog_query() -> str:
        """Return the catalog query for collecting snapshots."""
        return SNAPSHOT_QUERY
