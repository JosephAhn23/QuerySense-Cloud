"""
pg_stat_statements Time-Series Snapshotter.

Provides the "time series view" of pg_stat_statements that pganalyze gives
Atlassian and that Jon Erdman (Bitbucket Cloud DBA) described as essential:

    "Without a time series view, it's not that helpful. The only way for me
    to know which queries are the hottest at any given time is to reset it,
    let it run for a minute, then inspect it, and reset it again."

This module:
1. Periodically snapshots pg_stat_statements into a local SQLite database
2. Computes per-interval differentials (calls/sec, time/call, rows/call)
3. Provides time-series queries: "show me query X's performance over 24h"
4. Detects regressions automatically via rolling average comparison
5. Ranks queries by resource consumption within any time window

The key insight: pg_stat_statements is cumulative. To get per-interval rates,
you need the PREVIOUS snapshot. This module stores snapshots and computes
the deltas automatically.

Usage:
    from querysense.temporal.pgss_timeseries import (
        PGSSTimeSeriesStore,
        PGSSTimeSeriesConfig,
    )

    store = PGSSTimeSeriesStore(PGSSTimeSeriesConfig(db_path="pgss_history.db"))
    store.init()

    # Record a snapshot (call periodically, e.g., every 60s)
    store.record_snapshot(queries)

    # Query time-series data
    series = store.get_query_timeseries(fingerprint="abc123", hours=24)
    for point in series:
        print(f"{point.timestamp}: {point.calls_per_sec:.1f} calls/s, "
              f"{point.mean_time_ms:.2f} ms/call")

    # Top queries in a time window
    top = store.top_queries_in_window(hours=1, limit=20, sort_by="total_time")
    for q in top:
        print(f"{q.fingerprint}: {q.total_time_ms:.0f}ms total, {q.calls} calls")

    # Detect regressions
    regressions = store.detect_regressions(threshold_pct=50)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PGSSTimeSeriesConfig:
    """Configuration for the time-series store."""
    db_path: str = ".querysense/pgss_timeseries.db"
    retention_days: int = 30
    max_queries_per_snapshot: int = 1000


@dataclass
class PGSSDataPoint:
    """A single time-series data point for one query in one interval."""
    timestamp: float
    fingerprint: str
    queryid: int = 0
    query_text: str = ""
    interval_seconds: float = 0.0
    calls: int = 0
    calls_per_sec: float = 0.0
    total_time_ms: float = 0.0
    mean_time_ms: float = 0.0
    min_time_ms: float = 0.0
    max_time_ms: float = 0.0
    stddev_time_ms: float = 0.0
    rows: int = 0
    rows_per_call: float = 0.0
    shared_blks_hit: int = 0
    shared_blks_read: int = 0
    cache_hit_ratio: float = 1.0
    temp_blks_written: int = 0
    blk_read_time_ms: float = 0.0
    blk_write_time_ms: float = 0.0

    @property
    def datetime_utc(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.datetime_utc.isoformat(),
            "fingerprint": self.fingerprint,
            "query_text": self.query_text[:200],
            "calls": self.calls,
            "calls_per_sec": round(self.calls_per_sec, 2),
            "total_time_ms": round(self.total_time_ms, 2),
            "mean_time_ms": round(self.mean_time_ms, 3),
            "rows_per_call": round(self.rows_per_call, 1),
            "cache_hit_ratio": round(self.cache_hit_ratio, 4),
        }


@dataclass
class QueryWindowSummary:
    """Aggregated stats for a query over a time window."""
    fingerprint: str
    query_text: str = ""
    total_time_ms: float = 0.0
    total_calls: int = 0
    avg_mean_time_ms: float = 0.0
    max_mean_time_ms: float = 0.0
    avg_calls_per_sec: float = 0.0
    avg_cache_hit_ratio: float = 1.0
    data_points: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "query_text": self.query_text[:200],
            "total_time_ms": round(self.total_time_ms, 1),
            "total_calls": self.total_calls,
            "avg_mean_time_ms": round(self.avg_mean_time_ms, 3),
            "max_mean_time_ms": round(self.max_mean_time_ms, 3),
            "avg_calls_per_sec": round(self.avg_calls_per_sec, 2),
            "avg_cache_hit_ratio": round(self.avg_cache_hit_ratio, 4),
            "data_points": self.data_points,
        }


@dataclass
class QueryRegression:
    """A detected performance regression for a query."""
    fingerprint: str
    query_text: str = ""
    baseline_mean_ms: float = 0.0
    current_mean_ms: float = 0.0
    increase_pct: float = 0.0
    baseline_calls_per_sec: float = 0.0
    current_calls_per_sec: float = 0.0
    regression_type: str = "latency"

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "query_text": self.query_text[:200],
            "regression_type": self.regression_type,
            "baseline_mean_ms": round(self.baseline_mean_ms, 3),
            "current_mean_ms": round(self.current_mean_ms, 3),
            "increase_pct": round(self.increase_pct, 1),
        }


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS pgss_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    snapshot_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pgss_timeseries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    fingerprint TEXT NOT NULL,
    queryid INTEGER,
    query_text TEXT,
    interval_seconds REAL DEFAULT 0,
    delta_calls INTEGER DEFAULT 0,
    delta_total_time_ms REAL DEFAULT 0,
    delta_rows INTEGER DEFAULT 0,
    mean_time_ms REAL DEFAULT 0,
    min_time_ms REAL DEFAULT 0,
    max_time_ms REAL DEFAULT 0,
    stddev_time_ms REAL DEFAULT 0,
    calls_per_sec REAL DEFAULT 0,
    rows_per_call REAL DEFAULT 0,
    shared_blks_hit INTEGER DEFAULT 0,
    shared_blks_read INTEGER DEFAULT 0,
    cache_hit_ratio REAL DEFAULT 1.0,
    temp_blks_written INTEGER DEFAULT 0,
    blk_read_time_ms REAL DEFAULT 0,
    blk_write_time_ms REAL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pgss_ts_fingerprint
    ON pgss_timeseries(fingerprint, timestamp);

CREATE INDEX IF NOT EXISTS idx_pgss_ts_timestamp
    ON pgss_timeseries(timestamp);

CREATE TABLE IF NOT EXISTS pgss_latest (
    fingerprint TEXT PRIMARY KEY,
    queryid INTEGER,
    query_text TEXT,
    snapshot_timestamp REAL,
    cumulative_calls INTEGER,
    cumulative_total_time_ms REAL,
    cumulative_rows INTEGER,
    mean_time_ms REAL,
    min_time_ms REAL,
    max_time_ms REAL,
    stddev_time_ms REAL,
    shared_blks_hit INTEGER,
    shared_blks_read INTEGER,
    temp_blks_written INTEGER,
    blk_read_time_ms REAL,
    blk_write_time_ms REAL
);
"""


class PGSSTimeSeriesStore:
    """
    Time-series store for pg_stat_statements snapshots.

    Records periodic snapshots and computes per-interval differential
    metrics automatically. Provides queries for historical analysis.
    """

    def __init__(self, config: PGSSTimeSeriesConfig | None = None) -> None:
        self.config = config or PGSSTimeSeriesConfig()
        self._conn: sqlite3.Connection | None = None

    def init(self) -> None:
        """Initialize the database schema."""
        db_path = Path(self.config.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.init()
        assert self._conn is not None
        return self._conn

    def record_snapshot(
        self,
        queries: list[dict[str, Any]],
        timestamp: float | None = None,
    ) -> int:
        """
        Record a pg_stat_statements snapshot and compute deltas.

        Args:
            queries: List of dicts from pg_stat_statements, each with keys:
                     queryid, query, fingerprint, calls, total_exec_time_ms,
                     mean_exec_time_ms, rows, shared_blks_hit, shared_blks_read, etc.
            timestamp: Unix timestamp (defaults to now).

        Returns:
            Number of data points written.
        """
        ts = timestamp or time.time()
        conn = self.conn

        conn.execute(
            "INSERT INTO pgss_snapshots (timestamp, snapshot_json) VALUES (?, ?)",
            (ts, json.dumps({"query_count": len(queries), "timestamp": ts})),
        )

        prev_rows = conn.execute(
            "SELECT fingerprint, cumulative_calls, cumulative_total_time_ms, "
            "cumulative_rows, snapshot_timestamp, shared_blks_hit, shared_blks_read, "
            "temp_blks_written, blk_read_time_ms, blk_write_time_ms "
            "FROM pgss_latest"
        ).fetchall()
        prev_map = {r["fingerprint"]: dict(r) for r in prev_rows}

        data_points = 0

        for q in queries[:self.config.max_queries_per_snapshot]:
            fp = q.get("fingerprint", "")
            if not fp:
                continue

            cum_calls = q.get("calls", 0)
            cum_time = q.get("total_exec_time_ms", 0.0)
            cum_rows = q.get("rows", 0)
            hits = q.get("shared_blks_hit", 0)
            reads = q.get("shared_blks_read", 0)
            temp_w = q.get("temp_blks_written", 0)
            blk_r = q.get("blk_read_time_ms", 0.0)
            blk_w = q.get("blk_write_time_ms", 0.0)

            prev = prev_map.get(fp)

            if prev and prev["snapshot_timestamp"] and prev["snapshot_timestamp"] < ts:
                interval = ts - prev["snapshot_timestamp"]
                delta_calls = max(cum_calls - (prev["cumulative_calls"] or 0), 0)
                delta_time = max(cum_time - (prev["cumulative_total_time_ms"] or 0), 0.0)
                delta_rows = max(cum_rows - (prev["cumulative_rows"] or 0), 0)
                delta_hits = max(hits - (prev["shared_blks_hit"] or 0), 0)
                delta_reads = max(reads - (prev["shared_blks_read"] or 0), 0)

                calls_per_sec = delta_calls / interval if interval > 0 else 0.0
                mean_ms = delta_time / delta_calls if delta_calls > 0 else 0.0
                rows_per_call = delta_rows / delta_calls if delta_calls > 0 else 0.0
                total_blocks = delta_hits + delta_reads
                chr_ = delta_hits / total_blocks if total_blocks > 0 else 1.0

                if delta_calls > 0:
                    conn.execute(
                        "INSERT INTO pgss_timeseries "
                        "(timestamp, fingerprint, queryid, query_text, "
                        "interval_seconds, delta_calls, delta_total_time_ms, "
                        "delta_rows, mean_time_ms, min_time_ms, max_time_ms, "
                        "stddev_time_ms, calls_per_sec, rows_per_call, "
                        "shared_blks_hit, shared_blks_read, cache_hit_ratio, "
                        "temp_blks_written, blk_read_time_ms, blk_write_time_ms) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            ts, fp, q.get("queryid", 0),
                            (q.get("query", "") or "")[:2000],
                            interval, delta_calls, delta_time, delta_rows,
                            mean_ms,
                            q.get("min_exec_time_ms", 0.0),
                            q.get("max_exec_time_ms", 0.0),
                            q.get("stddev_exec_time_ms", 0.0),
                            calls_per_sec, rows_per_call,
                            delta_hits, delta_reads, chr_,
                            temp_w, blk_r, blk_w,
                        ),
                    )
                    data_points += 1

            conn.execute(
                "INSERT OR REPLACE INTO pgss_latest "
                "(fingerprint, queryid, query_text, snapshot_timestamp, "
                "cumulative_calls, cumulative_total_time_ms, cumulative_rows, "
                "mean_time_ms, min_time_ms, max_time_ms, stddev_time_ms, "
                "shared_blks_hit, shared_blks_read, temp_blks_written, "
                "blk_read_time_ms, blk_write_time_ms) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    fp, q.get("queryid", 0),
                    (q.get("query", "") or "")[:2000],
                    ts, cum_calls, cum_time, cum_rows,
                    q.get("mean_exec_time_ms", 0.0),
                    q.get("min_exec_time_ms", 0.0),
                    q.get("max_exec_time_ms", 0.0),
                    q.get("stddev_exec_time_ms", 0.0),
                    hits, reads, temp_w, blk_r, blk_w,
                ),
            )

        conn.commit()

        self._cleanup_old_data()

        return data_points

    def get_query_timeseries(
        self,
        fingerprint: str,
        hours: int = 24,
    ) -> list[PGSSDataPoint]:
        """
        Get time-series data for a specific query.

        Args:
            fingerprint: Query fingerprint.
            hours: Number of hours of history.

        Returns:
            List of data points ordered by timestamp.
        """
        cutoff = time.time() - (hours * 3600)
        rows = self.conn.execute(
            "SELECT * FROM pgss_timeseries "
            "WHERE fingerprint = ? AND timestamp >= ? "
            "ORDER BY timestamp ASC",
            (fingerprint, cutoff),
        ).fetchall()

        return [
            PGSSDataPoint(
                timestamp=r["timestamp"],
                fingerprint=r["fingerprint"],
                queryid=r["queryid"],
                query_text=r["query_text"] or "",
                interval_seconds=r["interval_seconds"],
                calls=r["delta_calls"],
                calls_per_sec=r["calls_per_sec"],
                total_time_ms=r["delta_total_time_ms"],
                mean_time_ms=r["mean_time_ms"],
                min_time_ms=r["min_time_ms"],
                max_time_ms=r["max_time_ms"],
                stddev_time_ms=r["stddev_time_ms"],
                rows=r["delta_rows"],
                rows_per_call=r["rows_per_call"],
                shared_blks_hit=r["shared_blks_hit"],
                shared_blks_read=r["shared_blks_read"],
                cache_hit_ratio=r["cache_hit_ratio"],
                temp_blks_written=r["temp_blks_written"],
                blk_read_time_ms=r["blk_read_time_ms"],
                blk_write_time_ms=r["blk_write_time_ms"],
            )
            for r in rows
        ]

    def top_queries_in_window(
        self,
        hours: int = 1,
        limit: int = 20,
        sort_by: str = "total_time",
    ) -> list[QueryWindowSummary]:
        """
        Rank queries by resource consumption within a time window.

        Args:
            hours: Time window in hours.
            limit: Maximum number of queries to return.
            sort_by: "total_time", "calls", "mean_time", or "cache_misses".
        """
        cutoff = time.time() - (hours * 3600)

        order_clause = {
            "total_time": "SUM(delta_total_time_ms) DESC",
            "calls": "SUM(delta_calls) DESC",
            "mean_time": "AVG(mean_time_ms) DESC",
            "cache_misses": "AVG(cache_hit_ratio) ASC",
        }.get(sort_by, "SUM(delta_total_time_ms) DESC")

        rows = self.conn.execute(
            f"SELECT fingerprint, "
            f"  MAX(query_text) AS query_text, "
            f"  SUM(delta_total_time_ms) AS total_time_ms, "
            f"  SUM(delta_calls) AS total_calls, "
            f"  AVG(mean_time_ms) AS avg_mean_time_ms, "
            f"  MAX(mean_time_ms) AS max_mean_time_ms, "
            f"  AVG(calls_per_sec) AS avg_calls_per_sec, "
            f"  AVG(cache_hit_ratio) AS avg_cache_hit_ratio, "
            f"  COUNT(*) AS data_points "
            f"FROM pgss_timeseries "
            f"WHERE timestamp >= ? "
            f"GROUP BY fingerprint "
            f"ORDER BY {order_clause} "
            f"LIMIT ?",
            (cutoff, limit),
        ).fetchall()

        return [
            QueryWindowSummary(
                fingerprint=r["fingerprint"],
                query_text=r["query_text"] or "",
                total_time_ms=r["total_time_ms"] or 0.0,
                total_calls=r["total_calls"] or 0,
                avg_mean_time_ms=r["avg_mean_time_ms"] or 0.0,
                max_mean_time_ms=r["max_mean_time_ms"] or 0.0,
                avg_calls_per_sec=r["avg_calls_per_sec"] or 0.0,
                avg_cache_hit_ratio=r["avg_cache_hit_ratio"] or 1.0,
                data_points=r["data_points"] or 0,
            )
            for r in rows
        ]

    def detect_regressions(
        self,
        threshold_pct: float = 50.0,
        baseline_hours: int = 24,
        recent_hours: int = 1,
    ) -> list[QueryRegression]:
        """
        Detect queries whose latency has increased significantly.

        Compares the recent window's average mean_time_ms to the
        longer-term baseline average.

        Args:
            threshold_pct: Minimum % increase to flag as regression.
            baseline_hours: Hours for the baseline period.
            recent_hours: Hours for the recent period.
        """
        now = time.time()
        baseline_start = now - (baseline_hours * 3600)
        recent_start = now - (recent_hours * 3600)

        baseline_rows = self.conn.execute(
            "SELECT fingerprint, "
            "  MAX(query_text) AS query_text, "
            "  AVG(mean_time_ms) AS avg_mean, "
            "  AVG(calls_per_sec) AS avg_cps "
            "FROM pgss_timeseries "
            "WHERE timestamp >= ? AND timestamp < ? "
            "GROUP BY fingerprint "
            "HAVING SUM(delta_calls) >= 10",
            (baseline_start, recent_start),
        ).fetchall()
        baseline_map = {r["fingerprint"]: dict(r) for r in baseline_rows}

        recent_rows = self.conn.execute(
            "SELECT fingerprint, "
            "  MAX(query_text) AS query_text, "
            "  AVG(mean_time_ms) AS avg_mean, "
            "  AVG(calls_per_sec) AS avg_cps "
            "FROM pgss_timeseries "
            "WHERE timestamp >= ? "
            "GROUP BY fingerprint "
            "HAVING SUM(delta_calls) >= 5",
            (recent_start,),
        ).fetchall()

        regressions: list[QueryRegression] = []
        for r in recent_rows:
            fp = r["fingerprint"]
            baseline = baseline_map.get(fp)
            if not baseline or not baseline["avg_mean"] or baseline["avg_mean"] <= 0:
                continue

            increase_pct = (
                (r["avg_mean"] - baseline["avg_mean"]) / baseline["avg_mean"] * 100
            )

            if increase_pct >= threshold_pct:
                regressions.append(QueryRegression(
                    fingerprint=fp,
                    query_text=r["query_text"] or "",
                    baseline_mean_ms=baseline["avg_mean"],
                    current_mean_ms=r["avg_mean"],
                    increase_pct=increase_pct,
                    baseline_calls_per_sec=baseline["avg_cps"] or 0.0,
                    current_calls_per_sec=r["avg_cps"] or 0.0,
                    regression_type="latency",
                ))

        return sorted(regressions, key=lambda r: -r.increase_pct)

    def get_snapshot_count(self) -> int:
        """Return the total number of snapshots recorded."""
        row = self.conn.execute("SELECT COUNT(*) AS cnt FROM pgss_snapshots").fetchone()
        return row["cnt"] if row else 0

    def get_unique_queries(self) -> int:
        """Return the number of unique query fingerprints tracked."""
        row = self.conn.execute(
            "SELECT COUNT(DISTINCT fingerprint) AS cnt FROM pgss_timeseries"
        ).fetchone()
        return row["cnt"] if row else 0

    def _cleanup_old_data(self) -> None:
        """Remove data older than retention period."""
        cutoff = time.time() - (self.config.retention_days * 86400)
        self.conn.execute("DELETE FROM pgss_timeseries WHERE timestamp < ?", (cutoff,))
        self.conn.execute("DELETE FROM pgss_snapshots WHERE timestamp < ?", (cutoff,))
        self.conn.commit()
