"""
SQLite-backed temporal store for local analysis history.

Enables `querysense track` and `querysense trends` without any cloud
infrastructure.  All data stays in a local SQLite file.

Features:
- Tracks every analysis run with timestamps
- Supports time-range queries for trend analysis
- Detects regressions by comparing against historical data
- Zero config: auto-creates DB on first use

Usage:
    from querysense.temporal.sqlite_store import SQLiteTemporalStore

    store = SQLiteTemporalStore("~/.querysense/history.db")
    store.store(snapshot)
    trends = store.trends("query_id", days=30)
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from querysense.temporal.store import PlanSnapshot, TemporalStore


_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    structure_hash TEXT NOT NULL,
    latency_p50_ms REAL,
    latency_p95_ms REAL,
    rows_processed REAL,
    cost_total REAL,
    node_count INTEGER DEFAULT 0,
    plan_features TEXT DEFAULT '{}',
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_snapshots_query_id
    ON snapshots(query_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp
    ON snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_snapshots_query_ts
    ON snapshots(query_id, timestamp);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL UNIQUE,
    file_path TEXT,
    query_id TEXT,
    timestamp TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    warning_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    evidence_level TEXT DEFAULT 'PLAN',
    node_count INTEGER DEFAULT 0,
    execution_time_ms REAL,
    findings_json TEXT DEFAULT '[]',
    summary_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_analyses_query_id
    ON analyses(query_id);
CREATE INDEX IF NOT EXISTS idx_analyses_timestamp
    ON analyses(timestamp);
CREATE INDEX IF NOT EXISTS idx_analyses_file_path
    ON analyses(file_path);
"""


class SQLiteTemporalStore(TemporalStore):
    """
    SQLite-backed implementation of TemporalStore.

    Stores plan snapshots and analysis results in a local SQLite database.
    Thread-safe via WAL mode and check_same_thread=False.
    """

    def __init__(self, db_path: str | Path = "~/.querysense/history.db") -> None:
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA_SQL)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a DB connection with WAL mode."""
        conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── TemporalStore interface ──────────────────────────────────────

    def store(self, snapshot: PlanSnapshot) -> None:
        """Store a new plan snapshot."""
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO snapshots
                   (query_id, timestamp, structure_hash,
                    latency_p50_ms, latency_p95_ms, rows_processed,
                    cost_total, node_count, plan_features, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    snapshot.query_id,
                    snapshot.timestamp.isoformat(),
                    snapshot.structure_hash,
                    snapshot.latency_p50_ms,
                    snapshot.latency_p95_ms,
                    snapshot.rows_processed,
                    snapshot.cost_total,
                    snapshot.node_count,
                    json.dumps(snapshot.plan_features),
                    json.dumps(snapshot.metadata),
                ),
            )

    def query(
        self,
        query_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 1000,
    ) -> list[PlanSnapshot]:
        """Retrieve snapshots for a query, ordered by timestamp."""
        sql = "SELECT * FROM snapshots WHERE query_id = ?"
        params: list[Any] = [query_id]

        if since:
            sql += " AND timestamp >= ?"
            params.append(since.isoformat())
        if until:
            sql += " AND timestamp <= ?"
            params.append(until.isoformat())

        sql += " ORDER BY timestamp ASC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [self._row_to_snapshot(row) for row in rows]

    def latest(self, query_id: str) -> PlanSnapshot | None:
        """Get the most recent snapshot for a query."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM snapshots WHERE query_id = ? "
                "ORDER BY timestamp DESC LIMIT 1",
                (query_id,),
            ).fetchone()

        return self._row_to_snapshot(row) if row else None

    def all_query_ids(self) -> list[str]:
        """List all unique query IDs."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT query_id FROM snapshots ORDER BY query_id"
            ).fetchall()
        return [row["query_id"] for row in rows]

    # ── Analysis tracking ────────────────────────────────────────────

    def store_analysis(
        self,
        analysis_id: str,
        file_path: str | None,
        query_id: str | None,
        result: Any,
    ) -> None:
        """
        Store an analysis result for history tracking.

        Args:
            analysis_id: Unique analysis ID from AnalysisResult
            file_path: Path to the EXPLAIN file
            query_id: Query identifier
            result: AnalysisResult object
        """
        summary = result.summary()
        findings_data = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "suggestion": f.suggestion,
                "impact_score": f.impact_score,
                "metrics": f.metrics,
            }
            for f in result.findings
        ]

        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO analyses
                   (analysis_id, file_path, query_id, timestamp,
                    total_findings, critical_count, warning_count, info_count,
                    evidence_level, node_count, execution_time_ms,
                    findings_json, summary_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    analysis_id,
                    file_path,
                    query_id,
                    datetime.now(timezone.utc).isoformat(),
                    summary["total"],
                    summary["critical"],
                    summary["warning"],
                    summary["info"],
                    summary["evidence_level"],
                    result.metadata.node_count,
                    result.metadata.execution_time_ms,
                    json.dumps(findings_data, default=str),
                    json.dumps(summary, default=str),
                ),
            )

    # ── Trend analysis ───────────────────────────────────────────────

    def trends(
        self,
        query_id: str | None = None,
        file_path: str | None = None,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """
        Get analysis trends over time.

        Args:
            query_id: Filter by query ID (optional)
            file_path: Filter by file path (optional)
            days: Number of days to look back

        Returns:
            List of analysis summary dicts ordered by timestamp
        """
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        sql = "SELECT * FROM analyses WHERE timestamp >= ?"
        params: list[Any] = [since]

        if query_id:
            sql += " AND query_id = ?"
            params.append(query_id)
        if file_path:
            sql += " AND file_path = ?"
            params.append(file_path)

        sql += " ORDER BY timestamp ASC"

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [
            {
                "analysis_id": row["analysis_id"],
                "timestamp": row["timestamp"],
                "file_path": row["file_path"],
                "query_id": row["query_id"],
                "total_findings": row["total_findings"],
                "critical_count": row["critical_count"],
                "warning_count": row["warning_count"],
                "info_count": row["info_count"],
                "evidence_level": row["evidence_level"],
                "node_count": row["node_count"],
                "execution_time_ms": row["execution_time_ms"],
            }
            for row in rows
        ]

    def regression_check(
        self,
        query_id: str,
        current_cost: float,
        threshold_pct: float = 20.0,
    ) -> dict[str, Any] | None:
        """
        Check if current cost represents a regression vs historical average.

        Args:
            query_id: Query identifier
            current_cost: Current total plan cost
            threshold_pct: Percentage increase that triggers regression

        Returns:
            Regression info dict if regression detected, None otherwise
        """
        snapshots = self.query(
            query_id,
            since=datetime.now(timezone.utc) - timedelta(days=7),
        )

        if not snapshots:
            return None

        costs = [s.cost_total for s in snapshots if s.cost_total is not None]
        if not costs:
            return None

        avg_cost = sum(costs) / len(costs)
        if avg_cost <= 0:
            return None

        pct_change = ((current_cost - avg_cost) / avg_cost) * 100

        if pct_change > threshold_pct:
            return {
                "query_id": query_id,
                "current_cost": current_cost,
                "avg_cost_7d": round(avg_cost, 1),
                "pct_change": round(pct_change, 1),
                "regression": True,
                "message": (
                    f"Cost increased {pct_change:.0f}% vs 7-day average "
                    f"({current_cost:,.0f} vs {avg_cost:,.0f})"
                ),
            }

        return None

    def summary_stats(self) -> dict[str, Any]:
        """Get overall history statistics."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            queries = conn.execute(
                "SELECT COUNT(DISTINCT query_id) FROM snapshots"
            ).fetchone()[0]

            recent = conn.execute(
                "SELECT COUNT(*) FROM analyses WHERE timestamp >= ?",
                ((datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),),
            ).fetchone()[0]

        return {
            "total_analyses": total,
            "unique_queries": queries,
            "analyses_last_7d": recent,
            "db_path": str(self.db_path),
        }

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> PlanSnapshot:
        """Convert a DB row to a PlanSnapshot."""
        return PlanSnapshot(
            query_id=row["query_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            structure_hash=row["structure_hash"],
            latency_p50_ms=row["latency_p50_ms"],
            latency_p95_ms=row["latency_p95_ms"],
            rows_processed=row["rows_processed"],
            cost_total=row["cost_total"],
            node_count=row["node_count"] or 0,
            plan_features=json.loads(row["plan_features"] or "{}"),
            metadata=json.loads(row["metadata"] or "{}"),
        )
