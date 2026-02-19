"""
Plan regression watch daemon for QuerySense.

Polls pg_stat_statements for query performance changes, detects plan
regressions, computes severity scores, and dispatches alerts.

Auto-detects the best available data source:
  pg_stat_monitor > pg_store_plans > pg_stat_statements (with EXPLAIN fallback)

Usage:
    from querysense.watch import WatchDaemon, WatchConfig

    config = WatchConfig(dsn="postgresql://localhost/mydb")
    daemon = WatchDaemon(config)
    await daemon.run()

CLI:
    querysense watch --dsn postgresql://localhost/mydb --interval 60
"""

from __future__ import annotations

import hashlib
import json
import logging
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Data Source Detection ──────────────────────────────────────────────


class DataSource(str, Enum):
    """Available plan tracking data sources, in priority order."""

    PG_STAT_MONITOR = "pg_stat_monitor"
    PG_STORE_PLANS = "pg_store_plans"
    PG_STAT_STATEMENTS = "pg_stat_statements"


@dataclass(frozen=True)
class QuerySnapshot:
    """Point-in-time snapshot of a query's performance metrics."""

    queryid: str
    query_text: str
    calls: int
    total_exec_time: float  # ms
    mean_exec_time: float  # ms
    min_exec_time: float
    max_exec_time: float
    rows: int
    shared_blks_hit: int = 0
    shared_blks_read: int = 0
    planid: str | None = None
    plan_text: str | None = None
    timestamp: str = ""

    @property
    def mean_time_ms(self) -> float:
        return self.mean_exec_time

    @property
    def buffer_hit_ratio(self) -> float:
        total = self.shared_blks_hit + self.shared_blks_read
        if total == 0:
            return 1.0
        return self.shared_blks_hit / total


@dataclass(frozen=True)
class RegressionEvent:
    """A detected plan regression event."""

    queryid: str
    query_text: str
    severity_score: int  # 0-100
    severity_label: str  # "critical", "high", "medium", "low", "info"

    # Time metrics
    before_mean_time: float
    after_mean_time: float
    time_increase_factor: float

    # Plan changes
    plan_changed: bool = False
    before_planid: str | None = None
    after_planid: str | None = None
    structural_changes: list[str] = field(default_factory=list)

    # Row estimate changes
    before_rows: int = 0
    after_rows: int = 0

    # IO changes
    before_buffer_hit_ratio: float = 1.0
    after_buffer_hit_ratio: float = 1.0

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "queryid": self.queryid,
            "query_text": self.query_text[:200],
            "severity_score": self.severity_score,
            "severity_label": self.severity_label,
            "before_mean_time": round(self.before_mean_time, 3),
            "after_mean_time": round(self.after_mean_time, 3),
            "time_increase_factor": round(self.time_increase_factor, 2),
            "plan_changed": self.plan_changed,
            "structural_changes": self.structural_changes,
            "timestamp": self.timestamp,
        }


# ── Severity Scoring ───────────────────────────────────────────────────


def compute_regression_severity(
    before: QuerySnapshot,
    after: QuerySnapshot,
    plan_changed: bool = False,
    scan_downgrade: bool = False,
    join_change: bool = False,
) -> int:
    """
    Compute regression severity on a 0-100 scale.

    Weights:
    - Execution time increase: 30%
    - Row estimate accuracy: 20%
    - Scan method regression (Index→Seq): 20%
    - Join method changes: 15%
    - Buffer/IO increase: 10%
    - Cost increase: 5%
    """
    score = 0.0

    # 1. Execution time increase (30 points max)
    if before.mean_exec_time > 0:
        time_factor = after.mean_exec_time / before.mean_exec_time
        if time_factor >= 10:
            score += 30
        elif time_factor >= 5:
            score += 25
        elif time_factor >= 3:
            score += 20
        elif time_factor >= 2:
            score += 15
        elif time_factor >= 1.5:
            score += 10
        elif time_factor >= 1.2:
            score += 5

    # 2. Row estimate accuracy (20 points max)
    if before.rows > 0 and after.rows > 0:
        row_ratio = max(after.rows / before.rows, before.rows / after.rows)
        if row_ratio >= 100:
            score += 20
        elif row_ratio >= 10:
            score += 15
        elif row_ratio >= 5:
            score += 10
        elif row_ratio >= 2:
            score += 5

    # 3. Scan method regression (20 points max)
    if scan_downgrade:
        score += 20

    # 4. Join method changes (15 points max)
    if join_change:
        score += 15

    # 5. Buffer/IO increase (10 points max)
    hit_ratio_drop = before.buffer_hit_ratio - after.buffer_hit_ratio
    if hit_ratio_drop > 0.3:
        score += 10
    elif hit_ratio_drop > 0.1:
        score += 5

    # 6. Plan changed at all (5 points)
    if plan_changed:
        score += 5

    return min(int(score), 100)


def severity_label(score: int) -> str:
    """Convert numeric severity to label."""
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


# ── Plan Hash ──────────────────────────────────────────────────────────


def compute_plan_hash(plan_json: dict[str, Any]) -> str:
    """
    Compute structural plan hash (SHA-256).

    Walks the EXPLAIN JSON tree depth-first, extracts structural fields,
    ignores volatile fields (costs, timing, rows), and produces a stable
    hash that changes only when the plan structure changes.
    """
    structural_parts: list[str] = []
    _walk_plan_node(plan_json, structural_parts)
    canonical = "|".join(structural_parts)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _walk_plan_node(node: dict[str, Any], parts: list[str]) -> None:
    """Depth-first walk extracting structural fields."""
    structural_fields = [
        "Node Type",
        "Relation Name",
        "Index Name",
        "Join Type",
        "Sort Key",
        "Hash Cond",
        "Index Cond",
        "Filter",
        "Merge Cond",
        "Group Key",
        "Strategy",
        "Partial Mode",
        "Parent Relationship",
    ]

    node_parts: list[str] = []
    for f in structural_fields:
        val = node.get(f)
        if val is not None:
            if isinstance(val, list):
                node_parts.append(f"{f}={','.join(str(v) for v in val)}")
            else:
                node_parts.append(f"{f}={val}")

    parts.append(";".join(node_parts))

    # Recurse into children
    for child in node.get("Plans", []):
        _walk_plan_node(child, parts)


# ── Watch Configuration ────────────────────────────────────────────────


@dataclass
class WatchConfig:
    """Configuration for the watch daemon."""

    dsn: str = "postgresql://localhost:5432/postgres"
    interval_seconds: int = 60
    top_queries: int = 100
    time_increase_threshold: float = 2.0  # Alert on 2x+ increase
    min_severity: int = 30  # Minimum severity to alert on
    storage_path: str = ".querysense/watch_state.json"

    # Alerting
    slack_webhook: str | None = None
    pagerduty_routing_key: str | None = None
    webhook_url: str | None = None
    email_smtp_host: str | None = None
    email_to: list[str] = field(default_factory=list)

    # Data source preferences
    prefer_pg_stat_monitor: bool = True


# ── Watch State ────────────────────────────────────────────────────────


class WatchState:
    """Persists query snapshots between daemon runs."""

    def __init__(self, path: str = ".querysense/watch_state.json") -> None:
        self.path = Path(path)
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._snapshots = data.get("snapshots", {})
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load watch state: %s", e)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "snapshots": self._snapshots,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_previous(self, queryid: str) -> QuerySnapshot | None:
        raw = self._snapshots.get(queryid)
        if raw is None:
            return None
        return QuerySnapshot(**raw)

    def record(self, snapshot: QuerySnapshot) -> None:
        self._snapshots[snapshot.queryid] = {
            "queryid": snapshot.queryid,
            "query_text": snapshot.query_text,
            "calls": snapshot.calls,
            "total_exec_time": snapshot.total_exec_time,
            "mean_exec_time": snapshot.mean_exec_time,
            "min_exec_time": snapshot.min_exec_time,
            "max_exec_time": snapshot.max_exec_time,
            "rows": snapshot.rows,
            "shared_blks_hit": snapshot.shared_blks_hit,
            "shared_blks_read": snapshot.shared_blks_read,
            "planid": snapshot.planid,
            "plan_text": snapshot.plan_text,
            "timestamp": snapshot.timestamp
            or datetime.now(timezone.utc).isoformat(),
        }

    @property
    def query_count(self) -> int:
        return len(self._snapshots)


# ── Watch Daemon ───────────────────────────────────────────────────────


class WatchDaemon:
    """
    Continuous plan regression detector.

    Polls pg_stat_statements (or pg_stat_monitor) for performance changes,
    compares against previous snapshots, and dispatches alerts when
    regressions exceed the severity threshold.
    """

    def __init__(self, config: WatchConfig) -> None:
        self.config = config
        self.state = WatchState(config.storage_path)
        self._running = False
        self._data_source: DataSource | None = None

    def detect_data_source(self, extensions: list[str]) -> DataSource:
        """Auto-detect the best available data source."""
        ext_set = {e.lower() for e in extensions}

        if self.config.prefer_pg_stat_monitor and "pg_stat_monitor" in ext_set:
            logger.info("Using pg_stat_monitor for plan tracking")
            return DataSource.PG_STAT_MONITOR

        if "pg_store_plans" in ext_set:
            logger.info("Using pg_store_plans for plan tracking")
            return DataSource.PG_STORE_PLANS

        logger.info("Using pg_stat_statements (EXPLAIN fallback)")
        return DataSource.PG_STAT_STATEMENTS

    def poll_query(self, raw_snapshot: dict[str, Any]) -> RegressionEvent | None:
        """
        Compare a query snapshot against its previous state.

        Returns a RegressionEvent if a regression is detected, None otherwise.
        """
        snapshot = QuerySnapshot(
            queryid=str(raw_snapshot.get("queryid", "")),
            query_text=raw_snapshot.get("query", "")[:2000],
            calls=raw_snapshot.get("calls", 0),
            total_exec_time=raw_snapshot.get("total_exec_time", 0),
            mean_exec_time=raw_snapshot.get("mean_exec_time", 0),
            min_exec_time=raw_snapshot.get("min_exec_time", 0),
            max_exec_time=raw_snapshot.get("max_exec_time", 0),
            rows=raw_snapshot.get("rows", 0),
            shared_blks_hit=raw_snapshot.get("shared_blks_hit", 0),
            shared_blks_read=raw_snapshot.get("shared_blks_read", 0),
            planid=raw_snapshot.get("planid"),
            plan_text=raw_snapshot.get("query_plan"),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        previous = self.state.get_previous(snapshot.queryid)

        # Record current state
        self.state.record(snapshot)

        # No previous data -> first observation
        if previous is None:
            return None

        # Check for significant change
        if previous.mean_exec_time == 0:
            return None

        time_factor = snapshot.mean_exec_time / previous.mean_exec_time
        if time_factor < self.config.time_increase_threshold:
            return None

        # Plan change detection
        plan_changed = (
            snapshot.planid is not None
            and previous.planid is not None
            and snapshot.planid != previous.planid
        )

        score = compute_regression_severity(
            before=previous,
            after=snapshot,
            plan_changed=plan_changed,
        )

        if score < self.config.min_severity:
            return None

        return RegressionEvent(
            queryid=snapshot.queryid,
            query_text=snapshot.query_text,
            severity_score=score,
            severity_label=severity_label(score),
            before_mean_time=previous.mean_exec_time,
            after_mean_time=snapshot.mean_exec_time,
            time_increase_factor=time_factor,
            plan_changed=plan_changed,
            before_planid=previous.planid,
            after_planid=snapshot.planid,
            before_rows=previous.rows,
            after_rows=snapshot.rows,
            before_buffer_hit_ratio=previous.buffer_hit_ratio,
            after_buffer_hit_ratio=snapshot.buffer_hit_ratio,
        )

    def run_sync(self) -> None:
        """
        Run the watch daemon synchronously (blocking).

        This is the entry point for `querysense watch`. It polls at
        the configured interval and dispatches alerts. Uses psycopg
        for synchronous database access.
        """
        from querysense.alerting import AlertDispatcher, AlertPayload

        dispatcher = self._build_dispatcher()

        logger.info(
            "Watch daemon starting (interval=%ds, threshold=%.1fx, min_severity=%d)",
            self.config.interval_seconds,
            self.config.time_increase_threshold,
            self.config.min_severity,
        )

        self._running = True

        def _handle_signal(signum: int, frame: Any) -> None:
            logger.info("Received signal %d, shutting down", signum)
            self._running = False

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        try:
            import psycopg

            with psycopg.connect(self.config.dsn) as conn:
                # Detect available extensions
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT extname FROM pg_extension "
                        "WHERE extname IN ('pg_stat_monitor', 'pg_store_plans', 'pg_stat_statements')"
                    )
                    extensions = [row[0] for row in cur.fetchall()]

                self._data_source = self.detect_data_source(extensions)

                cycle = 0
                while self._running:
                    cycle += 1
                    events = self._poll_cycle(conn)

                    if events:
                        logger.info(
                            "Cycle %d: %d regression(s) detected", cycle, len(events)
                        )
                        for event in events:
                            payload = AlertPayload(
                                query_id=event.queryid,
                                severity=event.severity_label,
                                danger_score=event.severity_score,
                                summary=(
                                    f"Query time increased {event.time_increase_factor:.1f}x "
                                    f"({event.before_mean_time:.1f}ms -> {event.after_mean_time:.1f}ms)"
                                ),
                                structural_changes=event.structural_changes,
                            )
                            dispatcher.send(payload)
                    else:
                        logger.debug("Cycle %d: no regressions", cycle)

                    self.state.save()

                    if self._running:
                        time.sleep(self.config.interval_seconds)

        except ImportError:
            logger.error(
                "psycopg not installed. Install with: pip install 'querysense[db]'"
            )
            raise SystemExit(1)

    def _poll_cycle(self, conn: Any) -> list[RegressionEvent]:
        """Execute one polling cycle against the database."""
        events: list[RegressionEvent] = []

        query = self._build_poll_query()

        try:
            with conn.cursor() as cur:
                cur.execute(query, [self.config.top_queries])
                columns = [desc[0] for desc in cur.description]
                for row in cur.fetchall():
                    raw = dict(zip(columns, row))
                    event = self.poll_query(raw)
                    if event is not None:
                        events.append(event)
        except Exception as e:
            logger.error("Poll cycle failed: %s", e)

        return events

    def _build_poll_query(self) -> str:
        """Build the SQL query for the current data source."""
        if self._data_source == DataSource.PG_STAT_MONITOR:
            return """
                SELECT queryid, query, calls, total_exec_time, mean_exec_time,
                       min_exec_time, max_exec_time, rows,
                       shared_blks_hit, shared_blks_read,
                       planid, query_plan
                FROM pg_stat_monitor
                ORDER BY total_exec_time DESC
                LIMIT %s
            """
        elif self._data_source == DataSource.PG_STORE_PLANS:
            return """
                SELECT s.queryid, s.query, s.calls, s.total_exec_time,
                       s.mean_exec_time, s.min_exec_time, s.max_exec_time,
                       s.rows, s.shared_blks_hit, s.shared_blks_read,
                       p.planid::text as planid, p.plan as query_plan
                FROM pg_stat_statements s
                LEFT JOIN pg_store_plans p ON s.queryid = p.queryid
                ORDER BY s.total_exec_time DESC
                LIMIT %s
            """
        else:
            return """
                SELECT queryid, query, calls, total_exec_time, mean_exec_time,
                       min_exec_time, max_exec_time, rows,
                       shared_blks_hit, shared_blks_read,
                       NULL as planid, NULL as query_plan
                FROM pg_stat_statements
                ORDER BY total_exec_time DESC
                LIMIT %s
            """

    def _build_dispatcher(self) -> "AlertDispatcher":
        """Build alert dispatcher from config."""
        from querysense.alerting import (
            AlertDispatcher,
            EmailAlert,
            PagerDutyAlert,
            SlackAlert,
            WebhookAlert,
        )

        dispatcher = AlertDispatcher()

        if self.config.slack_webhook:
            dispatcher.add_channel(SlackAlert(self.config.slack_webhook))

        if self.config.pagerduty_routing_key:
            dispatcher.add_channel(PagerDutyAlert(self.config.pagerduty_routing_key))

        if self.config.webhook_url:
            dispatcher.add_channel(WebhookAlert(self.config.webhook_url))

        if self.config.email_smtp_host and self.config.email_to:
            dispatcher.add_channel(
                EmailAlert(
                    smtp_host=self.config.email_smtp_host,
                    to_addrs=self.config.email_to,
                )
            )

        return dispatcher

    def stop(self) -> None:
        """Signal the daemon to stop."""
        self._running = False
