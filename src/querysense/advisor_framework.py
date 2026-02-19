"""
Advisor Framework — configurable, YAML-based check system.

Closes the gap vs Percona PMM's built-in advisor framework. Checks are:
- Defined in YAML (name, query, severity, interval)
- Run as SQL queries against the target database
- Results stored locally in SQLite
- Entirely offline — data never leaves the server

Supports:
- SQL queries against target PostgreSQL/MySQL
- Instant metrics (current state snapshot)
- Range metrics (historical over time window)
- Configurable severity levels: critical, warning, info, debug
- Configurable intervals: frequent (4h), standard (24h), rare (78h)
- Custom user-defined checks in ~/.querysense/checks.yml
- Built-in checks for common PostgreSQL issues

Usage:
    from querysense.advisor_framework import AdvisorRunner

    runner = AdvisorRunner()
    results = await runner.run_all(dsn="postgresql://localhost/mydb")
    for r in results:
        print(f"[{r.severity}] {r.title}: {r.message}")
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────

class Severity(str, Enum):
    """Severity levels (Percona PMM compatible)."""
    EMERGENCY = "emergency"
    ALERT = "alert"
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"

    @property
    def score(self) -> int:
        """Map to numeric score for filtering/sorting."""
        return {
            "emergency": 10, "alert": 9, "critical": 8, "error": 7,
            "warning": 6, "notice": 5, "info": 4, "debug": 2,
        }.get(self.value, 0)

    @property
    def color(self) -> str:
        """Rich color for CLI output."""
        return {
            "emergency": "bold red", "alert": "red", "critical": "red",
            "error": "red", "warning": "yellow", "notice": "cyan",
            "info": "blue", "debug": "dim",
        }.get(self.value, "white")


class Interval(str, Enum):
    """Check run intervals."""
    FREQUENT = "frequent"   # Every 4 hours
    STANDARD = "standard"   # Every 24 hours
    RARE = "rare"           # Every 78 hours

    @property
    def seconds(self) -> int:
        return {
            "frequent": 4 * 3600,
            "standard": 24 * 3600,
            "rare": 78 * 3600,
        }[self.value]


class QueryType(str, Enum):
    """Supported query types (Percona PMM compatible)."""
    POSTGRESQL_SELECT = "postgresql_select"
    METRICS_INSTANT = "metrics_instant"
    METRICS_RANGE = "metrics_range"
    SYSTEM_METRICS = "system_metrics"


@dataclass
class AdvisorCheck:
    """A single advisor check definition."""
    name: str
    title: str
    description: str = ""
    query: str = ""  # SQL query to execute
    query_type: QueryType = QueryType.POSTGRESQL_SELECT
    severity: Severity = Severity.WARNING
    interval: Interval = Interval.STANDARD
    category: str = "general"
    enabled: bool = True
    # Evaluation
    condition: str = ""  # Python expression evaluated against row, e.g. "value > 100"
    message_template: str = ""  # f-string template using row columns

    @property
    def id(self) -> str:
        return hashlib.md5(self.name.encode()).hexdigest()[:12]


@dataclass
class CheckResult:
    """Result of running an advisor check."""
    check_name: str
    check_id: str
    title: str
    severity: Severity
    category: str
    status: str = "pass"  # "pass", "fail", "error", "skip"
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    duration_ms: float = 0.0
    target_dsn: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_name": self.check_name,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "status": self.status,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class AdvisorReport:
    """Complete advisor run report."""
    results: list[CheckResult] = field(default_factory=list)
    checks_run: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_errored: int = 0
    checks_skipped: int = 0
    total_duration_ms: float = 0.0
    timestamp: str = ""

    @property
    def has_failures(self) -> bool:
        return self.checks_failed > 0

    @property
    def critical_count(self) -> int:
        return sum(
            1 for r in self.results
            if r.status == "fail" and r.severity.score >= 8
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "checks_errored": self.checks_errored,
            "checks_skipped": self.checks_skipped,
            "critical_count": self.critical_count,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "timestamp": self.timestamp,
            "results": [r.to_dict() for r in self.results],
        }


# ── Built-in checks ──────────────────────────────────────────────────

BUILTIN_CHECKS: list[AdvisorCheck] = [
    AdvisorCheck(
        name="pg_long_running_queries",
        title="Long-Running Queries",
        description="Detect queries running longer than 5 minutes",
        query="""
            SELECT pid, usename, state,
                   EXTRACT(EPOCH FROM (now() - query_start)) AS duration_sec,
                   left(query, 100) AS query_snippet
            FROM pg_stat_activity
            WHERE state = 'active'
              AND query NOT ILIKE '%pg_stat%'
              AND EXTRACT(EPOCH FROM (now() - query_start)) > 300
            ORDER BY duration_sec DESC
            LIMIT 10;
        """,
        severity=Severity.WARNING,
        interval=Interval.FREQUENT,
        category="performance",
        condition="len(rows) > 0",
        message_template="Found {count} queries running > 5 minutes. "
                         "Longest: {max_duration:.0f}s by {user}.",
    ),
    AdvisorCheck(
        name="pg_unused_indexes",
        title="Unused Indexes",
        description="Indexes with zero scans since last stats reset",
        query="""
            SELECT schemaname, relname, indexrelname,
                   idx_scan, pg_relation_size(indexrelid) AS size_bytes
            FROM pg_stat_user_indexes
            WHERE idx_scan = 0
              AND indexrelname NOT LIKE '%_pkey'
            ORDER BY pg_relation_size(indexrelid) DESC
            LIMIT 20;
        """,
        severity=Severity.INFO,
        interval=Interval.STANDARD,
        category="indexing",
        condition="len(rows) > 0",
        message_template="Found {count} unused indexes consuming "
                         "{total_size_mb:.0f}MB of disk space.",
    ),
    AdvisorCheck(
        name="pg_high_dead_tuples",
        title="High Dead Tuple Ratio",
        description="Tables where dead tuples exceed 20% of live tuples",
        query="""
            SELECT schemaname, relname, n_live_tup, n_dead_tup,
                   CASE WHEN n_live_tup > 0
                        THEN n_dead_tup::float / n_live_tup
                        ELSE 0 END AS dead_ratio,
                   last_autovacuum
            FROM pg_stat_user_tables
            WHERE n_live_tup > 1000
              AND n_dead_tup::float / GREATEST(n_live_tup, 1) > 0.2
            ORDER BY dead_ratio DESC
            LIMIT 15;
        """,
        severity=Severity.WARNING,
        interval=Interval.FREQUENT,
        category="vacuum",
        condition="len(rows) > 0",
        message_template="Found {count} tables with >20% dead tuples. "
                         "Worst: {worst_table} at {worst_ratio:.0%}.",
    ),
    AdvisorCheck(
        name="pg_xid_wraparound_risk",
        title="Transaction ID Wraparound Risk",
        description="Tables approaching XID wraparound (>50% of 2B limit)",
        query="""
            SELECT n.nspname, c.relname,
                   age(c.relfrozenxid) AS xid_age,
                   age(c.relfrozenxid)::float / 2000000000 AS pct_to_wrap,
                   age(c.relminmxid) AS mxid_age,
                   age(c.relminmxid)::float / 2000000000 AS mxid_pct_to_wrap
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND (age(c.relfrozenxid) > 1000000000
                   OR age(c.relminmxid) > 1000000000)
            ORDER BY age(c.relfrozenxid) DESC
            LIMIT 10;
        """,
        severity=Severity.CRITICAL,
        interval=Interval.FREQUENT,
        category="vacuum",
        condition="len(rows) > 0",
        message_template="DANGER: {count} table(s) at >{worst_pct:.0%} of XID "
                         "wraparound limit. Immediate VACUUM FREEZE required.",
    ),
    AdvisorCheck(
        name="pg_replication_lag",
        title="Replication Lag",
        description="Detect replicas lagging more than 10 seconds",
        query="""
            SELECT application_name, client_addr::text,
                   state, sync_state,
                   EXTRACT(EPOCH FROM (now() - reply_time)) AS lag_seconds,
                   pg_wal_lsn_diff(sent_lsn, replay_lsn) AS lag_bytes
            FROM pg_stat_replication
            WHERE EXTRACT(EPOCH FROM (now() - reply_time)) > 10
            ORDER BY lag_seconds DESC;
        """,
        severity=Severity.WARNING,
        interval=Interval.FREQUENT,
        category="replication",
        condition="len(rows) > 0",
        message_template="WARNING: {count} replica(s) lagging >10s. "
                         "Max lag: {max_lag:.1f}s ({max_lag_app}).",
    ),
    AdvisorCheck(
        name="pg_connection_saturation",
        title="Connection Pool Saturation",
        description="Connection usage approaching max_connections",
        query="""
            SELECT
                count(*) AS active_connections,
                current_setting('max_connections')::int AS max_connections,
                count(*)::float / current_setting('max_connections')::int AS utilization
            FROM pg_stat_activity;
        """,
        severity=Severity.WARNING,
        interval=Interval.FREQUENT,
        category="performance",
        condition="len(rows) > 0 and rows[0].get('utilization', 0) > 0.8",
        message_template="Connection utilization at {utilization:.0%} "
                         "({active}/{max}). Increase max_connections or use "
                         "a connection pooler (pgbouncer).",
    ),
    AdvisorCheck(
        name="pg_sequence_exhaustion",
        title="Sequence Exhaustion Risk",
        description="Sequences approaching their max value",
        query="""
            SELECT sequencename, last_value,
                   CASE data_type
                       WHEN 'smallint' THEN 32767
                       WHEN 'integer' THEN 2147483647
                       WHEN 'bigint' THEN 9223372036854775807
                       ELSE 2147483647
                   END AS max_value,
                   last_value::float / CASE data_type
                       WHEN 'smallint' THEN 32767
                       WHEN 'integer' THEN 2147483647
                       WHEN 'bigint' THEN 9223372036854775807
                       ELSE 2147483647
                   END AS utilization
            FROM pg_sequences
            WHERE last_value IS NOT NULL
              AND last_value::float / CASE data_type
                       WHEN 'smallint' THEN 32767
                       WHEN 'integer' THEN 2147483647
                       WHEN 'bigint' THEN 9223372036854775807
                       ELSE 2147483647
                   END > 0.5
            ORDER BY utilization DESC
            LIMIT 10;
        """,
        severity=Severity.CRITICAL,
        interval=Interval.STANDARD,
        category="schema",
        condition="len(rows) > 0",
        message_template="DANGER: {count} sequence(s) at >{worst_pct:.0%} capacity. "
                         "Worst: {worst_seq}. Migrate to bigint before exhaustion.",
    ),
    AdvisorCheck(
        name="pg_checkpoint_pressure",
        title="Excessive Forced Checkpoints",
        description="High ratio of requested (forced) vs timed checkpoints",
        query="""
            SELECT checkpoints_timed, checkpoints_req,
                   CASE WHEN (checkpoints_timed + checkpoints_req) > 0
                        THEN checkpoints_req::float /
                             (checkpoints_timed + checkpoints_req)
                        ELSE 0 END AS request_ratio
            FROM pg_stat_bgwriter;
        """,
        severity=Severity.WARNING,
        interval=Interval.STANDARD,
        category="performance",
        condition="len(rows) > 0 and rows[0].get('request_ratio', 0) > 0.3",
        message_template="Forced checkpoints are {ratio:.0%} of total. "
                         "Increase max_wal_size to reduce checkpoint frequency.",
    ),
    AdvisorCheck(
        name="pg_bloated_tables",
        title="Table Bloat Estimation",
        description="Tables with estimated bloat > 30%",
        query="""
            SELECT schemaname, relname, n_live_tup, n_dead_tup,
                   pg_total_relation_size(relid) AS total_size,
                   CASE WHEN n_live_tup > 0
                        THEN n_dead_tup::float / (n_live_tup + n_dead_tup)
                        ELSE 0 END AS bloat_pct
            FROM pg_stat_user_tables
            WHERE n_live_tup + n_dead_tup > 10000
              AND n_dead_tup::float / GREATEST(n_live_tup + n_dead_tup, 1) > 0.3
            ORDER BY n_dead_tup DESC
            LIMIT 15;
        """,
        severity=Severity.WARNING,
        interval=Interval.STANDARD,
        category="vacuum",
        condition="len(rows) > 0",
        message_template="Found {count} tables with >30% estimated bloat. "
                         "Consider VACUUM FULL or pg_repack for worst offenders.",
    ),
    AdvisorCheck(
        name="pg_autovacuum_worker_saturation",
        title="Autovacuum Worker Saturation",
        description="Autovacuum workers near or at maximum",
        query="""
            SELECT
                count(*) AS running_workers,
                current_setting('autovacuum_max_workers')::int AS max_workers,
                count(*)::float / current_setting('autovacuum_max_workers')::int AS utilization
            FROM pg_stat_activity
            WHERE backend_type = 'autovacuum worker';
        """,
        severity=Severity.WARNING,
        interval=Interval.FREQUENT,
        category="vacuum",
        condition="len(rows) > 0 and rows[0].get('utilization', 0) > 0.8",
        message_template="Autovacuum worker utilization at {utilization:.0%} "
                         "({running}/{max}). Backlog may be forming. "
                         "Increase autovacuum_max_workers.",
    ),
]


# ── Results Storage ───────────────────────────────────────────────────

class ResultStore:
    """SQLite storage for advisor check results."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            db_path = Path.home() / ".querysense" / "advisor.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_id TEXT NOT NULL,
                    check_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}',
                    target_dsn TEXT NOT NULL DEFAULT '',
                    timestamp TEXT NOT NULL,
                    duration_ms REAL NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_results_check_time
                ON check_results (check_id, timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_results_severity
                ON check_results (severity, timestamp)
            """)

    def store(self, result: CheckResult) -> None:
        """Store a check result."""
        import json as _json

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT INTO check_results
                   (check_id, check_name, title, severity, category, status,
                    message, details_json, target_dsn, timestamp, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.check_id,
                    result.check_name,
                    result.title,
                    result.severity.value,
                    result.category,
                    result.status,
                    result.message,
                    _json.dumps(result.details),
                    result.target_dsn,
                    result.timestamp,
                    result.duration_ms,
                ),
            )

    def get_history(
        self,
        check_id: str | None = None,
        severity: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get historical results."""
        import json as _json

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            query = "SELECT * FROM check_results WHERE 1=1"
            params: list[Any] = []
            if check_id:
                query += " AND check_id = ?"
                params.append(check_id)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [
                {
                    **dict(row),
                    "details": _json.loads(row["details_json"]),
                }
                for row in rows
            ]

    def should_run(self, check: AdvisorCheck) -> bool:
        """Check if enough time has elapsed since last run."""
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT MAX(timestamp) AS last_run FROM check_results WHERE check_id = ?",
                (check.id,),
            ).fetchone()
            if row is None or row[0] is None:
                return True
            last_run = datetime.fromisoformat(row[0])
            elapsed = (datetime.now(timezone.utc) - last_run).total_seconds()
            return elapsed >= check.interval.seconds


# ── YAML config loader ────────────────────────────────────────────────

def load_checks_from_yaml(path: str | Path) -> list[AdvisorCheck]:
    """Load advisor checks from a YAML file.

    Expected format:
        checks:
          - name: my_custom_check
            title: "Custom Check"
            query: "SELECT count(*) AS cnt FROM my_table WHERE ..."
            severity: warning
            interval: frequent
            category: custom
            condition: "rows[0].get('cnt', 0) > 100"
            message_template: "Found {cnt} problematic rows."
    """
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed — cannot load YAML checks.")
        return []

    path = Path(path)
    if not path.exists():
        return []

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return []

    checks: list[AdvisorCheck] = []
    for entry in data.get("checks", []):
        if not isinstance(entry, dict):
            continue
        try:
            check = AdvisorCheck(
                name=entry["name"],
                title=entry.get("title", entry["name"]),
                description=entry.get("description", ""),
                query=entry.get("query", ""),
                query_type=QueryType(
                    entry.get("query_type", "postgresql_select")
                ),
                severity=Severity(entry.get("severity", "warning")),
                interval=Interval(entry.get("interval", "standard")),
                category=entry.get("category", "custom"),
                enabled=entry.get("enabled", True),
                condition=entry.get("condition", "len(rows) > 0"),
                message_template=entry.get("message_template", "Check failed."),
            )
            checks.append(check)
        except (KeyError, ValueError) as exc:
            logger.warning("Skipping invalid check entry: %s", exc)

    return checks


# ── Runner ────────────────────────────────────────────────────────────

class AdvisorRunner:
    """Run advisor checks against a PostgreSQL database."""

    def __init__(
        self,
        extra_checks_path: str | Path | None = None,
        store_path: str | Path | None = None,
        respect_intervals: bool = True,
    ) -> None:
        self.store = ResultStore(store_path)
        self.respect_intervals = respect_intervals

        # Load built-in + user checks
        self.checks: list[AdvisorCheck] = list(BUILTIN_CHECKS)

        # Load user-defined checks
        if extra_checks_path:
            self.checks.extend(load_checks_from_yaml(extra_checks_path))
        else:
            default_path = Path.home() / ".querysense" / "checks.yml"
            if default_path.exists():
                self.checks.extend(load_checks_from_yaml(default_path))

    async def run_all(
        self,
        dsn: str,
        categories: list[str] | None = None,
        min_severity: Severity = Severity.DEBUG,
    ) -> AdvisorReport:
        """Run all applicable advisor checks."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        t0 = time.perf_counter()
        report = AdvisorReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        conn = await asyncpg.connect(dsn)
        try:
            for check in self.checks:
                if not check.enabled:
                    continue
                if check.severity.score < min_severity.score:
                    continue
                if categories and check.category not in categories:
                    continue
                if self.respect_intervals and not self.store.should_run(check):
                    report.checks_skipped += 1
                    continue

                result = await self._run_check(conn, check, dsn)
                self.store.store(result)
                report.results.append(result)
                report.checks_run += 1

                if result.status == "pass":
                    report.checks_passed += 1
                elif result.status == "fail":
                    report.checks_failed += 1
                elif result.status == "error":
                    report.checks_errored += 1
        finally:
            await conn.close()

        report.total_duration_ms = (time.perf_counter() - t0) * 1000
        return report

    async def _run_check(
        self, conn: Any, check: AdvisorCheck, dsn: str,
    ) -> CheckResult:
        """Execute a single check and evaluate its condition."""
        t0 = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            raw_rows = await conn.fetch(check.query)
            rows = [dict(row) for row in raw_rows]
        except Exception as exc:
            return CheckResult(
                check_name=check.name,
                check_id=check.id,
                title=check.title,
                severity=check.severity,
                category=check.category,
                status="error",
                message=f"Query failed: {exc}",
                timestamp=now_iso,
                duration_ms=(time.perf_counter() - t0) * 1000,
                target_dsn=dsn,
            )

        # Evaluate condition
        try:
            triggered = bool(eval(check.condition, {"rows": rows, "len": len}))  # noqa: S307
        except Exception as exc:
            return CheckResult(
                check_name=check.name,
                check_id=check.id,
                title=check.title,
                severity=check.severity,
                category=check.category,
                status="error",
                message=f"Condition eval error: {exc}",
                timestamp=now_iso,
                duration_ms=(time.perf_counter() - t0) * 1000,
                target_dsn=dsn,
            )

        if not triggered:
            return CheckResult(
                check_name=check.name,
                check_id=check.id,
                title=check.title,
                severity=check.severity,
                category=check.category,
                status="pass",
                message="OK",
                timestamp=now_iso,
                duration_ms=(time.perf_counter() - t0) * 1000,
                target_dsn=dsn,
            )

        # Build failure message
        message = self._format_message(check, rows)

        return CheckResult(
            check_name=check.name,
            check_id=check.id,
            title=check.title,
            severity=check.severity,
            category=check.category,
            status="fail",
            message=message,
            details={"rows": rows[:5], "total_rows": len(rows)},
            timestamp=now_iso,
            duration_ms=(time.perf_counter() - t0) * 1000,
            target_dsn=dsn,
        )

    def _format_message(self, check: AdvisorCheck, rows: list[dict]) -> str:
        """Format the check message using template and row data."""
        if not check.message_template:
            return f"Check triggered with {len(rows)} row(s)."

        # Build template variables from rows
        ctx: dict[str, Any] = {"count": len(rows)}

        if rows:
            first = rows[0]
            ctx.update(first)

            # Common aggregates
            for key in first:
                vals = [r.get(key) for r in rows if isinstance(r.get(key), (int, float))]
                if vals:
                    ctx[f"max_{key}"] = max(vals)
                    ctx[f"min_{key}"] = min(vals)
                    ctx[f"sum_{key}"] = sum(vals)

            # Convenience aliases
            if "duration_sec" in first:
                ctx["max_duration"] = max(
                    r.get("duration_sec", 0) for r in rows
                )
                ctx["user"] = first.get("usename", "unknown")
            if "size_bytes" in first:
                total = sum(r.get("size_bytes", 0) for r in rows)
                ctx["total_size_mb"] = total / 1024 / 1024
            if "dead_ratio" in first:
                worst = max(rows, key=lambda r: r.get("dead_ratio", 0))
                ctx["worst_table"] = worst.get("relname", "")
                ctx["worst_ratio"] = worst.get("dead_ratio", 0)
            if "pct_to_wrap" in first:
                worst = max(rows, key=lambda r: r.get("pct_to_wrap", 0))
                ctx["worst_pct"] = worst.get("pct_to_wrap", 0)
            if "lag_seconds" in first:
                worst = max(rows, key=lambda r: r.get("lag_seconds", 0))
                ctx["max_lag"] = worst.get("lag_seconds", 0)
                ctx["max_lag_app"] = worst.get("application_name", "unknown")
            if "utilization" in first:
                ctx["utilization"] = first.get("utilization", 0)
                ctx["active"] = first.get("active_connections", 0)
                ctx["max"] = first.get("max_connections", 0)
                ctx["running"] = first.get("running_workers", 0)
            if "request_ratio" in first:
                ctx["ratio"] = first.get("request_ratio", 0)
            if "bloat_pct" in first:
                worst = max(rows, key=lambda r: r.get("bloat_pct", 0))
                ctx["worst_table"] = worst.get("relname", "")
            if "utilization" in first and "sequencename" in first:
                worst = max(rows, key=lambda r: r.get("utilization", 0))
                ctx["worst_pct"] = worst.get("utilization", 0)
                ctx["worst_seq"] = worst.get("sequencename", "")

        try:
            return check.message_template.format(**ctx)
        except (KeyError, IndexError, ValueError):
            return f"Check triggered with {len(rows)} row(s)."
