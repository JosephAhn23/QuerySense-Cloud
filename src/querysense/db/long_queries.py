"""
Long-running query detection and management.

Detects queries running longer than a threshold from pg_stat_activity,
provides blocking chain analysis, and optionally terminates them.
Closes the gap vs PgHero's long-running query detection.

Usage:
    from querysense.db.long_queries import detect_long_queries, LongQueryReport

    report = await detect_long_queries(conn, threshold_seconds=30)
    for q in report.queries:
        print(f"PID {q.pid}: running {q.duration_seconds:.1f}s - {q.query[:80]}")

    # Terminate a specific query
    await terminate_query(conn, pid=12345)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class LongQuery:
    """A long-running query detected from pg_stat_activity."""

    pid: int
    query: str
    state: str
    duration_seconds: float
    wait_event_type: str | None = None
    wait_event: str | None = None
    database: str = ""
    username: str = ""
    application_name: str = ""
    client_addr: str = ""
    blocking_pids: list[int] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return len(self.blocking_pids) > 0

    @property
    def is_idle_in_transaction(self) -> bool:
        return "idle in transaction" in (self.state or "")

    @property
    def severity(self) -> str:
        if self.duration_seconds > 3600:
            return "critical"
        if self.duration_seconds > 300:
            return "warning"
        return "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "query": self.query[:500],
            "state": self.state,
            "duration_seconds": round(self.duration_seconds, 1),
            "severity": self.severity,
            "wait_event_type": self.wait_event_type,
            "wait_event": self.wait_event,
            "database": self.database,
            "username": self.username,
            "application_name": self.application_name,
            "is_blocked": self.is_blocked,
            "blocking_pids": self.blocking_pids,
        }


@dataclass
class LongQueryReport:
    """Report of long-running queries."""

    queries: list[LongQuery] = field(default_factory=list)
    idle_in_transaction: list[LongQuery] = field(default_factory=list)
    threshold_seconds: float = 30.0
    total_backends: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.queries) + len(self.idle_in_transaction)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for q in self.queries + self.idle_in_transaction
            if q.severity == "critical"
        )

    @property
    def blocked_count(self) -> int:
        return sum(1 for q in self.queries if q.is_blocked)

    def summary(self) -> str:
        parts = [f"{len(self.queries)} long-running queries (>{self.threshold_seconds}s)"]
        if self.idle_in_transaction:
            parts.append(f"{len(self.idle_in_transaction)} idle-in-transaction")
        if self.blocked_count:
            parts.append(f"{self.blocked_count} blocked by other sessions")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "threshold_seconds": self.threshold_seconds,
            "total_backends": self.total_backends,
            "long_running_count": len(self.queries),
            "idle_in_transaction_count": len(self.idle_in_transaction),
            "blocked_count": self.blocked_count,
            "queries": [q.to_dict() for q in self.queries],
            "idle_in_transaction": [q.to_dict() for q in self.idle_in_transaction],
            "errors": self.errors,
        }


async def detect_long_queries(
    conn: AsyncDBConnection,
    threshold_seconds: float = 30.0,
    idle_threshold_seconds: float = 300.0,
) -> LongQueryReport:
    """
    Detect long-running queries and idle-in-transaction sessions.

    Args:
        conn: Database connection
        threshold_seconds: Alert threshold for active queries
        idle_threshold_seconds: Alert threshold for idle-in-transaction
    """
    report = LongQueryReport(threshold_seconds=threshold_seconds)

    # Total backends
    try:
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()"
        )
        report.total_backends = int(total) if total else 0
    except Exception as e:
        report.errors.append(f"backend_count: {e}")

    # Long-running active queries
    try:
        rows = await conn.fetch(
            """SELECT pid, query, state,
                      EXTRACT(EPOCH FROM (now() - query_start)) AS duration_s,
                      wait_event_type, wait_event,
                      datname, usename, application_name,
                      COALESCE(client_addr::text, '') AS client_addr
               FROM pg_stat_activity
               WHERE datname = current_database()
                 AND pid != pg_backend_pid()
                 AND state = 'active'
                 AND query_start IS NOT NULL
                 AND EXTRACT(EPOCH FROM (now() - query_start)) > $1
               ORDER BY duration_s DESC
               LIMIT 50""",
            threshold_seconds,
        )
        for row in rows:
            report.queries.append(LongQuery(
                pid=row["pid"],
                query=(row["query"] or "")[:1000],
                state=row["state"] or "",
                duration_seconds=row["duration_s"] or 0.0,
                wait_event_type=row["wait_event_type"],
                wait_event=row["wait_event"],
                database=row["datname"] or "",
                username=row["usename"] or "",
                application_name=row["application_name"] or "",
                client_addr=row["client_addr"] or "",
            ))
    except Exception as e:
        report.errors.append(f"long_queries: {e}")

    # Idle-in-transaction sessions
    try:
        rows = await conn.fetch(
            """SELECT pid, query, state,
                      EXTRACT(EPOCH FROM (now() - state_change)) AS duration_s,
                      wait_event_type, wait_event,
                      datname, usename, application_name,
                      COALESCE(client_addr::text, '') AS client_addr
               FROM pg_stat_activity
               WHERE datname = current_database()
                 AND pid != pg_backend_pid()
                 AND state LIKE 'idle in transaction%%'
                 AND state_change IS NOT NULL
                 AND EXTRACT(EPOCH FROM (now() - state_change)) > $1
               ORDER BY duration_s DESC
               LIMIT 50""",
            idle_threshold_seconds,
        )
        for row in rows:
            report.idle_in_transaction.append(LongQuery(
                pid=row["pid"],
                query=(row["query"] or "")[:1000],
                state=row["state"] or "",
                duration_seconds=row["duration_s"] or 0.0,
                wait_event_type=row["wait_event_type"],
                wait_event=row["wait_event"],
                database=row["datname"] or "",
                username=row["usename"] or "",
                application_name=row["application_name"] or "",
                client_addr=row["client_addr"] or "",
            ))
    except Exception as e:
        report.errors.append(f"idle_in_txn: {e}")

    # Find blocking PIDs
    try:
        rows = await conn.fetch(
            """SELECT blocked.pid AS blocked_pid,
                      array_agg(DISTINCT blocking.pid) AS blocking_pids
               FROM pg_locks blocked
               JOIN pg_locks blocking
                    ON blocking.locktype = blocked.locktype
                    AND blocking.database IS NOT DISTINCT FROM blocked.database
                    AND blocking.relation IS NOT DISTINCT FROM blocked.relation
                    AND blocking.page IS NOT DISTINCT FROM blocked.page
                    AND blocking.tuple IS NOT DISTINCT FROM blocked.tuple
                    AND blocking.pid != blocked.pid
               WHERE NOT blocked.granted AND blocking.granted
               GROUP BY blocked.pid"""
        )
        blocking_map = {row["blocked_pid"]: list(row["blocking_pids"]) for row in rows}
        for q in report.queries:
            q.blocking_pids = blocking_map.get(q.pid, [])
    except Exception as e:
        report.errors.append(f"blocking: {e}")

    return report


async def terminate_query(conn: AsyncDBConnection, pid: int) -> bool:
    """
    Terminate a specific query by PID.

    Uses pg_terminate_backend which is safe and non-destructive.
    """
    result = await conn.fetchval("SELECT pg_terminate_backend($1)", pid)
    return bool(result)


async def cancel_query(conn: AsyncDBConnection, pid: int) -> bool:
    """
    Cancel (but don't terminate) a specific query.

    Uses pg_cancel_backend which sends a cancel signal.
    The connection remains alive.
    """
    result = await conn.fetchval("SELECT pg_cancel_backend($1)", pid)
    return bool(result)
