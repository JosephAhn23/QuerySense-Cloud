"""
Wait event analysis for PostgreSQL.

Reads pg_stat_activity to capture wait events, classify them, and
correlate with slow queries. This closes the gap vs Datadog DBM's
wait event analysis.

Wait event types:
- LWLock: Lightweight lock contention
- Lock: Heavy-weight lock contention (row-level, table-level)
- BufferPin: Buffer pin contention
- Activity: Background worker activity
- Client: Waiting for client
- Extension: Extension-provided wait events
- IO: I/O operations
- IPC: Inter-process communication
- Timeout: Timeout events

Usage:
    from querysense.db.wait_events import collect_wait_events, WaitEventSnapshot

    snapshot = await collect_wait_events(conn)
    for event in snapshot.top_events:
        print(f"{event.wait_type}/{event.wait_event}: {event.count} sessions")

    # Correlate with a slow query
    diagnosis = snapshot.diagnose_query(query_text="SELECT * FROM orders...")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class WaitEvent:
    """A single wait event observation."""

    wait_event_type: str
    wait_event: str
    count: int = 0
    pids: list[int] = field(default_factory=list)
    sample_query: str = ""

    @property
    def category(self) -> str:
        """Broad category for the wait event."""
        return _WAIT_CATEGORIES.get(self.wait_event_type, "other")


@dataclass
class WaitingQuery:
    """A query currently waiting on something."""

    pid: int
    query: str
    wait_event_type: str | None
    wait_event: str | None
    state: str
    duration_seconds: float = 0.0
    blocking_pids: list[int] = field(default_factory=list)
    database: str = ""
    username: str = ""


@dataclass
class LockInfo:
    """Information about a database lock."""

    pid: int
    lock_type: str
    relation: str = ""
    mode: str = ""
    granted: bool = True
    query: str = ""
    waiting_since_seconds: float = 0.0


@dataclass
class WaitEventSnapshot:
    """Complete wait event analysis snapshot."""

    events: list[WaitEvent] = field(default_factory=list)
    waiting_queries: list[WaitingQuery] = field(default_factory=list)
    lock_contention: list[LockInfo] = field(default_factory=list)
    total_backends: int = 0
    waiting_backends: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def top_events(self) -> list[WaitEvent]:
        """Top wait events by session count."""
        return sorted(self.events, key=lambda e: e.count, reverse=True)

    @property
    def has_lock_contention(self) -> bool:
        """Whether there's active lock contention."""
        return any(not l.granted for l in self.lock_contention)

    @property
    def io_wait_count(self) -> int:
        """Number of backends waiting on I/O."""
        return sum(e.count for e in self.events if e.wait_event_type == "IO")

    @property
    def lock_wait_count(self) -> int:
        """Number of backends waiting on locks."""
        return sum(
            e.count for e in self.events
            if e.wait_event_type in ("Lock", "LWLock")
        )

    def diagnose_query(self, query_text: str) -> list[str]:
        """
        Correlate wait events with a specific query.

        Returns actionable diagnostic messages.
        """
        diagnostics: list[str] = []
        query_lower = query_text.lower().strip()[:200]

        for wq in self.waiting_queries:
            if wq.query and query_lower[:50] in wq.query.lower()[:200]:
                if wq.wait_event_type == "Lock":
                    diagnostics.append(
                        f"Query is blocked by lock ({wq.wait_event}); "
                        f"waiting {wq.duration_seconds:.1f}s. "
                        f"Blocking PIDs: {wq.blocking_pids}"
                    )
                elif wq.wait_event_type == "IO":
                    diagnostics.append(
                        f"Query is waiting on I/O ({wq.wait_event}); "
                        f"likely reading from disk. "
                        f"Consider adding indexes or increasing shared_buffers."
                    )
                elif wq.wait_event_type == "LWLock":
                    diagnostics.append(
                        f"Query hit lightweight lock contention ({wq.wait_event}); "
                        f"possible buffer pool pressure."
                    )

        # General diagnostics from overall wait state
        if self.io_wait_count > self.total_backends * 0.3:
            diagnostics.append(
                f"{self.io_wait_count} of {self.total_backends} backends "
                f"waiting on I/O; storage may be saturated."
            )
        if self.lock_wait_count > 5:
            diagnostics.append(
                f"{self.lock_wait_count} backends waiting on locks; "
                f"check for long-running transactions."
            )

        return diagnostics

    def health_warnings(self) -> list[str]:
        """Generate health warnings from wait event analysis."""
        warnings: list[str] = []

        if self.waiting_backends > self.total_backends * 0.5 and self.total_backends > 2:
            warnings.append(
                f"{self.waiting_backends}/{self.total_backends} backends are waiting; "
                f"system may be under heavy contention."
            )

        for event in self.top_events[:5]:
            if event.wait_event_type == "IO" and event.count > 3:
                warnings.append(
                    f"{event.count} backends waiting on IO:{event.wait_event}; "
                    f"check disk performance and shared_buffers."
                )
            if event.wait_event == "WALWrite" and event.count > 2:
                warnings.append(
                    f"{event.count} backends waiting on WAL writes; "
                    f"consider faster WAL disk or wal_buffers tuning."
                )
            if event.wait_event_type == "LWLock" and "Buffer" in event.wait_event:
                warnings.append(
                    f"Buffer contention ({event.wait_event}): {event.count} backends; "
                    f"increase shared_buffers or reduce concurrent queries."
                )
            if event.wait_event_type == "Lock" and event.count > 2:
                warnings.append(
                    f"Lock contention ({event.wait_event}): {event.count} backends; "
                    f"check for long-held locks or deadlock-prone patterns."
                )

        return warnings

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "total_backends": self.total_backends,
            "waiting_backends": self.waiting_backends,
            "top_wait_events": [
                {
                    "type": e.wait_event_type,
                    "event": e.wait_event,
                    "count": e.count,
                    "category": e.category,
                }
                for e in self.top_events[:10]
            ],
            "waiting_queries": [
                {
                    "pid": q.pid,
                    "wait_type": q.wait_event_type,
                    "wait_event": q.wait_event,
                    "duration_seconds": round(q.duration_seconds, 1),
                    "query": q.query[:200],
                    "blocking_pids": q.blocking_pids,
                }
                for q in self.waiting_queries[:20]
            ],
            "lock_contention": [
                {
                    "pid": l.pid,
                    "type": l.lock_type,
                    "relation": l.relation,
                    "mode": l.mode,
                    "granted": l.granted,
                }
                for l in self.lock_contention
                if not l.granted
            ],
            "health_warnings": self.health_warnings(),
            "errors": self.errors,
        }


# ── Wait event categories ────────────────────────────────────────────

_WAIT_CATEGORIES: dict[str, str] = {
    "IO": "storage",
    "Lock": "locking",
    "LWLock": "locking",
    "BufferPin": "memory",
    "Activity": "background",
    "Client": "client",
    "Extension": "extension",
    "IPC": "communication",
    "Timeout": "timeout",
}

_WAIT_SUGGESTIONS: dict[str, str] = {
    "DataFileRead": "Disk reads are slow; add indexes to reduce sequential scans or increase shared_buffers",
    "DataFileWrite": "Disk writes are slow; check storage performance or checkpoint settings",
    "WALWrite": "WAL write bottleneck; use faster WAL disk or increase wal_buffers",
    "WALSync": "WAL sync overhead; consider wal_sync_method tuning",
    "BufFileRead": "Reading temp files; increase work_mem to avoid spilling to disk",
    "BufFileWrite": "Writing temp files; increase work_mem for sorts/hashes",
    "relation": "Table-level lock contention; check for DDL or VACUUM FULL",
    "tuple": "Row-level lock contention; review transaction isolation and commit timing",
    "transactionid": "Waiting for another transaction to complete; check for long transactions",
    "BufferContent": "Buffer content lock; high concurrency on same pages — consider partitioning",
    "WALInsert": "WAL insertion contention; consider full_page_writes tuning",
}


# ── Collection ───────────────────────────────────────────────────────

async def collect_wait_events(conn: AsyncDBConnection) -> WaitEventSnapshot:
    """
    Collect current wait event data from pg_stat_activity.

    Provides a point-in-time snapshot of what every backend is
    waiting on, plus lock contention details.
    """
    snapshot = WaitEventSnapshot()

    # Wait events aggregated
    try:
        rows = await conn.fetch(
            """SELECT wait_event_type, wait_event, COUNT(*) AS cnt,
                      array_agg(pid) AS pids,
                      (array_agg(query))[1] AS sample_query
               FROM pg_stat_activity
               WHERE datname = current_database()
                 AND pid != pg_backend_pid()
                 AND wait_event IS NOT NULL
               GROUP BY wait_event_type, wait_event
               ORDER BY cnt DESC"""
        )
        for row in rows:
            snapshot.events.append(WaitEvent(
                wait_event_type=row["wait_event_type"] or "",
                wait_event=row["wait_event"] or "",
                count=row["cnt"],
                pids=list(row["pids"] or []),
                sample_query=(row["sample_query"] or "")[:200],
            ))
    except Exception as e:
        snapshot.errors.append(f"wait_events: {e}")

    # Waiting queries with duration
    try:
        rows = await conn.fetch(
            """SELECT pid, query, wait_event_type, wait_event, state,
                      datname, usename,
                      EXTRACT(EPOCH FROM (now() - query_start)) AS duration_s
               FROM pg_stat_activity
               WHERE datname = current_database()
                 AND pid != pg_backend_pid()
                 AND wait_event IS NOT NULL
                 AND state = 'active'
               ORDER BY duration_s DESC
               LIMIT 50"""
        )
        for row in rows:
            wq = WaitingQuery(
                pid=row["pid"],
                query=(row["query"] or "")[:500],
                wait_event_type=row["wait_event_type"],
                wait_event=row["wait_event"],
                state=row["state"] or "",
                duration_seconds=row["duration_s"] or 0.0,
                database=row["datname"] or "",
                username=row["usename"] or "",
            )
            snapshot.waiting_queries.append(wq)
    except Exception as e:
        snapshot.errors.append(f"waiting_queries: {e}")

    # Blocking PIDs (PG 9.6+)
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
               WHERE NOT blocked.granted
                 AND blocking.granted
               GROUP BY blocked.pid"""
        )
        blocking_map = {row["blocked_pid"]: list(row["blocking_pids"]) for row in rows}
        for wq in snapshot.waiting_queries:
            wq.blocking_pids = blocking_map.get(wq.pid, [])
    except Exception as e:
        snapshot.errors.append(f"blocking_pids: {e}")

    # Lock contention
    try:
        rows = await conn.fetch(
            """SELECT l.pid, l.locktype, COALESCE(c.relname, '') AS relation,
                      l.mode, l.granted,
                      a.query,
                      EXTRACT(EPOCH FROM (now() - a.query_start)) AS wait_s
               FROM pg_locks l
               JOIN pg_stat_activity a ON a.pid = l.pid
               LEFT JOIN pg_class c ON c.oid = l.relation
               WHERE NOT l.granted
                 AND a.datname = current_database()
               ORDER BY wait_s DESC
               LIMIT 20"""
        )
        for row in rows:
            snapshot.lock_contention.append(LockInfo(
                pid=row["pid"],
                lock_type=row["locktype"],
                relation=row["relation"],
                mode=row["mode"],
                granted=row["granted"],
                query=(row["query"] or "")[:200],
                waiting_since_seconds=row["wait_s"] or 0.0,
            ))
    except Exception as e:
        snapshot.errors.append(f"lock_contention: {e}")

    # Total backends
    try:
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()"
        )
        snapshot.total_backends = int(total) if total else 0
        snapshot.waiting_backends = sum(e.count for e in snapshot.events)
    except Exception as e:
        snapshot.errors.append(f"backend_count: {e}")

    return snapshot
