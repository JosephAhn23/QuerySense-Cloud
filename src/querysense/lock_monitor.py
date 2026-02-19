"""
Runtime Lock Monitor — detect blocking queries, deadlocks, and lock contention.

Closes the pganalyze gap: "Lock analysis — shows blocking queries, deadlock traces."
Queries pg_locks + pg_stat_activity to build blocking chain visualization.

Capabilities:
1. Blocking chain detection: Who is blocking whom (recursive)
2. Lock wait duration: How long each query has been waiting
3. Lock type breakdown: AccessShareLock, RowExclusiveLock, etc.
4. Deadlock detection: Circular blocking chains
5. Recommendations: Kill long-running blockers, optimize queries

Usage:
    from querysense.lock_monitor import LockMonitor

    monitor = LockMonitor()
    report = await monitor.check(dsn)
    for chain in report.blocking_chains:
        print(chain)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LockWaiter:
    """A process waiting for a lock."""

    pid: int
    query: str
    wait_duration_sec: float
    lock_type: str
    relation: str
    state: str
    application_name: str
    client_addr: str
    username: str


@dataclass(frozen=True)
class LockHolder:
    """A process holding a lock that blocks others."""

    pid: int
    query: str
    lock_type: str
    relation: str
    state: str
    duration_sec: float
    application_name: str
    client_addr: str
    username: str
    blocked_pids: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class BlockingChain:
    """A chain of blocking: holder → waiter(s)."""

    holder: LockHolder
    waiters: list[LockWaiter]
    depth: int = 1  # How deep the chain goes (1 = direct, 2+ = transitive)
    is_deadlock: bool = False

    @property
    def total_blocked_time_sec(self) -> float:
        return sum(w.wait_duration_sec for w in self.waiters)

    @property
    def severity(self) -> str:
        if self.is_deadlock:
            return "critical"
        max_wait = max((w.wait_duration_sec for w in self.waiters), default=0)
        if max_wait > 60:
            return "critical"
        if max_wait > 10:
            return "warning"
        return "info"


@dataclass
class LockReport:
    """Complete lock monitoring report."""

    blocking_chains: list[BlockingChain] = field(default_factory=list)
    total_blocked_queries: int = 0
    total_blocking_queries: int = 0
    max_wait_duration_sec: float = 0
    deadlock_detected: bool = False
    lock_type_distribution: dict[str, int] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(c.severity == "critical" for c in self.blocking_chains)

    def summary(self) -> str:
        if not self.blocking_chains:
            return "No blocking queries detected."
        parts = [f"{self.total_blocking_queries} blocking query(ies)"]
        parts.append(f"{self.total_blocked_queries} blocked query(ies)")
        if self.max_wait_duration_sec > 0:
            parts.append(f"max wait: {self.max_wait_duration_sec:.1f}s")
        if self.deadlock_detected:
            parts.append("DEADLOCK DETECTED")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "total_blocked": self.total_blocked_queries,
            "total_blocking": self.total_blocking_queries,
            "max_wait_sec": round(self.max_wait_duration_sec, 1),
            "deadlock": self.deadlock_detected,
            "lock_types": self.lock_type_distribution,
            "chains": [
                {
                    "severity": chain.severity,
                    "depth": chain.depth,
                    "is_deadlock": chain.is_deadlock,
                    "holder": {
                        "pid": chain.holder.pid,
                        "query": chain.holder.query[:200],
                        "lock_type": chain.holder.lock_type,
                        "relation": chain.holder.relation,
                        "state": chain.holder.state,
                        "duration_sec": round(chain.holder.duration_sec, 1),
                    },
                    "waiters": [
                        {
                            "pid": w.pid,
                            "query": w.query[:200],
                            "wait_sec": round(w.wait_duration_sec, 1),
                            "lock_type": w.lock_type,
                        }
                        for w in chain.waiters
                    ],
                }
                for chain in self.blocking_chains
            ],
            "recommendations": self.recommendations,
        }


# ── Catalog Queries ───────────────────────────────────────────────────

BLOCKING_QUERY = """
SELECT
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocked_activity.query AS blocked_query,
    blocked_activity.application_name AS blocked_app,
    blocked_activity.client_addr AS blocked_addr,
    blocked_activity.state AS blocked_state,
    EXTRACT(EPOCH FROM (now() - blocked_activity.query_start)) AS blocked_duration_sec,
    blocked_locks.locktype AS blocked_locktype,
    blocked_locks.mode AS blocked_mode,
    COALESCE(blocked_locks.relation::regclass::text, '') AS blocked_relation,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocking_activity.query AS blocking_query,
    blocking_activity.application_name AS blocking_app,
    blocking_activity.client_addr AS blocking_addr,
    blocking_activity.state AS blocking_state,
    EXTRACT(EPOCH FROM (now() - blocking_activity.query_start)) AS blocking_duration_sec,
    blocking_locks.locktype AS blocking_locktype,
    blocking_locks.mode AS blocking_mode,
    COALESCE(blocking_locks.relation::regclass::text, '') AS blocking_relation
FROM pg_locks blocked_locks
JOIN pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_locks blocking_locks ON (
    blocking_locks.locktype = blocked_locks.locktype
    AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
    AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
    AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
    AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
    AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
    AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
    AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
    AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
    AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
    AND blocking_locks.pid != blocked_locks.pid
)
JOIN pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted
ORDER BY blocked_duration_sec DESC;
"""

LOCK_DISTRIBUTION_QUERY = """
SELECT mode, COUNT(*) AS count
FROM pg_locks
WHERE locktype = 'relation'
GROUP BY mode
ORDER BY count DESC;
"""

LONG_RUNNING_QUERY = """
SELECT
    pid,
    usename,
    application_name,
    client_addr::text,
    state,
    query,
    EXTRACT(EPOCH FROM (now() - query_start)) AS duration_sec,
    wait_event_type,
    wait_event
FROM pg_stat_activity
WHERE state != 'idle'
  AND pid != pg_backend_pid()
  AND query_start IS NOT NULL
ORDER BY duration_sec DESC
LIMIT 20;
"""


class LockMonitor:
    """Monitor runtime locks, blocking chains, and deadlocks."""

    def analyze_from_data(
        self,
        blocking_data: list[dict[str, Any]],
        lock_distribution: list[dict[str, Any]] | None = None,
    ) -> LockReport:
        """Analyze lock data fetched from catalog queries.

        Args:
            blocking_data: Results from BLOCKING_QUERY
            lock_distribution: Results from LOCK_DISTRIBUTION_QUERY
        """
        report = LockReport()

        if not blocking_data:
            report.recommendations.append("No blocking queries detected — lock health is good.")
            return report

        # Build blocking chains
        holders: dict[int, LockHolder] = {}
        waiter_map: dict[int, list[LockWaiter]] = {}
        blocked_pids: set[int] = set()
        blocking_pids: set[int] = set()

        for row in blocking_data:
            blocking_pid = row.get("blocking_pid", 0)
            blocked_pid = row.get("blocked_pid", 0)

            blocking_pids.add(blocking_pid)
            blocked_pids.add(blocked_pid)

            if blocking_pid not in holders:
                holders[blocking_pid] = LockHolder(
                    pid=blocking_pid,
                    query=row.get("blocking_query", ""),
                    lock_type=row.get("blocking_mode", ""),
                    relation=row.get("blocking_relation", ""),
                    state=row.get("blocking_state", ""),
                    duration_sec=row.get("blocking_duration_sec", 0),
                    application_name=row.get("blocking_app", ""),
                    client_addr=str(row.get("blocking_addr", "")),
                    username=row.get("blocking_user", ""),
                    blocked_pids=[],
                )

            waiter = LockWaiter(
                pid=blocked_pid,
                query=row.get("blocked_query", ""),
                wait_duration_sec=row.get("blocked_duration_sec", 0),
                lock_type=row.get("blocked_mode", ""),
                relation=row.get("blocked_relation", ""),
                state=row.get("blocked_state", ""),
                application_name=row.get("blocked_app", ""),
                client_addr=str(row.get("blocked_addr", "")),
                username=row.get("blocked_user", ""),
            )

            waiter_map.setdefault(blocking_pid, []).append(waiter)

        # Detect deadlocks: a blocked PID that is also a blocking PID
        deadlock_pids = blocked_pids & blocking_pids
        report.deadlock_detected = len(deadlock_pids) > 0

        # Build chains
        for pid, holder in holders.items():
            waiters = waiter_map.get(pid, [])
            if not waiters:
                continue

            # Compute depth
            depth = 1
            if pid in blocked_pids:
                depth = 2  # This holder is itself blocked

            chain = BlockingChain(
                holder=holder,
                waiters=waiters,
                depth=depth,
                is_deadlock=pid in deadlock_pids,
            )
            report.blocking_chains.append(chain)

        # Sort by severity
        severity_order = {"critical": 0, "warning": 1, "info": 2}
        report.blocking_chains.sort(key=lambda c: severity_order.get(c.severity, 3))

        report.total_blocking_queries = len(blocking_pids)
        report.total_blocked_queries = len(blocked_pids)
        report.max_wait_duration_sec = max(
            (w.wait_duration_sec for chain in report.blocking_chains for w in chain.waiters),
            default=0,
        )

        # Lock type distribution
        if lock_distribution:
            report.lock_type_distribution = {
                row.get("mode", ""): row.get("count", 0)
                for row in lock_distribution
            }

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        return report

    def _generate_recommendations(self, report: LockReport) -> list[str]:
        recs: list[str] = []

        if report.deadlock_detected:
            recs.append(
                "DEADLOCK DETECTED: Two or more queries are waiting for each other. "
                "PostgreSQL will automatically resolve one, but investigate the "
                "transaction ordering in your application code."
            )

        # Long-blocking queries
        for chain in report.blocking_chains:
            if chain.holder.duration_sec > 60:
                recs.append(
                    f"PID {chain.holder.pid} has been blocking {len(chain.waiters)} "
                    f"query(ies) for {chain.holder.duration_sec:.0f}s. "
                    f"State: {chain.holder.state}. "
                    f"Consider: SELECT pg_terminate_backend({chain.holder.pid});"
                )

        # Heavy lock types
        if report.lock_type_distribution:
            exclusive_count = sum(
                count for lock_type, count in report.lock_type_distribution.items()
                if "Exclusive" in lock_type and "Share" not in lock_type
            )
            if exclusive_count > 5:
                recs.append(
                    f"{exclusive_count} exclusive locks active. This indicates DDL operations "
                    f"or heavy write contention. Consider batching writes or running DDL "
                    f"during off-peak hours."
                )

        # General advice
        if report.max_wait_duration_sec > 30:
            recs.append(
                f"Longest wait is {report.max_wait_duration_sec:.0f}s. "
                f"Consider setting lock_timeout to prevent infinite waits: "
                f"SET lock_timeout = '10s';"
            )

        if not recs and not report.blocking_chains:
            recs.append("No lock issues detected. Database lock health is good.")

        return recs

    @staticmethod
    def get_catalog_queries() -> dict[str, str]:
        """Return catalog queries for lock monitoring."""
        return {
            "blocking": BLOCKING_QUERY,
            "distribution": LOCK_DISTRIBUTION_QUERY,
            "long_running": LONG_RUNNING_QUERY,
        }
