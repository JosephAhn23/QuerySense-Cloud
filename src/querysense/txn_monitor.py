"""
Long-Running Transaction Monitor — detect idle transactions with one-click kill.

Based on "PostgreSQL Mistakes and How to Avoid Them" (Angelakos 2025):
long-running idle transactions block vacuum, hold locks, and cause bloat.

Detects:
- Idle-in-transaction sessions exceeding threshold
- Long-running active queries
- Lock holders blocking other sessions
- Prepared transactions (2PC) that were forgotten

Outputs specific pg_terminate_backend() commands with safety checks.

Usage:
    from querysense.txn_monitor import TransactionMonitor, TxnHealth

    monitor = TransactionMonitor()
    health = await monitor.check(dsn="postgresql://localhost/mydb")
    for txn in health.long_running:
        print(f"PID {txn.pid}: idle for {txn.duration_seconds}s")
        print(f"  Kill: {txn.kill_command}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class LongTransaction:
    """A detected long-running transaction."""
    pid: int
    state: str  # idle in transaction, active, idle
    duration_seconds: float
    query: str
    application_name: str
    client_addr: str
    wait_event: str
    blocking_pids: list[int] = field(default_factory=list)
    blocked_queries: int = 0
    tables_affected: list[str] = field(default_factory=list)

    @property
    def kill_command(self) -> str:
        return f"SELECT pg_terminate_backend({self.pid});"

    @property
    def cancel_command(self) -> str:
        return f"SELECT pg_cancel_backend({self.pid});"

    @property
    def severity(self) -> str:
        if self.state == "idle in transaction" and self.duration_seconds > 300:
            return "critical"
        if self.blocked_queries > 0:
            return "critical"
        if self.duration_seconds > 600:
            return "warning"
        return "info"


@dataclass
class LockInfo:
    """A detected lock contention."""
    blocking_pid: int
    blocked_pid: int
    blocking_query: str
    blocked_query: str
    lock_type: str
    lock_mode: str
    relation: str
    duration_seconds: float

    @property
    def severity(self) -> str:
        if self.duration_seconds > 60:
            return "critical"
        if self.duration_seconds > 10:
            return "warning"
        return "info"


@dataclass
class TxnHealth:
    """Complete transaction health report."""
    long_running: list[LongTransaction] = field(default_factory=list)
    locks: list[LockInfo] = field(default_factory=list)
    total_connections: int = 0
    idle_in_transaction: int = 0
    active_queries: int = 0
    max_idle_duration_seconds: float = 0.0
    prepared_transactions: int = 0

    @property
    def fix_script(self) -> str:
        lines = ["-- QuerySense Transaction Health Fix Script", ""]
        for txn in self.long_running:
            if txn.severity in ("critical", "warning"):
                lines.append(f"-- PID {txn.pid}: {txn.state} for {txn.duration_seconds:.0f}s")
                lines.append(f"-- App: {txn.application_name} | Client: {txn.client_addr}")
                lines.append(f"-- Query: {txn.query[:100]}...")
                if txn.state == "idle in transaction":
                    lines.append(f"{txn.kill_command}  -- Safe: idle transaction")
                else:
                    lines.append(f"{txn.cancel_command}  -- Cancel query first")
                    lines.append(f"-- If still running: {txn.kill_command}")
                lines.append("")

        if self.prepared_transactions > 0:
            lines.append(f"-- {self.prepared_transactions} prepared transaction(s) — investigate:")
            lines.append("SELECT * FROM pg_prepared_xacts;")
            lines.append("-- ROLLBACK PREPARED 'transaction_name';")
        return "\n".join(lines)


class TransactionMonitor:
    """
    Monitor transactions for idle, long-running, and lock-blocking sessions.

    Provides one-click pg_terminate_backend commands with safety context.
    """

    async def check(
        self,
        dsn: str,
        idle_threshold_seconds: float = 300.0,
        active_threshold_seconds: float = 600.0,
    ) -> TxnHealth:
        """Run transaction health check."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            health = TxnHealth()

            # Connection overview
            row = await conn.fetchrow("""
                SELECT
                    count(*) AS total,
                    count(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_txn,
                    count(*) FILTER (WHERE state = 'active') AS active
                FROM pg_stat_activity
                WHERE backend_type = 'client backend'
            """)
            health.total_connections = row["total"]
            health.idle_in_transaction = row["idle_in_txn"]
            health.active_queries = row["active"]

            # Long-running transactions
            health.long_running = await self._fetch_long_running(
                conn, idle_threshold_seconds, active_threshold_seconds,
            )

            if health.long_running:
                health.max_idle_duration_seconds = max(
                    t.duration_seconds for t in health.long_running
                )

            # Lock contention
            health.locks = await self._fetch_locks(conn)

            # Prepared transactions
            health.prepared_transactions = await conn.fetchval(
                "SELECT count(*) FROM pg_prepared_xacts"
            ) or 0

            return health
        finally:
            await conn.close()

    async def _fetch_long_running(
        self,
        conn: Any,
        idle_threshold: float,
        active_threshold: float,
    ) -> list[LongTransaction]:
        """Fetch long-running transactions."""
        rows = await conn.fetch("""
            SELECT
                pid,
                state,
                EXTRACT(EPOCH FROM (now() - COALESCE(state_change, query_start))) AS duration_secs,
                COALESCE(query, '') AS query,
                COALESCE(application_name, '') AS app_name,
                COALESCE(client_addr::text, 'local') AS client_addr,
                COALESCE(wait_event, '') AS wait_event,
                pg_blocking_pids(pid) AS blocking_pids
            FROM pg_stat_activity
            WHERE backend_type = 'client backend'
              AND pid != pg_backend_pid()
              AND (
                (state = 'idle in transaction' AND
                 EXTRACT(EPOCH FROM (now() - state_change)) > $1)
                OR
                (state = 'active' AND
                 EXTRACT(EPOCH FROM (now() - query_start)) > $2)
              )
            ORDER BY duration_secs DESC
        """, idle_threshold, active_threshold)

        txns: list[LongTransaction] = []
        for row in rows:
            blocking_pids = row["blocking_pids"] or []
            txn = LongTransaction(
                pid=row["pid"],
                state=row["state"],
                duration_seconds=row["duration_secs"],
                query=row["query"],
                application_name=row["app_name"],
                client_addr=row["client_addr"],
                wait_event=row["wait_event"],
                blocking_pids=list(blocking_pids),
            )

            # Count sessions blocked by this PID
            blocked = await conn.fetchval("""
                SELECT count(*) FROM pg_stat_activity
                WHERE $1 = ANY(pg_blocking_pids(pid))
            """, row["pid"])
            txn.blocked_queries = blocked or 0

            txns.append(txn)

        return txns

    async def _fetch_locks(self, conn: Any) -> list[LockInfo]:
        """Fetch lock contention info."""
        rows = await conn.fetch("""
            SELECT
                blocked_locks.pid AS blocked_pid,
                blocking_locks.pid AS blocking_pid,
                blocked_activity.query AS blocked_query,
                blocking_activity.query AS blocking_query,
                blocked_locks.locktype AS lock_type,
                blocked_locks.mode AS lock_mode,
                COALESCE(blocked_locks.relation::regclass::text, '') AS relation,
                EXTRACT(EPOCH FROM (now() - blocked_activity.query_start)) AS duration_secs
            FROM pg_catalog.pg_locks blocked_locks
            JOIN pg_catalog.pg_stat_activity blocked_activity
                ON blocked_activity.pid = blocked_locks.pid
            JOIN pg_catalog.pg_locks blocking_locks
                ON blocking_locks.locktype = blocked_locks.locktype
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
            JOIN pg_catalog.pg_stat_activity blocking_activity
                ON blocking_activity.pid = blocking_locks.pid
            WHERE NOT blocked_locks.granted
            ORDER BY duration_secs DESC
            LIMIT 20
        """)

        locks: list[LockInfo] = []
        for row in rows:
            locks.append(LockInfo(
                blocking_pid=row["blocking_pid"],
                blocked_pid=row["blocked_pid"],
                blocking_query=row["blocking_query"] or "",
                blocked_query=row["blocked_query"] or "",
                lock_type=row["lock_type"],
                lock_mode=row["lock_mode"],
                relation=row["relation"],
                duration_seconds=row["duration_secs"],
            ))

        return locks
