"""
Xmin Horizon Tracker — detect what's blocking VACUUM from reclaiming dead tuples.

Reverse-engineered from pganalyze's VACUUM Advisor
(https://pganalyze.com/docs/insights/vacuum-advisor):

The xmin horizon is the oldest transaction ID still visible to any active
process. VACUUM cannot reclaim dead tuples newer than the xmin horizon,
because some process might still need to see them.

The xmin horizon is determined by the OLDEST of:
1. Active transactions (pg_stat_activity.backend_xmin)
2. Replication slots (pg_replication_slots.xmin / catalog_xmin)
3. Prepared transactions (pg_prepared_xacts.transaction)
4. Standby feedback (pg_stat_replication.backend_xmin)

When any of these holds an old xmin, ALL tables are blocked from
reclaiming dead tuples — even if autovacuum runs constantly.

This is the #1 cause of table bloat that pganalyze surfaces but
most monitoring tools miss entirely.

Usage:
    from querysense.db.xmin_horizon import XminHorizonTracker, XminHorizonReport

    tracker = XminHorizonTracker()
    report = await tracker.analyze(conn)
    print(f"Xmin horizon: {report.horizon_xid}")
    print(f"Held by: {report.holder_type} ({report.holder_detail})")
    for blocker in report.blockers:
        print(f"  {blocker.source}: xmin={blocker.xmin} age={blocker.age}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


# ── Data Classes ───────────────────────────────────────────────────────


@dataclass
class XminBlocker:
    """Something holding the xmin horizon back."""
    source: str          # "transaction" | "replication_slot" | "prepared_txn" | "standby"
    xmin: int            # The xmin value being held
    age: int             # age(xmin) — how old it is
    detail: str          # Human-readable detail
    pid: int | None = None
    database: str = ""
    application_name: str = ""
    state: str = ""
    query_start: str = ""
    duration_seconds: float = 0.0
    fix_command: str = ""

    @property
    def severity(self) -> str:
        if self.age > 500_000_000:
            return "critical"
        if self.age > 100_000_000:
            return "warning"
        return "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "xmin": self.xmin,
            "age": self.age,
            "detail": self.detail,
            "pid": self.pid,
            "database": self.database,
            "application_name": self.application_name,
            "state": self.state,
            "duration_seconds": round(self.duration_seconds, 1),
            "severity": self.severity,
            "fix_command": self.fix_command,
        }


@dataclass
class XminHorizonReport:
    """Complete xmin horizon analysis."""
    horizon_xid: int = 0          # The actual xmin horizon value
    horizon_age: int = 0          # age(horizon_xid)
    holder_type: str = ""         # What's holding the horizon
    holder_detail: str = ""       # Description of the holder
    blockers: list[XminBlocker] = field(default_factory=list)

    # Summary metrics
    active_txn_count: int = 0
    oldest_txn_age: int = 0
    slot_count: int = 0
    oldest_slot_age: int = 0
    prepared_txn_count: int = 0
    standby_count: int = 0

    # Wraparound risk
    xid_age: int = 0              # max(age(datfrozenxid))
    xid_limit: int = 2_000_000_000
    autovacuum_freeze_max_age: int = 200_000_000

    errors: list[str] = field(default_factory=list)

    @property
    def wraparound_risk_pct(self) -> float:
        if self.xid_limit == 0:
            return 0.0
        return self.xid_age / self.xid_limit * 100

    @property
    def freeze_urgency_pct(self) -> float:
        """How close we are to autovacuum_freeze_max_age (triggers aggressive VACUUM)."""
        if self.autovacuum_freeze_max_age == 0:
            return 0.0
        return self.xid_age / self.autovacuum_freeze_max_age * 100

    @property
    def severity(self) -> str:
        if self.wraparound_risk_pct > 75 or self.horizon_age > 500_000_000:
            return "critical"
        if self.wraparound_risk_pct > 50 or self.horizon_age > 100_000_000:
            return "warning"
        return "ok"

    @property
    def is_blocked(self) -> bool:
        return self.horizon_age > 10_000_000  # >10M txns old

    def summary(self) -> str:
        parts = []
        if self.is_blocked:
            parts.append(
                f"XMIN HORIZON BLOCKED by {self.holder_type}: "
                f"age={self.horizon_age:,} ({self.holder_detail})"
            )
        else:
            parts.append(f"Xmin horizon healthy: age={self.horizon_age:,}")

        parts.append(f"Wraparound risk: {self.wraparound_risk_pct:.1f}%")

        if self.blockers:
            parts.append(f"{len(self.blockers)} blocker(s) detected")

        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "horizon_xid": self.horizon_xid,
            "horizon_age": self.horizon_age,
            "holder_type": self.holder_type,
            "holder_detail": self.holder_detail,
            "severity": self.severity,
            "is_blocked": self.is_blocked,
            "wraparound_risk_pct": round(self.wraparound_risk_pct, 1),
            "freeze_urgency_pct": round(self.freeze_urgency_pct, 1),
            "active_txn_count": self.active_txn_count,
            "oldest_txn_age": self.oldest_txn_age,
            "slot_count": self.slot_count,
            "oldest_slot_age": self.oldest_slot_age,
            "prepared_txn_count": self.prepared_txn_count,
            "standby_count": self.standby_count,
            "xid_age": self.xid_age,
            "blockers": [b.to_dict() for b in self.blockers],
            "errors": self.errors,
        }


# ── SQL Queries ────────────────────────────────────────────────────────


# 1. Active transactions holding old xmin
_ACTIVE_TXNS_QUERY = """
SELECT
    pid,
    datname,
    usename,
    application_name,
    state,
    backend_xmin::text::bigint AS xmin_val,
    age(backend_xmin) AS xmin_age,
    backend_xid::text::bigint AS xid_val,
    age(backend_xid) AS xid_age,
    query_start::text,
    now() - query_start AS query_duration,
    EXTRACT(EPOCH FROM (now() - xact_start)) AS txn_duration_seconds,
    xact_start::text,
    wait_event_type,
    wait_event,
    query
FROM pg_stat_activity
WHERE backend_xmin IS NOT NULL
  AND state != 'idle'
  AND pid != pg_backend_pid()
ORDER BY age(backend_xmin) DESC
"""

# 2. Replication slots holding old xmin
_REPLICATION_SLOTS_QUERY = """
SELECT
    slot_name,
    slot_type,
    database,
    active,
    xmin::text::bigint AS xmin_val,
    CASE WHEN xmin IS NOT NULL THEN age(xmin) ELSE 0 END AS xmin_age,
    catalog_xmin::text::bigint AS catalog_xmin_val,
    CASE WHEN catalog_xmin IS NOT NULL THEN age(catalog_xmin) ELSE 0 END AS catalog_xmin_age,
    restart_lsn::text,
    confirmed_flush_lsn::text
FROM pg_replication_slots
ORDER BY GREATEST(
    CASE WHEN xmin IS NOT NULL THEN age(xmin) ELSE 0 END,
    CASE WHEN catalog_xmin IS NOT NULL THEN age(catalog_xmin) ELSE 0 END
) DESC
"""

# 3. Prepared transactions holding old xmin
_PREPARED_TXNS_QUERY = """
SELECT
    gid,
    owner,
    database,
    transaction::text::bigint AS xid_val,
    age(transaction) AS xid_age,
    prepared::text AS prepared_at
FROM pg_prepared_xacts
ORDER BY age(transaction) DESC
"""

# 4. Standby servers holding old xmin via feedback
_STANDBY_FEEDBACK_QUERY = """
SELECT
    pid,
    usename,
    application_name,
    client_addr::text,
    backend_xmin::text::bigint AS xmin_val,
    CASE WHEN backend_xmin IS NOT NULL THEN age(backend_xmin) ELSE 0 END AS xmin_age,
    sent_lsn::text,
    write_lsn::text,
    flush_lsn::text,
    replay_lsn::text,
    sync_state
FROM pg_stat_replication
WHERE backend_xmin IS NOT NULL
ORDER BY age(backend_xmin) DESC
"""

# 5. Global xmin horizon and wraparound info
_GLOBAL_XMIN_QUERY = """
SELECT
    (SELECT max(age(datfrozenxid)) FROM pg_database) AS max_xid_age,
    (SELECT current_setting('autovacuum_freeze_max_age')::bigint) AS freeze_max_age,
    txid_current() AS current_xid
"""

# 6. Idle-in-transaction sessions (common xmin blocker)
_IDLE_IN_TXN_QUERY = """
SELECT
    pid,
    datname,
    usename,
    application_name,
    state,
    backend_xmin::text::bigint AS xmin_val,
    age(backend_xmin) AS xmin_age,
    xact_start::text,
    EXTRACT(EPOCH FROM (now() - xact_start)) AS idle_seconds,
    query
FROM pg_stat_activity
WHERE state = 'idle in transaction'
  AND backend_xmin IS NOT NULL
  AND pid != pg_backend_pid()
ORDER BY age(backend_xmin) DESC
"""


# ── Tracker ────────────────────────────────────────────────────────────


class XminHorizonTracker:
    """
    Track what's holding the xmin horizon and blocking VACUUM.

    Checks all four sources:
    1. Active/idle-in-transaction sessions
    2. Replication slots (including inactive/orphaned)
    3. Prepared transactions (2PC)
    4. Standby server feedback
    """

    async def analyze(self, conn: AsyncDBConnection) -> XminHorizonReport:
        """
        Analyze the current xmin horizon.

        Returns:
            XminHorizonReport with all blockers identified
        """
        report = XminHorizonReport()

        # Global info
        await self._collect_global(conn, report)

        # Check all four xmin sources
        await self._check_active_transactions(conn, report)
        await self._check_idle_in_transaction(conn, report)
        await self._check_replication_slots(conn, report)
        await self._check_prepared_transactions(conn, report)
        await self._check_standby_feedback(conn, report)

        # Determine the actual horizon holder
        self._determine_horizon(report)

        return report

    async def _collect_global(
        self, conn: AsyncDBConnection, report: XminHorizonReport,
    ) -> None:
        """Collect global xmin/wraparound info."""
        try:
            row = await conn.fetchrow(_GLOBAL_XMIN_QUERY)
            if row:
                report.xid_age = row["max_xid_age"] or 0
                report.autovacuum_freeze_max_age = row["freeze_max_age"] or 200_000_000
        except Exception as e:
            report.errors.append(f"Global xmin query failed: {e}")

    async def _check_active_transactions(
        self, conn: AsyncDBConnection, report: XminHorizonReport,
    ) -> None:
        """Check active transactions for old xmin."""
        try:
            rows = await conn.fetch(_ACTIVE_TXNS_QUERY)
            report.active_txn_count = len(rows)

            for row in rows:
                xmin_age = row["xmin_age"] or 0
                if xmin_age > report.oldest_txn_age:
                    report.oldest_txn_age = xmin_age

                if xmin_age > 1_000_000:  # Only report significant ones
                    duration = row.get("txn_duration_seconds", 0) or 0
                    query_text = (row.get("query") or "")[:200]
                    report.blockers.append(XminBlocker(
                        source="transaction",
                        xmin=row["xmin_val"] or 0,
                        age=xmin_age,
                        detail=(
                            f"Active transaction (PID {row['pid']}) in database "
                            f"'{row['datname']}' running for {duration:.0f}s"
                        ),
                        pid=row["pid"],
                        database=row["datname"] or "",
                        application_name=row["application_name"] or "",
                        state=row["state"] or "",
                        query_start=row["query_start"] or "",
                        duration_seconds=duration,
                        fix_command=(
                            f"-- Check if this transaction can be terminated:\n"
                            f"-- Query: {query_text}\n"
                            f"SELECT pg_terminate_backend({row['pid']});"
                        ),
                    ))

        except Exception as e:
            report.errors.append(f"Active transaction check failed: {e}")

    async def _check_idle_in_transaction(
        self, conn: AsyncDBConnection, report: XminHorizonReport,
    ) -> None:
        """Check idle-in-transaction sessions (common blocker)."""
        try:
            rows = await conn.fetch(_IDLE_IN_TXN_QUERY)

            for row in rows:
                xmin_age = row["xmin_age"] or 0
                idle_seconds = row.get("idle_seconds", 0) or 0

                if xmin_age > 1_000_000 or idle_seconds > 300:
                    query_text = (row.get("query") or "")[:200]
                    report.blockers.append(XminBlocker(
                        source="idle_in_transaction",
                        xmin=row["xmin_val"] or 0,
                        age=xmin_age,
                        detail=(
                            f"IDLE IN TRANSACTION (PID {row['pid']}) in '{row['datname']}' "
                            f"idle for {idle_seconds:.0f}s — blocking VACUUM on ALL tables"
                        ),
                        pid=row["pid"],
                        database=row["datname"] or "",
                        application_name=row["application_name"] or "",
                        state="idle in transaction",
                        duration_seconds=idle_seconds,
                        fix_command=(
                            f"-- This idle transaction is blocking VACUUM globally!\n"
                            f"-- Last query: {query_text}\n"
                            f"SELECT pg_terminate_backend({row['pid']});\n"
                            f"-- Prevent in future:\n"
                            f"ALTER SYSTEM SET idle_in_transaction_session_timeout = '5min';"
                        ),
                    ))

        except Exception as e:
            report.errors.append(f"Idle-in-transaction check failed: {e}")

    async def _check_replication_slots(
        self, conn: AsyncDBConnection, report: XminHorizonReport,
    ) -> None:
        """Check replication slots for old xmin."""
        try:
            rows = await conn.fetch(_REPLICATION_SLOTS_QUERY)
            report.slot_count = len(rows)

            for row in rows:
                xmin_age = max(row.get("xmin_age") or 0, row.get("catalog_xmin_age") or 0)
                xmin_val = row.get("xmin_val") or row.get("catalog_xmin_val") or 0
                is_active = row.get("active", False)

                if xmin_age > report.oldest_slot_age:
                    report.oldest_slot_age = xmin_age

                if xmin_age > 1_000_000:
                    slot_name = row.get("slot_name", "unknown")
                    active_str = "active" if is_active else "INACTIVE"

                    fix = ""
                    if not is_active:
                        fix = (
                            f"-- INACTIVE slot '{slot_name}' is blocking VACUUM!\n"
                            f"-- If the subscriber is permanently gone, drop the slot:\n"
                            f"SELECT pg_drop_replication_slot('{slot_name}');"
                        )
                    else:
                        fix = (
                            f"-- Active slot '{slot_name}' has old xmin.\n"
                            f"-- Check if the subscriber is lagging:\n"
                            f"SELECT * FROM pg_stat_replication "
                            f"WHERE application_name = '{slot_name}';"
                        )

                    report.blockers.append(XminBlocker(
                        source="replication_slot",
                        xmin=xmin_val,
                        age=xmin_age,
                        detail=(
                            f"Replication slot '{slot_name}' ({row.get('slot_type', '?')}, "
                            f"{active_str}) — xmin age: {xmin_age:,}"
                        ),
                        database=row.get("database") or "",
                        fix_command=fix,
                    ))

        except Exception as e:
            report.errors.append(f"Replication slot check failed: {e}")

    async def _check_prepared_transactions(
        self, conn: AsyncDBConnection, report: XminHorizonReport,
    ) -> None:
        """Check prepared transactions (2PC) for old xmin."""
        try:
            rows = await conn.fetch(_PREPARED_TXNS_QUERY)
            report.prepared_txn_count = len(rows)

            for row in rows:
                xid_age = row.get("xid_age") or 0

                if xid_age > 1_000_000:
                    gid = row.get("gid", "unknown")
                    report.blockers.append(XminBlocker(
                        source="prepared_transaction",
                        xmin=row.get("xid_val") or 0,
                        age=xid_age,
                        detail=(
                            f"Prepared transaction '{gid}' (owner: {row.get('owner', '?')}, "
                            f"database: {row.get('database', '?')}) — age: {xid_age:,}"
                        ),
                        database=row.get("database") or "",
                        fix_command=(
                            f"-- Orphaned prepared transaction is blocking VACUUM!\n"
                            f"-- If this transaction should be rolled back:\n"
                            f"ROLLBACK PREPARED '{gid}';\n"
                            f"-- If it should be committed:\n"
                            f"COMMIT PREPARED '{gid}';"
                        ),
                    ))

        except Exception as e:
            report.errors.append(f"Prepared transaction check failed: {e}")

    async def _check_standby_feedback(
        self, conn: AsyncDBConnection, report: XminHorizonReport,
    ) -> None:
        """Check standby server feedback for old xmin."""
        try:
            rows = await conn.fetch(_STANDBY_FEEDBACK_QUERY)
            report.standby_count = len(rows)

            for row in rows:
                xmin_age = row.get("xmin_age") or 0

                if xmin_age > 1_000_000:
                    app_name = row.get("application_name") or "unknown"
                    client = row.get("client_addr") or "unknown"

                    report.blockers.append(XminBlocker(
                        source="standby",
                        xmin=row.get("xmin_val") or 0,
                        age=xmin_age,
                        detail=(
                            f"Standby '{app_name}' ({client}) sending old xmin feedback — "
                            f"age: {xmin_age:,}. Standby may have long-running queries."
                        ),
                        pid=row.get("pid"),
                        application_name=app_name,
                        fix_command=(
                            f"-- Standby '{app_name}' is blocking VACUUM on primary.\n"
                            f"-- Option 1: Cancel long queries on standby.\n"
                            f"-- Option 2: Disable hot_standby_feedback on standby:\n"
                            f"--   ALTER SYSTEM SET hot_standby_feedback = off;  -- on standby\n"
                            f"-- Option 3: Set max_standby_streaming_delay on standby:\n"
                            f"--   ALTER SYSTEM SET max_standby_streaming_delay = '30s';"
                        ),
                    ))

        except Exception as e:
            report.errors.append(f"Standby feedback check failed: {e}")

    def _determine_horizon(self, report: XminHorizonReport) -> None:
        """Determine what's holding the xmin horizon."""
        if not report.blockers:
            report.holder_type = "none"
            report.holder_detail = "No xmin blockers detected — VACUUM can proceed freely"
            return

        # Sort by age (oldest = the actual horizon)
        report.blockers.sort(key=lambda b: b.age, reverse=True)
        oldest = report.blockers[0]

        report.horizon_xid = oldest.xmin
        report.horizon_age = oldest.age
        report.holder_type = oldest.source
        report.holder_detail = oldest.detail
