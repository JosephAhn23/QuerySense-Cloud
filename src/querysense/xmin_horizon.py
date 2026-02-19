"""
Xmin Horizon Tracker -- track oldest transaction IDs blocking VACUUM.

pganalyze tracks the "xmin horizon" -- the oldest transaction ID that any
connection (backend, replication slot, or prepared transaction) is still
referencing. VACUUM cannot clean up dead tuples newer than this horizon.

When the horizon is old:
- Dead tuples accumulate (table bloat)
- Autovacuum can't reclaim space
- Transaction ID wraparound risk increases

This module identifies what's holding the xmin horizon back and generates
actionable recommendations.

Usage:
    from querysense.xmin_horizon import XminHorizonTracker

    tracker = XminHorizonTracker()
    report = await tracker.analyze(dsn)
    print(f"Horizon age: {report.horizon_age_seconds}s")
    for blocker in report.blockers:
        print(f"  {blocker.source}: {blocker.description}")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class XminBlocker:
    """Something holding back the xmin horizon."""
    source: str               # backend, replication_slot, prepared_txn
    pid: int = 0
    xmin_age: int = 0         # Age in XIDs
    duration_seconds: float = 0.0
    description: str = ""
    state: str = ""           # active, idle, idle in transaction
    query: str = ""
    slot_name: str = ""       # For replication slots
    severity: str = "warning" # info, warning, critical
    fix_sql: str = ""
    fix_description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source": self.source,
            "xmin_age": self.xmin_age,
            "duration_seconds": round(self.duration_seconds, 1),
            "severity": self.severity,
            "description": self.description,
        }
        if self.pid:
            d["pid"] = self.pid
        if self.slot_name:
            d["slot_name"] = self.slot_name
        if self.fix_sql:
            d["fix_sql"] = self.fix_sql
        return d


@dataclass
class XminHorizonReport:
    """Report on the xmin horizon state."""
    horizon_xmin: int = 0
    horizon_age_xid: int = 0
    horizon_age_seconds: float = 0.0
    blockers: list[XminBlocker] = field(default_factory=list)
    worst_blocker: XminBlocker | None = None
    # Impact
    dead_tuples_blocked: int = 0
    estimated_bloat_mb: float = 0.0
    # Context
    current_xid: int = 0
    autovacuum_freeze_max_age: int = 200_000_000
    pct_to_wraparound: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon_age_xid": self.horizon_age_xid,
            "horizon_age_seconds": round(self.horizon_age_seconds, 1),
            "blocker_count": len(self.blockers),
            "dead_tuples_blocked": self.dead_tuples_blocked,
            "estimated_bloat_mb": round(self.estimated_bloat_mb, 2),
            "pct_to_wraparound": round(self.pct_to_wraparound, 4),
            "blockers": [b.to_dict() for b in self.blockers],
            "worst_blocker": self.worst_blocker.to_dict() if self.worst_blocker else None,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  XMIN HORIZON ANALYSIS")
        lines.append("  " + "=" * 60)
        lines.append(f"  Horizon XID age: {self.horizon_age_xid:,}")
        lines.append(f"  Horizon time: {self.horizon_age_seconds:.0f}s ({self.horizon_age_seconds / 60:.1f}min)")
        lines.append(f"  Dead tuples blocked: {self.dead_tuples_blocked:,}")
        lines.append(f"  Estimated bloat: {self.estimated_bloat_mb:.1f}MB")
        lines.append(f"  Wraparound risk: {self.pct_to_wraparound:.2%}")
        lines.append("")

        if self.worst_blocker:
            wb = self.worst_blocker
            lines.append(f"  Worst blocker: {wb.source}")
            lines.append(f"    {wb.description}")
            if wb.fix_sql:
                lines.append(f"    Fix: {wb.fix_sql}")
            lines.append("")

        for b in self.blockers:
            sev = {"critical": "[!!]", "warning": "[! ]", "info": "[  ]"}.get(b.severity, "[  ]")
            lines.append(f"  {sev} {b.source}: {b.description}")
            if b.fix_sql:
                lines.append(f"       Fix: {b.fix_sql}")

        lines.append("")
        return "\n".join(lines)


class XminHorizonTracker:
    """
    Track the xmin horizon and identify what's holding it back.

    Checks three sources of xmin holds:
    1. Long-running transactions (idle in transaction)
    2. Replication slots (inactive or lagging)
    3. Prepared transactions (2PC)
    """

    # SQL queries for collecting xmin data
    _BACKEND_XMIN_SQL = """
    SELECT
        pid,
        backend_xmin,
        age(backend_xmin) AS xmin_age,
        state,
        EXTRACT(EPOCH FROM (now() - xact_start)) AS duration_seconds,
        COALESCE(LEFT(query, 200), '') AS query,
        usename,
        application_name
    FROM pg_stat_activity
    WHERE backend_xmin IS NOT NULL
      AND pid != pg_backend_pid()
    ORDER BY age(backend_xmin) DESC
    LIMIT 20;
    """

    _SLOT_XMIN_SQL = """
    SELECT
        slot_name,
        slot_type,
        active,
        xmin,
        age(xmin) AS xmin_age,
        catalog_xmin,
        age(catalog_xmin) AS catalog_xmin_age,
        COALESCE(
            pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::bigint,
            0
        ) AS lag_bytes
    FROM pg_replication_slots
    WHERE xmin IS NOT NULL OR catalog_xmin IS NOT NULL
    ORDER BY GREATEST(age(xmin), age(catalog_xmin)) DESC;
    """

    _PREPARED_TXN_SQL = """
    SELECT
        gid,
        owner,
        age(transaction) AS xmin_age,
        EXTRACT(EPOCH FROM (now() - prepared)) AS duration_seconds
    FROM pg_prepared_xacts
    ORDER BY age(transaction) DESC;
    """

    _DEAD_TUPLES_SQL = """
    SELECT COALESCE(SUM(n_dead_tup), 0) AS total_dead
    FROM pg_stat_user_tables;
    """

    _SYSTEM_SQL = """
    SELECT
        txid_current()::text AS current_xid,
        current_setting('autovacuum_freeze_max_age')::bigint AS freeze_max_age;
    """

    async def analyze(self, dsn: str) -> XminHorizonReport:
        """Analyze the xmin horizon for a PostgreSQL instance."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            return await self._analyze_conn(conn)
        finally:
            await conn.close()

    async def _analyze_conn(self, conn: Any) -> XminHorizonReport:
        """Run analysis on an existing connection."""
        report = XminHorizonReport()
        blockers: list[XminBlocker] = []

        # System info
        sys_row = await conn.fetchrow(self._SYSTEM_SQL)
        if sys_row:
            report.current_xid = int(sys_row["current_xid"])
            report.autovacuum_freeze_max_age = int(sys_row["freeze_max_age"])

        # Dead tuples
        dead = await conn.fetchval(self._DEAD_TUPLES_SQL)
        report.dead_tuples_blocked = dead or 0
        report.estimated_bloat_mb = (dead or 0) * 200 / 1024 / 1024  # ~200 bytes per dead tuple

        # Check backends
        rows = await conn.fetch(self._BACKEND_XMIN_SQL)
        for row in rows:
            age = row["xmin_age"] or 0
            duration = row["duration_seconds"] or 0
            state = row["state"] or ""

            severity = "info"
            if state == "idle in transaction" and duration > 60:
                severity = "critical" if duration > 300 else "warning"
            elif age > 1_000_000:
                severity = "critical" if age > 10_000_000 else "warning"

            fix = ""
            fix_desc = ""
            if state == "idle in transaction" and duration > 60:
                fix = f"SELECT pg_terminate_backend({row['pid']});"
                fix_desc = "Terminate idle-in-transaction session"

            blockers.append(XminBlocker(
                source="backend",
                pid=row["pid"],
                xmin_age=age,
                duration_seconds=duration,
                state=state,
                query=row["query"],
                severity=severity,
                description=(
                    f"PID {row['pid']} ({state}): xmin age {age:,}, "
                    f"running {duration:.0f}s, user={row['usename']}"
                ),
                fix_sql=fix,
                fix_description=fix_desc,
            ))

        # Check replication slots
        try:
            rows = await conn.fetch(self._SLOT_XMIN_SQL)
            for row in rows:
                xmin_age = row["xmin_age"] or row.get("catalog_xmin_age") or 0
                lag = row["lag_bytes"] or 0
                active = row["active"]

                severity = "info"
                if not active and xmin_age > 1_000_000:
                    severity = "critical"
                elif xmin_age > 5_000_000:
                    severity = "warning"

                fix = ""
                if not active and xmin_age > 1_000_000:
                    fix = f"SELECT pg_drop_replication_slot('{row['slot_name']}');"

                blockers.append(XminBlocker(
                    source="replication_slot",
                    slot_name=row["slot_name"],
                    xmin_age=xmin_age,
                    severity=severity,
                    description=(
                        f"Slot '{row['slot_name']}' ({row['slot_type']}): "
                        f"{'ACTIVE' if active else 'INACTIVE'}, "
                        f"xmin age {xmin_age:,}, lag {lag / 1024 / 1024:.1f}MB"
                    ),
                    fix_sql=fix,
                ))
        except Exception:
            pass  # pg_replication_slots might not be accessible

        # Check prepared transactions
        try:
            rows = await conn.fetch(self._PREPARED_TXN_SQL)
            for row in rows:
                age = row["xmin_age"] or 0
                duration = row["duration_seconds"] or 0

                severity = "warning" if age > 1_000_000 else "info"
                if duration > 3600:
                    severity = "critical"

                blockers.append(XminBlocker(
                    source="prepared_txn",
                    xmin_age=age,
                    duration_seconds=duration,
                    severity=severity,
                    description=(
                        f"Prepared txn '{row['gid']}': "
                        f"age {age:,}, prepared {duration:.0f}s ago"
                    ),
                    fix_sql=f"ROLLBACK PREPARED '{row['gid']}';",
                ))
        except Exception:
            pass

        # Sort by xmin age (worst first)
        blockers.sort(key=lambda b: -b.xmin_age)
        report.blockers = blockers
        report.worst_blocker = blockers[0] if blockers else None

        if blockers:
            report.horizon_age_xid = blockers[0].xmin_age
            report.horizon_age_seconds = blockers[0].duration_seconds
        if report.autovacuum_freeze_max_age > 0 and report.horizon_age_xid > 0:
            report.pct_to_wraparound = report.horizon_age_xid / report.autovacuum_freeze_max_age

        return report

    def analyze_offline(
        self,
        backend_rows: list[dict[str, Any]],
        slot_rows: list[dict[str, Any]] | None = None,
        prepared_rows: list[dict[str, Any]] | None = None,
        dead_tuples: int = 0,
    ) -> XminHorizonReport:
        """Analyze xmin horizon from pre-collected data (no DB connection needed)."""
        report = XminHorizonReport()
        report.dead_tuples_blocked = dead_tuples
        report.estimated_bloat_mb = dead_tuples * 200 / 1024 / 1024
        blockers: list[XminBlocker] = []

        for row in backend_rows:
            age = row.get("xmin_age", 0)
            duration = row.get("duration_seconds", 0)
            state = row.get("state", "")

            severity = "info"
            if state == "idle in transaction" and duration > 60:
                severity = "critical" if duration > 300 else "warning"

            blockers.append(XminBlocker(
                source="backend",
                pid=row.get("pid", 0),
                xmin_age=age,
                duration_seconds=duration,
                state=state,
                severity=severity,
                description=(
                    f"PID {row.get('pid', '?')} ({state}): "
                    f"xmin age {age:,}, running {duration:.0f}s"
                ),
            ))

        for row in (slot_rows or []):
            age = row.get("xmin_age", 0)
            active = row.get("active", True)
            severity = "critical" if not active and age > 1_000_000 else "info"

            blockers.append(XminBlocker(
                source="replication_slot",
                slot_name=row.get("slot_name", ""),
                xmin_age=age,
                severity=severity,
                description=(
                    f"Slot '{row.get('slot_name', '')}': "
                    f"{'ACTIVE' if active else 'INACTIVE'}, age {age:,}"
                ),
            ))

        blockers.sort(key=lambda b: -b.xmin_age)
        report.blockers = blockers
        report.worst_blocker = blockers[0] if blockers else None
        if blockers:
            report.horizon_age_xid = blockers[0].xmin_age
            report.horizon_age_seconds = blockers[0].duration_seconds

        return report
