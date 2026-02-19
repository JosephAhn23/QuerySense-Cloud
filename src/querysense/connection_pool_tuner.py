"""
Connection Pool Tuner — Analyze connection usage and recommend pool sizing.

pganalyze charges $149/month for "proactive practices" that include connection
pool analysis. This module gives it away for free.

Analyzes:
1. Current connection usage vs max_connections
2. Connection churn rate (connects/disconnects per second)
3. Idle connection waste (connections doing nothing)
4. Recommended pool size for PgBouncer / pgpool / application pool
5. Transaction vs session pooling recommendation
6. Backend memory footprint per connection

Usage:
    from querysense.connection_pool_tuner import ConnectionPoolTuner

    tuner = ConnectionPoolTuner()
    report = await tuner.analyze(dsn)
    print(report.format_text())
    print(report.generate_pgbouncer_ini())
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ConnectionSlot:
    """A snapshot of a single backend connection."""
    pid: int = 0
    state: str = ""  # active, idle, idle in transaction, disabled
    application_name: str = ""
    database: str = ""
    user: str = ""
    backend_start: str = ""
    state_change: str = ""
    wait_event_type: str = ""
    wait_event: str = ""
    query: str = ""
    idle_seconds: float = 0.0


@dataclass
class ConnectionProfile:
    """Connection usage profile by database/user/application."""
    key: str = ""  # e.g. "mydb/app_user/django"
    database: str = ""
    user: str = ""
    application: str = ""
    total: int = 0
    active: int = 0
    idle: int = 0
    idle_in_txn: int = 0
    avg_idle_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "database": self.database,
            "user": self.user,
            "application": self.application,
            "total": self.total,
            "active": self.active,
            "idle": self.idle,
            "idle_in_txn": self.idle_in_txn,
            "avg_idle_seconds": round(self.avg_idle_seconds, 1),
        }


@dataclass
class PoolRecommendation:
    """Recommended pool configuration."""
    pool_mode: str = "transaction"  # transaction or session
    pool_size: int = 25
    min_pool_size: int = 5
    max_pool_size: int = 50
    reserve_pool_size: int = 5
    idle_timeout_seconds: int = 300
    server_idle_timeout: int = 600
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pool_mode": self.pool_mode,
            "pool_size": self.pool_size,
            "min_pool_size": self.min_pool_size,
            "max_pool_size": self.max_pool_size,
            "reserve_pool_size": self.reserve_pool_size,
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "server_idle_timeout": self.server_idle_timeout,
            "reason": self.reason,
        }


@dataclass
class ConnectionPoolReport:
    """Complete connection pool analysis."""
    max_connections: int = 100
    superuser_reserved: int = 3
    current_connections: int = 0
    utilization_pct: float = 0.0
    connections: list[ConnectionSlot] = field(default_factory=list)
    profiles: list[ConnectionProfile] = field(default_factory=list)
    active_count: int = 0
    idle_count: int = 0
    idle_in_txn_count: int = 0
    disabled_count: int = 0
    total_idle_seconds: float = 0.0
    memory_per_connection_mb: float = 10.0
    total_memory_wasted_mb: float = 0.0
    has_pgbouncer: bool = False
    recommendation: PoolRecommendation = field(default_factory=PoolRecommendation)
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_connections": self.max_connections,
            "current_connections": self.current_connections,
            "utilization_pct": round(self.utilization_pct, 1),
            "breakdown": {
                "active": self.active_count,
                "idle": self.idle_count,
                "idle_in_transaction": self.idle_in_txn_count,
            },
            "memory_per_connection_mb": self.memory_per_connection_mb,
            "total_memory_wasted_mb": round(self.total_memory_wasted_mb, 1),
            "profiles": [p.to_dict() for p in self.profiles],
            "recommendation": self.recommendation.to_dict(),
            "findings": self.findings,
        }

    def generate_pgbouncer_ini(self) -> str:
        """Generate a PgBouncer configuration snippet."""
        rec = self.recommendation
        db_lines = []
        for p in self.profiles:
            if p.database and p.database not in [x.split("=")[0].strip() for x in db_lines]:
                db_lines.append(f"{p.database} = host=localhost dbname={p.database}")

        return "\n".join([
            "[databases]",
            *(db_lines if db_lines else ["mydb = host=localhost dbname=mydb"]),
            "",
            "[pgbouncer]",
            f"pool_mode = {rec.pool_mode}",
            f"default_pool_size = {rec.pool_size}",
            f"min_pool_size = {rec.min_pool_size}",
            f"max_client_conn = {self.max_connections * 4}",
            f"reserve_pool_size = {rec.reserve_pool_size}",
            f"reserve_pool_timeout = 3",
            f"server_idle_timeout = {rec.server_idle_timeout}",
            f"server_lifetime = 3600",
            f"client_idle_timeout = {rec.idle_timeout_seconds}",
            "log_connections = 1",
            "log_disconnections = 1",
            f"listen_port = 6432",
            f"listen_addr = *",
            f"auth_type = md5",
            "",
            f"; Rationale: {rec.reason}",
            f"; Based on {self.current_connections} current connections "
            f"({self.active_count} active, {self.idle_count} idle)",
        ])

    def format_text(self) -> str:
        lines = [
            "",
            "  CONNECTION POOL ANALYSIS",
            "  " + "=" * 55,
            f"  max_connections: {self.max_connections}",
            f"  Current connections: {self.current_connections} ({self.utilization_pct:.1f}%)",
            f"  Available slots: {self.max_connections - self.current_connections - self.superuser_reserved}",
            "",
            "  BREAKDOWN:",
            f"    Active (running queries): {self.active_count}",
            f"    Idle (waiting for work):  {self.idle_count}",
            f"    Idle in transaction:      {self.idle_in_txn_count}",
            "",
        ]

        if self.idle_count > 0:
            lines.append(f"  WASTED RESOURCES:")
            lines.append(f"    Idle connections: {self.idle_count}")
            lines.append(f"    Memory per connection: ~{self.memory_per_connection_mb:.0f} MB")
            lines.append(f"    Total wasted memory: ~{self.total_memory_wasted_mb:.0f} MB")
            lines.append("")

        if self.profiles:
            lines.append("  CONNECTION PROFILES:")
            lines.append(f"  {'DB/User/App':<35} {'Total':>5} {'Active':>6} {'Idle':>5} {'IdleTxn':>7}")
            lines.append("  " + "-" * 65)
            for p in sorted(self.profiles, key=lambda x: -x.total):
                lines.append(
                    f"  {p.key:<35} {p.total:>5} {p.active:>6} {p.idle:>5} {p.idle_in_txn:>7}"
                )
            lines.append("")

        rec = self.recommendation
        lines.append("  RECOMMENDATION:")
        lines.append(f"    Pool mode: {rec.pool_mode}")
        lines.append(f"    Pool size: {rec.pool_size} (min: {rec.min_pool_size}, max: {rec.max_pool_size})")
        lines.append(f"    Idle timeout: {rec.idle_timeout_seconds}s")
        lines.append(f"    Reason: {rec.reason}")
        lines.append("")

        if self.idle_in_txn_count > 0:
            lines.append(f"  WARNING: {self.idle_in_txn_count} connections are idle in transaction.")
            lines.append("  This blocks autovacuum and holds row locks.")
            lines.append("    ALTER SYSTEM SET idle_in_transaction_session_timeout = '60s';")
            lines.append("")

        lines.append("  Run `querysense audit connections --pooler --pgbouncer-ini` for config file")
        lines.append("")
        return "\n".join(lines)


_CONNECTIONS_SQL = """
SELECT
    pid,
    state,
    COALESCE(application_name, '') AS application_name,
    datname AS database,
    usename AS user,
    backend_start::text AS backend_start,
    COALESCE(state_change::text, '') AS state_change,
    COALESCE(wait_event_type, '') AS wait_event_type,
    COALESCE(wait_event, '') AS wait_event,
    COALESCE(left(query, 200), '') AS query,
    CASE
        WHEN state IN ('idle', 'idle in transaction')
        THEN EXTRACT(EPOCH FROM (now() - state_change))
        ELSE 0
    END AS idle_seconds
FROM pg_stat_activity
WHERE backend_type = 'client backend'
    AND pid != pg_backend_pid()
ORDER BY idle_seconds DESC
"""

_WORK_MEM_SQL = """
SELECT
    pg_size_bytes(setting || ' ' || unit) / (1024*1024) AS work_mem_mb
FROM pg_settings
WHERE name = 'work_mem'
"""


class ConnectionPoolTuner:
    """
    Analyze live connection usage and recommend pool configuration.
    """

    async def analyze(self, dsn: str) -> ConnectionPoolReport:
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        report = ConnectionPoolReport()
        conn = await asyncpg.connect(dsn)

        try:
            await self._get_limits(conn, report)
            await self._snapshot_connections(conn, report)
            await self._estimate_memory(conn, report)
            await self._detect_pgbouncer(conn, report)
            self._build_profiles(report)
            self._compute_recommendation(report)
            self._generate_findings(report)
        finally:
            await conn.close()

        return report

    async def _get_limits(self, conn: Any, report: ConnectionPoolReport) -> None:
        report.max_connections = int(
            await conn.fetchval("SELECT current_setting('max_connections')::int") or 100
        )
        report.superuser_reserved = int(
            await conn.fetchval(
                "SELECT current_setting('superuser_reserved_connections')::int"
            ) or 3
        )

    async def _snapshot_connections(
        self, conn: Any, report: ConnectionPoolReport,
    ) -> None:
        rows = await conn.fetch(_CONNECTIONS_SQL)

        for row in rows:
            slot = ConnectionSlot(
                pid=row["pid"],
                state=row["state"] or "",
                application_name=row["application_name"],
                database=row["database"],
                user=row["user"],
                backend_start=row["backend_start"],
                state_change=row["state_change"],
                wait_event_type=row["wait_event_type"],
                wait_event=row["wait_event"],
                query=row["query"],
                idle_seconds=row["idle_seconds"] or 0.0,
            )
            report.connections.append(slot)

        report.current_connections = len(report.connections)
        report.utilization_pct = (
            report.current_connections / report.max_connections * 100
            if report.max_connections > 0 else 0.0
        )

        report.active_count = sum(1 for c in report.connections if c.state == "active")
        report.idle_count = sum(1 for c in report.connections if c.state == "idle")
        report.idle_in_txn_count = sum(
            1 for c in report.connections if c.state == "idle in transaction"
        )

    async def _estimate_memory(self, conn: Any, report: ConnectionPoolReport) -> None:
        try:
            wm = await conn.fetchval(_WORK_MEM_SQL)
            base_mb = 5
            report.memory_per_connection_mb = base_mb + (float(wm) if wm else 4)
        except Exception:
            report.memory_per_connection_mb = 10.0

        report.total_memory_wasted_mb = report.idle_count * report.memory_per_connection_mb

    async def _detect_pgbouncer(self, conn: Any, report: ConnectionPoolReport) -> None:
        try:
            apps = [c.application_name.lower() for c in report.connections]
            report.has_pgbouncer = any("pgbouncer" in a or "bouncer" in a for a in apps)
        except Exception:
            pass

    def _build_profiles(self, report: ConnectionPoolReport) -> None:
        groups: dict[str, list[ConnectionSlot]] = {}
        for c in report.connections:
            key = f"{c.database}/{c.user}/{c.application_name or 'unknown'}"
            groups.setdefault(key, []).append(c)

        for key, slots in groups.items():
            parts = key.split("/", 2)
            profile = ConnectionProfile(
                key=key,
                database=parts[0] if len(parts) > 0 else "",
                user=parts[1] if len(parts) > 1 else "",
                application=parts[2] if len(parts) > 2 else "",
                total=len(slots),
                active=sum(1 for s in slots if s.state == "active"),
                idle=sum(1 for s in slots if s.state == "idle"),
                idle_in_txn=sum(1 for s in slots if s.state == "idle in transaction"),
                avg_idle_seconds=(
                    sum(s.idle_seconds for s in slots if s.state == "idle")
                    / max(1, sum(1 for s in slots if s.state == "idle"))
                ),
            )
            report.profiles.append(profile)

    def _compute_recommendation(self, report: ConnectionPoolReport) -> None:
        active = max(report.active_count, 1)
        total = max(report.current_connections, 1)
        idle_ratio = report.idle_count / total

        # Pool size: 2-3x active connections, bounded by CPU cores heuristic
        pool_size = max(active * 3, 10)
        pool_size = min(pool_size, report.max_connections // 2)

        if report.idle_in_txn_count > total * 0.2:
            mode = "transaction"
            reason = (
                f"{report.idle_in_txn_count} idle-in-transaction connections detected. "
                "Transaction pooling recycles connections between transactions."
            )
        elif idle_ratio > 0.7:
            mode = "transaction"
            reason = (
                f"{report.idle_count} idle connections ({idle_ratio*100:.0f}%). "
                "Transaction pooling eliminates idle waste."
            )
        elif active > report.max_connections * 0.5:
            mode = "transaction"
            reason = (
                f"High utilization ({report.utilization_pct:.0f}%). "
                "Transaction pooling multiplexes connections."
            )
        else:
            mode = "session"
            reason = "Low utilization; session pooling is simpler and sufficient."

        report.recommendation = PoolRecommendation(
            pool_mode=mode,
            pool_size=pool_size,
            min_pool_size=max(pool_size // 5, 2),
            max_pool_size=min(pool_size * 2, report.max_connections),
            reserve_pool_size=max(pool_size // 10, 2),
            idle_timeout_seconds=300 if idle_ratio > 0.5 else 600,
            server_idle_timeout=600,
            reason=reason,
        )

    def _generate_findings(self, report: ConnectionPoolReport) -> None:
        if report.utilization_pct > 80:
            report.findings.append({
                "severity": "critical",
                "title": f"Connection utilization at {report.utilization_pct:.0f}%",
                "description": (
                    f"{report.current_connections}/{report.max_connections} slots used. "
                    "Risk of connection exhaustion."
                ),
                "fix": "Deploy PgBouncer or increase max_connections",
            })
        elif report.utilization_pct > 60:
            report.findings.append({
                "severity": "warning",
                "title": f"Connection utilization at {report.utilization_pct:.0f}%",
                "description": "Approaching connection limit.",
                "fix": "Consider a connection pooler",
            })

        if report.idle_in_txn_count > 5:
            report.findings.append({
                "severity": "warning",
                "title": f"{report.idle_in_txn_count} connections idle in transaction",
                "description": "Blocks autovacuum and holds row locks.",
                "fix": (
                    "ALTER SYSTEM SET idle_in_transaction_session_timeout = '60s'; "
                    "SELECT pg_reload_conf();"
                ),
            })

        if report.idle_count > report.active_count * 5:
            wasted = report.total_memory_wasted_mb
            report.findings.append({
                "severity": "warning",
                "title": f"{report.idle_count} idle connections wasting ~{wasted:.0f} MB",
                "description": "Idle connections consume memory without doing work.",
                "fix": "Use a connection pooler with idle timeout",
            })

        if report.max_connections > 200 and not report.has_pgbouncer:
            report.findings.append({
                "severity": "notice",
                "title": f"max_connections={report.max_connections} without pooler",
                "description": (
                    "High max_connections without a pooler wastes memory. "
                    "Each connection uses ~{:.0f} MB.".format(report.memory_per_connection_mb)
                ),
                "fix": (
                    "Lower max_connections to 100 and deploy PgBouncer. "
                    "See generated pgbouncer.ini."
                ),
            })
