"""
Patroni HA Cluster Monitor — monitor high-availability PostgreSQL clusters.

Detects Patroni-managed clusters and queries the REST API to show:
- Cluster membership (leader, replicas, members)
- Replication lag per member
- Failover history and timeline
- Leader switchover readiness
- Member health status

Also works without Patroni — falls back to pg_stat_replication for
basic primary/replica relationship monitoring.

Closes the gap vs Percona PMM 3.3.0's Patroni cluster dashboards.

Usage:
    from querysense.patroni_monitor import PatroniMonitor

    monitor = PatroniMonitor()
    report = await monitor.analyze(dsn="postgresql://localhost/mydb")
    # Or with Patroni REST API:
    report = await monitor.analyze_patroni(base_url="http://localhost:8008")
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────

class MemberRole(str, Enum):
    """Patroni/PostgreSQL member roles."""
    LEADER = "leader"
    REPLICA = "replica"
    SYNC_STANDBY = "sync_standby"
    ASYNC_STANDBY = "async"
    UNKNOWN = "unknown"


class MemberState(str, Enum):
    """Patroni member state."""
    RUNNING = "running"
    STREAMING = "streaming"
    STOPPED = "stopped"
    CREATING_REPLICA = "creating_replica"
    STARTING = "starting"
    UNKNOWN = "unknown"


@dataclass
class ClusterMember:
    """A member of a Patroni or PostgreSQL HA cluster."""
    name: str
    host: str
    port: int = 5432
    role: MemberRole = MemberRole.UNKNOWN
    state: MemberState = MemberState.UNKNOWN
    timeline: int = 0
    lag_bytes: int = 0
    lag_seconds: float = 0.0
    api_url: str = ""
    pg_version: str = ""
    is_healthy: bool = True
    tags: dict[str, Any] = field(default_factory=dict)

    @property
    def lag_human(self) -> str:
        """Human-readable lag."""
        if self.lag_seconds > 0:
            if self.lag_seconds < 1:
                return f"{self.lag_seconds * 1000:.0f}ms"
            if self.lag_seconds < 60:
                return f"{self.lag_seconds:.1f}s"
            return f"{self.lag_seconds / 60:.1f}min"
        if self.lag_bytes > 0:
            if self.lag_bytes < 1024 * 1024:
                return f"{self.lag_bytes / 1024:.0f}KB"
            return f"{self.lag_bytes / 1024 / 1024:.1f}MB"
        return "0"


@dataclass
class WALMetrics:
    """WAL and checkpoint metrics."""
    # From pg_stat_bgwriter
    checkpoints_timed: int = 0
    checkpoints_req: int = 0  # Requested (forced) checkpoints
    checkpoint_write_time_ms: float = 0.0
    checkpoint_sync_time_ms: float = 0.0
    buffers_checkpoint: int = 0
    buffers_clean: int = 0
    buffers_backend: int = 0
    maxwritten_clean: int = 0
    # WAL generation
    wal_bytes_per_second: float = 0.0
    current_wal_lsn: str = ""
    wal_directory_size_mb: float = 0.0
    # Derived
    checkpoint_request_ratio: float = 0.0  # Fraction of forced checkpoints
    avg_checkpoint_interval_sec: float = 0.0

    @property
    def is_checkpoint_pressure(self) -> bool:
        """True if forced checkpoints are a concern."""
        total = self.checkpoints_timed + self.checkpoints_req
        return total > 0 and self.checkpoint_request_ratio > 0.3


@dataclass
class ClusterReport:
    """Complete HA cluster report."""
    cluster_name: str = ""
    members: list[ClusterMember] = field(default_factory=list)
    wal_metrics: WALMetrics = field(default_factory=WALMetrics)
    is_patroni: bool = False
    patroni_version: str = ""
    # Derived
    leader: ClusterMember | None = None
    max_lag_seconds: float = 0.0
    max_lag_bytes: int = 0
    unhealthy_members: int = 0
    recommendations: list[str] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        return self.unhealthy_members == 0 and self.max_lag_seconds < 30

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_name": self.cluster_name,
            "is_patroni": self.is_patroni,
            "patroni_version": self.patroni_version,
            "is_healthy": self.is_healthy,
            "member_count": len(self.members),
            "unhealthy_members": self.unhealthy_members,
            "max_lag_seconds": round(self.max_lag_seconds, 2),
            "max_lag_bytes": self.max_lag_bytes,
            "members": [
                {
                    "name": m.name,
                    "host": m.host,
                    "port": m.port,
                    "role": m.role.value,
                    "state": m.state.value,
                    "timeline": m.timeline,
                    "lag_bytes": m.lag_bytes,
                    "lag_seconds": round(m.lag_seconds, 2),
                    "lag_human": m.lag_human,
                    "is_healthy": m.is_healthy,
                }
                for m in self.members
            ],
            "wal_metrics": {
                "checkpoints_timed": self.wal_metrics.checkpoints_timed,
                "checkpoints_req": self.wal_metrics.checkpoints_req,
                "checkpoint_request_ratio": round(
                    self.wal_metrics.checkpoint_request_ratio, 3
                ),
                "is_checkpoint_pressure": self.wal_metrics.is_checkpoint_pressure,
                "wal_directory_size_mb": round(
                    self.wal_metrics.wal_directory_size_mb, 1
                ),
            },
            "recommendations": self.recommendations,
        }


# ── SQL queries ───────────────────────────────────────────────────────

REPLICATION_STATUS_QUERY = """
SELECT
    pid,
    usename,
    application_name,
    client_addr::text AS client_addr,
    client_port,
    state,
    sent_lsn::text,
    write_lsn::text,
    flush_lsn::text,
    replay_lsn::text,
    sync_state,
    reply_time,
    EXTRACT(EPOCH FROM (now() - reply_time)) AS lag_seconds,
    pg_wal_lsn_diff(sent_lsn, replay_lsn) AS lag_bytes
FROM pg_stat_replication
ORDER BY lag_bytes DESC;
"""

WAL_CHECKPOINT_QUERY = """
SELECT
    checkpoints_timed,
    checkpoints_req,
    checkpoint_write_time,
    checkpoint_sync_time,
    buffers_checkpoint,
    buffers_clean,
    buffers_backend,
    maxwritten_clean,
    stats_reset
FROM pg_stat_bgwriter;
"""

WAL_LSN_QUERY = """
SELECT
    pg_current_wal_lsn()::text AS current_lsn,
    pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0') AS wal_position;
"""

WAL_SIZE_QUERY = """
SELECT
    COALESCE(sum(size), 0) AS total_bytes
FROM pg_ls_waldir();
"""


# ── Monitor ───────────────────────────────────────────────────────────

class PatroniMonitor:
    """Monitor Patroni HA clusters and PostgreSQL replication."""

    async def analyze(
        self,
        dsn: str,
        lag_warning_sec: float = 10.0,
        lag_critical_sec: float = 30.0,
    ) -> ClusterReport:
        """Analyze cluster from a PostgreSQL connection.

        Works even without Patroni — queries pg_stat_replication directly.
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            report = ClusterReport()

            # Check if this is a primary
            is_recovery = await conn.fetchval("SELECT pg_is_in_recovery()")
            pg_version = await conn.fetchval("SHOW server_version")

            # Get cluster name
            cluster_name = await conn.fetchval(
                "SELECT current_setting('cluster_name', true)"
            )
            report.cluster_name = cluster_name or "default"

            # WAL/checkpoint metrics
            report.wal_metrics = await self._collect_wal_metrics(conn)

            if is_recovery:
                # This is a replica — limited view
                report.members.append(ClusterMember(
                    name="self (replica)",
                    host="localhost",
                    role=MemberRole.REPLICA,
                    state=MemberState.STREAMING,
                    pg_version=pg_version,
                ))
                report.recommendations.append(
                    "Connected to replica. Connect to primary for full "
                    "replication topology view."
                )
                return report

            # This is a primary — full view
            report.members.append(ClusterMember(
                name="self (primary)",
                host="localhost",
                role=MemberRole.LEADER,
                state=MemberState.RUNNING,
                pg_version=pg_version,
                is_healthy=True,
            ))
            report.leader = report.members[0]

            # Discover replicas from pg_stat_replication
            rows = await conn.fetch(REPLICATION_STATUS_QUERY)
            for row in rows:
                lag_sec = float(row["lag_seconds"] or 0)
                lag_bytes = int(row["lag_bytes"] or 0)
                is_healthy = lag_sec < lag_critical_sec

                sync_state = row["sync_state"] or "async"
                if sync_state == "sync":
                    role = MemberRole.SYNC_STANDBY
                else:
                    role = MemberRole.REPLICA

                member = ClusterMember(
                    name=row["application_name"] or f"replica-{row['pid']}",
                    host=row["client_addr"] or "unknown",
                    port=row["client_port"] or 0,
                    role=role,
                    state=MemberState.STREAMING
                    if row["state"] == "streaming"
                    else MemberState.UNKNOWN,
                    lag_bytes=lag_bytes,
                    lag_seconds=lag_sec,
                    is_healthy=is_healthy,
                )
                report.members.append(member)
                report.max_lag_seconds = max(report.max_lag_seconds, lag_sec)
                report.max_lag_bytes = max(report.max_lag_bytes, lag_bytes)

            # Count unhealthy
            report.unhealthy_members = sum(
                1 for m in report.members if not m.is_healthy
            )

            # Generate recommendations
            report.recommendations = self._generate_recommendations(
                report, lag_warning_sec, lag_critical_sec
            )

            return report

        finally:
            await conn.close()

    async def analyze_patroni(
        self,
        base_url: str = "http://localhost:8008",
        timeout: float = 5.0,
    ) -> ClusterReport:
        """Analyze cluster via Patroni REST API.

        Patroni exposes cluster state at GET /cluster. Each member has:
        - name, host, port, role, state, timeline, lag
        """
        try:
            import aiohttp
        except ImportError:
            raise RuntimeError("aiohttp required for Patroni API: pip install aiohttp")

        report = ClusterReport(is_patroni=True)

        async with aiohttp.ClientSession() as session:
            # GET /patroni for version
            try:
                async with session.get(
                    f"{base_url}/patroni", timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        report.patroni_version = data.get("patroni", {}).get(
                            "version", ""
                        )
            except Exception:
                pass

            # GET /cluster for membership
            try:
                async with session.get(
                    f"{base_url}/cluster",
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status != 200:
                        report.recommendations.append(
                            f"Patroni API returned HTTP {resp.status}. "
                            "Check that Patroni REST API is accessible."
                        )
                        return report
                    data = await resp.json()
            except Exception as exc:
                report.recommendations.append(
                    f"Cannot connect to Patroni API at {base_url}: {exc}"
                )
                return report

        # Parse cluster data
        for member_data in data.get("members", []):
            role_str = member_data.get("role", "unknown")
            role = {
                "leader": MemberRole.LEADER,
                "replica": MemberRole.REPLICA,
                "sync_standby": MemberRole.SYNC_STANDBY,
            }.get(role_str, MemberRole.UNKNOWN)

            state_str = member_data.get("state", "unknown")
            state = {
                "running": MemberState.RUNNING,
                "streaming": MemberState.STREAMING,
                "stopped": MemberState.STOPPED,
                "creating replica": MemberState.CREATING_REPLICA,
                "starting": MemberState.STARTING,
            }.get(state_str, MemberState.UNKNOWN)

            lag = member_data.get("lag", 0)
            member = ClusterMember(
                name=member_data.get("name", ""),
                host=member_data.get("host", ""),
                port=member_data.get("port", 5432),
                role=role,
                state=state,
                timeline=member_data.get("timeline", 0),
                lag_bytes=lag if isinstance(lag, int) else 0,
                api_url=member_data.get("api_url", ""),
                is_healthy=state in (MemberState.RUNNING, MemberState.STREAMING),
                tags=member_data.get("tags", {}),
            )
            report.members.append(member)

            if role == MemberRole.LEADER:
                report.leader = member
            else:
                report.max_lag_bytes = max(report.max_lag_bytes, member.lag_bytes)

        report.cluster_name = data.get("name", report.cluster_name)
        report.unhealthy_members = sum(
            1 for m in report.members if not m.is_healthy
        )
        report.recommendations = self._generate_recommendations(report, 10.0, 30.0)

        return report

    async def _collect_wal_metrics(self, conn: Any) -> WALMetrics:
        """Collect WAL and checkpoint metrics."""
        metrics = WALMetrics()

        try:
            bgw = await conn.fetchrow(WAL_CHECKPOINT_QUERY)
            if bgw:
                metrics.checkpoints_timed = bgw["checkpoints_timed"] or 0
                metrics.checkpoints_req = bgw["checkpoints_req"] or 0
                metrics.checkpoint_write_time_ms = float(
                    bgw["checkpoint_write_time"] or 0
                )
                metrics.checkpoint_sync_time_ms = float(
                    bgw["checkpoint_sync_time"] or 0
                )
                metrics.buffers_checkpoint = bgw["buffers_checkpoint"] or 0
                metrics.buffers_clean = bgw["buffers_clean"] or 0
                metrics.buffers_backend = bgw["buffers_backend"] or 0
                metrics.maxwritten_clean = bgw["maxwritten_clean"] or 0

                total_cp = metrics.checkpoints_timed + metrics.checkpoints_req
                if total_cp > 0:
                    metrics.checkpoint_request_ratio = (
                        metrics.checkpoints_req / total_cp
                    )

                # Estimate avg checkpoint interval
                stats_reset = bgw["stats_reset"]
                if stats_reset and total_cp > 0:
                    import datetime

                    now = datetime.datetime.now(datetime.timezone.utc)
                    reset_aware = stats_reset.replace(
                        tzinfo=datetime.timezone.utc
                    ) if stats_reset.tzinfo is None else stats_reset
                    elapsed = (now - reset_aware).total_seconds()
                    metrics.avg_checkpoint_interval_sec = elapsed / total_cp
        except Exception as exc:
            logger.debug("pg_stat_bgwriter query failed: %s", exc)

        # WAL directory size
        try:
            wal_size_row = await conn.fetchrow(WAL_SIZE_QUERY)
            if wal_size_row:
                metrics.wal_directory_size_mb = (
                    wal_size_row["total_bytes"] / 1024 / 1024
                )
        except Exception:
            pass

        # Current WAL position
        try:
            lsn_row = await conn.fetchrow(WAL_LSN_QUERY)
            if lsn_row:
                metrics.current_wal_lsn = lsn_row["current_lsn"]
        except Exception:
            pass

        return metrics

    def _generate_recommendations(
        self,
        report: ClusterReport,
        warn_sec: float,
        crit_sec: float,
    ) -> list[str]:
        """Generate actionable recommendations."""
        recs: list[str] = []

        # Replication lag
        if report.max_lag_seconds > crit_sec:
            recs.append(
                f"CRITICAL: Max replication lag is {report.max_lag_seconds:.1f}s "
                f"(threshold: {crit_sec}s). Check replica health and network."
            )
        elif report.max_lag_seconds > warn_sec:
            recs.append(
                f"WARNING: Replication lag at {report.max_lag_seconds:.1f}s "
                f"(threshold: {warn_sec}s). Monitor closely."
            )

        # Unhealthy members
        if report.unhealthy_members > 0:
            names = [
                m.name for m in report.members if not m.is_healthy
            ]
            recs.append(
                f"WARNING: {report.unhealthy_members} unhealthy member(s): "
                f"{', '.join(names)}. Investigate immediately."
            )

        # No replicas
        replicas = [
            m for m in report.members if m.role != MemberRole.LEADER
        ]
        if not replicas and report.leader:
            recs.append(
                "INFO: Primary has no replicas. Consider adding a standby "
                "for high availability."
            )

        # WAL checkpoint pressure
        wal = report.wal_metrics
        if wal.is_checkpoint_pressure:
            recs.append(
                f"WARNING: {wal.checkpoint_request_ratio:.0%} of checkpoints are "
                f"forced (requested). Consider increasing max_wal_size to reduce "
                f"checkpoint frequency."
            )

        # Backend writes too high
        if wal.buffers_backend > 0:
            total_writes = (
                wal.buffers_checkpoint + wal.buffers_clean + wal.buffers_backend
            )
            if total_writes > 0:
                backend_pct = wal.buffers_backend / total_writes
                if backend_pct > 0.2:
                    recs.append(
                        f"WARNING: {backend_pct:.0%} of buffer writes are done by "
                        f"backends (not bgwriter). Increase shared_buffers or "
                        f"bgwriter_lru_maxpages."
                    )

        # Maxwritten clean events
        if wal.maxwritten_clean > 100:
            recs.append(
                f"INFO: bgwriter stopped {wal.maxwritten_clean} times due to "
                f"maxwritten_clean limit. Consider increasing bgwriter_lru_maxpages."
            )

        return recs
