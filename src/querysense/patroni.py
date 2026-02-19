"""
Patroni HA Cluster Integration.

Detects and monitors Patroni-managed PostgreSQL clusters by querying the
Patroni REST API. Provides failover tracking, leader/replica status, and
cluster health monitoring.

Patroni exposes a REST API on each node (default port 8008):
    GET /cluster       → cluster topology, members, leader
    GET /patroni       → node status, timeline, role
    GET /health        → HTTP 200 if healthy
    GET /primary       → HTTP 200 if primary
    GET /replica       → HTTP 200 if replica
    GET /history       → failover history

This integrates with QuerySense's ClusterDetector to auto-detect
Patroni-managed clusters without manual configuration.

Usage:
    from querysense.patroni import PatroniClient, PatroniCluster

    client = PatroniClient("http://patroni-node:8008")
    cluster = await client.get_cluster()
    for member in cluster.members:
        print(f"{member.name}: {member.role} ({member.state})")

    # Or auto-detect from DSN:
    from querysense.patroni import detect_patroni
    patroni = await detect_patroni(dsn="postgresql://primary:5432/mydb")
    if patroni:
        cluster = await patroni.get_cluster()
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


@dataclass
class PatroniMember:
    """A member (node) in a Patroni cluster."""
    name: str
    host: str
    port: int = 5432
    role: str = ""  # leader, replica, sync_standby
    state: str = ""  # running, streaming, stopped
    timeline: int = 0
    lag: int = 0  # Replication lag in bytes
    api_url: str = ""
    tags: dict[str, Any] = field(default_factory=dict)

    @property
    def is_leader(self) -> bool:
        return self.role in ("leader", "master", "primary")

    @property
    def is_replica(self) -> bool:
        return self.role in ("replica", "sync_standby", "async")

    @property
    def is_healthy(self) -> bool:
        return self.state in ("running", "streaming")

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.host}:{self.port}"


@dataclass
class PatroniCluster:
    """A Patroni-managed PostgreSQL cluster."""
    cluster_name: str = ""
    members: list[PatroniMember] = field(default_factory=list)
    scope: str = ""
    patroni_version: str = ""

    @property
    def leader(self) -> PatroniMember | None:
        for m in self.members:
            if m.is_leader:
                return m
        return None

    @property
    def replicas(self) -> list[PatroniMember]:
        return [m for m in self.members if m.is_replica]

    @property
    def healthy_replicas(self) -> list[PatroniMember]:
        return [m for m in self.replicas if m.is_healthy]

    @property
    def unhealthy_members(self) -> list[PatroniMember]:
        return [m for m in self.members if not m.is_healthy]

    @property
    def is_healthy(self) -> bool:
        return self.leader is not None and all(m.is_healthy for m in self.members)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_name": self.cluster_name,
            "scope": self.scope,
            "patroni_version": self.patroni_version,
            "is_healthy": self.is_healthy,
            "members": [
                {
                    "name": m.name,
                    "host": m.host,
                    "port": m.port,
                    "role": m.role,
                    "state": m.state,
                    "timeline": m.timeline,
                    "lag": m.lag,
                    "is_healthy": m.is_healthy,
                }
                for m in self.members
            ],
        }


@dataclass
class FailoverEvent:
    """A failover event from Patroni history."""
    timeline: int
    timestamp: str
    old_leader: str
    new_leader: str
    reason: str = ""


@dataclass
class PatroniHealth:
    """Health assessment of a Patroni cluster."""
    cluster: PatroniCluster
    findings: list[dict[str, Any]] = field(default_factory=list)
    failover_history: list[FailoverEvent] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        return self.cluster.is_healthy and not any(
            f.get("severity") in ("critical", "error") for f in self.findings
        )


class PatroniClient:
    """
    Client for the Patroni REST API.

    Patroni REST API endpoints:
        /cluster    → Full cluster topology
        /patroni    → Node status
        /health     → Health check (200/503)
        /primary    → Primary check (200/503)
        /replica    → Replica check (200/503)
        /history    → Failover history
        /config     → Patroni configuration
    """

    def __init__(
        self,
        api_url: str,
        timeout: int = 5,
    ) -> None:
        """
        Initialize Patroni client.

        Args:
            api_url: Patroni REST API URL (e.g., http://node:8008)
            timeout: Request timeout in seconds
        """
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    async def get_cluster(self) -> PatroniCluster:
        """Get full cluster topology."""
        data = self._request("/cluster")
        if not data:
            return PatroniCluster()

        cluster = PatroniCluster(
            scope=data.get("scope", ""),
            patroni_version=data.get("patroni", {}).get("version", ""),
        )
        cluster.cluster_name = data.get("scope", "")

        for member_data in data.get("members", []):
            member = PatroniMember(
                name=member_data.get("name", ""),
                host=member_data.get("host", ""),
                port=member_data.get("port", 5432),
                role=member_data.get("role", ""),
                state=member_data.get("state", ""),
                timeline=member_data.get("timeline", 0),
                lag=member_data.get("lag", 0),
                api_url=member_data.get("api_url", ""),
                tags=member_data.get("tags", {}),
            )
            cluster.members.append(member)

        return cluster

    async def get_node_status(self) -> dict[str, Any]:
        """Get status of the local node."""
        return self._request("/patroni") or {}

    async def is_healthy(self) -> bool:
        """Check if the node is healthy (HTTP 200)."""
        try:
            self._request("/health")
            return True
        except Exception:
            return False

    async def is_primary(self) -> bool:
        """Check if the node is the primary."""
        try:
            self._request("/primary")
            return True
        except Exception:
            return False

    async def is_replica(self) -> bool:
        """Check if the node is a replica."""
        try:
            self._request("/replica")
            return True
        except Exception:
            return False

    async def get_history(self) -> list[FailoverEvent]:
        """Get failover history."""
        data = self._request("/history")
        if not data:
            return []

        events: list[FailoverEvent] = []
        for entry in data if isinstance(data, list) else data.get("history", []):
            if isinstance(entry, list) and len(entry) >= 4:
                events.append(FailoverEvent(
                    timeline=int(entry[0]),
                    timestamp=str(entry[2]) if len(entry) > 2 else "",
                    old_leader=str(entry[3]) if len(entry) > 3 else "",
                    new_leader=str(entry[4]) if len(entry) > 4 else "",
                    reason=str(entry[1]) if len(entry) > 1 else "",
                ))
            elif isinstance(entry, dict):
                events.append(FailoverEvent(
                    timeline=entry.get("timeline", 0),
                    timestamp=entry.get("timestamp", ""),
                    old_leader=entry.get("old_leader", ""),
                    new_leader=entry.get("new_leader", ""),
                    reason=entry.get("reason", ""),
                ))

        return events

    async def get_config(self) -> dict[str, Any]:
        """Get Patroni configuration."""
        return self._request("/config") or {}

    async def check_health(self) -> PatroniHealth:
        """Run comprehensive health check on the cluster."""
        cluster = await self.get_cluster()
        health = PatroniHealth(cluster=cluster)

        # Check leader
        if not cluster.leader:
            health.findings.append({
                "severity": "critical",
                "check": "no_leader",
                "description": "Cluster has no leader!",
                "remediation": "Check Patroni logs and DCS connectivity.",
            })

        # Check unhealthy members
        for member in cluster.unhealthy_members:
            health.findings.append({
                "severity": "error",
                "check": "unhealthy_member",
                "description": f"Member '{member.name}' ({member.host}) is {member.state}",
                "remediation": f"Check logs on {member.host}. Consider: patronictl reinit {cluster.scope} {member.name}",
            })

        # Check replica lag
        for replica in cluster.replicas:
            if replica.lag > 100_000_000:  # >100MB lag
                health.findings.append({
                    "severity": "warning",
                    "check": "replica_lag",
                    "description": (
                        f"Replica '{replica.name}' has {replica.lag // 1024 // 1024}MB lag"
                    ),
                    "remediation": "Check replica I/O and network. May need rewind or reinit.",
                })

        # Check timeline consistency
        timelines = set(m.timeline for m in cluster.members if m.timeline > 0)
        if len(timelines) > 1:
            health.findings.append({
                "severity": "warning",
                "check": "timeline_divergence",
                "description": f"Members on different timelines: {timelines}",
                "remediation": "Run: patronictl reinit for members on older timeline.",
            })

        # Get failover history
        try:
            health.failover_history = await self.get_history()
        except Exception:
            pass

        return health

    def _request(self, path: str) -> dict | list | None:
        """Make HTTP request to Patroni REST API."""
        url = f"{self.api_url}{path}"
        try:
            req = Request(url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body)
        except (URLError, json.JSONDecodeError, OSError) as e:
            logger.debug("Patroni request to %s failed: %s", url, e)
            return None


async def detect_patroni(
    dsn: str,
    patroni_port: int = 8008,
) -> PatroniClient | None:
    """
    Auto-detect Patroni by probing common API endpoints.

    Tries to connect to the Patroni REST API on the same host as the DSN.
    """
    import re
    # Extract host from DSN
    match = re.search(r"@([^/:]+)", dsn)
    host = match.group(1) if match else "localhost"

    # Try common Patroni ports
    for port in [patroni_port, 8008, 8009]:
        url = f"http://{host}:{port}"
        client = PatroniClient(url, timeout=3)
        try:
            status = await client.get_node_status()
            if status and "patroni" in status:
                logger.info("Detected Patroni at %s", url)
                return client
        except Exception:
            continue

    return None


async def detect_patroni_from_pg(dsn: str) -> PatroniClient | None:
    """
    Detect Patroni by checking PostgreSQL for Patroni-specific settings.

    Patroni sets specific GUCs and comments that can be detected.
    """
    try:
        import asyncpg
        conn = await asyncpg.connect(dsn, timeout=5)
        try:
            # Check for Patroni-specific settings/comments
            # Patroni sets application_name to the node name
            result = await conn.fetchval("""
                SELECT count(*) FROM pg_stat_activity
                WHERE application_name LIKE 'patroni%'
            """)
            if result and result > 0:
                # Patroni is managing this cluster, try to find API
                return await detect_patroni(dsn)

            # Check for Patroni comment in pg_settings
            result = await conn.fetchval("""
                SELECT count(*) FROM pg_settings
                WHERE source = 'configuration file'
                  AND name = 'cluster_name'
            """)
            if result and result > 0:
                return await detect_patroni(dsn)

        finally:
            await conn.close()
    except Exception:
        pass

    return None
