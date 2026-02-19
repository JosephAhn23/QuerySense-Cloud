"""
Cluster Detection and Management for PostgreSQL clusters.

Detects which PostgreSQL servers belong to the same cluster (primary + replicas)
so that the Index Advisor can produce globally optimal, cluster-wide recommendations.

Cluster detection methods (in priority order):
1. Manual: api_cluster_id in config or --cluster-id on CLI
2. Cloud provider: RDS/Aurora cluster ID, AlloyDB cluster, Crunchy Bridge
3. Automatic: pg_controldata "Database system identifier" — identical
   across all replicas streaming from the same primary

Design mirrors pganalyze's Feb 2026 cluster-aware Index Advisor:
- Primary is source of truth for all recommendations
- Scans from replicas are merged with primary scans before CP-SAT
- An index is only "unused" if unused across ALL servers in cluster
- Recommendations are grouped by (database, schema, table) across cluster

Usage:
    from querysense.cluster import ClusterDetector, ClusterTopology

    detector = ClusterDetector()
    cluster = await detector.detect(dsns=[primary_dsn, replica1_dsn, replica2_dsn])
    # Or auto-detect from a single DSN:
    cluster = await detector.detect_from_primary(primary_dsn)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ServerInfo:
    """Information about a single PostgreSQL server in a cluster."""
    dsn: str
    host: str = ""
    port: int = 5432
    system_identifier: str = ""  # From pg_controldata / pg_control_system()
    is_primary: bool = False
    is_replica: bool = False
    pg_version: str = ""
    cluster_id: str = ""  # Manual or cloud-provider cluster ID
    server_name: str = ""  # Human-readable label

    # Cloud provider metadata
    cloud_provider: str = ""  # aws, gcp, azure, crunchy, none
    cloud_cluster_id: str = ""  # Provider-specific cluster identifier
    cloud_instance_id: str = ""

    # Replication details
    replication_lag_bytes: int = 0
    replication_lag_seconds: float = 0.0
    recovery_is_paused: bool = False

    @property
    def label(self) -> str:
        if self.server_name:
            return self.server_name
        role = "primary" if self.is_primary else "replica"
        return f"{self.host}:{self.port} ({role})"


@dataclass
class ClusterTopology:
    """
    A detected PostgreSQL cluster: one primary + zero or more replicas.

    All servers share the same Database System Identifier or cluster_id.
    """
    cluster_id: str  # Unique identifier for this cluster
    primary: ServerInfo | None = None
    replicas: list[ServerInfo] = field(default_factory=list)
    detection_method: str = ""  # manual, cloud, system_identifier

    @property
    def all_servers(self) -> list[ServerInfo]:
        """All servers in the cluster (primary first)."""
        servers: list[ServerInfo] = []
        if self.primary:
            servers.append(self.primary)
        servers.extend(self.replicas)
        return servers

    @property
    def all_dsns(self) -> list[str]:
        return [s.dsn for s in self.all_servers]

    @property
    def primary_dsn(self) -> str | None:
        return self.primary.dsn if self.primary else None

    @property
    def replica_dsns(self) -> list[str]:
        return [r.dsn for r in self.replicas]

    @property
    def server_count(self) -> int:
        return len(self.all_servers)

    @property
    def is_standalone(self) -> bool:
        """True if cluster has no replicas (treated as single-server)."""
        return len(self.replicas) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "detection_method": self.detection_method,
            "server_count": self.server_count,
            "is_standalone": self.is_standalone,
            "primary": {
                "host": self.primary.host,
                "port": self.primary.port,
                "pg_version": self.primary.pg_version,
                "system_identifier": self.primary.system_identifier,
            } if self.primary else None,
            "replicas": [
                {
                    "host": r.host,
                    "port": r.port,
                    "pg_version": r.pg_version,
                    "lag_bytes": r.replication_lag_bytes,
                    "lag_seconds": r.replication_lag_seconds,
                }
                for r in self.replicas
            ],
        }


class ClusterDetector:
    """
    Detects PostgreSQL cluster topology from DSN(s).

    Three detection strategies:
    1. Manual cluster_id → group all servers with the same ID
    2. Cloud provider APIs → fetch cluster ID from RDS, AlloyDB, etc.
    3. System identifier → query pg_control_system() on each server
    """

    async def detect(
        self,
        dsns: list[str],
        cluster_id: str = "",
    ) -> ClusterTopology:
        """
        Detect cluster topology from a list of DSNs.

        If cluster_id is provided, all DSNs are assumed to be in that cluster.
        Otherwise, servers are grouped by their system identifier.
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        servers: list[ServerInfo] = []

        for dsn in dsns:
            info = await self._probe_server(dsn)
            if cluster_id:
                info.cluster_id = cluster_id
            servers.append(info)

        if not servers:
            return ClusterTopology(cluster_id=cluster_id or "unknown")

        # Determine cluster identity
        if cluster_id:
            return self._build_topology(servers, cluster_id, "manual")

        # Group by system identifier
        identifiers = set(s.system_identifier for s in servers if s.system_identifier)
        if len(identifiers) == 1:
            sys_id = identifiers.pop()
            return self._build_topology(servers, sys_id, "system_identifier")

        # Cloud provider fallback
        cloud_ids = set(s.cloud_cluster_id for s in servers if s.cloud_cluster_id)
        if len(cloud_ids) == 1:
            cid = cloud_ids.pop()
            return self._build_topology(servers, cid, "cloud")

        # If we can't determine cluster, treat as separate standalones
        # Use the first server's system_identifier
        first_id = servers[0].system_identifier or "standalone"
        return self._build_topology(servers, first_id, "fallback")

    async def detect_from_primary(
        self,
        primary_dsn: str,
        cluster_id: str = "",
    ) -> ClusterTopology:
        """
        Detect cluster by querying the primary for its replicas.

        Queries pg_stat_replication to find connected replicas, then probes
        each one to build the full topology.
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        primary = await self._probe_server(primary_dsn)
        if not primary.is_primary:
            logger.warning("Server at %s does not appear to be a primary", primary_dsn)

        if cluster_id:
            primary.cluster_id = cluster_id

        topology = ClusterTopology(
            cluster_id=cluster_id or primary.system_identifier or "standalone",
            primary=primary,
            detection_method="primary_probe",
        )

        # Try to discover replicas from pg_stat_replication
        try:
            conn = await asyncpg.connect(primary_dsn)
            try:
                rep_rows = await conn.fetch("""
                    SELECT
                        client_addr::text,
                        client_port,
                        state,
                        pg_wal_lsn_diff(sent_lsn, replay_lsn) AS lag_bytes,
                        EXTRACT(EPOCH FROM replay_lag) AS lag_seconds
                    FROM pg_stat_replication
                    WHERE state = 'streaming'
                """)
                for row in rep_rows:
                    addr = row["client_addr"]
                    if addr:
                        topology.replicas.append(ServerInfo(
                            dsn="",  # We don't know the full DSN
                            host=addr,
                            port=row["client_port"] or 5432,
                            is_replica=True,
                            system_identifier=primary.system_identifier,
                            replication_lag_bytes=int(row["lag_bytes"] or 0),
                            replication_lag_seconds=float(row["lag_seconds"] or 0),
                        ))
            finally:
                await conn.close()
        except Exception as e:
            logger.debug("Could not discover replicas: %s", e)

        return topology

    async def _probe_server(self, dsn: str) -> ServerInfo:
        """Probe a single server to determine its role and identity."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required")

        info = ServerInfo(dsn=dsn)

        conn = await asyncpg.connect(dsn, timeout=10)
        try:
            # Extract host/port from connection
            addr = conn.get_server_pid()  # just to verify connection
            # Parse DSN for host/port
            info.host, info.port = self._parse_dsn_host(dsn)

            # Get PostgreSQL version
            info.pg_version = str(await conn.fetchval("SELECT version()"))

            # Get system identifier (works on PG 9.6+)
            try:
                row = await conn.fetchrow("SELECT system_identifier FROM pg_control_system()")
                if row:
                    info.system_identifier = str(row["system_identifier"])
            except Exception:
                # pg_control_system() might not be available
                try:
                    # Fallback: query pg_controldata via SQL (PG 10+)
                    ident = await conn.fetchval(
                        "SELECT setting FROM pg_settings WHERE name = 'data_checksums'"
                    )
                    # Can't get system_identifier this way, leave empty
                except Exception:
                    pass

            # Determine if primary or replica
            is_in_recovery = await conn.fetchval("SELECT pg_is_in_recovery()")
            info.is_primary = not is_in_recovery
            info.is_replica = is_in_recovery

            # If replica, get lag info
            if info.is_replica:
                try:
                    lag_row = await conn.fetchrow("""
                        SELECT
                            pg_wal_lsn_diff(
                                pg_last_wal_receive_lsn(),
                                pg_last_wal_replay_lsn()
                            ) AS lag_bytes,
                            EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())) AS lag_seconds
                    """)
                    if lag_row:
                        info.replication_lag_bytes = int(lag_row["lag_bytes"] or 0)
                        info.replication_lag_seconds = float(lag_row["lag_seconds"] or 0)
                except Exception:
                    pass

            # Detect cloud provider
            info.cloud_provider, info.cloud_cluster_id = await self._detect_cloud(conn)

        finally:
            await conn.close()

        return info

    async def _detect_cloud(self, conn: Any) -> tuple[str, str]:
        """Detect cloud provider and cluster ID from database metadata."""
        try:
            # Check for RDS/Aurora
            rds_check = await conn.fetchval(
                "SELECT count(*) FROM pg_settings WHERE name = 'rds.extensions'"
            )
            if rds_check:
                # Try to get Aurora cluster ID
                try:
                    cluster_id = await conn.fetchval(
                        "SELECT setting FROM pg_settings WHERE name = 'aurora.cluster_id'"
                    )
                    if cluster_id:
                        return "aws_aurora", str(cluster_id)
                except Exception:
                    pass
                return "aws_rds", ""

            # Check for AlloyDB
            alloy_check = await conn.fetchval(
                "SELECT count(*) FROM pg_settings WHERE name LIKE 'alloydb%'"
            )
            if alloy_check:
                try:
                    cluster_id = await conn.fetchval(
                        "SELECT setting FROM pg_settings WHERE name = 'alloydb.cluster_id'"
                    )
                    if cluster_id:
                        return "gcp_alloydb", str(cluster_id)
                except Exception:
                    pass
                return "gcp_alloydb", ""

            # Check for Crunchy Bridge
            crunchy_check = await conn.fetchval(
                "SELECT count(*) FROM pg_settings WHERE name LIKE 'crunchy%'"
            )
            if crunchy_check:
                return "crunchy_bridge", ""

            # Check for Azure
            azure_check = await conn.fetchval(
                "SELECT count(*) FROM pg_settings WHERE name LIKE 'azure%'"
            )
            if azure_check:
                return "azure", ""

        except Exception:
            pass

        return "none", ""

    def _parse_dsn_host(self, dsn: str) -> tuple[str, int]:
        """Extract host and port from a DSN string."""
        import re
        # postgresql://user:pass@host:port/dbname
        m = re.search(r"@([^/:]+)(?::(\d+))?", dsn)
        if m:
            return m.group(1), int(m.group(2) or 5432)
        # host=xxx port=yyy format
        host_m = re.search(r"host=(\S+)", dsn)
        port_m = re.search(r"port=(\d+)", dsn)
        return (
            host_m.group(1) if host_m else "localhost",
            int(port_m.group(1)) if port_m else 5432,
        )

    def _build_topology(
        self,
        servers: list[ServerInfo],
        cluster_id: str,
        method: str,
    ) -> ClusterTopology:
        """Build ClusterTopology from a list of probed servers."""
        primary = None
        replicas: list[ServerInfo] = []

        for server in servers:
            if server.is_primary and primary is None:
                primary = server
            else:
                replicas.append(server)

        # If no explicit primary, pick the first
        if primary is None and servers:
            primary = servers[0]
            primary.is_primary = True
            replicas = servers[1:]

        return ClusterTopology(
            cluster_id=cluster_id,
            primary=primary,
            replicas=replicas,
            detection_method=method,
        )
