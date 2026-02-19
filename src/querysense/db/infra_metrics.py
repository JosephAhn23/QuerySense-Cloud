"""
Infrastructure metrics collector for PostgreSQL.

Reads system-level metrics from pg_stat_database and pg_stat_bgwriter
alongside plan analysis to enable infrastructure correlation.

Outputs in Prometheus exposition format for Datadog/Grafana import.

Usage:
    from querysense.db.infra_metrics import InfraMetrics, collect_infra_metrics

    metrics = await collect_infra_metrics(conn)
    print(metrics.to_prometheus())
    # querysense_pg_blks_hit{db="mydb"} 123456
    # querysense_pg_blks_read{db="mydb"} 7890
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class DatabaseStats:
    """Metrics from pg_stat_database."""

    datname: str = ""
    numbackends: int = 0
    xact_commit: int = 0
    xact_rollback: int = 0
    blks_read: int = 0
    blks_hit: int = 0
    tup_returned: int = 0
    tup_fetched: int = 0
    tup_inserted: int = 0
    tup_updated: int = 0
    tup_deleted: int = 0
    conflicts: int = 0
    temp_files: int = 0
    temp_bytes: int = 0
    deadlocks: int = 0
    blk_read_time: float = 0.0
    blk_write_time: float = 0.0
    db_size_bytes: int = 0

    @property
    def cache_hit_ratio(self) -> float:
        """Buffer cache hit ratio (0.0-1.0). >0.99 is healthy."""
        total = self.blks_hit + self.blks_read
        if total == 0:
            return 1.0
        return self.blks_hit / total

    @property
    def commit_ratio(self) -> float:
        """Transaction commit ratio. <0.95 suggests issues."""
        total = self.xact_commit + self.xact_rollback
        if total == 0:
            return 1.0
        return self.xact_commit / total


@dataclass
class BGWriterStats:
    """Metrics from pg_stat_bgwriter."""

    checkpoints_timed: int = 0
    checkpoints_req: int = 0
    checkpoint_write_time: float = 0.0
    checkpoint_sync_time: float = 0.0
    buffers_checkpoint: int = 0
    buffers_clean: int = 0
    maxwritten_clean: int = 0
    buffers_backend: int = 0
    buffers_backend_fsync: int = 0
    buffers_alloc: int = 0

    @property
    def checkpoint_request_ratio(self) -> float:
        """Ratio of requested vs timed checkpoints. High = checkpoints too infrequent."""
        total = self.checkpoints_timed + self.checkpoints_req
        if total == 0:
            return 0.0
        return self.checkpoints_req / total

    @property
    def backend_write_ratio(self) -> float:
        """Ratio of buffers written by backends (bad) vs bgwriter (good)."""
        total = self.buffers_checkpoint + self.buffers_clean + self.buffers_backend
        if total == 0:
            return 0.0
        return self.buffers_backend / total


@dataclass
class ConnectionStats:
    """Active connection statistics."""

    total: int = 0
    active: int = 0
    idle: int = 0
    idle_in_transaction: int = 0
    waiting: int = 0
    max_connections: int = 100


@dataclass
class ReplicationStats:
    """Replication lag info."""

    is_replica: bool = False
    replay_lag_bytes: int = 0
    replay_lag_seconds: float = 0.0


@dataclass
class InfraMetrics:
    """Complete infrastructure metrics snapshot."""

    timestamp: float = 0.0
    database: DatabaseStats = field(default_factory=DatabaseStats)
    bgwriter: BGWriterStats = field(default_factory=BGWriterStats)
    connections: ConnectionStats = field(default_factory=ConnectionStats)
    replication: ReplicationStats = field(default_factory=ReplicationStats)
    pg_version: str = ""
    uptime_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize all metrics."""
        return {
            "timestamp": self.timestamp,
            "pg_version": self.pg_version,
            "uptime_seconds": self.uptime_seconds,
            "database": {
                "name": self.database.datname,
                "cache_hit_ratio": round(self.database.cache_hit_ratio, 4),
                "commit_ratio": round(self.database.commit_ratio, 4),
                "numbackends": self.database.numbackends,
                "blks_read": self.database.blks_read,
                "blks_hit": self.database.blks_hit,
                "tup_returned": self.database.tup_returned,
                "tup_fetched": self.database.tup_fetched,
                "temp_files": self.database.temp_files,
                "temp_bytes": self.database.temp_bytes,
                "deadlocks": self.database.deadlocks,
                "db_size_bytes": self.database.db_size_bytes,
            },
            "bgwriter": {
                "checkpoint_request_ratio": round(self.bgwriter.checkpoint_request_ratio, 4),
                "backend_write_ratio": round(self.bgwriter.backend_write_ratio, 4),
                "checkpoints_timed": self.bgwriter.checkpoints_timed,
                "checkpoints_req": self.bgwriter.checkpoints_req,
                "buffers_backend": self.bgwriter.buffers_backend,
                "buffers_backend_fsync": self.bgwriter.buffers_backend_fsync,
            },
            "connections": {
                "total": self.connections.total,
                "active": self.connections.active,
                "idle": self.connections.idle,
                "idle_in_transaction": self.connections.idle_in_transaction,
                "waiting": self.connections.waiting,
                "max_connections": self.connections.max_connections,
            },
            "errors": self.errors,
        }

    def to_prometheus(self, prefix: str = "querysense") -> str:
        """
        Format metrics in Prometheus exposition format.

        Output can be scraped by Prometheus, imported into Datadog,
        or consumed by any OpenMetrics-compatible system.
        """
        db = self.database.datname or "unknown"
        lines: list[str] = []

        def gauge(name: str, value: float | int, help_text: str = "", **labels: str) -> None:
            label_str = ",".join(f'{k}="{v}"' for k, v in {**labels, "db": db}.items())
            if help_text:
                lines.append(f"# HELP {prefix}_{name} {help_text}")
                lines.append(f"# TYPE {prefix}_{name} gauge")
            lines.append(f"{prefix}_{name}{{{label_str}}} {value}")

        # Database metrics
        gauge("pg_cache_hit_ratio", round(self.database.cache_hit_ratio, 4),
              "Buffer cache hit ratio")
        gauge("pg_commit_ratio", round(self.database.commit_ratio, 4),
              "Transaction commit ratio")
        gauge("pg_numbackends", self.database.numbackends,
              "Number of connected backends")
        gauge("pg_blks_read_total", self.database.blks_read,
              "Disk blocks read")
        gauge("pg_blks_hit_total", self.database.blks_hit,
              "Buffer cache hits")
        gauge("pg_tup_returned_total", self.database.tup_returned,
              "Rows returned by queries")
        gauge("pg_tup_fetched_total", self.database.tup_fetched,
              "Rows fetched by queries")
        gauge("pg_tup_inserted_total", self.database.tup_inserted,
              "Rows inserted")
        gauge("pg_tup_updated_total", self.database.tup_updated,
              "Rows updated")
        gauge("pg_tup_deleted_total", self.database.tup_deleted,
              "Rows deleted")
        gauge("pg_temp_files_total", self.database.temp_files,
              "Temporary files created")
        gauge("pg_temp_bytes_total", self.database.temp_bytes,
              "Temporary file bytes")
        gauge("pg_deadlocks_total", self.database.deadlocks,
              "Deadlocks detected")
        gauge("pg_db_size_bytes", self.database.db_size_bytes,
              "Database size in bytes")

        # BGWriter metrics
        gauge("pg_checkpoints_timed_total", self.bgwriter.checkpoints_timed,
              "Scheduled checkpoints")
        gauge("pg_checkpoints_req_total", self.bgwriter.checkpoints_req,
              "Requested checkpoints")
        gauge("pg_buffers_backend_total", self.bgwriter.buffers_backend,
              "Buffers written by backends (should be low)")
        gauge("pg_buffers_backend_fsync_total", self.bgwriter.buffers_backend_fsync,
              "Backend fsync calls (should be 0)")
        gauge("pg_checkpoint_request_ratio", round(self.bgwriter.checkpoint_request_ratio, 4),
              "Ratio of requested checkpoints")
        gauge("pg_backend_write_ratio", round(self.bgwriter.backend_write_ratio, 4),
              "Ratio of backend-written buffers")

        # Connection metrics
        gauge("pg_connections_total", self.connections.total,
              "Total connections")
        gauge("pg_connections_active", self.connections.active,
              "Active connections")
        gauge("pg_connections_idle", self.connections.idle,
              "Idle connections")
        gauge("pg_connections_idle_in_transaction", self.connections.idle_in_transaction,
              "Idle in transaction connections")
        gauge("pg_connections_max", self.connections.max_connections,
              "Max allowed connections")

        # Replication
        if self.replication.is_replica:
            gauge("pg_replication_lag_bytes", self.replication.replay_lag_bytes,
                  "Replication lag in bytes")
            gauge("pg_replication_lag_seconds", self.replication.replay_lag_seconds,
                  "Replication lag in seconds")

        gauge("pg_uptime_seconds", self.uptime_seconds, "PostgreSQL uptime")

        return "\n".join(lines) + "\n"

    def health_summary(self) -> list[str]:
        """Return a list of health warnings based on metrics."""
        warnings: list[str] = []

        if self.database.cache_hit_ratio < 0.99:
            warnings.append(
                f"Cache hit ratio {self.database.cache_hit_ratio:.2%} "
                f"(should be >99%); consider increasing shared_buffers"
            )
        if self.database.commit_ratio < 0.95:
            warnings.append(
                f"Commit ratio {self.database.commit_ratio:.2%}; "
                f"high rollback rate suggests application errors"
            )
        if self.database.deadlocks > 0:
            warnings.append(
                f"{self.database.deadlocks} deadlocks detected; "
                f"review lock ordering in application"
            )
        if self.database.temp_files > 100:
            warnings.append(
                f"{self.database.temp_files} temp files created; "
                f"consider increasing work_mem"
            )
        if self.bgwriter.buffers_backend_fsync > 0:
            warnings.append(
                f"{self.bgwriter.buffers_backend_fsync} backend fsyncs; "
                f"bgwriter can't keep up — tune bgwriter_lru_maxpages"
            )
        if self.bgwriter.checkpoint_request_ratio > 0.5:
            warnings.append(
                f"Checkpoint request ratio {self.bgwriter.checkpoint_request_ratio:.0%}; "
                f"increase checkpoint_timeout or max_wal_size"
            )

        conn_usage = self.connections.total / max(self.connections.max_connections, 1)
        if conn_usage > 0.8:
            warnings.append(
                f"Connection usage {conn_usage:.0%}; "
                f"approaching max_connections limit"
            )
        if self.connections.idle_in_transaction > 5:
            warnings.append(
                f"{self.connections.idle_in_transaction} idle-in-transaction connections; "
                f"may hold locks and prevent vacuum"
            )

        return warnings


async def collect_infra_metrics(conn: AsyncDBConnection) -> InfraMetrics:
    """
    Collect all infrastructure metrics from a PostgreSQL connection.

    Args:
        conn: asyncpg connection or compatible

    Returns:
        InfraMetrics with all available system metrics
    """
    metrics = InfraMetrics(timestamp=time.time())

    # pg_stat_database
    try:
        row = await conn.fetchrow(
            """SELECT d.datname, d.numbackends,
                      d.xact_commit, d.xact_rollback,
                      d.blks_read, d.blks_hit,
                      d.tup_returned, d.tup_fetched,
                      d.tup_inserted, d.tup_updated, d.tup_deleted,
                      d.conflicts, d.temp_files, d.temp_bytes,
                      d.deadlocks, d.blk_read_time, d.blk_write_time,
                      pg_database_size(d.datname) AS db_size_bytes
               FROM pg_stat_database d
               WHERE d.datname = current_database()"""
        )
        if row:
            metrics.database = DatabaseStats(
                datname=row["datname"],
                numbackends=row["numbackends"] or 0,
                xact_commit=row["xact_commit"] or 0,
                xact_rollback=row["xact_rollback"] or 0,
                blks_read=row["blks_read"] or 0,
                blks_hit=row["blks_hit"] or 0,
                tup_returned=row["tup_returned"] or 0,
                tup_fetched=row["tup_fetched"] or 0,
                tup_inserted=row["tup_inserted"] or 0,
                tup_updated=row["tup_updated"] or 0,
                tup_deleted=row["tup_deleted"] or 0,
                conflicts=row["conflicts"] or 0,
                temp_files=row["temp_files"] or 0,
                temp_bytes=row["temp_bytes"] or 0,
                deadlocks=row["deadlocks"] or 0,
                blk_read_time=row["blk_read_time"] or 0.0,
                blk_write_time=row["blk_write_time"] or 0.0,
                db_size_bytes=row["db_size_bytes"] or 0,
            )
    except Exception as e:
        metrics.errors.append(f"pg_stat_database: {e}")

    # pg_stat_bgwriter
    try:
        row = await conn.fetchrow(
            """SELECT checkpoints_timed, checkpoints_req,
                      checkpoint_write_time, checkpoint_sync_time,
                      buffers_checkpoint, buffers_clean,
                      maxwritten_clean, buffers_backend,
                      buffers_backend_fsync, buffers_alloc
               FROM pg_stat_bgwriter"""
        )
        if row:
            metrics.bgwriter = BGWriterStats(
                checkpoints_timed=row["checkpoints_timed"] or 0,
                checkpoints_req=row["checkpoints_req"] or 0,
                checkpoint_write_time=row["checkpoint_write_time"] or 0.0,
                checkpoint_sync_time=row["checkpoint_sync_time"] or 0.0,
                buffers_checkpoint=row["buffers_checkpoint"] or 0,
                buffers_clean=row["buffers_clean"] or 0,
                maxwritten_clean=row["maxwritten_clean"] or 0,
                buffers_backend=row["buffers_backend"] or 0,
                buffers_backend_fsync=row["buffers_backend_fsync"] or 0,
                buffers_alloc=row["buffers_alloc"] or 0,
            )
    except Exception as e:
        metrics.errors.append(f"pg_stat_bgwriter: {e}")

    # Connection stats
    try:
        rows = await conn.fetch(
            """SELECT state, COUNT(*) AS cnt
               FROM pg_stat_activity
               WHERE datname = current_database()
               GROUP BY state"""
        )
        max_conn = await conn.fetchval("SHOW max_connections")
        total = 0
        for r in rows:
            cnt = r["cnt"]
            total += cnt
            state = r["state"]
            if state == "active":
                metrics.connections.active = cnt
            elif state == "idle":
                metrics.connections.idle = cnt
            elif state and "idle in transaction" in state:
                metrics.connections.idle_in_transaction += cnt
        metrics.connections.total = total
        metrics.connections.max_connections = int(max_conn) if max_conn else 100
    except Exception as e:
        metrics.errors.append(f"connections: {e}")

    # Version and uptime
    try:
        metrics.pg_version = await conn.fetchval("SHOW server_version") or ""
        uptime_row = await conn.fetchval(
            "SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time()))"
        )
        metrics.uptime_seconds = float(uptime_row) if uptime_row else 0.0
    except Exception as e:
        metrics.errors.append(f"version/uptime: {e}")

    # Replication lag (safe - returns null if not a replica)
    try:
        is_replica = await conn.fetchval("SELECT pg_is_in_recovery()")
        metrics.replication.is_replica = bool(is_replica)
        if is_replica:
            lag = await conn.fetchval(
                "SELECT pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())"
            )
            metrics.replication.replay_lag_bytes = int(lag) if lag else 0
    except Exception as e:
        metrics.errors.append(f"replication: {e}")

    return metrics
