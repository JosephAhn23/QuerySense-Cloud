"""
RDS/CloudWatch Metrics Integration.

Pulls real-time and historical performance metrics from AWS CloudWatch for
RDS and Aurora PostgreSQL instances. This fills a key gap identified in the
pganalyze/Atlassian case study: "full integration with Amazon RDS, including
CloudWatch and log file monitoring."

Metrics collected:
- CPU Utilization (%)
- Freeable Memory (bytes)
- Read/Write IOPS
- Read/Write Latency (ms)
- Database Connections (count)
- Free Storage Space (bytes)
- Network Receive/Transmit Throughput
- Replica Lag (Aurora)
- Deadlocks (Aurora)
- Buffer Cache Hit Ratio (Aurora)
- Commit Latency (Aurora)

Usage:
    from querysense.db.rds_cloudwatch import RDSMetricsCollector, RDSConfig

    config = RDSConfig(
        instance_id="my-postgres-db",
        region="us-east-1",
    )
    collector = RDSMetricsCollector(config)

    # Single snapshot
    snapshot = await collector.collect()
    print(snapshot.format_text())

    # Historical data (last 6 hours)
    history = await collector.collect_range(hours=6, period_seconds=300)
    for point in history.cpu_utilization:
        print(f"{point.timestamp}: {point.value:.1f}%")
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RDSConfig:
    """Configuration for RDS/CloudWatch metrics collection."""
    instance_id: str
    region: str = "us-east-1"
    is_aurora: bool = False
    is_cluster: bool = False
    aws_profile: str | None = None
    period_seconds: int = 60
    enhanced_monitoring: bool = False


@dataclass
class MetricDataPoint:
    """A single CloudWatch metric data point."""
    timestamp: datetime
    value: float
    unit: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "value": round(self.value, 4),
            "unit": self.unit,
        }


@dataclass
class RDSMetricSnapshot:
    """A complete snapshot of RDS metrics at a point in time."""
    instance_id: str
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_aurora: bool = False
    cpu_utilization_pct: float = 0.0
    freeable_memory_bytes: int = 0
    read_iops: float = 0.0
    write_iops: float = 0.0
    read_latency_ms: float = 0.0
    write_latency_ms: float = 0.0
    database_connections: int = 0
    free_storage_bytes: int = 0
    network_receive_throughput: float = 0.0
    network_transmit_throughput: float = 0.0
    swap_usage_bytes: int = 0
    # Aurora-specific
    replica_lag_ms: float = 0.0
    deadlocks: int = 0
    buffer_cache_hit_ratio: float = 0.0
    commit_latency_ms: float = 0.0
    aurora_replica_lag_max_ms: float = 0.0

    @property
    def freeable_memory_gb(self) -> float:
        return self.freeable_memory_bytes / (1024 ** 3)

    @property
    def free_storage_gb(self) -> float:
        return self.free_storage_bytes / (1024 ** 3)

    @property
    def total_iops(self) -> float:
        return self.read_iops + self.write_iops

    @property
    def health_status(self) -> str:
        issues: list[str] = []
        if self.cpu_utilization_pct > 80:
            issues.append(f"CPU {self.cpu_utilization_pct:.0f}%")
        if self.freeable_memory_gb < 0.5:
            issues.append(f"Low memory ({self.freeable_memory_gb:.1f}GB)")
        if self.free_storage_gb < 10:
            issues.append(f"Low storage ({self.free_storage_gb:.0f}GB)")
        if self.database_connections > 200:
            issues.append(f"High connections ({self.database_connections})")
        if self.is_aurora and self.buffer_cache_hit_ratio < 95:
            issues.append(f"Low cache hit ({self.buffer_cache_hit_ratio:.0f}%)")
        if self.read_latency_ms > 20:
            issues.append(f"High read latency ({self.read_latency_ms:.1f}ms)")

        if not issues:
            return "healthy"
        if any("CPU" in i or "memory" in i or "storage" in i for i in issues):
            return "warning"
        return "degraded"

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "collected_at": self.collected_at.isoformat(),
            "health_status": self.health_status,
            "cpu_utilization_pct": round(self.cpu_utilization_pct, 1),
            "freeable_memory_gb": round(self.freeable_memory_gb, 2),
            "read_iops": round(self.read_iops, 1),
            "write_iops": round(self.write_iops, 1),
            "total_iops": round(self.total_iops, 1),
            "read_latency_ms": round(self.read_latency_ms, 3),
            "write_latency_ms": round(self.write_latency_ms, 3),
            "database_connections": self.database_connections,
            "free_storage_gb": round(self.free_storage_gb, 1),
            "network_receive_throughput": round(self.network_receive_throughput, 1),
            "network_transmit_throughput": round(self.network_transmit_throughput, 1),
            "is_aurora": self.is_aurora,
            "aurora_buffer_cache_hit_ratio": round(self.buffer_cache_hit_ratio, 1) if self.is_aurora else None,
            "aurora_commit_latency_ms": round(self.commit_latency_ms, 2) if self.is_aurora else None,
            "aurora_replica_lag_ms": round(self.replica_lag_ms, 2) if self.is_aurora else None,
            "aurora_deadlocks": self.deadlocks if self.is_aurora else None,
        }

    def format_text(self) -> str:
        lines = [
            "",
            f"  RDS METRICS — {self.instance_id}",
            "  " + "=" * 55,
            f"  Status: {self.health_status.upper()}",
            f"  Collected: {self.collected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            f"  {'Metric':<30} {'Value':>15} {'Status':>10}",
            "  " + "-" * 55,
            f"  {'CPU Utilization':<30} {self.cpu_utilization_pct:>14.1f}% {_status_icon(self.cpu_utilization_pct, 70, 90):>10}",
            f"  {'Freeable Memory':<30} {self.freeable_memory_gb:>13.1f}GB {_status_icon_inv(self.freeable_memory_gb, 1.0, 0.5):>10}",
            f"  {'Read IOPS':<30} {self.read_iops:>15.0f} {'':>10}",
            f"  {'Write IOPS':<30} {self.write_iops:>15.0f} {'':>10}",
            f"  {'Read Latency':<30} {self.read_latency_ms:>13.2f}ms {_status_icon(self.read_latency_ms, 10, 20):>10}",
            f"  {'Write Latency':<30} {self.write_latency_ms:>13.2f}ms {_status_icon(self.write_latency_ms, 10, 20):>10}",
            f"  {'Database Connections':<30} {self.database_connections:>15} {_status_icon(self.database_connections, 150, 300):>10}",
            f"  {'Free Storage':<30} {self.free_storage_gb:>13.1f}GB {_status_icon_inv(self.free_storage_gb, 20, 5):>10}",
        ]

        if self.is_aurora:
            lines.extend([
                "",
                "  Aurora-Specific:",
                f"  {'Buffer Cache Hit Ratio':<30} {self.buffer_cache_hit_ratio:>14.1f}% {_status_icon_inv(self.buffer_cache_hit_ratio, 99, 95):>10}",
                f"  {'Commit Latency':<30} {self.commit_latency_ms:>13.2f}ms {'':>10}",
                f"  {'Replica Lag':<30} {self.replica_lag_ms:>13.2f}ms {_status_icon(self.replica_lag_ms, 100, 500):>10}",
                f"  {'Deadlocks':<30} {self.deadlocks:>15} {_status_icon(self.deadlocks, 0, 5):>10}",
            ])

        lines.append("")
        return "\n".join(lines)


@dataclass
class RDSMetricHistory:
    """Time-series metric data from CloudWatch."""
    instance_id: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_seconds: int = 300
    cpu_utilization: list[MetricDataPoint] = field(default_factory=list)
    freeable_memory: list[MetricDataPoint] = field(default_factory=list)
    read_iops: list[MetricDataPoint] = field(default_factory=list)
    write_iops: list[MetricDataPoint] = field(default_factory=list)
    read_latency: list[MetricDataPoint] = field(default_factory=list)
    write_latency: list[MetricDataPoint] = field(default_factory=list)
    database_connections: list[MetricDataPoint] = field(default_factory=list)

    @property
    def avg_cpu(self) -> float:
        if not self.cpu_utilization:
            return 0.0
        return sum(p.value for p in self.cpu_utilization) / len(self.cpu_utilization)

    @property
    def max_cpu(self) -> float:
        return max((p.value for p in self.cpu_utilization), default=0.0)

    @property
    def avg_connections(self) -> float:
        if not self.database_connections:
            return 0.0
        return sum(p.value for p in self.database_connections) / len(self.database_connections)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "period_seconds": self.period_seconds,
            "summary": {
                "avg_cpu_pct": round(self.avg_cpu, 1),
                "max_cpu_pct": round(self.max_cpu, 1),
                "avg_connections": round(self.avg_connections, 0),
                "data_points": len(self.cpu_utilization),
            },
            "cpu_utilization": [p.to_dict() for p in self.cpu_utilization],
            "read_iops": [p.to_dict() for p in self.read_iops],
            "write_iops": [p.to_dict() for p in self.write_iops],
            "database_connections": [p.to_dict() for p in self.database_connections],
        }


# CloudWatch metric definitions for RDS
_RDS_METRICS = [
    ("CPUUtilization", "Percent", "cpu_utilization_pct"),
    ("FreeableMemory", "Bytes", "freeable_memory_bytes"),
    ("ReadIOPS", "Count/Second", "read_iops"),
    ("WriteIOPS", "Count/Second", "write_iops"),
    ("ReadLatency", "Seconds", "read_latency_ms"),
    ("WriteLatency", "Seconds", "write_latency_ms"),
    ("DatabaseConnections", "Count", "database_connections"),
    ("FreeStorageSpace", "Bytes", "free_storage_bytes"),
    ("NetworkReceiveThroughput", "Bytes/Second", "network_receive_throughput"),
    ("NetworkTransmitThroughput", "Bytes/Second", "network_transmit_throughput"),
    ("SwapUsage", "Bytes", "swap_usage_bytes"),
]

_AURORA_METRICS = [
    ("AuroraReplicaLag", "Milliseconds", "replica_lag_ms"),
    ("Deadlocks", "Count", "deadlocks"),
    ("BufferCacheHitRatio", "Percent", "buffer_cache_hit_ratio"),
    ("CommitLatency", "Milliseconds", "commit_latency_ms"),
    ("AuroraReplicaLagMaximum", "Milliseconds", "aurora_replica_lag_max_ms"),
]

_LATENCY_FIELDS = {"read_latency_ms", "write_latency_ms"}


class RDSMetricsCollector:
    """
    Collects RDS/Aurora performance metrics from CloudWatch.

    Requires boto3 and appropriate AWS credentials (environment variables,
    IAM role, or AWS profile).
    """

    def __init__(self, config: RDSConfig) -> None:
        self.config = config
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3
            except ImportError:
                raise RuntimeError(
                    "boto3 required for RDS metrics: pip install boto3"
                )

            session_kwargs: dict[str, Any] = {"region_name": self.config.region}
            if self.config.aws_profile:
                session_kwargs["profile_name"] = self.config.aws_profile

            session = boto3.Session(**session_kwargs)
            self._client = session.client("cloudwatch")
        return self._client

    async def collect(self) -> RDSMetricSnapshot:
        """
        Collect a current snapshot of RDS metrics.

        Returns the most recent data point for each metric (last 5 minutes).
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._collect_sync)

    def _collect_sync(self) -> RDSMetricSnapshot:
        client = self._get_client()
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=5)

        snapshot = RDSMetricSnapshot(
            instance_id=self.config.instance_id,
            collected_at=now,
            is_aurora=self.config.is_aurora,
        )

        dimension_name = (
            "DBClusterIdentifier" if self.config.is_cluster
            else "DBInstanceIdentifier"
        )
        dimensions = [
            {"Name": dimension_name, "Value": self.config.instance_id}
        ]

        metrics = list(_RDS_METRICS)
        if self.config.is_aurora:
            metrics.extend(_AURORA_METRICS)

        for metric_name, unit, attr in metrics:
            try:
                response = client.get_metric_statistics(
                    Namespace="AWS/RDS",
                    MetricName=metric_name,
                    Dimensions=dimensions,
                    StartTime=start,
                    EndTime=now,
                    Period=self.config.period_seconds,
                    Statistics=["Average"],
                )

                datapoints = response.get("Datapoints", [])
                if datapoints:
                    latest = max(datapoints, key=lambda d: d["Timestamp"])
                    value = latest["Average"]

                    if attr in _LATENCY_FIELDS:
                        value *= 1000

                    if attr == "database_connections":
                        value = int(value)
                    elif attr in ("freeable_memory_bytes", "free_storage_bytes", "swap_usage_bytes"):
                        value = int(value)
                    elif attr == "deadlocks":
                        value = int(value)

                    setattr(snapshot, attr, value)

            except Exception as e:
                logger.debug("Failed to fetch %s: %s", metric_name, e)

        return snapshot

    async def collect_range(
        self,
        hours: int = 6,
        period_seconds: int = 300,
    ) -> RDSMetricHistory:
        """
        Collect historical metrics over a time range.

        Args:
            hours: Number of hours of history to collect.
            period_seconds: Granularity of data points (default 5 minutes).
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._collect_range_sync, hours, period_seconds
        )

    def _collect_range_sync(
        self, hours: int, period_seconds: int,
    ) -> RDSMetricHistory:
        client = self._get_client()
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)

        history = RDSMetricHistory(
            instance_id=self.config.instance_id,
            start_time=start,
            end_time=now,
            period_seconds=period_seconds,
        )

        dimension_name = (
            "DBClusterIdentifier" if self.config.is_cluster
            else "DBInstanceIdentifier"
        )
        dimensions = [
            {"Name": dimension_name, "Value": self.config.instance_id}
        ]

        metric_map = {
            "CPUUtilization": ("cpu_utilization", "Percent", "%"),
            "FreeableMemory": ("freeable_memory", "Bytes", "bytes"),
            "ReadIOPS": ("read_iops", "Count/Second", "iops"),
            "WriteIOPS": ("write_iops", "Count/Second", "iops"),
            "ReadLatency": ("read_latency", "Seconds", "ms"),
            "WriteLatency": ("write_latency", "Seconds", "ms"),
            "DatabaseConnections": ("database_connections", "Count", "count"),
        }

        for metric_name, (attr, unit, display_unit) in metric_map.items():
            try:
                response = client.get_metric_statistics(
                    Namespace="AWS/RDS",
                    MetricName=metric_name,
                    Dimensions=dimensions,
                    StartTime=start,
                    EndTime=now,
                    Period=period_seconds,
                    Statistics=["Average"],
                )

                points: list[MetricDataPoint] = []
                for dp in sorted(response.get("Datapoints", []), key=lambda d: d["Timestamp"]):
                    value = dp["Average"]
                    if display_unit == "ms" and unit == "Seconds":
                        value *= 1000
                    points.append(MetricDataPoint(
                        timestamp=dp["Timestamp"],
                        value=value,
                        unit=display_unit,
                    ))

                setattr(history, attr, points)

            except Exception as e:
                logger.debug("Failed to fetch history for %s: %s", metric_name, e)

        return history

    async def check_alarms(self) -> list[dict[str, Any]]:
        """Check for active CloudWatch alarms on this instance."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._check_alarms_sync)

    def _check_alarms_sync(self) -> list[dict[str, Any]]:
        client = self._get_client()
        alarms: list[dict[str, Any]] = []

        try:
            response = client.describe_alarms(
                StateValue="ALARM",
                MaxRecords=100,
            )

            for alarm in response.get("MetricAlarms", []):
                dims = {d["Name"]: d["Value"] for d in alarm.get("Dimensions", [])}
                instance = dims.get("DBInstanceIdentifier") or dims.get("DBClusterIdentifier")
                if instance == self.config.instance_id:
                    alarms.append({
                        "name": alarm["AlarmName"],
                        "metric": alarm["MetricName"],
                        "state": alarm["StateValue"],
                        "reason": alarm.get("StateReason", ""),
                        "threshold": alarm.get("Threshold"),
                        "comparison": alarm.get("ComparisonOperator"),
                    })

        except Exception as e:
            logger.warning("Failed to check alarms: %s", e)

        return alarms


def _status_icon(value: float, warn_threshold: float, crit_threshold: float) -> str:
    if value >= crit_threshold:
        return "CRITICAL"
    if value >= warn_threshold:
        return "WARNING"
    return "OK"


def _status_icon_inv(value: float, warn_threshold: float, crit_threshold: float) -> str:
    if value <= crit_threshold:
        return "CRITICAL"
    if value <= warn_threshold:
        return "WARNING"
    return "OK"
