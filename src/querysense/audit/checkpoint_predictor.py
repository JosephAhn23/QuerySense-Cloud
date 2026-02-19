"""
Checkpoint Predictor — Forecast checkpoint bottlenecks before they happen.

pganalyze teaches "proactive practices" for $149/month. This module automates
the prediction: given current WAL rate and growth trends, forecast when
checkpoints will become a bottleneck.

This extends CheckpointAuditor with:
1. WAL rate measurement (bytes/sec over observation window)
2. Time-to-saturation prediction (when max_wal_size fills before timeout)
3. I/O budget forecasting (what % of disk bandwidth checkpoints consume)
4. Growth trend extrapolation (linear regression on WAL rate)
5. Proactive alerting thresholds with auto-generated fix scripts

Usage:
    from querysense.audit.checkpoint_predictor import CheckpointPredictor

    predictor = CheckpointPredictor()
    forecast = await predictor.predict(conn)
    print(forecast.format_text())
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Protocol

from querysense.audit.checkpoints import CheckpointAuditor, CheckpointReport, CheckpointStats

logger = logging.getLogger(__name__)


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class WALRateSnapshot:
    """Point-in-time WAL generation rate measurement."""
    timestamp: float = 0.0
    lsn_offset: int = 0
    wal_bytes_since_reset: int = 0
    wal_rate_bytes_per_sec: float = 0.0


@dataclass
class CheckpointForecast:
    """Predictive checkpoint analysis."""
    current_report: CheckpointReport = field(default_factory=CheckpointReport)

    # WAL rate measurements
    wal_rate_bytes_per_sec: float = 0.0
    wal_rate_mb_per_min: float = 0.0
    wal_rate_gb_per_hour: float = 0.0

    # Capacity analysis
    max_wal_size_bytes: int = 0
    checkpoint_timeout_sec: int = 300
    wal_capacity_per_timeout: float = 0.0  # bytes generated in one timeout period
    fill_ratio: float = 0.0  # capacity / max_wal_size (>1 = forced checkpoints)

    # Predictions
    time_to_wal_full_sec: float = 0.0
    predicted_checkpoints_per_hour: float = 0.0
    predicted_io_pct: float = 0.0  # % of disk bandwidth consumed by checkpoints
    days_until_critical: float = float("inf")

    # Growth trend (if historical data available)
    wal_rate_trend_pct_per_day: float = 0.0
    has_trend_data: bool = False

    # Thresholds
    is_healthy: bool = True
    risk_level: str = "low"  # low, medium, high, critical
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "wal_rate": {
                "bytes_per_sec": round(self.wal_rate_bytes_per_sec, 0),
                "mb_per_min": round(self.wal_rate_mb_per_min, 2),
                "gb_per_hour": round(self.wal_rate_gb_per_hour, 2),
            },
            "capacity": {
                "max_wal_size_bytes": self.max_wal_size_bytes,
                "checkpoint_timeout_sec": self.checkpoint_timeout_sec,
                "fill_ratio": round(self.fill_ratio, 2),
                "time_to_wal_full_sec": round(self.time_to_wal_full_sec, 1),
            },
            "prediction": {
                "checkpoints_per_hour": round(self.predicted_checkpoints_per_hour, 1),
                "io_pct": round(self.predicted_io_pct, 1),
                "days_until_critical": (
                    round(self.days_until_critical, 1)
                    if self.days_until_critical < 365 else None
                ),
            },
            "risk_level": self.risk_level,
            "findings": self.findings,
        }

    def format_text(self) -> str:
        lines = [
            "",
            "  CHECKPOINT PREDICTION",
            "  " + "=" * 55,
            "",
            "  WAL GENERATION RATE:",
            f"    Current: {self.wal_rate_mb_per_min:.1f} MB/min ({self.wal_rate_gb_per_hour:.2f} GB/hour)",
        ]

        if self.has_trend_data and self.wal_rate_trend_pct_per_day != 0:
            direction = "increasing" if self.wal_rate_trend_pct_per_day > 0 else "decreasing"
            lines.append(
                f"    Trend: {direction} at {abs(self.wal_rate_trend_pct_per_day):.1f}%/day"
            )

        lines.extend([
            "",
            "  CHECKPOINT CAPACITY:",
            f"    max_wal_size: {self.max_wal_size_bytes / (1024**3):.1f} GB",
            f"    checkpoint_timeout: {self.checkpoint_timeout_sec}s",
            f"    WAL per timeout period: {self.wal_capacity_per_timeout / (1024**3):.2f} GB",
            f"    Fill ratio: {self.fill_ratio:.2f} {'(FORCED checkpoints!)' if self.fill_ratio > 1.0 else '(OK)'}",
            "",
            "  FORECAST:",
            f"    Time until WAL full: {self._fmt_duration(self.time_to_wal_full_sec)}",
            f"    Predicted checkpoints/hour: {self.predicted_checkpoints_per_hour:.1f}",
            f"    Checkpoint I/O overhead: ~{self.predicted_io_pct:.1f}% of disk bandwidth",
        ])

        if self.days_until_critical < 365:
            lines.append(
                f"    Days until critical (at current growth): {self.days_until_critical:.0f}"
            )

        lines.extend([
            "",
            f"  RISK LEVEL: {self.risk_level.upper()}",
        ])

        for finding in self.findings:
            sev = finding.get("severity", "info").upper()
            lines.append(f"    [{sev}] {finding['title']}")
            if finding.get("fix"):
                lines.append(f"           Fix: {finding['fix']}")

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        if seconds <= 0:
            return "N/A"
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            return f"{seconds / 60:.1f} min"
        return f"{seconds / 3600:.1f} hours"


_WAL_RATE_SQL = """
SELECT
    pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0') AS lsn_offset,
    EXTRACT(EPOCH FROM now()) AS ts
"""

_MAX_WAL_SIZE_SQL = """
SELECT pg_size_bytes(setting || CASE WHEN unit = '' THEN '' ELSE unit END) AS bytes
FROM pg_settings
WHERE name = 'max_wal_size'
"""

_CHECKPOINT_TIMEOUT_SQL = """
SELECT setting::int AS seconds
FROM pg_settings
WHERE name = 'checkpoint_timeout'
"""

_DISK_BANDWIDTH_ESTIMATE_SQL = """
SELECT
    CASE
        WHEN current_setting('effective_io_concurrency')::int >= 200 THEN 500
        WHEN current_setting('effective_io_concurrency')::int >= 100 THEN 250
        ELSE 100
    END AS estimated_disk_mb_per_sec
"""


class CheckpointPredictor:
    """
    Predict when checkpoint configuration will become a bottleneck.

    Extends CheckpointAuditor with forward-looking analysis.
    """

    def __init__(self) -> None:
        self._auditor = CheckpointAuditor()

    async def predict(
        self,
        conn: AsyncDBConnection,
        wal_rate_samples: list[WALRateSnapshot] | None = None,
    ) -> CheckpointForecast:
        """
        Run predictive checkpoint analysis.

        If wal_rate_samples is provided (from historical collection), uses them
        for trend analysis. Otherwise takes a single point-in-time measurement.
        """
        forecast = CheckpointForecast()

        # Run the existing checkpoint audit
        forecast.current_report = await self._auditor.analyze(conn)

        # Measure current WAL rate
        await self._measure_wal_rate(conn, forecast)

        # Get configuration
        await self._get_config(conn, forecast)

        # Compute predictions
        self._compute_capacity(forecast)
        self._predict_checkpoints(forecast)
        self._predict_io_impact(conn, forecast)

        # Trend analysis if historical data available
        if wal_rate_samples and len(wal_rate_samples) >= 2:
            self._compute_trend(wal_rate_samples, forecast)

        # Risk assessment
        self._assess_risk(forecast)

        return forecast

    async def _measure_wal_rate(
        self, conn: AsyncDBConnection, forecast: CheckpointForecast,
    ) -> None:
        """Measure WAL generation rate from bgwriter stats."""
        stats = forecast.current_report.stats
        age = stats.stats_age_seconds

        if age > 0 and stats.buffers_checkpoint > 0:
            # buffers_checkpoint * 8KB = total bytes written at checkpoint
            total_ckpt_bytes = stats.buffers_checkpoint * 8192
            # WAL generated ≈ checkpoint data * 1.5 (WAL amplification)
            wal_bytes = total_ckpt_bytes * 1.5
            forecast.wal_rate_bytes_per_sec = wal_bytes / age
        else:
            try:
                row = await conn.fetch(_WAL_RATE_SQL)
                if row:
                    r = row[0]
                    lsn = r[0] if isinstance(r, (list, tuple)) else getattr(r, "lsn_offset", 0)
                    # Rough estimate: total LSN / uptime
                    if age > 0:
                        forecast.wal_rate_bytes_per_sec = float(lsn or 0) / age
                    else:
                        forecast.wal_rate_bytes_per_sec = 0
            except Exception:
                forecast.wal_rate_bytes_per_sec = 0

        forecast.wal_rate_mb_per_min = forecast.wal_rate_bytes_per_sec * 60 / (1024 * 1024)
        forecast.wal_rate_gb_per_hour = forecast.wal_rate_bytes_per_sec * 3600 / (1024 ** 3)

    async def _get_config(
        self, conn: AsyncDBConnection, forecast: CheckpointForecast,
    ) -> None:
        try:
            rows = await conn.fetch(_MAX_WAL_SIZE_SQL)
            if rows:
                r = rows[0]
                val = r[0] if isinstance(r, (list, tuple)) else getattr(r, "bytes", 0)
                forecast.max_wal_size_bytes = int(val or 0)
        except Exception:
            forecast.max_wal_size_bytes = 1024 * 1024 * 1024  # 1GB default

        try:
            rows = await conn.fetch(_CHECKPOINT_TIMEOUT_SQL)
            if rows:
                r = rows[0]
                val = r[0] if isinstance(r, (list, tuple)) else getattr(r, "seconds", 300)
                forecast.checkpoint_timeout_sec = int(val or 300)
        except Exception:
            forecast.checkpoint_timeout_sec = 300

    def _compute_capacity(self, forecast: CheckpointForecast) -> None:
        rate = forecast.wal_rate_bytes_per_sec
        timeout = forecast.checkpoint_timeout_sec

        forecast.wal_capacity_per_timeout = rate * timeout

        if forecast.max_wal_size_bytes > 0:
            forecast.fill_ratio = forecast.wal_capacity_per_timeout / forecast.max_wal_size_bytes
        else:
            forecast.fill_ratio = 0.0

        if rate > 0 and forecast.max_wal_size_bytes > 0:
            forecast.time_to_wal_full_sec = forecast.max_wal_size_bytes / rate
        else:
            forecast.time_to_wal_full_sec = float("inf")

    def _predict_checkpoints(self, forecast: CheckpointForecast) -> None:
        if forecast.fill_ratio > 1.0:
            # WAL fills before timeout — forced checkpoints
            if forecast.time_to_wal_full_sec > 0:
                forecast.predicted_checkpoints_per_hour = 3600.0 / forecast.time_to_wal_full_sec
            else:
                forecast.predicted_checkpoints_per_hour = 0
        else:
            # Timer-driven checkpoints
            if forecast.checkpoint_timeout_sec > 0:
                forecast.predicted_checkpoints_per_hour = (
                    3600.0 / forecast.checkpoint_timeout_sec
                )
            else:
                forecast.predicted_checkpoints_per_hour = 0

    def _predict_io_impact(self, conn: Any, forecast: CheckpointForecast) -> None:
        # Estimate: checkpoint writes / disk bandwidth
        ckpt_write_rate = forecast.wal_rate_bytes_per_sec / (1024 * 1024)  # MB/s
        # Assume SSD ~500 MB/s, HDD ~100 MB/s — use middle ground
        estimated_disk_bandwidth = 250.0  # MB/s

        if estimated_disk_bandwidth > 0:
            forecast.predicted_io_pct = (ckpt_write_rate / estimated_disk_bandwidth) * 100
        else:
            forecast.predicted_io_pct = 0

    def _compute_trend(
        self,
        samples: list[WALRateSnapshot],
        forecast: CheckpointForecast,
    ) -> None:
        """Linear regression on WAL rate over time."""
        if len(samples) < 2:
            return

        forecast.has_trend_data = True
        n = len(samples)
        ts = [s.timestamp for s in samples]
        rates = [s.wal_rate_bytes_per_sec for s in samples]

        mean_t = sum(ts) / n
        mean_r = sum(rates) / n

        # Slope: Σ(t-mean_t)(r-mean_r) / Σ(t-mean_t)²
        num = sum((t - mean_t) * (r - mean_r) for t, r in zip(ts, rates))
        den = sum((t - mean_t) ** 2 for t in ts)

        if den == 0 or mean_r == 0:
            forecast.wal_rate_trend_pct_per_day = 0.0
            return

        slope_per_sec = num / den
        slope_per_day = slope_per_sec * 86400

        forecast.wal_rate_trend_pct_per_day = (slope_per_day / mean_r) * 100

        if forecast.wal_rate_trend_pct_per_day > 0 and forecast.fill_ratio < 1.0:
            current_rate = forecast.wal_rate_bytes_per_sec
            critical_rate = forecast.max_wal_size_bytes / forecast.checkpoint_timeout_sec

            if current_rate < critical_rate and slope_per_sec > 0:
                time_to_critical = (critical_rate - current_rate) / slope_per_sec
                forecast.days_until_critical = time_to_critical / 86400
            else:
                forecast.days_until_critical = float("inf")

    def _assess_risk(self, forecast: CheckpointForecast) -> None:
        # Determine risk level
        if forecast.fill_ratio > 2.0:
            forecast.risk_level = "critical"
            forecast.is_healthy = False
        elif forecast.fill_ratio > 1.0:
            forecast.risk_level = "high"
            forecast.is_healthy = False
        elif forecast.fill_ratio > 0.7:
            forecast.risk_level = "medium"
            forecast.is_healthy = True
        else:
            forecast.risk_level = "low"
            forecast.is_healthy = True

        if forecast.fill_ratio > 1.0:
            needed_gb = math.ceil(
                forecast.wal_capacity_per_timeout / (1024 ** 3) * 1.5
            )
            forecast.findings.append({
                "severity": "critical" if forecast.fill_ratio > 2.0 else "warning",
                "title": (
                    f"WAL fills {forecast.fill_ratio:.1f}x faster than checkpoint_timeout. "
                    "Forced checkpoints are inevitable."
                ),
                "fix": (
                    f"ALTER SYSTEM SET max_wal_size = '{needed_gb}GB'; "
                    "SELECT pg_reload_conf();"
                ),
            })

        if forecast.predicted_checkpoints_per_hour > 12:
            forecast.findings.append({
                "severity": "warning",
                "title": (
                    f"Predicted {forecast.predicted_checkpoints_per_hour:.0f} "
                    "checkpoints/hour (target: <12)"
                ),
                "fix": (
                    "ALTER SYSTEM SET checkpoint_timeout = '15min'; "
                    "ALTER SYSTEM SET max_wal_size = '10GB'; "
                    "SELECT pg_reload_conf();"
                ),
            })

        if forecast.predicted_io_pct > 20:
            forecast.findings.append({
                "severity": "warning",
                "title": (
                    f"Checkpoints consuming ~{forecast.predicted_io_pct:.0f}% "
                    "of estimated disk bandwidth"
                ),
                "fix": (
                    "ALTER SYSTEM SET checkpoint_completion_target = 0.9; "
                    "SELECT pg_reload_conf();"
                ),
            })

        if forecast.has_trend_data and forecast.days_until_critical < 30:
            forecast.findings.append({
                "severity": "warning",
                "title": (
                    f"At current growth rate, checkpoints become critical in "
                    f"~{forecast.days_until_critical:.0f} days"
                ),
                "fix": "Proactively increase max_wal_size or reduce write workload",
            })

        if not forecast.findings:
            forecast.findings.append({
                "severity": "info",
                "title": "Checkpoint configuration is healthy",
                "fix": "No action needed",
            })
