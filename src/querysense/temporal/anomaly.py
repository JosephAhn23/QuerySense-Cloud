"""
Statistical anomaly detection for query performance time series.

Detects outliers and anomalies in query latency, cost, and row counts
using multiple statistical methods. Closes the gap vs Datadog's
anomaly detection and alerts.

Methods:
- Z-score: Standard deviation from mean (good for normal distributions)
- IQR (Interquartile Range): Robust to outliers (better for skewed data)
- MAD (Median Absolute Deviation): Very robust outlier detection
- EWMA (Exponential Weighted Moving Average): Trend-aware detection

Usage:
    from querysense.temporal.anomaly import detect_anomalies, AnomalyReport

    # From raw values
    report = detect_anomalies(latencies, method="iqr")
    for anomaly in report.anomalies:
        print(f"Index {anomaly.index}: {anomaly.value} ({anomaly.severity})")

    # From temporal store snapshots
    report = detect_anomalies_from_store(store, query_id="users_by_email")
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Anomaly:
    """A single detected anomaly."""

    index: int
    value: float
    expected: float
    deviation: float  # How many sigma/IQR from expected
    severity: str  # "info", "warning", "critical"
    method: str
    timestamp: str = ""
    query_id: str = ""

    @property
    def pct_deviation(self) -> float:
        if self.expected == 0:
            return 0.0
        return ((self.value - self.expected) / self.expected) * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "value": round(self.value, 2),
            "expected": round(self.expected, 2),
            "deviation": round(self.deviation, 2),
            "pct_deviation": round(self.pct_deviation, 1),
            "severity": self.severity,
            "method": self.method,
            "timestamp": self.timestamp,
            "query_id": self.query_id,
        }


@dataclass
class AnomalyReport:
    """Results of anomaly detection."""

    method: str
    values_count: int = 0
    anomalies: list[Anomaly] = field(default_factory=list)
    mean: float = 0.0
    median: float = 0.0
    std: float = 0.0
    iqr: float = 0.0
    threshold_low: float = 0.0
    threshold_high: float = 0.0

    @property
    def anomaly_count(self) -> int:
        return len(self.anomalies)

    @property
    def has_anomalies(self) -> bool:
        return len(self.anomalies) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.anomalies if a.severity == "critical")

    def summary(self) -> str:
        if not self.has_anomalies:
            return f"No anomalies in {self.values_count} values ({self.method})"
        return (
            f"{self.anomaly_count} anomaly(ies) in {self.values_count} values "
            f"({self.method}): {self.critical_count} critical"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "values_count": self.values_count,
            "anomaly_count": self.anomaly_count,
            "critical_count": self.critical_count,
            "summary": self.summary(),
            "stats": {
                "mean": round(self.mean, 2),
                "median": round(self.median, 2),
                "std": round(self.std, 2),
                "iqr": round(self.iqr, 2),
                "threshold_low": round(self.threshold_low, 2),
                "threshold_high": round(self.threshold_high, 2),
            },
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


# ── Statistical helpers ──────────────────────────────────────────────

def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    if n % 2 == 0:
        return (s[n // 2 - 1] + s[n // 2]) / 2
    return s[n // 2]


def _std(values: list[float], mean_val: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean_val) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = (len(s) - 1) * pct
    lower = int(idx)
    upper = min(lower + 1, len(s) - 1)
    frac = idx - lower
    return s[lower] * (1 - frac) + s[upper] * frac


def _mad(values: list[float]) -> float:
    """Median Absolute Deviation."""
    med = _median(values)
    deviations = [abs(v - med) for v in values]
    return _median(deviations) * 1.4826  # Scale factor for normal distribution


def _severity_from_deviation(deviation: float) -> str:
    """Classify anomaly severity based on deviation magnitude."""
    if abs(deviation) >= 4.0:
        return "critical"
    if abs(deviation) >= 3.0:
        return "warning"
    return "info"


# ── Detection methods ────────────────────────────────────────────────

def _detect_zscore(
    values: list[float],
    threshold: float = 3.0,
) -> AnomalyReport:
    """Z-score based anomaly detection."""
    report = AnomalyReport(method="zscore", values_count=len(values))
    if len(values) < 5:
        return report

    m = _mean(values)
    s = _std(values, m)
    report.mean = m
    report.std = s

    if s == 0:
        return report

    report.threshold_low = m - threshold * s
    report.threshold_high = m + threshold * s

    for i, v in enumerate(values):
        z = (v - m) / s
        if abs(z) > threshold:
            report.anomalies.append(Anomaly(
                index=i,
                value=v,
                expected=m,
                deviation=z,
                severity=_severity_from_deviation(z),
                method="zscore",
            ))

    return report


def _detect_iqr(
    values: list[float],
    multiplier: float = 1.5,
) -> AnomalyReport:
    """IQR-based anomaly detection (robust to skewed distributions)."""
    report = AnomalyReport(method="iqr", values_count=len(values))
    if len(values) < 5:
        return report

    q1 = _percentile(values, 0.25)
    q3 = _percentile(values, 0.75)
    iqr = q3 - q1
    report.iqr = iqr
    report.mean = _mean(values)
    report.median = _median(values)

    if iqr == 0:
        return report

    lower = q1 - multiplier * iqr
    upper = q3 + multiplier * iqr
    report.threshold_low = lower
    report.threshold_high = upper

    for i, v in enumerate(values):
        if v < lower:
            deviation = (v - q1) / iqr
            report.anomalies.append(Anomaly(
                index=i, value=v, expected=report.median,
                deviation=deviation, severity=_severity_from_deviation(deviation),
                method="iqr",
            ))
        elif v > upper:
            deviation = (v - q3) / iqr
            report.anomalies.append(Anomaly(
                index=i, value=v, expected=report.median,
                deviation=deviation, severity=_severity_from_deviation(deviation),
                method="iqr",
            ))

    return report


def _detect_mad(
    values: list[float],
    threshold: float = 3.0,
) -> AnomalyReport:
    """MAD-based anomaly detection (very robust)."""
    report = AnomalyReport(method="mad", values_count=len(values))
    if len(values) < 5:
        return report

    med = _median(values)
    mad_val = _mad(values)
    report.median = med
    report.mean = _mean(values)

    if mad_val == 0:
        return report

    report.threshold_low = med - threshold * mad_val
    report.threshold_high = med + threshold * mad_val

    for i, v in enumerate(values):
        deviation = (v - med) / mad_val
        if abs(deviation) > threshold:
            report.anomalies.append(Anomaly(
                index=i, value=v, expected=med,
                deviation=deviation, severity=_severity_from_deviation(deviation),
                method="mad",
            ))

    return report


def _detect_ewma(
    values: list[float],
    span: int = 10,
    threshold: float = 3.0,
) -> AnomalyReport:
    """EWMA-based anomaly detection (trend-aware)."""
    report = AnomalyReport(method="ewma", values_count=len(values))
    if len(values) < 5:
        return report

    alpha = 2.0 / (span + 1)
    report.mean = _mean(values)
    report.std = _std(values, report.mean)

    # Compute EWMA
    ewma = values[0]
    ewma_var = 0.0

    for i, v in enumerate(values):
        if i == 0:
            ewma = v
            ewma_var = 0.0
            continue

        ewma = alpha * v + (1 - alpha) * ewma
        ewma_var = alpha * (v - ewma) ** 2 + (1 - alpha) * ewma_var
        ewma_std = math.sqrt(ewma_var) if ewma_var > 0 else 1.0

        if ewma_std > 0:
            deviation = (v - ewma) / ewma_std
            if abs(deviation) > threshold:
                report.anomalies.append(Anomaly(
                    index=i, value=v, expected=ewma,
                    deviation=deviation, severity=_severity_from_deviation(deviation),
                    method="ewma",
                ))

    return report


# ── Public API ───────────────────────────────────────────────────────

_METHODS = {
    "zscore": _detect_zscore,
    "iqr": _detect_iqr,
    "mad": _detect_mad,
    "ewma": _detect_ewma,
}


def detect_anomalies(
    values: list[float],
    method: str = "iqr",
    **kwargs: Any,
) -> AnomalyReport:
    """
    Detect anomalies in a list of values.

    Args:
        values: Time series values (e.g., latencies, costs)
        method: Detection method - "zscore", "iqr", "mad", or "ewma"
        **kwargs: Method-specific parameters (threshold, multiplier, span)

    Returns:
        AnomalyReport with detected anomalies
    """
    detector = _METHODS.get(method, _detect_iqr)
    return detector(values, **kwargs)


def detect_anomalies_from_store(
    store: Any,
    query_id: str,
    metric: str = "cost_total",
    method: str = "iqr",
    days: int = 30,
) -> AnomalyReport:
    """
    Detect anomalies from a temporal store's snapshot history.

    Args:
        store: SQLiteTemporalStore instance
        query_id: Query identifier
        metric: Which metric to analyze ("cost_total", "latency_p50_ms")
        method: Detection method
        days: How many days of history to use

    Returns:
        AnomalyReport with timestamps on anomalies
    """
    from datetime import datetime, timedelta, timezone

    since = datetime.now(timezone.utc) - timedelta(days=days)
    snapshots = store.query(query_id, since=since)

    if not snapshots:
        return AnomalyReport(method=method, values_count=0)

    values = []
    timestamps = []
    for snap in snapshots:
        val = getattr(snap, metric, None)
        if val is not None:
            values.append(float(val))
            timestamps.append(snap.timestamp.isoformat())

    report = detect_anomalies(values, method=method)

    # Add timestamps to anomalies
    for anomaly in report.anomalies:
        if anomaly.index < len(timestamps):
            anomaly.timestamp = timestamps[anomaly.index]
            anomaly.query_id = query_id

    return report
