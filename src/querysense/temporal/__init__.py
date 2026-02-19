"""
Temporal Intelligence: plan history, change-point detection, drift analysis.

Provides:
- IR-based plan fingerprinting over time
- Change-point detection (PELT algorithm) for regression identification
- Drift classification: plan regression vs data drift vs environmental shift
- TimescaleDB-backed store for production (90-day retention, continuous aggregates)
- EWMA-based anomaly detection with proactive regression alerts
"""

from querysense.temporal.store import (
    PlanSnapshot,
    TemporalStore,
    InMemoryTemporalStore,
)
from querysense.temporal.sqlite_store import SQLiteTemporalStore
from querysense.temporal.changepoint import (
    Changepoint,
    detect_changepoints,
    pelt_changepoints,
)
from querysense.temporal.drift import (
    DriftType,
    DriftEvent,
    DriftAnalyzer,
)
from querysense.temporal.anomaly import (
    AnomalyReport,
    detect_anomalies,
    detect_anomalies_from_store,
)
from querysense.temporal.timescale_store import (
    TimescaleTemporalStore,
    TimeSeriesBucket,
    RegressionAlert,
    TrendSummary,
    EWMADetector,
)

__all__ = [
    "PlanSnapshot",
    "TemporalStore",
    "InMemoryTemporalStore",
    "SQLiteTemporalStore",
    # TimescaleDB production store
    "TimescaleTemporalStore",
    "TimeSeriesBucket",
    "RegressionAlert",
    "TrendSummary",
    "EWMADetector",
    # Change-point detection
    "Changepoint",
    "detect_changepoints",
    "pelt_changepoints",
    # Drift analysis
    "DriftType",
    "DriftEvent",
    "DriftAnalyzer",
    # Anomaly detection
    "AnomalyReport",
    "detect_anomalies",
    "detect_anomalies_from_store",
]
