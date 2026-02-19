"""
Database probe module for Level 3 analysis.

Provides read-only database access to validate recommendations:
- Check if indexes already exist
- Verify table statistics freshness
- Get table size and row counts
- Query pg_stat_statements for query frequency (optional)

Design principle: Recommendations must be validated when possible.
"""

from querysense.db.probe import (
    DBBudget,
    DBProbe,
    IndexInfo,
    QueryStats,
    TableStats,
    TopQueryEntry,
    get_probe,
    is_db_available,
)
from querysense.db.infra_metrics import (
    InfraMetrics,
    DatabaseStats,
    BGWriterStats,
    ConnectionStats,
    collect_infra_metrics,
)
from querysense.db.wait_events import (
    WaitEventSnapshot,
    collect_wait_events,
)
from querysense.db.vacuum_advisor import (
    VacuumReport,
    collect_vacuum_health,
)
from querysense.db.long_queries import (
    LongQueryReport,
    detect_long_queries,
)
from querysense.db.index_bloat import (
    IndexReport,
    detect_redundant_indexes,
)
from querysense.db.config_auditor import (
    ConfigAuditReport,
    ConfigIssue,
    audit_config,
)
from querysense.db.schema_reviewer import (
    SchemaReviewReport,
    SchemaIssue,
    review_schema,
)
from querysense.db.bloat_estimator import (
    BloatEstimator,
    BloatReport,
    TableBloat,
    IndexBloat,
)
from querysense.db.xmin_horizon import (
    XminHorizonTracker,
    XminHorizonReport,
    XminBlocker,
)
from querysense.db.monitoring_setup import (
    MonitoringSetup,
    SetupReport,
)
from querysense.db.vacuum_history import (
    VacuumHistoryTracker,
    VacuumTrend,
    BloatPrediction,
)
from querysense.db.rds_cloudwatch import (
    RDSConfig,
    RDSMetricSnapshot,
    RDSMetricHistory,
    RDSMetricsCollector,
    MetricDataPoint,
)

__all__ = [
    "DBBudget",
    "DBProbe",
    "IndexInfo",
    "QueryStats",
    "TableStats",
    "TopQueryEntry",
    "get_probe",
    "is_db_available",
    "InfraMetrics",
    "DatabaseStats",
    "BGWriterStats",
    "ConnectionStats",
    "collect_infra_metrics",
    "WaitEventSnapshot",
    "collect_wait_events",
    "VacuumReport",
    "collect_vacuum_health",
    "LongQueryReport",
    "detect_long_queries",
    "IndexReport",
    "detect_redundant_indexes",
    "ConfigAuditReport",
    "ConfigIssue",
    "audit_config",
    "SchemaReviewReport",
    "SchemaIssue",
    "review_schema",
    "BloatEstimator",
    "BloatReport",
    "TableBloat",
    "IndexBloat",
    "XminHorizonTracker",
    "XminHorizonReport",
    "XminBlocker",
    "MonitoringSetup",
    "SetupReport",
    "VacuumHistoryTracker",
    "VacuumTrend",
    "BloatPrediction",
    "RDSConfig",
    "RDSMetricSnapshot",
    "RDSMetricHistory",
    "RDSMetricsCollector",
    "MetricDataPoint",
]
