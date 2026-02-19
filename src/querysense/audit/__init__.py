"""
Audit Suite — PostgreSQL log and runtime health analysis.

Implements the features pganalyze charges $149/month for:
    - Lock contention detection (blocking chains, wait duration)
    - Checkpoint frequency and I/O impact analysis
    - Deadlock log parsing and cycle visualization
    - Connection audit (auth failures, SOC2 compliance)
    - Temp file detection (queries spilling to disk)
    - PostgreSQL log parser engine
"""

from querysense.audit.log_parser import LogEvent, LogParser, LogSeverity
from querysense.audit.checkpoints import CheckpointAuditor, CheckpointReport
from querysense.audit.deadlocks import DeadlockParser, DeadlockEvent
from querysense.audit.connections import ConnectionAuditor, ConnectionReport
from querysense.audit.tempfiles import TempFileAuditor, TempFileReport
from querysense.audit.vacuum_tracker import VacuumTracker, VacuumTrackerReport
from querysense.audit.plan_history import PlanHistoryTracker, PlanHistoryReport
from querysense.audit.table_health import TableHealthDashboard, TableHealthReport
from querysense.audit.logger import AuditLogger, AuditEvent, AuditEventType
from querysense.audit.cost_model import CostModelAuditor, CostModelReport
from querysense.audit.dependencies import ColumnDependencyDetector, DependencyReport
from querysense.audit.gin_advisor import GINIndexAdvisor, GINReport
from querysense.audit.query_load import QueryLoadProfiler, QueryLoadReport
from querysense.audit.index_bloat import IndexBloatCalculator, IndexBloatReport

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "CheckpointAuditor",
    "CheckpointReport",
    "ColumnDependencyDetector",
    "ConnectionAuditor",
    "ConnectionReport",
    "CostModelAuditor",
    "CostModelReport",
    "DeadlockEvent",
    "DeadlockParser",
    "DependencyReport",
    "GINIndexAdvisor",
    "GINReport",
    "IndexBloatCalculator",
    "IndexBloatReport",
    "LogEvent",
    "LogParser",
    "LogSeverity",
    "PlanHistoryReport",
    "PlanHistoryTracker",
    "QueryLoadProfiler",
    "QueryLoadReport",
    "TableHealthDashboard",
    "TableHealthReport",
    "TempFileAuditor",
    "TempFileReport",
    "VacuumTracker",
    "VacuumTrackerReport",
]
