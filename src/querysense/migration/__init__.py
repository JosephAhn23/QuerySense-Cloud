"""Migration automation module — safety analysis and zero-downtime patterns."""

# Re-export original migration analyzer (was migration.py, now migration/analyzer.py)
from querysense.migration.analyzer import (
    DataImpact,
    LockAnalysis,
    LockLevel,
    MigrationAnalyzer,
    MigrationReport,
    PerformanceImpact,
    RiskLevel,
    SafeMigrationStep,
)

# Zero-downtime migration planner (new)
from querysense.migration.zero_downtime import (
    MigrationPhaseType,
    MigrationPhase,
    ZeroDowntimePlan,
    ZeroDowntimePlanner,
)

# Oracle-to-PostgreSQL hint translator
from querysense.migration.hint_translator import (
    Confidence as HintConfidence,
    HintTranslation,
    HintType,
    OracleHintTranslator,
    QueryTranslation,
)

__all__ = [
    # Original analyzer
    "DataImpact",
    "LockAnalysis",
    "LockLevel",
    "MigrationAnalyzer",
    "MigrationReport",
    "PerformanceImpact",
    "RiskLevel",
    "SafeMigrationStep",
    # Zero-downtime planner
    "MigrationPhaseType",
    "MigrationPhase",
    "ZeroDowntimePlan",
    "ZeroDowntimePlanner",
    # Hint translator
    "HintConfidence",
    "HintTranslation",
    "HintType",
    "OracleHintTranslator",
    "QueryTranslation",
]
