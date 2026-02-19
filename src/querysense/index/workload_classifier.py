"""
Automatic Table Workload Classifier.

Implements pganalyze's automatic table classification based on workload
characteristics. Tables are classified into one of four categories:

    WRITE_OPTIMIZED: writes/min > 60
        → Prioritise fewer indexes, allow higher scan costs
    READ_OPTIMIZED:  scans/min > 1000
        → Prioritise more indexes, minimise scan costs
    BALANCED:        neither threshold met
        → Balanced trade-off
    IGNORE:          table size < 10MB
        → Excluded entirely (not worth indexing)

Thresholds come from pganalyze's empirical research on when write overhead
starts to impact performance and when scan costs become noticeable.
They are configurable because every workload is different.

Reference:
    https://pganalyze.com/docs/index-advisor/configuration
"""

from __future__ import annotations

from dataclasses import dataclass, field

from querysense.index.cp_model import (
    Goal,
    GoalName,
    Rule,
    RuleName,
    SolverSettings,
    TableConfiguration,
)


@dataclass
class TableStats:
    """
    Statistics about a table's workload.

    These can be obtained from pg_stat_all_tables or provided manually.
    """

    table_name: str
    schema_name: str = "public"

    # Size
    table_size_bytes: int = 0

    # Write metrics (from pg_stat_all_tables)
    n_tup_ins: int = 0  # Total inserts since last reset
    n_tup_upd: int = 0  # Total updates
    n_tup_del: int = 0  # Total deletes
    n_tup_hot_upd: int = 0  # HOT updates

    # Read metrics
    seq_scan: int = 0  # Number of sequential scans
    seq_tup_read: int = 0  # Rows returned by sequential scans
    idx_scan: int = 0  # Number of index scans
    idx_tup_fetch: int = 0  # Rows fetched by index scans

    # Time window
    stats_reset_seconds: float = 86400.0  # How long since stats reset (default 1 day)

    @property
    def table_size_mb(self) -> float:
        """Table size in megabytes."""
        return self.table_size_bytes / (1024 * 1024)

    @property
    def writes_per_minute(self) -> float:
        """Total writes (INS + UPD + DEL) per minute."""
        if self.stats_reset_seconds <= 0:
            return 0.0
        total_writes = self.n_tup_ins + self.n_tup_upd + self.n_tup_del
        return total_writes / (self.stats_reset_seconds / 60.0)

    @property
    def scans_per_minute(self) -> float:
        """Total scans (seq + idx) per minute."""
        if self.stats_reset_seconds <= 0:
            return 0.0
        total_scans = self.seq_scan + self.idx_scan
        return total_scans / (self.stats_reset_seconds / 60.0)

    @property
    def hot_update_ratio(self) -> float:
        """Fraction of updates that are HOT (Heap-Only Tuple) updates."""
        if self.n_tup_upd <= 0:
            return 0.0
        return self.n_tup_hot_upd / self.n_tup_upd


@dataclass
class IndexingConfiguration:
    """
    CP model configuration derived from table classification.

    Encodes the goals, tolerances, and constraints appropriate
    for each table classification type.
    """

    config_type: TableConfiguration
    description: str = ""
    primary_goal: GoalName = GoalName.MINIMAL_COST
    secondary_goal: GoalName = GoalName.MINIMAL_INDEXES
    primary_tolerance: float = 0.1
    max_indexes: int | None = None
    max_iwo: float | None = None

    def to_solver_settings(self, time_limit: float = 10.0) -> SolverSettings:
        """Convert to SolverSettings for the CP solver."""
        goals = [
            Goal(name=self.primary_goal, strictness=1.0 - self.primary_tolerance),
            Goal(name=self.secondary_goal, strictness=1.0),
        ]
        rules: list[Rule] = []
        if self.max_indexes is not None:
            rules.append(
                Rule(name=RuleName.MAXIMUM_NUMBER_OF_INDEXES, value=float(self.max_indexes))
            )
        if self.max_iwo is not None:
            rules.append(Rule(name=RuleName.MAXIMUM_IWO, value=self.max_iwo))

        return SolverSettings(
            goals=goals,
            rules=rules,
            time_limit_seconds=time_limit,
        )


# Pre-defined configurations for each table classification type
CONFIGURATIONS: dict[TableConfiguration, IndexingConfiguration] = {
    TableConfiguration.WRITE_OPTIMIZED: IndexingConfiguration(
        config_type=TableConfiguration.WRITE_OPTIMIZED,
        description="Prioritize fewer indexes, allow higher scan costs",
        primary_goal=GoalName.MINIMAL_INDEXES,
        secondary_goal=GoalName.MINIMAL_COST,
        primary_tolerance=0.2,  # 20% slack on index count
        max_indexes=3,
    ),
    TableConfiguration.READ_OPTIMIZED: IndexingConfiguration(
        config_type=TableConfiguration.READ_OPTIMIZED,
        description="Prioritize performance, accept more indexes",
        primary_goal=GoalName.MINIMAL_COST,
        secondary_goal=GoalName.MINIMAL_INDEXES,
        primary_tolerance=0.1,  # 10% slack on cost
        max_indexes=10,
    ),
    TableConfiguration.BALANCED: IndexingConfiguration(
        config_type=TableConfiguration.BALANCED,
        description="Balanced trade-off between cost and index count",
        primary_goal=GoalName.MINIMAL_COST,
        secondary_goal=GoalName.MINIMAL_INDEXES,
        primary_tolerance=0.15,  # 15% slack on cost
        max_indexes=5,
    ),
    TableConfiguration.IGNORE: IndexingConfiguration(
        config_type=TableConfiguration.IGNORE,
        description="Table too small to benefit from indexing (<10MB)",
        primary_goal=GoalName.MINIMAL_COST,
        secondary_goal=GoalName.MINIMAL_INDEXES,
        primary_tolerance=0.0,
        max_indexes=0,
    ),
}


class WorkloadClassifier:
    """
    Classifies tables based on workload characteristics.

    Default thresholds from pganalyze:
        write_threshold = 60 writes/minute
        read_threshold = 1000 scans/minute
        min_table_size_mb = 10 MB
    """

    def __init__(
        self,
        write_threshold: float = 60.0,
        read_threshold: float = 1000.0,
        min_table_size_mb: float = 10.0,
    ) -> None:
        self.write_threshold = write_threshold
        self.read_threshold = read_threshold
        self.min_table_size_mb = min_table_size_mb

    def classify(self, stats: TableStats) -> TableConfiguration:
        """
        Classify a table into one of pganalyze's built-in configurations.

        Args:
            stats: Table statistics from pg_stat_all_tables.

        Returns:
            TableConfiguration enum value.
        """
        if stats.table_size_mb < self.min_table_size_mb:
            return TableConfiguration.IGNORE

        if stats.writes_per_minute > self.write_threshold:
            return TableConfiguration.WRITE_OPTIMIZED

        if stats.scans_per_minute > self.read_threshold:
            return TableConfiguration.READ_OPTIMIZED

        return TableConfiguration.BALANCED

    def get_configuration(self, stats: TableStats) -> IndexingConfiguration:
        """
        Get the full CP model configuration for a table.

        Args:
            stats: Table statistics.

        Returns:
            IndexingConfiguration with appropriate goals and rules.
        """
        config_type = self.classify(stats)
        return CONFIGURATIONS[config_type]

    def classify_with_details(
        self, stats: TableStats
    ) -> tuple[TableConfiguration, dict[str, float]]:
        """
        Classify and return the metrics that drove the decision.

        Returns:
            Tuple of (classification, metrics_dict).
        """
        config_type = self.classify(stats)
        metrics = {
            "table_size_mb": stats.table_size_mb,
            "writes_per_minute": stats.writes_per_minute,
            "scans_per_minute": stats.scans_per_minute,
            "hot_update_ratio": stats.hot_update_ratio,
            "write_threshold": self.write_threshold,
            "read_threshold": self.read_threshold,
            "min_table_size_mb": self.min_table_size_mb,
        }
        return config_type, metrics
