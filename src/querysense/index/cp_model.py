"""
Core data models for the Constraint Programming Index Advisor.

Defines the input/output data structures for the CP-SAT solver,
following the format from pganalyze's PGCon 2023 open-source model:
https://github.com/pganalyze/pgcon2023

The key abstractions:
    Scan  - A scan extracted from a query (WHERE/JOIN conditions)
    Index - A candidate index (existing or proposed)
    IndexSelectionProblem - Complete problem definition
    IndexSelectionSolution - Solution from the CP solver
    Goal / Rule / SolverSettings - Configuration for the optimizer
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class GoalName(str, Enum):
    """Available optimization goals (what to optimize for)."""

    MINIMAL_COST = "Minimal Cost"
    MAXIMAL_COVERAGE = "Maximal Coverage"
    MINIMAL_INDEXES = "Minimal Indexes"
    MINIMAL_IWO = "Minimal IWO"


class RuleName(str, Enum):
    """Available hard constraints (rules)."""

    MAXIMUM_NUMBER_OF_INDEXES = "Maximum Number of Indexes"
    MAXIMUM_IWO = "Maximum IWO"


class TableConfiguration(str, Enum):
    """
    Automatic table classification based on workload.

    Thresholds from pganalyze:
        WRITE_OPTIMIZED: writes/min > 60
        READ_OPTIMIZED:  scans/min > 1000
        BALANCED:        neither threshold met
        IGNORE:          table size < 10MB
    """

    WRITE_OPTIMIZED = "write_optimized"
    READ_OPTIMIZED = "read_optimized"
    BALANCED = "balanced"
    IGNORE = "ignore"


@dataclass(frozen=True)
class Scan:
    """
    A scan extracted from a query (WHERE/JOIN conditions).

    Corresponds to a row in pganalyze's input data format:
    {
        "Name": "scan_orders_by_user",
        "Sequential Cost": 15000,
        "Index Costs": [{"Index": "idx_user", "Cost": 150}, ...]
    }

    Attributes:
        id: Unique identifier for this scan.
        name: Human-readable description.
        sequential_cost: Cost of a sequential scan (no index).
        index_costs: Mapping of index_id -> cost when that index is used.
            Missing entries mean the index does not cover this scan.
        frequency: How often this scan executes (for weighting).
    """

    id: str
    name: str = ""
    sequential_cost: int = 0
    index_costs: dict[str, int] = field(default_factory=dict)
    frequency: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scan:
        """Create from pganalyze JSON format."""
        index_costs: dict[str, int] = {}
        for entry in data.get("Index Costs", []):
            cost = entry.get("Cost")
            if cost is not None:
                index_costs[entry["Index"]] = int(cost)
        return cls(
            id=data.get("Name", ""),
            name=data.get("Name", ""),
            sequential_cost=int(data.get("Sequential Cost", 0)),
            index_costs=index_costs,
            frequency=int(data.get("Frequency", 1)),
        )


@dataclass(frozen=True)
class Index:
    """
    A candidate index (existing or proposed).

    Attributes:
        id: Unique identifier matching keys in Scan.index_costs.
        name: Human-readable name (e.g., "idx_orders_customer_id").
        columns: Ordered list of columns in the index.
        table: Table this index belongs to.
        is_existing: True if this index already exists in the database.
        write_overhead: Index write overhead score (IWO).
        index_type: PostgreSQL index type (btree, gin, gist, brin, hash).
        size_bytes: Estimated or actual index size in bytes.
        definition: Full CREATE INDEX SQL if available.
    """

    id: str
    name: str = ""
    columns: tuple[str, ...] = ()
    table: str = ""
    is_existing: bool = False
    write_overhead: float = 0.0
    index_type: str = "btree"
    size_bytes: int = 0
    definition: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Index:
        """Create from dict representation."""
        cols = data.get("columns", [])
        return cls(
            id=data.get("id", data.get("name", "")),
            name=data.get("name", ""),
            columns=tuple(cols) if isinstance(cols, list) else (cols,),
            table=data.get("table", ""),
            is_existing=data.get("is_existing", False),
            write_overhead=float(data.get("write_overhead", 0.0)),
            index_type=data.get("index_type", "btree"),
            size_bytes=int(data.get("size_bytes", 0)),
            definition=data.get("definition", ""),
        )


@dataclass
class Goal:
    """
    An optimization goal with optional strictness parameter.

    The strictness (0.0-1.0) defines how much slack is allowed
    when optimizing subsequent goals in the hierarchy.

    Example:
        Goal(name=GoalName.MINIMAL_COST, strictness=0.9)
        -> Allow up to 10% worse than optimal cost
    """

    name: GoalName
    strictness: float = 1.0  # 1.0 = exact, 0.9 = 10% tolerance

    @property
    def tolerance(self) -> float:
        """Tolerance as a fraction (e.g., 0.1 for 10% slack)."""
        return 1.0 - self.strictness

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Goal:
        """Create from pganalyze JSON format."""
        name_str = data.get("Name", "Minimal Cost")
        try:
            name = GoalName(name_str)
        except ValueError:
            name = GoalName.MINIMAL_COST
        return cls(
            name=name,
            strictness=float(data.get("Strictness", 1.0)),
        )


@dataclass
class Rule:
    """
    A hard constraint (rule) for the optimizer.

    Example:
        Rule(name=RuleName.MAXIMUM_NUMBER_OF_INDEXES, value=5)
        -> No more than 5 indexes
    """

    name: RuleName
    value: float

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> list[Rule]:
        """Create rules from pganalyze settings JSON format."""
        rules: list[Rule] = []
        for key, value in data.items():
            try:
                name = RuleName(key)
                rules.append(cls(name=name, value=float(value)))
            except (ValueError, TypeError):
                continue
        return rules


@dataclass
class SolverSettings:
    """
    Complete solver configuration combining goals, rules, and parameters.

    Based on pganalyze's settings_example.json:
    {
        "Goals": [
            {"Name": "Minimal Cost", "Strictness": 0.9},
            {"Name": "Minimal Indexes"}
        ],
        "Rules": {
            "Maximum Number of Indexes": 4
        }
    }
    """

    goals: list[Goal] = field(default_factory=lambda: [
        Goal(name=GoalName.MINIMAL_COST, strictness=0.9),
        Goal(name=GoalName.MINIMAL_INDEXES),
    ])
    rules: list[Rule] = field(default_factory=list)
    time_limit_seconds: float = 10.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SolverSettings:
        """Create from pganalyze settings JSON format."""
        goals = [Goal.from_dict(g) for g in data.get("Goals", [])]
        rules = Rule.from_dict(data.get("Rules", {}))
        if not goals:
            goals = [
                Goal(name=GoalName.MINIMAL_COST, strictness=0.9),
                Goal(name=GoalName.MINIMAL_INDEXES),
            ]
        return cls(
            goals=goals,
            rules=rules,
            time_limit_seconds=float(data.get("TimeLimitSeconds", 10.0)),
        )

    @classmethod
    def default(cls) -> SolverSettings:
        """Default settings: minimize cost (10% tolerance), then minimize indexes."""
        return cls()


@dataclass
class IndexSelectionProblem:
    """
    Complete index selection problem definition.

    This is the input to the CP solver. It contains:
    - A set of scans (extracted from queries)
    - A set of candidate indexes
    - Configuration (goals, rules, time limit)

    Based on pganalyze's data_example.json format.
    """

    scans: list[Scan] = field(default_factory=list)
    indexes: list[Index] = field(default_factory=list)
    existing_indexes: list[str] = field(default_factory=list)
    index_write_overheads: dict[str, float] = field(default_factory=dict)
    settings: SolverSettings = field(default_factory=SolverSettings.default)

    @classmethod
    def from_dict(cls, data: dict[str, Any], settings: SolverSettings | None = None) -> IndexSelectionProblem:
        """
        Create from pganalyze's data JSON format.

        Expected format:
        {
            "Scans": [...],
            "Existing Indexes": ["idx_user"],
            "Index Write Overhead": {"idx_user": 10, ...}
        }
        """
        scans = [Scan.from_dict(s) for s in data.get("Scans", [])]

        # Collect all index IDs referenced across scans
        all_index_ids: set[str] = set()
        for scan in scans:
            all_index_ids.update(scan.index_costs.keys())

        existing = data.get("Existing Indexes", [])
        iwo = data.get("Index Write Overhead", {})

        indexes = [
            Index(
                id=idx_id,
                name=idx_id,
                is_existing=idx_id in existing,
                write_overhead=float(iwo.get(idx_id, 0.0)),
            )
            for idx_id in sorted(all_index_ids)
        ]

        return cls(
            scans=scans,
            indexes=indexes,
            existing_indexes=existing,
            index_write_overheads={k: float(v) for k, v in iwo.items()},
            settings=settings or SolverSettings.default(),
        )


@dataclass
class ScanResult:
    """Result for a single scan in the solution."""

    scan_id: str
    cost: int
    covering_index: str | None = None
    is_sequential: bool = False


@dataclass
class IndexSelectionSolution:
    """
    Solution from the CP solver.

    Contains the selected indexes, per-scan costs, and aggregate metrics.
    """

    status: str = "UNKNOWN"  # OPTIMAL, FEASIBLE, INFEASIBLE, UNKNOWN
    selected_indexes: list[str] = field(default_factory=list)
    scan_results: list[ScanResult] = field(default_factory=list)
    total_cost: int = 0
    total_indexes: int = 0
    total_write_overhead: float = 0.0
    solve_time_ms: float = 0.0
    objective_value: int = 0

    # Coverage metrics
    scans_covered: int = 0
    scans_uncovered: int = 0
    total_scans: int = 0

    @property
    def coverage_pct(self) -> float:
        """Percentage of scans covered by at least one index."""
        if self.total_scans == 0:
            return 0.0
        return (self.scans_covered / self.total_scans) * 100.0

    @property
    def is_optimal(self) -> bool:
        """Whether the solver found the provably optimal solution."""
        return self.status == "OPTIMAL"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "status": self.status,
            "selected_indexes": self.selected_indexes,
            "total_cost": self.total_cost,
            "total_indexes": self.total_indexes,
            "total_write_overhead": self.total_write_overhead,
            "solve_time_ms": round(self.solve_time_ms, 2),
            "coverage_pct": round(self.coverage_pct, 1),
            "scans_covered": self.scans_covered,
            "scans_uncovered": self.scans_uncovered,
            "scan_results": [
                {
                    "scan_id": sr.scan_id,
                    "cost": sr.cost,
                    "covering_index": sr.covering_index,
                    "is_sequential": sr.is_sequential,
                }
                for sr in self.scan_results
            ],
        }
