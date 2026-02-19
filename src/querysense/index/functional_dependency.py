"""
Functional Dependency Detection for Index Optimisation.

Detects functional dependencies between columns using PostgreSQL's
extended statistics (CREATE STATISTICS ... WITH dependencies). When
columns are functionally dependent (e.g., zipcode -> state), composite
indexes can be simplified.

Example:
    If zipcode determines state, index on (zipcode, state) can be
    simplified to just (zipcode), saving space and write overhead.

Based on pganalyze's Index Advisor 3.0 approach:
https://pganalyze.com/blog/index-advisor-v3
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FunctionalDependency:
    """
    A detected functional dependency between columns.

    determinant -> dependent means: knowing the determinant column's
    value uniquely determines the dependent column's value.
    """

    table: str
    determinant: tuple[str, ...]
    dependent: str
    confidence: float = 1.0  # Strength of dependency (0.0-1.0)
    source: str = "extended_statistics"  # How it was detected

    @property
    def description(self) -> str:
        """Human-readable description."""
        det = ", ".join(self.determinant)
        return f"{det} -> {self.dependent} (confidence: {self.confidence:.0%})"


@dataclass
class FDAnalysisResult:
    """Result of functional dependency analysis on an index."""

    original_columns: tuple[str, ...]
    optimized_columns: tuple[str, ...]
    dependencies_found: list[FunctionalDependency] = field(default_factory=list)
    columns_removed: list[str] = field(default_factory=list)
    was_optimized: bool = False

    @property
    def space_savings_estimate(self) -> float:
        """Estimated space savings from removing dependent columns (0.0-1.0)."""
        if not self.was_optimized or len(self.original_columns) == 0:
            return 0.0
        return len(self.columns_removed) / len(self.original_columns)


class FunctionalDependencyDetector:
    """
    Detect and exploit functional dependencies for index optimization.

    Uses two detection methods:
    1. PostgreSQL extended statistics (CREATE STATISTICS WITH dependencies)
    2. Heuristic correlation analysis from column statistics

    The detector can be used with or without a database connection:
    - With connection: queries pg_statistic_ext for real dependency data
    - Without connection: uses provided statistics or known patterns
    """

    def __init__(self) -> None:
        # Known common functional dependencies
        # These are pattern-based heuristics for common schemas
        self._known_patterns: list[tuple[str, str]] = [
            ("zipcode", "state"),
            ("zipcode", "city"),
            ("zip_code", "state"),
            ("zip_code", "city"),
            ("city", "state"),
            ("country_code", "country_name"),
            ("country_code", "country"),
            ("currency_code", "currency_name"),
            ("category_id", "category_name"),
            ("department_id", "department_name"),
            ("status_code", "status_name"),
        ]

    def detect_from_statistics(
        self,
        table: str,
        columns: list[str],
        extended_stats: list[dict[str, Any]] | None = None,
    ) -> list[FunctionalDependency]:
        """
        Detect functional dependencies from PostgreSQL extended statistics.

        Args:
            table: Table name.
            columns: Columns to check.
            extended_stats: Results from pg_statistic_ext_data query.
                Expected format: [{"columns": ["a", "b"], "dependencies": {"a=>b": 0.95}}]

        Returns:
            List of detected functional dependencies.
        """
        dependencies: list[FunctionalDependency] = []

        if extended_stats:
            for stat in extended_stats:
                stat_columns = stat.get("columns", [])
                deps = stat.get("dependencies", {})
                for dep_str, confidence in deps.items():
                    if "=>" in dep_str:
                        parts = dep_str.split("=>")
                        if len(parts) == 2:
                            determinant = tuple(c.strip() for c in parts[0].split(","))
                            dependent = parts[1].strip()
                            # Only include if columns are in our candidate set
                            if all(c in columns for c in determinant) and dependent in columns:
                                dependencies.append(
                                    FunctionalDependency(
                                        table=table,
                                        determinant=determinant,
                                        dependent=dependent,
                                        confidence=float(confidence),
                                        source="extended_statistics",
                                    )
                                )

        # Also check known patterns
        dependencies.extend(self._detect_from_patterns(table, columns))

        return dependencies

    def _detect_from_patterns(
        self, table: str, columns: list[str]
    ) -> list[FunctionalDependency]:
        """Detect dependencies from known common patterns."""
        dependencies: list[FunctionalDependency] = []
        columns_lower = {c.lower(): c for c in columns}

        for det, dep in self._known_patterns:
            if det in columns_lower and dep in columns_lower:
                dependencies.append(
                    FunctionalDependency(
                        table=table,
                        determinant=(columns_lower[det],),
                        dependent=columns_lower[dep],
                        confidence=0.8,
                        source="known_pattern",
                    )
                )

        return dependencies

    def optimize_index_columns(
        self,
        table: str,
        columns: list[str],
        extended_stats: list[dict[str, Any]] | None = None,
        min_confidence: float = 0.7,
    ) -> FDAnalysisResult:
        """
        Optimize index columns by removing functionally dependent columns.

        If column A -> column B (A determines B), then an index on (A, B)
        can be simplified to just (A), because any query filtering on both
        will find the same rows with just (A).

        Args:
            table: Table name.
            columns: Ordered list of columns in the candidate index.
            extended_stats: PostgreSQL extended statistics data.
            min_confidence: Minimum confidence to act on a dependency.

        Returns:
            FDAnalysisResult with original and optimized columns.
        """
        if len(columns) <= 1:
            return FDAnalysisResult(
                original_columns=tuple(columns),
                optimized_columns=tuple(columns),
            )

        dependencies = self.detect_from_statistics(table, columns, extended_stats)

        # Filter by confidence
        strong_deps = [d for d in dependencies if d.confidence >= min_confidence]

        if not strong_deps:
            return FDAnalysisResult(
                original_columns=tuple(columns),
                optimized_columns=tuple(columns),
            )

        # Find columns that can be removed (they are determined by other columns)
        removable: set[str] = set()
        for dep in strong_deps:
            # Only remove if ALL determinant columns are in the index
            if all(d in columns for d in dep.determinant):
                removable.add(dep.dependent)

        # Never remove the first column (it's the leading column of the index)
        removable.discard(columns[0])

        optimized = [c for c in columns if c not in removable]
        removed = [c for c in columns if c in removable]

        return FDAnalysisResult(
            original_columns=tuple(columns),
            optimized_columns=tuple(optimized),
            dependencies_found=strong_deps,
            columns_removed=removed,
            was_optimized=len(removed) > 0,
        )

    def generate_create_statistics_sql(
        self,
        table: str,
        columns: list[str],
        schema: str = "public",
    ) -> str:
        """
        Generate SQL to create extended statistics for dependency detection.

        This helps PostgreSQL's planner and also feeds back into our
        dependency detection.
        """
        cols = ", ".join(columns)
        stat_name = f"stat_{table}_{'_'.join(columns[:3])}"
        return (
            f"CREATE STATISTICS IF NOT EXISTS {stat_name}\n"
            f"    (dependencies, ndistinct, mcv)\n"
            f"    ON {cols}\n"
            f"    FROM {schema}.{table};"
        )
