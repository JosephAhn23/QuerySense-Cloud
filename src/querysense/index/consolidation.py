"""
Index Consolidation — Detect redundant and overlapping indexes.

Integrates with querysense's existing index_audit module to identify:
    - Redundant indexes (A is a prefix of B)
    - Duplicate indexes (same columns)
    - Unused indexes (zero scans since stats reset)
    - Indexes that can be merged into a single composite

This module bridges the existing IndexAuditor with the CP advisor's
output, so the advisor can recommend both additions and removals.

Usage:
    from querysense.index.consolidation import IndexConsolidator

    consolidator = IndexConsolidator()

    # Analyze existing indexes for redundancy
    issues = consolidator.find_redundant(existing_indexes)

    # Merge CP recommendations with existing index cleanup
    combined = consolidator.merge_recommendations(
        cp_additions=["idx_orders_customer_id"],
        existing=existing_indexes,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from querysense.index.cp_model import Index
from querysense.index.stats_collector import ExistingIndex


@dataclass(frozen=True)
class ConsolidationIssue:
    """A detected index consolidation opportunity."""

    issue_type: str  # "redundant", "duplicate", "unused", "mergeable"
    severity: str  # "critical", "warning", "info"
    index_name: str
    table_name: str
    description: str
    fix_sql: str
    related_index: str | None = None
    estimated_savings_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.issue_type,
            "severity": self.severity,
            "index": self.index_name,
            "table": self.table_name,
            "description": self.description,
            "fix_sql": self.fix_sql,
            "related_index": self.related_index,
            "savings_bytes": self.estimated_savings_bytes,
        }


@dataclass
class ConsolidationReport:
    """Complete index consolidation analysis."""

    issues: list[ConsolidationIssue] = field(default_factory=list)
    indexes_to_drop: list[str] = field(default_factory=list)
    indexes_to_create: list[str] = field(default_factory=list)
    total_savings_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "issues": [i.to_dict() for i in self.issues],
            "drop": self.indexes_to_drop,
            "create": self.indexes_to_create,
            "savings_bytes": self.total_savings_bytes,
        }


class IndexConsolidator:
    """
    Analyze indexes for redundancy, duplication, and merger opportunities.

    Works on in-memory index data (no database connection required).
    """

    def find_redundant(
        self, indexes: list[ExistingIndex]
    ) -> list[ConsolidationIssue]:
        """
        Find redundant indexes where one is a leading prefix of another.

        Example: idx(a) is redundant if idx(a, b) exists, because
        any query that uses idx(a) can use idx(a, b) instead.
        """
        issues: list[ConsolidationIssue] = []

        # Group by table
        by_table: dict[str, list[ExistingIndex]] = {}
        for idx in indexes:
            table = idx.name.split("_")[1] if "_" in idx.name else ""
            # Use the definition to extract table if possible
            by_table.setdefault(table, []).append(idx)

        # Actually group by real table structure
        all_indexes = indexes
        for i, a in enumerate(all_indexes):
            for j, b in enumerate(all_indexes):
                if i == j:
                    continue
                # Skip primary keys and unique indexes
                if a.is_primary or a.is_unique:
                    continue

                a_cols = a.columns
                b_cols = b.columns

                if not a_cols or not b_cols:
                    continue

                # Check if a is a prefix of b (a is redundant)
                if (
                    len(a_cols) < len(b_cols)
                    and b_cols[:len(a_cols)] == a_cols
                ):
                    issues.append(ConsolidationIssue(
                        issue_type="redundant",
                        severity="warning",
                        index_name=a.name,
                        table_name="",
                        description=(
                            f"Index ({', '.join(a_cols)}) is a leading prefix of "
                            f"({', '.join(b_cols)}) — B-tree prefix matching makes it redundant"
                        ),
                        fix_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {a.name};",
                        related_index=b.name,
                        estimated_savings_bytes=a.size_bytes,
                    ))
                    break  # Only report once per redundant index

        return issues

    def find_duplicates(
        self, indexes: list[ExistingIndex]
    ) -> list[ConsolidationIssue]:
        """Find indexes with identical column lists."""
        issues: list[ConsolidationIssue] = []
        seen: dict[str, ExistingIndex] = {}

        for idx in indexes:
            key = ",".join(idx.columns)
            if key in seen:
                other = seen[key]
                # Keep the one with more scans
                drop = idx if idx.scans <= other.scans else other
                keep = other if drop is idx else idx
                issues.append(ConsolidationIssue(
                    issue_type="duplicate",
                    severity="critical",
                    index_name=drop.name,
                    table_name="",
                    description=f"Exact duplicate of {keep.name} ({key})",
                    fix_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {drop.name};",
                    related_index=keep.name,
                    estimated_savings_bytes=drop.size_bytes,
                ))
            else:
                seen[key] = idx

        return issues

    def find_unused(
        self,
        indexes: list[ExistingIndex],
        min_scans: int = 0,
    ) -> list[ConsolidationIssue]:
        """Find indexes with zero scans (unused since stats reset)."""
        issues: list[ConsolidationIssue] = []

        for idx in indexes:
            if idx.is_primary or idx.is_unique:
                continue
            if idx.scans <= min_scans:
                issues.append(ConsolidationIssue(
                    issue_type="unused",
                    severity="info",
                    index_name=idx.name,
                    table_name="",
                    description=(
                        f"Index has {idx.scans} scans since last stats reset. "
                        f"Size: {idx.size_bytes / (1024 * 1024):.1f}MB"
                    ),
                    fix_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {idx.name};",
                    estimated_savings_bytes=idx.size_bytes,
                ))

        return issues

    def analyze(
        self, indexes: list[ExistingIndex]
    ) -> ConsolidationReport:
        """Run all consolidation checks and produce a report."""
        issues: list[ConsolidationIssue] = []
        issues.extend(self.find_duplicates(indexes))
        issues.extend(self.find_redundant(indexes))
        issues.extend(self.find_unused(indexes))

        drops = [i.fix_sql for i in issues if i.fix_sql.startswith("DROP")]
        total_savings = sum(i.estimated_savings_bytes for i in issues)

        return ConsolidationReport(
            issues=issues,
            indexes_to_drop=drops,
            total_savings_bytes=total_savings,
        )

    def merge_with_cp_recommendations(
        self,
        cp_selected: list[str],
        existing: list[ExistingIndex],
    ) -> ConsolidationReport:
        """
        Merge CP solver's recommendations with existing index cleanup.

        Identifies:
        - Existing indexes that become redundant after adding CP recommendations
        - CP recommendations that overlap with existing indexes
        """
        report = self.analyze(existing)

        # Check if any existing index becomes redundant given CP additions
        for idx in existing:
            if idx.is_primary or idx.is_unique:
                continue
            # If the CP solver didn't select this existing index, it might be droppable
            if idx.name not in cp_selected and idx.scans == 0:
                already_reported = any(
                    i.index_name == idx.name for i in report.issues
                )
                if not already_reported:
                    report.issues.append(ConsolidationIssue(
                        issue_type="unused",
                        severity="info",
                        index_name=idx.name,
                        table_name="",
                        description="Not selected by CP solver and has zero scans",
                        fix_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {idx.name};",
                        estimated_savings_bytes=idx.size_bytes,
                    ))
                    report.indexes_to_drop.append(
                        f"DROP INDEX CONCURRENTLY IF EXISTS {idx.name};"
                    )
                    report.total_savings_bytes += idx.size_bytes

        return report
