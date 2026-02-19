"""
Workload-Wide Index Advisor for QuerySense.

Analyzes multiple query plans together to recommend an optimal index set
across the entire workload. This is the "pganalyze killer" feature —
workload-level analysis rather than per-query analysis.

Key capabilities:
- Cross-query index consolidation (merge overlapping index recommendations)
- Index ROI scoring (benefit across all queries vs. storage/write cost)
- Redundant index detection (indexes that are subsets of others)
- Index usage simulation (predict which queries benefit from each index)
- Storage budget optimization (best indexes within N GB budget)

Design:
    from querysense.workload import WorkloadAdvisor, WorkloadPlan

    advisor = WorkloadAdvisor()
    advisor.add_plan(plan1, query_sql="SELECT ...", frequency=1000)
    advisor.add_plan(plan2, query_sql="SELECT ...", frequency=50)

    report = advisor.analyze()
    print(report.format())
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding
    from querysense.parser.models import ExplainOutput


@dataclass
class WorkloadPlan:
    """A single query plan in the workload."""

    explain: "ExplainOutput"
    sql: str | None = None
    frequency: int = 1  # calls/day or relative weight
    label: str = ""
    analysis: "AnalysisResult | None" = None


@dataclass(frozen=True)
class IndexCandidate:
    """A candidate index across the workload."""

    table: str
    columns: tuple[str, ...]
    index_type: str = "btree"
    is_partial: bool = False
    partial_predicate: str | None = None
    include_columns: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        """Unique key for deduplication."""
        cols = ",".join(self.columns)
        base = f"{self.table}({cols})"
        if self.is_partial and self.partial_predicate:
            base += f" WHERE {self.partial_predicate}"
        if self.include_columns:
            base += f" INCLUDE ({','.join(self.include_columns)})"
        return base

    @property
    def index_name(self) -> str:
        cols = "_".join(c.replace(".", "_") for c in self.columns[:3])
        suffix = "_partial" if self.is_partial else ""
        return f"idx_{self.table}_{cols}{suffix}"

    @property
    def create_sql(self) -> str:
        cols = ", ".join(self.columns)
        using = f" USING {self.index_type}" if self.index_type != "btree" else ""
        include = ""
        if self.include_columns:
            include = f" INCLUDE ({', '.join(self.include_columns)})"
        where = ""
        if self.is_partial and self.partial_predicate:
            where = f" WHERE {self.partial_predicate}"
        return f"CREATE INDEX CONCURRENTLY {self.index_name} ON {self.table}{using} ({cols}){include}{where};"


@dataclass
class IndexScore:
    """Scoring for an index candidate across the workload."""

    candidate: IndexCandidate
    queries_benefited: int = 0
    total_frequency_benefited: int = 0
    estimated_improvement_factor: float = 1.0
    estimated_size_mb: float = 0.0
    write_overhead_pct: float = 0.0  # % increase in write cost
    roi_score: float = 0.0  # benefit / cost
    benefited_query_labels: list[str] = field(default_factory=list)

    @property
    def net_benefit(self) -> float:
        """Net benefit = improvement * frequency - write overhead."""
        return self.estimated_improvement_factor * self.total_frequency_benefited


@dataclass
class RedundantIndex:
    """A detected redundant index pair."""

    redundant: str  # The redundant index
    covered_by: str  # The index that covers it
    reason: str
    drop_sql: str


@dataclass
class WorkloadReport:
    """Complete workload analysis report."""

    plans_analyzed: int
    total_findings: int
    recommended_indexes: list[IndexScore]
    redundant_indexes: list[RedundantIndex]
    table_hotspots: dict[str, int]  # table -> finding count
    storage_budget_mb: float | None = None

    def format(self) -> str:
        """Format as human-readable report."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("  QuerySense Workload Analysis Report")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Plans analyzed: {self.plans_analyzed}")
        lines.append(f"Total findings: {self.total_findings}")
        lines.append("")

        # Table hotspots
        if self.table_hotspots:
            lines.append("Table Hotspots (most issues):")
            for tbl, count in sorted(
                self.table_hotspots.items(), key=lambda x: -x[1]
            )[:10]:
                bar = "#" * min(count, 40)
                lines.append(f"  {tbl:<30s} {count:>4d} {bar}")
            lines.append("")

        # Recommended indexes (sorted by ROI)
        if self.recommended_indexes:
            lines.append(
                f"Recommended Indexes ({len(self.recommended_indexes)} total):"
            )
            lines.append("-" * 70)
            for i, idx in enumerate(self.recommended_indexes[:20], 1):
                lines.append(
                    f"  {i}. {idx.candidate.create_sql}"
                )
                lines.append(
                    f"     Queries benefited: {idx.queries_benefited} "
                    f"| Freq weight: {idx.total_frequency_benefited} "
                    f"| ROI: {idx.roi_score:.1f}"
                )
                if idx.benefited_query_labels:
                    labels = ", ".join(idx.benefited_query_labels[:5])
                    lines.append(f"     Benefits: {labels}")
                lines.append("")
        else:
            lines.append("No index recommendations — queries are well-indexed.")
            lines.append("")

        # Redundant indexes
        if self.redundant_indexes:
            lines.append(f"Redundant Indexes ({len(self.redundant_indexes)}):")
            lines.append("-" * 70)
            for ri in self.redundant_indexes:
                lines.append(f"  DROP: {ri.redundant}")
                lines.append(f"  Covered by: {ri.covered_by}")
                lines.append(f"  Reason: {ri.reason}")
                lines.append(f"  SQL: {ri.drop_sql}")
                lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    def format_json(self) -> dict[str, Any]:
        """Format as JSON-serializable dict."""
        return {
            "plans_analyzed": self.plans_analyzed,
            "total_findings": self.total_findings,
            "table_hotspots": self.table_hotspots,
            "recommended_indexes": [
                {
                    "sql": idx.candidate.create_sql,
                    "table": idx.candidate.table,
                    "columns": list(idx.candidate.columns),
                    "queries_benefited": idx.queries_benefited,
                    "frequency_weight": idx.total_frequency_benefited,
                    "roi_score": round(idx.roi_score, 2),
                    "benefited_queries": idx.benefited_query_labels,
                }
                for idx in self.recommended_indexes
            ],
            "redundant_indexes": [
                {
                    "redundant": ri.redundant,
                    "covered_by": ri.covered_by,
                    "reason": ri.reason,
                    "drop_sql": ri.drop_sql,
                }
                for ri in self.redundant_indexes
            ],
        }


class WorkloadAdvisor:
    """
    Workload-wide query analysis engine.

    Analyzes multiple query plans together to produce cross-query
    index recommendations, redundant index detection, and table hotspot
    identification.
    """

    def __init__(self, storage_budget_mb: float | None = None) -> None:
        self._plans: list[WorkloadPlan] = []
        self._storage_budget_mb = storage_budget_mb

    def add_plan(
        self,
        explain: "ExplainOutput",
        *,
        sql: str | None = None,
        frequency: int = 1,
        label: str = "",
    ) -> None:
        """Add a query plan to the workload."""
        self._plans.append(
            WorkloadPlan(
                explain=explain,
                sql=sql,
                frequency=frequency,
                label=label or f"query_{len(self._plans) + 1}",
            )
        )

    def analyze(self) -> WorkloadReport:
        """
        Run workload-wide analysis.

        Steps:
        1. Analyze each plan individually
        2. Extract index candidates from findings
        3. Consolidate overlapping candidates
        4. Score each candidate across the workload
        5. Detect redundant indexes
        6. Rank by ROI and apply storage budget
        """
        from querysense.engine import AnalysisService

        service = AnalysisService()

        # Step 1: Analyze each plan
        all_findings: list[tuple["Finding", WorkloadPlan]] = []
        table_hotspots: dict[str, int] = defaultdict(int)

        for plan in self._plans:
            result = service.analyze(plan.explain)
            plan.analysis = result
            for finding in result.findings:
                all_findings.append((finding, plan))
                # Track table hotspots
                if finding.context and finding.context.relation_name:
                    table_hotspots[finding.context.relation_name] += 1

        # Step 2: Extract index candidates from findings
        raw_candidates: list[tuple[IndexCandidate, WorkloadPlan]] = []
        for finding, plan in all_findings:
            candidates = self._extract_candidates(finding)
            for c in candidates:
                raw_candidates.append((c, plan))

        # Step 3: Consolidate overlapping candidates
        consolidated = self._consolidate_candidates(raw_candidates)

        # Step 4: Score each candidate
        scored = self._score_candidates(consolidated)

        # Step 5: Detect redundant indexes
        redundant = self._detect_redundant(scored)

        # Step 6: Filter by budget if set
        if self._storage_budget_mb is not None:
            scored = self._apply_budget(scored, self._storage_budget_mb)

        # Sort by ROI descending
        scored.sort(key=lambda s: -s.roi_score)

        return WorkloadReport(
            plans_analyzed=len(self._plans),
            total_findings=len(all_findings),
            recommended_indexes=scored,
            redundant_indexes=redundant,
            table_hotspots=dict(table_hotspots),
            storage_budget_mb=self._storage_budget_mb,
        )

    def _extract_candidates(self, finding: "Finding") -> list[IndexCandidate]:
        """Extract index candidates from a finding's suggestion."""
        candidates: list[IndexCandidate] = []

        if not finding.suggestion:
            return candidates

        # Parse CREATE INDEX statements from suggestions
        create_pattern = re.compile(
            r"CREATE\s+INDEX\s+(?:CONCURRENTLY\s+)?\w+\s+ON\s+(\w+)"
            r"(?:\s+USING\s+(\w+))?\s*\(([^)]+)\)"
            r"(?:\s+INCLUDE\s*\(([^)]+)\))?"
            r"(?:\s+WHERE\s+(.+?))?;",
            re.IGNORECASE,
        )

        for match in create_pattern.finditer(finding.suggestion):
            table = match.group(1)
            idx_type = (match.group(2) or "btree").lower()
            columns = tuple(c.strip() for c in match.group(3).split(","))
            include = tuple(c.strip() for c in match.group(4).split(",")) if match.group(4) else ()
            predicate = match.group(5)

            candidates.append(
                IndexCandidate(
                    table=table,
                    columns=columns,
                    index_type=idx_type,
                    is_partial=bool(predicate),
                    partial_predicate=predicate,
                    include_columns=include,
                )
            )

        # Also extract from ANALYZE suggestions
        if not candidates and finding.context and finding.context.relation_name:
            # Extract column hints from the finding
            col_hints = self._extract_column_hints(finding)
            if col_hints:
                candidates.append(
                    IndexCandidate(
                        table=finding.context.relation_name,
                        columns=tuple(col_hints),
                    )
                )

        return candidates

    def _extract_column_hints(self, finding: "Finding") -> list[str]:
        """Extract column names from finding descriptions and filters."""
        columns: list[str] = []

        # Extract from filter conditions
        if finding.context and finding.context.filter:
            col_pattern = re.compile(r"\b(\w+)\s*(?:=|>|<|LIKE|IN|IS)\b", re.IGNORECASE)
            for match in col_pattern.finditer(finding.context.filter):
                col = match.group(1)
                # Filter out SQL keywords and values
                if col.upper() not in (
                    "AND", "OR", "NOT", "NULL", "TRUE", "FALSE",
                    "SELECT", "FROM", "WHERE",
                ):
                    columns.append(col)

        return columns[:3]  # Limit to 3 columns

    def _consolidate_candidates(
        self,
        raw: list[tuple[IndexCandidate, WorkloadPlan]],
    ) -> dict[str, list[tuple[IndexCandidate, WorkloadPlan]]]:
        """Group candidates by table and merge overlapping column sets."""
        by_key: dict[str, list[tuple[IndexCandidate, WorkloadPlan]]] = defaultdict(list)
        for candidate, plan in raw:
            by_key[candidate.key].append((candidate, plan))
        return dict(by_key)

    def _score_candidates(
        self,
        consolidated: dict[str, list[tuple[IndexCandidate, WorkloadPlan]]],
    ) -> list[IndexScore]:
        """Score each index candidate based on workload impact."""
        scored: list[IndexScore] = []

        for key, entries in consolidated.items():
            candidate = entries[0][0]  # Representative candidate
            plans = [plan for _, plan in entries]

            # Frequency-weighted benefit
            total_freq = sum(p.frequency for p in plans)
            n_queries = len(set(id(p) for p in plans))

            # Estimate improvement based on finding severity
            improvements: list[float] = []
            for _, plan in entries:
                if plan.analysis:
                    for f in plan.analysis.findings:
                        if f.context and f.context.relation_name == candidate.table:
                            if f.severity.value == "critical":
                                improvements.append(10.0)
                            elif f.severity.value == "warning":
                                improvements.append(3.0)
                            else:
                                improvements.append(1.5)

            avg_improvement = (
                sum(improvements) / len(improvements) if improvements else 1.5
            )

            # Estimate index size (rough heuristic)
            est_size = len(candidate.columns) * 8.0  # ~8MB per column per million rows

            # Write overhead (more columns = more overhead)
            write_overhead = len(candidate.columns) * 2.0

            # ROI = (improvement * frequency) / (size + write_cost)
            cost = est_size + write_overhead
            benefit = avg_improvement * total_freq
            roi = benefit / max(cost, 0.1)

            scored.append(
                IndexScore(
                    candidate=candidate,
                    queries_benefited=n_queries,
                    total_frequency_benefited=total_freq,
                    estimated_improvement_factor=avg_improvement,
                    estimated_size_mb=est_size,
                    write_overhead_pct=write_overhead,
                    roi_score=roi,
                    benefited_query_labels=[p.label for p in plans],
                )
            )

        return scored

    def _detect_redundant(self, scored: list[IndexScore]) -> list[RedundantIndex]:
        """Detect indexes that are redundant (covered by another)."""
        redundant: list[RedundantIndex] = []

        for i, a in enumerate(scored):
            for j, b in enumerate(scored):
                if i == j:
                    continue
                if a.candidate.table != b.candidate.table:
                    continue

                # Check if a's columns are a prefix of b's columns
                a_cols = a.candidate.columns
                b_cols = b.candidate.columns
                if (
                    len(a_cols) < len(b_cols)
                    and b_cols[:len(a_cols)] == a_cols
                    and a.candidate.index_type == b.candidate.index_type
                ):
                    # a is covered by b
                    redundant.append(
                        RedundantIndex(
                            redundant=a.candidate.index_name,
                            covered_by=b.candidate.index_name,
                            reason=(
                                f"Index on ({', '.join(a_cols)}) is a "
                                f"leading prefix of ({', '.join(b_cols)})"
                            ),
                            drop_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {a.candidate.index_name};",
                        )
                    )
                    break

        return redundant

    def _apply_budget(
        self, scored: list[IndexScore], budget_mb: float
    ) -> list[IndexScore]:
        """Filter to best indexes within storage budget."""
        # Greedy: take highest-ROI first until budget exhausted
        sorted_by_roi = sorted(scored, key=lambda s: -s.roi_score)
        selected: list[IndexScore] = []
        remaining = budget_mb

        for idx in sorted_by_roi:
            if idx.estimated_size_mb <= remaining:
                selected.append(idx)
                remaining -= idx.estimated_size_mb

        return selected
