"""
Load Test Comparison Mode

Inspired by the CounterPath / pganalyze case study:
  "We are not just using pganalyze to get insights on user load, but also
   for doing QA. For example, by performing activities like doing a
   large-scale load test against the sync server to see what pganalyze
   can tell us about it."

This module provides a before/after comparison framework for QA load
testing.  Feed it EXPLAIN snapshots from before and after a change, and
it produces a structured comparison report showing:
  - Which findings were resolved
  - Which findings are new (regressions)
  - Which findings persist
  - Aggregate improvement metrics (execution time, cost, row estimates)

Usage:
    from querysense.load_test import LoadTestComparison, PlanSnapshot

    before = PlanSnapshot.from_analysis(before_result, label="baseline v1.2")
    after = PlanSnapshot.from_analysis(after_result, label="candidate v1.3")

    comparison = LoadTestComparison()
    report = comparison.compare(before, after)
    print(report.format())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from querysense.analyzer.models import AnalysisResult, Finding, Severity


class ChangeStatus(str, Enum):
    RESOLVED = "resolved"
    NEW = "new"
    PERSISTS = "persists"
    IMPROVED = "improved"
    REGRESSED = "regressed"


@dataclass(frozen=True)
class FindingDelta:
    """Comparison between a before/after finding pair."""
    finding: Finding
    status: ChangeStatus
    before_score: float = 0.0
    after_score: float = 0.0
    score_delta: float = 0.0

    @property
    def is_improvement(self) -> bool:
        return self.status in (ChangeStatus.RESOLVED, ChangeStatus.IMPROVED)

    @property
    def is_regression(self) -> bool:
        return self.status in (ChangeStatus.NEW, ChangeStatus.REGRESSED)


@dataclass(frozen=True)
class PlanSnapshot:
    """A snapshot of analysis results at a point in time."""
    label: str
    findings: tuple[Finding, ...]
    execution_time_ms: float | None = None
    total_cost: float = 0.0
    node_count: int = 0
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_analysis(
        cls,
        result: AnalysisResult,
        label: str = "snapshot",
    ) -> "PlanSnapshot":
        findings = result.findings
        return cls(
            label=label,
            findings=findings,
            execution_time_ms=result.metadata.execution_time_ms,
            total_cost=sum(
                f.context.total_cost for f in findings
            ),
            node_count=result.metadata.node_count,
            critical_count=len(result.findings_by_severity(Severity.CRITICAL)),
            warning_count=len(result.findings_by_severity(Severity.WARNING)),
            info_count=len(result.findings_by_severity(Severity.INFO)),
        )


def _finding_key(f: Finding) -> str:
    """Generate a stable key for matching findings across snapshots."""
    return f"{f.rule_id}:{f.context.node_type}:{f.context.relation_name or ''}:{f.context.index_name or ''}"


@dataclass(frozen=True)
class ComparisonReport:
    """Complete before/after comparison report."""
    before: PlanSnapshot
    after: PlanSnapshot
    deltas: tuple[FindingDelta, ...]
    resolved_count: int = 0
    new_count: int = 0
    persists_count: int = 0
    improved_count: int = 0
    regressed_count: int = 0

    @property
    def is_improvement(self) -> bool:
        return (
            self.new_count == 0
            and self.regressed_count == 0
            and (self.resolved_count > 0 or self.improved_count > 0)
        )

    @property
    def is_regression(self) -> bool:
        return self.new_count > 0 or self.regressed_count > 0

    @property
    def execution_time_delta_ms(self) -> float | None:
        if self.before.execution_time_ms is None or self.after.execution_time_ms is None:
            return None
        return self.after.execution_time_ms - self.before.execution_time_ms

    @property
    def execution_time_improvement(self) -> float | None:
        if self.before.execution_time_ms is None or self.after.execution_time_ms is None:
            return None
        if self.after.execution_time_ms == 0:
            return float("inf")
        return self.before.execution_time_ms / self.after.execution_time_ms

    @property
    def cost_delta(self) -> float:
        return self.after.total_cost - self.before.total_cost

    def format(self) -> str:
        """Format a human-readable comparison report."""
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║          LOAD TEST COMPARISON REPORT                       ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
            f"  Before: {self.before.label}",
            f"  After:  {self.after.label}",
            "",
        ]

        if self.execution_time_delta_ms is not None:
            imp = self.execution_time_improvement
            delta = self.execution_time_delta_ms
            direction = "faster" if delta < 0 else "slower"
            lines.append(
                f"  Execution time: "
                f"{self.before.execution_time_ms:.1f} ms → "
                f"{self.after.execution_time_ms:.1f} ms  "
                f"({abs(delta):.1f} ms {direction}"
                f"{f', {imp:.1f}x' if imp and imp > 1 else ''})"
            )

        lines.append(
            f"  Findings: "
            f"{len(self.before.findings)} → {len(self.after.findings)}"
        )
        lines.append(
            f"  Critical: "
            f"{self.before.critical_count} → {self.after.critical_count}  |  "
            f"Warning: "
            f"{self.before.warning_count} → {self.after.warning_count}  |  "
            f"Info: "
            f"{self.before.info_count} → {self.after.info_count}"
        )
        lines.append("")

        if self.resolved_count:
            lines.append(f"  RESOLVED ({self.resolved_count}):")
            for d in self.deltas:
                if d.status == ChangeStatus.RESOLVED:
                    lines.append(f"    [+] {d.finding.title}")
            lines.append("")

        if self.improved_count:
            lines.append(f"  IMPROVED ({self.improved_count}):")
            for d in self.deltas:
                if d.status == ChangeStatus.IMPROVED:
                    lines.append(
                        f"    [~] {d.finding.title}  "
                        f"(score: {d.before_score:.1f} → {d.after_score:.1f})"
                    )
            lines.append("")

        if self.new_count:
            lines.append(f"  NEW REGRESSIONS ({self.new_count}):")
            for d in self.deltas:
                if d.status == ChangeStatus.NEW:
                    lines.append(
                        f"    [!] {d.finding.title}  "
                        f"(score: {d.after_score:.1f})"
                    )
            lines.append("")

        if self.regressed_count:
            lines.append(f"  REGRESSED ({self.regressed_count}):")
            for d in self.deltas:
                if d.status == ChangeStatus.REGRESSED:
                    lines.append(
                        f"    [!] {d.finding.title}  "
                        f"(score: {d.before_score:.1f} → {d.after_score:.1f})"
                    )
            lines.append("")

        if self.persists_count:
            lines.append(f"  UNCHANGED ({self.persists_count}):")
            for d in self.deltas:
                if d.status == ChangeStatus.PERSISTS:
                    lines.append(f"    [-] {d.finding.title}")
            lines.append("")

        verdict = "PASS" if self.is_improvement else "FAIL" if self.is_regression else "NEUTRAL"
        lines.append(f"  Verdict: {verdict}")

        return "\n".join(lines)


class LoadTestComparison:
    """Compares two PlanSnapshots and produces a structured delta report."""

    def compare(
        self,
        before: PlanSnapshot,
        after: PlanSnapshot,
    ) -> ComparisonReport:
        before_map: dict[str, Finding] = {}
        for f in before.findings:
            key = _finding_key(f)
            before_map[key] = f

        after_map: dict[str, Finding] = {}
        for f in after.findings:
            key = _finding_key(f)
            after_map[key] = f

        deltas: list[FindingDelta] = []

        for key, bf in before_map.items():
            if key not in after_map:
                deltas.append(FindingDelta(
                    finding=bf,
                    status=ChangeStatus.RESOLVED,
                    before_score=bf.impact_score,
                    after_score=0.0,
                    score_delta=-bf.impact_score,
                ))
            else:
                af = after_map[key]
                score_delta = af.impact_score - bf.impact_score

                if score_delta < -0.5:
                    status = ChangeStatus.IMPROVED
                elif score_delta > 0.5:
                    status = ChangeStatus.REGRESSED
                else:
                    status = ChangeStatus.PERSISTS

                deltas.append(FindingDelta(
                    finding=af,
                    status=status,
                    before_score=bf.impact_score,
                    after_score=af.impact_score,
                    score_delta=score_delta,
                ))

        for key, af in after_map.items():
            if key not in before_map:
                deltas.append(FindingDelta(
                    finding=af,
                    status=ChangeStatus.NEW,
                    before_score=0.0,
                    after_score=af.impact_score,
                    score_delta=af.impact_score,
                ))

        deltas.sort(key=lambda d: (d.status.value, -abs(d.score_delta)))

        return ComparisonReport(
            before=before,
            after=after,
            deltas=tuple(deltas),
            resolved_count=sum(1 for d in deltas if d.status == ChangeStatus.RESOLVED),
            new_count=sum(1 for d in deltas if d.status == ChangeStatus.NEW),
            persists_count=sum(1 for d in deltas if d.status == ChangeStatus.PERSISTS),
            improved_count=sum(1 for d in deltas if d.status == ChangeStatus.IMPROVED),
            regressed_count=sum(1 for d in deltas if d.status == ChangeStatus.REGRESSED),
        )
