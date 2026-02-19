"""
CPU Impact Estimator

Inspired by the CounterPath / pganalyze case study:
  "With pganalyze's help, we improved a query that led to an instant CPU
   utilisation drop from 400% down to 25% on the live database server."

This module estimates the CPU impact of analyzer findings based on the
EXPLAIN plan's cost model and buffer statistics.  It answers the question:
"If I fix this finding, how much CPU will I save?"

PostgreSQL's cost model uses cpu_tuple_cost (0.01) and cpu_operator_cost
(0.0025) to estimate CPU work.  Combined with buffer hit/read ratios and
query frequency, we can produce a rough but actionable CPU estimate.

Usage:
    from querysense.cpu_impact import CPUEstimator, CPUImpact

    estimator = CPUEstimator()
    impact = estimator.estimate(finding, explain)
    print(f"Before: ~{impact.cpu_pct_before:.0f}%  After: ~{impact.cpu_pct_after:.0f}%")
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from querysense.analyzer.models import Finding, ImpactBand, Severity


class CPUReductionBand(str, Enum):
    """Expected CPU reduction band after fix."""
    DRAMATIC = "dramatic"      # >10x reduction (like 400% → 25%)
    SIGNIFICANT = "significant"  # 3-10x reduction
    MODERATE = "moderate"      # 1.5-3x reduction
    MINOR = "minor"           # <1.5x reduction
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CPUImpact:
    """Estimated CPU impact of resolving a finding."""
    finding_rule_id: str
    finding_title: str

    cpu_cost_before: float
    cpu_cost_after: float

    cpu_pct_before: float
    cpu_pct_after: float

    reduction_factor: float
    reduction_band: CPUReductionBand

    tuples_processed: int
    tuples_after_fix: int

    buffer_reads_before: int
    buffer_reads_after: int

    @property
    def cpu_pct_saved(self) -> float:
        return max(self.cpu_pct_before - self.cpu_pct_after, 0.0)

    @property
    def improvement_description(self) -> str:
        if self.reduction_factor >= 10:
            return (
                f"~{self.reduction_factor:.0f}x CPU reduction "
                f"({self.cpu_pct_before:.0f}% → {self.cpu_pct_after:.0f}%)"
            )
        if self.reduction_factor >= 2:
            return (
                f"~{self.reduction_factor:.1f}x CPU reduction "
                f"({self.cpu_pct_before:.1f}% → {self.cpu_pct_after:.1f}%)"
            )
        return f"~{self.cpu_pct_saved:.1f}% CPU reduction"


PG_CPU_TUPLE_COST = 0.01
PG_CPU_OPERATOR_COST = 0.0025
PG_SEQ_PAGE_COST = 1.0
PG_RANDOM_PAGE_COST = 4.0
PG_BLOCK_SIZE = 8192


@dataclass
class CPUEstimator:
    """
    Estimates CPU impact of findings using PostgreSQL cost-model constants.

    The model is intentionally conservative — it produces order-of-magnitude
    estimates, not precise predictions.  The goal is to help teams prioritise
    which findings to fix first based on expected CPU savings.
    """

    cpu_tuple_cost: float = PG_CPU_TUPLE_COST
    cpu_operator_cost: float = PG_CPU_OPERATOR_COST
    baseline_cpu_pct: float = 100.0

    def estimate(self, finding: Finding) -> CPUImpact:
        ctx = finding.context
        metrics = finding.metrics

        rows_before = metrics.get(
            "total_fetched",
            metrics.get(
                "rows_scanned",
                ctx.actual_rows or ctx.plan_rows or 0,
            ),
        )
        rows_before = int(rows_before)

        rows_removed = int(metrics.get("rows_removed_by_filter", 0))
        rows_after_fix = max(rows_before - rows_removed, ctx.actual_rows or 1)

        discard_ratio = metrics.get("discard_ratio", 0.0)
        if discard_ratio > 0:
            rows_after_fix = max(int(rows_before * (1.0 - discard_ratio)), 1)

        cpu_before = rows_before * self.cpu_tuple_cost
        if ctx.filter:
            cpu_before += rows_before * self.cpu_operator_cost

        cpu_after = rows_after_fix * self.cpu_tuple_cost
        if ctx.filter and discard_ratio < 0.5:
            cpu_after += rows_after_fix * self.cpu_operator_cost

        buf_reads_before = int(
            metrics.get("shared_read_blocks", 0)
            + metrics.get("rows_scanned", rows_before) / max(1, PG_BLOCK_SIZE // 100)
        )
        reduction_in_rows = max(rows_before / max(rows_after_fix, 1), 1.0)
        buf_reads_after = max(int(buf_reads_before / reduction_in_rows), 1)

        if cpu_before > 0 and cpu_after > 0:
            reduction = cpu_before / cpu_after
        elif cpu_before > 0:
            reduction = cpu_before
        else:
            reduction = 1.0

        cpu_pct_before = self._estimate_cpu_pct(finding, rows_before)
        cpu_pct_after = cpu_pct_before / max(reduction, 1.0)

        band = self._classify_reduction(reduction)

        return CPUImpact(
            finding_rule_id=finding.rule_id,
            finding_title=finding.title,
            cpu_cost_before=round(cpu_before, 4),
            cpu_cost_after=round(cpu_after, 4),
            cpu_pct_before=round(cpu_pct_before, 2),
            cpu_pct_after=round(cpu_pct_after, 2),
            reduction_factor=round(reduction, 2),
            reduction_band=band,
            tuples_processed=rows_before,
            tuples_after_fix=rows_after_fix,
            buffer_reads_before=buf_reads_before,
            buffer_reads_after=buf_reads_after,
        )

    def estimate_batch(
        self, findings: tuple[Finding, ...] | list[Finding],
    ) -> list[CPUImpact]:
        """Estimate CPU impact for all findings, sorted by reduction factor."""
        impacts = [self.estimate(f) for f in findings]
        impacts.sort(key=lambda i: i.reduction_factor, reverse=True)
        return impacts

    def _estimate_cpu_pct(self, finding: Finding, rows: int) -> float:
        """
        Rough CPU% estimate based on severity, row count, and cost.

        This is intentionally approximate — we use severity and impact_score
        as proxies since we don't have access to the full system load.
        """
        base = {
            Severity.CRITICAL: 40.0,
            Severity.WARNING: 15.0,
            Severity.INFO: 5.0,
        }.get(finding.severity, 10.0)

        row_factor = 1.0 + math.log10(max(rows, 1)) / 6.0
        score_factor = 1.0 + finding.impact_score / 5.0

        return min(base * row_factor * score_factor, 800.0)

    @staticmethod
    def _classify_reduction(factor: float) -> CPUReductionBand:
        if factor >= 10.0:
            return CPUReductionBand.DRAMATIC
        if factor >= 3.0:
            return CPUReductionBand.SIGNIFICANT
        if factor >= 1.5:
            return CPUReductionBand.MODERATE
        if factor > 1.0:
            return CPUReductionBand.MINOR
        return CPUReductionBand.UNKNOWN

    def format_report(
        self,
        impacts: list[CPUImpact],
        *,
        top_n: int = 10,
    ) -> str:
        """Format a human-readable CPU impact report."""
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║              CPU IMPACT ESTIMATION REPORT                  ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
        ]

        if not impacts:
            lines.append("  No findings to estimate.")
            return "\n".join(lines)

        for i, imp in enumerate(impacts[:top_n], 1):
            lines.append(
                f"  #{i}  [{imp.reduction_band.value.upper()}]  "
                f"{imp.reduction_factor:.1f}x reduction"
            )
            lines.append(f"       {imp.finding_title}")
            lines.append(f"       {imp.improvement_description}")
            lines.append(
                f"       Tuples: {imp.tuples_processed:,} → "
                f"{imp.tuples_after_fix:,}  |  "
                f"Buffers: {imp.buffer_reads_before:,} → "
                f"{imp.buffer_reads_after:,}"
            )
            lines.append("")

        dramatic = sum(1 for i in impacts if i.reduction_band == CPUReductionBand.DRAMATIC)
        significant = sum(1 for i in impacts if i.reduction_band == CPUReductionBand.SIGNIFICANT)

        if dramatic:
            lines.append(
                f"  ⚡ {dramatic} finding(s) with DRAMATIC CPU reduction potential (>10x)"
            )
        if significant:
            lines.append(
                f"  ⚡ {significant} finding(s) with SIGNIFICANT CPU reduction (3-10x)"
            )

        return "\n".join(lines)
