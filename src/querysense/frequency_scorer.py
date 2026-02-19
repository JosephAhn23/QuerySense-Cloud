"""
Query Frequency Impact Scorer

Inspired by the CounterPath / pganalyze case study:
  "We use pganalyze frequently to identify problem areas. It's instrumental
   to see how often each query is called, not just which queries are slow."

This module re-ranks analyzer findings by combining:
  - impact_score  (how bad is the finding per execution?)
  - call frequency (how often is this query executed?)
  - mean duration  (how much wall-clock time per call?)

The composite score lets teams focus on the queries with the biggest
*aggregate* impact on the system, not just the slowest single execution.

Usage:
    from querysense.frequency_scorer import FrequencyScorer, QueryStats

    stats = QueryStats(calls_per_minute=350, mean_duration_ms=12.5)
    scorer = FrequencyScorer()
    ranked = scorer.rank_findings(result.findings, stats)
    for item in ranked:
        print(f"{item.composite_score:.1f}  {item.finding.title}")
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum

from querysense.analyzer.models import Finding, Severity


class ImpactTier(str, Enum):
    """Aggregate impact tier after frequency weighting."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass(frozen=True)
class QueryStats:
    """
    Frequency and duration statistics for a query, typically sourced
    from pg_stat_statements or an APM tool.
    """
    calls_per_minute: float = 0.0
    mean_duration_ms: float = 0.0
    total_exec_time_ms: float = 0.0
    stddev_duration_ms: float = 0.0
    rows_per_call: float = 0.0
    shared_blks_hit: int = 0
    shared_blks_read: int = 0

    @property
    def calls_per_second(self) -> float:
        return self.calls_per_minute / 60.0

    @property
    def cache_hit_ratio(self) -> float | None:
        total = self.shared_blks_hit + self.shared_blks_read
        if total == 0:
            return None
        return self.shared_blks_hit / total

    @property
    def total_time_per_minute_ms(self) -> float:
        return self.calls_per_minute * self.mean_duration_ms


@dataclass(frozen=True)
class RankedFinding:
    """A finding enriched with frequency-weighted composite score."""
    finding: Finding
    query_stats: QueryStats
    composite_score: float
    time_saved_per_minute_ms: float
    impact_tier: ImpactTier
    rank: int = 0

    @property
    def cpu_minutes_saved_per_hour(self) -> float:
        """Estimated CPU-minutes freed per hour if the finding is resolved."""
        return (self.time_saved_per_minute_ms * 60.0) / 60_000.0


@dataclass
class FrequencyScorer:
    """
    Ranks findings by aggregate system impact using query frequency data.

    Scoring formula:
        composite = impact_score × log2(1 + calls_per_min) × duration_weight

    where duration_weight = 1 + log10(1 + mean_duration_ms / 100)

    The log scales prevent extremely high-frequency but trivial queries
    from dominating the ranking over moderately frequent but expensive ones.
    """

    severity_multiplier: dict[Severity, float] = field(default_factory=lambda: {
        Severity.CRITICAL: 2.0,
        Severity.WARNING: 1.0,
        Severity.INFO: 0.5,
    })

    def score_finding(
        self,
        finding: Finding,
        stats: QueryStats,
    ) -> RankedFinding:
        freq_factor = math.log2(1.0 + stats.calls_per_minute)
        duration_weight = 1.0 + math.log10(1.0 + stats.mean_duration_ms / 100.0)
        sev_mult = self.severity_multiplier.get(finding.severity, 1.0)

        composite = finding.impact_score * freq_factor * duration_weight * sev_mult
        composite = round(composite, 2)

        improvement_fraction = min(finding.impact_score / 10.0, 1.0)
        time_saved = (
            stats.total_time_per_minute_ms * improvement_fraction
        )

        tier = self._classify_tier(composite)

        return RankedFinding(
            finding=finding,
            query_stats=stats,
            composite_score=composite,
            time_saved_per_minute_ms=round(time_saved, 2),
            impact_tier=tier,
        )

    def rank_findings(
        self,
        findings: tuple[Finding, ...] | list[Finding],
        stats: QueryStats,
    ) -> list[RankedFinding]:
        """Score all findings and return them sorted by composite score (desc)."""
        scored = [self.score_finding(f, stats) for f in findings]
        scored.sort(key=lambda r: r.composite_score, reverse=True)
        return [
            RankedFinding(
                finding=r.finding,
                query_stats=r.query_stats,
                composite_score=r.composite_score,
                time_saved_per_minute_ms=r.time_saved_per_minute_ms,
                impact_tier=r.impact_tier,
                rank=i + 1,
            )
            for i, r in enumerate(scored)
        ]

    @staticmethod
    def _classify_tier(score: float) -> ImpactTier:
        if score >= 50.0:
            return ImpactTier.CRITICAL
        if score >= 20.0:
            return ImpactTier.HIGH
        if score >= 5.0:
            return ImpactTier.MEDIUM
        if score >= 1.0:
            return ImpactTier.LOW
        return ImpactTier.NEGLIGIBLE

    def format_report(
        self,
        ranked: list[RankedFinding],
        *,
        top_n: int = 10,
    ) -> str:
        """Format a human-readable priority report."""
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║         FREQUENCY-WEIGHTED IMPACT REPORT                   ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
        ]

        if not ranked:
            lines.append("  No findings to rank.")
            return "\n".join(lines)

        stats = ranked[0].query_stats
        lines.append(
            f"  Query stats: {stats.calls_per_minute:.0f} calls/min, "
            f"{stats.mean_duration_ms:.1f} ms avg"
        )
        if stats.cache_hit_ratio is not None:
            lines.append(
                f"  Cache hit ratio: {stats.cache_hit_ratio:.1%}"
            )
        lines.append("")

        for item in ranked[:top_n]:
            sev = item.finding.severity.value.upper()
            lines.append(
                f"  #{item.rank}  [{sev}]  Score: {item.composite_score:.1f}  "
                f"({item.impact_tier.value})"
            )
            lines.append(f"       {item.finding.title}")
            lines.append(
                f"       Est. savings: {item.time_saved_per_minute_ms:.0f} "
                f"ms/min  ({item.cpu_minutes_saved_per_hour:.1f} CPU-min/hr)"
            )
            lines.append("")

        total_savings = sum(r.time_saved_per_minute_ms for r in ranked)
        lines.append(f"  Total potential savings: {total_savings:.0f} ms/min")
        lines.append(
            f"  ({total_savings * 60 / 60_000:.1f} CPU-minutes/hour)"
        )

        return "\n".join(lines)
