"""
Rule: CPU vs I/O Query Classifier

Classifies each query plan as CPU-bound, I/O-bound, or balanced based on
buffer statistics, execution timing, and node characteristics. Provides a
clear percentage breakdown that pganalyze surfaces for Atlassian-scale
operations (3M queries/min).

Why it matters:
- CPU-bound queries benefit from query rewrites, fewer function calls,
  and parallel execution — not more RAM or faster disks.
- I/O-bound queries benefit from better indexes, covering indexes,
  increased shared_buffers, or faster storage — not more CPU cores.
- Misclassifying the bottleneck wastes tuning effort on the wrong axis.

How it works:
1. Walk the plan tree, summing I/O time (blk_read_time, blk_write_time)
   and total execution time.
2. For nodes with BUFFERS data: high cache miss ratio → I/O-bound signal.
3. For nodes without I/O timing (track_io_timing off): estimate from
   shared_read_blocks × avg_read_latency_ms.
4. Compute the split: io_pct = io_time / total_time.
5. Classify: ≥60% I/O → I/O-bound, ≤25% I/O → CPU-bound, else balanced.

Requires:
- EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) output for accurate results.
- track_io_timing = on for precise I/O measurement (degrades gracefully).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import (
    Finding,
    ImpactBand,
    NodeContext,
    RulePhase,
    Severity,
)
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput, PlanNode


class CPUIoClassifierConfig(RuleConfig):
    """Configuration for CPU vs I/O classification."""

    io_bound_threshold_pct: float = 60.0
    cpu_bound_threshold_pct: float = 25.0
    min_total_time_ms: float = 5.0
    estimated_read_latency_ms: float = 0.1


@register_rule
class CPUIoClassifier(Rule):
    """
    Classify query plans as CPU-bound, I/O-bound, or balanced.

    Provides actionable tuning direction: if I/O-bound, optimize disk access
    (indexes, shared_buffers, covering indexes). If CPU-bound, optimize the
    query itself (rewrites, fewer sorts, JIT compilation).
    """

    rule_id = "CPU_IO_CLASSIFIER"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Classifies queries as CPU-bound vs I/O-bound with percentage breakdown"
    config_schema = CPUIoClassifierConfig
    phase = RulePhase.AGGREGATE

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: CPUIoClassifierConfig = self.config  # type: ignore[assignment]
        root = explain.plan

        total_time = root.actual_total_time or 0.0
        if total_time < config.min_total_time_ms:
            return []

        stats = _collect_io_stats(root, config.estimated_read_latency_ms)

        io_pct = (stats.io_time_ms / total_time * 100) if total_time > 0 else 0.0
        cpu_pct = 100.0 - io_pct

        if io_pct >= config.io_bound_threshold_pct:
            classification = "I/O-bound"
            sev = Severity.WARNING
        elif io_pct <= config.cpu_bound_threshold_pct:
            classification = "CPU-bound"
            sev = Severity.INFO
        else:
            classification = "Balanced"
            sev = Severity.INFO

        context = NodeContext.from_node(root, self._root_path(), None)

        return [Finding(
            rule_id=self.rule_id,
            severity=sev,
            context=context,
            title=f"Query is {classification}: {cpu_pct:.0f}% CPU / {io_pct:.0f}% I/O",
            description=_build_description(
                classification, cpu_pct, io_pct, stats, total_time,
            ),
            suggestion=_build_suggestion(classification, stats),
            impact_band=(
                ImpactBand.HIGH if classification == "I/O-bound"
                else ImpactBand.LOW
            ),
            impact_score=min(10.0, round(io_pct / 10.0, 1)) if classification == "I/O-bound" else 1.0,
            metrics={
                "cpu_pct": round(cpu_pct, 1),
                "io_pct": round(io_pct, 1),
                "total_time_ms": round(total_time, 2),
                "io_time_ms": round(stats.io_time_ms, 2),
                "cpu_time_ms": round(total_time - stats.io_time_ms, 2),
                "shared_hit_blocks": stats.total_hits,
                "shared_read_blocks": stats.total_reads,
                "cache_hit_ratio": round(stats.cache_hit_ratio, 4),
                "io_timing_available": 1 if stats.has_io_timing else 0,
            },
        )]

    def _root_path(self):
        from querysense.analyzer.path import NodePath
        return NodePath.root()


class _IoStats:
    """Aggregated I/O statistics from plan tree."""
    __slots__ = (
        "io_time_ms", "total_hits", "total_reads",
        "temp_reads", "temp_writes", "has_io_timing",
    )

    def __init__(self) -> None:
        self.io_time_ms: float = 0.0
        self.total_hits: int = 0
        self.total_reads: int = 0
        self.temp_reads: int = 0
        self.temp_writes: int = 0
        self.has_io_timing: bool = False

    @property
    def cache_hit_ratio(self) -> float:
        total = self.total_hits + self.total_reads
        return self.total_hits / total if total > 0 else 1.0


def _collect_io_stats(node: "PlanNode", est_latency_ms: float) -> _IoStats:
    """Walk plan tree and aggregate I/O statistics."""
    stats = _IoStats()
    _walk(node, stats, est_latency_ms)
    return stats


def _walk(node: "PlanNode", stats: _IoStats, est_latency_ms: float) -> None:
    hit = node.shared_hit_blocks or 0
    read = node.shared_read_blocks or 0
    stats.total_hits += hit
    stats.total_reads += read

    temp_r = getattr(node, "temp_read_blocks", 0) or 0
    temp_w = getattr(node, "temp_written_blocks", 0) or 0
    stats.temp_reads += temp_r
    stats.temp_writes += temp_w

    io_read = getattr(node, "io_read_time", None) or getattr(node, "blk_read_time", None)
    io_write = getattr(node, "io_write_time", None) or getattr(node, "blk_write_time", None)

    if io_read is not None or io_write is not None:
        stats.has_io_timing = True
        stats.io_time_ms += (io_read or 0.0) + (io_write or 0.0)
    elif read > 0:
        stats.io_time_ms += read * est_latency_ms

    if node.plans:
        for child in node.plans:
            _walk(child, stats, est_latency_ms)


def _build_description(
    classification: str,
    cpu_pct: float,
    io_pct: float,
    stats: _IoStats,
    total_time: float,
) -> str:
    lines = [
        f"This query spent {cpu_pct:.0f}% of its {total_time:.1f}ms execution "
        f"on CPU (computation, sorting, hashing) and {io_pct:.0f}% on I/O "
        f"(disk reads, buffer cache misses).\n",
    ]

    if stats.total_reads + stats.total_hits > 0:
        lines.append(
            f"Buffer statistics: {stats.total_hits:,} cache hits, "
            f"{stats.total_reads:,} disk reads "
            f"(cache hit ratio: {stats.cache_hit_ratio:.1%})."
        )

    if stats.temp_reads + stats.temp_writes > 0:
        temp_mb = (stats.temp_reads + stats.temp_writes) * 8 / 1024
        lines.append(f"Temp disk usage: {temp_mb:.1f}MB (sorts/hashes spilling).")

    if not stats.has_io_timing:
        lines.append(
            "\nNote: track_io_timing is OFF. I/O time was estimated from "
            "block read counts. Enable it for precise measurement:\n"
            "  ALTER SYSTEM SET track_io_timing = on;\n"
            "  SELECT pg_reload_conf();"
        )

    lines.append(f"\nClassification: **{classification}**")
    return "\n".join(lines)


def _build_suggestion(classification: str, stats: _IoStats) -> str:
    if classification == "I/O-bound":
        parts = [
            "-- This query is I/O-bound. Focus on reducing disk reads:\n",
            "-- 1. Add covering indexes to avoid heap lookups:\n"
            "--    CREATE INDEX ON <table>(<filter_cols>) INCLUDE (<select_cols>);\n",
            "-- 2. Increase shared_buffers if cache hit ratio is low:\n"
            "--    ALTER SYSTEM SET shared_buffers = '4GB';\n",
        ]
        if stats.cache_hit_ratio < 0.95:
            parts.append(
                f"-- 3. Current cache hit ratio: {stats.cache_hit_ratio:.1%}\n"
                f"--    Target: ≥99% for OLTP workloads\n"
            )
        if stats.temp_reads + stats.temp_writes > 0:
            parts.append(
                "-- 4. Temp spills detected — increase work_mem:\n"
                "--    SET work_mem = '256MB';\n"
            )
        return "".join(parts)

    if classification == "CPU-bound":
        return (
            "-- This query is CPU-bound. Focus on reducing computation:\n"
            "-- 1. Simplify complex expressions or move logic to application\n"
            "-- 2. Use parallel query if not already:\n"
            "--    SET max_parallel_workers_per_gather = 4;\n"
            "-- 3. Consider JIT compilation for complex queries:\n"
            "--    SET jit = on; SET jit_above_cost = 100000;\n"
            "-- 4. Eliminate unnecessary sorts with index-ordered scans\n"
            "-- 5. Reduce result set size with tighter WHERE clauses\n"
        )

    return (
        "-- This query has a balanced CPU/I/O profile.\n"
        "-- Improvements in either area will help. Prioritize:\n"
        "-- 1. Index optimization for the largest I/O-bound nodes\n"
        "-- 2. Query simplification for the most CPU-intensive operations\n"
        "-- 3. Monitor with: EXPLAIN (ANALYZE, BUFFERS, TIMING)\n"
    )
