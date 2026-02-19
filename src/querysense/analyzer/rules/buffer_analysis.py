"""
Rule: Buffer/IO Analysis

Detects inefficient buffer usage patterns that indicate poor cache behavior.
This is a critical depth signal that pganalyze surfaces prominently and
that most free tools miss entirely.

Analyzes:
- Cache miss ratio (shared_read vs shared_hit)
- Excessive temp buffer usage (temp_read + temp_written)
- I/O amplification (reads much larger than result set)
- Sequential I/O vs random I/O patterns

Why it matters:
- High cache miss ratios cause orders-of-magnitude slowdowns
- Temp buffer usage indicates work_mem pressure
- I/O patterns determine whether SSD vs HDD matters
- Buffer data only available with EXPLAIN (ANALYZE, BUFFERS)

Requires:
- EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) output
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


class BufferAnalysisConfig(RuleConfig):
    """Configuration for buffer analysis."""

    cache_miss_threshold_pct: float = 20.0  # % reads vs hits to flag
    temp_buffer_warning_kb: int = 10_240  # 10MB temp usage
    temp_buffer_critical_kb: int = 102_400  # 100MB temp usage
    io_amplification_threshold: float = 100.0  # reads per result row


@register_rule
class BufferAnalysis(Rule):
    """
    Analyze buffer usage patterns to detect I/O inefficiencies.

    Examines BUFFERS output from EXPLAIN ANALYZE to identify
    cache misses, temp spills, and I/O amplification.
    """

    rule_id = "BUFFER_ANALYSIS"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects inefficient buffer/IO patterns from EXPLAIN BUFFERS data"
    config_schema = BufferAnalysisConfig
    phase = RulePhase.PER_NODE

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: BufferAnalysisConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Check 1: Cache miss ratio
            hit = node.shared_hit_blocks or 0
            read = node.shared_read_blocks or 0
            total_blocks = hit + read

            if total_blocks > 100:  # Only meaningful with enough blocks
                miss_pct = (read / total_blocks) * 100

                if miss_pct >= config.cache_miss_threshold_pct:
                    severity = (
                        Severity.CRITICAL if miss_pct >= 50.0 else Severity.WARNING
                    )
                    context = NodeContext.from_node(node, path, parent)
                    table = node.relation_name or node.node_type

                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=severity,
                        context=context,
                        title=(
                            f"High cache miss rate on {table}: "
                            f"{miss_pct:.0f}% of blocks read from disk"
                        ),
                        description=(
                            f"This {node.node_type} on '{table}' has a "
                            f"{miss_pct:.1f}% cache miss rate "
                            f"({read:,} disk reads vs {hit:,} cache hits, "
                            f"{total_blocks:,} total blocks).\n\n"
                            f"High cache miss rates cause significant I/O latency. "
                            f"Each disk read is ~100x slower than a cache hit.\n\n"
                            + _cache_miss_explanation(miss_pct, total_blocks)
                        ),
                        suggestion=_cache_miss_suggestion(
                            node, miss_pct, total_blocks,
                        ),
                        impact_band=(
                            ImpactBand.HIGH if miss_pct >= 50.0 else ImpactBand.MEDIUM
                        ),
                        impact_score=min(10.0, miss_pct / 10.0),
                        metrics={
                            "shared_hit_blocks": hit,
                            "shared_read_blocks": read,
                            "cache_miss_pct": round(miss_pct, 1),
                            "total_blocks": total_blocks,
                        },
                        assumptions=(
                            "Cache hit ratio depends on shared_buffers size and workload",
                            "First execution after restart will have higher miss rates",
                        ),
                        verification_steps=(
                            "Run the query again to see warm-cache behavior",
                            "Check shared_buffers setting: SHOW shared_buffers",
                            "Check effective_cache_size: SHOW effective_cache_size",
                            "Monitor pg_stat_user_tables.heap_blks_hit ratio",
                        ),
                    ))

            # Check 2: Temp buffer usage (spill to disk)
            temp_read = getattr(node, "temp_read_blocks", 0) or 0
            temp_written = getattr(node, "temp_written_blocks", 0) or 0
            temp_total_blocks = temp_read + temp_written

            if temp_total_blocks > 0:
                temp_kb = temp_total_blocks * 8  # 8KB per block

                if temp_kb >= config.temp_buffer_warning_kb:
                    severity = (
                        Severity.CRITICAL
                        if temp_kb >= config.temp_buffer_critical_kb
                        else Severity.WARNING
                    )
                    context = NodeContext.from_node(node, path, parent)
                    table = node.relation_name or node.node_type

                    temp_mb = temp_kb / 1024

                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=severity,
                        context=context,
                        title=(
                            f"Temp disk usage on {table}: "
                            f"{temp_mb:.1f}MB spilled"
                        ),
                        description=(
                            f"This {node.node_type} spilled {temp_mb:.1f}MB "
                            f"to temporary files ({temp_total_blocks:,} blocks).\n\n"
                            f"Disk spills occur when work_mem is insufficient for "
                            f"sorts, hash joins, or aggregations. This can cause "
                            f"10-100x slowdowns compared to in-memory operations."
                        ),
                        suggestion=(
                            f"-- Increase work_mem for this session:\n"
                            f"SET work_mem = '{max(64, int(temp_mb * 2))}MB';\n\n"
                            f"-- Or increase globally (affects all queries):\n"
                            f"ALTER SYSTEM SET work_mem = '{max(64, int(temp_mb * 1.5))}MB';\n"
                            f"SELECT pg_reload_conf();\n\n"
                            f"-- Current spill: {temp_mb:.1f}MB. Recommended work_mem: "
                            f"at least {max(64, int(temp_mb * 2))}MB"
                        ),
                        impact_band=ImpactBand.HIGH,
                        impact_score=min(10.0, temp_mb / 10.0),
                        metrics={
                            "temp_read_blocks": temp_read,
                            "temp_written_blocks": temp_written,
                            "temp_total_kb": temp_kb,
                        },
                        assumptions=(
                            "work_mem is per-operation, not per-query",
                            "Multiple sorts in one query each get their own work_mem",
                        ),
                        verification_steps=(
                            "Check current work_mem: SHOW work_mem",
                            f"Set work_mem = '{max(64, int(temp_mb * 2))}MB' and re-run",
                            "Monitor with: EXPLAIN (ANALYZE, BUFFERS)",
                        ),
                    ))

            # Check 3: I/O amplification
            if (
                node.actual_rows is not None
                and node.actual_rows > 0
                and read > 0
            ):
                io_ratio = read / node.actual_rows
                if io_ratio >= config.io_amplification_threshold:
                    context = NodeContext.from_node(node, path, parent)
                    table = node.relation_name or node.node_type

                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=Severity.INFO,
                        context=context,
                        title=(
                            f"I/O amplification on {table}: "
                            f"{io_ratio:.0f} blocks per row"
                        ),
                        description=(
                            f"This {node.node_type} reads {read:,} blocks "
                            f"to produce {node.actual_rows:,} rows "
                            f"({io_ratio:.0f}x amplification).\n\n"
                            f"High I/O amplification suggests the table may be "
                            f"bloated, have wide rows, or use a non-covering index "
                            f"causing heap lookups."
                        ),
                        suggestion=(
                            f"-- Consider a covering index to avoid heap access:\n"
                            f"-- CREATE INDEX ON {table}(<columns>) INCLUDE (<selected_columns>);\n\n"
                            f"-- Or check for table bloat:\n"
                            f"-- SELECT pg_size_pretty(pg_table_size('{table}'));\n"
                            f"-- VACUUM FULL {table};  -- Use cautiously in production"
                        ),
                        impact_band=ImpactBand.MEDIUM,
                        impact_score=min(8.0, io_ratio / 50.0),
                        metrics={
                            "io_amplification": round(io_ratio, 1),
                            "blocks_read": read,
                            "rows_produced": node.actual_rows,
                        },
                    ))

        return findings


def _cache_miss_explanation(miss_pct: float, total_blocks: int) -> str:
    """Explain what the cache miss rate means."""
    if miss_pct >= 80:
        return (
            "This is a very high miss rate — most data is being read from disk. "
            "This is expected for cold caches or tables larger than shared_buffers."
        )
    if miss_pct >= 50:
        return (
            "Over half the data is being read from disk. Consider whether "
            "shared_buffers is appropriately sized for your workload."
        )
    return (
        "Moderate cache miss rate. The table may be partially cached. "
        "Repeated queries should show improvement."
    )


def _cache_miss_suggestion(
    node: "PlanNode",
    miss_pct: float,
    total_blocks: int,
) -> str:
    """Build suggestion for cache miss findings."""
    table = node.relation_name or "<table>"
    total_mb = (total_blocks * 8) / 1024  # 8KB per block

    parts = [
        f"-- Cache miss rate: {miss_pct:.0f}% ({total_blocks:,} blocks = ~{total_mb:.0f}MB)\n",
    ]

    if total_mb > 1024:
        parts.append(
            f"-- Table data exceeds 1GB — consider:\n"
            f"--   1. Partitioning: CREATE TABLE {table} PARTITION BY RANGE(...);\n"
            f"--   2. Covering index to avoid heap access\n"
            f"--   3. Increase shared_buffers (currently serving {100 - miss_pct:.0f}% from cache)\n"
        )
    else:
        parts.append(
            f"-- Table data is ~{total_mb:.0f}MB — should fit in cache:\n"
            f"--   1. Increase shared_buffers: ALTER SYSTEM SET shared_buffers = "
            f"'{max(256, int(total_mb * 3))}MB';\n"
            f"--   2. Pre-warm cache: SELECT pg_prewarm('{table}');\n"
        )

    if node.filter:
        parts.append(
            f"-- Adding an index can reduce blocks read significantly:\n"
            f"-- Current filter: {node.filter}"
        )

    return "".join(parts)
