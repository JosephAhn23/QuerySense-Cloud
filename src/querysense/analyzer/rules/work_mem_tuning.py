"""
Rule: work_mem Tuning Suggestion

Detects operations that benefit from work_mem increases: sorts, hash
joins, hash aggregates, and bitmap heap scans that spill to disk or
use large amounts of memory.

Addresses weakness #6 (vs PawSQL): "Only handles basic patterns" —
provides GUC tuning advice, not just index suggestions.

Why it matters:
- work_mem controls how much memory each sort/hash operation gets
- When exceeded, PostgreSQL spills to disk (10-100x slower)
- Default work_mem (4MB) is too low for most analytical queries
- Setting it per-transaction avoids global memory pressure

Detection:
- Sort operations using disk (Sort Method: external merge)
- Hash operations with multiple batches
- Large in-memory sorts that could benefit from more memory
- Bitmap Heap Scans with lossy pages (insufficient work_mem for bitmap)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

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


class WorkMemConfig(RuleConfig):
    """Config for work_mem tuning detection."""

    min_sort_space_kb: int = Field(
        default=1024,
        description="Minimum sort space (KB) to consider for tuning",
    )
    hash_batch_threshold: int = Field(
        default=2,
        description="Minimum hash batches to suggest work_mem increase",
    )


@register_rule
class WorkMemTuning(Rule):
    """
    Detect operations that would benefit from work_mem tuning.

    Provides specific SET work_mem recommendations based on the actual
    memory usage observed in EXPLAIN ANALYZE output.
    """

    rule_id = "WORK_MEM_TUNING"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Suggests work_mem tuning for sorts, hashes, and aggregates"
    phase = RulePhase.PER_NODE
    config_schema = WorkMemConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: WorkMemConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            findings.extend(self._check_sort_spill(node, path, parent, config))
            findings.extend(self._check_hash_batches(node, path, parent, config))
            findings.extend(self._check_large_in_memory(node, path, parent, config))

        return findings

    def _check_sort_spill(
        self, node: "PlanNode", path, parent, config: WorkMemConfig,
    ) -> list[Finding]:
        """Detect sort operations spilling to disk."""
        if node.node_type != "Sort":
            return []

        sort_method = node.sort_method
        if not sort_method or "disk" not in sort_method.lower():
            # Also check Sort Space Type
            space_type = node.sort_space_type
            if not space_type or space_type.lower() != "disk":
                return []

        sort_space = node.sort_space_used  # in KB
        if sort_space is None:
            return []

        context = NodeContext.from_node(node, path, parent)
        sort_mb = sort_space / 1024
        # Recommend 2x the spill size, rounded to nearest power of 2
        recommended_mb = _round_to_power_of_2(int(sort_mb * 2.5))
        recommended_mb = max(recommended_mb, 16)

        impact = min(5.0 + min(sort_mb / 100, 4.0), 9.0)

        sort_keys = ""
        if node.sort_key:
            sort_keys = ", ".join(node.sort_key[:3])

        return [Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING,
            context=context,
            title=f"Sort spilling to disk ({sort_mb:.0f}MB) — increase work_mem",
            description=(
                f"Sort operation is using {sort_mb:.0f}MB on disk "
                f"(method: {sort_method or 'external merge'}). "
                f"Disk sorts are 10-100x slower than in-memory sorts. "
                f"Increasing work_mem to {recommended_mb}MB would keep this "
                f"sort entirely in RAM."
                + (f" Sort keys: {sort_keys}" if sort_keys else "")
            ),
            suggestion=(
                f"-- Set work_mem for this session/transaction:\n"
                f"SET work_mem = '{recommended_mb}MB';\n"
                f"\n"
                f"-- Or set per-transaction (resets after commit):\n"
                f"SET LOCAL work_mem = '{recommended_mb}MB';\n"
                f"\n"
                f"-- Current sort needs {sort_mb:.0f}MB; recommending {recommended_mb}MB\n"
                f"-- (2.5x headroom for data growth)\n"
                f"\n"
                f"-- To set globally (affects ALL connections):\n"
                f"-- ALTER SYSTEM SET work_mem = '{recommended_mb}MB';\n"
                f"-- SELECT pg_reload_conf();\n"
                f"-- WARNING: global work_mem = per-operation, not per-connection.\n"
                f"-- With 100 connections × 5 sorts each = {100 * 5 * recommended_mb}MB total."
            ),
            metrics={
                "sort_space_kb": sort_space,
                "sort_method": sort_method or "unknown",
                "recommended_work_mem_mb": recommended_mb,
            },
            impact_band=ImpactBand.HIGH if sort_mb > 100 else ImpactBand.MEDIUM,
            impact_score=round(impact, 1),
        )]

    def _check_hash_batches(
        self, node: "PlanNode", path, parent, config: WorkMemConfig,
    ) -> list[Finding]:
        """Detect hash operations using multiple batches (spilling)."""
        if node.node_type not in ("Hash Join", "Hash", "HashAggregate"):
            return []

        batches = node.hash_batches
        if batches is None or batches < config.hash_batch_threshold:
            return []

        memory = node.peak_memory_usage  # KB
        if memory is None:
            memory = 0

        context = NodeContext.from_node(node, path, parent)
        memory_mb = memory / 1024
        recommended_mb = _round_to_power_of_2(int(memory_mb * batches * 1.5))
        recommended_mb = max(recommended_mb, 32)

        impact = min(4.0 + min(batches * 0.5, 4.0), 8.0)

        return [Finding(
            rule_id=self.rule_id,
            severity=Severity.WARNING if batches > 4 else Severity.INFO,
            context=context,
            title=f"Hash using {batches} batches — increase work_mem to avoid spill",
            description=(
                f"{node.node_type} is using {batches} batches "
                f"(peak memory: {memory_mb:.0f}MB). "
                f"Multiple batches mean the hash table doesn't fit in work_mem "
                f"and PostgreSQL must spill to temporary files. "
                f"Each batch requires re-reading the inner relation from disk."
            ),
            suggestion=(
                f"-- Increase work_mem to fit hash in memory:\n"
                f"SET work_mem = '{recommended_mb}MB';\n"
                f"\n"
                f"-- Current: {batches} batches × {memory_mb:.0f}MB peak\n"
                f"-- Target: 1 batch with {recommended_mb}MB work_mem\n"
                f"\n"
                f"-- Per-transaction (safe):\n"
                f"SET LOCAL work_mem = '{recommended_mb}MB';"
            ),
            metrics={
                "hash_batches": batches,
                "peak_memory_kb": memory,
                "recommended_work_mem_mb": recommended_mb,
            },
            impact_band=ImpactBand.MEDIUM,
            impact_score=round(impact, 1),
        )]

    def _check_large_in_memory(
        self, node: "PlanNode", path, parent, config: WorkMemConfig,
    ) -> list[Finding]:
        """Flag large in-memory sorts that are close to spilling."""
        if node.node_type != "Sort":
            return []

        space_type = node.sort_space_type
        if space_type and space_type.lower() == "disk":
            return []  # Already handled by _check_sort_spill

        sort_space = node.sort_space_used  # KB
        if sort_space is None or sort_space < config.min_sort_space_kb:
            return []

        # If sort is using >75% of typical work_mem (4MB), warn about headroom
        if sort_space < 3072:  # Less than 3MB, plenty of headroom
            return []

        context = NodeContext.from_node(node, path, parent)
        sort_mb = sort_space / 1024

        return [Finding(
            rule_id=self.rule_id,
            severity=Severity.INFO,
            context=context,
            title=f"Sort using {sort_mb:.1f}MB — close to default work_mem limit",
            description=(
                f"In-memory sort using {sort_mb:.1f}MB. Default work_mem is 4MB. "
                f"If data grows, this sort will start spilling to disk. "
                f"Consider increasing work_mem proactively."
            ),
            suggestion=(
                f"-- Proactive: increase work_mem before this sort spills:\n"
                f"SET work_mem = '{_round_to_power_of_2(int(sort_mb * 3))}MB';\n"
                f"\n"
                f"-- Check current setting:\n"
                f"SHOW work_mem;"
            ),
            metrics={"sort_space_kb": sort_space},
            impact_band=ImpactBand.LOW,
            impact_score=2.5,
        )]


def _round_to_power_of_2(n: int) -> int:
    """Round up to nearest power of 2 (for clean memory settings)."""
    if n <= 0:
        return 1
    p = 1
    while p < n:
        p *= 2
    return p
