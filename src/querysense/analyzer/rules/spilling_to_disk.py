"""
Rule: Spilling to Disk

Detects Sort and Hash operations that exceed work_mem and spill to disk,
causing significant performance degradation.

Why it matters:
- In-memory operations are 10-100x faster than disk-based ones
- Sort spilling uses external merge sort (much slower than quicksort)
- Hash spilling uses multiple batches with disk I/O
- Indicates work_mem is too low for the workload
- work_mem affects sorts/hashes and can cause spills that are frequently
  discovered late in production under load

When to fix:
- Increase work_mem (per-operation setting)
- Add indexes to avoid sorts
- Reduce result set size before sorting

v2.0 enhancements:
- Distinguishes external merge sort from external sort (multi-pass vs single-pass)
- Provides calibrated work_mem recommendations based on spill size
- Includes impact bands and verification steps
- Reports sort algorithm details for diagnostic value
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


@register_rule
class SpillingToDisk(Rule):
    """
    Detect Sort and Hash operations spilling to disk.

    Checks for:
    - Sort nodes with sort_space_type = "Disk"
    - Sort nodes with sort_method containing "external"
    - Hash nodes with hash_batches > 1

    v2.0: Enhanced with calibrated work_mem recommendations,
    sort algorithm classification, and impact bands.
    """

    rule_id = "SPILLING_TO_DISK"
    version = "2.0.0"
    severity = Severity.WARNING
    description = "Detects operations spilling to disk due to insufficient work_mem"
    phase = RulePhase.PER_NODE

    # Node types that can spill
    SORT_TYPES = {"Sort", "Incremental Sort"}
    HASH_TYPES = {"Hash", "HashAggregate"}

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Find operations that spilled to disk.

        Args:
            explain: Parsed EXPLAIN output
            prior_findings: Not used (PER_NODE rule)

        Returns:
            List of findings for spilling operations
        """
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            finding = None

            if node.node_type in self.SORT_TYPES:
                finding = self._check_sort_spill(node, path, parent)
            elif node.node_type in self.HASH_TYPES:
                finding = self._check_hash_spill(node, path, parent)

            if finding:
                findings.append(finding)

        return findings

    def _check_sort_spill(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
    ) -> Finding | None:
        """Check if a Sort node spilled to disk."""
        # Check sort_space_type (most reliable)
        is_disk = node.sort_space_type == "Disk"

        # Check sort_method for external sort
        sort_method = (node.sort_method or "").lower()
        is_external = "external" in sort_method
        is_merge = "merge" in sort_method

        if not (is_disk or is_external):
            return None

        space_kb = node.sort_space_used or 0
        space_mb = space_kb / 1024

        # Escalate to CRITICAL for large spills (> 100MB)
        # or for multi-pass external merge (much worse than single-pass)
        if space_mb > 100 or (is_merge and space_mb > 50):
            severity = Severity.CRITICAL
        else:
            severity = self.severity

        context = NodeContext.from_node(node, path, parent)

        # Calibrated work_mem recommendation:
        # - For single-pass external sort: work_mem = 2 * spill_size
        # - For multi-pass external merge: work_mem = 3 * spill_size
        #   (merge needs additional memory for merge passes)
        multiplier = 3.0 if is_merge else 2.0
        recommended_mb = int(max(space_mb * multiplier, 64))

        sort_type = "external merge sort" if is_merge else "external sort"

        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=f"Sort spilled {space_mb:.1f}MB to disk ({sort_type})",
            description=self._build_sort_description(node, space_mb, is_merge),
            suggestion=self._build_sort_suggestion(node, space_mb, recommended_mb),
            metrics={
                "space_used_kb": space_kb,
                "space_used_mb": round(space_mb, 2),
                "recommended_work_mem_mb": recommended_mb,
                "is_external_merge": is_merge,
            },
            impact_band=(
                ImpactBand.HIGH if space_mb > 100 or is_merge
                else ImpactBand.MEDIUM if space_mb > 10
                else ImpactBand.LOW
            ),
            assumptions=(
                "work_mem is at the system default (4MB) or below the spill threshold",
                f"Setting work_mem >= {recommended_mb}MB would prevent disk spill",
                "Increasing work_mem is safe for this workload's concurrency level",
            ),
            verification_steps=(
                f"SET work_mem = '{recommended_mb}MB'; then re-run EXPLAIN ANALYZE",
                "Verify sort_space_type changes from 'Disk' to 'Memory'",
                "Check total work_mem usage across concurrent connections",
                "Monitor pg_stat_activity for memory pressure after change",
            ),
        )

    def _check_hash_spill(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
    ) -> Finding | None:
        """Check if a Hash node spilled to multiple batches."""
        # hash_batches > 1 means data didn't fit in work_mem
        if node.hash_batches is None or node.hash_batches <= 1:
            return None

        batches = node.hash_batches
        memory_kb = node.peak_memory_usage or 0
        memory_mb = memory_kb / 1024

        # More batches = more severity
        if batches > 16:
            severity = Severity.CRITICAL
        elif batches > 4:
            severity = Severity.WARNING
        else:
            severity = Severity.INFO

        context = NodeContext.from_node(node, path, parent)

        # Calibrated work_mem: to fit in one batch, need
        # peak_memory * batches (all data) + overhead
        current = max(memory_mb, 4)
        recommended_mb = int(current * batches * 1.5)
        recommended_mb = min(recommended_mb, 4096)  # Cap at 4GB

        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=f"Hash used {batches} batches (spilled to disk)",
            description=self._build_hash_description(node, batches, memory_mb),
            suggestion=self._build_hash_suggestion(node, batches, memory_mb, recommended_mb),
            metrics={
                "hash_batches": batches,
                "hash_buckets": node.hash_buckets or 0,
                "peak_memory_kb": memory_kb,
                "peak_memory_mb": round(memory_mb, 2),
                "recommended_work_mem_mb": recommended_mb,
            },
            impact_band=(
                ImpactBand.HIGH if batches > 16
                else ImpactBand.MEDIUM if batches > 4
                else ImpactBand.LOW
            ),
            assumptions=(
                f"Setting work_mem >= {recommended_mb}MB would fit the hash table in memory",
                "Hash table size is representative of production data volume",
            ),
            verification_steps=(
                f"SET work_mem = '{recommended_mb}MB'; then re-run EXPLAIN ANALYZE",
                "Verify hash_batches drops to 1",
                "Check that work_mem * max_connections fits in available RAM",
            ),
        )

    def _build_sort_description(
        self,
        node: "PlanNode",
        space_mb: float,
        is_merge: bool,
    ) -> str:
        """Build description for sort spill."""
        parts = [
            f"Sort operation exceeded work_mem and spilled {space_mb:.1f}MB to disk."
        ]

        if node.sort_method:
            parts.append(f"Algorithm: {node.sort_method}.")

            if is_merge:
                parts.append(
                    "External merge sort requires multiple passes over the data, "
                    "making it significantly slower than single-pass external sort. "
                    "This typically indicates the data volume is many times larger "
                    "than work_mem."
                )
            else:
                parts.append(
                    "External sort performs a single pass to disk but is still "
                    "10-100x slower than in-memory quicksort due to I/O overhead."
                )

        if node.sort_key:
            keys = ", ".join(node.sort_key[:3])
            if len(node.sort_key) > 3:
                keys += f" (+{len(node.sort_key) - 3} more)"
            parts.append(f"Sorting on: {keys}.")

        return " ".join(parts)

    def _build_hash_description(
        self,
        node: "PlanNode",
        batches: int,
        memory_mb: float,
    ) -> str:
        """Build description for hash spill."""
        parts = [
            f"Hash operation used {batches} batches because data exceeded work_mem."
        ]

        if memory_mb > 0:
            parts.append(f"Peak memory usage: {memory_mb:.1f}MB.")

        parts.append(
            f"Each additional batch requires disk I/O, significantly slowing the operation. "
            f"With {batches} batches, data is being read/written multiple times."
        )

        if batches > 16:
            parts.append(
                "With >16 batches, the overhead is severe — disk I/O dominates "
                "and the hash operation may be slower than a sort-based alternative."
            )

        return " ".join(parts)

    def _build_sort_suggestion(
        self,
        node: "PlanNode",
        space_mb: float,
        recommended_mb: int,
    ) -> str:
        """Build suggestion for sort spill with calibrated work_mem."""
        lines = [
            f"SET work_mem = '{recommended_mb}MB';",
            f"-- Calibrated: {recommended_mb}MB fits the {space_mb:.1f}MB sort in memory",
            "",
            "-- Or set per-session for heavy queries:",
            f"SET LOCAL work_mem = '{recommended_mb}MB';",
            "",
        ]

        if node.sort_key:
            lines.append("-- Consider adding an index to avoid sorting:")
            keys_str = ", ".join(node.sort_key[:3])
            lines.append(f"CREATE INDEX idx_sort ON <table>({keys_str});")
            lines.append("")

        lines.extend([
            "-- Safety check: work_mem * max_connections < available RAM",
            f"-- With 100 connections: {recommended_mb}MB * 100 = {recommended_mb * 100 / 1024:.1f}GB",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/runtime-config-resource.html#GUC-WORK-MEM",
        ])

        return "\n".join(lines)

    def _build_hash_suggestion(
        self,
        node: "PlanNode",
        batches: int,
        memory_mb: float,
        recommended_mb: int,
    ) -> str:
        """Build suggestion for hash spill with calibrated work_mem."""
        lines = [
            f"SET work_mem = '{recommended_mb}MB';",
            f"-- Calibrated to fit {batches} batches into a single in-memory hash",
            "",
            "-- Note: work_mem is per-operation, not per-query",
            "-- A complex query may use work_mem multiple times",
            "",
            "-- For a single heavy query, use LOCAL:",
            f"SET LOCAL work_mem = '{recommended_mb}MB';",
            "",
            "-- Safety check: work_mem * max_connections < available RAM",
            f"-- With 100 connections: {recommended_mb}MB * 100 = {recommended_mb * 100 / 1024:.1f}GB",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/runtime-config-resource.html#GUC-WORK-MEM",
        ]

        return "\n".join(lines)
