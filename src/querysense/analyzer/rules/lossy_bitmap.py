"""
Rule: Lossy Bitmap Heap Blocks

Detects Bitmap Heap Scan nodes operating in lossy mode, where individual
row pointers are lost and entire heap pages must be rechecked.

Why it matters:
- Lossy bitmaps discard row-level pointers and keep only page-level bits
- Every row on affected pages must be rechecked against the original
  condition, adding significant CPU overhead
- Recheck cost scales with page density (wide rows = fewer rechecks,
  narrow rows = many rechecks per page)
- Indicates work_mem is too small for the bitmap index scan's needs
- Can cause 2-10x slowdown compared to exact bitmap mode

When it happens:
- work_mem is too low to hold all matching TID pointers
- High-cardinality bitmap scans exceed the memory budget
- Multiple bitmap scans combined with BitmapAnd/BitmapOr

Detection:
- Bitmap Heap Scan nodes with "Lossy Heap Blocks" > 0 in EXPLAIN ANALYZE
- Ratio of lossy to exact blocks indicates severity

Requires EXPLAIN ANALYZE to detect (lossy/exact block counts are runtime data).
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


class LossyBitmapConfig(RuleConfig):
    """
    Configuration for lossy bitmap detection.

    Attributes:
        min_lossy_blocks: Minimum lossy heap blocks to trigger (default 1).
        critical_lossy_blocks: Lossy block count for CRITICAL severity.
    """

    min_lossy_blocks: int = Field(
        default=1,
        ge=0,
        description="Minimum lossy heap blocks to trigger a warning",
    )
    critical_lossy_blocks: int = Field(
        default=1000,
        ge=1,
        description="Lossy heap block count to escalate to CRITICAL",
    )


@register_rule
class LossyBitmap(Rule):
    """
    Detect Bitmap Heap Scan nodes with lossy heap blocks.

    When work_mem is insufficient, PostgreSQL degrades bitmap scans from
    exact (row-level) to lossy (page-level), requiring expensive rechecks.
    This rule flags that degradation as a CI-enforceable signal.
    """

    rule_id = "LOSSY_BITMAP"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects bitmap heap scans degraded to lossy mode"
    phase = RulePhase.PER_NODE

    config_schema = LossyBitmapConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Find Bitmap Heap Scan nodes with lossy blocks."""
        config: LossyBitmapConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "Bitmap Heap Scan":
                continue

            # Lossy/Exact Heap Blocks are reported in model_extra
            lossy_blocks = _get_extra_int(node, "Lossy Heap Blocks")
            exact_blocks = _get_extra_int(node, "Exact Heap Blocks")

            if lossy_blocks < config.min_lossy_blocks:
                continue

            total_blocks = lossy_blocks + exact_blocks
            lossy_pct = (lossy_blocks / total_blocks * 100) if total_blocks > 0 else 100.0

            # Severity escalation
            if lossy_blocks >= config.critical_lossy_blocks:
                severity = Severity.CRITICAL
            elif lossy_pct > 50:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "unknown table"

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Lossy bitmap on {table} "
                    f"({lossy_blocks:,} lossy / {total_blocks:,} total blocks)"
                ),
                description=self._build_description(
                    node, lossy_blocks, exact_blocks, lossy_pct
                ),
                suggestion=self._build_suggestion(
                    node, lossy_blocks, exact_blocks
                ),
                metrics={
                    "lossy_heap_blocks": lossy_blocks,
                    "exact_heap_blocks": exact_blocks,
                    "total_heap_blocks": total_blocks,
                    "lossy_pct": round(lossy_pct, 2),
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.HIGH if lossy_pct > 80
                    else ImpactBand.MEDIUM if lossy_pct > 30
                    else ImpactBand.LOW
                ),
                assumptions=(
                    "Lossy blocks indicate work_mem exhaustion during bitmap scan",
                    "Rechecks add CPU overhead proportional to rows per page",
                ),
                verification_steps=(
                    "Run EXPLAIN (ANALYZE, BUFFERS) to confirm lossy block counts",
                    "Test with increased work_mem: SET work_mem = '256MB'",
                    "Check if the bitmap scan can be replaced with a plain index scan",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        lossy: int,
        exact: int,
        lossy_pct: float,
    ) -> str:
        """Build detailed description of the lossy bitmap problem."""
        table = node.relation_name or "this table"
        parts = [
            f"Bitmap Heap Scan on '{table}' is operating in lossy mode: "
            f"{lossy:,} of {lossy + exact:,} heap blocks ({lossy_pct:.1f}%) "
            f"lost row-level pointers."
        ]

        if node.recheck_cond:
            parts.append(f"Recheck Cond: {node.recheck_cond}")

        parts.append(
            "In lossy mode, every row on affected pages must be rechecked "
            "against the original condition. This adds significant CPU "
            "overhead, especially for narrow rows where many tuples share "
            "a single heap page."
        )

        if lossy_pct > 80:
            parts.append(
                "Over 80% of blocks are lossy — the bitmap scan is almost "
                "entirely degraded. A plain index scan may be faster."
            )

        return " ".join(parts)

    def _build_suggestion(
        self,
        node: "PlanNode",
        lossy: int,
        exact: int,
    ) -> str:
        """Build actionable suggestion for lossy bitmap."""
        total_blocks = lossy + exact
        # Rough heuristic: each block pointer is ~6 bytes, page pointer is ~1 bit
        # To fit all blocks as exact, need ~6 * 8192 * total_blocks bytes
        # Simplified: recommend work_mem that's at least total_blocks * 8KB / 1024 = total_blocks * 8 KB
        recommended_mb = max(int(total_blocks * 8 / 1024) * 2, 64)

        lines = [
            f"SET work_mem = '{recommended_mb}MB';  "
            f"-- Fit bitmap in memory ({total_blocks:,} blocks)",
            "",
            "-- Or set per-session for specific queries:",
            f"SET LOCAL work_mem = '{recommended_mb}MB';",
            "",
            "-- Alternative: reduce the number of matching rows to shrink the bitmap",
            "-- by adding more selective conditions or partitioning the table.",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/runtime-config-resource.html#GUC-WORK-MEM",
        ]

        return "\n".join(lines)


def _get_extra_int(node: "PlanNode", key: str) -> int:
    """Safely extract an integer from PlanNode.model_extra."""
    if node.model_extra:
        value = node.model_extra.get(key, 0)
        if isinstance(value, int):
            return value
    return 0
