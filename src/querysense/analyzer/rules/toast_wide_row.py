"""
Rule: TOAST / Wide Row Performance Detector

Inspired by pganalyze articles:
  - "Postgres performance cliffs with large JSONB values and TOAST" (E3)
  - "Performance implications of medium size values and TOAST" (E89)

The key insight: values between ~2KB and 8KB trigger TOAST compression
and out-of-line storage, causing significant read amplification.
Each access to a TOASTed value requires an extra lookup to the TOAST
table, which can multiply I/O by 2-10x for wide rows.

Detection from EXPLAIN plans:
  - Plan Width (average row width in bytes) > threshold
  - Scan nodes processing many rows with wide output
  - High Shared Read Blocks relative to rows (I/O amplification)
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


class ToastWideRowConfig(RuleConfig):
    warning_width_bytes: int = Field(
        default=2000,
        ge=100,
        description="Plan Width threshold for WARNING (bytes)",
    )
    critical_width_bytes: int = Field(
        default=8000,
        ge=100,
        description="Plan Width threshold for CRITICAL (bytes)",
    )
    min_rows: int = Field(
        default=1000,
        ge=0,
        description="Minimum rows scanned to trigger",
    )


@register_rule
class ToastWideRow(Rule):
    """
    Detect scan nodes with wide rows (high Plan Width) that likely
    trigger TOAST storage, causing I/O amplification.

    Postgres stores values larger than ~2KB in a separate TOAST table.
    Accessing these values requires an extra heap lookup per row, which
    adds significant overhead when scanning many rows.
    """

    rule_id = "TOAST_WIDE_ROW"
    version = "1.0.0"
    severity = Severity.INFO
    description = (
        "Detects wide rows (>2KB) that trigger TOAST storage and "
        "I/O amplification on large scans"
    )
    phase = RulePhase.PER_NODE
    config_schema = ToastWideRowConfig

    _SCAN_TYPES = {
        "Seq Scan", "Index Scan", "Index Only Scan",
        "Bitmap Heap Scan",
    }

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: ToastWideRowConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in self._SCAN_TYPES:
                continue

            width = node.plan_width
            if width < config.warning_width_bytes:
                continue

            rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
            if rows < config.min_rows:
                continue

            if width >= config.critical_width_bytes:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "unknown table"

            read_blocks = node.shared_read_blocks or 0
            hit_blocks = node.shared_hit_blocks or 0
            total_blocks = read_blocks + hit_blocks
            bytes_per_row = (total_blocks * 8192 / rows) if rows > 0 and total_blocks > 0 else 0
            io_amplification = bytes_per_row / max(width, 1) if width > 0 and bytes_per_row > 0 else 0

            base_score = 2.0
            if width >= 8000:
                base_score += 3.0
            elif width >= 4000:
                base_score += 2.0
            elif width >= 2000:
                base_score += 1.0
            if rows >= 100_000:
                base_score += 2.0
            impact_score = min(round(base_score, 1), 9.0)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"Wide rows on {table} ({width:,} bytes/row, "
                    f"{rows:,} rows) — possible TOAST overhead"
                ),
                description=self._build_description(
                    node, table, width, rows, io_amplification,
                ),
                suggestion=self._build_suggestion(table, width),
                metrics={
                    "plan_width_bytes": width,
                    "rows_scanned": rows,
                    "shared_read_blocks": read_blocks,
                    "shared_hit_blocks": hit_blocks,
                    "io_amplification": round(io_amplification, 2),
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.MEDIUM if width >= 4000
                    else ImpactBand.LOW
                ),
                impact_score=impact_score,
                assumptions=(
                    "Values >2KB are stored in the TOAST table",
                    "Each TOAST access adds an extra heap lookup per row",
                    "Selecting fewer columns or using covering indexes reduces TOAST I/O",
                ),
                verification_steps=(
                    f"Check column sizes: SELECT avg(pg_column_size(col)) FROM {table}",
                    "Use SELECT with only needed columns instead of SELECT *",
                    "Consider JSONB → separate columns for frequently accessed fields",
                    "Check if an index-only scan can avoid TOAST access",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        table: str,
        width: int,
        rows: int,
        io_amp: float,
    ) -> str:
        parts = [
            f"{node.node_type} on '{table}' returns rows averaging "
            f"{width:,} bytes wide across {rows:,} rows."
        ]

        if width >= 2048:
            parts.append(
                f"At {width:,} bytes, many column values will be stored "
                f"in the TOAST table (threshold ~2KB). Each TOASTed value "
                f"requires an extra heap page lookup, which can multiply "
                f"I/O by 2-10x compared to inline storage."
            )

        if width >= 8000:
            parts.append(
                "These rows are close to or exceeding the 8KB page size. "
                "This causes maximum TOAST overhead and can severely degrade "
                "scan performance. Consider normalizing large columns into "
                "separate tables or using JSONB path extraction."
            )

        if io_amp > 2.0:
            parts.append(
                f"I/O amplification factor: {io_amp:.1f}x — the actual "
                f"bytes read per row exceed the logical row width, "
                f"confirming TOAST-related overhead."
            )

        parts.append(
            "Tip: SELECT only the columns you need. Avoid SELECT * on "
            "tables with large TEXT, JSONB, or BYTEA columns."
        )

        return " ".join(parts)

    def _build_suggestion(self, table: str, width: int) -> str:
        lines = [
            "-- Reduce TOAST overhead by selecting only needed columns:",
            f"-- Before: SELECT * FROM {table} WHERE ...",
            f"-- After:  SELECT id, name, status FROM {table} WHERE ...",
            "",
        ]

        if width >= 4000:
            lines.extend([
                "-- For JSONB columns, extract only needed keys:",
                f"-- SELECT data->>'key1', data->>'key2' FROM {table}",
                "-- This avoids decompressing the entire JSONB value.",
                "",
                "-- Consider normalizing large columns:",
                f"-- CREATE TABLE {table}_details (id REFERENCES {table}, ...);",
                "",
            ])

        lines.extend([
            "-- For covering indexes (Index Only Scan), TOAST is avoided:",
            f"-- CREATE INDEX ON {table} (filter_col) INCLUDE (small_col);",
            "",
            "-- Monitor column sizes:",
            f"-- SELECT attname, avg_width FROM pg_stats WHERE tablename = '{table}';",
            "",
            "-- Ref: https://www.postgresql.org/docs/current/storage-toast.html",
        ])

        return "\n".join(lines)
