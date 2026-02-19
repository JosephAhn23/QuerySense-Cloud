"""
Rule: WAL & Full Page Write Advisor

Inspired by pganalyze articles:
  - "5mins of Postgres E10: max_wal_size, full page writes and UUID vs
    BIGINT primary keys" — UUIDs scatter writes across many pages, each
    first-write after a checkpoint triggers a full-page write (~8KB vs
    a few bytes for the actual tuple).
  - "5mins of Postgres E86: HOT Updates and BRIN indexes in Postgres 16"
  - "Reducing table size with optimal column ordering" (E100)

Detection from EXPLAIN plans:
  - Index Scan on random-pattern columns (UUID) with many actual rows
  - Many Shared Dirtied Blocks relative to rows written
  - Insert/Update nodes with high block I/O relative to rows

This rule focuses on detecting plans where UUID-indexed or random-order
writes likely cause excessive WAL via full page writes.
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


class WALFullPageConfig(RuleConfig):
    blocks_per_row_threshold: float = Field(
        default=2.0,
        ge=0.1,
        description="Dirty+written blocks per row threshold to trigger",
    )
    min_rows: int = Field(
        default=100,
        ge=1,
        description="Minimum rows to trigger",
    )


@register_rule
class WALFullPageWrites(Rule):
    """
    Detect write-heavy operations with high block dirtying that
    suggests excessive WAL from full page writes.

    After each checkpoint, the first modification to a page writes
    the entire 8KB page to WAL (full_page_writes=on). Random-order
    primary keys (UUIDs) scatter writes across many pages, causing
    each insert to dirty a different page — and each page's first
    write triggers a full 8KB WAL record vs the ~100 bytes for
    sequential BIGINT inserts.
    """

    rule_id = "WAL_FULL_PAGE_WRITE"
    version = "1.0.0"
    severity = Severity.INFO
    description = (
        "Detects excessive block dirtying that likely causes WAL "
        "amplification from full page writes"
    )
    phase = RulePhase.PER_NODE
    config_schema = WALFullPageConfig

    _WRITE_NODES = {
        "Insert", "Update", "Delete", "Merge",
        "ModifyTable",
    }
    _SCAN_WITH_WRITE_PARENT = {
        "Index Scan", "Seq Scan", "Bitmap Heap Scan",
    }

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: WALFullPageConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            rows = node.actual_rows if node.actual_rows is not None else node.plan_rows
            if rows < config.min_rows:
                continue

            dirtied = node.shared_dirtied_blocks or 0
            written = node.shared_written_blocks or 0
            dirty_total = dirtied + written

            if dirty_total == 0:
                continue

            blocks_per_row = dirty_total / max(rows, 1)

            is_write_node = node.node_type in self._WRITE_NODES
            is_scan_under_write = (
                node.node_type in self._SCAN_WITH_WRITE_PARENT
                and parent is not None
                and parent.node_type in self._WRITE_NODES
            )

            if not is_write_node and not is_scan_under_write:
                if blocks_per_row < config.blocks_per_row_threshold * 2:
                    continue

            if blocks_per_row < config.blocks_per_row_threshold:
                continue

            if blocks_per_row >= 4.0:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            context = NodeContext.from_node(node, path, parent)
            table = node.relation_name or "target table"

            base_score = 2.0
            if blocks_per_row >= 4.0:
                base_score += 3.0
            elif blocks_per_row >= 2.0:
                base_score += 1.5
            if rows >= 10_000:
                base_score += 2.0
            impact_score = min(round(base_score, 1), 8.0)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=(
                    f"High block dirtying on {table}: {blocks_per_row:.1f} "
                    f"blocks/row over {rows:,} rows — WAL amplification likely"
                ),
                description=self._build_description(
                    node, table, rows, dirtied, written, blocks_per_row,
                ),
                suggestion=self._build_suggestion(table, blocks_per_row),
                metrics={
                    "rows_affected": rows,
                    "shared_dirtied_blocks": dirtied,
                    "shared_written_blocks": written,
                    "blocks_per_row": round(blocks_per_row, 2),
                    "wal_overhead_estimate_kb": round(dirty_total * 8, 1),
                    "total_cost": node.total_cost,
                },
                impact_band=(
                    ImpactBand.MEDIUM if blocks_per_row >= 4.0
                    else ImpactBand.LOW
                ),
                impact_score=impact_score,
                assumptions=(
                    "full_page_writes is ON (the default and recommended setting)",
                    "Each dirty page triggers an 8KB WAL record on first write after checkpoint",
                    "High blocks/row indicates random I/O pattern (e.g. UUID primary keys)",
                ),
                verification_steps=(
                    "Check pg_stat_wal for wal_fpi (full page images) count",
                    "Compare WAL generation rate during INSERT batches",
                    "Consider BIGINT sequences instead of UUID for primary keys",
                    "Tune checkpoint_timeout and max_wal_size to reduce checkpoint frequency",
                ),
            ))

        return findings

    def _build_description(
        self,
        node: "PlanNode",
        table: str,
        rows: int,
        dirtied: int,
        written: int,
        blocks_per_row: float,
    ) -> str:
        parts = [
            f"{node.node_type} on '{table}' dirtied {dirtied:,} blocks "
            f"and wrote {written:,} blocks for {rows:,} rows "
            f"({blocks_per_row:.1f} blocks per row)."
        ]

        if blocks_per_row >= 2.0:
            parts.append(
                "This ratio suggests each row is touching a different page. "
                "With full_page_writes=on (the default), the first write to "
                "each page after a checkpoint generates an 8KB WAL record — "
                "even if only 100 bytes are being written."
            )

        if blocks_per_row >= 4.0:
            parts.append(
                "This extreme ratio is typical of UUID primary keys or other "
                "random-order indexed columns. Sequential BIGINT keys pack "
                "inserts into the same page, reducing WAL by 10-50x."
            )

        parts.append(
            "Excessive WAL generation causes: slower checkpoints, increased "
            "replication lag, higher I/O, and larger backup sizes."
        )

        return " ".join(parts)

    def _build_suggestion(self, table: str, blocks_per_row: float) -> str:
        lines = [
            "-- 1. Use sequential primary keys to reduce page scatter:",
            f"--    ALTER TABLE {table} ALTER COLUMN id TYPE BIGINT;",
            "--    (Consider UUIDv7 if you need distributed IDs — it's time-sorted)",
            "",
            "-- 2. Tune checkpoint settings to reduce full-page write frequency:",
            "--    checkpoint_timeout = '15min'  -- default is 5min",
            "--    max_wal_size = '4GB'          -- default is 1GB",
            "--    (Longer intervals mean fewer checkpoints, fewer FPWs)",
            "",
            "-- 3. Monitor WAL full page images:",
            "--    SELECT wal_fpi FROM pg_stat_wal;  -- PG15+",
            "",
            "-- 4. For bulk inserts, use COPY instead of INSERT:",
            f"--    COPY {table} FROM STDIN;",
            "--    (COPY uses a ring buffer and packs pages efficiently)",
            "",
        ]

        if blocks_per_row >= 4.0:
            lines.extend([
                "-- 5. Consider UUIDv7 (PG18+) for time-sorted UUIDs:",
                "--    UUIDv7 embeds a timestamp, so inserts are sequential",
                "--    and pack into fewer pages. See RFC 9562.",
                "",
            ])

        lines.append(
            "-- Ref: https://www.postgresql.org/docs/current/wal-configuration.html"
        )

        return "\n".join(lines)
