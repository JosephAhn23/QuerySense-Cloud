"""
Autovacuum Worker Utilization Analyzer.

pganalyze tracks autovacuum worker utilization -- how saturated the
autovacuum system is. When all workers are busy, VACUUM is delayed
and bloat accumulates. This module detects:

1. Worker saturation (all workers busy)
2. Queue depth (tables waiting for vacuum)
3. I/O budget utilization (vacuum_cost_limit)
4. Long-running vacuum operations
5. Autovacuum parameter tuning per table

Key insight from pganalyze: "pganalyze observes dead rows and
insert/update behavior over 7 days" to predict vacuum needs.

Usage:
    from querysense.autovacuum_utilization import AutovacuumAnalyzer

    analyzer = AutovacuumAnalyzer()
    report = await analyzer.analyze(dsn)
    print(f"Worker saturation: {report.saturation_pct:.0%}")
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkerStatus:
    """Status of an autovacuum worker."""
    pid: int
    table: str
    phase: str
    elapsed_seconds: float
    heap_blks_total: int
    heap_blks_scanned: int
    progress_pct: float
    dead_tuples_collected: int = 0
    index_vacuum_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "table": self.table,
            "phase": self.phase,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "progress_pct": round(self.progress_pct, 2),
        }


@dataclass
class QueuedTable:
    """Table waiting for autovacuum."""
    table: str
    schema: str = "public"
    dead_tuples: int = 0
    live_tuples: int = 0
    dead_ratio: float = 0.0
    threshold: int = 0           # Autovacuum threshold for this table
    last_vacuum_seconds: float = 0.0
    estimated_wait_minutes: float = 0.0
    urgency: str = "normal"      # normal, high, critical

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "dead_tuples": self.dead_tuples,
            "dead_ratio": round(self.dead_ratio, 4),
            "threshold": self.threshold,
            "urgency": self.urgency,
            "estimated_wait_min": round(self.estimated_wait_minutes, 1),
        }


@dataclass
class TableVacuumTuning:
    """Per-table autovacuum tuning recommendation."""
    table: str
    parameter: str
    current_value: str
    recommended_value: str
    reason: str
    alter_sql: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "parameter": self.parameter,
            "current": self.current_value,
            "recommended": self.recommended_value,
            "reason": self.reason,
            "sql": self.alter_sql,
        }


@dataclass
class AutovacuumReport:
    """Complete autovacuum utilization report."""
    # Worker utilization
    max_workers: int = 3
    active_workers: int = 0
    saturation_pct: float = 0.0
    workers: list[WorkerStatus] = field(default_factory=list)
    # Queue
    queue_depth: int = 0
    queued_tables: list[QueuedTable] = field(default_factory=list)
    # I/O budget
    vacuum_cost_limit: int = 200
    vacuum_cost_delay_ms: int = 2
    effective_io_rate_pages_sec: float = 0.0
    io_budget_pct: float = 0.0   # How much of I/O budget is used
    # Tuning
    tuning_recommendations: list[TableVacuumTuning] = field(default_factory=list)
    # System
    tables_needing_vacuum: int = 0
    tables_needing_analyze: int = 0
    total_dead_tuples: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_workers": self.max_workers,
            "active_workers": self.active_workers,
            "saturation_pct": round(self.saturation_pct, 2),
            "queue_depth": self.queue_depth,
            "io_budget_pct": round(self.io_budget_pct, 2),
            "tables_needing_vacuum": self.tables_needing_vacuum,
            "total_dead_tuples": self.total_dead_tuples,
            "workers": [w.to_dict() for w in self.workers],
            "queued": [q.to_dict() for q in self.queued_tables[:20]],
            "tuning": [t.to_dict() for t in self.tuning_recommendations],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  AUTOVACUUM UTILIZATION ANALYSIS")
        lines.append("  " + "=" * 60)

        # Saturation gauge
        sat_bar = "#" * int(self.saturation_pct * 20 / 100) + "-" * (20 - int(self.saturation_pct * 20 / 100))
        lines.append(f"  Workers: {self.active_workers}/{self.max_workers} [{sat_bar}] {self.saturation_pct:.0f}%")
        lines.append(f"  Queue depth: {self.queue_depth} tables waiting")
        lines.append(f"  I/O budget usage: {self.io_budget_pct:.0f}%")
        lines.append(f"  Dead tuples: {self.total_dead_tuples:,}")
        lines.append("")

        if self.workers:
            lines.append("  Active Workers:")
            for w in self.workers:
                lines.append(
                    f"    PID {w.pid}: {w.table} ({w.phase}) "
                    f"{w.progress_pct:.0f}% [{w.elapsed_seconds:.0f}s]"
                )
            lines.append("")

        if self.queued_tables:
            lines.append("  Vacuum Queue (most urgent):")
            for q in self.queued_tables[:10]:
                urg = {"critical": "[!!]", "high": "[! ]", "normal": "[  ]"}.get(q.urgency, "[  ]")
                lines.append(
                    f"    {urg} {q.table}: {q.dead_tuples:,} dead "
                    f"({q.dead_ratio:.1%}) ETA: {q.estimated_wait_minutes:.0f}min"
                )
            lines.append("")

        if self.tuning_recommendations:
            lines.append("  Tuning Recommendations:")
            for t in self.tuning_recommendations:
                lines.append(f"    {t.table}: {t.parameter} {t.current_value} -> {t.recommended_value}")
                lines.append(f"      {t.reason}")
                lines.append(f"      SQL: {t.alter_sql}")
            lines.append("")

        return "\n".join(lines)


class AutovacuumAnalyzer:
    """Analyze autovacuum worker utilization and queue depth."""

    _WORKER_SQL = """
    SELECT
        a.pid,
        a.query,
        p.relid,
        c.relname AS table_name,
        p.phase,
        EXTRACT(EPOCH FROM (now() - a.xact_start)) AS elapsed_seconds,
        p.heap_blks_total,
        p.heap_blks_scanned,
        CASE WHEN p.heap_blks_total > 0
            THEN (p.heap_blks_scanned::float / p.heap_blks_total * 100)
            ELSE 0 END AS progress_pct
    FROM pg_stat_activity a
    LEFT JOIN pg_stat_progress_vacuum p ON a.pid = p.pid
    LEFT JOIN pg_class c ON p.relid = c.oid
    WHERE a.backend_type = 'autovacuum worker'
    ORDER BY elapsed_seconds DESC;
    """

    _QUEUE_SQL = """
    SELECT
        schemaname,
        relname,
        n_dead_tup,
        n_live_tup,
        CASE WHEN n_live_tup > 0
            THEN n_dead_tup::float / n_live_tup
            ELSE 0 END AS dead_ratio,
        -- Autovacuum threshold formula:
        -- threshold + scale_factor * n_live_tup
        (COALESCE(
            (SELECT option_value::int FROM pg_options_to_table(c.reloptions)
             WHERE option_name = 'autovacuum_vacuum_threshold'), 50
        ) + COALESCE(
            (SELECT option_value::float FROM pg_options_to_table(c.reloptions)
             WHERE option_name = 'autovacuum_vacuum_scale_factor'), 0.2
        ) * n_live_tup)::int AS threshold,
        EXTRACT(EPOCH FROM (now() - last_autovacuum)) AS since_vacuum_seconds
    FROM pg_stat_user_tables s
    JOIN pg_class c ON c.relname = s.relname AND c.relnamespace = (
        SELECT oid FROM pg_namespace WHERE nspname = s.schemaname
    )
    WHERE n_dead_tup > (
        COALESCE(
            (SELECT option_value::int FROM pg_options_to_table(c.reloptions)
             WHERE option_name = 'autovacuum_vacuum_threshold'), 50
        ) + COALESCE(
            (SELECT option_value::float FROM pg_options_to_table(c.reloptions)
             WHERE option_name = 'autovacuum_vacuum_scale_factor'), 0.2
        ) * n_live_tup
    )
    ORDER BY n_dead_tup DESC;
    """

    async def analyze(self, dsn: str) -> AutovacuumReport:
        """Analyze autovacuum utilization."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            return await self._analyze_conn(conn)
        finally:
            await conn.close()

    async def _analyze_conn(self, conn: Any) -> AutovacuumReport:
        report = AutovacuumReport()

        # System settings
        report.max_workers = int(
            await conn.fetchval("SELECT current_setting('autovacuum_max_workers')")
        )
        report.vacuum_cost_limit = int(
            await conn.fetchval("SELECT current_setting('autovacuum_vacuum_cost_limit')")
        )
        report.vacuum_cost_delay_ms = int(
            await conn.fetchval("SELECT current_setting('autovacuum_vacuum_cost_delay')")
        )

        # I/O rate: cost_limit / cost_delay * page_size
        if report.vacuum_cost_delay_ms > 0:
            report.effective_io_rate_pages_sec = (
                report.vacuum_cost_limit / (report.vacuum_cost_delay_ms / 1000.0)
            )

        # Active workers
        try:
            rows = await conn.fetch(self._WORKER_SQL)
            for row in rows:
                report.workers.append(WorkerStatus(
                    pid=row["pid"],
                    table=row["table_name"] or "unknown",
                    phase=row["phase"] or "scanning",
                    elapsed_seconds=row["elapsed_seconds"] or 0,
                    heap_blks_total=row["heap_blks_total"] or 0,
                    heap_blks_scanned=row["heap_blks_scanned"] or 0,
                    progress_pct=row["progress_pct"] or 0,
                ))
        except Exception:
            # Fallback: count workers from pg_stat_activity
            wc = await conn.fetchval(
                "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'autovacuum worker'"
            )
            report.active_workers = wc or 0

        report.active_workers = len(report.workers) or report.active_workers
        report.saturation_pct = (
            (report.active_workers / report.max_workers * 100) if report.max_workers > 0 else 0
        )

        # Queue
        try:
            rows = await conn.fetch(self._QUEUE_SQL)
            for row in rows:
                urgency = "normal"
                dead = row["n_dead_tup"] or 0
                live = row["n_live_tup"] or 0
                ratio = row["dead_ratio"] or 0

                if ratio > 0.5 or dead > 10_000_000:
                    urgency = "critical"
                elif ratio > 0.2 or dead > 1_000_000:
                    urgency = "high"

                # Estimate wait time based on queue position and worker speed
                eta = 0.0
                if report.effective_io_rate_pages_sec > 0 and report.max_workers > 0:
                    pages_to_vacuum = dead * 200 / 8192  # ~200 bytes per dead tuple / page size
                    eta = pages_to_vacuum / report.effective_io_rate_pages_sec / 60  # minutes

                report.queued_tables.append(QueuedTable(
                    table=row["relname"],
                    schema=row["schemaname"],
                    dead_tuples=dead,
                    live_tuples=live,
                    dead_ratio=ratio,
                    threshold=row["threshold"] or 50,
                    last_vacuum_seconds=row["since_vacuum_seconds"] or 0,
                    estimated_wait_minutes=eta,
                    urgency=urgency,
                ))
        except Exception:
            pass

        report.queue_depth = len(report.queued_tables)
        report.total_dead_tuples = sum(q.dead_tuples for q in report.queued_tables)
        report.tables_needing_vacuum = len(report.queued_tables)

        # Generate tuning recommendations
        report.tuning_recommendations = self._generate_tuning(report)

        return report

    def _generate_tuning(self, report: AutovacuumReport) -> list[TableVacuumTuning]:
        """Generate per-table autovacuum tuning recommendations."""
        recs: list[TableVacuumTuning] = []

        # If workers are saturated, recommend increasing max_workers
        if report.saturation_pct >= 100:
            recs.append(TableVacuumTuning(
                table="(system)",
                parameter="autovacuum_max_workers",
                current_value=str(report.max_workers),
                recommended_value=str(min(report.max_workers + 2, 10)),
                reason="All autovacuum workers busy -- vacuum is falling behind",
                alter_sql=f"ALTER SYSTEM SET autovacuum_max_workers = {min(report.max_workers + 2, 10)};",
            ))

        # Per-table tuning for critical tables
        for q in report.queued_tables:
            if q.urgency == "critical":
                # Lower scale factor for faster vacuuming
                recs.append(TableVacuumTuning(
                    table=q.table,
                    parameter="autovacuum_vacuum_scale_factor",
                    current_value="0.2 (default)",
                    recommended_value="0.01",
                    reason=f"Table has {q.dead_tuples:,} dead tuples ({q.dead_ratio:.0%} dead ratio)",
                    alter_sql=(
                        f"ALTER TABLE {q.schema}.{q.table} SET "
                        f"(autovacuum_vacuum_scale_factor = 0.01, "
                        f"autovacuum_vacuum_threshold = 1000);"
                    ),
                ))

        return recs

    def analyze_offline(
        self,
        max_workers: int = 3,
        active_workers: int = 0,
        queued_tables: list[dict[str, Any]] | None = None,
    ) -> AutovacuumReport:
        """Analyze from pre-collected data (no DB connection)."""
        report = AutovacuumReport(
            max_workers=max_workers,
            active_workers=active_workers,
            saturation_pct=(active_workers / max_workers * 100) if max_workers > 0 else 0,
        )

        for t in (queued_tables or []):
            dead = t.get("dead_tuples", 0)
            live = t.get("live_tuples", 0)
            ratio = dead / live if live > 0 else 0

            urgency = "normal"
            if ratio > 0.5 or dead > 10_000_000:
                urgency = "critical"
            elif ratio > 0.2 or dead > 1_000_000:
                urgency = "high"

            report.queued_tables.append(QueuedTable(
                table=t.get("table", ""),
                schema=t.get("schema", "public"),
                dead_tuples=dead,
                live_tuples=live,
                dead_ratio=ratio,
                urgency=urgency,
            ))

        report.queue_depth = len(report.queued_tables)
        report.total_dead_tuples = sum(q.dead_tuples for q in report.queued_tables)
        report.tuning_recommendations = self._generate_tuning(report)

        return report
