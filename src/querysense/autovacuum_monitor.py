"""
Autovacuum Health Monitor — proactive warnings and tuning commands.

Based on "PostgreSQL Mistakes and How to Avoid Them" (Angelakos 2025):
autovacuum misconfiguration is one of the most common production mistakes.

Detects:
- Autovacuum falling behind (dead tuple accumulation)
- Tables approaching transaction ID wraparound
- Bloat ratio exceeding thresholds
- Autovacuum workers being fully consumed
- Individual table tuning needs

Provides exact ALTER TABLE SET commands, not just warnings.

Usage:
    from querysense.autovacuum_monitor import AutovacuumMonitor, VacuumHealth

    monitor = AutovacuumMonitor()
    health = await monitor.check(dsn="postgresql://localhost/mydb")
    for alert in health.alerts:
        print(f"{alert.severity}: {alert.message}")
        print(f"  Fix: {alert.fix_command}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VacuumAlert:
    """A single vacuum health alert."""
    severity: str  # critical, warning, info
    category: str  # dead_tuples, bloat, wraparound, config, workers
    table: str
    message: str
    fix_command: str
    impact: str
    metric_value: float = 0.0
    threshold: float = 0.0

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.table}: {self.message}"


@dataclass
class TableVacuumInfo:
    """Vacuum info for a single table."""
    schema: str
    table: str
    n_live_tup: int
    n_dead_tup: int
    dead_ratio: float
    last_vacuum: str | None
    last_autovacuum: str | None
    last_analyze: str | None
    autovacuum_count: int
    vacuum_count: int
    bloat_ratio: float
    table_size_bytes: int
    age_xid: int  # Transaction ID age


@dataclass
class VacuumHealth:
    """Complete autovacuum health report."""
    alerts: list[VacuumAlert] = field(default_factory=list)
    tables: list[TableVacuumInfo] = field(default_factory=list)
    total_dead_tuples: int = 0
    total_bloat_bytes: int = 0
    autovacuum_workers_running: int = 0
    autovacuum_max_workers: int = 3
    wraparound_danger_tables: int = 0
    overall_health: str = "healthy"  # healthy, degraded, critical

    @property
    def fix_script(self) -> str:
        lines = ["-- QuerySense Autovacuum Health Fix Script", ""]
        for alert in self.alerts:
            if alert.severity in ("critical", "warning"):
                lines.append(f"-- {alert.message}")
                lines.append(f"{alert.fix_command}")
                lines.append("")
        return "\n".join(lines)


class AutovacuumMonitor:
    """
    Monitor autovacuum health and provide proactive tuning.

    Connects to a live database and analyzes vacuum stats for all tables.
    """

    async def check(
        self,
        dsn: str,
        dead_tuple_ratio_warn: float = 0.1,
        dead_tuple_ratio_critical: float = 0.2,
        bloat_ratio_warn: float = 0.3,
        wraparound_warn_pct: float = 0.5,  # 50% of 2B = 1B XIDs
    ) -> VacuumHealth:
        """Run autovacuum health check."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            health = VacuumHealth()

            # Get autovacuum worker status
            health.autovacuum_max_workers = int(
                await conn.fetchval("SELECT current_setting('autovacuum_max_workers')")
            )
            row = await conn.fetchval(
                "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'autovacuum worker'"
            )
            health.autovacuum_workers_running = row or 0

            # Check if workers are saturated
            if health.autovacuum_workers_running >= health.autovacuum_max_workers:
                health.alerts.append(VacuumAlert(
                    severity="critical",
                    category="workers",
                    table="(system-wide)",
                    message=(
                        f"All {health.autovacuum_max_workers} autovacuum workers are busy! "
                        f"Vacuum is falling behind."
                    ),
                    fix_command=(
                        f"ALTER SYSTEM SET autovacuum_max_workers = "
                        f"{health.autovacuum_max_workers + 2};"
                    ),
                    impact="Tables not getting vacuumed, bloat accumulating",
                ))

            # Get per-table stats
            tables = await self._fetch_table_stats(conn)
            health.tables = tables

            for t in tables:
                health.total_dead_tuples += t.n_dead_tup

                # Dead tuple ratio
                if t.n_live_tup > 1000:
                    if t.dead_ratio > dead_tuple_ratio_critical:
                        health.alerts.append(VacuumAlert(
                            severity="critical",
                            category="dead_tuples",
                            table=f"{t.schema}.{t.table}",
                            message=(
                                f"{t.n_dead_tup:,} dead tuples ({t.dead_ratio:.0%} of table). "
                                f"Autovacuum is not keeping up."
                            ),
                            fix_command=(
                                f"-- Immediate vacuum:\n"
                                f"VACUUM (VERBOSE) {t.schema}.{t.table};\n"
                                f"-- Tune for this table:\n"
                                f"ALTER TABLE {t.schema}.{t.table} SET (\n"
                                f"  autovacuum_vacuum_scale_factor = 0.01,\n"
                                f"  autovacuum_vacuum_threshold = 50\n"
                                f");"
                            ),
                            impact="Table bloat causing slower queries and wasted disk",
                            metric_value=t.dead_ratio,
                            threshold=dead_tuple_ratio_critical,
                        ))
                    elif t.dead_ratio > dead_tuple_ratio_warn:
                        health.alerts.append(VacuumAlert(
                            severity="warning",
                            category="dead_tuples",
                            table=f"{t.schema}.{t.table}",
                            message=(
                                f"{t.n_dead_tup:,} dead tuples ({t.dead_ratio:.0%}). "
                                f"Approaching bloat threshold."
                            ),
                            fix_command=(
                                f"ALTER TABLE {t.schema}.{t.table} SET (\n"
                                f"  autovacuum_vacuum_scale_factor = 0.05\n"
                                f");"
                            ),
                            impact="Growing bloat will slow scans",
                            metric_value=t.dead_ratio,
                            threshold=dead_tuple_ratio_warn,
                        ))

                # Bloat
                if t.bloat_ratio > bloat_ratio_warn and t.table_size_bytes > 100 * 1024 * 1024:
                    health.total_bloat_bytes += int(t.table_size_bytes * t.bloat_ratio)
                    health.alerts.append(VacuumAlert(
                        severity="warning",
                        category="bloat",
                        table=f"{t.schema}.{t.table}",
                        message=(
                            f"Table bloat ratio: {t.bloat_ratio:.0%}. "
                            f"~{int(t.table_size_bytes * t.bloat_ratio) // 1024 // 1024}MB wasted."
                        ),
                        fix_command=(
                            f"-- For moderate bloat:\n"
                            f"VACUUM (FULL) {t.schema}.{t.table};  -- WARNING: locks table\n"
                            f"-- For production (no lock):\n"
                            f"-- Use pg_repack: pg_repack -t {t.schema}.{t.table} -d <dbname>"
                        ),
                        impact="Wasted disk space and slower sequential scans",
                        metric_value=t.bloat_ratio,
                    ))

                # Transaction ID wraparound
                max_xid = 2_000_000_000
                if t.age_xid > int(max_xid * wraparound_warn_pct):
                    health.wraparound_danger_tables += 1
                    remaining = max_xid - t.age_xid
                    health.alerts.append(VacuumAlert(
                        severity="critical" if remaining < 200_000_000 else "warning",
                        category="wraparound",
                        table=f"{t.schema}.{t.table}",
                        message=(
                            f"Transaction ID age: {t.age_xid:,}. "
                            f"Wraparound in {remaining:,} transactions. "
                            f"{'URGENT: database will shut down to prevent corruption!' if remaining < 200_000_000 else 'Needs aggressive vacuum.'}"
                        ),
                        fix_command=(
                            f"VACUUM (FREEZE, VERBOSE) {t.schema}.{t.table};"
                        ),
                        impact="Transaction ID wraparound causes database shutdown",
                        metric_value=float(t.age_xid),
                        threshold=float(max_xid),
                    ))

                # Never vacuumed
                if t.last_vacuum is None and t.last_autovacuum is None and t.n_live_tup > 10000:
                    health.alerts.append(VacuumAlert(
                        severity="warning",
                        category="config",
                        table=f"{t.schema}.{t.table}",
                        message=f"Table has NEVER been vacuumed ({t.n_live_tup:,} rows)",
                        fix_command=f"VACUUM (ANALYZE, VERBOSE) {t.schema}.{t.table};",
                        impact="Accumulating dead tuples with no cleanup scheduled",
                    ))

            # Overall health
            crit = sum(1 for a in health.alerts if a.severity == "critical")
            warn = sum(1 for a in health.alerts if a.severity == "warning")
            if crit > 0:
                health.overall_health = "critical"
            elif warn > 2:
                health.overall_health = "degraded"
            else:
                health.overall_health = "healthy"

            return health
        finally:
            await conn.close()

    async def _fetch_table_stats(self, conn: Any) -> list[TableVacuumInfo]:
        """Fetch vacuum stats for all tables."""
        rows = await conn.fetch("""
            SELECT
                schemaname,
                relname,
                n_live_tup,
                n_dead_tup,
                CASE WHEN n_live_tup + n_dead_tup > 0
                     THEN n_dead_tup::float / (n_live_tup + n_dead_tup)
                     ELSE 0 END AS dead_ratio,
                last_vacuum::text,
                last_autovacuum::text,
                last_analyze::text,
                autovacuum_count,
                vacuum_count,
                pg_total_relation_size(relid) AS table_size,
                age(relfrozenxid) AS xid_age
            FROM pg_stat_user_tables
            JOIN pg_class ON pg_class.oid = relid
            WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY n_dead_tup DESC
        """)

        tables: list[TableVacuumInfo] = []
        for row in rows:
            n_live = row["n_live_tup"] or 0
            n_dead = row["n_dead_tup"] or 0
            size = row["table_size"] or 0

            # Estimate bloat from dead tuple ratio
            total_rows = n_live + n_dead
            bloat_ratio = n_dead / total_rows if total_rows > 0 else 0.0

            tables.append(TableVacuumInfo(
                schema=row["schemaname"],
                table=row["relname"],
                n_live_tup=n_live,
                n_dead_tup=n_dead,
                dead_ratio=row["dead_ratio"],
                last_vacuum=row["last_vacuum"],
                last_autovacuum=row["last_autovacuum"],
                last_analyze=row["last_analyze"],
                autovacuum_count=row["autovacuum_count"],
                vacuum_count=row["vacuum_count"],
                bloat_ratio=bloat_ratio,
                table_size_bytes=size,
                age_xid=row["xid_age"],
            ))

        return tables
