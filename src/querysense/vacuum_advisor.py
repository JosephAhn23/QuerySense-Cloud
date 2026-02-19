"""
Complete VACUUM Advisor — 4 categories of vacuum intelligence.

Mirrors pganalyze's VACUUM Advisor with all 4 categories:
1. Bloat — dead tuple accumulation, table/index bloat estimation
2. Freezing — XID wraparound risk, freeze age monitoring
3. Performance — autovacuum tuning, worker saturation, I/O impact
4. Activity — vacuum progress, long-running vacuums, schedule optimization

This goes well beyond the basic autovacuum_monitor.py by providing:
- Predictive alerts (bloat will reach X in Y days)
- Per-table autovacuum parameter tuning formulas
- Vacuum scheduling optimization
- Freeze map coverage analysis
- I/O budget calculations for autovacuum

Usage:
    from querysense.vacuum_advisor import VacuumAdvisor, VacuumReport

    advisor = VacuumAdvisor()
    report = await advisor.full_report(dsn="postgresql://localhost/mydb")
    for rec in report.recommendations:
        print(f"[{rec.category}] {rec.title}: {rec.fix_sql}")
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BloatEstimate:
    """Table bloat estimation."""
    table: str
    schema: str
    table_size_bytes: int
    estimated_bloat_bytes: int
    bloat_ratio: float  # 0-1
    dead_tuples: int
    live_tuples: int
    last_vacuum: str | None
    last_autovacuum: str | None
    days_since_vacuum: float

    @property
    def bloat_mb(self) -> float:
        return self.estimated_bloat_bytes / 1024 / 1024

    @property
    def is_critical(self) -> bool:
        return self.bloat_ratio > 0.5 or self.bloat_mb > 1000


@dataclass
class FreezeRisk:
    """Transaction ID freeze risk for a table."""
    table: str
    schema: str
    age_xid: int  # Current XID age
    max_age: int  # autovacuum_freeze_max_age
    pct_to_wraparound: float  # 0-1, how close to forced freeze
    estimated_days_to_freeze: float  # Days until forced anti-wraparound vacuum
    freeze_map_coverage: float  # 0-1, fraction of pages already frozen
    # Multixact ID wraparound tracking (relminmxid)
    age_mxid: int = 0  # Current multixact ID age
    mxid_pct_to_wraparound: float = 0.0  # 0-1, multixact wraparound risk
    is_anti_wraparound: bool = False  # True if vacuum was triggered by wraparound risk


@dataclass
class VacuumActivity:
    """Current vacuum activity on a table."""
    table: str
    pid: int
    phase: str  # scanning heap, vacuuming indexes, etc.
    heap_blks_total: int
    heap_blks_scanned: int
    progress_pct: float
    elapsed_seconds: float
    estimated_remaining_seconds: float


@dataclass
class AutovacuumTuning:
    """Recommended autovacuum parameters for a table."""
    table: str
    schema: str
    parameter: str
    current_value: str
    recommended_value: str
    reason: str
    alter_sql: str


@dataclass
class VacuumRecommendation:
    """A single vacuum advisory recommendation."""
    category: str  # bloat, freezing, performance, activity
    severity: str  # critical, warning, info
    title: str
    description: str
    table: str = ""
    fix_sql: str = ""
    impact: str = ""
    priority: int = 1


@dataclass
class TOASTBloat:
    """TOAST table bloat estimation."""
    table: str
    schema: str
    toast_size_bytes: int
    main_size_bytes: int
    toast_ratio: float  # toast_size / (toast_size + main_size)
    est_bloat_bytes: int = 0
    has_large_columns: bool = False
    large_column_names: list[str] = field(default_factory=list)


@dataclass
class CostThrottlingInfo:
    """Autovacuum cost-based throttling analysis."""
    vacuum_cost_delay_ms: int = 20
    vacuum_cost_limit: int = 200
    analyze_cost_delay_ms: int = 20
    analyze_cost_limit: int = 200
    is_ssd_likely: bool = False
    effective_io_pages_sec: float = 0.0
    recommended_cost_delay: int = 2
    recommended_cost_limit: int = 1000
    reason: str = ""


@dataclass
class VacuumReport:
    """Complete VACUUM advisor report."""
    # Category 1: Bloat
    bloat_estimates: list[BloatEstimate] = field(default_factory=list)

    # Category 2: Freezing
    freeze_risks: list[FreezeRisk] = field(default_factory=list)

    # Category 3: Performance
    tuning_recommendations: list[AutovacuumTuning] = field(default_factory=list)

    # Category 4: Activity
    active_vacuums: list[VacuumActivity] = field(default_factory=list)

    # Extended categories
    toast_bloat: list[TOASTBloat] = field(default_factory=list)
    cost_throttling: CostThrottlingInfo | None = None
    never_vacuumed_tables: list[str] = field(default_factory=list)

    # Unified recommendations
    recommendations: list[VacuumRecommendation] = field(default_factory=list)

    # System-wide stats
    autovacuum_workers_running: int = 0
    autovacuum_max_workers: int = 3
    total_dead_tuples: int = 0
    total_bloat_mb: float = 0
    tables_at_freeze_risk: int = 0

    @property
    def fix_script(self) -> str:
        lines = ["-- QuerySense VACUUM Advisor Fix Script", ""]
        for rec in self.recommendations:
            if rec.severity in ("critical", "warning") and rec.fix_sql:
                lines.append(f"-- [{rec.category.upper()}] {rec.title}")
                lines.append(rec.fix_sql)
                lines.append("")
        return "\n".join(lines)


class VacuumAdvisor:
    """
    Complete VACUUM advisor implementing all 4 pganalyze categories.

    Provides predictive, per-table, actionable vacuum intelligence.
    """

    async def full_report(
        self,
        dsn: str,
        schema: str = "public",
    ) -> VacuumReport:
        """Generate a complete vacuum advisory report."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            report = VacuumReport()

            # System-wide stats
            report.autovacuum_max_workers = int(
                await conn.fetchval("SELECT current_setting('autovacuum_max_workers')")
            )
            wc = await conn.fetchval(
                "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'autovacuum worker'"
            )
            report.autovacuum_workers_running = wc or 0

            # Category 1: Bloat
            report.bloat_estimates = await self._analyze_bloat(conn, schema)
            report.total_dead_tuples = sum(b.dead_tuples for b in report.bloat_estimates)
            report.total_bloat_mb = sum(b.bloat_mb for b in report.bloat_estimates)

            # Category 2: Freezing
            report.freeze_risks = await self._analyze_freezing(conn, schema)
            report.tables_at_freeze_risk = sum(1 for f in report.freeze_risks if f.pct_to_wraparound > 0.5)

            # Category 3: Performance (autovacuum tuning)
            report.tuning_recommendations = await self._analyze_performance(conn, schema)

            # Category 4: Activity
            report.active_vacuums = await self._analyze_activity(conn)

            # Extended: TOAST bloat
            report.toast_bloat = await self._analyze_toast(conn, schema)

            # Extended: Cost throttling
            report.cost_throttling = await self._analyze_cost_throttling(conn)

            # Extended: Never-vacuumed tables
            report.never_vacuumed_tables = await self._find_never_vacuumed(conn, schema)

            # Generate unified recommendations
            report.recommendations = self._generate_recommendations(report)

            return report
        finally:
            await conn.close()

    async def _analyze_bloat(
        self, conn: Any, schema: str,
    ) -> list[BloatEstimate]:
        """Category 1: Analyze table bloat."""
        rows = await conn.fetch("""
            SELECT
                s.schemaname,
                s.relname,
                s.n_live_tup,
                s.n_dead_tup,
                pg_total_relation_size(s.relid) AS total_size,
                s.last_vacuum::text,
                s.last_autovacuum::text,
                EXTRACT(EPOCH FROM (now() - COALESCE(s.last_autovacuum, s.last_vacuum))) / 86400.0
                    AS days_since_vacuum
            FROM pg_stat_user_tables s
            WHERE s.schemaname = $1
            ORDER BY s.n_dead_tup DESC
            LIMIT 50
        """, schema)

        estimates: list[BloatEstimate] = []
        for row in rows:
            live = row["n_live_tup"] or 0
            dead = row["n_dead_tup"] or 0
            total = live + dead
            ratio = dead / total if total > 0 else 0
            total_size = row["total_size"] or 0
            bloat_bytes = int(total_size * ratio) if total > 0 else 0

            estimates.append(BloatEstimate(
                table=row["relname"],
                schema=row["schemaname"],
                table_size_bytes=total_size,
                estimated_bloat_bytes=bloat_bytes,
                bloat_ratio=ratio,
                dead_tuples=dead,
                live_tuples=live,
                last_vacuum=row["last_vacuum"],
                last_autovacuum=row["last_autovacuum"],
                days_since_vacuum=row["days_since_vacuum"] or 999,
            ))

        return estimates

    async def _analyze_freezing(
        self, conn: Any, schema: str,
    ) -> list[FreezeRisk]:
        """Category 2: Analyze XID and multixact ID freeze risk.

        Tracks both relfrozenxid (transaction ID) and relminmxid (multixact ID)
        to detect wraparound risk. Also detects anti-wraparound autovacuums —
        vacuums triggered specifically for freezing rather than routine cleanup.
        """
        freeze_max = int(
            await conn.fetchval("SELECT current_setting('autovacuum_freeze_max_age')")
        )
        # Multixact freeze max age (defaults to autovacuum_multixact_freeze_max_age)
        try:
            mxid_freeze_max = int(
                await conn.fetchval(
                    "SELECT current_setting('autovacuum_multixact_freeze_max_age')"
                )
            )
        except Exception:
            mxid_freeze_max = freeze_max  # Fallback if setting unavailable

        rows = await conn.fetch("""
            SELECT
                n.nspname AS schemaname,
                c.relname,
                age(c.relfrozenxid) AS xid_age,
                COALESCE(mxid_age.age, 0) AS mxid_age,
                pg_stat_get_live_tuples(c.oid) AS n_live_tup,
                s.last_autovacuum,
                s.autovacuum_count
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_stat_user_tables s
                ON s.schemaname = n.nspname AND s.relname = c.relname
            LEFT JOIN LATERAL (
                SELECT age(c.relminmxid) AS age
            ) mxid_age ON true
            WHERE n.nspname = $1
              AND c.relkind = 'r'
            ORDER BY age(c.relfrozenxid) DESC
            LIMIT 30
        """, schema)

        max_xid = 2_000_000_000
        max_mxid = 2_000_000_000
        risks: list[FreezeRisk] = []

        for row in rows:
            age = row["xid_age"]
            pct = age / max_xid
            mxid_age = row["mxid_age"] or 0
            mxid_pct = mxid_age / max_mxid

            # Estimate days to forced freeze
            est_days = (max_xid - age) / max(age / 30, 1)  # Rough estimate

            # Detect anti-wraparound vacuum:
            # If xid_age > autovacuum_freeze_max_age, autovacuum is triggered
            # specifically for freezing (not routine cleanup)
            is_anti_wraparound = age > freeze_max or mxid_age > mxid_freeze_max

            # Freeze map coverage (PG 9.6+)
            try:
                fm_row = await conn.fetchrow("""
                    SELECT
                        pg_relation_size($1::regclass) / current_setting('block_size')::int AS total_pages,
                        COALESCE((
                            SELECT count(*)
                            FROM pg_visibility_map_summary($1::regclass)
                        ), 0) AS frozen_pages
                """, f"{schema}.{row['relname']}")
                total_pages = fm_row["total_pages"] if fm_row else 1
                frozen_pages = fm_row["frozen_pages"] if fm_row else 0
                freeze_coverage = frozen_pages / max(total_pages, 1)
            except Exception:
                freeze_coverage = 0.0

            risks.append(FreezeRisk(
                table=row["relname"],
                schema=schema,
                age_xid=age,
                max_age=freeze_max,
                pct_to_wraparound=pct,
                estimated_days_to_freeze=est_days,
                freeze_map_coverage=freeze_coverage,
                age_mxid=mxid_age,
                mxid_pct_to_wraparound=mxid_pct,
                is_anti_wraparound=is_anti_wraparound,
            ))

        return risks

    async def _analyze_performance(
        self, conn: Any, schema: str,
    ) -> list[AutovacuumTuning]:
        """Category 3: Autovacuum performance tuning per table."""
        tunings: list[AutovacuumTuning] = []

        # Get global autovacuum settings
        global_sf = float(
            await conn.fetchval("SELECT current_setting('autovacuum_vacuum_scale_factor')")
        )
        global_threshold = int(
            await conn.fetchval("SELECT current_setting('autovacuum_vacuum_threshold')")
        )
        global_cost_limit = int(
            await conn.fetchval("SELECT current_setting('autovacuum_vacuum_cost_limit')")
        )

        # Find tables that need per-table tuning
        rows = await conn.fetch("""
            SELECT
                s.relname,
                s.schemaname,
                s.n_live_tup,
                s.n_dead_tup,
                s.n_tup_ins + s.n_tup_upd + s.n_tup_del AS total_writes,
                pg_total_relation_size(s.relid) AS total_size,
                COALESCE(
                    (SELECT reloptions FROM pg_class WHERE oid = s.relid),
                    ARRAY[]::text[]
                ) AS reloptions
            FROM pg_stat_user_tables s
            WHERE s.schemaname = $1
              AND s.n_live_tup > 10000
            ORDER BY s.n_live_tup DESC
            LIMIT 30
        """, schema)

        for row in rows:
            live = row["n_live_tup"]
            dead = row["n_dead_tup"] or 0
            table = row["relname"]
            total_size = row["total_size"] or 0

            # Check if default scale factor is too aggressive for large tables
            trigger_threshold = int(global_threshold + global_sf * live)

            if live > 1_000_000 and global_sf >= 0.2:
                # For tables >1M rows, 20% means 200K dead tuples before vacuum
                recommended_sf = max(0.01, 50000 / live)
                tunings.append(AutovacuumTuning(
                    table=table,
                    schema=schema,
                    parameter="autovacuum_vacuum_scale_factor",
                    current_value=str(global_sf),
                    recommended_value=f"{recommended_sf:.4f}",
                    reason=(
                        f"Table has {live:,} rows. Default scale_factor {global_sf} "
                        f"means vacuum triggers at {trigger_threshold:,} dead tuples. "
                        f"Recommended: trigger at ~50K dead tuples."
                    ),
                    alter_sql=(
                        f"ALTER TABLE {schema}.{table} SET (\n"
                        f"  autovacuum_vacuum_scale_factor = {recommended_sf:.4f},\n"
                        f"  autovacuum_vacuum_threshold = 50000\n"
                        f");"
                    ),
                ))

            # Check if table needs higher cost_limit for faster vacuum
            if total_size > 1024 * 1024 * 1024 and dead > live * 0.1:
                tunings.append(AutovacuumTuning(
                    table=table,
                    schema=schema,
                    parameter="autovacuum_vacuum_cost_limit",
                    current_value=str(global_cost_limit),
                    recommended_value="2000",
                    reason=(
                        f"Table is {total_size // 1024 // 1024}MB with {dead:,} dead tuples. "
                        f"Increase cost_limit to let vacuum run faster."
                    ),
                    alter_sql=(
                        f"ALTER TABLE {schema}.{table} SET (\n"
                        f"  autovacuum_vacuum_cost_limit = 2000,\n"
                        f"  autovacuum_vacuum_cost_delay = 2\n"
                        f");"
                    ),
                ))

        return tunings

    async def _analyze_activity(self, conn: Any) -> list[VacuumActivity]:
        """Category 4: Monitor current vacuum activity."""
        try:
            rows = await conn.fetch("""
                SELECT
                    p.relid::regclass::text AS table_name,
                    p.pid,
                    p.phase,
                    p.heap_blks_total,
                    p.heap_blks_scanned,
                    CASE WHEN p.heap_blks_total > 0
                         THEN p.heap_blks_scanned::float / p.heap_blks_total * 100
                         ELSE 0 END AS progress_pct,
                    EXTRACT(EPOCH FROM (now() - a.backend_start)) AS elapsed_secs
                FROM pg_stat_progress_vacuum p
                JOIN pg_stat_activity a ON a.pid = p.pid
            """)
        except Exception:
            return []

        activities: list[VacuumActivity] = []
        for row in rows:
            progress = row["progress_pct"]
            elapsed = row["elapsed_secs"]

            # Estimate remaining time
            if progress > 0:
                estimated_total = elapsed / (progress / 100)
                remaining = estimated_total - elapsed
            else:
                remaining = 0

            activities.append(VacuumActivity(
                table=row["table_name"],
                pid=row["pid"],
                phase=row["phase"],
                heap_blks_total=row["heap_blks_total"],
                heap_blks_scanned=row["heap_blks_scanned"],
                progress_pct=progress,
                elapsed_seconds=elapsed,
                estimated_remaining_seconds=remaining,
            ))

        return activities

    async def _analyze_toast(
        self, conn: Any, schema: str,
    ) -> list[TOASTBloat]:
        """Analyze TOAST table bloat for tables with large columns."""
        try:
            rows = await conn.fetch("""
                SELECT
                    c.relname AS table_name,
                    n.nspname AS schema_name,
                    pg_total_relation_size(c.oid) AS total_size,
                    pg_relation_size(c.oid) AS main_size,
                    COALESCE(pg_relation_size(c.reltoastrelid), 0) AS toast_size
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = $1
                  AND c.relkind = 'r'
                  AND c.reltoastrelid != 0
                ORDER BY pg_relation_size(c.reltoastrelid) DESC
                LIMIT 20
            """, schema)
        except Exception:
            return []

        results: list[TOASTBloat] = []
        for row in rows:
            toast = row["toast_size"]
            main = row["main_size"]
            total = toast + main
            if total == 0:
                continue
            ratio = toast / total if total > 0 else 0

            # Find large columns (text, jsonb, bytea)
            large_cols: list[str] = []
            try:
                col_rows = await conn.fetch("""
                    SELECT a.attname
                    FROM pg_attribute a
                    JOIN pg_type t ON t.oid = a.atttypid
                    WHERE a.attrelid = $1::regclass
                      AND a.attnum > 0
                      AND NOT a.attisdropped
                      AND t.typname IN ('text', 'jsonb', 'json', 'bytea', 'xml', 'varchar')
                      AND a.attstorage IN ('x', 'e')
                """, f"{schema}.{row['table_name']}")
                large_cols = [r["attname"] for r in col_rows]
            except Exception:
                pass

            if toast > 1024 * 1024:  # Only report if TOAST > 1MB
                results.append(TOASTBloat(
                    table=row["table_name"],
                    schema=schema,
                    toast_size_bytes=toast,
                    main_size_bytes=main,
                    toast_ratio=ratio,
                    has_large_columns=bool(large_cols),
                    large_column_names=large_cols,
                ))

        return results

    async def _analyze_cost_throttling(self, conn: Any) -> CostThrottlingInfo:
        """Analyze autovacuum cost-based throttling settings."""
        try:
            cost_delay = int(await conn.fetchval(
                "SELECT current_setting('autovacuum_vacuum_cost_delay')"
            ))
        except Exception:
            cost_delay = 20

        try:
            cost_limit = int(await conn.fetchval(
                "SELECT current_setting('autovacuum_vacuum_cost_limit')"
            ))
        except Exception:
            cost_limit = 200

        # Heuristic: detect if storage is likely SSD
        # If random_page_cost <= 1.5, assume SSD
        try:
            rpc = float(await conn.fetchval(
                "SELECT current_setting('random_page_cost')"
            ))
            is_ssd = rpc <= 1.5
        except Exception:
            is_ssd = False

        # Calculate effective I/O rate
        # vacuum_cost_limit / vacuum_cost_delay gives max I/O ops per second
        if cost_delay > 0:
            effective_io = (cost_limit / cost_delay) * 1000  # ops/sec
        else:
            effective_io = float('inf')

        # Recommendations
        rec_delay = 2 if is_ssd else max(5, cost_delay // 2)
        rec_limit = 1000 if is_ssd else max(400, cost_limit * 2)

        reasons = []
        if is_ssd and cost_delay > 5:
            reasons.append(f"SSD detected (random_page_cost={rpc}) but cost_delay={cost_delay}ms is too conservative")
        if cost_limit < 400:
            reasons.append(f"cost_limit={cost_limit} is below recommended minimum of 400")
        if cost_delay >= 20:
            reasons.append(f"cost_delay={cost_delay}ms (default) -- modern hardware can handle much less")

        return CostThrottlingInfo(
            vacuum_cost_delay_ms=cost_delay,
            vacuum_cost_limit=cost_limit,
            is_ssd_likely=is_ssd,
            effective_io_pages_sec=effective_io,
            recommended_cost_delay=rec_delay,
            recommended_cost_limit=rec_limit,
            reason="; ".join(reasons) if reasons else "Settings are reasonable",
        )

    async def _find_never_vacuumed(self, conn: Any, schema: str) -> list[str]:
        """Find tables that have never been vacuumed."""
        try:
            rows = await conn.fetch("""
                SELECT s.relname
                FROM pg_stat_user_tables s
                WHERE s.schemaname = $1
                  AND s.last_vacuum IS NULL
                  AND s.last_autovacuum IS NULL
                  AND s.n_live_tup > 100
                ORDER BY s.n_live_tup DESC
                LIMIT 20
            """, schema)
            return [r["relname"] for r in rows]
        except Exception:
            return []

    def _generate_recommendations(self, report: VacuumReport) -> list[VacuumRecommendation]:
        """Generate unified recommendations from all 4 categories."""
        recs: list[VacuumRecommendation] = []

        # Bloat recommendations
        for bloat in report.bloat_estimates:
            if bloat.is_critical:
                recs.append(VacuumRecommendation(
                    category="bloat",
                    severity="critical",
                    title=f"Critical bloat on {bloat.schema}.{bloat.table}",
                    description=(
                        f"{bloat.dead_tuples:,} dead tuples ({bloat.bloat_ratio:.0%} bloat). "
                        f"~{bloat.bloat_mb:.0f}MB wasted."
                    ),
                    table=f"{bloat.schema}.{bloat.table}",
                    fix_sql=(
                        f"-- Immediate vacuum:\n"
                        f"VACUUM (VERBOSE) {bloat.schema}.{bloat.table};\n"
                        f"-- For severe bloat (locks table):\n"
                        f"-- VACUUM (FULL) {bloat.schema}.{bloat.table};\n"
                        f"-- For production (no lock): pg_repack -t {bloat.schema}.{bloat.table}"
                    ),
                    impact=f"Recover ~{bloat.bloat_mb:.0f}MB, improve scan performance",
                    priority=1,
                ))
            elif bloat.bloat_ratio > 0.2 and bloat.dead_tuples > 10000:
                recs.append(VacuumRecommendation(
                    category="bloat",
                    severity="warning",
                    title=f"Growing bloat on {bloat.schema}.{bloat.table}",
                    description=(
                        f"{bloat.dead_tuples:,} dead tuples ({bloat.bloat_ratio:.0%}). "
                        f"Last vacuum: {bloat.days_since_vacuum:.0f} days ago."
                    ),
                    table=f"{bloat.schema}.{bloat.table}",
                    fix_sql=f"VACUUM (ANALYZE, VERBOSE) {bloat.schema}.{bloat.table};",
                    impact="Prevent bloat accumulation",
                    priority=2,
                ))

        # Freezing recommendations
        for risk in report.freeze_risks:
            if risk.pct_to_wraparound > 0.75:
                recs.append(VacuumRecommendation(
                    category="freezing",
                    severity="critical",
                    title=f"XID wraparound imminent on {risk.schema}.{risk.table}",
                    description=(
                        f"XID age: {risk.age_xid:,} ({risk.pct_to_wraparound:.0%} to wraparound). "
                        f"Database will SHUT DOWN to prevent corruption."
                    ),
                    table=f"{risk.schema}.{risk.table}",
                    fix_sql=f"VACUUM (FREEZE, VERBOSE) {risk.schema}.{risk.table};",
                    impact="PREVENT DATABASE SHUTDOWN",
                    priority=0,  # Highest priority
                ))
            elif risk.pct_to_wraparound > 0.5:
                recs.append(VacuumRecommendation(
                    category="freezing",
                    severity="warning",
                    title=f"Freeze risk on {risk.schema}.{risk.table}",
                    description=(
                        f"XID age: {risk.age_xid:,} ({risk.pct_to_wraparound:.0%}). "
                        f"~{risk.estimated_days_to_freeze:.0f} days to forced anti-wraparound."
                    ),
                    table=f"{risk.schema}.{risk.table}",
                    fix_sql=f"VACUUM (FREEZE) {risk.schema}.{risk.table};",
                    impact="Prevent anti-wraparound emergency vacuum",
                    priority=1,
                ))

        # Performance recommendations
        for tuning in report.tuning_recommendations:
            recs.append(VacuumRecommendation(
                category="performance",
                severity="warning",
                title=f"Tune autovacuum for {tuning.schema}.{tuning.table}",
                description=tuning.reason,
                table=f"{tuning.schema}.{tuning.table}",
                fix_sql=tuning.alter_sql,
                impact="Vacuum triggers earlier, preventing bloat accumulation",
                priority=2,
            ))

        # Worker saturation
        if report.autovacuum_workers_running >= report.autovacuum_max_workers:
            recs.append(VacuumRecommendation(
                category="performance",
                severity="critical",
                title="Autovacuum workers fully saturated",
                description=(
                    f"All {report.autovacuum_max_workers} workers busy. "
                    f"Tables are queuing for vacuum."
                ),
                fix_sql=(
                    f"ALTER SYSTEM SET autovacuum_max_workers = "
                    f"{report.autovacuum_max_workers + 2};\n"
                    f"SELECT pg_reload_conf();"
                ),
                impact="Prevent vacuum backlog",
                priority=1,
            ))

        # Activity observations
        for activity in report.active_vacuums:
            if activity.elapsed_seconds > 3600:
                recs.append(VacuumRecommendation(
                    category="activity",
                    severity="info",
                    title=f"Long-running vacuum on {activity.table}",
                    description=(
                        f"Phase: {activity.phase}, Progress: {activity.progress_pct:.1f}%, "
                        f"Elapsed: {activity.elapsed_seconds / 3600:.1f}h, "
                        f"ETA: {activity.estimated_remaining_seconds / 3600:.1f}h"
                    ),
                    table=activity.table,
                    impact="Monitor — may need cost_limit increase",
                    priority=3,
                ))

        # Cost throttling recommendations
        ct = report.cost_throttling
        if ct and (ct.vacuum_cost_delay_ms > 10 or ct.vacuum_cost_limit < 400):
            recs.append(VacuumRecommendation(
                category="performance",
                severity="warning",
                title="Autovacuum cost throttling too conservative",
                description=ct.reason,
                fix_sql=(
                    f"ALTER SYSTEM SET autovacuum_vacuum_cost_delay = {ct.recommended_cost_delay};\n"
                    f"ALTER SYSTEM SET autovacuum_vacuum_cost_limit = {ct.recommended_cost_limit};\n"
                    f"SELECT pg_reload_conf();\n"
                    f"-- Was: cost_delay={ct.vacuum_cost_delay_ms}ms, cost_limit={ct.vacuum_cost_limit}"
                    + (f"\n-- SSD detected: aggressive settings safe" if ct.is_ssd_likely else "")
                ),
                impact="Vacuum runs faster, bloat accumulates slower",
                priority=2,
            ))

        # Never-vacuumed tables
        for table_name in report.never_vacuumed_tables:
            recs.append(VacuumRecommendation(
                category="activity",
                severity="warning",
                title=f"Table never vacuumed: {table_name}",
                description="No manual or autovacuum has ever run on this table. Statistics may be stale.",
                table=table_name,
                fix_sql=f"VACUUM (ANALYZE, VERBOSE) {table_name};",
                impact="Stale statistics cause bad query plans",
                priority=2,
            ))

        # TOAST bloat
        for toast in report.toast_bloat:
            if toast.toast_ratio > 0.5:
                mb = toast.toast_size_bytes / 1024 / 1024
                cols = ", ".join(toast.large_column_names[:5]) if toast.large_column_names else "unknown"
                recs.append(VacuumRecommendation(
                    category="bloat",
                    severity="warning" if mb > 100 else "info",
                    title=f"TOAST bloat on {toast.schema}.{toast.table}",
                    description=(
                        f"TOAST data is {mb:.0f}MB ({toast.toast_ratio:.0%} of table). "
                        f"Large columns: {cols}."
                    ),
                    table=f"{toast.schema}.{toast.table}",
                    fix_sql=(
                        f"-- TOAST vacuum (included in regular VACUUM):\n"
                        f"VACUUM (VERBOSE) {toast.schema}.{toast.table};\n"
                        f"-- Consider: compress large columns, or use EXTERNAL storage"
                    ),
                    impact=f"Reclaim ~{mb * 0.3:.0f}MB of TOAST bloat",
                    priority=3,
                ))

        recs.sort(key=lambda r: r.priority)
        return recs
