"""
Vacuum Advisor Checks — Percona-style VACUUM health monitoring.

Implements 5 critical vacuum checks:
    1. Table bloat detection (dead tuple ratio)
    2. Transaction ID wraparound prevention
    3. Autovacuum logging configuration
    4. Autovacuum scale factor tuning
    5. Long-running vacuum detection

Bridges to querysense.vacuum_advisor for deeper analysis.
"""

from __future__ import annotations

from querysense.advisor.base import (
    AdvisorCategory,
    AdvisorCheck,
    AsyncDBConnection,
    CheckInterval,
    CheckResult,
    CheckSeverity,
    Finding,
)


class TableBloatCheck(AdvisorCheck):
    """Check for tables with excessive bloat (dead tuples)."""

    name = "postgres_table_bloat"
    title = "Table Bloat Detection"
    description = "Detect tables with high dead tuple ratio"
    category = AdvisorCategory.VACUUM
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        rows = await conn.fetch(
            "SELECT schemaname, relname, n_live_tup, n_dead_tup, "
            "  CASE WHEN n_live_tup > 0 THEN n_dead_tup::float / n_live_tup ELSE 0 END AS dead_ratio, "
            "  pg_size_pretty(pg_relation_size(relid)) AS table_size, "
            "  pg_relation_size(relid) AS size_bytes, "
            "  last_vacuum, last_autovacuum "
            "FROM pg_stat_user_tables "
            "WHERE n_dead_tup > 10000 "
            "ORDER BY n_dead_tup DESC LIMIT 10"
        )

        for row in rows:
            if isinstance(row, (list, tuple)):
                schema, table, live, dead, ratio, size_pretty, size_bytes, last_vac, last_auto = row[:9]
            else:
                schema = getattr(row, "schemaname", "")
                table = getattr(row, "relname", "")
                live = getattr(row, "n_live_tup", 0)
                dead = getattr(row, "n_dead_tup", 0)
                ratio = getattr(row, "dead_ratio", 0)
                size_pretty = getattr(row, "table_size", "")
                size_bytes = getattr(row, "size_bytes", 0)
                last_vac = getattr(row, "last_vacuum", None)
                last_auto = getattr(row, "last_autovacuum", None)

            ratio_f = float(ratio or 0)
            dead_i = int(dead or 0)

            if ratio_f > 0.5:
                sev = CheckSeverity.CRITICAL
            elif ratio_f > 0.2:
                sev = CheckSeverity.WARNING
            elif dead_i > 100000:
                sev = CheckSeverity.WARNING
            else:
                sev = CheckSeverity.NOTICE

            result.findings.append(Finding(
                severity=sev,
                title=f"{schema}.{table}: {dead_i:,} dead tuples ({ratio_f:.0%} bloat)",
                description=f"Table size: {size_pretty}. Live: {int(live or 0):,}. Dead: {dead_i:,}.",
                recommendation=f"VACUUM ANALYZE {schema}.{table};",
                fix_sql=f"VACUUM ANALYZE {schema}.{table};",
                evidence={
                    "dead_tuples": dead_i,
                    "live_tuples": int(live or 0),
                    "ratio": round(ratio_f, 3),
                    "size_bytes": int(size_bytes or 0),
                },
                tags=["bloat", "vacuum"],
            ))
            result.passed = False

        return result


class XIDWraparoundCheck(AdvisorCheck):
    """Check for transaction ID wraparound risk."""

    name = "postgres_xid_wraparound"
    title = "Transaction ID Wraparound"
    description = "Detect tables approaching the 2-billion XID limit"
    category = AdvisorCategory.VACUUM
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        rows = await conn.fetch(
            "SELECT c.oid::regclass AS table_name, "
            "  age(c.relfrozenxid) AS xid_age, "
            "  pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size "
            "FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind = 'r' "
            "  AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
            "  AND age(c.relfrozenxid) > 500000000 "
            "ORDER BY age(c.relfrozenxid) DESC LIMIT 10"
        )

        for row in rows:
            if isinstance(row, (list, tuple)):
                table, xid_age, size = row[:3]
            else:
                table = getattr(row, "table_name", "")
                xid_age = getattr(row, "xid_age", 0)
                size = getattr(row, "total_size", "")

            age = int(xid_age or 0)
            pct = age / 2_000_000_000

            if age > 1_500_000_000:
                sev = CheckSeverity.EMERGENCY
            elif age > 1_000_000_000:
                sev = CheckSeverity.CRITICAL
            elif age > 500_000_000:
                sev = CheckSeverity.WARNING
            else:
                continue

            result.findings.append(Finding(
                severity=sev,
                title=f"XID wraparound risk: {table} age={age:,} ({pct:.0%} to limit)",
                description=(
                    f"Table {table} (size: {size}) has XID age {age:,}. "
                    f"PostgreSQL forces anti-wraparound VACUUM at 200M. "
                    f"Forced shutdown at 40M remaining."
                ),
                recommendation=f"VACUUM FREEZE {table}; immediately.",
                fix_sql=f"VACUUM FREEZE {table};",
                rationale=(
                    "Transaction ID wraparound causes PostgreSQL to refuse ALL writes "
                    "until the situation is resolved. This is a database emergency."
                ),
                evidence={"xid_age": age, "pct_to_limit": round(pct, 3)},
                tags=["xid", "wraparound", "emergency"],
            ))
            result.passed = False

        return result


class AutovacuumLoggingCheck(AdvisorCheck):
    """Check if autovacuum logging is enabled."""

    name = "postgres_autovacuum_logging"
    title = "Autovacuum Logging"
    description = "Verify log_autovacuum_min_duration is set for monitoring"
    category = AdvisorCategory.VACUUM
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW log_autovacuum_min_duration")
        try:
            ms = int(val)
        except (ValueError, TypeError):
            ms = -1

        if ms == -1:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title="Autovacuum logging is disabled",
                description=(
                    "log_autovacuum_min_duration = -1. Autovacuum runs are not logged, "
                    "making it impossible to diagnose vacuum performance issues."
                ),
                recommendation="Set to 1000ms to log slow autovacuum runs.",
                fix_sql="ALTER SYSTEM SET log_autovacuum_min_duration = 1000;",
                rationale="Without logging, you can't tell if autovacuum is keeping up with dead tuples.",
                tags=["autovacuum", "logging", "monitoring"],
            ))
            result.passed = False
        elif ms == 0:
            result.findings.append(Finding(
                severity=CheckSeverity.NOTICE,
                title="ALL autovacuum runs are being logged",
                description="log_autovacuum_min_duration = 0 logs every autovacuum event.",
                recommendation="Consider setting to 1000-5000ms for less log noise.",
                tags=["autovacuum", "logging"],
            ))

        return result


class AutovacuumScaleFactorCheck(AdvisorCheck):
    """Check autovacuum_vacuum_scale_factor for large tables."""

    name = "postgres_autovacuum_scale_factor"
    title = "Autovacuum Scale Factor"
    description = "Detect when default scale factor is too aggressive for large tables"
    category = AdvisorCategory.VACUUM
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        # Check global setting
        val = await conn.fetchval("SHOW autovacuum_vacuum_scale_factor")
        try:
            scale = float(val)
        except (ValueError, TypeError):
            return result

        # Find large tables where 20% scale factor means millions of dead tuples
        rows = await conn.fetch(
            "SELECT relname, n_live_tup, pg_size_pretty(pg_relation_size(relid)) "
            "FROM pg_stat_user_tables "
            "WHERE n_live_tup > 1000000 "
            "ORDER BY n_live_tup DESC LIMIT 5"
        )

        for row in rows:
            if isinstance(row, (list, tuple)):
                table, live_tup, size = row[:3]
            else:
                table = getattr(row, "relname", "")
                live_tup = getattr(row, "n_live_tup", 0)
                size = getattr(row, "pg_size_pretty", "")

            live = int(live_tup or 0)
            trigger_threshold = int(live * scale)

            if trigger_threshold > 200000:
                result.findings.append(Finding(
                    severity=CheckSeverity.WARNING,
                    title=f"Large table '{table}': autovacuum triggers at {trigger_threshold:,} dead tuples",
                    description=(
                        f"Table '{table}' has {live:,} rows (size: {size}). "
                        f"With scale_factor={scale}, autovacuum waits for {trigger_threshold:,} "
                        f"dead tuples before running — this allows significant bloat."
                    ),
                    recommendation=(
                        f"Set per-table threshold: ALTER TABLE {table} SET "
                        f"(autovacuum_vacuum_scale_factor = 0.01, autovacuum_vacuum_threshold = 1000);"
                    ),
                    fix_sql=(
                        f"ALTER TABLE {table} SET ("
                        f"autovacuum_vacuum_scale_factor = 0.01, "
                        f"autovacuum_vacuum_threshold = 1000);"
                    ),
                    evidence={"live_tuples": live, "scale_factor": scale, "threshold": trigger_threshold},
                    tags=["autovacuum", "tuning", "bloat"],
                ))
                result.passed = False

        return result


class LongRunningVacuumCheck(AdvisorCheck):
    """Detect long-running vacuum processes."""

    name = "postgres_long_running_vacuum"
    title = "Long-Running VACUUM Detection"
    description = "Find vacuum processes running for extended periods"
    category = AdvisorCategory.VACUUM
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT pid, relid::regclass AS table_name, phase, "
                "  heap_blks_total, heap_blks_scanned, heap_blks_vacuumed, "
                "  EXTRACT(EPOCH FROM (now() - query_start))::int AS runtime_seconds "
                "FROM pg_stat_progress_vacuum v "
                "JOIN pg_stat_activity a USING (pid) "
                "WHERE EXTRACT(EPOCH FROM (now() - query_start)) > 300 "
                "ORDER BY query_start"
            )
        except Exception:
            return result

        for row in rows:
            if isinstance(row, (list, tuple)):
                pid, table, phase, total, scanned, vacuumed, runtime = row[:7]
            else:
                pid = getattr(row, "pid", 0)
                table = getattr(row, "table_name", "")
                phase = getattr(row, "phase", "")
                total = getattr(row, "heap_blks_total", 0)
                scanned = getattr(row, "heap_blks_scanned", 0)
                vacuumed = getattr(row, "heap_blks_vacuumed", 0)
                runtime = getattr(row, "runtime_seconds", 0)

            rt = int(runtime or 0)
            pct = float(scanned or 0) / max(1, float(total or 1)) * 100

            sev = CheckSeverity.CRITICAL if rt > 3600 else CheckSeverity.WARNING

            result.findings.append(Finding(
                severity=sev,
                title=f"VACUUM on {table} running for {rt // 60}m ({pct:.0f}% done)",
                description=f"PID {pid}, phase: {phase}, {pct:.0f}% scanned.",
                recommendation="Monitor progress. If stuck, check for lock contention.",
                evidence={"pid": int(pid or 0), "runtime_seconds": rt, "progress_pct": round(pct, 1)},
                tags=["vacuum", "long-running"],
            ))
            result.passed = False

        return result


def get_vacuum_checks() -> list[AdvisorCheck]:
    """Return all vacuum advisor checks."""
    return [
        TableBloatCheck(),
        XIDWraparoundCheck(),
        AutovacuumLoggingCheck(),
        AutovacuumScaleFactorCheck(),
        LongRunningVacuumCheck(),
    ]
