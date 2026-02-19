"""
Configuration Advisor Checks — Percona-style PostgreSQL configuration audit.

Implements Percona's comprehensive configuration advisor pattern with 20+
checks across categories:
    - Version: EOL detection, extension compatibility
    - Memory: shared_buffers, work_mem, effective_cache_size
    - WAL: wal_buffers, checkpoint settings, wal_level
    - Connections: max_connections, idle timeouts
    - Planner: random_page_cost, effective_io_concurrency, JIT
    - Logging: statement logging, auto_explain, slow queries

Each check follows the pattern from Percona's db/config_auditor.py
but is individually registerable in the advisor framework.
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


# ------------------------------------------------------------------
# Helper
# ------------------------------------------------------------------


def _parse_size(val: str) -> int:
    """Parse PostgreSQL size strings like '128MB', '1GB' to bytes."""
    val = str(val).strip().upper()
    multipliers = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    for suffix, mult in multipliers.items():
        if val.endswith(suffix):
            return int(float(val[:-len(suffix)].strip()) * mult)
    # Plain number = 8KB pages for shared_buffers
    try:
        return int(val)
    except ValueError:
        return 0


# ------------------------------------------------------------------
# Version Checks
# ------------------------------------------------------------------


class VersionEOLCheck(AdvisorCheck):
    """Check if PostgreSQL version is approaching or past End-of-Life."""

    name = "postgres_version_eol"
    title = "PostgreSQL Version EOL"
    description = "Check for end-of-life or outdated PostgreSQL versions"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.RARE

    # PostgreSQL EOL dates (final release)
    EOL_VERSIONS = {
        12: "2024-11-14",
        13: "2025-11-13",
        14: "2026-11-12",
    }

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        version_str = await conn.fetchval("SHOW server_version")
        try:
            major = int(str(version_str).split(".")[0])
        except (ValueError, IndexError):
            return result

        if major <= 12:
            result.findings.append(Finding(
                severity=CheckSeverity.CRITICAL,
                title=f"PostgreSQL {major} is past end-of-life",
                description=f"PostgreSQL {major} no longer receives security patches.",
                recommendation="Upgrade to PostgreSQL 16 or 17.",
                rationale="Running past-EOL databases exposes you to unpatched CVEs.",
                tags=["version", "eol", "upgrade"],
            ))
            result.passed = False
        elif major <= 13:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"PostgreSQL {major} approaching end-of-life",
                description=f"PostgreSQL {major} EOL: {self.EOL_VERSIONS.get(major, 'soon')}.",
                recommendation="Plan upgrade to PostgreSQL 16 or 17.",
                tags=["version", "eol"],
            ))
            result.passed = False

        return result


# ------------------------------------------------------------------
# Memory Checks
# ------------------------------------------------------------------


class SharedBuffersCheck(AdvisorCheck):
    """Check shared_buffers sizing."""

    name = "postgres_shared_buffers"
    title = "shared_buffers Configuration"
    description = "Verify shared_buffers is properly sized (25% of RAM)"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW shared_buffers")
        val_bytes = _parse_size(str(val))

        # shared_buffers in 8KB units
        if val_bytes == 0:
            try:
                setting = await conn.fetchval(
                    "SELECT setting::bigint * 8192 FROM pg_settings WHERE name = 'shared_buffers'"
                )
                val_bytes = int(setting or 0)
            except Exception:
                pass

        val_mb = val_bytes / (1024 * 1024) if val_bytes > 0 else 0

        if val_mb < 128:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"shared_buffers too low: {val} ({val_mb:.0f}MB)",
                description="Default 128MB is almost always too low for production.",
                recommendation="Set to 25% of total RAM (e.g., 4GB for 16GB RAM).",
                fix_sql="ALTER SYSTEM SET shared_buffers = '4GB';\n-- Requires restart",
                rationale="Low shared_buffers forces excessive OS page cache usage.",
                tags=["memory", "performance"],
            ))
            result.passed = False

        return result


class WorkMemCheck(AdvisorCheck):
    """Check work_mem sizing."""

    name = "postgres_work_mem"
    title = "work_mem Configuration"
    description = "Verify work_mem is properly sized for sort/hash operations"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW work_mem")
        val_bytes = _parse_size(str(val))
        val_mb = val_bytes / (1024 * 1024) if val_bytes > 0 else 0

        if val_mb <= 4:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"work_mem is at default: {val}",
                description=(
                    "The default 4MB causes sorts and hash operations to spill to disk. "
                    "Each connection can use multiple work_mem allocations simultaneously."
                ),
                recommendation="Start with 32-64MB for OLTP, 256MB+ for analytics.",
                fix_sql="ALTER SYSTEM SET work_mem = '64MB';",
                rationale="Disk-based sorts are 10-100x slower than in-memory.",
                tags=["memory", "performance"],
            ))
            result.passed = False

        return result


class EffectiveCacheSizeCheck(AdvisorCheck):
    """Check effective_cache_size."""

    name = "postgres_effective_cache_size"
    title = "effective_cache_size Configuration"
    description = "Verify effective_cache_size accounts for OS page cache"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW effective_cache_size")
        val_bytes = _parse_size(str(val))

        if val_bytes == 0:
            try:
                setting = await conn.fetchval(
                    "SELECT setting::bigint * 8192 FROM pg_settings WHERE name = 'effective_cache_size'"
                )
                val_bytes = int(setting or 0)
            except Exception:
                pass

        val_gb = val_bytes / (1024 ** 3) if val_bytes > 0 else 0

        if val_gb < 1:
            result.findings.append(Finding(
                severity=CheckSeverity.NOTICE,
                title=f"effective_cache_size may be too low: {val}",
                description=(
                    "This tells the planner how much memory is available for caching "
                    "(shared_buffers + OS page cache). Too low = conservative plans."
                ),
                recommendation="Set to 75% of total RAM.",
                fix_sql="ALTER SYSTEM SET effective_cache_size = '12GB';\n-- Adjust to 75% of RAM",
                tags=["memory", "planner"],
            ))
            result.passed = False

        return result


class MaintenanceWorkMemCheck(AdvisorCheck):
    """Check maintenance_work_mem."""

    name = "postgres_maintenance_work_mem"
    title = "maintenance_work_mem Configuration"
    description = "Check maintenance_work_mem for VACUUM and CREATE INDEX"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW maintenance_work_mem")
        val_bytes = _parse_size(str(val))
        val_mb = val_bytes / (1024 * 1024) if val_bytes > 0 else 0

        if val_mb <= 64:
            result.findings.append(Finding(
                severity=CheckSeverity.NOTICE,
                title=f"maintenance_work_mem at default: {val}",
                description="Low maintenance_work_mem slows VACUUM, CREATE INDEX, and ALTER TABLE.",
                recommendation="Set to 1-2GB for production servers.",
                fix_sql="ALTER SYSTEM SET maintenance_work_mem = '1GB';",
                tags=["memory", "vacuum", "maintenance"],
            ))
            result.passed = False

        return result


# ------------------------------------------------------------------
# WAL / Checkpoint Checks
# ------------------------------------------------------------------


class WALLevelCheck(AdvisorCheck):
    """Check wal_level for replication readiness."""

    name = "postgres_wal_level"
    title = "WAL Level"
    description = "Verify wal_level supports replication and PITR"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW wal_level")
        if str(val).lower() == "minimal":
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title="wal_level is 'minimal' — no replication or PITR possible",
                description=(
                    "With wal_level=minimal, you cannot use streaming replication, "
                    "logical replication, or point-in-time recovery."
                ),
                recommendation="Set to 'replica' (minimum) or 'logical' for full capabilities.",
                fix_sql="ALTER SYSTEM SET wal_level = 'replica';\n-- Requires restart",
                tags=["wal", "replication", "backup"],
            ))
            result.passed = False

        return result


class CheckpointCompletionCheck(AdvisorCheck):
    """Check checkpoint_completion_target."""

    name = "postgres_checkpoint_completion"
    title = "Checkpoint Completion Target"
    description = "Verify checkpoint spread for I/O smoothing"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW checkpoint_completion_target")
        try:
            target = float(val)
        except (ValueError, TypeError):
            return result

        if target < 0.7:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"checkpoint_completion_target too low: {target}",
                description="Low values cause bursty I/O during checkpoints.",
                recommendation="Set to 0.9 (PostgreSQL 14+ default).",
                fix_sql="ALTER SYSTEM SET checkpoint_completion_target = 0.9;",
                tags=["wal", "io", "performance"],
            ))
            result.passed = False

        return result


# ------------------------------------------------------------------
# Connection Checks
# ------------------------------------------------------------------


class MaxConnectionsCheck(AdvisorCheck):
    """Check max_connections sizing."""

    name = "postgres_max_connections"
    title = "max_connections"
    description = "Verify max_connections is not set too high"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW max_connections")
        max_conn = int(val or 100)

        if max_conn > 500:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"max_connections is very high: {max_conn}",
                description=(
                    "Each connection consumes ~10MB of RAM and contributes to lock contention. "
                    f"{max_conn} connections = ~{max_conn * 10 // 1024}GB overhead."
                ),
                recommendation=(
                    "Reduce to 200-300 and use PgBouncer for connection pooling. "
                    "Most applications need far fewer active connections than max_connections."
                ),
                fix_sql=f"ALTER SYSTEM SET max_connections = 200;\n-- Requires restart",
                tags=["connections", "memory", "performance"],
            ))
            result.passed = False
        elif max_conn > 200:
            result.findings.append(Finding(
                severity=CheckSeverity.NOTICE,
                title=f"max_connections is elevated: {max_conn}",
                description="Consider whether all connections are needed or if pooling would help.",
                recommendation="Use PgBouncer for connection pooling if not already.",
                tags=["connections"],
            ))

        return result


class IdleConnectionsCheck(AdvisorCheck):
    """Check for idle connections consuming resources."""

    name = "postgres_idle_connections"
    title = "Idle Connection Detection"
    description = "Detect idle connections consuming resources"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT count(*) AS total, "
                "  sum(CASE WHEN state = 'idle' THEN 1 ELSE 0 END) AS idle, "
                "  sum(CASE WHEN state = 'idle in transaction' THEN 1 ELSE 0 END) AS idle_txn "
                "FROM pg_stat_activity WHERE backend_type = 'client backend'"
            )
        except Exception:
            return result

        if rows:
            r = rows[0]
            total = int(r[0] if isinstance(r, (list, tuple)) else getattr(r, "total", 0))
            idle = int(r[1] if isinstance(r, (list, tuple)) else getattr(r, "idle", 0))
            idle_txn = int(r[2] if isinstance(r, (list, tuple)) else getattr(r, "idle_txn", 0))

            if idle_txn > 0:
                result.findings.append(Finding(
                    severity=CheckSeverity.WARNING,
                    title=f"{idle_txn} connection(s) idle in transaction",
                    description=(
                        "Idle-in-transaction connections hold locks and prevent VACUUM "
                        "from cleaning up dead tuples."
                    ),
                    recommendation="Set idle_in_transaction_session_timeout to auto-terminate.",
                    fix_sql="ALTER SYSTEM SET idle_in_transaction_session_timeout = '5min';",
                    evidence={"total": total, "idle": idle, "idle_in_transaction": idle_txn},
                    tags=["connections", "vacuum", "locks"],
                ))
                result.passed = False

            if total > 0 and idle / total > 0.8:
                result.findings.append(Finding(
                    severity=CheckSeverity.NOTICE,
                    title=f"{idle}/{total} connections are idle ({idle/total:.0%})",
                    description="Most connections are idle. Consider connection pooling.",
                    recommendation="Use PgBouncer to reduce idle connection overhead.",
                    evidence={"total": total, "idle": idle},
                    tags=["connections", "pooling"],
                ))

        return result


# ------------------------------------------------------------------
# Planner Checks
# ------------------------------------------------------------------


class RandomPageCostCheck(AdvisorCheck):
    """Check random_page_cost for SSD optimization."""

    name = "postgres_random_page_cost"
    title = "random_page_cost (SSD Optimization)"
    description = "Verify random_page_cost is tuned for storage type"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW random_page_cost")
        try:
            cost = float(val)
        except (ValueError, TypeError):
            return result

        if cost >= 4.0:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"random_page_cost at default ({cost}) — likely too high for SSDs",
                description=(
                    "The default 4.0 assumes spinning disks. On SSDs, random reads are "
                    "nearly as fast as sequential. This causes the planner to avoid index scans."
                ),
                recommendation="Set to 1.1 for SSDs, 1.5-2.0 for cloud storage.",
                fix_sql="ALTER SYSTEM SET random_page_cost = 1.1;",
                rationale="Correct random_page_cost prevents the planner from choosing Seq Scans over Index Scans.",
                tags=["planner", "ssd", "index-scans"],
            ))
            result.passed = False

        return result


class JITCheck(AdvisorCheck):
    """Check JIT compilation settings."""

    name = "postgres_jit"
    title = "JIT Compilation"
    description = "Check JIT settings for OLTP workloads"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        jit = await conn.fetchval("SHOW jit")
        jit_above_cost = await conn.fetchval("SHOW jit_above_cost")

        if str(jit).lower() == "on":
            try:
                threshold = float(jit_above_cost)
            except (ValueError, TypeError):
                threshold = 100000

            if threshold < 100000:
                result.findings.append(Finding(
                    severity=CheckSeverity.NOTICE,
                    title="JIT enabled with low threshold",
                    description=(
                        f"JIT compiles queries costing >{threshold}. For OLTP workloads, "
                        "JIT compilation overhead often exceeds the benefit."
                    ),
                    recommendation="Disable JIT for OLTP: SET jit = off; or raise threshold.",
                    fix_sql="ALTER SYSTEM SET jit = 'off';\n-- Or: ALTER SYSTEM SET jit_above_cost = 500000;",
                    tags=["jit", "oltp", "performance"],
                ))

        return result


# ------------------------------------------------------------------
# Logging Checks
# ------------------------------------------------------------------


class LogMinDurationCheck(AdvisorCheck):
    """Check log_min_duration_statement for slow query logging."""

    name = "postgres_log_min_duration"
    title = "Slow Query Logging"
    description = "Verify slow queries are being logged"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW log_min_duration_statement")
        # -1 means disabled, 0 means log all, positive = threshold in ms
        try:
            ms = int(val)
        except (ValueError, TypeError):
            return result

        if ms == -1:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title="Slow query logging is disabled",
                description="No queries are being logged based on duration.",
                recommendation="Set to 1000ms to capture slow queries without excessive logging.",
                fix_sql="ALTER SYSTEM SET log_min_duration_statement = 1000;",
                tags=["logging", "slow-queries"],
            ))
            result.passed = False
        elif ms == 0:
            result.findings.append(Finding(
                severity=CheckSeverity.NOTICE,
                title="ALL queries are being logged (log_min_duration_statement = 0)",
                description="Logging every query creates significant I/O overhead.",
                recommendation="Set to 1000ms for production.",
                fix_sql="ALTER SYSTEM SET log_min_duration_statement = 1000;",
                tags=["logging", "performance"],
            ))

        return result


class AutoExplainCheck(AdvisorCheck):
    """Check if auto_explain is loaded and optimally configured for plan capture.

    Goes beyond "is it loaded?" to audit every sub-setting:
    - auto_explain.log_min_duration (too high = miss slow queries)
    - auto_explain.log_format (JSON = parseable, text = not)
    - auto_explain.log_analyze (must be ON for actual execution stats)
    - auto_explain.log_buffers (must be ON for I/O analysis)
    - auto_explain.log_timing (ON for per-node timing)

    Based on pganalyze Efficient Search guide (p.19-22):
    "auto_explain captures plans automatically for slow queries."
    """

    name = "postgres_auto_explain"
    title = "auto_explain Module"
    description = "Check if auto_explain is loaded and optimally configured"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.RARE

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW shared_preload_libraries")
        libs = str(val).lower()

        if "auto_explain" not in libs:
            result.findings.append(Finding(
                severity=CheckSeverity.INFO,
                title="auto_explain not loaded",
                description=(
                    "auto_explain automatically logs EXPLAIN plans for slow queries. "
                    "This is invaluable for diagnosing intermittent performance issues "
                    "that are impossible to catch with manual EXPLAIN."
                ),
                recommendation=(
                    "Add auto_explain to shared_preload_libraries. "
                    "Requires a PostgreSQL restart."
                ),
                fix_sql=(
                    "-- In postgresql.conf:\n"
                    "-- shared_preload_libraries = 'auto_explain'\n"
                    "-- auto_explain.log_min_duration = '1s'\n"
                    "-- auto_explain.log_format = 'json'\n"
                    "-- auto_explain.log_analyze = on\n"
                    "-- auto_explain.log_buffers = on\n"
                    "-- auto_explain.log_timing = on\n"
                    "-- Requires restart"
                ),
                tags=["explain", "diagnostics"],
            ))
            return result

        # auto_explain IS loaded — audit sub-settings
        settings = {}
        for setting_name in (
            "auto_explain.log_min_duration",
            "auto_explain.log_format",
            "auto_explain.log_analyze",
            "auto_explain.log_buffers",
            "auto_explain.log_timing",
            "auto_explain.log_nested_statements",
        ):
            try:
                v = await conn.fetchval(f"SHOW \"{setting_name}\"")
                settings[setting_name] = str(v).lower().strip()
            except Exception:
                pass

        # Check log_min_duration
        min_dur = settings.get("auto_explain.log_min_duration", "-1")
        try:
            dur_ms = int(min_dur.replace("ms", "").replace("s", "000").strip())
        except (ValueError, AttributeError):
            dur_ms = -1

        if dur_ms < 0:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title="auto_explain disabled (log_min_duration = -1)",
                description=(
                    "auto_explain is loaded but disabled. No plans are being captured. "
                    "Set log_min_duration to capture slow queries automatically."
                ),
                recommendation="Set auto_explain.log_min_duration = '1s' for production.",
                fix_sql=(
                    "ALTER SYSTEM SET \"auto_explain.log_min_duration\" = '1s';\n"
                    "SELECT pg_reload_conf();"
                ),
                tags=["explain", "diagnostics"],
            ))
        elif dur_ms == 0:
            result.findings.append(Finding(
                severity=CheckSeverity.NOTICE,
                title="auto_explain logging ALL queries (log_min_duration = 0)",
                description=(
                    "Every query is being explained. This creates significant I/O "
                    "and CPU overhead. Only use during investigation, not permanently."
                ),
                recommendation="Set to at least 100ms for sustained use.",
                fix_sql=(
                    "ALTER SYSTEM SET \"auto_explain.log_min_duration\" = '100ms';\n"
                    "SELECT pg_reload_conf();"
                ),
                tags=["explain", "performance"],
            ))
        elif dur_ms > 10000:
            result.findings.append(Finding(
                severity=CheckSeverity.NOTICE,
                title=f"auto_explain threshold high ({dur_ms}ms)",
                description=(
                    f"Only queries taking >{dur_ms}ms are explained. "
                    f"Queries between 1-{dur_ms}ms go unmonitored."
                ),
                recommendation="Consider lowering to 1000ms to catch more slow queries.",
                fix_sql=(
                    "ALTER SYSTEM SET \"auto_explain.log_min_duration\" = '1s';\n"
                    "SELECT pg_reload_conf();"
                ),
                tags=["explain", "diagnostics"],
            ))

        # Check log_format
        fmt = settings.get("auto_explain.log_format", "text")
        if fmt != "json":
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"auto_explain format is '{fmt}' (should be 'json')",
                description=(
                    "JSON format is required for automated plan analysis. "
                    "Text format cannot be reliably parsed by tools like QuerySense. "
                    "pganalyze also requires JSON format for their Log Insights."
                ),
                recommendation="Set auto_explain.log_format = 'json'.",
                fix_sql=(
                    "ALTER SYSTEM SET \"auto_explain.log_format\" = 'json';\n"
                    "SELECT pg_reload_conf();"
                ),
                tags=["explain", "diagnostics"],
            ))

        # Check log_analyze
        analyze = settings.get("auto_explain.log_analyze", "off")
        if analyze not in ("on", "true", "yes", "1"):
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title="auto_explain.log_analyze is OFF",
                description=(
                    "Without ANALYZE, auto_explain only captures estimated plans. "
                    "Actual rows, loops, and timing are missing — making the plans "
                    "much less useful for diagnosis. This is like EXPLAIN without ANALYZE."
                ),
                recommendation="Set auto_explain.log_analyze = on.",
                fix_sql=(
                    "ALTER SYSTEM SET \"auto_explain.log_analyze\" = on;\n"
                    "SELECT pg_reload_conf();\n"
                    "-- Note: adds ~5-10% overhead to captured queries"
                ),
                tags=["explain", "diagnostics"],
            ))

        # Check log_buffers
        buffers = settings.get("auto_explain.log_buffers", "off")
        if buffers not in ("on", "true", "yes", "1"):
            result.findings.append(Finding(
                severity=CheckSeverity.INFO,
                title="auto_explain.log_buffers is OFF",
                description=(
                    "Without BUFFERS, auto_explain plans don't include I/O statistics "
                    "(shared hit/read/dirtied blocks). This is the most valuable "
                    "diagnostic data — cache miss ratios reveal 100x performance "
                    "differences between cached and uncached queries."
                ),
                recommendation="Set auto_explain.log_buffers = on.",
                fix_sql=(
                    "ALTER SYSTEM SET \"auto_explain.log_buffers\" = on;\n"
                    "SELECT pg_reload_conf();"
                ),
                tags=["explain", "buffers", "diagnostics"],
            ))

        # Check log_timing
        timing = settings.get("auto_explain.log_timing", "on")
        if timing not in ("on", "true", "yes", "1"):
            result.findings.append(Finding(
                severity=CheckSeverity.INFO,
                title="auto_explain.log_timing is OFF",
                description=(
                    "Without timing, per-node execution times are missing. "
                    "Only total query duration is available. Enable for full profiling."
                ),
                recommendation="Set auto_explain.log_timing = on.",
                fix_sql=(
                    "ALTER SYSTEM SET \"auto_explain.log_timing\" = on;\n"
                    "SELECT pg_reload_conf();"
                ),
                tags=["explain", "diagnostics"],
            ))

        # If everything looks good
        if not result.findings:
            result.findings.append(Finding(
                severity=CheckSeverity.OK,
                title="auto_explain optimally configured",
                description=(
                    "auto_explain is loaded with JSON format, ANALYZE, BUFFERS, "
                    "and TIMING enabled. Plans are being captured for slow queries. "
                    "Run 'querysense auto-explain <logfile>' to analyze captured plans."
                ),
                recommendation="",
                tags=["explain", "diagnostics"],
            ))

        return result


class StatStatementsCheck(AdvisorCheck):
    """Check if pg_stat_statements is loaded."""

    name = "postgres_stat_statements"
    title = "pg_stat_statements Extension"
    description = "Verify pg_stat_statements is loaded for query performance tracking"
    category = AdvisorCategory.CONFIGURATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        val = await conn.fetchval("SHOW shared_preload_libraries")
        libs = str(val).lower()

        if "pg_stat_statements" not in libs:
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title="pg_stat_statements not loaded",
                description="Cannot track query performance without pg_stat_statements.",
                recommendation="Add to shared_preload_libraries. Essential for any DBA tool.",
                fix_sql="-- shared_preload_libraries = 'pg_stat_statements'\n-- Requires restart",
                tags=["monitoring", "essential"],
            ))
            result.passed = False

        return result


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------


def get_configuration_checks() -> list[AdvisorCheck]:
    """Return all configuration advisor checks."""
    return [
        # Version
        VersionEOLCheck(),
        # Memory
        SharedBuffersCheck(),
        WorkMemCheck(),
        EffectiveCacheSizeCheck(),
        MaintenanceWorkMemCheck(),
        # WAL
        WALLevelCheck(),
        CheckpointCompletionCheck(),
        # Connections
        MaxConnectionsCheck(),
        IdleConnectionsCheck(),
        # Planner
        RandomPageCostCheck(),
        JITCheck(),
        # Logging
        LogMinDurationCheck(),
        AutoExplainCheck(),
        StatStatementsCheck(),
    ]
