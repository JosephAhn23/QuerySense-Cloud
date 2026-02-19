"""
PostgreSQL Configuration Auditor.

Connects to a PostgreSQL instance and audits pg_settings against
best-practice recommendations from:
- PostgreSQL Query Optimization (Dombrovskaya et al. 2024), Ch. 10
- PostgreSQL documentation
- Real-world production experience

Checks:
- Memory settings (shared_buffers, work_mem, effective_cache_size)
- WAL/checkpoint settings (wal_buffers, checkpoint_completion_target)
- Planner settings (random_page_cost, effective_io_concurrency)
- Autovacuum tuning
- Connection settings (max_connections, idle timeouts)
- Logging settings (log_min_duration_statement, auto_explain)
- Parallel query settings

Usage:
    from querysense.db.config_auditor import audit_config

    report = await audit_config(conn)
    for issue in report.issues:
        print(f"[{issue.severity}] {issue.parameter}: {issue.message}")
        print(f"  Current: {issue.current_value}")
        print(f"  Recommended: {issue.recommended}")
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass(frozen=True)
class ConfigIssue:
    """A single configuration issue found during audit."""
    parameter: str
    severity: str          # critical / warning / info
    category: str          # memory / wal / planner / autovacuum / connections / logging / parallel
    current_value: str
    recommended: str
    message: str
    rationale: str = ""
    fix_sql: str = ""      # ALTER SYSTEM SET ...


@dataclass
class SystemInfo:
    """System information collected from PostgreSQL."""
    version: str = ""
    version_num: int = 0
    total_ram_bytes: int = 0     # from shared_buffers context
    max_connections: int = 100
    data_directory: str = ""
    is_primary: bool = True


@dataclass
class ConfigAuditReport:
    """Full configuration audit report."""
    system_info: SystemInfo = field(default_factory=SystemInfo)
    settings: dict[str, Any] = field(default_factory=dict)
    issues: list[ConfigIssue] = field(default_factory=list)
    score: int = 100  # Start at 100, deduct for issues

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")

    @property
    def info_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "info")

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "system": {
                "version": self.system_info.version,
                "max_connections": self.system_info.max_connections,
                "is_primary": self.system_info.is_primary,
            },
            "summary": {
                "critical": self.critical_count,
                "warning": self.warning_count,
                "info": self.info_count,
                "total_issues": len(self.issues),
            },
            "issues": [
                {
                    "parameter": i.parameter,
                    "severity": i.severity,
                    "category": i.category,
                    "current_value": i.current_value,
                    "recommended": i.recommended,
                    "message": i.message,
                    "rationale": i.rationale,
                    "fix_sql": i.fix_sql,
                }
                for i in self.issues
            ],
        }


def _parse_memory_setting(value: str) -> int:
    """Parse a PostgreSQL memory setting to bytes."""
    value = value.strip().lower()
    multipliers = {
        "kb": 1024,
        "mb": 1024 ** 2,
        "gb": 1024 ** 3,
        "tb": 1024 ** 4,
    }
    for suffix, mult in multipliers.items():
        if value.endswith(suffix):
            return int(float(value[: -len(suffix)]) * mult)
    # Might be in 8kB pages (shared_buffers default unit)
    try:
        return int(value) * 8192  # default PostgreSQL block size
    except ValueError:
        return 0


def _format_bytes(b: int) -> str:
    """Format bytes to human-readable."""
    if b >= 1024 ** 3:
        return f"{b / (1024 ** 3):.1f}GB"
    if b >= 1024 ** 2:
        return f"{b / (1024 ** 2):.0f}MB"
    if b >= 1024:
        return f"{b / 1024:.0f}kB"
    return f"{b}B"


async def audit_config(conn: AsyncDBConnection) -> ConfigAuditReport:
    """
    Audit PostgreSQL configuration against best practices.

    Reads pg_settings and cross-references with workload heuristics
    to identify suboptimal configuration.

    Args:
        conn: Async database connection

    Returns:
        ConfigAuditReport with all issues found
    """
    report = ConfigAuditReport()

    # Collect system info
    version_row = await conn.fetchrow("SELECT version(), current_setting('server_version_num')::int")
    report.system_info.version = str(version_row[0]) if version_row else ""
    report.system_info.version_num = int(version_row[1]) if version_row else 0

    # Collect all relevant settings
    rows = await conn.fetch(
        "SELECT name, setting, unit, category, short_desc, context, boot_val "
        "FROM pg_settings "
        "WHERE name IN ("
        "  'shared_buffers', 'work_mem', 'maintenance_work_mem', "
        "  'effective_cache_size', 'wal_buffers', 'checkpoint_completion_target', "
        "  'max_wal_size', 'min_wal_size', 'random_page_cost', "
        "  'effective_io_concurrency', 'max_connections', "
        "  'max_parallel_workers_per_gather', 'max_parallel_workers', "
        "  'max_parallel_maintenance_workers', 'max_worker_processes', "
        "  'autovacuum', 'autovacuum_max_workers', 'autovacuum_naptime', "
        "  'autovacuum_vacuum_cost_delay', 'autovacuum_vacuum_cost_limit', "
        "  'autovacuum_vacuum_scale_factor', 'autovacuum_analyze_scale_factor', "
        "  'log_min_duration_statement', 'log_checkpoints', "
        "  'log_lock_waits', 'log_temp_files', "
        "  'track_io_timing', 'track_activity_query_size', "
        "  'default_statistics_target', 'jit', "
        "  'huge_pages', 'temp_buffers', 'idle_in_transaction_session_timeout', "
        "  'statement_timeout', 'lock_timeout'"
        ")"
    )

    settings: dict[str, dict[str, Any]] = {}
    for row in rows:
        settings[row[0]] = {
            "value": row[1],
            "unit": row[2],
            "category": row[3],
            "desc": row[4],
            "context": row[5],
            "boot_val": row[6],
        }
    report.settings = settings

    max_conn = int(settings.get("max_connections", {}).get("value", 100))
    report.system_info.max_connections = max_conn

    issues = report.issues

    # ── Memory Settings ──────────────────────────────────────────────

    # shared_buffers
    sb = settings.get("shared_buffers", {})
    if sb:
        sb_bytes = _parse_memory_setting(sb["value"])
        sb_display = _format_bytes(sb_bytes)

        if sb_bytes <= 128 * 1024 * 1024:  # <= 128MB (default)
            issues.append(ConfigIssue(
                parameter="shared_buffers",
                severity="critical",
                category="memory",
                current_value=sb_display,
                recommended="25% of total RAM (e.g., 4GB for 16GB system)",
                message="shared_buffers is at default (128MB). This is severely undersized for production.",
                rationale=(
                    "shared_buffers controls PostgreSQL's buffer cache. The default 128MB "
                    "means most data reads go to the OS page cache, adding overhead. "
                    "Set to ~25% of total RAM for optimal performance."
                ),
                fix_sql="ALTER SYSTEM SET shared_buffers = '4GB';  -- Adjust for your RAM",
            ))

    # work_mem
    wm = settings.get("work_mem", {})
    if wm:
        wm_bytes = _parse_memory_setting(wm["value"])
        wm_display = _format_bytes(wm_bytes)

        if wm_bytes <= 4 * 1024 * 1024:  # <= 4MB (default)
            issues.append(ConfigIssue(
                parameter="work_mem",
                severity="warning",
                category="memory",
                current_value=wm_display,
                recommended="32MB-256MB (depends on max_connections and query complexity)",
                message="work_mem is at or near default (4MB). Sort/hash operations may spill to disk.",
                rationale=(
                    "work_mem controls memory for sorts and hash joins PER OPERATION. "
                    "Complex queries may use multiple work_mem allocations. "
                    "Total memory risk: max_connections * work_mem * operations_per_query. "
                    f"With {max_conn} connections, 64MB work_mem = up to {max_conn * 64}MB worst case."
                ),
                fix_sql="ALTER SYSTEM SET work_mem = '64MB';  -- Monitor temp file usage",
            ))
        elif wm_bytes > 512 * 1024 * 1024:  # > 512MB
            issues.append(ConfigIssue(
                parameter="work_mem",
                severity="warning",
                category="memory",
                current_value=wm_display,
                recommended="64MB-256MB for most workloads",
                message=f"work_mem is very high ({wm_display}). Risk of OOM with concurrent queries.",
                rationale=(
                    f"With {max_conn} connections, each using {wm_display} per sort operation, "
                    "concurrent complex queries could consume all available RAM."
                ),
            ))

    # maintenance_work_mem
    mwm = settings.get("maintenance_work_mem", {})
    if mwm:
        mwm_bytes = _parse_memory_setting(mwm["value"])
        mwm_display = _format_bytes(mwm_bytes)
        if mwm_bytes <= 64 * 1024 * 1024:  # <= 64MB (default)
            issues.append(ConfigIssue(
                parameter="maintenance_work_mem",
                severity="info",
                category="memory",
                current_value=mwm_display,
                recommended="512MB-2GB",
                message="maintenance_work_mem is low. VACUUM and CREATE INDEX will be slow.",
                rationale="Used for VACUUM, CREATE INDEX, ALTER TABLE ADD FOREIGN KEY. Higher values = faster maintenance.",
                fix_sql="ALTER SYSTEM SET maintenance_work_mem = '1GB';",
            ))

    # effective_cache_size
    ecs = settings.get("effective_cache_size", {})
    if ecs:
        ecs_bytes = _parse_memory_setting(ecs["value"])
        ecs_display = _format_bytes(ecs_bytes)
        if ecs_bytes <= 4 * 1024 ** 3:  # <= 4GB (default)
            issues.append(ConfigIssue(
                parameter="effective_cache_size",
                severity="warning",
                category="memory",
                current_value=ecs_display,
                recommended="75% of total RAM (e.g., 12GB for 16GB system)",
                message="effective_cache_size is at default (4GB). Planner underestimates cache availability.",
                rationale=(
                    "This tells the planner how much memory is available for disk caching "
                    "(shared_buffers + OS page cache). When set too low, the planner "
                    "avoids index scans because it assumes disk reads are expensive."
                ),
                fix_sql="ALTER SYSTEM SET effective_cache_size = '12GB';  -- 75% of RAM",
            ))

    # ── WAL/Checkpoint Settings ──────────────────────────────────────

    cct = settings.get("checkpoint_completion_target", {})
    if cct and float(cct.get("value", "0.9")) < 0.9:
        issues.append(ConfigIssue(
            parameter="checkpoint_completion_target",
            severity="warning",
            category="wal",
            current_value=cct["value"],
            recommended="0.9",
            message="checkpoint_completion_target should be 0.9 to spread checkpoint I/O.",
            fix_sql="ALTER SYSTEM SET checkpoint_completion_target = 0.9;",
        ))

    mws = settings.get("max_wal_size", {})
    if mws:
        mws_bytes = _parse_memory_setting(mws["value"])
        if mws_bytes < 2 * 1024 ** 3:  # < 2GB
            issues.append(ConfigIssue(
                parameter="max_wal_size",
                severity="info",
                category="wal",
                current_value=_format_bytes(mws_bytes),
                recommended="2GB-8GB for write-heavy workloads",
                message="max_wal_size is small. Frequent checkpoints increase I/O.",
                fix_sql="ALTER SYSTEM SET max_wal_size = '4GB';",
            ))

    # ── Planner Settings ─────────────────────────────────────────────

    rpc = settings.get("random_page_cost", {})
    if rpc:
        rpc_val = float(rpc.get("value", "4.0"))
        if rpc_val >= 4.0:
            issues.append(ConfigIssue(
                parameter="random_page_cost",
                severity="warning",
                category="planner",
                current_value=str(rpc_val),
                recommended="1.1-1.5 for SSD storage, 2.0 for fast SAN",
                message=(
                    "random_page_cost=4.0 (default) assumes spinning disks. "
                    "On SSDs, this makes the planner avoid index scans unnecessarily."
                ),
                rationale=(
                    "This is one of the most impactful settings on SSD-backed systems. "
                    "The default 4.0 was set for spinning disks where random I/O was 4x slower "
                    "than sequential. On SSDs, random and sequential are nearly equal."
                ),
                fix_sql="ALTER SYSTEM SET random_page_cost = 1.1;  -- For SSD storage",
            ))

    eio = settings.get("effective_io_concurrency", {})
    if eio:
        eio_val = int(eio.get("value", "1"))
        if eio_val <= 1:
            issues.append(ConfigIssue(
                parameter="effective_io_concurrency",
                severity="info",
                category="planner",
                current_value=str(eio_val),
                recommended="200 for SSD, 2-4 for HDD",
                message="effective_io_concurrency=1 (default). SSD storage can handle 200+ concurrent I/O.",
                fix_sql="ALTER SYSTEM SET effective_io_concurrency = 200;  -- For SSD",
            ))

    dst = settings.get("default_statistics_target", {})
    if dst:
        dst_val = int(dst.get("value", "100"))
        if dst_val <= 100:
            issues.append(ConfigIssue(
                parameter="default_statistics_target",
                severity="info",
                category="planner",
                current_value=str(dst_val),
                recommended="200-500 for tables with skewed data",
                message=(
                    "default_statistics_target=100 (default). Increase for better "
                    "row estimates on columns with non-uniform distribution."
                ),
                fix_sql="ALTER SYSTEM SET default_statistics_target = 200;",
            ))

    # ── Parallel Query Settings ──────────────────────────────────────

    mpwpg = settings.get("max_parallel_workers_per_gather", {})
    if mpwpg:
        mpwpg_val = int(mpwpg.get("value", "2"))
        if mpwpg_val == 0:
            issues.append(ConfigIssue(
                parameter="max_parallel_workers_per_gather",
                severity="warning",
                category="parallel",
                current_value="0 (disabled)",
                recommended="2-4",
                message="Parallel query is disabled. Large sequential scans can't use multiple cores.",
                rationale=(
                    "Parallel query can speed up large scans, aggregations, and joins by "
                    "distributing work across CPU cores. Disabling it leaves performance on the table."
                ),
                fix_sql="ALTER SYSTEM SET max_parallel_workers_per_gather = 4;",
            ))

    mpw = settings.get("max_parallel_workers", {})
    if mpw:
        mpw_val = int(mpw.get("value", "8"))
        if mpw_val < 4:
            issues.append(ConfigIssue(
                parameter="max_parallel_workers",
                severity="info",
                category="parallel",
                current_value=str(mpw_val),
                recommended="Number of CPU cores (or half for shared servers)",
                message=f"max_parallel_workers={mpw_val}. Consider increasing to match available cores.",
                fix_sql=f"ALTER SYSTEM SET max_parallel_workers = 8;  -- Adjust for your CPU count",
            ))

    # ── Connection Settings ──────────────────────────────────────────

    if max_conn > 200:
        issues.append(ConfigIssue(
            parameter="max_connections",
            severity="warning",
            category="connections",
            current_value=str(max_conn),
            recommended="100-200 (use connection pooling for more)",
            message=(
                f"max_connections={max_conn} is high. Each connection consumes ~10MB. "
                "Use PgBouncer or application-level pooling instead."
            ),
            rationale=(
                "High max_connections wastes memory (shared memory structures scale linearly) "
                "and can cause lock contention. Connection poolers are more efficient."
            ),
        ))

    iitst = settings.get("idle_in_transaction_session_timeout", {})
    if iitst:
        iitst_val = int(iitst.get("value", "0"))
        if iitst_val == 0:
            issues.append(ConfigIssue(
                parameter="idle_in_transaction_session_timeout",
                severity="warning",
                category="connections",
                current_value="0 (disabled)",
                recommended="30000-60000 (30-60 seconds)",
                message="No timeout for idle-in-transaction sessions. Leaked transactions can hold locks forever.",
                fix_sql="ALTER SYSTEM SET idle_in_transaction_session_timeout = '30s';",
            ))

    # ── Logging Settings (Observability) ─────────────────────────────

    lmds = settings.get("log_min_duration_statement", {})
    if lmds:
        lmds_val = int(lmds.get("value", "-1"))
        if lmds_val == -1:
            issues.append(ConfigIssue(
                parameter="log_min_duration_statement",
                severity="info",
                category="logging",
                current_value="-1 (disabled)",
                recommended="1000 (log queries > 1 second)",
                message="Slow query logging is disabled. You can't find slow queries you don't log.",
                fix_sql="ALTER SYSTEM SET log_min_duration_statement = 1000;  -- 1 second",
            ))

    tit = settings.get("track_io_timing", {})
    if tit and tit.get("value") == "off":
        issues.append(ConfigIssue(
            parameter="track_io_timing",
            severity="info",
            category="logging",
            current_value="off",
            recommended="on",
            message="I/O timing is disabled. EXPLAIN ANALYZE won't show I/O time per node.",
            rationale="Overhead is minimal (~2% CPU). The observability benefit is immense.",
            fix_sql="ALTER SYSTEM SET track_io_timing = on;",
        ))

    lc = settings.get("log_checkpoints", {})
    if lc and lc.get("value") == "off":
        issues.append(ConfigIssue(
            parameter="log_checkpoints",
            severity="info",
            category="logging",
            current_value="off",
            recommended="on",
            message="Checkpoint logging is off. You can't diagnose checkpoint spikes.",
            fix_sql="ALTER SYSTEM SET log_checkpoints = on;",
        ))

    llw = settings.get("log_lock_waits", {})
    if llw and llw.get("value") == "off":
        issues.append(ConfigIssue(
            parameter="log_lock_waits",
            severity="info",
            category="logging",
            current_value="off",
            recommended="on",
            message="Lock wait logging is off. You won't see deadlock investigations.",
            fix_sql="ALTER SYSTEM SET log_lock_waits = on;",
        ))

    taqs = settings.get("track_activity_query_size", {})
    if taqs:
        taqs_val = int(taqs.get("value", "1024"))
        if taqs_val <= 1024:
            issues.append(ConfigIssue(
                parameter="track_activity_query_size",
                severity="info",
                category="logging",
                current_value=str(taqs_val),
                recommended="4096-16384",
                message="track_activity_query_size is small. Long queries get truncated in pg_stat_activity.",
                fix_sql="ALTER SYSTEM SET track_activity_query_size = 8192;",
            ))

    # ── Autovacuum Settings ──────────────────────────────────────────

    av = settings.get("autovacuum", {})
    if av and av.get("value") == "off":
        issues.append(ConfigIssue(
            parameter="autovacuum",
            severity="critical",
            category="autovacuum",
            current_value="off",
            recommended="on",
            message="AUTOVACUUM IS OFF. Table bloat and transaction ID wraparound risk.",
            fix_sql="ALTER SYSTEM SET autovacuum = on;",
        ))

    avcd = settings.get("autovacuum_vacuum_cost_delay", {})
    if avcd:
        avcd_val = float(avcd.get("value", "2"))
        if avcd_val >= 20:  # Default was 20ms in older versions
            issues.append(ConfigIssue(
                parameter="autovacuum_vacuum_cost_delay",
                severity="warning",
                category="autovacuum",
                current_value=f"{avcd_val}ms",
                recommended="2ms (PG 12+ default) or 0 for fast storage",
                message="Autovacuum is throttled heavily. Vacuum may not keep up with update-heavy tables.",
                fix_sql="ALTER SYSTEM SET autovacuum_vacuum_cost_delay = '2ms';",
            ))

    avsf = settings.get("autovacuum_vacuum_scale_factor", {})
    if avsf:
        avsf_val = float(avsf.get("value", "0.2"))
        if avsf_val >= 0.2:
            issues.append(ConfigIssue(
                parameter="autovacuum_vacuum_scale_factor",
                severity="info",
                category="autovacuum",
                current_value=str(avsf_val),
                recommended="0.01-0.05 for large tables (per-table override)",
                message=(
                    f"autovacuum_vacuum_scale_factor={avsf_val} means VACUUM triggers after "
                    f"{avsf_val * 100:.0f}% of rows change. For a 10M row table, that's "
                    f"{int(avsf_val * 10_000_000):,} row changes before vacuum runs."
                ),
                fix_sql="-- Per-table: ALTER TABLE big_table SET (autovacuum_vacuum_scale_factor = 0.01);",
            ))

    # ── Calculate Score ──────────────────────────────────────────────

    score = 100
    for issue in issues:
        if issue.severity == "critical":
            score -= 15
        elif issue.severity == "warning":
            score -= 8
        elif issue.severity == "info":
            score -= 2
    report.score = max(0, score)

    return report
