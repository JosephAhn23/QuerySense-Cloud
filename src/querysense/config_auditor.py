"""
Server Configuration Auditor — compare live PostgreSQL settings against best practices.

Based on "PostgreSQL Mistakes and How to Avoid Them" (Angelakos 2025):
default production settings are one of the top mistakes. This module connects
to a live database, pulls SHOW ALL settings, and compares them against
evidence-based recommendations scaled to the system's hardware.

Outputs specific ALTER SYSTEM commands — not just "this is wrong" but
"run this exact command to fix it."

Usage:
    from querysense.config_auditor import ConfigAuditor, AuditResult

    auditor = ConfigAuditor()
    result = await auditor.audit(dsn="postgresql://localhost/mydb")
    for finding in result.findings:
        print(f"{finding.severity}: {finding.setting} = {finding.current}")
        print(f"  Recommended: {finding.recommended}")
        print(f"  Fix: {finding.fix_command}")
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AuditSeverity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


@dataclass
class ConfigFinding:
    """A single configuration audit finding."""
    setting: str
    current: str
    recommended: str
    severity: AuditSeverity
    category: str
    description: str
    fix_command: str
    impact: str
    reference: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.setting}: {self.current} → {self.recommended}"


@dataclass
class SystemInfo:
    """Detected system hardware info."""
    total_ram_bytes: int = 0
    cpu_count: int = 0
    pg_version: str = ""
    pg_version_num: int = 0
    is_ssd: bool = True  # assume SSD by default
    max_connections: int = 100
    data_directory: str = ""


@dataclass
class AuditResult:
    """Complete audit result."""
    system: SystemInfo
    findings: list[ConfigFinding] = field(default_factory=list)
    settings_checked: int = 0
    risk_score: float = 0.0  # 0-10

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == AuditSeverity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == AuditSeverity.WARNING)

    @property
    def fix_script(self) -> str:
        """Generate a complete fix script."""
        lines = ["-- QuerySense Configuration Audit Fix Script", ""]
        for f in self.findings:
            if f.severity in (AuditSeverity.CRITICAL, AuditSeverity.WARNING):
                lines.append(f"-- {f.description}")
                lines.append(f"{f.fix_command}")
                lines.append("")
        lines.append("-- Apply changes:")
        lines.append("SELECT pg_reload_conf();")
        return "\n".join(lines)


# ── Best Practice Rules ────────────────────────────────────────────────────

def _parse_memory(val: str) -> int:
    """Parse PostgreSQL memory string to bytes."""
    val = val.strip().upper()
    multipliers = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    for suffix, mult in multipliers.items():
        if val.endswith(suffix):
            return int(float(val[:-len(suffix)].strip()) * mult)
    # Plain number = 8kB blocks
    try:
        return int(val) * 8192
    except ValueError:
        return 0


def _format_memory(bytes_val: int) -> str:
    """Format bytes to PostgreSQL memory string."""
    if bytes_val >= 1024**3:
        return f"{bytes_val // (1024**3)}GB"
    if bytes_val >= 1024**2:
        return f"{bytes_val // (1024**2)}MB"
    return f"{bytes_val // 1024}kB"


class ConfigAuditor:
    """
    Audit PostgreSQL configuration against best practices.

    Connects to a live database, detects system hardware, and compares
    every critical setting against evidence-based recommendations.
    """

    async def audit(self, dsn: str) -> AuditResult:
        """Run a full configuration audit."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            # Gather system info
            system = await self._detect_system(conn)

            # Pull all settings
            settings = await self._get_all_settings(conn)

            # Run checks
            result = AuditResult(system=system)
            self._check_memory(settings, system, result)
            self._check_wal(settings, system, result)
            self._check_planner(settings, system, result)
            self._check_autovacuum(settings, result)
            self._check_connections(settings, system, result)
            self._check_logging(settings, result)
            self._check_parallelism(settings, system, result)
            self._check_checkpoints(settings, result)

            result.settings_checked = len(settings)
            result.risk_score = self._calculate_risk(result)
            return result
        finally:
            await conn.close()

    async def _detect_system(self, conn: Any) -> SystemInfo:
        """Detect system hardware from PostgreSQL."""
        info = SystemInfo()

        # PG version
        row = await conn.fetchrow("SELECT version(), current_setting('server_version_num')::int")
        info.pg_version = row[0]
        info.pg_version_num = row[1]

        # RAM (from shared_buffers hint or OS)
        try:
            row = await conn.fetchrow(
                "SELECT current_setting('shared_buffers'), "
                "current_setting('max_connections')::int"
            )
            sb = _parse_memory(row[0])
            info.max_connections = row[1]
            # Estimate total RAM as 4x shared_buffers (conservative default)
            info.total_ram_bytes = max(sb * 4, 1024**3)  # At least 1GB
        except Exception:
            info.total_ram_bytes = 4 * 1024**3  # Default 4GB

        # CPU count
        try:
            row = await conn.fetchrow(
                "SELECT current_setting('max_parallel_workers')"
            )
            info.cpu_count = max(int(row[0]), 2)
        except Exception:
            info.cpu_count = 4

        return info

    async def _get_all_settings(self, conn: Any) -> dict[str, str]:
        """Get all PostgreSQL settings."""
        rows = await conn.fetch("SELECT name, setting FROM pg_settings")
        return {row["name"]: row["setting"] for row in rows}

    def _check_memory(
        self, settings: dict[str, str], system: SystemInfo, result: AuditResult,
    ) -> None:
        """Check memory-related settings."""
        ram = system.total_ram_bytes

        # shared_buffers — should be 25% of RAM
        sb = _parse_memory(settings.get("shared_buffers", "128MB"))
        recommended_sb = ram // 4
        if sb < recommended_sb * 0.5:
            result.findings.append(ConfigFinding(
                setting="shared_buffers",
                current=_format_memory(sb),
                recommended=_format_memory(recommended_sb),
                severity=AuditSeverity.CRITICAL,
                category="Memory",
                description=f"shared_buffers is {_format_memory(sb)}, should be ~25% of RAM ({_format_memory(recommended_sb)})",
                fix_command=f"ALTER SYSTEM SET shared_buffers = '{_format_memory(recommended_sb)}';",
                impact="Major — PostgreSQL will rely heavily on OS cache, reducing buffer hit rate",
                reference="PostgreSQL Mistakes (Angelakos 2025), Ch. 3",
            ))

        # effective_cache_size — should be 75% of RAM
        ecs = _parse_memory(settings.get("effective_cache_size", "4GB"))
        recommended_ecs = int(ram * 0.75)
        if ecs < recommended_ecs * 0.5:
            result.findings.append(ConfigFinding(
                setting="effective_cache_size",
                current=_format_memory(ecs),
                recommended=_format_memory(recommended_ecs),
                severity=AuditSeverity.WARNING,
                category="Memory",
                description="effective_cache_size too low — planner underestimates index scan cost",
                fix_command=f"ALTER SYSTEM SET effective_cache_size = '{_format_memory(recommended_ecs)}';",
                impact="Planner may choose sequential scans over index scans unnecessarily",
                reference="Mastering PostgreSQL 13 (Schönig 2020)",
            ))

        # work_mem — 4MB baseline, scale with RAM
        wm = _parse_memory(settings.get("work_mem", "4MB"))
        # Formula: RAM / (2 * max_connections)
        recommended_wm = max(ram // (2 * system.max_connections), 4 * 1024**2)
        recommended_wm = min(recommended_wm, 256 * 1024**2)  # Cap at 256MB
        if wm < 4 * 1024**2 and ram > 2 * 1024**3:
            result.findings.append(ConfigFinding(
                setting="work_mem",
                current=_format_memory(wm),
                recommended=_format_memory(recommended_wm),
                severity=AuditSeverity.WARNING,
                category="Memory",
                description="work_mem at default 4MB — sorts and hashes will spill to disk",
                fix_command=f"ALTER SYSTEM SET work_mem = '{_format_memory(recommended_wm)}';",
                impact="Disk-based sorts are 10-100x slower than in-memory",
                reference="PostgreSQL Query Optimization (Dombrovskaya 2024)",
            ))

        # maintenance_work_mem — should be higher for VACUUM/CREATE INDEX
        mwm = _parse_memory(settings.get("maintenance_work_mem", "64MB"))
        recommended_mwm = min(ram // 8, 2 * 1024**3)  # 12.5% of RAM, max 2GB
        if mwm < 256 * 1024**2 and ram > 4 * 1024**3:
            result.findings.append(ConfigFinding(
                setting="maintenance_work_mem",
                current=_format_memory(mwm),
                recommended=_format_memory(recommended_mwm),
                severity=AuditSeverity.INFO,
                category="Memory",
                description="maintenance_work_mem too low — VACUUM and CREATE INDEX will be slower",
                fix_command=f"ALTER SYSTEM SET maintenance_work_mem = '{_format_memory(recommended_mwm)}';",
                impact="VACUUM and index creation performance",
            ))

    def _check_wal(
        self, settings: dict[str, str], system: SystemInfo, result: AuditResult,
    ) -> None:
        """Check WAL-related settings."""
        # wal_buffers
        wb = _parse_memory(settings.get("wal_buffers", "-1"))
        if wb < 16 * 1024**2 and wb > 0:
            result.findings.append(ConfigFinding(
                setting="wal_buffers",
                current=_format_memory(wb),
                recommended="64MB",
                severity=AuditSeverity.INFO,
                category="WAL",
                description="wal_buffers below recommended 64MB for write-heavy workloads",
                fix_command="ALTER SYSTEM SET wal_buffers = '64MB';",
                impact="Write throughput for concurrent transactions",
            ))

        # max_wal_size
        mws = settings.get("max_wal_size", "1GB")
        mws_bytes = _parse_memory(mws)
        if mws_bytes < 2 * 1024**3:
            result.findings.append(ConfigFinding(
                setting="max_wal_size",
                current=mws,
                recommended="4GB",
                severity=AuditSeverity.WARNING,
                category="WAL",
                description="max_wal_size too low — causes frequent checkpoints under load",
                fix_command="ALTER SYSTEM SET max_wal_size = '4GB';",
                impact="Frequent checkpoints cause I/O spikes and increased latency",
                reference="Mastering PostgreSQL 13 (Schönig 2020)",
            ))

    def _check_planner(
        self, settings: dict[str, str], system: SystemInfo, result: AuditResult,
    ) -> None:
        """Check planner-related settings."""
        rpc = float(settings.get("random_page_cost", "4"))
        if rpc > 1.5 and system.is_ssd:
            result.findings.append(ConfigFinding(
                setting="random_page_cost",
                current=str(rpc),
                recommended="1.1",
                severity=AuditSeverity.WARNING,
                category="Planner",
                description=f"random_page_cost={rpc} assumes spinning disks — too high for SSDs",
                fix_command="ALTER SYSTEM SET random_page_cost = 1.1;",
                impact="Planner avoids index scans that would be fast on SSD",
                reference="PostgreSQL Query Optimization (Dombrovskaya 2024)",
            ))

        dst = int(settings.get("default_statistics_target", "100"))
        if dst == 100:
            result.findings.append(ConfigFinding(
                setting="default_statistics_target",
                current=str(dst),
                recommended="200-500 for complex queries",
                severity=AuditSeverity.INFO,
                category="Planner",
                description="default_statistics_target at default 100 — may cause bad estimates on skewed data",
                fix_command="ALTER SYSTEM SET default_statistics_target = 200;",
                impact="Better row estimates → better plan choices for skewed distributions",
            ))

    def _check_autovacuum(self, settings: dict[str, str], result: AuditResult) -> None:
        """Check autovacuum settings."""
        enabled = settings.get("autovacuum", "on")
        if enabled != "on":
            result.findings.append(ConfigFinding(
                setting="autovacuum",
                current=enabled,
                recommended="on",
                severity=AuditSeverity.CRITICAL,
                category="Autovacuum",
                description="AUTOVACUUM IS DISABLED — table bloat and transaction ID wraparound will occur",
                fix_command="ALTER SYSTEM SET autovacuum = on;",
                impact="CRITICAL — without autovacuum, tables bloat unboundedly and eventually become inaccessible",
                reference="PostgreSQL Mistakes (Angelakos 2025), Ch. 5",
            ))

        nap = int(settings.get("autovacuum_naptime", "60"))
        if nap > 120:
            result.findings.append(ConfigFinding(
                setting="autovacuum_naptime",
                current=f"{nap}s",
                recommended="60s",
                severity=AuditSeverity.WARNING,
                category="Autovacuum",
                description=f"autovacuum_naptime={nap}s — vacuum may not keep up with dead tuples",
                fix_command="ALTER SYSTEM SET autovacuum_naptime = '60s';",
                impact="Dead tuples accumulate between vacuum runs",
            ))

        sf = float(settings.get("autovacuum_vacuum_scale_factor", "0.2"))
        if sf >= 0.2:
            result.findings.append(ConfigFinding(
                setting="autovacuum_vacuum_scale_factor",
                current=str(sf),
                recommended="0.05 for large tables",
                severity=AuditSeverity.INFO,
                category="Autovacuum",
                description="Default scale factor 0.2 means vacuum waits until 20% of table is dead — too late for large tables",
                fix_command="ALTER SYSTEM SET autovacuum_vacuum_scale_factor = 0.05;",
                impact="Large tables accumulate bloat before vacuum triggers",
                reference="PostgreSQL Mistakes (Angelakos 2025), Ch. 5",
            ))

    def _check_connections(
        self, settings: dict[str, str], system: SystemInfo, result: AuditResult,
    ) -> None:
        """Check connection settings."""
        mc = int(settings.get("max_connections", "100"))
        if mc > 200:
            result.findings.append(ConfigFinding(
                setting="max_connections",
                current=str(mc),
                recommended="100-200 (use pgBouncer for more)",
                severity=AuditSeverity.WARNING,
                category="Connections",
                description=f"max_connections={mc} — each connection uses ~10MB RAM. Use a connection pooler instead.",
                fix_command=f"-- Consider: ALTER SYSTEM SET max_connections = 200;\n-- And use pgBouncer for connection pooling",
                impact=f"~{mc * 10}MB RAM reserved just for connections",
                reference="PostgreSQL Mistakes (Angelakos 2025)",
            ))

    def _check_logging(self, settings: dict[str, str], result: AuditResult) -> None:
        """Check logging settings."""
        lmsd = settings.get("log_min_duration_statement", "-1")
        if lmsd == "-1":
            result.findings.append(ConfigFinding(
                setting="log_min_duration_statement",
                current="disabled",
                recommended="1000 (1 second)",
                severity=AuditSeverity.WARNING,
                category="Logging",
                description="Slow query logging is DISABLED — you cannot identify slow queries from logs",
                fix_command="ALTER SYSTEM SET log_min_duration_statement = 1000;",
                impact="No visibility into slow queries without external monitoring",
            ))

    def _check_parallelism(
        self, settings: dict[str, str], system: SystemInfo, result: AuditResult,
    ) -> None:
        """Check parallelism settings."""
        mpw = int(settings.get("max_parallel_workers_per_gather", "2"))
        if mpw == 0:
            result.findings.append(ConfigFinding(
                setting="max_parallel_workers_per_gather",
                current="0",
                recommended=str(min(system.cpu_count // 2, 4)),
                severity=AuditSeverity.WARNING,
                category="Parallelism",
                description="Parallel query is DISABLED — large table scans will be single-threaded",
                fix_command=f"ALTER SYSTEM SET max_parallel_workers_per_gather = {min(system.cpu_count // 2, 4)};",
                impact="Analytical queries on large tables will not use multiple CPUs",
                reference="PostgreSQL Query Optimization (Dombrovskaya 2024)",
            ))

    def _check_checkpoints(self, settings: dict[str, str], result: AuditResult) -> None:
        """Check checkpoint settings."""
        cc = float(settings.get("checkpoint_completion_target", "0.5"))
        if cc < 0.9:
            result.findings.append(ConfigFinding(
                setting="checkpoint_completion_target",
                current=str(cc),
                recommended="0.9",
                severity=AuditSeverity.INFO,
                category="Checkpoints",
                description="checkpoint_completion_target too low — checkpoints will cause I/O spikes",
                fix_command="ALTER SYSTEM SET checkpoint_completion_target = 0.9;",
                impact="Spreads checkpoint I/O over more time, reducing latency spikes",
            ))

    def _calculate_risk(self, result: AuditResult) -> float:
        """Calculate overall risk score 0-10."""
        score = 0.0
        for f in result.findings:
            if f.severity == AuditSeverity.CRITICAL:
                score += 3.0
            elif f.severity == AuditSeverity.WARNING:
                score += 1.5
            elif f.severity == AuditSeverity.INFO:
                score += 0.5
        return min(10.0, score)
