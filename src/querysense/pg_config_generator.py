"""
PostgreSQL Configuration Generator

Generates recommended postgresql.conf snippets for optimal monitoring,
auto_explain, logging, and performance tuning based on system resources.

Inspired by pganalyze best-practice recommendations and the CounterPath
case study where shared_buffers tuning reduced startup time 4x.

Usage:
    from querysense.pg_config_generator import ConfigGenerator, SystemProfile

    profile = SystemProfile(ram_gb=32, cpu_cores=8, storage="ssd")
    gen = ConfigGenerator(profile)
    print(gen.generate_monitoring_config())
    print(gen.generate_logging_config())
    print(gen.generate_performance_config())
    print(gen.generate_full_config())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class StorageType(str, Enum):
    SSD = "ssd"
    HDD = "hdd"
    NVME = "nvme"


class WorkloadType(str, Enum):
    OLTP = "oltp"
    OLAP = "olap"
    MIXED = "mixed"
    WEB = "web"


@dataclass(frozen=True)
class SystemProfile:
    """System resource profile for tuning recommendations."""
    ram_gb: float = 16.0
    cpu_cores: int = 4
    storage: str = "ssd"
    max_connections: int = 200
    workload: str = "mixed"
    pg_version: int = 15
    is_dedicated: bool = True
    has_replicas: bool = False


@dataclass
class ConfigEntry:
    """A single postgresql.conf entry with documentation."""
    key: str
    value: str
    comment: str = ""
    section: str = ""
    requires_restart: bool = False


class ConfigGenerator:
    """
    Generates PostgreSQL configuration recommendations.

    Produces well-commented postgresql.conf snippets optimised for
    QuerySense monitoring and overall database performance.
    """

    def __init__(self, profile: SystemProfile | None = None) -> None:
        self.profile = profile or SystemProfile()

    def generate_auto_explain_config(self) -> list[ConfigEntry]:
        """Generate auto_explain configuration for query analysis."""
        return [
            ConfigEntry(
                "shared_preload_libraries",
                "'auto_explain,pg_stat_statements'",
                "Load extensions at server start (requires restart)",
                "Extensions",
                requires_restart=True,
            ),
            ConfigEntry(
                "auto_explain.log_min_duration",
                "'100ms'",
                "Log EXPLAIN for queries taking >100ms",
                "Auto-Explain",
            ),
            ConfigEntry(
                "auto_explain.log_analyze", "on",
                "Include actual timing (requires ANALYZE overhead)",
                "Auto-Explain",
            ),
            ConfigEntry(
                "auto_explain.log_buffers", "on",
                "Include buffer usage stats",
                "Auto-Explain",
            ),
            ConfigEntry(
                "auto_explain.log_timing", "on",
                "Include per-node timing",
                "Auto-Explain",
            ),
            ConfigEntry(
                "auto_explain.log_triggers", "on",
                "Include trigger execution time",
                "Auto-Explain",
            ),
            ConfigEntry(
                "auto_explain.log_verbose", "on",
                "Include output column lists",
                "Auto-Explain",
            ),
            ConfigEntry(
                "auto_explain.log_nested_statements", "on",
                "Log plans for nested statements (functions/procedures)",
                "Auto-Explain",
            ),
            ConfigEntry(
                "auto_explain.log_format", "'json'",
                "JSON format for machine-readable parsing by QuerySense",
                "Auto-Explain",
            ),
            ConfigEntry(
                "auto_explain.sample_rate", "0.01",
                "Sample 1% of queries (adjust up for dev, down for prod)",
                "Auto-Explain",
            ),
        ]

    def generate_logging_config(self) -> list[ConfigEntry]:
        """Generate enhanced logging configuration."""
        return [
            ConfigEntry(
                "log_min_duration_statement", "'100ms'",
                "Log queries taking >100ms (set to -1 to disable)",
                "Logging",
            ),
            ConfigEntry(
                "log_line_prefix",
                "'%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '",
                "Structured log prefix for parsing",
                "Logging",
            ),
            ConfigEntry(
                "log_checkpoints", "on",
                "Log checkpoint activity for I/O analysis",
                "Logging",
            ),
            ConfigEntry(
                "log_connections", "on",
                "Log new connections",
                "Logging",
            ),
            ConfigEntry(
                "log_disconnections", "on",
                "Log disconnections with session duration",
                "Logging",
            ),
            ConfigEntry(
                "log_lock_waits", "on",
                "Log lock waits exceeding deadlock_timeout",
                "Logging",
            ),
            ConfigEntry(
                "log_temp_files", "'0'",
                "Log all temp file usage (sort/hash spills)",
                "Logging",
            ),
            ConfigEntry(
                "log_autovacuum_min_duration", "'0'",
                "Log all autovacuum actions",
                "Logging",
            ),
            ConfigEntry(
                "log_error_verbosity", "default",
                "Standard error verbosity",
                "Logging",
            ),
            ConfigEntry(
                "log_statement", "'ddl'",
                "Log all DDL statements (CREATE, ALTER, DROP)",
                "Logging",
            ),
        ]

    def generate_pgss_config(self) -> list[ConfigEntry]:
        """Generate pg_stat_statements configuration."""
        max_stmts = "10000" if self.profile.max_connections > 100 else "5000"
        return [
            ConfigEntry(
                "pg_stat_statements.max", max_stmts,
                f"Track up to {max_stmts} distinct queries",
                "pg_stat_statements",
                requires_restart=True,
            ),
            ConfigEntry(
                "pg_stat_statements.track", "'all'",
                "Track all statements including nested ones",
                "pg_stat_statements",
            ),
            ConfigEntry(
                "pg_stat_statements.track_utility", "on",
                "Track utility commands (VACUUM, CREATE, etc.)",
                "pg_stat_statements",
            ),
            ConfigEntry(
                "pg_stat_statements.track_planning", "on",
                "Track planning time (PG 13+)",
                "pg_stat_statements",
            ),
        ]

    def generate_performance_config(self) -> list[ConfigEntry]:
        """Generate performance tuning based on system profile."""
        p = self.profile
        ram_mb = int(p.ram_gb * 1024)

        shared_buffers_mb = int(ram_mb * 0.25) if p.is_dedicated else int(ram_mb * 0.15)
        effective_cache_mb = int(ram_mb * 0.75) if p.is_dedicated else int(ram_mb * 0.50)

        work_mem_mb = max(4, int(ram_mb / (p.max_connections * 4)))
        maint_work_mem_mb = min(2048, int(ram_mb * 0.05))

        if p.workload == "olap":
            work_mem_mb = max(work_mem_mb, 64)
        elif p.workload == "web":
            work_mem_mb = max(4, min(work_mem_mb, 16))

        random_page_cost = "1.1" if p.storage in ("ssd", "nvme") else "4.0"
        effective_io_concurrency = "200" if p.storage in ("ssd", "nvme") else "2"

        max_parallel = max(1, min(p.cpu_cores // 2, 4))
        max_parallel_maint = max(1, min(p.cpu_cores // 2, 4))

        wal_buffers_mb = min(64, max(1, shared_buffers_mb // 32))

        entries = [
            ConfigEntry(
                "shared_buffers", f"'{shared_buffers_mb}MB'",
                f"25% of {p.ram_gb}GB RAM (dedicated server)",
                "Memory",
                requires_restart=True,
            ),
            ConfigEntry(
                "effective_cache_size", f"'{effective_cache_mb}MB'",
                f"75% of {p.ram_gb}GB RAM (planner hint, not allocation)",
                "Memory",
            ),
            ConfigEntry(
                "work_mem", f"'{work_mem_mb}MB'",
                f"Per-sort/hash memory ({p.max_connections} connections, {p.workload} workload)",
                "Memory",
            ),
            ConfigEntry(
                "maintenance_work_mem", f"'{maint_work_mem_mb}MB'",
                "Memory for VACUUM, CREATE INDEX, etc.",
                "Memory",
            ),
            ConfigEntry(
                "wal_buffers", f"'{wal_buffers_mb}MB'",
                "WAL buffer size",
                "WAL",
                requires_restart=True,
            ),
            ConfigEntry(
                "random_page_cost", random_page_cost,
                f"Tuned for {p.storage.upper()} storage",
                "Planner",
            ),
            ConfigEntry(
                "effective_io_concurrency", effective_io_concurrency,
                f"Concurrent I/O operations ({p.storage.upper()})",
                "Planner",
            ),
            ConfigEntry(
                "max_parallel_workers_per_gather", str(max_parallel),
                f"Parallel query workers (from {p.cpu_cores} cores)",
                "Parallelism",
            ),
            ConfigEntry(
                "max_parallel_maintenance_workers", str(max_parallel_maint),
                "Parallel maintenance (VACUUM, CREATE INDEX)",
                "Parallelism",
            ),
            ConfigEntry(
                "max_parallel_workers", str(min(p.cpu_cores, 8)),
                "Total parallel workers across all queries",
                "Parallelism",
                requires_restart=True,
            ),
        ]

        if p.has_replicas:
            entries.extend([
                ConfigEntry(
                    "wal_level", "'replica'",
                    "Required for streaming replication",
                    "Replication",
                    requires_restart=True,
                ),
                ConfigEntry(
                    "max_wal_senders", "10",
                    "Max concurrent replication connections",
                    "Replication",
                    requires_restart=True,
                ),
                ConfigEntry(
                    "hot_standby", "on",
                    "Allow read queries on replicas",
                    "Replication",
                    requires_restart=True,
                ),
            ])

        return entries

    def generate_full_config(self) -> str:
        """Generate a complete recommended postgresql.conf snippet."""
        sections: dict[str, list[ConfigEntry]] = {}

        all_entries = (
            self.generate_auto_explain_config()
            + self.generate_logging_config()
            + self.generate_pgss_config()
            + self.generate_performance_config()
        )

        for entry in all_entries:
            section = entry.section or "General"
            sections.setdefault(section, []).append(entry)

        lines = [
            "#" + "=" * 70,
            "# QuerySense Recommended PostgreSQL Configuration",
            f"# System: {self.profile.ram_gb}GB RAM, "
            f"{self.profile.cpu_cores} cores, {self.profile.storage.upper()}, "
            f"{self.profile.workload} workload",
            f"# Max connections: {self.profile.max_connections}",
            f"# PostgreSQL: {self.profile.pg_version}",
            "#" + "=" * 70,
            "",
        ]

        for section_name, entries in sections.items():
            lines.append(f"# --- {section_name} " + "-" * (60 - len(section_name)))
            for e in entries:
                restart_note = "  # REQUIRES RESTART" if e.requires_restart else ""
                lines.append(f"# {e.comment}")
                lines.append(f"{e.key} = {e.value}{restart_note}")
                lines.append("")

        return "\n".join(lines)

    def generate_extension_sql(self) -> str:
        """Generate SQL to install required extensions."""
        return "\n".join([
            "-- QuerySense: Required PostgreSQL Extensions",
            "-- Run this as a superuser or extension-capable role",
            "",
            "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;",
            "CREATE EXTENSION IF NOT EXISTS pg_buffercache;",
            "",
            "-- Optional: auto_explain (loaded via shared_preload_libraries)",
            "-- No CREATE EXTENSION needed; it's a preloaded module.",
            "",
            "-- Optional: Enhanced CPU/IO statistics",
            "-- CREATE EXTENSION IF NOT EXISTS pg_stat_kcache;",
            "",
            "-- Optional: Hypothetical index testing",
            "-- CREATE EXTENSION IF NOT EXISTS hypopg;",
            "",
            "-- Verify installed extensions:",
            "SELECT extname, extversion FROM pg_extension ORDER BY extname;",
        ])
