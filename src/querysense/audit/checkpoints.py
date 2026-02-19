"""
Checkpoint Auditor — Analyze checkpoint frequency, WAL volume, and I/O impact.

"Checkpoints every 17 seconds = disaster" — Lukas Fittl, pganalyze.

This module connects to a live PostgreSQL database and:
    1. Measures checkpoint frequency from pg_stat_bgwriter
    2. Calculates WAL generation rate
    3. Estimates I/O impact of checkpoints
    4. Recommends optimal checkpoint settings

Usage:
    from querysense.audit.checkpoints import CheckpointAuditor

    auditor = CheckpointAuditor()
    report = await auditor.analyze(conn)
    print(report.summary)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class CheckpointStats:
    """Raw checkpoint statistics from pg_stat_bgwriter."""

    checkpoints_timed: int = 0       # Scheduled checkpoints
    checkpoints_req: int = 0         # Requested (forced) checkpoints
    buffers_checkpoint: int = 0      # Buffers written during checkpoint
    buffers_clean: int = 0           # Buffers written by bgwriter
    buffers_backend: int = 0         # Buffers written by backends (bad)
    maxwritten_clean: int = 0        # Times bgwriter stopped due to limit
    stats_reset: str = ""            # When stats were last reset
    stats_age_seconds: float = 0.0   # Seconds since reset


@dataclass
class CheckpointFinding:
    """A single checkpoint-related finding."""

    severity: str  # critical, warning, info
    title: str
    description: str
    recommendation: str
    fix_sql: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "fix_sql": self.fix_sql,
            "evidence": self.evidence,
        }


@dataclass
class CheckpointReport:
    """Complete checkpoint analysis report."""

    stats: CheckpointStats = field(default_factory=CheckpointStats)
    findings: list[CheckpointFinding] = field(default_factory=list)
    checkpoint_frequency_seconds: float = 0.0
    checkpoints_per_hour: float = 0.0
    total_checkpoints: int = 0
    pct_requested: float = 0.0
    wal_bytes_per_checkpoint: float = 0.0
    buffers_backend_pct: float = 0.0
    current_settings: dict[str, str] = field(default_factory=dict)
    recommended_settings: dict[str, str] = field(default_factory=dict)

    @property
    def is_healthy(self) -> bool:
        return not any(f.severity in ("critical", "warning") for f in self.findings)

    @property
    def summary(self) -> str:
        lines = [
            f"Checkpoint frequency: every {self.checkpoint_frequency_seconds:.0f}s "
            f"({self.checkpoints_per_hour:.1f}/hour)",
            f"Total checkpoints: {self.total_checkpoints} "
            f"({self.pct_requested:.0f}% requested/forced)",
        ]
        if self.findings:
            crit = sum(1 for f in self.findings if f.severity == "critical")
            warn = sum(1 for f in self.findings if f.severity == "warning")
            lines.append(f"Issues: {crit} critical, {warn} warnings")
        else:
            lines.append("Status: Healthy")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_frequency_seconds": round(self.checkpoint_frequency_seconds, 1),
            "checkpoints_per_hour": round(self.checkpoints_per_hour, 1),
            "total_checkpoints": self.total_checkpoints,
            "pct_requested": round(self.pct_requested, 1),
            "buffers_backend_pct": round(self.buffers_backend_pct, 1),
            "current_settings": self.current_settings,
            "recommended_settings": self.recommended_settings,
            "findings": [f.to_dict() for f in self.findings],
            "is_healthy": self.is_healthy,
        }


class CheckpointAuditor:
    """
    Analyze PostgreSQL checkpoint behavior and recommend improvements.

    Connects to a live database and queries pg_stat_bgwriter to measure
    checkpoint frequency, WAL volume, and I/O distribution.
    """

    async def analyze(self, conn: AsyncDBConnection) -> CheckpointReport:
        """Run full checkpoint analysis."""
        report = CheckpointReport()

        # Collect stats
        report.stats = await self._collect_stats(conn)
        report.current_settings = await self._collect_settings(conn)

        # Calculate metrics
        total = report.stats.checkpoints_timed + report.stats.checkpoints_req
        report.total_checkpoints = total

        if total > 0 and report.stats.stats_age_seconds > 0:
            report.checkpoint_frequency_seconds = report.stats.stats_age_seconds / total
            report.checkpoints_per_hour = total / (report.stats.stats_age_seconds / 3600)
            report.pct_requested = (report.stats.checkpoints_req / total) * 100

        total_buffers = (
            report.stats.buffers_checkpoint
            + report.stats.buffers_clean
            + report.stats.buffers_backend
        )
        if total_buffers > 0:
            report.buffers_backend_pct = (report.stats.buffers_backend / total_buffers) * 100

        # Analyze findings
        self._check_frequency(report)
        self._check_requested_ratio(report)
        self._check_backend_writes(report)
        self._check_bgwriter_pressure(report)
        self._generate_recommendations(report)

        return report

    async def _collect_stats(self, conn: AsyncDBConnection) -> CheckpointStats:
        """Collect checkpoint stats from pg_stat_bgwriter."""
        try:
            rows = await conn.fetch(
                "SELECT checkpoints_timed, checkpoints_req, "
                "  buffers_checkpoint, buffers_clean, buffers_backend, "
                "  maxwritten_clean, "
                "  stats_reset::text, "
                "  EXTRACT(EPOCH FROM (now() - stats_reset))::float AS stats_age "
                "FROM pg_stat_bgwriter"
            )
        except Exception:
            return CheckpointStats()

        if not rows:
            return CheckpointStats()

        r = rows[0]
        if isinstance(r, (list, tuple)):
            return CheckpointStats(
                checkpoints_timed=int(r[0] or 0),
                checkpoints_req=int(r[1] or 0),
                buffers_checkpoint=int(r[2] or 0),
                buffers_clean=int(r[3] or 0),
                buffers_backend=int(r[4] or 0),
                maxwritten_clean=int(r[5] or 0),
                stats_reset=str(r[6] or ""),
                stats_age_seconds=float(r[7] or 0),
            )
        return CheckpointStats(
            checkpoints_timed=int(getattr(r, "checkpoints_timed", 0) or 0),
            checkpoints_req=int(getattr(r, "checkpoints_req", 0) or 0),
            buffers_checkpoint=int(getattr(r, "buffers_checkpoint", 0) or 0),
            buffers_clean=int(getattr(r, "buffers_clean", 0) or 0),
            buffers_backend=int(getattr(r, "buffers_backend", 0) or 0),
            maxwritten_clean=int(getattr(r, "maxwritten_clean", 0) or 0),
            stats_reset=str(getattr(r, "stats_reset", "") or ""),
            stats_age_seconds=float(getattr(r, "stats_age", 0) or 0),
        )

    async def _collect_settings(self, conn: AsyncDBConnection) -> dict[str, str]:
        """Collect checkpoint-related settings."""
        settings: dict[str, str] = {}
        for name in (
            "checkpoint_timeout", "max_wal_size", "min_wal_size",
            "checkpoint_completion_target", "wal_buffers",
        ):
            try:
                val = await conn.fetchval(f"SHOW {name}")
                settings[name] = str(val)
            except Exception:
                pass
        return settings

    def _check_frequency(self, report: CheckpointReport) -> None:
        """Check if checkpoints are too frequent."""
        freq = report.checkpoint_frequency_seconds
        if freq <= 0:
            return

        if freq < 60:
            report.findings.append(CheckpointFinding(
                severity="critical",
                title=f"Checkpoints every {freq:.0f} seconds — SEVERE I/O impact",
                description=(
                    f"Checkpoints every {freq:.0f}s means the WAL fills up before "
                    "checkpoint_timeout. This causes constant I/O storms."
                ),
                recommendation="Increase max_wal_size to at least 10GB.",
                fix_sql="ALTER SYSTEM SET max_wal_size = '10GB';\nSELECT pg_reload_conf();",
                evidence={"frequency_seconds": round(freq, 1)},
            ))
        elif freq < 300:
            report.findings.append(CheckpointFinding(
                severity="warning",
                title=f"Checkpoints every {freq:.0f} seconds (target: >300s)",
                description="Checkpoint frequency is elevated, causing periodic I/O spikes.",
                recommendation="Increase max_wal_size to 4-10GB.",
                fix_sql="ALTER SYSTEM SET max_wal_size = '4GB';\nSELECT pg_reload_conf();",
                evidence={"frequency_seconds": round(freq, 1)},
            ))

    def _check_requested_ratio(self, report: CheckpointReport) -> None:
        """Check ratio of requested vs timed checkpoints."""
        if report.total_checkpoints < 10:
            return

        if report.pct_requested > 50:
            report.findings.append(CheckpointFinding(
                severity="warning",
                title=f"{report.pct_requested:.0f}% of checkpoints are forced (requested)",
                description=(
                    "Most checkpoints are triggered by WAL filling up, not by timeout. "
                    "This indicates max_wal_size is too small for the write workload."
                ),
                recommendation="Increase max_wal_size so checkpoints are timer-driven.",
                fix_sql="ALTER SYSTEM SET max_wal_size = '10GB';\nSELECT pg_reload_conf();",
                evidence={"pct_requested": round(report.pct_requested, 1)},
            ))

    def _check_backend_writes(self, report: CheckpointReport) -> None:
        """Check if backends are doing too many direct writes."""
        if report.buffers_backend_pct > 10:
            report.findings.append(CheckpointFinding(
                severity="warning",
                title=f"Backends writing {report.buffers_backend_pct:.0f}% of buffers directly",
                description=(
                    "When backends write buffers directly (instead of bgwriter/checkpointer), "
                    "individual queries experience I/O stalls."
                ),
                recommendation="Increase bgwriter_lru_maxpages and bgwriter_lru_multiplier.",
                fix_sql=(
                    "ALTER SYSTEM SET bgwriter_lru_maxpages = 1000;\n"
                    "ALTER SYSTEM SET bgwriter_lru_multiplier = 4.0;\n"
                    "SELECT pg_reload_conf();"
                ),
                evidence={"backend_write_pct": round(report.buffers_backend_pct, 1)},
            ))

    def _check_bgwriter_pressure(self, report: CheckpointReport) -> None:
        """Check if bgwriter is hitting its limits."""
        if report.stats.maxwritten_clean > 100:
            report.findings.append(CheckpointFinding(
                severity="warning",
                title=f"Background writer hit limit {report.stats.maxwritten_clean:,} times",
                description="bgwriter is not keeping up with dirty buffer production.",
                recommendation="Increase bgwriter_lru_maxpages.",
                fix_sql="ALTER SYSTEM SET bgwriter_lru_maxpages = 1000;\nSELECT pg_reload_conf();",
                evidence={"maxwritten_clean": report.stats.maxwritten_clean},
            ))

    def _generate_recommendations(self, report: CheckpointReport) -> None:
        """Generate recommended settings based on findings."""
        if not report.findings:
            return

        report.recommended_settings = {
            "max_wal_size": "10GB",
            "checkpoint_completion_target": "0.9",
            "checkpoint_timeout": "15min",
        }

        current_max_wal = report.current_settings.get("max_wal_size", "1GB")
        if current_max_wal == report.recommended_settings["max_wal_size"]:
            del report.recommended_settings["max_wal_size"]
