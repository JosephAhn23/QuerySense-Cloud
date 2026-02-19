"""
Temp File Auditor — Detect queries spilling to disk.

When work_mem is too low, sorts and hash operations spill to temporary files.
These are 10-100x slower than in-memory operations.

Two modes:
    1. Live: Query pg_stat_database for temp file counts and sizes
    2. Log: Parse PostgreSQL logs for "temporary file" events

Usage:
    from querysense.audit.tempfiles import TempFileAuditor

    auditor = TempFileAuditor()
    report = await auditor.analyze_live(conn)
    print(report.summary)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from querysense.audit.log_parser import LogEvent, LogParser


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class TempFileEvent:
    """A single temp file creation from logs."""

    query: str = ""
    size_bytes: int = 0
    operation: str = ""  # sort, hash, etc.
    pid: int = 0
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query[:200],
            "size_bytes": self.size_bytes,
            "size_mb": round(self.size_bytes / (1024 * 1024), 1),
            "operation": self.operation,
            "pid": self.pid,
        }


@dataclass
class TempFileFinding:
    """A temp-file-related finding."""

    severity: str
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
class TempFileReport:
    """Complete temp file analysis report."""

    total_temp_files: int = 0
    total_temp_bytes: int = 0
    events: list[TempFileEvent] = field(default_factory=list)
    findings: list[TempFileFinding] = field(default_factory=list)
    current_work_mem: str = ""
    databases: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def total_temp_mb(self) -> float:
        return self.total_temp_bytes / (1024 * 1024) if self.total_temp_bytes > 0 else 0

    @property
    def summary(self) -> str:
        if self.total_temp_files == 0:
            return "No temp files detected — work_mem is adequate"
        return (
            f"{self.total_temp_files:,} temp files ({self.total_temp_mb:.0f}MB total). "
            f"Current work_mem: {self.current_work_mem}."
        )

    @property
    def is_healthy(self) -> bool:
        return not any(f.severity in ("critical", "warning") for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_temp_files": self.total_temp_files,
            "total_temp_bytes": self.total_temp_bytes,
            "total_temp_mb": round(self.total_temp_mb, 1),
            "current_work_mem": self.current_work_mem,
            "databases": self.databases,
            "findings": [f.to_dict() for f in self.findings],
            "events": [e.to_dict() for e in self.events[:20]],
            "is_healthy": self.is_healthy,
        }


class TempFileAuditor:
    """
    Detect and analyze temporary file usage.

    Temp files indicate work_mem is too low for the workload.
    """

    async def analyze_live(self, conn: AsyncDBConnection) -> TempFileReport:
        """Analyze temp file usage from live database."""
        report = TempFileReport()

        # Get current work_mem
        try:
            report.current_work_mem = str(await conn.fetchval("SHOW work_mem"))
        except Exception:
            pass

        # Get temp file stats per database
        try:
            rows = await conn.fetch(
                "SELECT datname, temp_files, temp_bytes, "
                "  pg_size_pretty(temp_bytes) AS temp_size "
                "FROM pg_stat_database "
                "WHERE temp_bytes > 0 "
                "ORDER BY temp_bytes DESC"
            )
        except Exception:
            return report

        for r in rows:
            if isinstance(r, (list, tuple)):
                db, files, bytes_val, size_pretty = r[:4]
            else:
                db = getattr(r, "datname", "")
                files = getattr(r, "temp_files", 0)
                bytes_val = getattr(r, "temp_bytes", 0)
                size_pretty = getattr(r, "temp_size", "")

            files_i = int(files or 0)
            bytes_i = int(bytes_val or 0)

            report.total_temp_files += files_i
            report.total_temp_bytes += bytes_i
            report.databases[str(db)] = {"files": files_i, "bytes": bytes_i}

        # Try to find top temp-file-creating queries from pg_stat_statements
        try:
            rows = await conn.fetch(
                "SELECT query, temp_blks_written, temp_blks_read, calls "
                "FROM pg_stat_statements "
                "WHERE temp_blks_written > 0 "
                "ORDER BY temp_blks_written DESC LIMIT 10"
            )
            for r in rows:
                if isinstance(r, (list, tuple)):
                    query, written, read, calls = r[:4]
                else:
                    query = getattr(r, "query", "")
                    written = getattr(r, "temp_blks_written", 0)
                    read = getattr(r, "temp_blks_read", 0)
                    calls = getattr(r, "calls", 0)

                report.events.append(TempFileEvent(
                    query=str(query)[:500],
                    size_bytes=int(written or 0) * 8192,  # 8KB blocks
                    operation="sort/hash",
                    pid=0,
                ))
        except Exception:
            pass  # pg_stat_statements may not be available

        # Generate findings
        self._analyze_findings(report)

        return report

    def analyze_file(self, log_path: str | Path) -> TempFileReport:
        """Analyze temp file events from log file."""
        parser = LogParser()
        events = parser.parse_file(log_path)
        return self.analyze_events(events)

    def analyze_events(self, events: list[LogEvent]) -> TempFileReport:
        """Analyze pre-parsed log events for temp file usage."""
        import re

        report = TempFileReport()

        for event in events:
            if not event.is_temp_file:
                continue

            # Extract size from "temporary file: path ..., size NNNN"
            size_match = re.search(r"size\s+(\d+)", event.message)
            size = int(size_match.group(1)) if size_match else 0

            report.events.append(TempFileEvent(
                query=event.statement or "",
                size_bytes=size,
                operation="sort/hash",
                pid=event.pid,
                timestamp=event.timestamp.isoformat() if event.timestamp else "",
            ))
            report.total_temp_files += 1
            report.total_temp_bytes += size

        self._analyze_findings(report)
        return report

    def _analyze_findings(self, report: TempFileReport) -> None:
        """Generate findings from temp file analysis."""
        if report.total_temp_bytes > 10 * 1024 * 1024 * 1024:  # > 10GB
            report.findings.append(TempFileFinding(
                severity="critical",
                title=f"Massive temp file usage: {report.total_temp_mb:.0f}MB",
                description="Queries are heavily spilling to disk. This causes severe performance degradation.",
                recommendation="Increase work_mem to 256MB-1GB for analytics workloads.",
                fix_sql="ALTER SYSTEM SET work_mem = '256MB';\nSELECT pg_reload_conf();",
                evidence={"total_mb": round(report.total_temp_mb, 1)},
            ))
        elif report.total_temp_bytes > 1024 * 1024 * 1024:  # > 1GB
            report.findings.append(TempFileFinding(
                severity="warning",
                title=f"Significant temp file usage: {report.total_temp_mb:.0f}MB",
                description="Some queries are spilling sorts/hashes to disk.",
                recommendation="Increase work_mem from default 4MB to 32-64MB.",
                fix_sql="ALTER SYSTEM SET work_mem = '64MB';\nSELECT pg_reload_conf();",
                evidence={"total_mb": round(report.total_temp_mb, 1)},
            ))
        elif report.total_temp_files > 1000:
            report.findings.append(TempFileFinding(
                severity="notice",
                title=f"{report.total_temp_files:,} temp files created",
                description="Many small temp files. Consider increasing work_mem.",
                recommendation="Set work_mem = '32MB' as a starting point.",
                fix_sql="ALTER SYSTEM SET work_mem = '32MB';\nSELECT pg_reload_conf();",
            ))

        # Check for individual large spills
        large_events = [e for e in report.events if e.size_bytes > 100 * 1024 * 1024]  # >100MB
        for ev in large_events[:3]:
            report.findings.append(TempFileFinding(
                severity="warning",
                title=f"Large temp file: {ev.size_bytes // (1024 * 1024)}MB from single query",
                description=f"Query: {ev.query[:100]}...",
                recommendation="Optimize this query or increase work_mem for this session.",
                fix_sql=f"SET work_mem = '512MB'; -- For this session only",
            ))
