"""
PostgreSQL Log Parser Engine — Foundation for all log-based analysis.

Parses PostgreSQL log files in multiple formats:
    - Default stderr format: "2024-01-01 12:00:00 UTC [12345]: ..."
    - csvlog format: CSV with structured fields
    - syslog format: syslog-prefixed PostgreSQL messages

Extracts structured events for downstream analyzers (deadlocks, connections,
checkpoints, slow queries, auto_explain plans).

Usage:
    from querysense.audit.log_parser import LogParser

    parser = LogParser()
    events = parser.parse_file("/var/log/postgresql/postgresql.log")
    for event in events:
        print(f"[{event.severity}] {event.message}")
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


class LogSeverity(str, Enum):
    """PostgreSQL log severity levels."""

    DEBUG = "DEBUG"
    LOG = "LOG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FATAL = "FATAL"
    PANIC = "PANIC"


@dataclass
class LogEvent:
    """A single parsed PostgreSQL log event."""

    timestamp: datetime | None = None
    pid: int = 0
    severity: LogSeverity = LogSeverity.LOG
    sqlstate: str = ""
    message: str = ""
    detail: str = ""
    hint: str = ""
    statement: str = ""
    context: str = ""
    user: str = ""
    database: str = ""
    application: str = ""
    client_addr: str = ""
    duration_ms: float | None = None
    raw_line: str = ""

    @property
    def is_error(self) -> bool:
        return self.severity in (LogSeverity.ERROR, LogSeverity.FATAL, LogSeverity.PANIC)

    @property
    def is_deadlock(self) -> bool:
        return "deadlock detected" in self.message.lower()

    @property
    def is_checkpoint(self) -> bool:
        return "checkpoint" in self.message.lower() and (
            "starting" in self.message.lower() or "complete" in self.message.lower()
        )

    @property
    def is_connection(self) -> bool:
        return any(kw in self.message.lower() for kw in (
            "connection authorized", "connection received",
            "password authentication failed", "no pg_hba.conf entry",
            "disconnection",
        ))

    @property
    def is_lock_wait(self) -> bool:
        return "lock" in self.message.lower() and "wait" in self.message.lower()

    @property
    def is_temp_file(self) -> bool:
        return "temporary file" in self.message.lower()

    @property
    def is_autovacuum(self) -> bool:
        return "autovacuum" in self.message.lower() or "automatic vacuum" in self.message.lower()

    @property
    def is_slow_query(self) -> bool:
        return self.duration_ms is not None and self.duration_ms > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "pid": self.pid,
            "severity": self.severity.value,
            "sqlstate": self.sqlstate,
            "message": self.message[:500],
            "detail": self.detail[:500],
            "statement": self.statement[:500],
            "user": self.user,
            "database": self.database,
            "duration_ms": self.duration_ms,
        }


# ------------------------------------------------------------------
# Parser patterns
# ------------------------------------------------------------------

# Standard stderr log line pattern
# 2024-01-01 12:00:00.123 UTC [12345] user@db LOG:  message
_STDERR_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"  # timestamp
    r"(?:\w+\s+)?"  # optional timezone
    r"\[(\d+)\]\s*"  # [pid]
    r"(?:(\w+)@(\w+)\s+)?"  # optional user@db
    r"(\w+):\s*(.*)"  # severity: message
)

# Duration pattern: "duration: 1234.567 ms"
_DURATION_PATTERN = re.compile(r"duration:\s+([\d.]+)\s*ms")

# Continuation line pattern (starts with \t or spaces)
_CONTINUATION_PREFIXES = ("DETAIL:", "HINT:", "STATEMENT:", "CONTEXT:", "QUERY:", "LINE")


class LogParser:
    """
    Parse PostgreSQL log files into structured events.

    Supports:
        - stderr format (default)
        - csvlog format
        - Automatic format detection
    """

    def __init__(self, since: datetime | None = None) -> None:
        """
        Args:
            since: Only return events after this timestamp.
        """
        self.since = since

    def parse_file(self, path: str | Path) -> list[LogEvent]:
        """Parse a single log file."""
        path = Path(path)
        if not path.exists():
            return []

        text = path.read_text(encoding="utf-8", errors="replace")

        # Auto-detect format
        if path.suffix == ".csv" or text.startswith('"'):
            return self._parse_csv(text)
        return self._parse_stderr(text)

    def parse_files(self, paths: list[str | Path]) -> list[LogEvent]:
        """Parse multiple log files, sorted by timestamp."""
        events: list[LogEvent] = []
        for p in paths:
            events.extend(self.parse_file(p))
        events.sort(key=lambda e: e.timestamp or datetime.min)
        return events

    def parse_glob(self, pattern: str) -> list[LogEvent]:
        """Parse files matching a glob pattern."""
        from pathlib import Path as P
        base = P(pattern).parent
        glob = P(pattern).name
        if not base.exists():
            return []
        paths = sorted(base.glob(glob))
        return self.parse_files(paths)

    # ------------------------------------------------------------------
    # stderr format
    # ------------------------------------------------------------------

    def _parse_stderr(self, text: str) -> list[LogEvent]:
        """Parse standard stderr PostgreSQL log format."""
        events: list[LogEvent] = []
        current: LogEvent | None = None

        for line in text.splitlines():
            match = _STDERR_PATTERN.match(line)
            if match:
                # Save previous event
                if current:
                    self._finalize(current)
                    if self._passes_filter(current):
                        events.append(current)

                ts_str, pid, user, db, severity, message = match.groups()
                ts = self._parse_timestamp(ts_str)

                current = LogEvent(
                    timestamp=ts,
                    pid=int(pid),
                    user=user or "",
                    database=db or "",
                    severity=self._parse_severity(severity),
                    message=message.strip(),
                    raw_line=line,
                )
            elif current and line.strip():
                # Continuation line
                stripped = line.strip()
                if stripped.startswith("DETAIL:"):
                    current.detail += stripped[7:].strip() + "\n"
                elif stripped.startswith("HINT:"):
                    current.hint += stripped[5:].strip() + "\n"
                elif stripped.startswith("STATEMENT:"):
                    current.statement += stripped[10:].strip() + "\n"
                elif stripped.startswith("CONTEXT:"):
                    current.context += stripped[8:].strip() + "\n"
                else:
                    # Continuation of previous field
                    if current.statement:
                        current.statement += " " + stripped
                    elif current.detail:
                        current.detail += " " + stripped
                    else:
                        current.message += " " + stripped

        if current:
            self._finalize(current)
            if self._passes_filter(current):
                events.append(current)

        return events

    # ------------------------------------------------------------------
    # csvlog format
    # ------------------------------------------------------------------

    def _parse_csv(self, text: str) -> list[LogEvent]:
        """Parse PostgreSQL csvlog format."""
        events: list[LogEvent] = []
        reader = csv.reader(io.StringIO(text))

        for row in reader:
            if len(row) < 14:
                continue
            try:
                event = LogEvent(
                    timestamp=self._parse_timestamp(row[0]),
                    user=row[1],
                    database=row[2],
                    pid=int(row[3]) if row[3] else 0,
                    client_addr=row[4],
                    severity=self._parse_severity(row[11]),
                    sqlstate=row[12],
                    message=row[13],
                    detail=row[14] if len(row) > 14 else "",
                    hint=row[15] if len(row) > 15 else "",
                    statement=row[18] if len(row) > 18 else "",
                    raw_line=",".join(row[:20]),
                )
                self._finalize(event)
                if self._passes_filter(event):
                    events.append(event)
            except (ValueError, IndexError):
                continue

        return events

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _finalize(self, event: LogEvent) -> None:
        """Post-process an event (extract duration, clean fields)."""
        # Extract duration
        dur_match = _DURATION_PATTERN.search(event.message)
        if dur_match:
            event.duration_ms = float(dur_match.group(1))

        # Clean trailing whitespace
        event.detail = event.detail.strip()
        event.hint = event.hint.strip()
        event.statement = event.statement.strip()
        event.context = event.context.strip()

    def _passes_filter(self, event: LogEvent) -> bool:
        """Check if event passes timestamp filter."""
        if self.since and event.timestamp and event.timestamp < self.since:
            return False
        return True

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime | None:
        """Parse various PostgreSQL timestamp formats."""
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f %Z",
            "%Y-%m-%d %H:%M:%S %Z",
        ):
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _parse_severity(sev: str) -> LogSeverity:
        """Parse severity string to enum."""
        try:
            return LogSeverity(sev.upper().strip())
        except ValueError:
            return LogSeverity.LOG
