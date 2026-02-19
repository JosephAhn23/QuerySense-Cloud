"""
Log-Based Query Collector — zero-connection query collection from log files.

Closes the gap vs Percona PMM's mongolog approach. Parses PostgreSQL log files
to extract query performance data without requiring a database connection.

Supports:
- PostgreSQL CSV log format (log_destination = 'csvlog')
- PostgreSQL stderr log format (standard text logs)
- Slow query extraction (queries exceeding log_min_duration_statement)
- Error/warning extraction
- Duration parsing from log_line_prefix containing %d
- Auto-detection of log format

Useful when:
- Running on read-only replicas without pg_stat_statements access
- Database connections are limited or restricted
- Parsing historical logs for forensic analysis
- Collecting from environments where extensions can't be installed

Usage:
    from querysense.log_collector import LogCollector

    collector = LogCollector()
    results = collector.parse_file("/var/log/postgresql/postgresql-16-main.log")
    for entry in results.slow_queries:
        print(f"{entry.duration_ms:.0f}ms: {entry.query[:80]}")
"""

from __future__ import annotations

import csv
import io
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────

@dataclass
class LogEntry:
    """A parsed log entry."""
    timestamp: str = ""
    user: str = ""
    database: str = ""
    pid: int = 0
    client_addr: str = ""
    session_id: str = ""
    log_level: str = ""  # LOG, ERROR, WARNING, FATAL, PANIC
    message: str = ""
    detail: str = ""
    hint: str = ""
    query: str = ""
    duration_ms: float = 0.0
    error_severity: str = ""
    sql_state_code: str = ""
    application_name: str = ""
    line_number: int = 0

    @property
    def is_slow_query(self) -> bool:
        return self.duration_ms > 0 and self.query != ""

    @property
    def is_error(self) -> bool:
        return self.log_level in ("ERROR", "FATAL", "PANIC")

    @property
    def is_warning(self) -> bool:
        return self.log_level == "WARNING"


@dataclass
class QueryStats:
    """Aggregated statistics for a query fingerprint."""
    fingerprint: str
    example_query: str = ""
    total_calls: int = 0
    total_duration_ms: float = 0.0
    min_duration_ms: float = float("inf")
    max_duration_ms: float = 0.0
    avg_duration_ms: float = 0.0
    users: set[str] = field(default_factory=set)
    databases: set[str] = field(default_factory=set)

    def add_execution(self, entry: LogEntry) -> None:
        self.total_calls += 1
        self.total_duration_ms += entry.duration_ms
        self.min_duration_ms = min(self.min_duration_ms, entry.duration_ms)
        self.max_duration_ms = max(self.max_duration_ms, entry.duration_ms)
        self.avg_duration_ms = self.total_duration_ms / self.total_calls
        if entry.user:
            self.users.add(entry.user)
        if entry.database:
            self.databases.add(entry.database)
        if not self.example_query:
            self.example_query = entry.query

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "example_query": self.example_query[:200],
            "total_calls": self.total_calls,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "min_duration_ms": round(self.min_duration_ms, 2),
            "max_duration_ms": round(self.max_duration_ms, 2),
            "avg_duration_ms": round(self.avg_duration_ms, 2),
            "users": sorted(self.users),
            "databases": sorted(self.databases),
        }


@dataclass
class CollectionResult:
    """Results from parsing a log file."""
    file_path: str = ""
    format_detected: str = ""  # "csvlog", "stderr", "unknown"
    total_lines: int = 0
    entries_parsed: int = 0
    parse_errors: int = 0
    # Extracted data
    slow_queries: list[LogEntry] = field(default_factory=list)
    errors: list[LogEntry] = field(default_factory=list)
    warnings: list[LogEntry] = field(default_factory=list)
    query_stats: dict[str, QueryStats] = field(default_factory=dict)
    # Time range
    first_timestamp: str = ""
    last_timestamp: str = ""

    @property
    def unique_queries(self) -> int:
        return len(self.query_stats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "format_detected": self.format_detected,
            "total_lines": self.total_lines,
            "entries_parsed": self.entries_parsed,
            "parse_errors": self.parse_errors,
            "slow_queries": len(self.slow_queries),
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "unique_queries": self.unique_queries,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "top_slow_queries": [
                qs.to_dict()
                for qs in sorted(
                    self.query_stats.values(),
                    key=lambda x: x.total_duration_ms,
                    reverse=True,
                )[:20]
            ],
        }


# ── Fingerprinting ────────────────────────────────────────────────────

# Regex patterns for parameter replacement
_PARAM_PATTERNS = [
    (re.compile(r"'[^']*'"), "'?'"),                    # String literals
    (re.compile(r"\b\d+(\.\d+)?\b"), "?"),              # Numbers
    (re.compile(r"\$\d+"), "$?"),                        # Positional params
    (re.compile(r"\bIN\s*\([^)]+\)"), "IN (?)"),        # IN lists
    (re.compile(r"\s+"), " "),                           # Collapse whitespace
]


def fingerprint_query(sql: str) -> str:
    """Create a fingerprint from a SQL query by replacing literals."""
    result = sql.strip()
    for pattern, replacement in _PARAM_PATTERNS:
        result = pattern.sub(replacement, result)
    return result[:500]


# ── Log parsing ───────────────────────────────────────────────────────

# PostgreSQL stderr log line patterns
_STDERR_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(\w+)\s+"  # timezone
)
_STDERR_PREFIX = re.compile(
    r"^(?:(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[^\s]*)\s+)?"
    r"(?:\[(\d+)\]\s*)?"               # PID
    r"(?:(\w+)@(\w+)\s*)?"             # user@database
    r"(LOG|ERROR|WARNING|FATAL|PANIC|DETAIL|HINT|STATEMENT|CONTEXT):\s*(.*)"
)

# Duration line pattern: "duration: 1234.567 ms  statement: SELECT ..."
_DURATION_PATTERN = re.compile(
    r"duration:\s+([\d.]+)\s+ms"
    r"(?:\s+(?:statement|execute\s+\w+):\s+(.*))?",
    re.DOTALL,
)

# CSV log columns (PostgreSQL 10+)
CSV_COLUMNS = [
    "log_time", "user_name", "database_name", "process_id",
    "connection_from", "session_id", "session_line_num",
    "command_tag", "session_start_time", "virtual_transaction_id",
    "transaction_id", "error_severity", "sql_state_code",
    "message", "detail", "hint", "internal_query",
    "internal_query_pos", "context", "query", "query_pos",
    "location", "application_name",
]


class LogCollector:
    """Parse PostgreSQL log files and extract query performance data."""

    def __init__(
        self,
        min_duration_ms: float = 0.0,
        max_entries: int = 100_000,
    ) -> None:
        self.min_duration_ms = min_duration_ms
        self.max_entries = max_entries

    def parse_file(
        self,
        path: str | Path,
        encoding: str = "utf-8",
    ) -> CollectionResult:
        """Parse a log file, auto-detecting format."""
        path = Path(path)
        result = CollectionResult(file_path=str(path))

        if not path.exists():
            logger.error("Log file not found: %s", path)
            return result

        # Read first few lines to detect format
        with open(path, encoding=encoding, errors="replace") as f:
            sample = f.read(4096)

        if self._is_csvlog(sample):
            result.format_detected = "csvlog"
            self._parse_csvlog(path, result, encoding)
        else:
            result.format_detected = "stderr"
            self._parse_stderr(path, result, encoding)

        return result

    def parse_string(
        self,
        content: str,
        format_hint: str = "auto",
    ) -> CollectionResult:
        """Parse log content from a string."""
        result = CollectionResult(file_path="<string>")

        if format_hint == "auto":
            if self._is_csvlog(content[:4096]):
                format_hint = "csvlog"
            else:
                format_hint = "stderr"

        result.format_detected = format_hint
        if format_hint == "csvlog":
            self._parse_csvlog_string(content, result)
        else:
            self._parse_stderr_string(content, result)

        return result

    def _is_csvlog(self, sample: str) -> bool:
        """Detect if the sample looks like CSV log format."""
        try:
            reader = csv.reader(io.StringIO(sample))
            first = next(reader, None)
            return first is not None and len(first) >= 14
        except csv.Error:
            return False

    def _parse_csvlog(
        self, path: Path, result: CollectionResult, encoding: str,
    ) -> None:
        """Parse PostgreSQL CSV log format."""
        with open(path, encoding=encoding, errors="replace") as f:
            self._parse_csvlog_string(f.read(), result)

    def _parse_csvlog_string(self, content: str, result: CollectionResult) -> None:
        """Parse CSV log content."""
        reader = csv.reader(io.StringIO(content))
        for line_num, row in enumerate(reader, 1):
            result.total_lines += 1
            if result.entries_parsed >= self.max_entries:
                break

            if len(row) < 14:
                result.parse_errors += 1
                continue

            try:
                entry = LogEntry(
                    timestamp=row[0] if len(row) > 0 else "",
                    user=row[1] if len(row) > 1 else "",
                    database=row[2] if len(row) > 2 else "",
                    pid=int(row[3]) if len(row) > 3 and row[3].isdigit() else 0,
                    client_addr=row[4] if len(row) > 4 else "",
                    session_id=row[5] if len(row) > 5 else "",
                    log_level=row[11] if len(row) > 11 else "",
                    sql_state_code=row[12] if len(row) > 12 else "",
                    message=row[13] if len(row) > 13 else "",
                    detail=row[14] if len(row) > 14 else "",
                    hint=row[15] if len(row) > 15 else "",
                    query=row[19] if len(row) > 19 else "",
                    application_name=row[22] if len(row) > 22 else "",
                    line_number=line_num,
                )

                # Extract duration from message
                dur_match = _DURATION_PATTERN.search(entry.message)
                if dur_match:
                    entry.duration_ms = float(dur_match.group(1))
                    if dur_match.group(2) and not entry.query:
                        entry.query = dur_match.group(2).strip()

                self._classify_entry(entry, result)
                result.entries_parsed += 1

                # Track timestamps
                if entry.timestamp:
                    if not result.first_timestamp:
                        result.first_timestamp = entry.timestamp
                    result.last_timestamp = entry.timestamp

            except (ValueError, IndexError) as exc:
                result.parse_errors += 1
                logger.debug("CSV parse error at line %d: %s", line_num, exc)

    def _parse_stderr(
        self, path: Path, result: CollectionResult, encoding: str,
    ) -> None:
        """Parse PostgreSQL stderr log format."""
        with open(path, encoding=encoding, errors="replace") as f:
            self._parse_stderr_string(f.read(), result)

    def _parse_stderr_string(self, content: str, result: CollectionResult) -> None:
        """Parse stderr log content."""
        current_entry: LogEntry | None = None

        for line_num, line in enumerate(content.splitlines(), 1):
            result.total_lines += 1
            if result.entries_parsed >= self.max_entries:
                break

            line = line.rstrip()
            if not line:
                continue

            match = _STDERR_PREFIX.match(line)
            if match:
                # Flush previous entry
                if current_entry:
                    self._finalize_stderr_entry(current_entry, result)

                ts, pid_str, user, db, level, msg = match.groups()
                current_entry = LogEntry(
                    timestamp=ts or "",
                    pid=int(pid_str) if pid_str else 0,
                    user=user or "",
                    database=db or "",
                    log_level=level or "",
                    message=msg or "",
                    line_number=line_num,
                )
                result.entries_parsed += 1

                # Track timestamps
                if ts:
                    if not result.first_timestamp:
                        result.first_timestamp = ts
                    result.last_timestamp = ts

            elif current_entry:
                # Continuation line
                if current_entry.log_level == "STATEMENT":
                    current_entry.query += " " + line.strip()
                elif current_entry.log_level == "DETAIL":
                    current_entry.detail += " " + line.strip()
                else:
                    current_entry.message += " " + line.strip()

        # Flush last entry
        if current_entry:
            self._finalize_stderr_entry(current_entry, result)

    def _finalize_stderr_entry(
        self, entry: LogEntry, result: CollectionResult,
    ) -> None:
        """Process a complete stderr log entry."""
        # Extract duration from message
        dur_match = _DURATION_PATTERN.search(entry.message)
        if dur_match:
            entry.duration_ms = float(dur_match.group(1))
            if dur_match.group(2) and not entry.query:
                entry.query = dur_match.group(2).strip()

        self._classify_entry(entry, result)

    def _classify_entry(self, entry: LogEntry, result: CollectionResult) -> None:
        """Classify and store an entry."""
        if entry.is_error:
            result.errors.append(entry)
        elif entry.is_warning:
            result.warnings.append(entry)

        if entry.is_slow_query and entry.duration_ms >= self.min_duration_ms:
            result.slow_queries.append(entry)

            # Aggregate stats
            fp = fingerprint_query(entry.query)
            if fp not in result.query_stats:
                result.query_stats[fp] = QueryStats(fingerprint=fp)
            result.query_stats[fp].add_execution(entry)
