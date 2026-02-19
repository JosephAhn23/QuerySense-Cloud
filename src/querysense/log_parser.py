"""
PostgreSQL Log Parser — zero-connection query collection.

Parses PostgreSQL log files to extract queries, durations, and error context
WITHOUT requiring a direct database connection. This enables QuerySense to
work in restricted environments where:
- Direct DB access is not available
- Only read-only replicas are accessible
- Security policies prevent pg_stat_statements
- Audit compliance requires log-based collection

Supported log formats:
1. PostgreSQL CSV log (log_destination = 'csvlog')
2. PostgreSQL stderr/text log with configurable log_line_prefix
3. MySQL slow query log (bonus: cross-engine support)

Usage:
    from querysense.log_parser import PostgresLogParser, ParsedQuery

    parser = PostgresLogParser()
    queries = parser.parse_file("/var/log/postgresql/postgresql-16-main.csv")
    for q in queries:
        print(f"{q.duration_ms:.1f}ms: {q.query[:80]}")

    # Or from stdin (pipe from journalctl, etc.)
    import sys
    queries = parser.parse_stream(sys.stdin)
"""

from __future__ import annotations

import csv
import io
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

logger = logging.getLogger(__name__)


@dataclass
class ParsedQuery:
    """A query extracted from a PostgreSQL log file."""
    query: str
    duration_ms: float = 0.0
    timestamp: datetime | None = None
    database: str = ""
    user: str = ""
    pid: int = 0
    session_id: str = ""
    client_addr: str = ""
    error_severity: str = ""  # LOG, WARNING, ERROR, FATAL, PANIC
    sql_state: str = ""
    detail: str = ""
    hint: str = ""
    context: str = ""
    application_name: str = ""
    virtual_transaction_id: str = ""
    lock_wait_ms: float = 0.0  # From MySQL slow log
    rows_examined: int = 0  # From MySQL slow log
    rows_sent: int = 0  # From MySQL slow log
    source_file: str = ""
    source_line: int = 0

    @property
    def is_slow(self) -> bool:
        return self.duration_ms > 1000

    @property
    def is_error(self) -> bool:
        return self.error_severity in ("ERROR", "FATAL", "PANIC")

    @property
    def normalized_query(self) -> str:
        """Normalize query by replacing literals with placeholders."""
        q = self.query
        # Replace string literals
        q = re.sub(r"'[^']*'", "'$1'", q)
        # Replace numeric literals
        q = re.sub(r"\b\d+\b", "$1", q)
        # Collapse whitespace
        q = re.sub(r"\s+", " ", q).strip()
        return q


@dataclass
class LogParseResult:
    """Result of parsing a log file."""
    queries: list[ParsedQuery] = field(default_factory=list)
    errors: list[ParsedQuery] = field(default_factory=list)
    total_lines: int = 0
    parsed_lines: int = 0
    parse_errors: int = 0
    log_format: str = ""  # csv, stderr, mysql_slow
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None

    @property
    def slow_queries(self) -> list[ParsedQuery]:
        return [q for q in self.queries if q.is_slow]

    @property
    def unique_queries(self) -> int:
        return len(set(q.normalized_query for q in self.queries))

    def top_by_duration(self, n: int = 20) -> list[ParsedQuery]:
        return sorted(self.queries, key=lambda q: q.duration_ms, reverse=True)[:n]

    def top_by_frequency(self, n: int = 20) -> list[tuple[str, int, float]]:
        """Returns (normalized_query, count, avg_duration_ms)."""
        from collections import defaultdict
        groups: dict[str, list[float]] = defaultdict(list)
        for q in self.queries:
            groups[q.normalized_query].append(q.duration_ms)
        result = [
            (query, len(durations), sum(durations) / len(durations))
            for query, durations in groups.items()
        ]
        return sorted(result, key=lambda x: x[1], reverse=True)[:n]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "total_queries": len(self.queries),
            "total_errors": len(self.errors),
            "slow_queries": len(self.slow_queries),
            "unique_queries": self.unique_queries,
            "log_format": self.log_format,
            "time_range": {
                "start": self.time_range_start.isoformat() if self.time_range_start else None,
                "end": self.time_range_end.isoformat() if self.time_range_end else None,
            },
        }


class PostgresLogParser:
    """
    Parse PostgreSQL log files (CSV and stderr formats).

    CSV format (log_destination = 'csvlog'):
        Columns: timestamp, user, database, pid, connection_from,
                 session_id, session_line_num, command_tag, session_start,
                 virtual_transaction_id, transaction_id, error_severity,
                 sql_state_code, message, detail, hint, internal_query,
                 internal_query_pos, context, query, query_pos,
                 location, application_name, backend_type (PG 14+),
                 leader_pid (PG 14+), query_id (PG 14+)

    Stderr format:
        Parsed using log_line_prefix patterns to extract metadata.
    """

    # Default log_line_prefix: '%m [%p] %q%u@%d '
    DEFAULT_PREFIX_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.\d]*\s*\w*)"
        r"\s+\[(?P<pid>\d+)\]\s+"
        r"(?:(?P<user>\w+)@(?P<database>\w+)\s+)?"
    )

    # Duration pattern from log_min_duration_statement
    DURATION_PATTERN = re.compile(
        r"duration:\s+(?P<duration>[\d.]+)\s+ms"
    )

    # Statement/query pattern
    STATEMENT_PATTERN = re.compile(
        r"(?:statement|execute\s+\w+):\s*(?P<query>.+)",
        re.DOTALL | re.IGNORECASE,
    )

    def parse_file(
        self,
        path: str | Path,
        encoding: str = "utf-8",
    ) -> LogParseResult:
        """Parse a PostgreSQL log file (auto-detects CSV vs stderr)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        # Detect format from extension or first line
        if p.suffix.lower() == ".csv":
            return self._parse_csv(p, encoding)

        # Try to detect CSV by reading first line
        with open(p, encoding=encoding, errors="replace") as f:
            first_line = f.readline()
            f.seek(0)

            # CSV logs have many commas and start with a timestamp
            if first_line.count(",") >= 10 and re.match(r"\d{4}-\d{2}-\d{2}", first_line):
                return self._parse_csv_stream(f, str(p))
            else:
                return self._parse_stderr_stream(f, str(p))

    def parse_stream(
        self,
        stream: TextIO,
        format: str = "auto",
    ) -> LogParseResult:
        """Parse a log stream (stdin, pipe, etc.)."""
        if format == "csv":
            return self._parse_csv_stream(stream)
        elif format == "stderr":
            return self._parse_stderr_stream(stream)
        else:
            # Auto-detect: read first line
            first_line = stream.readline()
            rest = io.StringIO(first_line + stream.read())
            if first_line.count(",") >= 10:
                return self._parse_csv_stream(rest)
            return self._parse_stderr_stream(rest)

    def _parse_csv(self, path: Path, encoding: str) -> LogParseResult:
        """Parse a PostgreSQL CSV log file."""
        with open(path, encoding=encoding, errors="replace") as f:
            return self._parse_csv_stream(f, str(path))

    def _parse_csv_stream(
        self,
        stream: TextIO,
        source: str = "<stream>",
    ) -> LogParseResult:
        """Parse CSV log from a stream."""
        result = LogParseResult(log_format="csv")

        reader = csv.reader(stream)
        for row in reader:
            result.total_lines += 1
            try:
                if len(row) < 14:
                    result.parse_errors += 1
                    continue

                # PostgreSQL CSV log columns (0-indexed):
                # 0: timestamp, 1: user, 2: database, 3: pid,
                # 4: connection_from, 5: session_id, 6: session_line_num,
                # 7: command_tag, 8: session_start, 9: virtual_transaction_id,
                # 10: transaction_id, 11: error_severity, 12: sql_state_code,
                # 13: message
                timestamp_str = row[0]
                user = row[1]
                database = row[2]
                pid = int(row[3]) if row[3] else 0
                client_addr = row[4]
                session_id = row[5]
                error_severity = row[11]
                sql_state = row[12]
                message = row[13]
                detail = row[14] if len(row) > 14 else ""
                hint = row[15] if len(row) > 15 else ""
                context = row[18] if len(row) > 18 else ""
                query_text = row[19] if len(row) > 19 else ""
                app_name = row[22] if len(row) > 22 else ""
                vxid = row[9]

                # Parse timestamp
                ts = self._parse_timestamp(timestamp_str)
                if ts:
                    if not result.time_range_start or ts < result.time_range_start:
                        result.time_range_start = ts
                    if not result.time_range_end or ts > result.time_range_end:
                        result.time_range_end = ts

                # Extract duration from message
                duration = 0.0
                dur_match = self.DURATION_PATTERN.search(message)
                if dur_match:
                    duration = float(dur_match.group("duration"))

                # Extract query from message if not in query column
                query = query_text or ""
                if not query:
                    stmt_match = self.STATEMENT_PATTERN.search(message)
                    if stmt_match:
                        query = stmt_match.group("query").strip()

                if not query and "duration:" in message and "statement:" in message:
                    # "duration: 1.234 ms  statement: SELECT ..."
                    parts = message.split("statement:", 1)
                    if len(parts) == 2:
                        query = parts[1].strip()

                if query:
                    parsed = ParsedQuery(
                        query=query,
                        duration_ms=duration,
                        timestamp=ts,
                        database=database,
                        user=user,
                        pid=pid,
                        session_id=session_id,
                        client_addr=client_addr,
                        error_severity=error_severity,
                        sql_state=sql_state,
                        detail=detail,
                        hint=hint,
                        context=context,
                        application_name=app_name,
                        virtual_transaction_id=vxid,
                        source_file=source,
                        source_line=result.total_lines,
                    )
                    result.parsed_lines += 1

                    if parsed.is_error:
                        result.errors.append(parsed)
                    else:
                        result.queries.append(parsed)

            except Exception as e:
                result.parse_errors += 1
                logger.debug("Parse error on line %d: %s", result.total_lines, e)

        return result

    def _parse_stderr_stream(
        self,
        stream: TextIO,
        source: str = "<stream>",
    ) -> LogParseResult:
        """Parse stderr-format PostgreSQL log."""
        result = LogParseResult(log_format="stderr")
        current_entry: dict[str, Any] = {}
        current_message_lines: list[str] = []

        def flush_entry() -> None:
            if current_entry and current_message_lines:
                message = "\n".join(current_message_lines)
                duration = 0.0
                dur_match = self.DURATION_PATTERN.search(message)
                if dur_match:
                    duration = float(dur_match.group("duration"))

                query = ""
                stmt_match = self.STATEMENT_PATTERN.search(message)
                if stmt_match:
                    query = stmt_match.group("query").strip()
                elif "duration:" in message and "statement:" in message:
                    parts = message.split("statement:", 1)
                    if len(parts) == 2:
                        query = parts[1].strip()

                if query or duration > 0:
                    parsed = ParsedQuery(
                        query=query or message[:200],
                        duration_ms=duration,
                        timestamp=current_entry.get("timestamp"),
                        database=current_entry.get("database", ""),
                        user=current_entry.get("user", ""),
                        pid=current_entry.get("pid", 0),
                        source_file=source,
                    )
                    result.parsed_lines += 1
                    if parsed.is_error:
                        result.errors.append(parsed)
                    else:
                        result.queries.append(parsed)

        for line in stream:
            result.total_lines += 1
            line = line.rstrip("\n\r")

            # Try to match a new log line
            match = self.DEFAULT_PREFIX_PATTERN.match(line)
            if match:
                # Flush previous entry
                flush_entry()
                current_entry = {
                    "timestamp": self._parse_timestamp(match.group("timestamp")),
                    "pid": int(match.group("pid")) if match.group("pid") else 0,
                    "user": match.group("user") or "",
                    "database": match.group("database") or "",
                }

                ts = current_entry["timestamp"]
                if ts:
                    if not result.time_range_start or ts < result.time_range_start:
                        result.time_range_start = ts
                    if not result.time_range_end or ts > result.time_range_end:
                        result.time_range_end = ts

                remainder = line[match.end():]
                current_message_lines = [remainder] if remainder else []
            else:
                # Continuation line
                current_message_lines.append(line)

        flush_entry()  # Final entry
        return result

    def _parse_timestamp(self, ts_str: str) -> datetime | None:
        """Parse various PostgreSQL timestamp formats."""
        ts_str = ts_str.strip()
        formats = [
            "%Y-%m-%d %H:%M:%S.%f %Z",
            "%Y-%m-%d %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        # Try ISO format
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            return None


class MySQLSlowLogParser:
    """
    Parse MySQL slow query log for cross-engine support.

    MySQL slow query log format:
        # Time: 2026-01-15T10:30:00.000000Z
        # User@Host: root[root] @ localhost [127.0.0.1]  Id:    10
        # Query_time: 2.000134  Lock_time: 0.000000 Rows_sent: 1  Rows_examined: 100000
        SET timestamp=1737017400;
        SELECT * FROM users WHERE status = 'active';
    """

    TIME_PATTERN = re.compile(r"# Time:\s+(.+)")
    USER_PATTERN = re.compile(r"# User@Host:\s+(\w+)\[.*\]\s*@\s*(\S+)")
    METRICS_PATTERN = re.compile(
        r"# Query_time:\s+([\d.]+)\s+Lock_time:\s+([\d.]+)\s+"
        r"Rows_sent:\s+(\d+)\s+Rows_examined:\s+(\d+)"
    )

    def parse_file(
        self,
        path: str | Path,
        encoding: str = "utf-8",
    ) -> LogParseResult:
        """Parse a MySQL slow query log file."""
        with open(path, encoding=encoding, errors="replace") as f:
            return self._parse_stream(f, str(path))

    def _parse_stream(
        self,
        stream: TextIO,
        source: str = "<stream>",
    ) -> LogParseResult:
        result = LogParseResult(log_format="mysql_slow")

        current_ts: datetime | None = None
        current_user: str = ""
        current_host: str = ""
        current_duration: float = 0.0
        current_lock: float = 0.0
        current_rows_sent: int = 0
        current_rows_examined: int = 0
        query_lines: list[str] = []

        def flush() -> None:
            nonlocal current_ts, current_user, current_host
            nonlocal current_duration, current_lock
            nonlocal current_rows_sent, current_rows_examined, query_lines

            query = "\n".join(query_lines).strip()
            # Remove SET timestamp=...;
            query = re.sub(r"SET\s+timestamp=\d+;\s*", "", query, flags=re.IGNORECASE).strip()

            if query:
                result.queries.append(ParsedQuery(
                    query=query,
                    duration_ms=current_duration * 1000,
                    timestamp=current_ts,
                    user=current_user,
                    client_addr=current_host,
                    lock_wait_ms=current_lock * 1000,
                    rows_sent=current_rows_sent,
                    rows_examined=current_rows_examined,
                    source_file=source,
                ))
                result.parsed_lines += 1

            query_lines = []
            current_duration = 0.0
            current_lock = 0.0
            current_rows_sent = 0
            current_rows_examined = 0

        for line in stream:
            result.total_lines += 1
            line = line.rstrip("\n\r")

            time_match = self.TIME_PATTERN.match(line)
            if time_match:
                flush()
                ts_str = time_match.group(1).strip()
                try:
                    current_ts = datetime.fromisoformat(
                        ts_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    current_ts = None

                if current_ts:
                    if not result.time_range_start or current_ts < result.time_range_start:
                        result.time_range_start = current_ts
                    if not result.time_range_end or current_ts > result.time_range_end:
                        result.time_range_end = current_ts
                continue

            user_match = self.USER_PATTERN.match(line)
            if user_match:
                current_user = user_match.group(1)
                current_host = user_match.group(2)
                continue

            metrics_match = self.METRICS_PATTERN.match(line)
            if metrics_match:
                current_duration = float(metrics_match.group(1))
                current_lock = float(metrics_match.group(2))
                current_rows_sent = int(metrics_match.group(3))
                current_rows_examined = int(metrics_match.group(4))
                continue

            # Skip MySQL header lines
            if line.startswith("#") or line.startswith("/"):
                continue

            # Query line
            if line.strip():
                query_lines.append(line)

        flush()  # Final entry
        return result
