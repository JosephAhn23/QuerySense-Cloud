"""
Auto-explain log parser for PostgreSQL.

Parses query plans captured by PostgreSQL's auto_explain module from
log files, enabling continuous plan analysis without manual EXPLAIN.
Closes the gap vs pganalyze's Log Insights with auto_explain integration.

auto_explain configuration (postgresql.conf):
    shared_preload_libraries = 'auto_explain'
    auto_explain.log_min_duration = '100ms'  # Log plans for queries >100ms
    auto_explain.log_format = 'json'         # JSON is best for parsing
    auto_explain.log_analyze = true           # Include actual execution stats
    auto_explain.log_buffers = true
    auto_explain.log_timing = true

Usage:
    from querysense.auto_explain_parser import parse_auto_explain_log

    entries = parse_auto_explain_log("/var/log/postgresql/postgresql.log")
    for entry in entries:
        print(f"Query: {entry.query[:80]}...")
        print(f"Duration: {entry.duration_ms}ms")
        # entry.plan is ready for QuerySense analysis
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


@dataclass
class AutoExplainEntry:
    """A single auto_explain log entry."""

    timestamp: str = ""
    database: str = ""
    username: str = ""
    pid: int = 0
    query: str = ""
    duration_ms: float = 0.0
    plan: dict[str, Any] | None = None
    plan_text: str = ""
    log_line: int = 0

    @property
    def has_json_plan(self) -> bool:
        return self.plan is not None

    @property
    def is_slow(self) -> bool:
        return self.duration_ms > 1000

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "database": self.database,
            "username": self.username,
            "pid": self.pid,
            "query": self.query[:500],
            "duration_ms": self.duration_ms,
            "has_plan": self.has_json_plan,
            "log_line": self.log_line,
        }


# ── Log line patterns ────────────────────────────────────────────────

# Standard PostgreSQL log prefix pattern
# Example: 2026-02-13 10:30:45.123 UTC [12345] user@db LOG:
_LOG_PREFIX = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*\s*\w*)"  # timestamp
    r"\s+\[(\d+)\]"  # PID
    r"\s+(\w+)@(\w+)"  # user@db
    r"\s+LOG:\s+",
)

# auto_explain duration line
# Example: LOG: duration: 523.456 ms  plan:
_DURATION_PATTERN = re.compile(
    r"duration:\s+([\d.]+)\s+ms\s+plan:"
)

# auto_explain query pattern
# Example: LOG: duration: 523.456 ms  statement: SELECT ...
_STATEMENT_PATTERN = re.compile(
    r"duration:\s+([\d.]+)\s+ms\s+statement:\s+(.*)"
)

# csvlog format
_CSVLOG_PATTERN = re.compile(
    r'^"?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*\s*\w*)"?,'  # timestamp
)


def parse_auto_explain_log(
    log_path: str | Path,
    min_duration_ms: float = 0.0,
    max_entries: int = 10000,
) -> list[AutoExplainEntry]:
    """
    Parse a PostgreSQL log file for auto_explain entries.

    Supports:
    - Standard PostgreSQL log format
    - JSON plan format (auto_explain.log_format = 'json')
    - Text plan format (auto_explain.log_format = 'text')

    Args:
        log_path: Path to the PostgreSQL log file
        min_duration_ms: Only include entries slower than this
        max_entries: Maximum entries to parse

    Returns:
        List of AutoExplainEntry objects with plans ready for analysis
    """
    path = Path(log_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    entries: list[AutoExplainEntry] = []
    current_entry: AutoExplainEntry | None = None
    json_buffer: list[str] = []
    in_json_plan = False
    in_text_plan = False
    text_plan_lines: list[str] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            if len(entries) >= max_entries:
                break

            # Check for new log entry (with prefix)
            prefix_match = _LOG_PREFIX.match(line)
            if prefix_match:
                # Save previous entry
                if current_entry and in_json_plan and json_buffer:
                    _finalize_json_plan(current_entry, json_buffer)
                    if current_entry.duration_ms >= min_duration_ms:
                        entries.append(current_entry)
                elif current_entry and in_text_plan and text_plan_lines:
                    current_entry.plan_text = "\n".join(text_plan_lines)
                    if current_entry.duration_ms >= min_duration_ms:
                        entries.append(current_entry)

                json_buffer = []
                text_plan_lines = []
                in_json_plan = False
                in_text_plan = False

                remaining = line[prefix_match.end():]

                # Check for duration + plan
                dur_match = _DURATION_PATTERN.search(remaining)
                if dur_match:
                    current_entry = AutoExplainEntry(
                        timestamp=prefix_match.group(1).strip(),
                        pid=int(prefix_match.group(2)),
                        username=prefix_match.group(3),
                        database=prefix_match.group(4),
                        duration_ms=float(dur_match.group(1)),
                        log_line=line_num,
                    )
                    # Check if JSON plan starts on same line
                    after_plan = remaining[dur_match.end():].strip()
                    if after_plan.startswith("[") or after_plan.startswith("{"):
                        in_json_plan = True
                        json_buffer.append(after_plan)
                    else:
                        in_text_plan = True
                        if after_plan:
                            text_plan_lines.append(after_plan)
                    continue

                # Check for statement
                stmt_match = _STATEMENT_PATTERN.search(remaining)
                if stmt_match and current_entry:
                    current_entry.query = stmt_match.group(2).strip()
                    continue

                current_entry = None
                continue

            # Continuation lines (part of plan or query)
            if current_entry:
                stripped = line.strip()
                if in_json_plan:
                    json_buffer.append(stripped)
                elif in_text_plan:
                    if stripped:
                        text_plan_lines.append(stripped)

    # Finalize last entry
    if current_entry and in_json_plan and json_buffer:
        _finalize_json_plan(current_entry, json_buffer)
        if current_entry.duration_ms >= min_duration_ms:
            entries.append(current_entry)
    elif current_entry and in_text_plan and text_plan_lines:
        current_entry.plan_text = "\n".join(text_plan_lines)
        if current_entry.duration_ms >= min_duration_ms:
            entries.append(current_entry)

    return entries


def parse_auto_explain_jsonl(
    log_path: str | Path,
    min_duration_ms: float = 0.0,
    max_entries: int = 10000,
) -> list[AutoExplainEntry]:
    """
    Parse a JSON-line format auto_explain output.

    Some setups output one JSON object per line (e.g., via pgBadger
    preprocessing or custom log_line_prefix).
    """
    path = Path(log_path).expanduser()
    entries: list[AutoExplainEntry] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            if len(entries) >= max_entries:
                break
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                entry = _parse_json_entry(data, line_num)
                if entry and entry.duration_ms >= min_duration_ms:
                    entries.append(entry)
            except json.JSONDecodeError:
                continue

    return entries


def _finalize_json_plan(entry: AutoExplainEntry, buffer: list[str]) -> None:
    """Parse accumulated JSON lines into a plan dict."""
    text = "\n".join(buffer)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list) and parsed:
            entry.plan = parsed[0] if isinstance(parsed[0], dict) else {"Plan": parsed[0]}
        elif isinstance(parsed, dict):
            entry.plan = parsed
    except json.JSONDecodeError:
        entry.plan_text = text


def _parse_json_entry(data: dict[str, Any], line_num: int) -> AutoExplainEntry | None:
    """Parse a single JSON auto_explain entry."""
    if "Plan" not in data and "plan" not in data:
        return None

    plan = data.get("Plan") or data.get("plan")
    if isinstance(plan, str):
        try:
            plan = json.loads(plan)
        except json.JSONDecodeError:
            return None

    return AutoExplainEntry(
        timestamp=data.get("timestamp", ""),
        database=data.get("database", data.get("db", "")),
        username=data.get("user", data.get("username", "")),
        pid=data.get("pid", 0),
        query=data.get("query", data.get("statement", ""))[:1000],
        duration_ms=data.get("duration", data.get("duration_ms", 0.0)),
        plan={"Plan": plan} if isinstance(plan, dict) else plan,
        log_line=line_num,
    )


def analyze_auto_explain_entries(
    entries: list[AutoExplainEntry],
) -> list[dict[str, Any]]:
    """
    Run QuerySense analysis on all auto_explain entries with JSON plans.

    Returns a list of analysis summaries for each entry.
    """
    from querysense.engine import AnalysisService
    from querysense.parser.parser import parse_explain

    service = AnalysisService()
    results: list[dict[str, Any]] = []

    for entry in entries:
        if not entry.has_json_plan:
            continue

        try:
            explain = parse_explain(entry.plan)
            result = service.analyze(explain, sql=entry.query or None)
            summary = result.summary()
            results.append({
                **entry.to_dict(),
                "findings_total": summary["total"],
                "findings_critical": summary["critical"],
                "findings_warning": summary["warning"],
                "top_finding": (
                    result.findings[0].title if result.findings else None
                ),
            })
        except Exception as e:
            results.append({
                **entry.to_dict(),
                "error": str(e),
            })

    return results
