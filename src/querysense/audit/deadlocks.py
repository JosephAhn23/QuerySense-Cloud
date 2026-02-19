"""
Deadlock Visualizer — Parse PostgreSQL logs for deadlock events.

"ORM-heavy apps are vulnerable. ActiveRecord/Hibernate patterns hide
deadlock risks." — pganalyze blog

Parses PostgreSQL log files to:
    1. Extract deadlock events with involved processes and queries
    2. Build dependency graphs and detect cycles
    3. Identify patterns (table hotspots, consistent ordering violations)
    4. Recommend fixes (consistent lock ordering, advisory locks)

Usage:
    from querysense.audit.deadlocks import DeadlockParser

    parser = DeadlockParser()
    report = parser.analyze_file("/var/log/postgresql/postgresql.log")
    for dl in report.deadlocks:
        print(dl.summary)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from querysense.audit.log_parser import LogEvent, LogParser


@dataclass
class DeadlockProcess:
    """A process involved in a deadlock."""

    pid: int = 0
    query: str = ""
    waiting_for: str = ""  # Lock type waiting for
    holding: str = ""      # Lock type holding
    table: str = ""


@dataclass
class DeadlockEvent:
    """A single deadlock occurrence."""

    timestamp: datetime | None = None
    processes: list[DeadlockProcess] = field(default_factory=list)
    tables_involved: list[str] = field(default_factory=list)
    raw_detail: str = ""

    @property
    def summary(self) -> str:
        pids = [p.pid for p in self.processes]
        tables = ", ".join(set(self.tables_involved)) or "unknown"
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "unknown"
        return f"Deadlock at {ts}: PIDs {pids} on table(s) {tables}"

    @property
    def cycle_description(self) -> str:
        """Describe the deadlock cycle."""
        if len(self.processes) < 2:
            return "Unknown cycle"
        parts = []
        for i, p in enumerate(self.processes):
            next_p = self.processes[(i + 1) % len(self.processes)]
            parts.append(f"PID {p.pid} waiting for PID {next_p.pid}")
        return " -> ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "processes": [
                {"pid": p.pid, "query": p.query[:200], "table": p.table}
                for p in self.processes
            ],
            "tables_involved": self.tables_involved,
            "cycle": self.cycle_description,
        }


@dataclass
class DeadlockPattern:
    """A recurring deadlock pattern."""

    tables: list[str]
    occurrence_count: int
    description: str
    fix_suggestion: str


@dataclass
class DeadlockReport:
    """Complete deadlock analysis report."""

    deadlocks: list[DeadlockEvent] = field(default_factory=list)
    patterns: list[DeadlockPattern] = field(default_factory=list)
    total_count: int = 0
    tables_affected: dict[str, int] = field(default_factory=dict)
    time_range: str = ""

    @property
    def summary(self) -> str:
        if not self.deadlocks:
            return "No deadlocks found"
        tables = ", ".join(
            f"{t} ({c}x)" for t, c in
            sorted(self.tables_affected.items(), key=lambda x: -x[1])[:5]
        )
        return f"{self.total_count} deadlocks found. Hot tables: {tables}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_count": self.total_count,
            "tables_affected": self.tables_affected,
            "time_range": self.time_range,
            "deadlocks": [d.to_dict() for d in self.deadlocks],
            "patterns": [
                {"tables": p.tables, "count": p.occurrence_count,
                 "description": p.description, "fix": p.fix_suggestion}
                for p in self.patterns
            ],
        }


# Patterns for parsing deadlock details
_PROCESS_PATTERN = re.compile(
    r"Process\s+(\d+)\s+waits\s+for\s+(\w+)\s+on\s+(?:relation\s+)?(\w+)",
    re.IGNORECASE,
)
_HOLDING_PATTERN = re.compile(
    r"Process\s+(\d+)\s+holds\s+(\w+)\s+on\s+(?:relation\s+)?(\w+)",
    re.IGNORECASE,
)
_STATEMENT_PATTERN = re.compile(
    r"Process\s+(\d+).*?STATEMENT:\s*(.*?)$",
    re.IGNORECASE | re.MULTILINE,
)


class DeadlockParser:
    """
    Parse PostgreSQL logs for deadlock events and analyze patterns.

    Works with both raw log files and pre-parsed LogEvent lists.
    """

    def analyze_file(self, log_path: str | Path) -> DeadlockReport:
        """Analyze a log file for deadlocks."""
        parser = LogParser()
        events = parser.parse_file(log_path)
        return self.analyze_events(events)

    def analyze_events(self, events: list[LogEvent]) -> DeadlockReport:
        """Analyze pre-parsed log events for deadlocks."""
        report = DeadlockReport()

        deadlock_events = [e for e in events if e.is_deadlock]

        for event in deadlock_events:
            dl = self._parse_deadlock(event)
            report.deadlocks.append(dl)

            for table in dl.tables_involved:
                report.tables_affected[table] = report.tables_affected.get(table, 0) + 1

        report.total_count = len(report.deadlocks)

        if report.deadlocks:
            first = report.deadlocks[0].timestamp
            last = report.deadlocks[-1].timestamp
            if first and last:
                report.time_range = f"{first.isoformat()} to {last.isoformat()}"

        # Detect patterns
        report.patterns = self._detect_patterns(report)

        return report

    def analyze_text(self, log_text: str) -> DeadlockReport:
        """Analyze raw log text for deadlocks."""
        parser = LogParser()
        events = parser._parse_stderr(log_text)
        return self.analyze_events(events)

    def _parse_deadlock(self, event: LogEvent) -> DeadlockEvent:
        """Parse a single deadlock log event into structured data."""
        dl = DeadlockEvent(
            timestamp=event.timestamp,
            raw_detail=event.detail or event.message,
        )

        text = f"{event.message}\n{event.detail}"

        # Extract processes waiting
        for match in _PROCESS_PATTERN.finditer(text):
            pid, lock_type, table = match.groups()
            proc = DeadlockProcess(
                pid=int(pid),
                waiting_for=lock_type,
                table=table,
            )
            dl.processes.append(proc)
            if table and table not in dl.tables_involved:
                dl.tables_involved.append(table)

        # Extract processes holding
        for match in _HOLDING_PATTERN.finditer(text):
            pid, lock_type, table = match.groups()
            pid_i = int(pid)
            for proc in dl.processes:
                if proc.pid == pid_i:
                    proc.holding = lock_type
                    break

        # Extract statements
        if event.statement:
            # Associate with first process
            if dl.processes:
                dl.processes[0].query = event.statement

        # Fallback: extract table names from queries
        if not dl.tables_involved and event.statement:
            table_match = re.findall(
                r"(?:FROM|UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+(\w+)",
                event.statement,
                re.IGNORECASE,
            )
            dl.tables_involved = list(set(table_match))

        return dl

    def _detect_patterns(self, report: DeadlockReport) -> list[DeadlockPattern]:
        """Detect recurring deadlock patterns."""
        patterns: list[DeadlockPattern] = []

        # Pattern 1: Same table(s) deadlocking repeatedly
        for table, count in report.tables_affected.items():
            if count >= 2:
                patterns.append(DeadlockPattern(
                    tables=[table],
                    occurrence_count=count,
                    description=f"Table '{table}' involved in {count} deadlocks",
                    fix_suggestion=(
                        f"Ensure all transactions accessing '{table}' lock rows "
                        f"in a consistent order (e.g., ORDER BY primary key). "
                        f"Consider using advisory locks for complex transactions."
                    ),
                ))

        # Pattern 2: Multi-table deadlocks (ordering issue)
        multi_table = [d for d in report.deadlocks if len(d.tables_involved) > 1]
        if multi_table:
            table_sets: dict[str, int] = {}
            for d in multi_table:
                key = ",".join(sorted(d.tables_involved))
                table_sets[key] = table_sets.get(key, 0) + 1

            for key, count in table_sets.items():
                tables = key.split(",")
                patterns.append(DeadlockPattern(
                    tables=tables,
                    occurrence_count=count,
                    description=f"Cross-table deadlock between {', '.join(tables)}",
                    fix_suggestion=(
                        f"Always access tables in the same order: "
                        f"{' -> '.join(sorted(tables))}. "
                        f"Use SELECT ... FOR UPDATE with ORDER BY to lock rows consistently."
                    ),
                ))

        return patterns
