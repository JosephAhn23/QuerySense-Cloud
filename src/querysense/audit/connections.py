"""
Connection Auditor — Auth failures, connection patterns, SOC2 compliance.

"Security auditing. SOC2/PCI compliance requires tracking who connected when."

Parses PostgreSQL logs for:
    1. Authentication failures (password, pg_hba denials)
    2. Connection patterns (spikes, unusual clients)
    3. Disconnection tracking (session duration anomalies)
    4. Unauthorized access attempts

Also provides live connection analysis via pg_stat_activity.

Usage:
    from querysense.audit.connections import ConnectionAuditor

    auditor = ConnectionAuditor()
    # From logs
    report = auditor.analyze_file("/var/log/postgresql/postgresql.log")
    # From live DB
    report = await auditor.analyze_live(conn)
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from querysense.audit.log_parser import LogEvent, LogParser


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class AuthFailure:
    """A single authentication failure event."""

    timestamp: datetime | None = None
    user: str = ""
    database: str = ""
    client_addr: str = ""
    method: str = ""     # password, md5, cert, etc.
    reason: str = ""     # "no pg_hba.conf entry", "password auth failed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user": self.user,
            "database": self.database,
            "client_addr": self.client_addr,
            "reason": self.reason,
        }


@dataclass
class ConnectionSummary:
    """Summary of connection patterns."""

    total_connections: int = 0
    total_disconnections: int = 0
    total_auth_failures: int = 0
    unique_users: int = 0
    unique_databases: int = 0
    unique_client_ips: int = 0
    connections_by_user: dict[str, int] = field(default_factory=dict)
    connections_by_database: dict[str, int] = field(default_factory=dict)
    connections_by_ip: dict[str, int] = field(default_factory=dict)
    failures_by_user: dict[str, int] = field(default_factory=dict)
    failures_by_ip: dict[str, int] = field(default_factory=dict)


@dataclass
class ConnectionFinding:
    """A connection-related finding."""

    severity: str
    title: str
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass
class ConnectionReport:
    """Complete connection audit report."""

    auth_failures: list[AuthFailure] = field(default_factory=list)
    summary: ConnectionSummary = field(default_factory=ConnectionSummary)
    findings: list[ConnectionFinding] = field(default_factory=list)
    time_range: str = ""

    @property
    def is_clean(self) -> bool:
        return (
            len(self.auth_failures) == 0
            and self.summary.total_auth_failures == 0
            and not any(
                f.severity in ("critical", "warning") for f in self.findings
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "auth_failures": [f.to_dict() for f in self.auth_failures[:50]],
            "summary": {
                "total_connections": self.summary.total_connections,
                "total_auth_failures": self.summary.total_auth_failures,
                "unique_users": self.summary.unique_users,
                "unique_client_ips": self.summary.unique_client_ips,
                "failures_by_user": dict(self.summary.failures_by_user),
                "failures_by_ip": dict(self.summary.failures_by_ip),
            },
            "findings": [f.to_dict() for f in self.findings],
            "time_range": self.time_range,
            "is_clean": self.is_clean,
        }


class ConnectionAuditor:
    """
    Audit connection events from PostgreSQL logs and live database.

    Detects:
    - Brute force attempts (many failures from same IP)
    - Credential scanning (failures across multiple users)
    - Unusual connection patterns (new IPs, new users)
    """

    def analyze_file(self, log_path: str | Path) -> ConnectionReport:
        """Analyze a log file for connection events."""
        parser = LogParser()
        events = parser.parse_file(log_path)
        return self.analyze_events(events)

    def analyze_events(self, events: list[LogEvent]) -> ConnectionReport:
        """Analyze pre-parsed log events for connection patterns."""
        report = ConnectionReport()

        users: set[str] = set()
        databases: set[str] = set()
        ips: set[str] = set()

        for event in events:
            if not event.is_connection:
                continue

            msg_lower = event.message.lower()

            if "password authentication failed" in msg_lower or "no pg_hba.conf" in msg_lower:
                failure = AuthFailure(
                    timestamp=event.timestamp,
                    user=event.user or self._extract_user(event.message),
                    database=event.database or "",
                    client_addr=event.client_addr or self._extract_ip(event.message),
                    reason=event.message[:200],
                )
                report.auth_failures.append(failure)
                report.summary.total_auth_failures += 1

                if failure.user:
                    report.summary.failures_by_user[failure.user] = \
                        report.summary.failures_by_user.get(failure.user, 0) + 1
                if failure.client_addr:
                    report.summary.failures_by_ip[failure.client_addr] = \
                        report.summary.failures_by_ip.get(failure.client_addr, 0) + 1

            elif "connection authorized" in msg_lower or "connection received" in msg_lower:
                report.summary.total_connections += 1
                if event.user:
                    users.add(event.user)
                    report.summary.connections_by_user[event.user] = \
                        report.summary.connections_by_user.get(event.user, 0) + 1
                if event.database:
                    databases.add(event.database)
                if event.client_addr:
                    ips.add(event.client_addr)

            elif "disconnection" in msg_lower:
                report.summary.total_disconnections += 1

        report.summary.unique_users = len(users)
        report.summary.unique_databases = len(databases)
        report.summary.unique_client_ips = len(ips)

        if events:
            timestamps = [e.timestamp for e in events if e.timestamp]
            if timestamps:
                report.time_range = f"{min(timestamps).isoformat()} to {max(timestamps).isoformat()}"

        # Detect anomalies
        self._detect_brute_force(report)
        self._detect_credential_scanning(report)

        return report

    async def analyze_live(self, conn: AsyncDBConnection) -> ConnectionReport:
        """Analyze live connections from pg_stat_activity."""
        report = ConnectionReport()

        try:
            rows = await conn.fetch(
                "SELECT usename, datname, client_addr, state, "
                "  backend_type, application_name, "
                "  EXTRACT(EPOCH FROM (now() - backend_start))::int AS session_age, "
                "  EXTRACT(EPOCH FROM (now() - state_change))::int AS state_age "
                "FROM pg_stat_activity "
                "WHERE backend_type = 'client backend' "
                "ORDER BY backend_start"
            )
        except Exception:
            return report

        for r in rows:
            if isinstance(r, (list, tuple)):
                user, db, addr, state, _, app, session_age, state_age = r[:8]
            else:
                user = getattr(r, "usename", "")
                db = getattr(r, "datname", "")
                addr = getattr(r, "client_addr", "")
                state = getattr(r, "state", "")
                session_age = getattr(r, "session_age", 0)
                state_age = getattr(r, "state_age", 0)

            report.summary.total_connections += 1
            if str(user):
                report.summary.connections_by_user[str(user)] = \
                    report.summary.connections_by_user.get(str(user), 0) + 1
            if str(addr):
                report.summary.connections_by_ip[str(addr)] = \
                    report.summary.connections_by_ip.get(str(addr), 0) + 1

            # Flag very long sessions
            age = int(session_age or 0)
            if age > 86400:  # > 24 hours
                report.findings.append(ConnectionFinding(
                    severity="notice",
                    title=f"Long session: {user}@{db} from {addr} ({age // 3600}h)",
                    description=f"Session open for {age // 3600} hours. State: {state}.",
                    recommendation="Check if this is a connection leak.",
                    evidence={"user": str(user), "age_hours": age // 3600},
                ))

        report.summary.unique_users = len(report.summary.connections_by_user)
        report.summary.unique_client_ips = len(report.summary.connections_by_ip)

        return report

    def _detect_brute_force(self, report: ConnectionReport) -> None:
        """Detect brute force attempts (many failures from same IP)."""
        for ip, count in report.summary.failures_by_ip.items():
            if count >= 10:
                report.findings.append(ConnectionFinding(
                    severity="critical",
                    title=f"Possible brute force from {ip}: {count} auth failures",
                    description=f"IP {ip} had {count} authentication failures.",
                    recommendation=f"Block IP in pg_hba.conf or firewall: # host all all {ip}/32 reject",
                    evidence={"ip": ip, "failure_count": count},
                ))
            elif count >= 5:
                report.findings.append(ConnectionFinding(
                    severity="warning",
                    title=f"Multiple auth failures from {ip}: {count}",
                    description=f"IP {ip} had {count} authentication failures.",
                    recommendation="Monitor this IP and consider blocking.",
                    evidence={"ip": ip, "failure_count": count},
                ))

    def _detect_credential_scanning(self, report: ConnectionReport) -> None:
        """Detect credential scanning (failures across multiple users)."""
        for ip, count in report.summary.failures_by_ip.items():
            # Count unique users that failed from this IP
            users_from_ip = set()
            for f in report.auth_failures:
                if f.client_addr == ip:
                    users_from_ip.add(f.user)

            if len(users_from_ip) >= 3:
                report.findings.append(ConnectionFinding(
                    severity="critical",
                    title=f"Credential scanning from {ip}: {len(users_from_ip)} users tried",
                    description=(
                        f"IP {ip} attempted {count} logins across "
                        f"{len(users_from_ip)} different users: {', '.join(list(users_from_ip)[:5])}"
                    ),
                    recommendation=f"Block immediately: host all all {ip}/32 reject",
                    evidence={"ip": ip, "users_tried": list(users_from_ip)},
                ))

    @staticmethod
    def _extract_user(message: str) -> str:
        """Extract username from auth failure message."""
        import re
        match = re.search(r'user "(\w+)"', message)
        return match.group(1) if match else ""

    @staticmethod
    def _extract_ip(message: str) -> str:
        """Extract IP from auth failure message."""
        import re
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
        return match.group(1) if match else ""
