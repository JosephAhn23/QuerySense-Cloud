"""
SOC2-compliant audit logging for QuerySense.

Every sensitive operation gets an immutable audit trail:
- Plan analysis (who, when, plan hash, findings count)
- Migration execution (who, SQL hash, rollback hash, status)
- Config changes (who, parameter, old/new value)
- Authentication events (login, logout, token refresh)
- Data access (plan views, report downloads)

Logs are structured JSON (structlog-compatible) for shipping to
SIEM systems (Splunk, ELK, Datadog Logs, CloudWatch).

Usage:
    from querysense.audit import AuditLogger

    audit = AuditLogger()
    audit.log_analysis(user_id="user-123", plan_hash="abc", findings_count=5)
    audit.log_migration(user_id="user-123", sql="ALTER TABLE ...", status="success")

    # Get audit trail for compliance reports
    events = audit.get_events(user_id="user-123", since=datetime(2026, 1, 1))
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class AuditEventType(str, Enum):
    """Types of auditable events."""
    PLAN_ANALYZED = "plan.analyzed"
    PLAN_COMPARED = "plan.compared"
    MIGRATION_EXECUTED = "migration.executed"
    MIGRATION_ROLLED_BACK = "migration.rolled_back"
    CONFIG_CHANGED = "config.changed"
    SCHEMA_SNAPSHOT = "schema.snapshot"
    SCHEMA_DRIFT_DETECTED = "schema.drift_detected"
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    REPORT_GENERATED = "report.generated"
    REPORT_EXPORTED = "report.exported"
    POLICY_VIOLATION = "policy.violation"
    BUDGET_CHECK = "budget.check"
    HEALTH_CHECK = "health.check"
    IMPORT_COMPLETED = "import.completed"


@dataclass
class AuditEvent:
    """A single audit log entry with optional chain validation."""
    event_type: AuditEventType
    timestamp: str              # ISO 8601
    user_id: str = ""
    workspace_id: str = ""
    resource_type: str = ""     # plan, migration, config, etc.
    resource_id: str = ""       # plan hash, migration id, etc.
    action: str = ""            # analyze, execute, compare, etc.
    status: str = "success"     # success, failure, denied
    details: dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    duration_ms: float = 0.0
    correlation_id: str = ""    # For tracing across services
    previous_hash: str = ""     # Hash of preceding event (chain link)
    event_hash: str = ""        # HMAC of this event (tamper evidence)

    def compute_hash(self, secret: bytes = b"querysense-audit") -> str:
        """Compute HMAC-SHA256 of this event's content for tamper detection."""
        import hmac as _hmac
        payload = {
            "event_type": self.event_type.value if isinstance(self.event_type, AuditEventType) else str(self.event_type),
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "status": self.status,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }
        return _hmac.new(
            secret,
            json.dumps(payload, sort_keys=True).encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify_chain(self, previous_event: "AuditEvent", secret: bytes = b"querysense-audit") -> bool:
        """Verify this event correctly chains to the previous event."""
        if self.previous_hash != previous_event.event_hash:
            return False
        return self.event_hash == self.compute_hash(secret)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value if isinstance(self.event_type, AuditEventType) else str(self.event_type),
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "status": self.status,
            "details": self.details,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "duration_ms": self.duration_ms,
            "correlation_id": self.correlation_id,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Structured audit logger for SOC2 compliance with hash chain validation.

    Writes JSON-structured audit events to:
    1. Python logging (ships to SIEM via log handlers)
    2. Optional file-based audit trail (append-only)
    3. Optional callback for real-time processing

    Each event includes an HMAC-SHA256 hash and a pointer to the previous
    event's hash, forming an immutable, tamper-evident chain.
    """

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        log_file: str | Path | None = None,
        logger_name: str = "querysense.audit",
        callback: Any = None,
        secret: bytes = b"querysense-audit",
    ):
        self._logger = logging.getLogger(logger_name)
        self._log_file = Path(log_file) if log_file else None
        self._callback = callback
        self._secret = secret
        self._events: list[AuditEvent] = []
        self._last_hash: str = self.GENESIS_HASH

        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            self._last_hash = self._read_last_hash()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _hash(self, data: str) -> str:
        """Hash sensitive data for audit trail without storing raw content."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]

    def _emit(self, event: AuditEvent) -> None:
        """Emit an audit event with chain hash to all configured sinks."""
        event.previous_hash = self._last_hash
        event.event_hash = event.compute_hash(self._secret)
        self._last_hash = event.event_hash

        self._events.append(event)

        self._logger.info(
            "audit_event",
            extra={"audit": event.to_dict()},
        )

        if self._log_file:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")

        if self._callback:
            try:
                self._callback(event)
            except Exception:
                pass

    def _read_last_hash(self) -> str:
        """Read the last event hash from the log file to resume the chain."""
        if not self._log_file or not self._log_file.exists():
            return self.GENESIS_HASH
        try:
            with open(self._log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if not lines:
                    return self.GENESIS_HASH
                last = json.loads(lines[-1])
                return last.get("event_hash", self.GENESIS_HASH)
        except Exception:
            return self.GENESIS_HASH

    def verify_chain(self) -> tuple[bool, int, list[str]]:
        """
        Verify the integrity of the entire event chain.

        Returns (is_valid, events_checked, list_of_errors).
        """
        errors: list[str] = []
        expected_prev = self.GENESIS_HASH

        for i, event in enumerate(self._events):
            if event.previous_hash != expected_prev:
                errors.append(
                    f"Event {i}: previous_hash mismatch "
                    f"(expected {expected_prev[:12]}..., got {event.previous_hash[:12]}...)"
                )
            computed = event.compute_hash(self._secret)
            if event.event_hash != computed:
                errors.append(
                    f"Event {i}: event_hash tampered "
                    f"(stored {event.event_hash[:12]}..., computed {computed[:12]}...)"
                )
            expected_prev = event.event_hash

        return len(errors) == 0, len(self._events), errors

    def verify_file_chain(self) -> tuple[bool, int, list[str]]:
        """Verify chain integrity from the log file on disk."""
        if not self._log_file or not self._log_file.exists():
            return True, 0, []

        errors: list[str] = []
        expected_prev = self.GENESIS_HASH
        count = 0

        with open(self._log_file, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    errors.append(f"Line {i}: invalid JSON")
                    continue

                count += 1
                stored_prev = data.get("previous_hash", "")
                stored_hash = data.get("event_hash", "")

                if stored_prev != expected_prev:
                    errors.append(
                        f"Line {i}: previous_hash mismatch "
                        f"(expected {expected_prev[:12]}..., got {stored_prev[:12]}...)"
                    )

                expected_prev = stored_hash

        return len(errors) == 0, count, errors

    # ── Convenience methods for common events ────────────────────────

    def log_analysis(
        self,
        user_id: str = "",
        plan_hash: str = "",
        findings_count: int = 0,
        severity_counts: dict[str, int] | None = None,
        duration_ms: float = 0.0,
        workspace_id: str = "",
    ) -> AuditEvent:
        """Log a plan analysis event."""
        event = AuditEvent(
            event_type=AuditEventType.PLAN_ANALYZED,
            timestamp=self._now(),
            user_id=user_id,
            workspace_id=workspace_id,
            resource_type="plan",
            resource_id=plan_hash,
            action="analyze",
            details={
                "findings_count": findings_count,
                "severity_counts": severity_counts or {},
            },
            duration_ms=duration_ms,
        )
        self._emit(event)
        return event

    def log_comparison(
        self,
        user_id: str = "",
        baseline_hash: str = "",
        current_hash: str = "",
        is_regression: bool = False,
        workspace_id: str = "",
    ) -> AuditEvent:
        """Log a plan comparison event."""
        event = AuditEvent(
            event_type=AuditEventType.PLAN_COMPARED,
            timestamp=self._now(),
            user_id=user_id,
            workspace_id=workspace_id,
            resource_type="plan",
            resource_id=f"{baseline_hash}:{current_hash}",
            action="compare",
            details={
                "baseline_hash": baseline_hash,
                "current_hash": current_hash,
                "is_regression": is_regression,
            },
        )
        self._emit(event)
        return event

    def log_migration(
        self,
        user_id: str = "",
        sql: str = "",
        rollback_sql: str = "",
        status: str = "success",
        risk_count: int = 0,
        workspace_id: str = "",
    ) -> AuditEvent:
        """Log a migration execution. SQL is hashed, never stored raw."""
        event = AuditEvent(
            event_type=AuditEventType.MIGRATION_EXECUTED,
            timestamp=self._now(),
            user_id=user_id,
            workspace_id=workspace_id,
            resource_type="migration",
            resource_id=self._hash(sql),
            action="execute",
            status=status,
            details={
                "sql_hash": self._hash(sql),
                "rollback_hash": self._hash(rollback_sql) if rollback_sql else "",
                "sql_length": len(sql),
                "risk_count": risk_count,
            },
        )
        self._emit(event)
        return event

    def log_config_change(
        self,
        user_id: str = "",
        parameter: str = "",
        old_value: str = "",
        new_value: str = "",
        workspace_id: str = "",
    ) -> AuditEvent:
        """Log a configuration change."""
        event = AuditEvent(
            event_type=AuditEventType.CONFIG_CHANGED,
            timestamp=self._now(),
            user_id=user_id,
            workspace_id=workspace_id,
            resource_type="config",
            resource_id=parameter,
            action="update",
            details={
                "parameter": parameter,
                "old_value": old_value,
                "new_value": new_value,
            },
        )
        self._emit(event)
        return event

    def log_policy_violation(
        self,
        user_id: str = "",
        policy_name: str = "",
        violation_details: str = "",
        blocked: bool = True,
        workspace_id: str = "",
    ) -> AuditEvent:
        """Log a policy violation (CI gate failure, budget breach, etc.)."""
        event = AuditEvent(
            event_type=AuditEventType.POLICY_VIOLATION,
            timestamp=self._now(),
            user_id=user_id,
            workspace_id=workspace_id,
            resource_type="policy",
            resource_id=policy_name,
            action="enforce",
            status="blocked" if blocked else "warned",
            details={
                "policy_name": policy_name,
                "violation": violation_details,
                "blocked": blocked,
            },
        )
        self._emit(event)
        return event

    def log_auth(
        self,
        user_id: str = "",
        event_type: AuditEventType = AuditEventType.USER_LOGIN,
        ip_address: str = "",
        user_agent: str = "",
        status: str = "success",
    ) -> AuditEvent:
        """Log an authentication event."""
        event = AuditEvent(
            event_type=event_type,
            timestamp=self._now(),
            user_id=user_id,
            resource_type="auth",
            action=event_type.value.split(".")[-1],
            status=status,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self._emit(event)
        return event

    # ── Query methods for compliance reports ─────────────────────────

    def get_events(
        self,
        user_id: str | None = None,
        event_type: AuditEventType | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events for compliance reporting."""
        result = self._events

        if user_id:
            result = [e for e in result if e.user_id == user_id]

        if event_type:
            result = [e for e in result if e.event_type == event_type]

        if since:
            since_iso = since.isoformat()
            result = [e for e in result if e.timestamp >= since_iso]

        return result[-limit:]

    def export_compliance_report(self, format: str = "json") -> str:
        """Export full audit trail for compliance review with chain verification."""
        events = [e.to_dict() for e in self._events]
        chain_valid, checked, chain_errors = self.verify_chain()

        if format == "json":
            return json.dumps({
                "report_type": "compliance_audit",
                "generated_at": self._now(),
                "total_events": len(events),
                "chain_integrity": {
                    "valid": chain_valid,
                    "events_checked": checked,
                    "errors": chain_errors,
                },
                "events": events,
            }, indent=2)

        # CSV format
        if not events:
            return "timestamp,event_type,user_id,action,status,resource_type,resource_id\n"

        lines = ["timestamp,event_type,user_id,action,status,resource_type,resource_id"]
        for e in events:
            lines.append(
                f"{e['timestamp']},{e['event_type']},{e['user_id']},"
                f"{e['action']},{e['status']},{e['resource_type']},{e['resource_id']}"
            )
        return "\n".join(lines)
