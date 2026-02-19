"""
Fix Tracker — lifecycle management for QuerySense-generated fixes.

Tracks which fixes have been generated, applied, or skipped.
Prevents duplicate migration files for the same underlying issue.
Provides audit trail for compliance.

State is persisted to .querysense/fixes.json (git-committable).

Usage:
    from querysense.fix_tracker import FixTracker, FixStatus

    tracker = FixTracker()
    tracker.record_fix(
        fix_id="CREATE_INDEX_idx_orders_status",
        sql="CREATE INDEX idx_orders_status ON orders(status);",
        finding_rule="MISSING_INDEX",
        migration_path="migrations/V003__add_orders_index.sql",
        migration_format="flyway",
    )
    tracker.mark_applied("CREATE_INDEX_idx_orders_status")
    print(tracker.status())
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FixStatus(str, Enum):
    """Lifecycle states for a tracked fix."""
    PENDING = "pending"           # Migration generated, not yet applied
    APPLIED = "applied"           # Confirmed applied to database
    SKIPPED = "skipped"           # Manually marked as not needed
    SUPERSEDED = "superseded"     # Replaced by a newer fix
    FAILED = "failed"             # Application attempted but failed


class TrackedFix:
    """A single tracked fix with full lifecycle metadata."""

    def __init__(
        self,
        fix_id: str,
        sql: str,
        finding_rule: str,
        status: FixStatus = FixStatus.PENDING,
        migration_path: str = "",
        migration_format: str = "",
        source_plan: str = "",
        created_at: str = "",
        applied_at: str = "",
        impact_score: float = 0.0,
        finding_title: str = "",
    ) -> None:
        self.fix_id = fix_id
        self.sql = sql
        self.finding_rule = finding_rule
        self.status = status
        self.migration_path = migration_path
        self.migration_format = migration_format
        self.source_plan = source_plan
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.applied_at = applied_at
        self.impact_score = impact_score
        self.finding_title = finding_title

    def to_dict(self) -> dict[str, Any]:
        return {
            "fix_id": self.fix_id,
            "sql": self.sql,
            "finding_rule": self.finding_rule,
            "status": self.status.value,
            "migration_path": self.migration_path,
            "migration_format": self.migration_format,
            "source_plan": self.source_plan,
            "created_at": self.created_at,
            "applied_at": self.applied_at,
            "impact_score": self.impact_score,
            "finding_title": self.finding_title,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TrackedFix:
        return cls(
            fix_id=d["fix_id"],
            sql=d["sql"],
            finding_rule=d["finding_rule"],
            status=FixStatus(d.get("status", "pending")),
            migration_path=d.get("migration_path", ""),
            migration_format=d.get("migration_format", ""),
            source_plan=d.get("source_plan", ""),
            created_at=d.get("created_at", ""),
            applied_at=d.get("applied_at", ""),
            impact_score=d.get("impact_score", 0.0),
            finding_title=d.get("finding_title", ""),
        )


def _sql_fingerprint(sql: str) -> str:
    """Generate a stable fingerprint for a SQL fix statement."""
    # Normalize whitespace, case-insensitive for DDL keywords
    normalized = " ".join(sql.strip().split()).lower()
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


class FixTracker:
    """
    Tracks the lifecycle of QuerySense-generated fixes.

    State is persisted to .querysense/fixes.json, which is designed
    to be committed to version control for team visibility.
    """

    def __init__(self, state_dir: str | Path = ".querysense") -> None:
        self.state_dir = Path(state_dir)
        self.state_file = self.state_dir / "fixes.json"
        self._fixes: dict[str, TrackedFix] = {}
        self._load()

    def _load(self) -> None:
        """Load persisted fix state."""
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                for d in data.get("fixes", []):
                    fix = TrackedFix.from_dict(d)
                    self._fixes[fix.fix_id] = fix
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Failed to load fix tracker state: %s", e)

    def _save(self) -> None:
        """Persist fix state to disk."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "fixes": [f.to_dict() for f in self._fixes.values()],
        }
        self.state_file.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def record_fix(
        self,
        sql: str,
        finding_rule: str,
        migration_path: str = "",
        migration_format: str = "",
        source_plan: str = "",
        impact_score: float = 0.0,
        finding_title: str = "",
    ) -> TrackedFix:
        """
        Record a newly generated fix.

        Returns the TrackedFix (existing if duplicate, new otherwise).
        """
        fix_id = f"{finding_rule}_{_sql_fingerprint(sql)}"

        # Check for duplicates
        if fix_id in self._fixes:
            existing = self._fixes[fix_id]
            if existing.status in (FixStatus.PENDING, FixStatus.APPLIED):
                logger.info("Fix already tracked: %s (%s)", fix_id, existing.status.value)
                return existing

        fix = TrackedFix(
            fix_id=fix_id,
            sql=sql,
            finding_rule=finding_rule,
            migration_path=migration_path,
            migration_format=migration_format,
            source_plan=source_plan,
            impact_score=impact_score,
            finding_title=finding_title,
        )
        self._fixes[fix_id] = fix
        self._save()
        return fix

    def mark_applied(self, fix_id: str) -> bool:
        """Mark a fix as applied."""
        if fix_id not in self._fixes:
            return False
        self._fixes[fix_id].status = FixStatus.APPLIED
        self._fixes[fix_id].applied_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

    def mark_skipped(self, fix_id: str) -> bool:
        """Mark a fix as intentionally skipped."""
        if fix_id not in self._fixes:
            return False
        self._fixes[fix_id].status = FixStatus.SKIPPED
        self._save()
        return True

    def is_duplicate(self, sql: str, finding_rule: str) -> bool:
        """Check if this fix has already been generated and is pending/applied."""
        fix_id = f"{finding_rule}_{_sql_fingerprint(sql)}"
        if fix_id in self._fixes:
            return self._fixes[fix_id].status in (
                FixStatus.PENDING, FixStatus.APPLIED
            )
        return False

    def get_all(self) -> list[TrackedFix]:
        """Return all tracked fixes, newest first."""
        return sorted(
            self._fixes.values(),
            key=lambda f: f.created_at,
            reverse=True,
        )

    def get_by_status(self, status: FixStatus) -> list[TrackedFix]:
        """Return fixes filtered by status."""
        return [f for f in self.get_all() if f.status == status]

    def summary(self) -> dict[str, int]:
        """Return counts by status."""
        counts: dict[str, int] = {}
        for fix in self._fixes.values():
            counts[fix.status.value] = counts.get(fix.status.value, 0) + 1
        return counts

    def clear(self) -> int:
        """Clear all tracked fixes. Returns count removed."""
        count = len(self._fixes)
        self._fixes.clear()
        self._save()
        return count
