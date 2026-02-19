"""
QuerySense Profiles: the "git diff for database performance".

A profile captures a database's performance baseline over time and
enables regression detection when queries change. This is the core
differentiator — none of the competitors do this well.

Workflow:
    1. Initialize a profile:
       querysense profile init --name production --connection $DATABASE_URL

    2. The profile stores baselines, snapshots, and configuration

    3. When someone opens a PR:
       querysense check --profile production --against pr_plan.json
       Output: "This query is 3x slower than last week. Here's why:..."

Usage:
    from querysense.profile import Profile, ProfileStore

    store = ProfileStore()
    profile = store.create("production", connection_dsn="postgresql://...")
    profile.record_snapshot(query_id, explain_output)

    # Later, check against profile
    report = profile.check(query_id, new_explain_output)
    if report.is_regression:
        print(report.message)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ProfileConfig:
    """Configuration for a QuerySense Profile."""

    name: str
    connection_dsn: str | None = None
    created_at: str = ""
    description: str = ""
    check_interval_minutes: int = 60
    regression_threshold_pct: float = 20.0
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "connection_dsn": self.connection_dsn,
            "created_at": self.created_at,
            "description": self.description,
            "check_interval_minutes": self.check_interval_minutes,
            "regression_threshold_pct": self.regression_threshold_pct,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProfileConfig:
        return cls(
            name=data["name"],
            connection_dsn=data.get("connection_dsn"),
            created_at=data.get("created_at", ""),
            description=data.get("description", ""),
            check_interval_minutes=data.get("check_interval_minutes", 60),
            regression_threshold_pct=data.get("regression_threshold_pct", 20.0),
            tags=data.get("tags", {}),
        )


@dataclass
class CheckResult:
    """Result of checking a plan against a profile."""

    query_id: str
    profile_name: str
    is_regression: bool = False
    is_improvement: bool = False
    cost_before: float = 0.0
    cost_after: float = 0.0
    cost_change_pct: float = 0.0
    structure_changed: bool = False
    findings_before: int = 0
    findings_after: int = 0
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""

    @property
    def speedup_ratio(self) -> float:
        if self.cost_after <= 0:
            return 0.0
        return self.cost_before / self.cost_after

    @property
    def summary(self) -> str:
        """One-line summary for CI output."""
        if self.is_regression:
            return (
                f"REGRESSION: {self.query_id} is {abs(self.cost_change_pct):.0f}% "
                f"slower ({self.cost_before:,.0f} → {self.cost_after:,.0f})"
            )
        if self.is_improvement:
            return (
                f"IMPROVED: {self.query_id} is {self.speedup_ratio:.1f}x faster "
                f"({self.cost_before:,.0f} → {self.cost_after:,.0f})"
            )
        return f"OK: {self.query_id} — no significant change"

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "profile_name": self.profile_name,
            "is_regression": self.is_regression,
            "is_improvement": self.is_improvement,
            "cost_before": self.cost_before,
            "cost_after": self.cost_after,
            "cost_change_pct": round(self.cost_change_pct, 1),
            "speedup_ratio": round(self.speedup_ratio, 1),
            "structure_changed": self.structure_changed,
            "findings_before": self.findings_before,
            "findings_after": self.findings_after,
            "new_findings_count": len(self.new_findings),
            "resolved_findings_count": len(self.resolved_findings),
            "message": self.message,
        }


class Profile:
    """
    A named performance profile for a database.

    Stores baselines and temporal snapshots, enabling regression
    detection when query plans change.
    """

    def __init__(self, config: ProfileConfig, base_dir: Path) -> None:
        self.config = config
        self.base_dir = base_dir
        self._baselines_path = base_dir / "baselines.json"
        self._history_db = base_dir / "history.db"

    @property
    def name(self) -> str:
        return self.config.name

    def record_snapshot(
        self,
        query_id: str,
        explain_json: dict[str, Any],
        result: Any | None = None,
    ) -> None:
        """
        Record a plan snapshot for the given query.

        Stores both the baseline (for structural comparison) and a
        temporal snapshot (for trend analysis).
        """
        from querysense.baseline import BaselineStore
        from querysense.parser.parser import parse_explain
        from querysense.temporal.sqlite_store import SQLiteTemporalStore
        from querysense.temporal.store import PlanSnapshot

        # Update baseline
        explain = parse_explain(explain_json)
        store = BaselineStore(self._baselines_path)
        store.record(query_id, explain)
        store.save()

        # Store temporal snapshot
        temporal = SQLiteTemporalStore(self._history_db)
        snapshot = PlanSnapshot(
            query_id=query_id,
            timestamp=datetime.now(timezone.utc),
            structure_hash=store._baselines.get(query_id, {}).get(
                "structure_hash", ""
            )
            if hasattr(store, "_baselines")
            else "",
            cost_total=explain.plan.total_cost,
            node_count=len(explain.all_nodes),
            latency_p50_ms=explain.execution_time,
            metadata={"profile": self.config.name},
        )
        temporal.store(snapshot)

        # Store analysis if provided
        if result is not None:
            temporal.store_analysis(
                analysis_id=result.reproducibility.analysis_id,
                file_path=None,
                query_id=query_id,
                result=result,
            )

    def check(
        self,
        query_id: str,
        explain_json: dict[str, Any],
    ) -> CheckResult:
        """
        Check a plan against this profile's baseline.

        Compares the new plan against the stored baseline and temporal
        history to detect regressions and improvements.

        Returns:
            CheckResult with regression/improvement analysis
        """
        from querysense.baseline import BaselineStore
        from querysense.engine import AnalysisService
        from querysense.parser.parser import parse_explain
        from querysense.temporal.sqlite_store import SQLiteTemporalStore

        explain = parse_explain(explain_json)
        new_cost = explain.plan.total_cost

        # Compare against baseline
        store = BaselineStore(self._baselines_path)
        baseline_diff = None
        if store.path.exists():
            baseline_diff = store.compare(query_id, explain)

        # Get historical cost
        temporal = SQLiteTemporalStore(self._history_db)
        regression_info = temporal.regression_check(
            query_id, new_cost,
            threshold_pct=self.config.regression_threshold_pct,
        )

        # Analyze new plan
        service = AnalysisService()
        new_result = service.analyze(explain)

        # Build result
        prev_snapshot = temporal.latest(query_id)
        prev_cost = prev_snapshot.cost_total if prev_snapshot else new_cost

        if prev_cost and prev_cost > 0:
            cost_change_pct = ((new_cost - prev_cost) / prev_cost) * 100
        else:
            cost_change_pct = 0.0

        is_regression = cost_change_pct > self.config.regression_threshold_pct
        is_improvement = cost_change_pct < -self.config.regression_threshold_pct

        structure_changed = (
            baseline_diff is not None
            and baseline_diff.status == "CHANGED"
        )

        message = ""
        if is_regression:
            message = (
                f"This query is {abs(cost_change_pct):.0f}% slower than the baseline. "
                f"Cost: {prev_cost:,.0f} → {new_cost:,.0f}."
            )
            if structure_changed and baseline_diff:
                message += " The plan structure also changed."
        elif is_improvement:
            speedup = prev_cost / new_cost if new_cost > 0 else 0
            message = (
                f"This query is {speedup:.1f}x faster than the baseline. "
                f"Cost: {prev_cost:,.0f} → {new_cost:,.0f}."
            )
        else:
            message = "No significant change from baseline."

        return CheckResult(
            query_id=query_id,
            profile_name=self.config.name,
            is_regression=is_regression,
            is_improvement=is_improvement,
            cost_before=prev_cost or 0.0,
            cost_after=new_cost,
            cost_change_pct=round(cost_change_pct, 1),
            structure_changed=structure_changed,
            findings_after=len(new_result.findings),
            message=message,
        )


class ProfileStore:
    """
    Manages QuerySense profiles.

    Profiles are stored in ~/.querysense/profiles/<name>/
    """

    def __init__(self, base_dir: str | Path = "~/.querysense/profiles") -> None:
        self.base_dir = Path(base_dir).expanduser()

    def create(
        self,
        name: str,
        connection_dsn: str | None = None,
        description: str = "",
    ) -> Profile:
        """Create a new profile."""
        profile_dir = self.base_dir / name
        profile_dir.mkdir(parents=True, exist_ok=True)

        config = ProfileConfig(
            name=name,
            connection_dsn=connection_dsn,
            created_at=datetime.now(timezone.utc).isoformat(),
            description=description,
        )

        config_path = profile_dir / "config.json"
        config_path.write_text(
            json.dumps(config.to_dict(), indent=2),
            encoding="utf-8",
        )

        return Profile(config, profile_dir)

    def get(self, name: str) -> Profile | None:
        """Get an existing profile by name."""
        profile_dir = self.base_dir / name
        config_path = profile_dir / "config.json"

        if not config_path.exists():
            return None

        data = json.loads(config_path.read_text(encoding="utf-8"))
        config = ProfileConfig.from_dict(data)
        return Profile(config, profile_dir)

    def list_profiles(self) -> list[ProfileConfig]:
        """List all profiles."""
        profiles: list[ProfileConfig] = []
        if not self.base_dir.exists():
            return profiles

        for entry in sorted(self.base_dir.iterdir()):
            config_path = entry / "config.json"
            if config_path.exists():
                data = json.loads(config_path.read_text(encoding="utf-8"))
                profiles.append(ProfileConfig.from_dict(data))

        return profiles

    def delete(self, name: str) -> bool:
        """Delete a profile."""
        import shutil

        profile_dir = self.base_dir / name
        if profile_dir.exists():
            shutil.rmtree(profile_dir)
            return True
        return False
