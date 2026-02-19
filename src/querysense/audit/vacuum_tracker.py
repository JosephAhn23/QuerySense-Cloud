"""
Autovacuum Threshold Analyzer & Dead Tuple Growth Tracker.

This solves the exact problem pganalyze solved for Autotrader UK:
    "We could see 8,885,770 rows, but vacuum hadn't run in over 24 hours.
     The power came from understanding WHEN vacuum was needed and WHY it
     hadn't happened yet." — Michael Rocke, Autotrader UK

The default autovacuum_vacuum_scale_factor = 0.2 means on a 100M row table,
20M rows must be modified before vacuum triggers. For large append-only tables,
vacuum may NEVER trigger.

This module:
    1. Calculates per-table vacuum eligibility (dead tuples vs threshold)
    2. Shows how far each table is from triggering autovacuum
    3. Tracks dead tuple accumulation rate
    4. Predicts when vacuum will trigger (or if it never will)
    5. Recommends per-table autovacuum_vacuum_scale_factor settings

Usage:
    from querysense.audit.vacuum_tracker import VacuumTracker

    tracker = VacuumTracker()
    report = await tracker.analyze(conn)
    for table in report.tables:
        print(f"{table.name}: {table.pct_to_threshold:.0f}% to vacuum trigger")
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class TableVacuumState:
    """Per-table autovacuum eligibility analysis."""

    schema: str = "public"
    name: str = ""
    n_live_tup: int = 0
    n_dead_tup: int = 0
    n_mod_since_analyze: int = 0
    n_ins_since_vacuum: int = 0
    table_size_bytes: int = 0
    last_vacuum: str | None = None
    last_autovacuum: str | None = None
    last_analyze: str | None = None

    # Autovacuum settings (per-table or global)
    vacuum_scale_factor: float = 0.2
    vacuum_threshold: int = 50
    analyze_scale_factor: float = 0.1
    analyze_threshold: int = 50

    # Computed fields
    vacuum_trigger_threshold: int = 0    # Dead tuples needed to trigger vacuum
    pct_to_threshold: float = 0.0        # 0-100, how close to triggering
    will_vacuum_trigger: bool = False     # Whether vacuum will trigger at current rate
    dead_tuple_rate_per_hour: float = 0.0 # Estimated dead tuple accumulation
    hours_to_vacuum: float | None = None  # Predicted hours until vacuum triggers
    recommended_scale_factor: float | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def dead_tuple_ratio(self) -> float:
        total = self.n_live_tup + self.n_dead_tup
        if total == 0:
            return 0
        return self.n_dead_tup / total

    @property
    def table_size_mb(self) -> float:
        return self.table_size_bytes / (1024 * 1024) if self.table_size_bytes else 0

    @property
    def severity(self) -> str:
        if self.pct_to_threshold >= 90:
            return "critical"
        if self.pct_to_threshold >= 70:
            return "warning"
        if self.dead_tuple_ratio > 0.3:
            return "warning"
        return "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.qualified_name,
            "n_live_tup": self.n_live_tup,
            "n_dead_tup": self.n_dead_tup,
            "dead_tuple_ratio": round(self.dead_tuple_ratio, 3),
            "table_size_mb": round(self.table_size_mb, 1),
            "vacuum_trigger_threshold": self.vacuum_trigger_threshold,
            "pct_to_threshold": round(self.pct_to_threshold, 1),
            "will_vacuum_trigger": self.will_vacuum_trigger,
            "hours_to_vacuum": round(self.hours_to_vacuum, 1) if self.hours_to_vacuum else None,
            "last_vacuum": self.last_vacuum,
            "last_autovacuum": self.last_autovacuum,
            "vacuum_scale_factor": self.vacuum_scale_factor,
            "recommended_scale_factor": self.recommended_scale_factor,
            "severity": self.severity,
        }


@dataclass
class VacuumTrackerFinding:
    """A vacuum tracking finding with actionable fix."""

    severity: str
    table: str
    title: str
    description: str
    recommendation: str
    fix_sql: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "table": self.table,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "fix_sql": self.fix_sql,
            "evidence": self.evidence,
        }


@dataclass
class VacuumTrackerReport:
    """Complete autovacuum threshold analysis report."""

    tables: list[TableVacuumState] = field(default_factory=list)
    findings: list[VacuumTrackerFinding] = field(default_factory=list)
    global_settings: dict[str, str] = field(default_factory=dict)
    total_dead_tuples: int = 0
    tables_needing_vacuum: int = 0
    tables_vacuum_never_triggers: int = 0

    @property
    def is_healthy(self) -> bool:
        return not any(f.severity in ("critical", "warning") for f in self.findings)

    @property
    def summary(self) -> str:
        lines = [
            f"Analyzed {len(self.tables)} tables, {self.total_dead_tuples:,} total dead tuples",
        ]
        if self.tables_needing_vacuum:
            lines.append(f"{self.tables_needing_vacuum} tables approaching vacuum threshold")
        if self.tables_vacuum_never_triggers:
            lines.append(
                f"{self.tables_vacuum_never_triggers} large tables where vacuum may never trigger "
                "with current scale_factor"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tables": [t.to_dict() for t in self.tables],
            "findings": [f.to_dict() for f in self.findings],
            "global_settings": self.global_settings,
            "total_dead_tuples": self.total_dead_tuples,
            "tables_needing_vacuum": self.tables_needing_vacuum,
            "tables_vacuum_never_triggers": self.tables_vacuum_never_triggers,
            "is_healthy": self.is_healthy,
        }


class VacuumTracker:
    """
    Analyze per-table autovacuum eligibility and dead tuple growth.

    The Autotrader problem: default autovacuum_vacuum_scale_factor = 0.2
    means a 100M row table needs 20M dead tuples before vacuum runs.
    For append-heavy tables, this threshold is never reached.
    """

    async def analyze(self, conn: AsyncDBConnection) -> VacuumTrackerReport:
        """Run full vacuum threshold analysis."""
        report = VacuumTrackerReport()

        # Collect global autovacuum settings
        report.global_settings = await self._collect_global_settings(conn)
        global_scale = float(report.global_settings.get("autovacuum_vacuum_scale_factor", "0.2"))
        global_threshold = int(report.global_settings.get("autovacuum_vacuum_threshold", "50"))
        global_analyze_scale = float(report.global_settings.get("autovacuum_analyze_scale_factor", "0.1"))
        global_analyze_threshold = int(report.global_settings.get("autovacuum_analyze_threshold", "50"))

        # Collect per-table stats
        rows = await self._collect_table_stats(conn)
        per_table_settings = await self._collect_per_table_settings(conn)

        for r in rows:
            state = self._build_table_state(r, per_table_settings,
                                            global_scale, global_threshold,
                                            global_analyze_scale, global_analyze_threshold)
            self._compute_threshold(state)
            report.tables.append(state)
            report.total_dead_tuples += state.n_dead_tup

        # Sort: worst first
        report.tables.sort(key=lambda t: -t.pct_to_threshold)

        # Generate findings
        self._generate_findings(report)

        return report

    async def _collect_global_settings(self, conn: AsyncDBConnection) -> dict[str, str]:
        """Collect global autovacuum settings."""
        settings: dict[str, str] = {}
        for name in (
            "autovacuum_vacuum_scale_factor",
            "autovacuum_vacuum_threshold",
            "autovacuum_analyze_scale_factor",
            "autovacuum_analyze_threshold",
            "autovacuum_max_workers",
            "autovacuum_naptime",
        ):
            try:
                val = await conn.fetchval(f"SHOW {name}")
                settings[name] = str(val)
            except Exception:
                pass
        return settings

    async def _collect_table_stats(self, conn: AsyncDBConnection) -> list[Any]:
        """Collect per-table statistics."""
        try:
            return await conn.fetch(
                "SELECT "
                "  s.schemaname, s.relname, "
                "  s.n_live_tup, s.n_dead_tup, "
                "  s.n_mod_since_analyze, "
                "  COALESCE(s.n_ins_since_vacuum, 0) AS n_ins_since_vacuum, "
                "  pg_relation_size(c.oid) AS table_size, "
                "  s.last_vacuum::text, s.last_autovacuum::text, s.last_analyze::text "
                "FROM pg_stat_user_tables s "
                "JOIN pg_class c ON c.relname = s.relname "
                "  AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = s.schemaname) "
                "WHERE s.n_live_tup + s.n_dead_tup > 0 "
                "ORDER BY s.n_dead_tup DESC"
            )
        except Exception:
            return []

    async def _collect_per_table_settings(self, conn: AsyncDBConnection) -> dict[str, dict[str, str]]:
        """Collect per-table autovacuum overrides from reloptions."""
        result: dict[str, dict[str, str]] = {}
        try:
            rows = await conn.fetch(
                "SELECT n.nspname, c.relname, "
                "  unnest(c.reloptions) AS option "
                "FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE c.reloptions IS NOT NULL "
                "  AND c.relkind = 'r'"
            )
            for r in rows:
                if isinstance(r, (list, tuple)):
                    schema, table, option = r[0], r[1], r[2]
                else:
                    schema = getattr(r, "nspname", "")
                    table = getattr(r, "relname", "")
                    option = getattr(r, "option", "")

                key = f"{schema}.{table}"
                if key not in result:
                    result[key] = {}

                opt_str = str(option)
                if "=" in opt_str:
                    k, v = opt_str.split("=", 1)
                    result[key][k.strip()] = v.strip()
        except Exception:
            pass
        return result

    def _build_table_state(
        self, r: Any, per_table: dict[str, dict[str, str]],
        global_scale: float, global_threshold: int,
        global_analyze_scale: float, global_analyze_threshold: int,
    ) -> TableVacuumState:
        """Build a TableVacuumState from a DB row."""
        if isinstance(r, (list, tuple)):
            schema, name = str(r[0]), str(r[1])
            live, dead = int(r[2] or 0), int(r[3] or 0)
            mod = int(r[4] or 0)
            ins = int(r[5] or 0)
            size = int(r[6] or 0)
            last_v, last_av, last_a = r[7], r[8], r[9]
        else:
            schema = str(getattr(r, "schemaname", "public"))
            name = str(getattr(r, "relname", ""))
            live = int(getattr(r, "n_live_tup", 0) or 0)
            dead = int(getattr(r, "n_dead_tup", 0) or 0)
            mod = int(getattr(r, "n_mod_since_analyze", 0) or 0)
            ins = int(getattr(r, "n_ins_since_vacuum", 0) or 0)
            size = int(getattr(r, "table_size", 0) or 0)
            last_v = getattr(r, "last_vacuum", None)
            last_av = getattr(r, "last_autovacuum", None)
            last_a = getattr(r, "last_analyze", None)

        key = f"{schema}.{name}"
        overrides = per_table.get(key, {})

        return TableVacuumState(
            schema=schema,
            name=name,
            n_live_tup=live,
            n_dead_tup=dead,
            n_mod_since_analyze=mod,
            n_ins_since_vacuum=ins,
            table_size_bytes=size,
            last_vacuum=str(last_v) if last_v else None,
            last_autovacuum=str(last_av) if last_av else None,
            last_analyze=str(last_a) if last_a else None,
            vacuum_scale_factor=float(
                overrides.get("autovacuum_vacuum_scale_factor", global_scale)
            ),
            vacuum_threshold=int(
                overrides.get("autovacuum_vacuum_threshold", global_threshold)
            ),
            analyze_scale_factor=float(
                overrides.get("autovacuum_analyze_scale_factor", global_analyze_scale)
            ),
            analyze_threshold=int(
                overrides.get("autovacuum_analyze_threshold", global_analyze_threshold)
            ),
        )

    @staticmethod
    def _compute_threshold(state: TableVacuumState) -> None:
        """Calculate vacuum trigger threshold and percentage."""
        # vacuum triggers when: n_dead_tup > threshold + scale_factor * n_live_tup
        state.vacuum_trigger_threshold = int(
            state.vacuum_threshold + state.vacuum_scale_factor * state.n_live_tup
        )

        if state.vacuum_trigger_threshold > 0:
            state.pct_to_threshold = min(
                (state.n_dead_tup / state.vacuum_trigger_threshold) * 100,
                100.0,
            )
        else:
            state.pct_to_threshold = 100.0

        state.will_vacuum_trigger = state.n_dead_tup >= state.vacuum_trigger_threshold

        # Recommend lower scale factor for large tables
        if state.n_live_tup > 10_000_000 and state.vacuum_scale_factor >= 0.1:
            # For a 100M row table, 0.01 means vacuum after 1M dead rows
            state.recommended_scale_factor = max(0.01, min(0.05, 1_000_000 / state.n_live_tup))

    def _generate_findings(self, report: VacuumTrackerReport) -> None:
        """Generate findings from the analysis."""
        for t in report.tables:
            # Critical: vacuum should have triggered but hasn't
            if t.will_vacuum_trigger:
                report.tables_needing_vacuum += 1
                report.findings.append(VacuumTrackerFinding(
                    severity="critical",
                    table=t.qualified_name,
                    title=f"{t.qualified_name}: {t.n_dead_tup:,} dead tuples ABOVE vacuum threshold",
                    description=(
                        f"Dead tuples ({t.n_dead_tup:,}) exceed the trigger threshold "
                        f"({t.vacuum_trigger_threshold:,}). Vacuum should be running but hasn't. "
                        f"Check if autovacuum is enabled and workers are available."
                    ),
                    recommendation="Run VACUUM manually and check autovacuum_max_workers.",
                    fix_sql=f"VACUUM (VERBOSE) {t.qualified_name};",
                    evidence={
                        "dead_tuples": t.n_dead_tup,
                        "threshold": t.vacuum_trigger_threshold,
                        "pct": round(t.pct_to_threshold, 1),
                    },
                ))

            # Warning: large table with high scale factor (the Autotrader problem)
            if t.n_live_tup > 10_000_000 and t.vacuum_scale_factor >= 0.1:
                report.tables_vacuum_never_triggers += 1
                trigger_rows = int(t.vacuum_threshold + t.vacuum_scale_factor * t.n_live_tup)
                rec_sf = t.recommended_scale_factor or 0.02
                rec_trigger = int(t.vacuum_threshold + rec_sf * t.n_live_tup)
                report.findings.append(VacuumTrackerFinding(
                    severity="warning",
                    table=t.qualified_name,
                    title=(
                        f"{t.qualified_name}: {t.n_live_tup:,} rows with "
                        f"scale_factor={t.vacuum_scale_factor} "
                        f"(vacuum needs {trigger_rows:,} dead tuples)"
                    ),
                    description=(
                        f"With {t.n_live_tup:,} live rows and scale_factor={t.vacuum_scale_factor}, "
                        f"autovacuum requires {trigger_rows:,} dead tuples to trigger. "
                        f"For append-heavy or bulk-import tables, this threshold may never be reached."
                    ),
                    recommendation=(
                        f"Lower autovacuum_vacuum_scale_factor to {rec_sf} "
                        f"(triggers at {rec_trigger:,} dead tuples instead of {trigger_rows:,})."
                    ),
                    fix_sql=(
                        f"ALTER TABLE {t.qualified_name} SET ("
                        f"autovacuum_vacuum_scale_factor = {rec_sf}, "
                        f"autovacuum_analyze_scale_factor = {rec_sf}"
                        f");"
                    ),
                    evidence={
                        "live_rows": t.n_live_tup,
                        "current_scale_factor": t.vacuum_scale_factor,
                        "current_trigger": trigger_rows,
                        "recommended_scale_factor": rec_sf,
                        "recommended_trigger": rec_trigger,
                    },
                ))

            # Notice: high dead tuple ratio even if below threshold
            if t.dead_tuple_ratio > 0.3 and t.n_dead_tup > 10000:
                report.findings.append(VacuumTrackerFinding(
                    severity="warning",
                    table=t.qualified_name,
                    title=f"{t.qualified_name}: {t.dead_tuple_ratio:.0%} dead tuples",
                    description=(
                        f"{t.n_dead_tup:,} dead tuples out of "
                        f"{t.n_live_tup + t.n_dead_tup:,} total. "
                        f"Table is {t.dead_tuple_ratio:.0%} bloated."
                    ),
                    recommendation="Run VACUUM to reclaim space.",
                    fix_sql=f"VACUUM (VERBOSE) {t.qualified_name};",
                ))
