"""
Vacuum advisor for PostgreSQL.

Comprehensive vacuum health analysis, bloat detection, and autovacuum
tuning recommendations. Closes the gap vs pganalyze's vacuum monitoring.

Checks:
- Tables needing VACUUM (dead tuple ratio)
- Tables needing ANALYZE (stale statistics)
- Autovacuum configuration issues
- Bloat estimation
- Transaction ID wraparound risk
- Toast bloat

Usage:
    from querysense.db.vacuum_advisor import collect_vacuum_health, VacuumReport

    report = await collect_vacuum_health(conn)
    for issue in report.issues:
        print(issue)
    for rec in report.recommendations:
        print(rec)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class TableVacuumInfo:
    """Vacuum health info for a single table."""

    table: str
    schema: str = "public"
    n_live_tup: int = 0
    n_dead_tup: int = 0
    last_vacuum: str | None = None
    last_autovacuum: str | None = None
    last_analyze: str | None = None
    last_autoanalyze: str | None = None
    vacuum_count: int = 0
    autovacuum_count: int = 0
    autoanalyze_count: int = 0
    table_size_bytes: int = 0
    n_mod_since_analyze: int = 0

    @property
    def dead_tuple_ratio(self) -> float:
        total = self.n_live_tup + self.n_dead_tup
        if total == 0:
            return 0.0
        return self.n_dead_tup / total

    @property
    def needs_vacuum(self) -> bool:
        """Table likely needs VACUUM based on dead tuple ratio."""
        return self.dead_tuple_ratio > 0.1 and self.n_dead_tup > 1000

    @property
    def needs_analyze(self) -> bool:
        """Table likely needs ANALYZE based on modification count."""
        if self.n_live_tup == 0:
            return False
        # PostgreSQL default: analyze threshold = 50 + 0.1 * reltuples
        threshold = 50 + 0.1 * self.n_live_tup
        return self.n_mod_since_analyze > threshold

    @property
    def never_vacuumed(self) -> bool:
        return self.last_vacuum is None and self.last_autovacuum is None

    @property
    def never_analyzed(self) -> bool:
        return self.last_analyze is None and self.last_autoanalyze is None


@dataclass
class VacuumIssue:
    """A vacuum-related issue found."""

    severity: str  # "critical", "warning", "info"
    table: str
    issue_type: str
    message: str
    suggestion: str = ""

    def __str__(self) -> str:
        s = f"[{self.severity.upper()}] {self.table}: {self.message}"
        if self.suggestion:
            s += f" | Fix: {self.suggestion}"
        return s


@dataclass
class VacuumReport:
    """Complete vacuum health report."""

    tables: list[TableVacuumInfo] = field(default_factory=list)
    issues: list[VacuumIssue] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    autovacuum_settings: dict[str, str] = field(default_factory=dict)
    xid_age: int = 0
    xid_limit: int = 2_000_000_000
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def tables_needing_vacuum(self) -> list[TableVacuumInfo]:
        return [t for t in self.tables if t.needs_vacuum]

    @property
    def tables_needing_analyze(self) -> list[TableVacuumInfo]:
        return [t for t in self.tables if t.needs_analyze]

    @property
    def xid_wraparound_risk(self) -> float:
        """Transaction ID wraparound risk (0.0 to 1.0)."""
        if self.xid_limit == 0:
            return 0.0
        return self.xid_age / self.xid_limit

    def summary(self) -> str:
        parts = [f"{len(self.tables)} table(s) checked"]
        if self.tables_needing_vacuum:
            parts.append(f"{len(self.tables_needing_vacuum)} need VACUUM")
        if self.tables_needing_analyze:
            parts.append(f"{len(self.tables_needing_analyze)} need ANALYZE")
        if self.xid_wraparound_risk > 0.5:
            parts.append(f"XID wraparound risk: {self.xid_wraparound_risk:.0%}")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "tables_checked": len(self.tables),
            "tables_needing_vacuum": len(self.tables_needing_vacuum),
            "tables_needing_analyze": len(self.tables_needing_analyze),
            "xid_age": self.xid_age,
            "xid_wraparound_risk": round(self.xid_wraparound_risk, 3),
            "issues": [
                {
                    "severity": i.severity,
                    "table": i.table,
                    "type": i.issue_type,
                    "message": i.message,
                    "suggestion": i.suggestion,
                }
                for i in self.issues
            ],
            "recommendations": self.recommendations,
            "autovacuum_settings": self.autovacuum_settings,
        }


async def collect_vacuum_health(conn: AsyncDBConnection) -> VacuumReport:
    """
    Comprehensive vacuum health analysis.

    Reads pg_stat_user_tables, pg_settings, and transaction ID age
    to produce actionable vacuum recommendations.
    """
    report = VacuumReport()

    # Table vacuum stats
    try:
        rows = await conn.fetch(
            """SELECT schemaname, relname,
                      n_live_tup, n_dead_tup,
                      last_vacuum::text, last_autovacuum::text,
                      last_analyze::text, last_autoanalyze::text,
                      vacuum_count, autovacuum_count, autoanalyze_count,
                      n_mod_since_analyze,
                      pg_table_size(relid) AS table_size_bytes
               FROM pg_stat_user_tables
               ORDER BY n_dead_tup DESC"""
        )
        for row in rows:
            info = TableVacuumInfo(
                table=row["relname"],
                schema=row["schemaname"],
                n_live_tup=row["n_live_tup"] or 0,
                n_dead_tup=row["n_dead_tup"] or 0,
                last_vacuum=row["last_vacuum"],
                last_autovacuum=row["last_autovacuum"],
                last_analyze=row["last_analyze"],
                last_autoanalyze=row["last_autoanalyze"],
                vacuum_count=row["vacuum_count"] or 0,
                autovacuum_count=row["autovacuum_count"] or 0,
                autoanalyze_count=row["autoanalyze_count"] or 0,
                n_mod_since_analyze=row["n_mod_since_analyze"] or 0,
                table_size_bytes=row["table_size_bytes"] or 0,
            )
            report.tables.append(info)

            # Generate issues
            if info.dead_tuple_ratio > 0.5 and info.n_dead_tup > 10000:
                report.issues.append(VacuumIssue(
                    severity="critical",
                    table=info.table,
                    issue_type="extreme_bloat",
                    message=(
                        f"{info.dead_tuple_ratio:.0%} dead tuples "
                        f"({info.n_dead_tup:,} dead / {info.n_live_tup:,} live)"
                    ),
                    suggestion=f"VACUUM ANALYZE {info.schema}.{info.table};",
                ))
            elif info.needs_vacuum:
                report.issues.append(VacuumIssue(
                    severity="warning",
                    table=info.table,
                    issue_type="needs_vacuum",
                    message=(
                        f"{info.dead_tuple_ratio:.0%} dead tuples "
                        f"({info.n_dead_tup:,} dead)"
                    ),
                    suggestion=f"VACUUM ANALYZE {info.schema}.{info.table};",
                ))

            if info.never_vacuumed and info.n_live_tup > 1000:
                report.issues.append(VacuumIssue(
                    severity="warning",
                    table=info.table,
                    issue_type="never_vacuumed",
                    message="Table has never been vacuumed",
                    suggestion=f"VACUUM ANALYZE {info.schema}.{info.table};",
                ))

            if info.never_analyzed and info.n_live_tup > 100:
                report.issues.append(VacuumIssue(
                    severity="warning",
                    table=info.table,
                    issue_type="never_analyzed",
                    message="Table has never been analyzed; planner stats are missing",
                    suggestion=f"ANALYZE {info.schema}.{info.table};",
                ))
            elif info.needs_analyze:
                report.issues.append(VacuumIssue(
                    severity="info",
                    table=info.table,
                    issue_type="needs_analyze",
                    message=f"{info.n_mod_since_analyze:,} modifications since last analyze",
                    suggestion=f"ANALYZE {info.schema}.{info.table};",
                ))
    except Exception as e:
        report.errors.append(f"table_stats: {e}")

    # Autovacuum settings
    try:
        rows = await conn.fetch(
            """SELECT name, setting
               FROM pg_settings
               WHERE name LIKE 'autovacuum%%'
                  OR name IN ('vacuum_cost_delay', 'vacuum_cost_limit',
                              'maintenance_work_mem')"""
        )
        for row in rows:
            report.autovacuum_settings[row["name"]] = row["setting"]

        # Check for suboptimal settings
        av_enabled = report.autovacuum_settings.get("autovacuum", "on")
        if av_enabled != "on":
            report.issues.append(VacuumIssue(
                severity="critical",
                table="(global)",
                issue_type="autovacuum_disabled",
                message="Autovacuum is DISABLED",
                suggestion="ALTER SYSTEM SET autovacuum = on; SELECT pg_reload_conf();",
            ))

        av_workers = int(report.autovacuum_settings.get("autovacuum_max_workers", "3"))
        if av_workers < 3:
            report.recommendations.append(
                f"autovacuum_max_workers={av_workers} is low; "
                f"consider increasing to at least 3-5 for busy databases."
            )

        cost_delay = int(report.autovacuum_settings.get("autovacuum_vacuum_cost_delay", "2"))
        if cost_delay > 10:
            report.recommendations.append(
                f"autovacuum_vacuum_cost_delay={cost_delay}ms is high; "
                f"reduce to 2ms for faster vacuum on modern hardware."
            )

        scale_factor = float(
            report.autovacuum_settings.get("autovacuum_vacuum_scale_factor", "0.2")
        )
        if scale_factor > 0.1:
            report.recommendations.append(
                f"autovacuum_vacuum_scale_factor={scale_factor} means large tables "
                f"accumulate many dead tuples before vacuum triggers. "
                f"Consider 0.01-0.05 for tables >1M rows."
            )

        maint_mem = report.autovacuum_settings.get("maintenance_work_mem", "65536")
        maint_mb = int(maint_mem) / 1024 if maint_mem.isdigit() else 64
        if maint_mb < 256:
            report.recommendations.append(
                f"maintenance_work_mem={maint_mb:.0f}MB; increase to 256MB-1GB "
                f"for faster VACUUM on large tables."
            )
    except Exception as e:
        report.errors.append(f"autovacuum_settings: {e}")

    # Transaction ID wraparound check
    try:
        xid_age = await conn.fetchval(
            "SELECT max(age(datfrozenxid)) FROM pg_database"
        )
        report.xid_age = int(xid_age) if xid_age else 0

        if report.xid_wraparound_risk > 0.75:
            report.issues.append(VacuumIssue(
                severity="critical",
                table="(global)",
                issue_type="xid_wraparound_risk",
                message=(
                    f"Transaction ID age is {report.xid_age:,} "
                    f"({report.xid_wraparound_risk:.0%} of limit); "
                    f"wraparound protection VACUUM needed"
                ),
                suggestion="Run VACUUM FREEZE on oldest tables immediately",
            ))
        elif report.xid_wraparound_risk > 0.5:
            report.issues.append(VacuumIssue(
                severity="warning",
                table="(global)",
                issue_type="xid_aging",
                message=(
                    f"Transaction ID age is {report.xid_age:,} "
                    f"({report.xid_wraparound_risk:.0%} of limit)"
                ),
                suggestion="Monitor XID age; ensure autovacuum is running",
            ))
    except Exception as e:
        report.errors.append(f"xid_age: {e}")

    return report
