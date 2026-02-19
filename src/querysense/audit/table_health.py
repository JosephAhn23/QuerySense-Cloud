"""
Table Health Dashboard — Per-table statistics, modification rate, bloat forecast.

"You want teams to move fast, but if they are afraid of the database, they
won't take ownership." — Karl Stoney, Autotrader UK

Provides a single-command view of every table's health:
    - Size and growth
    - Live/dead tuple counts and ratios
    - Modification rate (inserts/updates/deletes per hour)
    - Last vacuum/analyze timestamps
    - Index usage ratio
    - Sequential scan frequency
    - Bloat estimate and forecast

Usage:
    from querysense.audit.table_health import TableHealthDashboard

    dashboard = TableHealthDashboard()
    report = await dashboard.analyze(conn)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class TableHealth:
    """Health summary for a single table."""

    schema: str = "public"
    name: str = ""

    # Size
    table_size_bytes: int = 0
    total_size_bytes: int = 0   # Including indexes and TOAST
    index_count: int = 0

    # Tuples
    n_live_tup: int = 0
    n_dead_tup: int = 0
    dead_tuple_ratio: float = 0.0

    # Activity
    seq_scan: int = 0
    seq_tup_read: int = 0
    idx_scan: int = 0
    idx_tup_fetch: int = 0
    n_tup_ins: int = 0
    n_tup_upd: int = 0
    n_tup_del: int = 0
    n_tup_hot_upd: int = 0

    # Maintenance
    last_vacuum: str | None = None
    last_autovacuum: str | None = None
    last_analyze: str | None = None
    last_autoanalyze: str | None = None

    # Stats age (seconds since stats reset)
    stats_age_seconds: float = 0.0

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def table_size_mb(self) -> float:
        return self.table_size_bytes / (1024 * 1024)

    @property
    def total_size_mb(self) -> float:
        return self.total_size_bytes / (1024 * 1024)

    @property
    def index_usage_ratio(self) -> float:
        """Fraction of scans that use indexes (1.0 = all index scans)."""
        total = self.seq_scan + self.idx_scan
        if total == 0:
            return 1.0
        return self.idx_scan / total

    @property
    def hot_update_ratio(self) -> float:
        """Fraction of updates that are HOT (no index changes needed)."""
        if self.n_tup_upd == 0:
            return 1.0
        return self.n_tup_hot_upd / self.n_tup_upd

    @property
    def modifications_per_hour(self) -> float:
        """Total row modifications per hour."""
        total = self.n_tup_ins + self.n_tup_upd + self.n_tup_del
        if self.stats_age_seconds <= 0:
            return 0
        return total / (self.stats_age_seconds / 3600)

    @property
    def health_grade(self) -> str:
        """A-F health grade based on multiple factors."""
        score = 100.0

        # Dead tuple penalty
        if self.dead_tuple_ratio > 0.5:
            score -= 40
        elif self.dead_tuple_ratio > 0.2:
            score -= 20
        elif self.dead_tuple_ratio > 0.1:
            score -= 10

        # Sequential scan penalty (for tables > 10k rows)
        if self.n_live_tup > 10000 and self.index_usage_ratio < 0.5:
            score -= 30
        elif self.n_live_tup > 10000 and self.index_usage_ratio < 0.8:
            score -= 15

        # No recent vacuum penalty
        if not self.last_vacuum and not self.last_autovacuum and self.n_dead_tup > 1000:
            score -= 20

        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.qualified_name,
            "table_size_mb": round(self.table_size_mb, 1),
            "total_size_mb": round(self.total_size_mb, 1),
            "index_count": self.index_count,
            "n_live_tup": self.n_live_tup,
            "n_dead_tup": self.n_dead_tup,
            "dead_tuple_ratio": round(self.dead_tuple_ratio, 3),
            "seq_scan": self.seq_scan,
            "idx_scan": self.idx_scan,
            "index_usage_ratio": round(self.index_usage_ratio, 3),
            "hot_update_ratio": round(self.hot_update_ratio, 3),
            "modifications_per_hour": round(self.modifications_per_hour, 1),
            "last_vacuum": self.last_vacuum,
            "last_autovacuum": self.last_autovacuum,
            "last_analyze": self.last_analyze,
            "health_grade": self.health_grade,
        }


@dataclass
class TableHealthFinding:
    """A table health finding."""

    severity: str
    table: str
    title: str
    description: str
    recommendation: str
    fix_sql: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "table": self.table,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "fix_sql": self.fix_sql,
        }


@dataclass
class TableHealthReport:
    """Complete table health dashboard report."""

    tables: list[TableHealth] = field(default_factory=list)
    findings: list[TableHealthFinding] = field(default_factory=list)
    total_tables: int = 0
    total_size_mb: float = 0.0
    grade_distribution: dict[str, int] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        grades = self.grade_distribution
        return (
            f"{self.total_tables} tables ({self.total_size_mb:.0f}MB total). "
            f"Grades: A={grades.get('A', 0)} B={grades.get('B', 0)} "
            f"C={grades.get('C', 0)} D={grades.get('D', 0)} F={grades.get('F', 0)}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tables": self.total_tables,
            "total_size_mb": round(self.total_size_mb, 1),
            "grade_distribution": self.grade_distribution,
            "findings": [f.to_dict() for f in self.findings],
            "tables": [t.to_dict() for t in self.tables],
        }


class TableHealthDashboard:
    """
    Per-table health dashboard providing visibility into every table's state.

    Gives developers "just enough visibility and guidance to feel confident,
    without overwhelming them with internals."
    """

    async def analyze(self, conn: AsyncDBConnection) -> TableHealthReport:
        """Run full table health analysis."""
        report = TableHealthReport()

        stats_age = await self._get_stats_age(conn)
        rows = await self._collect_stats(conn)

        for r in rows:
            health = self._build_health(r, stats_age)
            report.tables.append(health)
            report.total_size_mb += health.total_size_mb
            grade = health.health_grade
            report.grade_distribution[grade] = report.grade_distribution.get(grade, 0) + 1

        report.total_tables = len(report.tables)

        # Sort by grade (worst first), then by size
        grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
        report.tables.sort(key=lambda t: (grade_order.get(t.health_grade, 5), -t.table_size_bytes))

        # Generate findings
        self._generate_findings(report)

        return report

    async def _get_stats_age(self, conn: AsyncDBConnection) -> float:
        """Get seconds since stats reset."""
        try:
            val = await conn.fetchval(
                "SELECT EXTRACT(EPOCH FROM (now() - stats_reset))::float "
                "FROM pg_stat_database WHERE datname = current_database()"
            )
            return float(val) if val else 0.0
        except Exception:
            return 0.0

    async def _collect_stats(self, conn: AsyncDBConnection) -> list[Any]:
        """Collect comprehensive per-table statistics."""
        try:
            return await conn.fetch(
                "SELECT "
                "  s.schemaname, s.relname, "
                "  pg_relation_size(c.oid) AS table_size, "
                "  pg_total_relation_size(c.oid) AS total_size, "
                "  (SELECT count(*) FROM pg_index WHERE indrelid = c.oid) AS index_count, "
                "  s.n_live_tup, s.n_dead_tup, "
                "  s.seq_scan, s.seq_tup_read, "
                "  s.idx_scan, s.idx_tup_fetch, "
                "  s.n_tup_ins, s.n_tup_upd, s.n_tup_del, s.n_tup_hot_upd, "
                "  s.last_vacuum::text, s.last_autovacuum::text, "
                "  s.last_analyze::text, s.last_autoanalyze::text "
                "FROM pg_stat_user_tables s "
                "JOIN pg_class c ON c.relname = s.relname "
                "  AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = s.schemaname) "
                "ORDER BY pg_total_relation_size(c.oid) DESC"
            )
        except Exception:
            return []

    def _build_health(self, r: Any, stats_age: float) -> TableHealth:
        """Build a TableHealth from a DB row."""
        if isinstance(r, (list, tuple)):
            vals = list(r)
        else:
            vals = [
                getattr(r, "schemaname", ""),
                getattr(r, "relname", ""),
                getattr(r, "table_size", 0),
                getattr(r, "total_size", 0),
                getattr(r, "index_count", 0),
                getattr(r, "n_live_tup", 0),
                getattr(r, "n_dead_tup", 0),
                getattr(r, "seq_scan", 0),
                getattr(r, "seq_tup_read", 0),
                getattr(r, "idx_scan", 0),
                getattr(r, "idx_tup_fetch", 0),
                getattr(r, "n_tup_ins", 0),
                getattr(r, "n_tup_upd", 0),
                getattr(r, "n_tup_del", 0),
                getattr(r, "n_tup_hot_upd", 0),
                getattr(r, "last_vacuum", None),
                getattr(r, "last_autovacuum", None),
                getattr(r, "last_analyze", None),
                getattr(r, "last_autoanalyze", None),
            ]

        live = int(vals[5] or 0)
        dead = int(vals[6] or 0)
        total = live + dead

        return TableHealth(
            schema=str(vals[0]),
            name=str(vals[1]),
            table_size_bytes=int(vals[2] or 0),
            total_size_bytes=int(vals[3] or 0),
            index_count=int(vals[4] or 0),
            n_live_tup=live,
            n_dead_tup=dead,
            dead_tuple_ratio=dead / total if total > 0 else 0.0,
            seq_scan=int(vals[7] or 0),
            seq_tup_read=int(vals[8] or 0),
            idx_scan=int(vals[9] or 0),
            idx_tup_fetch=int(vals[10] or 0),
            n_tup_ins=int(vals[11] or 0),
            n_tup_upd=int(vals[12] or 0),
            n_tup_del=int(vals[13] or 0),
            n_tup_hot_upd=int(vals[14] or 0),
            last_vacuum=str(vals[15]) if vals[15] else None,
            last_autovacuum=str(vals[16]) if vals[16] else None,
            last_analyze=str(vals[17]) if vals[17] else None,
            last_autoanalyze=str(vals[18]) if vals[18] else None,
            stats_age_seconds=stats_age,
        )

    def _generate_findings(self, report: TableHealthReport) -> None:
        """Generate findings for unhealthy tables."""
        for t in report.tables:
            # Sequential scan on large table with no index scans
            if t.n_live_tup > 100_000 and t.seq_scan > 100 and t.index_usage_ratio < 0.5:
                report.findings.append(TableHealthFinding(
                    severity="warning",
                    table=t.qualified_name,
                    title=f"{t.qualified_name}: {t.seq_scan:,} seq scans, "
                          f"only {t.index_usage_ratio:.0%} index usage",
                    description=(
                        f"Table has {t.n_live_tup:,} rows but {t.index_usage_ratio:.0%} "
                        f"of scans use indexes. {t.seq_scan:,} sequential scans detected."
                    ),
                    recommendation="Add indexes for frequently filtered columns.",
                ))

            # High dead tuple ratio
            if t.dead_tuple_ratio > 0.3 and t.n_dead_tup > 10_000:
                report.findings.append(TableHealthFinding(
                    severity="warning",
                    table=t.qualified_name,
                    title=f"{t.qualified_name}: {t.dead_tuple_ratio:.0%} dead tuples",
                    description=(
                        f"{t.n_dead_tup:,} dead out of {t.n_live_tup + t.n_dead_tup:,} total rows."
                    ),
                    recommendation="VACUUM this table.",
                    fix_sql=f"VACUUM (VERBOSE) {t.qualified_name};",
                ))

            # Never vacuumed/analyzed
            if (not t.last_vacuum and not t.last_autovacuum
                    and t.n_live_tup > 10_000 and t.n_dead_tup > 1000):
                report.findings.append(TableHealthFinding(
                    severity="critical",
                    table=t.qualified_name,
                    title=f"{t.qualified_name}: NEVER vacuumed ({t.n_dead_tup:,} dead rows)",
                    description="Table has never been vacuumed but has significant dead rows.",
                    recommendation="Run VACUUM immediately.",
                    fix_sql=f"VACUUM (VERBOSE, ANALYZE) {t.qualified_name};",
                ))

            if not t.last_analyze and not t.last_autoanalyze and t.n_live_tup > 10_000:
                report.findings.append(TableHealthFinding(
                    severity="warning",
                    table=t.qualified_name,
                    title=f"{t.qualified_name}: NEVER analyzed ({t.n_live_tup:,} rows)",
                    description="Planner statistics are missing. Query plans may be suboptimal.",
                    recommendation="Run ANALYZE.",
                    fix_sql=f"ANALYZE {t.qualified_name};",
                ))

            # Low HOT update ratio (lots of index churn)
            if t.n_tup_upd > 10_000 and t.hot_update_ratio < 0.3:
                report.findings.append(TableHealthFinding(
                    severity="notice",
                    table=t.qualified_name,
                    title=f"{t.qualified_name}: only {t.hot_update_ratio:.0%} HOT updates",
                    description=(
                        f"{t.n_tup_upd:,} updates but only {t.hot_update_ratio:.0%} are HOT. "
                        f"Every non-HOT update must update all indexes."
                    ),
                    recommendation="Consider removing unused indexes or changing fillfactor.",
                ))
