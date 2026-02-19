"""
Migration Safety Analyzer for QuerySense.

Analyzes SQL migration scripts for potential issues before they hit production.
This is the core engine behind `querysense predict`, `querysense migrate --safe`,
and the GitHub PR migration checker.

Capabilities:
- Lock duration estimation (ACCESS EXCLUSIVE vs SHARE UPDATE EXCLUSIVE)
- Data impact analysis (row rewrites, NULL backfills, constraint violations)
- Rollback SQL generation (automatic reverse migration)
- Performance impact prediction (index drops, column additions, type changes)
- Safe migration plan generation (batch operations, CONCURRENTLY hints)

Design principle: Offline-first. All analysis works without a database connection.
When a DSN is provided, estimates are refined with real table sizes and query stats.

Usage:
    from querysense.migration import MigrationAnalyzer, MigrationReport

    analyzer = MigrationAnalyzer()
    report = analyzer.analyze("ALTER TABLE orders ADD COLUMN user_id INT;")
    print(report.format())
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ============================================================================
# Data Models
# ============================================================================

class LockLevel(str, Enum):
    """PostgreSQL lock levels, ordered by severity."""
    ACCESS_SHARE = "ACCESS SHARE"              # SELECT
    ROW_SHARE = "ROW SHARE"                     # SELECT FOR UPDATE
    ROW_EXCLUSIVE = "ROW EXCLUSIVE"             # INSERT/UPDATE/DELETE
    SHARE_UPDATE_EXCLUSIVE = "SHARE UPDATE EXCLUSIVE"  # VACUUM, CREATE INDEX CONCURRENTLY
    SHARE = "SHARE"                             # CREATE INDEX
    SHARE_ROW_EXCLUSIVE = "SHARE ROW EXCLUSIVE"  # CREATE TRIGGER
    EXCLUSIVE = "EXCLUSIVE"                     # Refresh materialized view concurrently
    ACCESS_EXCLUSIVE = "ACCESS EXCLUSIVE"        # ALTER TABLE, DROP TABLE

    @property
    def severity(self) -> int:
        """Higher = more disruptive."""
        order = {
            "ACCESS SHARE": 0, "ROW SHARE": 1, "ROW EXCLUSIVE": 2,
            "SHARE UPDATE EXCLUSIVE": 3, "SHARE": 4,
            "SHARE ROW EXCLUSIVE": 5, "EXCLUSIVE": 6,
            "ACCESS EXCLUSIVE": 7,
        }
        return order.get(self.value, 0)

    @property
    def blocks_reads(self) -> bool:
        return self.severity >= 7

    @property
    def blocks_writes(self) -> bool:
        return self.severity >= 4


class RiskLevel(str, Enum):
    """Risk assessment for migration operations."""
    LOW = "low"          # Negligible impact
    MEDIUM = "medium"    # Brief disruption possible
    HIGH = "high"        # Extended lock or data rewrite
    CRITICAL = "critical"  # Potential data loss or extended downtime


@dataclass
class LockAnalysis:
    """Lock impact analysis for a migration statement."""
    lock_level: LockLevel
    estimated_duration_ms: float | None = None
    affected_table: str | None = None
    blocks_reads: bool = False
    blocks_writes: bool = False
    concurrent_query_impact: str = ""
    recommendation: str = ""


@dataclass
class DataImpact:
    """Data modification impact for a migration statement."""
    operation: str  # ADD COLUMN, DROP COLUMN, ALTER TYPE, etc.
    table: str
    column: str | None = None
    requires_rewrite: bool = False
    null_rows_created: bool = False
    data_loss_risk: bool = False
    affected_rows_estimate: str = "all rows"
    details: str = ""


@dataclass
class PerformanceImpact:
    """Performance impact prediction."""
    category: str  # "index_drop", "type_change", "constraint_add", etc.
    severity: RiskLevel
    description: str
    affected_queries: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class SafeMigrationStep:
    """A single step in a safe migration plan."""
    phase: int
    description: str
    sql: str
    estimated_duration: str = "instant"
    lock_level: str = "none"
    notes: str = ""


@dataclass
class MigrationReport:
    """Complete analysis report for a migration script."""
    original_sql: str
    statements: list[str]
    lock_analyses: list[LockAnalysis] = field(default_factory=list)
    data_impacts: list[DataImpact] = field(default_factory=list)
    performance_impacts: list[PerformanceImpact] = field(default_factory=list)
    rollback_sql: list[str] = field(default_factory=list)
    safe_plan: list[SafeMigrationStep] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.LOW

    # Optional: populated when DSN is provided
    table_row_counts: dict[str, int] = field(default_factory=dict)

    def format(self) -> str:
        """Format as human-readable report."""
        lines: list[str] = []
        risk_icon = {
            "low": "[OK]", "medium": "[!!]",
            "high": "[!!!]", "critical": "[DANGER]",
        }

        lines.append("=" * 70)
        lines.append("  MIGRATION IMPACT PREDICTION")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Overall Risk: {risk_icon.get(self.overall_risk.value, '?')} {self.overall_risk.value.upper()}")
        lines.append(f"Statements: {len(self.statements)}")
        lines.append("")

        # Lock Analysis
        if self.lock_analyses:
            lines.append("LOCK ANALYSIS")
            lines.append("-" * 40)
            for la in self.lock_analyses:
                lock_icon = "[!!!]" if la.blocks_reads else ("[!!]" if la.blocks_writes else "[OK]")
                lines.append(f"  {lock_icon} {la.lock_level.value}")
                if la.affected_table:
                    lines.append(f"      Table: {la.affected_table}")
                if la.estimated_duration_ms is not None:
                    if la.estimated_duration_ms < 100:
                        lines.append(f"      Duration: ~{la.estimated_duration_ms:.0f}ms (fast)")
                    elif la.estimated_duration_ms < 5000:
                        lines.append(f"      Duration: ~{la.estimated_duration_ms:.0f}ms")
                    else:
                        lines.append(f"      Duration: ~{la.estimated_duration_ms / 1000:.1f}s (SLOW)")
                if la.concurrent_query_impact:
                    lines.append(f"      Impact: {la.concurrent_query_impact}")
                if la.recommendation:
                    lines.append(f"      Recommendation: {la.recommendation}")
            lines.append("")

        # Data Impact
        if self.data_impacts:
            lines.append("DATA IMPACT")
            lines.append("-" * 40)
            for di in self.data_impacts:
                icon = "[!!!]" if di.data_loss_risk else ("[!!]" if di.requires_rewrite else "[OK]")
                lines.append(f"  {icon} {di.operation} on {di.table}")
                if di.column:
                    lines.append(f"      Column: {di.column}")
                if di.requires_rewrite:
                    lines.append(f"      Table rewrite required ({di.affected_rows_estimate})")
                if di.null_rows_created:
                    lines.append(f"      New NULL values in {di.affected_rows_estimate}")
                if di.data_loss_risk:
                    lines.append(f"      DATA LOSS RISK: {di.details}")
                elif di.details:
                    lines.append(f"      {di.details}")
            lines.append("")

        # Performance Impact
        if self.performance_impacts:
            lines.append("PERFORMANCE IMPACT")
            lines.append("-" * 40)
            for pi in self.performance_impacts:
                icon = {"low": "[OK]", "medium": "[!!]", "high": "[!!!]", "critical": "[DANGER]"}.get(pi.severity.value, "?")
                lines.append(f"  {icon} {pi.description}")
                if pi.recommendation:
                    lines.append(f"      Fix: {pi.recommendation}")
            lines.append("")

        # Rollback SQL
        if self.rollback_sql:
            lines.append("ROLLBACK SQL")
            lines.append("-" * 40)
            for sql in self.rollback_sql:
                lines.append(f"  {sql}")
            lines.append("")

        # Safe Migration Plan
        if self.safe_plan:
            lines.append("GENERATED SAFE MIGRATION")
            lines.append("-" * 40)
            for step in self.safe_plan:
                lines.append(f"  Phase {step.phase}: {step.description}")
                lines.append(f"    Lock: {step.lock_level} | Duration: {step.estimated_duration}")
                for sql_line in step.sql.split("\n"):
                    lines.append(f"    {sql_line}")
                if step.notes:
                    lines.append(f"    Note: {step.notes}")
                lines.append("")

        # Warnings
        if self.warnings:
            lines.append("WARNINGS")
            lines.append("-" * 40)
            for w in self.warnings:
                lines.append(f"  [!!] {w}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    def format_json(self) -> dict[str, Any]:
        """Format as JSON-serializable dict."""
        return {
            "overall_risk": self.overall_risk.value,
            "statements": self.statements,
            "lock_analyses": [
                {
                    "lock_level": la.lock_level.value,
                    "estimated_duration_ms": la.estimated_duration_ms,
                    "affected_table": la.affected_table,
                    "blocks_reads": la.blocks_reads,
                    "blocks_writes": la.blocks_writes,
                    "concurrent_query_impact": la.concurrent_query_impact,
                    "recommendation": la.recommendation,
                }
                for la in self.lock_analyses
            ],
            "data_impacts": [
                {
                    "operation": di.operation,
                    "table": di.table,
                    "column": di.column,
                    "requires_rewrite": di.requires_rewrite,
                    "null_rows_created": di.null_rows_created,
                    "data_loss_risk": di.data_loss_risk,
                    "details": di.details,
                }
                for di in self.data_impacts
            ],
            "performance_impacts": [
                {
                    "category": pi.category,
                    "severity": pi.severity.value,
                    "description": pi.description,
                    "recommendation": pi.recommendation,
                }
                for pi in self.performance_impacts
            ],
            "rollback_sql": self.rollback_sql,
            "safe_plan": [
                {
                    "phase": s.phase,
                    "description": s.description,
                    "sql": s.sql,
                    "estimated_duration": s.estimated_duration,
                    "lock_level": s.lock_level,
                }
                for s in self.safe_plan
            ],
            "warnings": self.warnings,
        }

    def format_pr_comment(self) -> str:
        """Format as a GitHub PR comment (Markdown)."""
        risk_emoji = {
            "low": "OK", "medium": "Warning",
            "high": "DANGER", "critical": "CRITICAL",
        }

        lines: list[str] = []
        lines.append("## QuerySense Migration Analysis")
        lines.append("")
        lines.append(f"**Overall Risk:** {risk_emoji.get(self.overall_risk.value, '?')} {self.overall_risk.value.upper()}")
        lines.append("")

        # Lock summary
        if self.lock_analyses:
            lines.append("### Lock Analysis")
            for la in self.lock_analyses:
                icon = "!!!" if la.blocks_reads else ("!!" if la.blocks_writes else "OK")
                dur = ""
                if la.estimated_duration_ms is not None:
                    if la.estimated_duration_ms < 1000:
                        dur = f" (~{la.estimated_duration_ms:.0f}ms)"
                    else:
                        dur = f" (~{la.estimated_duration_ms / 1000:.1f}s)"
                lines.append(f"- **{icon}** {la.lock_level.value}{dur}")
                if la.recommendation:
                    lines.append(f"  - {la.recommendation}")
            lines.append("")

        # Performance
        if self.performance_impacts:
            lines.append("### Performance Impact")
            for pi in self.performance_impacts:
                icon = {"low": "OK", "medium": "!!", "high": "!!!", "critical": "DANGER"}.get(pi.severity.value, "?")
                lines.append(f"- **{icon}** {pi.description}")
                if pi.recommendation:
                    lines.append(f"  - {pi.recommendation}")
            lines.append("")

        # Rollback
        if self.rollback_sql:
            lines.append("### Rollback Available")
            lines.append("```sql")
            for sql in self.rollback_sql:
                lines.append(sql)
            lines.append("```")
            lines.append("")

        # Safe plan
        if self.safe_plan:
            lines.append("<details><summary>Generated Safe Migration Plan</summary>")
            lines.append("")
            lines.append("```sql")
            for step in self.safe_plan:
                lines.append(f"-- Phase {step.phase}: {step.description}")
                lines.append(step.sql)
                lines.append("")
            lines.append("```")
            lines.append("</details>")
            lines.append("")

        # Warnings
        if self.warnings:
            lines.append("### Warnings")
            for w in self.warnings:
                lines.append(f"- {w}")

        return "\n".join(lines)


# ============================================================================
# Migration Analyzer Engine
# ============================================================================

class MigrationAnalyzer:
    """
    Analyzes SQL migration scripts for safety, performance, and correctness.

    Works offline by default. When table_sizes is provided (from a live DB),
    estimates are refined with real data.
    """

    def __init__(
        self,
        table_sizes: dict[str, int] | None = None,
        heavy_indexes: set[str] | None = None,
    ) -> None:
        """
        Args:
            table_sizes: Mapping of table name to row count (from live DB)
            heavy_indexes: Set of index names known to be heavily used
        """
        self._table_sizes = table_sizes or {}
        self._heavy_indexes = heavy_indexes or set()

    def analyze(self, sql: str) -> MigrationReport:
        """
        Analyze a complete migration script.

        Handles multi-statement scripts separated by semicolons.
        """
        statements = self._split_statements(sql)
        report = MigrationReport(original_sql=sql, statements=statements)

        for stmt in statements:
            stmt_upper = stmt.upper().strip()

            if "ALTER TABLE" in stmt_upper:
                self._analyze_alter_table(stmt, report)
            elif "CREATE INDEX" in stmt_upper:
                self._analyze_create_index(stmt, report)
            elif "DROP INDEX" in stmt_upper:
                self._analyze_drop_index(stmt, report)
            elif "DROP TABLE" in stmt_upper:
                self._analyze_drop_table(stmt, report)
            elif "CREATE TABLE" in stmt_upper:
                self._analyze_create_table(stmt, report)
            elif "TRUNCATE" in stmt_upper:
                self._analyze_truncate(stmt, report)
            elif any(kw in stmt_upper for kw in ("INSERT", "UPDATE", "DELETE")):
                self._analyze_dml(stmt, report)

        # Compute overall risk
        report.overall_risk = self._compute_overall_risk(report)

        # Generate safe migration plan
        report.safe_plan = self._generate_safe_plan(sql, report)

        return report

    # ========================================================================
    # Statement Parsers
    # ========================================================================

    def _analyze_alter_table(self, stmt: str, report: MigrationReport) -> None:
        """Analyze ALTER TABLE statement."""
        table = self._extract_table_name(stmt, "ALTER TABLE")
        row_count = self._table_sizes.get(table, 0) if table else 0
        stmt_upper = stmt.upper()

        # ADD COLUMN (must not match ADD CONSTRAINT / ADD CHECK)
        add_col_match = re.search(
            r"ADD\s+(?:COLUMN\s+)?(\w+)\s+(\w+(?:\([^)]*\))?)",
            stmt, re.IGNORECASE,
        )
        # Exclude ADD CONSTRAINT / ADD CHECK / ADD PRIMARY / ADD FOREIGN / ADD UNIQUE
        excluded_keywords = {"CONSTRAINT", "CHECK", "PRIMARY", "FOREIGN", "UNIQUE", "INDEX"}
        if add_col_match and add_col_match.group(1).upper() not in excluded_keywords:
            col_name = add_col_match.group(1)
            col_type = add_col_match.group(2)
            has_default = "DEFAULT" in stmt_upper
            has_not_null = "NOT NULL" in stmt_upper

            # PostgreSQL 11+ can add columns with non-volatile defaults without rewrite
            needs_rewrite = has_not_null and not has_default
            # Volatile defaults (e.g., DEFAULT now()) always require rewrite
            if has_default and re.search(r"DEFAULT\s+(now|current_|random|gen_random)", stmt, re.IGNORECASE):
                needs_rewrite = True

            lock = LockAnalysis(
                lock_level=LockLevel.ACCESS_EXCLUSIVE,
                affected_table=table,
                blocks_reads=needs_rewrite,
                blocks_writes=True,
            )

            if needs_rewrite:
                est_ms = max(100, row_count * 0.01) if row_count else None
                lock.estimated_duration_ms = est_ms
                lock.concurrent_query_impact = "All reads and writes blocked during table rewrite"
                lock.recommendation = (
                    f"Add column as NULL first, backfill, then SET NOT NULL"
                )
                report.warnings.append(
                    f"NOT NULL without DEFAULT on {table}.{col_name} forces table rewrite"
                )
            else:
                lock.estimated_duration_ms = 10.0  # Metadata-only change
                lock.concurrent_query_impact = "Brief metadata lock only"

            report.lock_analyses.append(lock)

            report.data_impacts.append(DataImpact(
                operation="ADD COLUMN",
                table=table or "unknown",
                column=col_name,
                requires_rewrite=needs_rewrite,
                null_rows_created=not has_default and not has_not_null,
                affected_rows_estimate=f"{row_count:,} rows" if row_count else "all rows",
                details=(
                    f"Column {col_name} ({col_type}) added"
                    + ("; table rewrite required" if needs_rewrite else "")
                    + (f"; {row_count:,} rows get NULL" if not has_default and row_count else "")
                ),
            ))

            # Generate rollback
            if table:
                report.rollback_sql.append(
                    f"ALTER TABLE {table} DROP COLUMN IF EXISTS {col_name};"
                )

        # DROP COLUMN
        drop_col_match = re.search(
            r"DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?(\w+)",
            stmt, re.IGNORECASE,
        )
        if drop_col_match and "DROP COLUMN" in stmt_upper:
            col_name = drop_col_match.group(1)

            report.lock_analyses.append(LockAnalysis(
                lock_level=LockLevel.ACCESS_EXCLUSIVE,
                affected_table=table,
                estimated_duration_ms=10.0,
                blocks_reads=False,
                blocks_writes=True,
                concurrent_query_impact="Brief metadata lock; column data remains until VACUUM",
                recommendation="Ensure no queries reference this column before dropping",
            ))

            report.data_impacts.append(DataImpact(
                operation="DROP COLUMN",
                table=table or "unknown",
                column=col_name,
                data_loss_risk=True,
                details=f"Column {col_name} will be dropped; data is NOT recoverable after VACUUM",
            ))

            report.performance_impacts.append(PerformanceImpact(
                category="column_drop",
                severity=RiskLevel.HIGH,
                description=f"Dropping {col_name} from {table} - verify no queries reference it",
                recommendation="Run `querysense scan` to find queries using this column",
            ))

        # ALTER COLUMN TYPE
        type_match = re.search(
            r"ALTER\s+(?:COLUMN\s+)?(\w+)\s+(?:SET\s+DATA\s+)?TYPE\s+(\w+)",
            stmt, re.IGNORECASE,
        )
        if type_match:
            col_name = type_match.group(1)
            new_type = type_match.group(2)

            report.lock_analyses.append(LockAnalysis(
                lock_level=LockLevel.ACCESS_EXCLUSIVE,
                affected_table=table,
                estimated_duration_ms=max(500, row_count * 0.05) if row_count else None,
                blocks_reads=True,
                blocks_writes=True,
                concurrent_query_impact="Full table rewrite - ALL queries blocked",
                recommendation="Consider creating new column, backfilling, then swapping",
            ))

            report.data_impacts.append(DataImpact(
                operation="ALTER TYPE",
                table=table or "unknown",
                column=col_name,
                requires_rewrite=True,
                affected_rows_estimate=f"{row_count:,} rows" if row_count else "all rows",
                details=f"Type change to {new_type} requires full table rewrite",
            ))

            report.warnings.append(
                f"Type change on {table}.{col_name} to {new_type} will rewrite the entire table"
            )

        # ADD CONSTRAINT
        if "ADD CONSTRAINT" in stmt_upper or "ADD CHECK" in stmt_upper:
            constraint_match = re.search(
                r"ADD\s+CONSTRAINT\s+(\w+)", stmt, re.IGNORECASE,
            )
            constraint_name = constraint_match.group(1) if constraint_match else "unnamed"

            is_not_valid = "NOT VALID" in stmt_upper

            if is_not_valid:
                report.lock_analyses.append(LockAnalysis(
                    lock_level=LockLevel.SHARE_UPDATE_EXCLUSIVE,
                    affected_table=table,
                    estimated_duration_ms=10.0,
                    blocks_reads=False,
                    blocks_writes=False,
                    concurrent_query_impact="Minimal - constraint only checked for new rows",
                    recommendation="Good pattern! Follow with VALIDATE CONSTRAINT separately",
                ))
            else:
                report.lock_analyses.append(LockAnalysis(
                    lock_level=LockLevel.ACCESS_EXCLUSIVE,
                    affected_table=table,
                    estimated_duration_ms=max(200, row_count * 0.02) if row_count else None,
                    blocks_reads=False,
                    blocks_writes=True,
                    concurrent_query_impact="Scans all rows to validate constraint",
                    recommendation=(
                        f"Use NOT VALID to add without scanning, "
                        f"then VALIDATE CONSTRAINT {constraint_name} separately"
                    ),
                ))

            if table:
                report.rollback_sql.append(
                    f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint_name};"
                )

        # SET NOT NULL
        if "SET NOT NULL" in stmt_upper:
            col_match = re.search(
                r"ALTER\s+(?:COLUMN\s+)?(\w+)\s+SET\s+NOT\s+NULL",
                stmt, re.IGNORECASE,
            )
            if col_match:
                col_name = col_match.group(1)
                report.lock_analyses.append(LockAnalysis(
                    lock_level=LockLevel.ACCESS_EXCLUSIVE,
                    affected_table=table,
                    estimated_duration_ms=max(100, row_count * 0.01) if row_count else None,
                    blocks_reads=False,
                    blocks_writes=True,
                    concurrent_query_impact="Full table scan to verify no NULLs",
                    recommendation=(
                        "Add CHECK constraint NOT VALID first, then validate"
                    ),
                ))

        # RENAME
        if "RENAME" in stmt_upper:
            report.lock_analyses.append(LockAnalysis(
                lock_level=LockLevel.ACCESS_EXCLUSIVE,
                affected_table=table,
                estimated_duration_ms=5.0,
                blocks_reads=False,
                blocks_writes=True,
                concurrent_query_impact="Instant metadata change",
            ))

    def _analyze_create_index(self, stmt: str, report: MigrationReport) -> None:
        """Analyze CREATE INDEX statement."""
        is_concurrent = "CONCURRENTLY" in stmt.upper()
        table = self._extract_table_name(stmt, "ON")
        row_count = self._table_sizes.get(table, 0) if table else 0

        idx_match = re.search(
            r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\w+)",
            stmt, re.IGNORECASE,
        )
        idx_name = idx_match.group(1) if idx_match else "unnamed"

        if is_concurrent:
            report.lock_analyses.append(LockAnalysis(
                lock_level=LockLevel.SHARE_UPDATE_EXCLUSIVE,
                affected_table=table,
                estimated_duration_ms=max(500, row_count * 0.1) if row_count else None,
                blocks_reads=False,
                blocks_writes=False,
                concurrent_query_impact="No blocking - index built in background",
                recommendation="Good! CONCURRENTLY is the safe approach",
            ))
        else:
            report.lock_analyses.append(LockAnalysis(
                lock_level=LockLevel.SHARE,
                affected_table=table,
                estimated_duration_ms=max(200, row_count * 0.05) if row_count else None,
                blocks_reads=False,
                blocks_writes=True,
                concurrent_query_impact="Blocks INSERT/UPDATE/DELETE during build",
                recommendation="Use CREATE INDEX CONCURRENTLY to avoid write blocking",
            ))
            report.warnings.append(
                f"CREATE INDEX without CONCURRENTLY blocks writes on {table}"
            )

        report.rollback_sql.append(f"DROP INDEX IF EXISTS {idx_name};")

    def _analyze_drop_index(self, stmt: str, report: MigrationReport) -> None:
        """Analyze DROP INDEX statement."""
        is_concurrent = "CONCURRENTLY" in stmt.upper()

        idx_match = re.search(
            r"DROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?(\w+)",
            stmt, re.IGNORECASE,
        )
        idx_name = idx_match.group(1) if idx_match else "unknown"

        is_heavily_used = idx_name in self._heavy_indexes

        lock_level = (
            LockLevel.SHARE_UPDATE_EXCLUSIVE if is_concurrent
            else LockLevel.ACCESS_EXCLUSIVE
        )

        report.lock_analyses.append(LockAnalysis(
            lock_level=lock_level,
            estimated_duration_ms=5.0,
            blocks_reads=not is_concurrent,
            blocks_writes=not is_concurrent,
            concurrent_query_impact=(
                "No blocking" if is_concurrent
                else "Brief exclusive lock on the table"
            ),
        ))

        severity = RiskLevel.HIGH if is_heavily_used else RiskLevel.MEDIUM
        report.performance_impacts.append(PerformanceImpact(
            category="index_drop",
            severity=severity,
            description=(
                f"Dropping index {idx_name}"
                + (" (HEAVILY USED)" if is_heavily_used else "")
            ),
            recommendation=(
                f"Verify no queries depend on {idx_name} with `querysense scan`"
            ),
        ))

        report.warnings.append(
            f"Cannot auto-generate rollback for DROP INDEX (original CREATE INDEX unknown)"
        )

    def _analyze_drop_table(self, stmt: str, report: MigrationReport) -> None:
        """Analyze DROP TABLE statement."""
        table = self._extract_table_name(stmt, "DROP TABLE")
        has_cascade = "CASCADE" in stmt.upper()

        report.lock_analyses.append(LockAnalysis(
            lock_level=LockLevel.ACCESS_EXCLUSIVE,
            affected_table=table,
            estimated_duration_ms=10.0,
            blocks_reads=True,
            blocks_writes=True,
            concurrent_query_impact="Table fully locked then removed",
        ))

        report.data_impacts.append(DataImpact(
            operation="DROP TABLE",
            table=table or "unknown",
            data_loss_risk=True,
            details=(
                f"ALL data in {table} will be permanently lost"
                + ("; CASCADE will drop dependent objects" if has_cascade else "")
            ),
        ))

        if has_cascade:
            report.warnings.append(
                f"DROP TABLE {table} CASCADE will also drop dependent views, "
                f"foreign keys, and triggers"
            )

    def _analyze_create_table(self, stmt: str, report: MigrationReport) -> None:
        """Analyze CREATE TABLE statement."""
        table = self._extract_table_name(stmt, "CREATE TABLE")

        report.lock_analyses.append(LockAnalysis(
            lock_level=LockLevel.ACCESS_EXCLUSIVE,
            affected_table=table,
            estimated_duration_ms=5.0,
            blocks_reads=False,
            blocks_writes=False,
            concurrent_query_impact="No impact - new table",
        ))

        if table:
            report.rollback_sql.append(f"DROP TABLE IF EXISTS {table};")

    def _analyze_truncate(self, stmt: str, report: MigrationReport) -> None:
        """Analyze TRUNCATE statement."""
        table = self._extract_table_name(stmt, "TRUNCATE")

        report.lock_analyses.append(LockAnalysis(
            lock_level=LockLevel.ACCESS_EXCLUSIVE,
            affected_table=table,
            estimated_duration_ms=50.0,
            blocks_reads=True,
            blocks_writes=True,
            concurrent_query_impact="Full exclusive lock on table",
        ))

        report.data_impacts.append(DataImpact(
            operation="TRUNCATE",
            table=table or "unknown",
            data_loss_risk=True,
            details="ALL data removed instantly (not recoverable without backup)",
        ))

    def _analyze_dml(self, stmt: str, report: MigrationReport) -> None:
        """Analyze INSERT/UPDATE/DELETE in migrations."""
        stmt_upper = stmt.upper().strip()

        if stmt_upper.startswith("UPDATE"):
            table = self._extract_table_name(stmt, "UPDATE")
            has_where = "WHERE" in stmt_upper
            if not has_where:
                report.warnings.append(
                    f"UPDATE on {table} without WHERE clause affects ALL rows"
                )
                report.data_impacts.append(DataImpact(
                    operation="UPDATE (no WHERE)",
                    table=table or "unknown",
                    requires_rewrite=False,
                    affected_rows_estimate="ALL rows",
                    details="Consider adding WHERE clause or batching",
                ))
        elif stmt_upper.startswith("DELETE"):
            table = self._extract_table_name(stmt, "FROM")
            has_where = "WHERE" in stmt_upper
            if not has_where:
                report.warnings.append(
                    f"DELETE FROM {table} without WHERE clause deletes ALL rows"
                )
                report.data_impacts.append(DataImpact(
                    operation="DELETE (no WHERE)",
                    table=table or "unknown",
                    data_loss_risk=True,
                    affected_rows_estimate="ALL rows",
                    details="Use TRUNCATE if intent is to clear table",
                ))

    # ========================================================================
    # Safe Migration Plan Generation
    # ========================================================================

    def _generate_safe_plan(
        self, original_sql: str, report: MigrationReport
    ) -> list[SafeMigrationStep]:
        """Generate a safe, phased migration plan."""
        steps: list[SafeMigrationStep] = []
        phase = 1

        for stmt in report.statements:
            stmt_upper = stmt.upper().strip()

            # ADD COLUMN with NOT NULL without DEFAULT -> split into phases
            if (
                "ALTER TABLE" in stmt_upper
                and "ADD" in stmt_upper
                and "NOT NULL" in stmt_upper
                and "DEFAULT" not in stmt_upper
            ):
                table = self._extract_table_name(stmt, "ALTER TABLE")
                col_match = re.search(
                    r"ADD\s+(?:COLUMN\s+)?(\w+)\s+(\w+(?:\([^)]*\))?)",
                    stmt, re.IGNORECASE,
                )
                if col_match:
                    col_name = col_match.group(1)
                    col_type = col_match.group(2)

                    steps.append(SafeMigrationStep(
                        phase=phase,
                        description=f"Add {col_name} as nullable (fast, no rewrite)",
                        sql=f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type};",
                        estimated_duration="instant",
                        lock_level="ACCESS EXCLUSIVE (brief)",
                        notes="Metadata-only change in PG11+",
                    ))
                    phase += 1

                    row_count = self._table_sizes.get(table, 0) if table else 0
                    batch_size = 1000
                    batches = max(1, row_count // batch_size) if row_count else 50

                    steps.append(SafeMigrationStep(
                        phase=phase,
                        description=f"Backfill {col_name} in batches (safe, low lock)",
                        sql=(
                            f"-- Backfill in batches of {batch_size}\n"
                            f"DO $$\n"
                            f"DECLARE\n"
                            f"  batch_start BIGINT := 0;\n"
                            f"  batch_size BIGINT := {batch_size};\n"
                            f"  max_id BIGINT;\n"
                            f"BEGIN\n"
                            f"  SELECT MAX(id) INTO max_id FROM {table};\n"
                            f"  WHILE batch_start <= COALESCE(max_id, 0) LOOP\n"
                            f"    UPDATE {table}\n"
                            f"    SET {col_name} = <your_value_here>\n"
                            f"    WHERE id BETWEEN batch_start AND batch_start + batch_size - 1\n"
                            f"      AND {col_name} IS NULL;\n"
                            f"    batch_start := batch_start + batch_size;\n"
                            f"    PERFORM pg_sleep(0.1);  -- Rate limit\n"
                            f"    COMMIT;\n"
                            f"  END LOOP;\n"
                            f"END $$;"
                        ),
                        estimated_duration=f"~{batches * 0.2:.0f}s (batched)",
                        lock_level="ROW EXCLUSIVE (per batch)",
                        notes="Adjust batch_size based on table size and load",
                    ))
                    phase += 1

                    steps.append(SafeMigrationStep(
                        phase=phase,
                        description=f"Add NOT NULL constraint (validates existing data)",
                        sql=(
                            f"-- Add constraint without full lock (PG12+)\n"
                            f"ALTER TABLE {table} ADD CONSTRAINT {table}_{col_name}_not_null\n"
                            f"  CHECK ({col_name} IS NOT NULL) NOT VALID;\n"
                            f"ALTER TABLE {table} VALIDATE CONSTRAINT {table}_{col_name}_not_null;\n"
                            f"-- Then set the actual NOT NULL\n"
                            f"ALTER TABLE {table} ALTER COLUMN {col_name} SET NOT NULL;\n"
                            f"ALTER TABLE {table} DROP CONSTRAINT {table}_{col_name}_not_null;"
                        ),
                        estimated_duration="varies by table size",
                        lock_level="SHARE UPDATE EXCLUSIVE (validation)",
                    ))
                    phase += 1
                continue

            # CREATE INDEX without CONCURRENTLY -> add CONCURRENTLY
            if "CREATE INDEX" in stmt_upper and "CONCURRENTLY" not in stmt_upper:
                safe_stmt = re.sub(
                    r"CREATE\s+(UNIQUE\s+)?INDEX",
                    r"CREATE \1INDEX CONCURRENTLY",
                    stmt,
                    flags=re.IGNORECASE,
                ).strip()
                steps.append(SafeMigrationStep(
                    phase=phase,
                    description="Create index without blocking writes",
                    sql=safe_stmt,
                    estimated_duration="varies (background build)",
                    lock_level="SHARE UPDATE EXCLUSIVE (non-blocking)",
                    notes="CONCURRENTLY cannot run inside a transaction",
                ))
                phase += 1
                continue

            # Everything else: keep as-is with a note
            steps.append(SafeMigrationStep(
                phase=phase,
                description="Execute original statement",
                sql=stmt.strip() + (";"),
                lock_level="varies",
            ))
            phase += 1

        return steps

    # ========================================================================
    # Helpers
    # ========================================================================

    def _split_statements(self, sql: str) -> list[str]:
        """Split SQL into individual statements."""
        from querysense.migration.sql_utils import split_statements

        return split_statements(sql, strip_comments=True)

    def _extract_table_name(self, stmt: str, keyword: str) -> str | None:
        """Extract table name after a keyword."""
        pattern = re.compile(
            rf"{keyword}\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:ONLY\s+)?(\w+(?:\.\w+)?)",
            re.IGNORECASE,
        )
        match = pattern.search(stmt)
        return match.group(1) if match else None

    def _compute_overall_risk(self, report: MigrationReport) -> RiskLevel:
        """Compute overall risk from individual analyses."""
        if any(di.data_loss_risk for di in report.data_impacts):
            return RiskLevel.CRITICAL

        if any(la.blocks_reads for la in report.lock_analyses):
            return RiskLevel.HIGH

        if any(la.blocks_writes and (la.estimated_duration_ms or 0) > 5000
               for la in report.lock_analyses):
            return RiskLevel.HIGH

        if any(pi.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)
               for pi in report.performance_impacts):
            return RiskLevel.HIGH

        if any(la.blocks_writes for la in report.lock_analyses):
            return RiskLevel.MEDIUM

        return RiskLevel.LOW
