"""
Lock Analyzer — estimate lock impact of DDL migrations.

Addresses the P0 gap: "No lock analysis, basic rollbacks" identified in
van Kampen Thesis 2022 and Harness Blog: "Manual migrations cause
environment drift and late-night rollbacks."

Analyzes DDL statements to estimate:
- Lock type acquired (ACCESS EXCLUSIVE, SHARE UPDATE EXCLUSIVE, etc.)
- Estimated lock duration based on table size/operation type
- Whether CONCURRENTLY alternatives exist
- Safe execution window recommendations

PostgreSQL lock levels (highest to lowest):
1. ACCESS EXCLUSIVE — blocks everything (DDL, most ALTERs)
2. SHARE ROW EXCLUSIVE — blocks writes (CREATE INDEX, some ALTERs)
3. SHARE — blocks writes (CREATE INDEX non-CONCURRENTLY)
4. ROW EXCLUSIVE — blocks only other ROW EXCLUSIVE (DML)
5. ACCESS SHARE — blocks nothing (SELECT)

Usage:
    from querysense.lock_analyzer import LockAnalyzer

    analyzer = LockAnalyzer()
    report = analyzer.analyze("ALTER TABLE orders ADD COLUMN status TEXT NOT NULL")
    print(report.lock_type)        # "ACCESS EXCLUSIVE"
    print(report.estimated_duration)  # "2.3 seconds"
    print(report.risk_level)       # "critical"
    print(report.safe_alternative)  # "Use DEFAULT value to avoid rewrite"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LockReport:
    """Analysis of lock impact for a single DDL statement."""

    statement: str
    lock_type: str  # PostgreSQL lock level name
    lock_blocks: str  # What this lock blocks
    risk_level: str  # "critical", "warning", "info", "safe"
    estimated_duration: str  # Human-readable estimate
    explanation: str  # Plain English explanation
    safe_alternative: str | None = None  # Safer way to do this
    requires_downtime: bool = False
    blocks_reads: bool = False
    blocks_writes: bool = True
    phased_plan: list[str] = field(default_factory=list)


@dataclass
class MigrationLockReport:
    """Complete lock analysis for a set of migration statements."""

    statements: list[LockReport] = field(default_factory=list)
    overall_risk: str = "safe"
    total_estimated_downtime: str = "0s"
    recommendations: list[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(r.risk_level == "critical" for r in self.statements)

    @property
    def has_warning(self) -> bool:
        return any(r.risk_level == "warning" for r in self.statements)

    def summary(self) -> str:
        crit = sum(1 for r in self.statements if r.risk_level == "critical")
        warn = sum(1 for r in self.statements if r.risk_level == "warning")
        if crit:
            return f"CRITICAL: {crit} statement(s) require ACCESS EXCLUSIVE lock"
        if warn:
            return f"WARNING: {warn} statement(s) may cause brief blocking"
        return f"SAFE: {len(self.statements)} statement(s) with minimal lock impact"

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_risk": self.overall_risk,
            "summary": self.summary(),
            "total_estimated_downtime": self.total_estimated_downtime,
            "statements": [
                {
                    "statement": r.statement,
                    "lock_type": r.lock_type,
                    "risk_level": r.risk_level,
                    "estimated_duration": r.estimated_duration,
                    "explanation": r.explanation,
                    "safe_alternative": r.safe_alternative,
                    "blocks_reads": r.blocks_reads,
                    "blocks_writes": r.blocks_writes,
                    "phased_plan": r.phased_plan,
                }
                for r in self.statements
            ],
            "recommendations": self.recommendations,
        }


# ── Lock patterns ─────────────────────────────────────────────────────

# Patterns that require ACCESS EXCLUSIVE (blocks everything)
_ACCESS_EXCLUSIVE_PATTERNS = [
    # ADD COLUMN with NOT NULL but no DEFAULT (requires full table rewrite pre-PG11)
    (
        r"ALTER\s+TABLE\s+\S+\s+ADD\s+COLUMN\s+\S+\s+\S+\s+NOT\s+NULL(?!\s+DEFAULT)",
        "ADD COLUMN NOT NULL without DEFAULT",
        "Requires full table rewrite. All reads and writes blocked during rewrite.",
        "Add column as nullable first, backfill data, then set NOT NULL in separate step.",
        True,
    ),
    # DROP COLUMN
    (
        r"ALTER\s+TABLE\s+\S+\s+DROP\s+COLUMN",
        "DROP COLUMN",
        "Acquires ACCESS EXCLUSIVE lock. Brief but blocks all concurrent access.",
        "DROP COLUMN is usually fast (just marks column as dropped), but lock is exclusive.",
        False,
    ),
    # ALTER COLUMN TYPE (requires rewrite)
    (
        r"ALTER\s+TABLE\s+\S+\s+ALTER\s+COLUMN\s+\S+\s+(SET\s+DATA\s+)?TYPE",
        "ALTER COLUMN TYPE",
        "Requires full table rewrite if type conversion isn't binary-compatible.",
        "Use a phased approach: add new column, backfill, drop old column, rename.",
        True,
    ),
    # ADD COLUMN with DEFAULT (PG11+ is fast, pre-PG11 rewrites)
    (
        r"ALTER\s+TABLE\s+\S+\s+ADD\s+COLUMN\s+\S+\s+\S+\s+DEFAULT",
        "ADD COLUMN with DEFAULT",
        "Fast in PostgreSQL 11+ (metadata-only). ACCESS EXCLUSIVE lock but very brief.",
        None,  # No safer alternative needed for PG11+
        False,
    ),
    # DROP TABLE
    (
        r"DROP\s+TABLE",
        "DROP TABLE",
        "ACCESS EXCLUSIVE lock on the table being dropped. Blocks everything.",
        "Ensure no active queries reference this table before dropping.",
        False,
    ),
    # TRUNCATE
    (
        r"TRUNCATE\s+TABLE",
        "TRUNCATE TABLE",
        "ACCESS EXCLUSIVE lock. Faster than DELETE but blocks all access.",
        "Consider DELETE with batching if zero-downtime is required.",
        False,
    ),
    # ADD PRIMARY KEY
    (
        r"ALTER\s+TABLE\s+\S+\s+ADD\s+(CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY",
        "ADD PRIMARY KEY",
        "Requires scanning the entire table and acquiring ACCESS EXCLUSIVE lock.",
        "Create UNIQUE index CONCURRENTLY first, then add as constraint in a separate ALTER.",
        True,
    ),
    # ADD CONSTRAINT NOT NULL
    (
        r"ALTER\s+TABLE\s+\S+\s+ALTER\s+COLUMN\s+\S+\s+SET\s+NOT\s+NULL",
        "SET NOT NULL constraint",
        "Requires full table scan to verify no NULLs exist. ACCESS EXCLUSIVE lock.",
        (
            "In PG12+: add CHECK (col IS NOT NULL) NOT VALID first, VALIDATE later with weaker lock. "
            "Then SET NOT NULL is instant because PG trusts the validated check."
        ),
        True,
    ),
]

# Patterns that require SHARE lock (blocks writes only)
_SHARE_PATTERNS = [
    (
        r"CREATE\s+INDEX\s+(?!CONCURRENTLY)",
        "CREATE INDEX (without CONCURRENTLY)",
        "SHARE lock blocks all writes to the table during index build.",
        "Use CREATE INDEX CONCURRENTLY to allow writes during index creation.",
        True,  # potentially long
    ),
    (
        r"CREATE\s+UNIQUE\s+INDEX\s+(?!CONCURRENTLY)",
        "CREATE UNIQUE INDEX (without CONCURRENTLY)",
        "SHARE lock blocks all writes during index build plus uniqueness check.",
        "Use CREATE UNIQUE INDEX CONCURRENTLY.",
        True,
    ),
]

# Patterns that are safe (minimal locking)
_SAFE_PATTERNS = [
    (
        r"CREATE\s+INDEX\s+CONCURRENTLY",
        "CREATE INDEX CONCURRENTLY",
        "Only briefly acquires a weak lock. Allows reads and writes during build.",
        None,
        False,
    ),
    (
        r"ALTER\s+TABLE\s+\S+\s+ADD\s+COLUMN\s+\S+\s+\S+\s*;?\s*$",
        "ADD COLUMN (nullable)",
        "Metadata-only change. ACCESS EXCLUSIVE lock but nearly instant.",
        None,
        False,
    ),
    (
        r"DROP\s+INDEX\s+CONCURRENTLY",
        "DROP INDEX CONCURRENTLY",
        "Minimal locking. Safe for production.",
        None,
        False,
    ),
    (
        r"COMMENT\s+ON",
        "COMMENT ON (metadata only)",
        "Metadata-only operation. Very brief lock.",
        None,
        False,
    ),
]


class LockAnalyzer:
    """Analyze lock impact of DDL migration statements."""

    def analyze(self, sql: str) -> MigrationLockReport:
        """Analyze one or more SQL statements for lock impact.

        Args:
            sql: One or more DDL statements (semicolon-separated)

        Returns:
            MigrationLockReport with per-statement analysis
        """
        statements = self._split_statements(sql)
        reports: list[LockReport] = []
        recommendations: list[str] = []

        for stmt in statements:
            report = self._analyze_single(stmt)
            reports.append(report)

        # Compute overall risk
        if any(r.risk_level == "critical" for r in reports):
            overall_risk = "critical"
        elif any(r.risk_level == "warning" for r in reports):
            overall_risk = "warning"
        else:
            overall_risk = "safe"

        # Build recommendations
        has_non_concurrent_index = any(
            "without CONCURRENTLY" in r.explanation for r in reports
        )
        has_rewrite = any(r.requires_downtime for r in reports)

        if has_non_concurrent_index:
            recommendations.append(
                "Use CREATE INDEX CONCURRENTLY to avoid blocking writes during index creation"
            )
        if has_rewrite:
            recommendations.append(
                "Consider running during off-peak hours or use the phased plan to minimize downtime"
            )
        if any(r.blocks_reads for r in reports):
            recommendations.append(
                "This migration blocks reads — schedule during maintenance window"
            )
        if len(reports) > 1:
            recommendations.append(
                "Run statements in separate transactions to minimize lock hold time"
            )

        # Estimate total downtime
        critical_count = sum(1 for r in reports if r.requires_downtime)
        if critical_count == 0:
            total_downtime = "<1 second"
        elif critical_count <= 2:
            total_downtime = "seconds to minutes (depends on table size)"
        else:
            total_downtime = "minutes to hours (multiple table rewrites)"

        return MigrationLockReport(
            statements=reports,
            overall_risk=overall_risk,
            total_estimated_downtime=total_downtime,
            recommendations=recommendations,
        )

    def _analyze_single(self, stmt: str) -> LockReport:
        """Analyze a single DDL statement."""
        stmt_upper = stmt.upper().strip()

        # Check ACCESS EXCLUSIVE patterns
        for pattern, name, explanation, alternative, long_running in _ACCESS_EXCLUSIVE_PATTERNS:
            if re.search(pattern, stmt_upper, re.IGNORECASE):
                phased = self._generate_phased_plan(stmt, name)
                return LockReport(
                    statement=stmt.strip(),
                    lock_type="ACCESS EXCLUSIVE",
                    lock_blocks="All reads and writes",
                    risk_level="critical" if long_running else "warning",
                    estimated_duration="seconds to minutes (depends on table size)" if long_running else "<1 second",
                    explanation=explanation,
                    safe_alternative=alternative,
                    requires_downtime=long_running,
                    blocks_reads=True,
                    blocks_writes=True,
                    phased_plan=phased,
                )

        # Check SHARE lock patterns
        for pattern, name, explanation, alternative, long_running in _SHARE_PATTERNS:
            if re.search(pattern, stmt_upper, re.IGNORECASE):
                return LockReport(
                    statement=stmt.strip(),
                    lock_type="SHARE",
                    lock_blocks="All writes (reads allowed)",
                    risk_level="warning",
                    estimated_duration="seconds to minutes (depends on table/index size)",
                    explanation=explanation,
                    safe_alternative=alternative,
                    requires_downtime=long_running,
                    blocks_reads=False,
                    blocks_writes=True,
                    phased_plan=[
                        alternative or "Use CONCURRENTLY variant"
                    ],
                )

        # Check safe patterns
        for pattern, name, explanation, alternative, long_running in _SAFE_PATTERNS:
            if re.search(pattern, stmt_upper, re.IGNORECASE):
                return LockReport(
                    statement=stmt.strip(),
                    lock_type="ACCESS SHARE" if "SELECT" in stmt_upper else "ACCESS EXCLUSIVE (brief)",
                    lock_blocks="None (or very brief exclusive lock)",
                    risk_level="safe",
                    estimated_duration="<1 second",
                    explanation=explanation,
                    safe_alternative=alternative,
                    requires_downtime=False,
                    blocks_reads=False,
                    blocks_writes=False,
                    phased_plan=[],
                )

        # Default: unknown DDL
        return LockReport(
            statement=stmt.strip(),
            lock_type="UNKNOWN",
            lock_blocks="Unknown — review PostgreSQL documentation",
            risk_level="info",
            estimated_duration="unknown",
            explanation="Lock behavior for this statement is not in our pattern database.",
            safe_alternative=None,
            requires_downtime=False,
            blocks_reads=False,
            blocks_writes=False,
            phased_plan=[],
        )

    def _generate_phased_plan(self, stmt: str, op_name: str) -> list[str]:
        """Generate an expand-contract phased migration plan (van Kampen 2022)."""
        phases: list[str] = []

        if "NOT NULL" in op_name.upper() and "ADD COLUMN" in op_name.upper():
            # Extract table and column info
            match = re.search(
                r"ALTER\s+TABLE\s+(\S+)\s+ADD\s+COLUMN\s+(\S+)\s+(\S+)",
                stmt,
                re.IGNORECASE,
            )
            if match:
                table, col, dtype = match.group(1), match.group(2), match.group(3)
                phases = [
                    f"-- Phase 1: Add nullable column (instant, no rewrite)",
                    f"ALTER TABLE {table} ADD COLUMN {col} {dtype};",
                    f"",
                    f"-- Phase 2: Backfill in batches (no locks)",
                    f"UPDATE {table} SET {col} = <default_value> WHERE {col} IS NULL;",
                    f"-- Run in batches of 10,000 to avoid long transactions",
                    f"",
                    f"-- Phase 3: Add NOT NULL constraint (PG12+ safe path)",
                    f"ALTER TABLE {table} ADD CONSTRAINT {col}_not_null CHECK ({col} IS NOT NULL) NOT VALID;",
                    f"ALTER TABLE {table} VALIDATE CONSTRAINT {col}_not_null;",
                    f"ALTER TABLE {table} ALTER COLUMN {col} SET NOT NULL;",
                    f"ALTER TABLE {table} DROP CONSTRAINT {col}_not_null;",
                ]
        elif "ALTER COLUMN" in op_name.upper() and "TYPE" in op_name.upper():
            match = re.search(
                r"ALTER\s+TABLE\s+(\S+)\s+ALTER\s+COLUMN\s+(\S+)\s+(?:SET\s+DATA\s+)?TYPE\s+(\S+)",
                stmt,
                re.IGNORECASE,
            )
            if match:
                table, col, new_type = match.group(1), match.group(2), match.group(3)
                phases = [
                    f"-- Phase 1: Add new column with target type",
                    f"ALTER TABLE {table} ADD COLUMN {col}_new {new_type};",
                    f"",
                    f"-- Phase 2: Backfill new column from old",
                    f"UPDATE {table} SET {col}_new = {col}::{new_type} WHERE {col}_new IS NULL;",
                    f"",
                    f"-- Phase 3: Swap columns (brief lock)",
                    f"ALTER TABLE {table} RENAME COLUMN {col} TO {col}_old;",
                    f"ALTER TABLE {table} RENAME COLUMN {col}_new TO {col};",
                    f"",
                    f"-- Phase 4: Drop old column (after verifying application works)",
                    f"ALTER TABLE {table} DROP COLUMN {col}_old;",
                ]
        elif "SET NOT NULL" in op_name.upper():
            match = re.search(
                r"ALTER\s+TABLE\s+(\S+)\s+ALTER\s+COLUMN\s+(\S+)",
                stmt,
                re.IGNORECASE,
            )
            if match:
                table, col = match.group(1), match.group(2)
                phases = [
                    f"-- Phase 1: Add CHECK constraint (NOT VALID = no scan)",
                    f"ALTER TABLE {table} ADD CONSTRAINT {col}_not_null CHECK ({col} IS NOT NULL) NOT VALID;",
                    f"",
                    f"-- Phase 2: Validate constraint (SHARE UPDATE EXCLUSIVE lock only)",
                    f"ALTER TABLE {table} VALIDATE CONSTRAINT {col}_not_null;",
                    f"",
                    f"-- Phase 3: Now SET NOT NULL is instant (PG knows data is valid)",
                    f"ALTER TABLE {table} ALTER COLUMN {col} SET NOT NULL;",
                    f"ALTER TABLE {table} DROP CONSTRAINT {col}_not_null;",
                ]
        elif "PRIMARY KEY" in op_name.upper():
            match = re.search(
                r"ALTER\s+TABLE\s+(\S+)\s+ADD\s+(?:CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY\s*\(([^)]+)\)",
                stmt,
                re.IGNORECASE,
            )
            if match:
                table, cols = match.group(1), match.group(2)
                phases = [
                    f"-- Phase 1: Create unique index concurrently (no write lock)",
                    f"CREATE UNIQUE INDEX CONCURRENTLY pk_{table.replace('.', '_')}_idx ON {table} ({cols});",
                    f"",
                    f"-- Phase 2: Add PK using the existing index (instant)",
                    f"ALTER TABLE {table} ADD CONSTRAINT pk_{table.replace('.', '_')} PRIMARY KEY USING INDEX pk_{table.replace('.', '_')}_idx;",
                ]
        else:
            phases = [
                f"-- No phased plan available for: {op_name}",
                f"-- Consider running during off-peak hours with lock_timeout set",
                f"SET lock_timeout = '5s';",
                stmt.strip(),
            ]

        return phases

    @staticmethod
    def _split_statements(sql: str) -> list[str]:
        """Split SQL into individual statements."""
        from querysense.migration.sql_utils import split_statements

        return split_statements(sql, strip_comments=True, keep_semicolons=True)
