"""
Migration safety checks and automatic rollback SQL generation.

Analyzes DDL statements for risky operations and generates safe
rollback SQL.  Designed to run before migrations execute, catching
problems like:
- Exclusive locks on large tables (ALTER TABLE ... ADD COLUMN ... NOT NULL)
- Missing timeouts on DDL operations
- Index creation without CONCURRENTLY
- Dropping columns/tables without backup plan

Usage:
    from querysense.migration_safety import check_migration, generate_rollback

    risks = check_migration("ALTER TABLE orders ADD COLUMN status TEXT NOT NULL")
    for risk in risks:
        print(risk)
    # [WARNING] ADD COLUMN NOT NULL requires rewriting entire table;
    #           use DEFAULT to avoid full lock

    rollback_sql = generate_rollback("ALTER TABLE orders ADD COLUMN status TEXT")
    print(rollback_sql)
    # ALTER TABLE orders DROP COLUMN status;
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MigrationRisk:
    """A single risk identified in a migration statement."""

    severity: str  # "critical", "warning", "info"
    rule: str
    message: str
    statement: str
    suggestion: str = ""

    def __str__(self) -> str:
        s = f"[{self.severity.upper()}] {self.rule}: {self.message}"
        if self.suggestion:
            s += f"\n  Suggestion: {self.suggestion}"
        return s


@dataclass
class MigrationReport:
    """Complete safety report for a set of migration statements."""

    statements: list[str] = field(default_factory=list)
    risks: list[MigrationRisk] = field(default_factory=list)
    rollback_sql: list[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(r.severity == "critical" for r in self.risks)

    @property
    def safe(self) -> bool:
        return not self.has_critical

    def summary(self) -> str:
        crit = sum(1 for r in self.risks if r.severity == "critical")
        warn = sum(1 for r in self.risks if r.severity == "warning")
        info = sum(1 for r in self.risks if r.severity == "info")
        status = "UNSAFE" if self.has_critical else ("CAUTION" if warn else "SAFE")
        return (
            f"[{status}] {len(self.statements)} statement(s), "
            f"{crit} critical, {warn} warning, {info} info"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe": self.safe,
            "summary": self.summary(),
            "statements_count": len(self.statements),
            "risks": [
                {
                    "severity": r.severity,
                    "rule": r.rule,
                    "message": r.message,
                    "suggestion": r.suggestion,
                }
                for r in self.risks
            ],
            "rollback_sql": self.rollback_sql,
        }


# ── Risk Detection Rules ─────────────────────────────────────────────

def _check_add_column_not_null(stmt: str) -> MigrationRisk | None:
    """ADD COLUMN NOT NULL without DEFAULT locks the table for rewrite."""
    pattern = re.compile(
        r"ALTER\s+TABLE\s+\w+\s+ADD\s+(?:COLUMN\s+)?\w+\s+\w+.*\bNOT\s+NULL\b",
        re.IGNORECASE,
    )
    if not pattern.search(stmt):
        return None

    has_default = re.search(r"\bDEFAULT\b", stmt, re.IGNORECASE)
    if has_default:
        return None  # Safe: DEFAULT + NOT NULL avoids table rewrite on PG 11+

    return MigrationRisk(
        severity="critical",
        rule="ADD_COLUMN_NOT_NULL_NO_DEFAULT",
        message="ADD COLUMN ... NOT NULL without DEFAULT requires full table rewrite and exclusive lock",
        statement=stmt,
        suggestion="Add DEFAULT value: ALTER TABLE t ADD COLUMN c TYPE NOT NULL DEFAULT 'value'",
    )


def _check_create_index_not_concurrent(stmt: str) -> MigrationRisk | None:
    """CREATE INDEX without CONCURRENTLY blocks writes."""
    if not re.search(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b", stmt, re.IGNORECASE):
        return None
    if re.search(r"\bCONCURRENTLY\b", stmt, re.IGNORECASE):
        return None

    return MigrationRisk(
        severity="warning",
        rule="INDEX_WITHOUT_CONCURRENTLY",
        message="CREATE INDEX without CONCURRENTLY blocks writes on the table",
        statement=stmt,
        suggestion="Use CREATE INDEX CONCURRENTLY to avoid blocking writes",
    )


def _check_drop_table(stmt: str) -> MigrationRisk | None:
    """DROP TABLE is irreversible without a backup."""
    match = re.search(r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)", stmt, re.IGNORECASE)
    if not match:
        return None

    table = match.group(1)
    return MigrationRisk(
        severity="critical",
        rule="DROP_TABLE",
        message=f"DROP TABLE {table} is irreversible; ensure backup exists",
        statement=stmt,
        suggestion=f"Consider renaming first: ALTER TABLE {table} RENAME TO {table}_backup",
    )


def _check_drop_column(stmt: str) -> MigrationRisk | None:
    """DROP COLUMN is irreversible."""
    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+DROP\s+(?:COLUMN\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if not match:
        return None

    table = match.group(1)
    column = match.group(2)
    return MigrationRisk(
        severity="warning",
        rule="DROP_COLUMN",
        message=f"DROP COLUMN {column} from {table} is irreversible",
        statement=stmt,
        suggestion=f"Consider a two-phase approach: first stop reading the column, then drop it later",
    )


def _check_alter_column_type(stmt: str) -> MigrationRisk | None:
    """ALTER COLUMN TYPE may require full table rewrite."""
    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+ALTER\s+(?:COLUMN\s+)?(\w+)\s+(?:SET\s+DATA\s+)?TYPE\s+(\w+)",
        stmt, re.IGNORECASE,
    )
    if not match:
        return None

    table = match.group(1)
    column = match.group(2)
    new_type = match.group(3)
    return MigrationRisk(
        severity="warning",
        rule="ALTER_COLUMN_TYPE",
        message=f"Changing {table}.{column} to {new_type} may require full table rewrite",
        statement=stmt,
        suggestion="For large tables, consider creating a new column and backfilling incrementally",
    )


def _check_rename_column(stmt: str) -> MigrationRisk | None:
    """RENAME COLUMN can break application queries."""
    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+RENAME\s+(?:COLUMN\s+)?(\w+)\s+TO\s+(\w+)",
        stmt, re.IGNORECASE,
    )
    if not match:
        return None

    return MigrationRisk(
        severity="warning",
        rule="RENAME_COLUMN",
        message=f"Renaming column will break queries referencing the old name",
        statement=stmt,
        suggestion="Deploy application changes first, or use a view as an alias layer",
    )


def _check_add_foreign_key(stmt: str) -> MigrationRisk | None:
    """ADD FOREIGN KEY validates all existing rows (full scan + lock)."""
    if not re.search(r"\bADD\s+(?:CONSTRAINT\s+\w+\s+)?FOREIGN\s+KEY\b", stmt, re.IGNORECASE):
        return None

    not_valid = re.search(r"\bNOT\s+VALID\b", stmt, re.IGNORECASE)
    if not_valid:
        return None

    return MigrationRisk(
        severity="warning",
        rule="FOREIGN_KEY_VALIDATES_ALL",
        message="ADD FOREIGN KEY validates all existing rows; blocks writes during scan",
        statement=stmt,
        suggestion="Use NOT VALID to skip validation, then VALIDATE CONSTRAINT separately",
    )


def _check_add_check_constraint(stmt: str) -> MigrationRisk | None:
    """ADD CHECK validates all rows."""
    if not re.search(r"\bADD\s+(?:CONSTRAINT\s+\w+\s+)?CHECK\b", stmt, re.IGNORECASE):
        return None

    not_valid = re.search(r"\bNOT\s+VALID\b", stmt, re.IGNORECASE)
    if not_valid:
        return None

    return MigrationRisk(
        severity="info",
        rule="CHECK_CONSTRAINT_VALIDATES",
        message="ADD CHECK validates all existing rows",
        statement=stmt,
        suggestion="Use NOT VALID to add without validation, then VALIDATE separately",
    )


def _check_lock_timeout(stmt: str) -> MigrationRisk | None:
    """DDL without lock_timeout can hang indefinitely."""
    ddl_patterns = [
        r"\bALTER\s+TABLE\b",
        r"\bDROP\s+TABLE\b",
        r"\bCREATE\s+INDEX\b(?!.*\bCONCURRENTLY\b)",
    ]
    is_ddl = any(re.search(p, stmt, re.IGNORECASE) for p in ddl_patterns)
    if not is_ddl:
        return None

    return MigrationRisk(
        severity="info",
        rule="NO_LOCK_TIMEOUT",
        message="DDL without lock_timeout can hang waiting for locks",
        statement=stmt,
        suggestion="Set lock_timeout before DDL: SET lock_timeout = '5s'",
    )


_RISK_CHECKS = [
    _check_add_column_not_null,
    _check_create_index_not_concurrent,
    _check_drop_table,
    _check_drop_column,
    _check_alter_column_type,
    _check_rename_column,
    _check_add_foreign_key,
    _check_add_check_constraint,
    _check_lock_timeout,
]


# ── Rollback Generation ──────────────────────────────────────────────

def _rollback_add_column(stmt: str) -> str | None:
    # Skip if this is ADD CONSTRAINT (handled separately)
    if re.search(r"\bADD\s+CONSTRAINT\b", stmt, re.IGNORECASE):
        return None
    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+ADD\s+(?:COLUMN\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if not match:
        return None
    return f"ALTER TABLE {match.group(1)} DROP COLUMN IF EXISTS {match.group(2)};"


def _rollback_drop_column(stmt: str) -> str | None:
    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+DROP\s+(?:COLUMN\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if not match:
        return None
    return f"-- Cannot auto-rollback DROP COLUMN {match.group(2)} from {match.group(1)}; restore from backup"


def _rollback_create_index(stmt: str) -> str | None:
    match = re.search(
        r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if not match:
        return None
    return f"DROP INDEX IF EXISTS {match.group(1)};"


def _rollback_drop_index(stmt: str) -> str | None:
    if re.search(r"\bDROP\s+INDEX\b", stmt, re.IGNORECASE):
        return f"-- Cannot auto-rollback DROP INDEX; recreate manually"
    return None


def _rollback_create_table(stmt: str) -> str | None:
    match = re.search(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if not match:
        return None
    return f"DROP TABLE IF EXISTS {match.group(1)};"


def _rollback_drop_table(stmt: str) -> str | None:
    if re.search(r"\bDROP\s+TABLE\b", stmt, re.IGNORECASE):
        return "-- Cannot auto-rollback DROP TABLE; restore from backup"
    return None


def _rollback_rename(stmt: str) -> str | None:
    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+RENAME\s+(?:COLUMN\s+)?(\w+)\s+TO\s+(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        return f"ALTER TABLE {match.group(1)} RENAME COLUMN {match.group(3)} TO {match.group(2)};"

    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+RENAME\s+TO\s+(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        return f"ALTER TABLE {match.group(2)} RENAME TO {match.group(1)};"

    return None


def _rollback_add_constraint(stmt: str) -> str | None:
    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+ADD\s+CONSTRAINT\s+(\w+)",
        stmt, re.IGNORECASE,
    )
    if not match:
        return None
    return f"ALTER TABLE {match.group(1)} DROP CONSTRAINT IF EXISTS {match.group(2)};"


_ROLLBACK_GENERATORS = [
    # Order matters: more specific patterns first
    _rollback_add_constraint,  # Must come before _rollback_add_column
    _rollback_rename,
    _rollback_add_column,
    _rollback_drop_column,
    _rollback_create_index,
    _rollback_drop_index,
    _rollback_create_table,
    _rollback_drop_table,
]


# ── Public API ───────────────────────────────────────────────────────

def check_migration(sql: str) -> list[MigrationRisk]:
    """
    Check a migration SQL for risks.

    Args:
        sql: One or more SQL statements

    Returns:
        List of identified risks
    """
    statements = _split_statements(sql)
    risks: list[MigrationRisk] = []

    for stmt in statements:
        for check_fn in _RISK_CHECKS:
            risk = check_fn(stmt)
            if risk:
                risks.append(risk)

    return risks


def generate_rollback(sql: str) -> str:
    """
    Generate rollback SQL for a migration.

    Args:
        sql: Migration SQL statements

    Returns:
        Rollback SQL (may contain comments for manual steps)
    """
    statements = _split_statements(sql)
    rollback_lines: list[str] = ["-- Auto-generated rollback by QuerySense"]
    rollback_lines.append(f"-- Rollback for {len(statements)} statement(s)")
    rollback_lines.append("")

    # Process in reverse order (undo last change first)
    for stmt in reversed(statements):
        generated = False
        for gen_fn in _ROLLBACK_GENERATORS:
            rb = gen_fn(stmt)
            if rb:
                rollback_lines.append(rb)
                generated = True
                break
        if not generated:
            rollback_lines.append(f"-- No auto-rollback for: {stmt.strip()[:80]}...")

    return "\n".join(rollback_lines)


def check_and_report(sql: str) -> MigrationReport:
    """
    Full migration safety check with rollback generation.

    Args:
        sql: Migration SQL

    Returns:
        MigrationReport with risks and rollback SQL
    """
    statements = _split_statements(sql)
    risks = check_migration(sql)

    rollback_stmts: list[str] = []
    for stmt in reversed(statements):
        for gen_fn in _ROLLBACK_GENERATORS:
            rb = gen_fn(stmt)
            if rb:
                rollback_stmts.append(rb)
                break

    return MigrationReport(
        statements=statements,
        risks=risks,
        rollback_sql=rollback_stmts,
    )


def _split_statements(sql: str) -> list[str]:
    """Split SQL into individual statements."""
    from querysense.migration.sql_utils import split_statements

    return split_statements(sql, strip_comments=True)
