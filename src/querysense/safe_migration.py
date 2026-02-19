"""
Safe Migration Planner — replication-aware, zero-downtime migration plans.

Based on "Mastering PostgreSQL 13" (Schönig 2020):
Schema changes can break replication, cause locks, and trigger outages.

Analyzes migration SQL and produces a phased execution plan that:
1. Checks replication compatibility
2. Estimates lock duration
3. Generates safe step-by-step execution order
4. Provides rollback plan
5. Includes validation queries for each step

Usage:
    from querysense.safe_migration import SafeMigrationPlanner, MigrationPlan

    planner = SafeMigrationPlanner()
    plan = planner.plan(migration_sql)
    for phase in plan.phases:
        print(f"Phase {phase.order}: {phase.title}")
        for step in phase.steps:
            print(f"  {step.sql}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LockLevel(str, Enum):
    NONE = "none"
    ROW_SHARE = "row_share"           # SELECT FOR UPDATE
    ROW_EXCLUSIVE = "row_exclusive"   # INSERT, UPDATE, DELETE
    SHARE = "share"                   # CREATE INDEX
    SHARE_ROW_EXCLUSIVE = "share_row_exclusive"
    EXCLUSIVE = "exclusive"
    ACCESS_EXCLUSIVE = "access_exclusive"  # ALTER TABLE, DROP


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MigrationStep:
    """A single migration step."""
    order: int
    sql: str
    description: str
    lock_level: LockLevel
    estimated_duration: str
    validation_query: str = ""
    rollback_sql: str = ""
    safe_on_replica: bool = True
    notes: list[str] = field(default_factory=list)


@dataclass
class MigrationPhase:
    """A phase of the migration (group of related steps)."""
    order: int
    title: str
    description: str
    steps: list[MigrationStep] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    requires_maintenance_window: bool = False
    estimated_total_duration: str = ""


@dataclass
class MigrationPlan:
    """Complete migration plan."""
    phases: list[MigrationPhase] = field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.LOW
    requires_downtime: bool = False
    replication_warnings: list[str] = field(default_factory=list)
    pre_checks: list[str] = field(default_factory=list)
    post_checks: list[str] = field(default_factory=list)
    rollback_plan: str = ""

    def to_markdown(self) -> str:
        """Render the plan as Markdown."""
        lines = ["# QuerySense Safe Migration Plan", ""]
        lines.append(f"**Overall Risk:** {self.overall_risk.value.upper()}")
        lines.append(f"**Requires Downtime:** {'Yes' if self.requires_downtime else 'No'}")
        lines.append("")

        if self.replication_warnings:
            lines.append("## ⚠️ Replication Warnings")
            for w in self.replication_warnings:
                lines.append(f"- {w}")
            lines.append("")

        if self.pre_checks:
            lines.append("## Pre-Migration Checks")
            for c in self.pre_checks:
                lines.append(f"```sql\n{c}\n```")
            lines.append("")

        for phase in self.phases:
            lines.append(f"## Phase {phase.order}: {phase.title}")
            lines.append(f"*Risk: {phase.risk_level.value} | {phase.estimated_total_duration}*")
            if phase.requires_maintenance_window:
                lines.append("**⚠️ Requires maintenance window**")
            lines.append("")
            for step in phase.steps:
                lines.append(f"### Step {step.order}: {step.description}")
                lines.append(f"Lock: `{step.lock_level.value}` | Duration: {step.estimated_duration}")
                lines.append(f"```sql\n{step.sql}\n```")
                if step.validation_query:
                    lines.append(f"**Validate:**\n```sql\n{step.validation_query}\n```")
                if step.rollback_sql:
                    lines.append(f"**Rollback:**\n```sql\n{step.rollback_sql}\n```")
                if step.notes:
                    for note in step.notes:
                        lines.append(f"> {note}")
                lines.append("")

        if self.post_checks:
            lines.append("## Post-Migration Checks")
            for c in self.post_checks:
                lines.append(f"```sql\n{c}\n```")

        return "\n".join(lines)


class SafeMigrationPlanner:
    """
    Analyze migration SQL and produce a safe, phased execution plan.

    Handles: ADD/DROP COLUMN, ALTER TYPE, CREATE INDEX, ADD CONSTRAINT,
    RENAME, and common DDL operations with replication awareness.
    """

    def plan(self, migration_sql: str) -> MigrationPlan:
        """
        Analyze migration SQL and generate a safe execution plan.

        Args:
            migration_sql: One or more SQL DDL statements

        Returns:
            MigrationPlan with phased, validated steps
        """
        result = MigrationPlan()

        # Split into individual statements
        statements = self._split_statements(migration_sql)

        # Pre-checks
        result.pre_checks = [
            "-- Check current connections and locks:\n"
            "SELECT count(*) AS connections FROM pg_stat_activity;",
            "-- Check replication lag:\n"
            "SELECT client_addr, replay_lag FROM pg_stat_replication;",
            "-- Check autovacuum status:\n"
            "SELECT relname, last_autovacuum FROM pg_stat_user_tables "
            "WHERE schemaname = 'public' ORDER BY n_dead_tup DESC LIMIT 5;",
        ]

        # Classify each statement
        classified = [self._classify_statement(s) for s in statements if s.strip()]

        # Group into phases
        phase_num = 0

        # Phase: Safe additive changes (no locks)
        additive = [c for c in classified if c["risk"] in (RiskLevel.LOW, RiskLevel.MEDIUM)]
        if additive:
            phase_num += 1
            phase = MigrationPhase(
                order=phase_num,
                title="Additive Changes (Online)",
                description="These changes can run without disrupting traffic",
                risk_level=RiskLevel.LOW,
            )
            for i, c in enumerate(additive, 1):
                phase.steps.append(self._make_step(i, c))
            phase.estimated_total_duration = "seconds to minutes"
            result.phases.append(phase)

        # Phase: Index creation (concurrent)
        indexes = [c for c in classified if c["type"] == "create_index"]
        if indexes:
            phase_num += 1
            phase = MigrationPhase(
                order=phase_num,
                title="Index Creation (Concurrent)",
                description="Create indexes concurrently to avoid locking",
                risk_level=RiskLevel.MEDIUM,
            )
            for i, c in enumerate(indexes, 1):
                phase.steps.append(self._make_step(i, c))
            phase.estimated_total_duration = "minutes (depends on table size)"
            result.phases.append(phase)

        # Phase: Dangerous changes (require maintenance window)
        dangerous = [c for c in classified if c["risk"] in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
        dangerous = [c for c in dangerous if c["type"] != "create_index"]
        if dangerous:
            phase_num += 1
            phase = MigrationPhase(
                order=phase_num,
                title="Schema Changes (Maintenance Window)",
                description="These changes require ACCESS EXCLUSIVE lock",
                risk_level=RiskLevel.HIGH,
                requires_maintenance_window=True,
            )
            for i, c in enumerate(dangerous, 1):
                phase.steps.append(self._make_step(i, c))
            phase.estimated_total_duration = "depends on table size"
            result.phases.append(phase)
            result.requires_downtime = True

        # Post-checks
        result.post_checks = [
            "-- Verify schema:\n"
            "SELECT column_name, data_type, is_nullable "
            "FROM information_schema.columns "
            "WHERE table_schema = 'public' ORDER BY table_name, ordinal_position;",
            "-- Verify replication is healthy:\n"
            "SELECT client_addr, state, replay_lag FROM pg_stat_replication;",
            "-- Update statistics:\n"
            "ANALYZE;",
        ]

        # Overall risk
        if dangerous:
            result.overall_risk = RiskLevel.HIGH
        elif indexes:
            result.overall_risk = RiskLevel.MEDIUM
        else:
            result.overall_risk = RiskLevel.LOW

        # Replication warnings
        from querysense.replication_analyzer import ReplicationAnalyzer
        analyzer = ReplicationAnalyzer()
        repl_alerts = analyzer.analyze_migration_safety(migration_sql)
        result.replication_warnings = [a.message for a in repl_alerts]

        # Rollback plan
        rollback_steps = []
        for phase in result.phases:
            for step in phase.steps:
                if step.rollback_sql:
                    rollback_steps.append(step.rollback_sql)
        result.rollback_plan = "\n".join(reversed(rollback_steps))

        return result

    def _split_statements(self, sql: str) -> list[str]:
        """Split SQL into individual statements."""
        from querysense.migration.sql_utils import split_statements

        return split_statements(sql)

    def _classify_statement(self, sql: str) -> dict[str, Any]:
        """Classify a DDL statement for risk and lock level."""
        upper = sql.upper().strip()

        # ADD COLUMN with DEFAULT
        if re.search(r"ADD\s+COLUMN.*DEFAULT", upper):
            return {
                "sql": sql,
                "type": "add_column_default",
                "risk": RiskLevel.LOW,  # PG 11+ doesn't rewrite
                "lock": LockLevel.ACCESS_EXCLUSIVE,
                "duration": "instant (PG 11+, requires rewrite on older versions)",
                "safe_replica": True,
                "notes": ["PG 11+ adds columns with defaults instantly (no rewrite)"],
            }

        # ADD COLUMN (no default)
        if re.search(r"ADD\s+COLUMN", upper):
            return {
                "sql": sql,
                "type": "add_column",
                "risk": RiskLevel.LOW,
                "lock": LockLevel.ACCESS_EXCLUSIVE,
                "duration": "instant",
                "safe_replica": True,
                "notes": [],
            }

        # DROP COLUMN
        if re.search(r"DROP\s+COLUMN", upper):
            return {
                "sql": sql,
                "type": "drop_column",
                "risk": RiskLevel.MEDIUM,
                "lock": LockLevel.ACCESS_EXCLUSIVE,
                "duration": "instant (marks column as dropped, no rewrite)",
                "safe_replica": False,
                "notes": ["Drop on subscriber FIRST if using logical replication"],
            }

        # CREATE INDEX CONCURRENTLY
        if re.search(r"CREATE\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY", upper):
            return {
                "sql": sql,
                "type": "create_index",
                "risk": RiskLevel.MEDIUM,
                "lock": LockLevel.SHARE,
                "duration": "minutes (concurrent, no write lock)",
                "safe_replica": True,
                "notes": ["Cannot run inside a transaction"],
            }

        # CREATE INDEX (non-concurrent)
        if re.search(r"CREATE\s+(UNIQUE\s+)?INDEX\b", upper):
            # Rewrite to use CONCURRENTLY
            safe_sql = re.sub(r"CREATE\s+(UNIQUE\s+)?INDEX\b", r"CREATE \1INDEX CONCURRENTLY", sql)
            return {
                "sql": safe_sql,
                "type": "create_index",
                "risk": RiskLevel.MEDIUM,
                "lock": LockLevel.SHARE,
                "duration": "minutes (rewritten to CONCURRENTLY)",
                "safe_replica": True,
                "notes": ["Auto-rewritten to CREATE INDEX CONCURRENTLY for safety"],
            }

        # ALTER COLUMN TYPE
        if re.search(r"ALTER\s+COLUMN\s+\w+\s+(SET\s+DATA\s+)?TYPE", upper):
            return {
                "sql": sql,
                "type": "alter_type",
                "risk": RiskLevel.CRITICAL,
                "lock": LockLevel.ACCESS_EXCLUSIVE,
                "duration": "minutes to hours (full table rewrite)",
                "safe_replica": False,
                "notes": [
                    "Requires full table rewrite — locks table for entire duration",
                    "Consider: add new column, migrate data, rename columns",
                ],
            }

        # ADD CONSTRAINT
        if re.search(r"ADD\s+CONSTRAINT.*NOT\s+VALID", upper):
            return {
                "sql": sql,
                "type": "add_constraint_not_valid",
                "risk": RiskLevel.LOW,
                "lock": LockLevel.ACCESS_EXCLUSIVE,
                "duration": "instant (NOT VALID skips existing rows)",
                "safe_replica": True,
                "notes": ["Follow up with VALIDATE CONSTRAINT in a separate transaction"],
            }

        if re.search(r"ADD\s+CONSTRAINT", upper):
            return {
                "sql": sql,
                "type": "add_constraint",
                "risk": RiskLevel.HIGH,
                "lock": LockLevel.ACCESS_EXCLUSIVE,
                "duration": "seconds to minutes (scans all existing rows)",
                "safe_replica": True,
                "notes": ["Consider ADD CONSTRAINT ... NOT VALID + VALIDATE CONSTRAINT"],
            }

        # RENAME
        if re.search(r"RENAME\s+(TABLE|TO|COLUMN)", upper):
            return {
                "sql": sql,
                "type": "rename",
                "risk": RiskLevel.HIGH,
                "lock": LockLevel.ACCESS_EXCLUSIVE,
                "duration": "instant",
                "safe_replica": False,
                "notes": ["Breaks logical replication subscriptions"],
            }

        # DROP TABLE
        if re.search(r"DROP\s+TABLE", upper):
            return {
                "sql": sql,
                "type": "drop_table",
                "risk": RiskLevel.CRITICAL,
                "lock": LockLevel.ACCESS_EXCLUSIVE,
                "duration": "instant",
                "safe_replica": False,
                "notes": ["IRREVERSIBLE — ensure backup exists"],
            }

        # Default
        return {
            "sql": sql,
            "type": "other",
            "risk": RiskLevel.MEDIUM,
            "lock": LockLevel.ACCESS_EXCLUSIVE,
            "duration": "unknown",
            "safe_replica": True,
            "notes": [],
        }

    def _make_step(self, order: int, classified: dict) -> MigrationStep:
        """Create a MigrationStep from a classified statement."""
        sql = classified["sql"]
        stmt_type = classified["type"]

        # Generate rollback
        rollback = self._generate_rollback(sql, stmt_type)

        # Generate validation
        validation = self._generate_validation(sql, stmt_type)

        return MigrationStep(
            order=order,
            sql=sql,
            description=f"{stmt_type.replace('_', ' ').title()}",
            lock_level=classified["lock"],
            estimated_duration=classified["duration"],
            validation_query=validation,
            rollback_sql=rollback,
            safe_on_replica=classified["safe_replica"],
            notes=classified["notes"],
        )

    def _generate_rollback(self, sql: str, stmt_type: str) -> str:
        """Generate rollback SQL for a statement."""
        upper = sql.upper()

        if stmt_type == "add_column" or stmt_type == "add_column_default":
            match = re.search(r"ADD\s+COLUMN\s+(\w+)", upper)
            table_match = re.search(r"ALTER\s+TABLE\s+(\S+)", upper)
            if match and table_match:
                col = match.group(1)
                table = table_match.group(1)
                return f"ALTER TABLE {table} DROP COLUMN IF EXISTS {col};"

        if stmt_type == "create_index":
            match = re.search(r"INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", upper)
            if match:
                return f"DROP INDEX CONCURRENTLY IF EXISTS {match.group(1)};"

        return f"-- Manual rollback required for: {stmt_type}"

    def _generate_validation(self, sql: str, stmt_type: str) -> str:
        """Generate validation query for a statement."""
        upper = sql.upper()

        if "ADD COLUMN" in upper:
            table_match = re.search(r"ALTER\s+TABLE\s+(\S+)", upper)
            col_match = re.search(r"ADD\s+COLUMN\s+(\w+)", upper)
            if table_match and col_match:
                return (
                    f"SELECT column_name, data_type FROM information_schema.columns "
                    f"WHERE table_name = '{table_match.group(1).lower()}' "
                    f"AND column_name = '{col_match.group(1).lower()}';"
                )

        if "INDEX" in upper:
            match = re.search(r"INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", upper)
            if match:
                return (
                    f"SELECT indexname, indexdef FROM pg_indexes "
                    f"WHERE indexname = '{match.group(1).lower()}';"
                )

        return "-- Verify changes in information_schema"
