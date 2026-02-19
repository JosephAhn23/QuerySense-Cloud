"""
Zero-Downtime Migration Planner.

Decomposes risky DDL into safe expand/migrate/contract phases:

1. EXPAND  — Add nullable columns, create indexes CONCURRENTLY
2. MIGRATE — Backfill data in batches (row-level locks only)
3. CONTRACT — Set NOT NULL constraints, drop old columns

Each phase includes:
- Safe SQL with lock timeout
- Rollback SQL
- Duration estimate
- Lock risk assessment
- Verification queries

Usage:
    from querysense.migration import ZeroDowntimePlanner

    planner = ZeroDowntimePlanner()
    plan = planner.plan("ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")

    for phase in plan.phases:
        print(f"Phase {phase.phase_number}: {phase.phase_type.value}")
        print(f"  SQL: {phase.sql}")
        print(f"  Rollback: {phase.rollback_sql}")
        print(f"  Lock risk: {phase.lock_risk}")
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MigrationPhaseType(str, Enum):
    EXPAND = "expand"        # Add nullable columns/indexes
    MIGRATE = "migrate"      # Backfill data in batches
    CONTRACT = "contract"    # Add constraints, drop old columns
    INDEX = "index"          # Create indexes concurrently
    VERIFY = "verify"        # Verify migration success


@dataclass
class MigrationPhase:
    """A single phase in a zero-downtime migration."""
    phase_number: int
    phase_type: MigrationPhaseType
    description: str
    sql: str
    rollback_sql: str
    lock_risk: str = "LOW"       # LOW / MEDIUM / HIGH
    duration_estimate: str = ""
    lock_timeout_ms: int = 5000
    requires_app_change: bool = False
    verification_sql: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase_number": self.phase_number,
            "phase_type": self.phase_type.value,
            "description": self.description,
            "sql": self.sql,
            "rollback_sql": self.rollback_sql,
            "lock_risk": self.lock_risk,
            "duration_estimate": self.duration_estimate,
            "lock_timeout_ms": self.lock_timeout_ms,
            "requires_app_change": self.requires_app_change,
            "verification_sql": self.verification_sql,
            "notes": self.notes,
        }


@dataclass
class ZeroDowntimePlan:
    """Complete zero-downtime migration plan."""
    original_sql: str
    phases: list[MigrationPhase] = field(default_factory=list)
    total_phases: int = 0
    estimated_total_time: str = ""
    max_lock_risk: str = "LOW"
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_sql": self.original_sql,
            "total_phases": self.total_phases,
            "estimated_total_time": self.estimated_total_time,
            "max_lock_risk": self.max_lock_risk,
            "warnings": self.warnings,
            "phases": [p.to_dict() for p in self.phases],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  ZERO-DOWNTIME MIGRATION PLAN")
        lines.append("  " + "=" * 60)
        lines.append(f"  Original SQL: {self.original_sql[:80]}")
        lines.append(f"  Total phases: {self.total_phases}")
        lines.append(f"  Estimated time: {self.estimated_total_time}")
        lines.append(f"  Max lock risk: {self.max_lock_risk}")
        lines.append("")

        if self.warnings:
            lines.append("  Warnings:")
            for w in self.warnings:
                lines.append(f"    ! {w}")
            lines.append("")

        for phase in self.phases:
            risk_marker = {"LOW": " ", "MEDIUM": "!", "HIGH": "X"}
            marker = risk_marker.get(phase.lock_risk, "?")
            lines.append(
                f"  [{marker}] Phase {phase.phase_number}: "
                f"{phase.phase_type.value.upper()} — {phase.description}"
            )
            lines.append(f"      SQL:      {phase.sql}")
            lines.append(f"      Rollback: {phase.rollback_sql}")
            lines.append(f"      Lock risk: {phase.lock_risk}")
            lines.append(f"      Duration: {phase.duration_estimate}")
            if phase.verification_sql:
                lines.append(f"      Verify: {phase.verification_sql}")
            if phase.notes:
                for note in phase.notes:
                    lines.append(f"      Note: {note}")
            lines.append("")

        return "\n".join(lines)


class ZeroDowntimePlanner:
    """
    Decompose DDL into zero-downtime migration phases.

    Handles:
    - ADD COLUMN NOT NULL -> expand (nullable) + migrate (backfill) + contract (NOT NULL)
    - CREATE INDEX -> CREATE INDEX CONCURRENTLY
    - ADD CONSTRAINT -> validate separately
    - DROP COLUMN -> deprecate (add comment) + verify unused + drop
    - RENAME COLUMN -> add new + backfill + update app + drop old
    - ALTER TYPE -> add new column + backfill + swap + drop
    """

    def __init__(self, lock_timeout_ms: int = 5000, batch_size: int = 10000):
        self.lock_timeout_ms = lock_timeout_ms
        self.batch_size = batch_size

    def plan(self, sql: str) -> ZeroDowntimePlan:
        """Generate a zero-downtime plan for a DDL statement."""
        sql_upper = sql.strip().upper()
        phases: list[MigrationPhase] = []
        warnings: list[str] = []

        if "ADD COLUMN" in sql_upper and "NOT NULL" in sql_upper:
            phases, warnings = self._plan_add_column_not_null(sql)
        elif "ADD COLUMN" in sql_upper:
            phases, warnings = self._plan_add_column(sql)
        elif "CREATE INDEX" in sql_upper and "CONCURRENTLY" not in sql_upper:
            phases, warnings = self._plan_create_index(sql)
        elif "DROP COLUMN" in sql_upper:
            phases, warnings = self._plan_drop_column(sql)
        elif "RENAME COLUMN" in sql_upper:
            phases, warnings = self._plan_rename_column(sql)
        elif "ALTER COLUMN" in sql_upper and "TYPE" in sql_upper:
            phases, warnings = self._plan_alter_type(sql)
        elif "ADD CONSTRAINT" in sql_upper:
            phases, warnings = self._plan_add_constraint(sql)
        elif "DROP TABLE" in sql_upper:
            phases, warnings = self._plan_drop_table(sql)
        else:
            # Generic pass-through with lock timeout
            phases = [
                MigrationPhase(
                    phase_number=1,
                    phase_type=MigrationPhaseType.EXPAND,
                    description="Execute with lock timeout",
                    sql=f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n{sql}",
                    rollback_sql="-- Manual rollback required",
                    lock_risk="MEDIUM",
                    duration_estimate="Unknown",
                    verification_sql="-- Verify manually",
                )
            ]

        max_risk = "LOW"
        for p in phases:
            if p.lock_risk == "HIGH":
                max_risk = "HIGH"
            elif p.lock_risk == "MEDIUM" and max_risk != "HIGH":
                max_risk = "MEDIUM"

        plan = ZeroDowntimePlan(
            original_sql=sql,
            phases=phases,
            total_phases=len(phases),
            estimated_total_time=self._estimate_total_time(phases),
            max_lock_risk=max_risk,
            warnings=warnings,
        )

        return plan

    # ── ADD COLUMN NOT NULL ──────────────────────────────────────────

    def _plan_add_column_not_null(self, sql: str) -> tuple[list[MigrationPhase], list[str]]:
        """Decompose ADD COLUMN ... NOT NULL into 3 phases."""
        m = re.search(
            r"ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)\s+(\w+(?:\([^)]*\))?)",
            sql,
            re.IGNORECASE,
        )
        if not m:
            return self._plan_add_column(sql)

        table = m.group(1)
        column = m.group(2)
        col_type = m.group(3)

        # Extract DEFAULT value if present
        default_m = re.search(r"DEFAULT\s+(.+?)(?:\s|;|$)", sql, re.IGNORECASE)
        default_val = default_m.group(1).strip().rstrip(";") if default_m else "NULL"

        phases = [
            # Phase 1: EXPAND — add nullable column with default
            MigrationPhase(
                phase_number=1,
                phase_type=MigrationPhaseType.EXPAND,
                description=f"Add {column} as NULLABLE with DEFAULT",
                sql=(
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"ALTER TABLE {table} ADD COLUMN {column} {col_type} DEFAULT {default_val};"
                ),
                rollback_sql=f"ALTER TABLE {table} DROP COLUMN IF EXISTS {column};",
                lock_risk="LOW",
                duration_estimate="< 100ms (metadata only in PG11+)",
                verification_sql=(
                    f"SELECT column_name, is_nullable, column_default "
                    f"FROM information_schema.columns "
                    f"WHERE table_name = '{table}' AND column_name = '{column}';"
                ),
                notes=[
                    "PG11+ adds columns with DEFAULT as metadata-only operation",
                    "No table rewrite required",
                ],
            ),
            # Phase 2: MIGRATE — backfill existing rows in batches
            MigrationPhase(
                phase_number=2,
                phase_type=MigrationPhaseType.MIGRATE,
                description=f"Backfill {column} in batches of {self.batch_size}",
                sql=(
                    f"DO $$\n"
                    f"DECLARE\n"
                    f"    batch_size INT := {self.batch_size};\n"
                    f"    affected BIGINT;\n"
                    f"BEGIN\n"
                    f"    LOOP\n"
                    f"        WITH batch AS (\n"
                    f"            SELECT ctid FROM {table}\n"
                    f"            WHERE {column} IS NULL\n"
                    f"            LIMIT batch_size\n"
                    f"            FOR UPDATE SKIP LOCKED\n"
                    f"        )\n"
                    f"        UPDATE {table}\n"
                    f"        SET {column} = {default_val}\n"
                    f"        WHERE ctid IN (SELECT ctid FROM batch);\n"
                    f"\n"
                    f"        GET DIAGNOSTICS affected = ROW_COUNT;\n"
                    f"        EXIT WHEN affected = 0;\n"
                    f"\n"
                    f"        PERFORM pg_sleep(0.1);  -- yield to other queries\n"
                    f"    END LOOP;\n"
                    f"END $$;"
                ),
                rollback_sql=f"UPDATE {table} SET {column} = NULL WHERE {column} = {default_val};",
                lock_risk="LOW",
                duration_estimate="Depends on table size (~10K rows/sec)",
                verification_sql=(
                    f"SELECT COUNT(*) AS remaining_nulls "
                    f"FROM {table} WHERE {column} IS NULL;"
                ),
                notes=[
                    "Uses FOR UPDATE SKIP LOCKED to avoid blocking other transactions",
                    "Batched to prevent long-running transactions",
                ],
            ),
            # Phase 3: CONTRACT — add NOT NULL constraint
            MigrationPhase(
                phase_number=3,
                phase_type=MigrationPhaseType.CONTRACT,
                description=f"Add NOT NULL constraint on {column}",
                sql=(
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"ALTER TABLE {table} ADD CONSTRAINT {table}_{column}_not_null "
                    f"CHECK ({column} IS NOT NULL) NOT VALID;\n"
                    f"ALTER TABLE {table} VALIDATE CONSTRAINT {table}_{column}_not_null;"
                ),
                rollback_sql=(
                    f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {table}_{column}_not_null;"
                ),
                lock_risk="LOW",
                duration_estimate="< 100ms (NOT VALID then VALIDATE pattern)",
                verification_sql=(
                    f"SELECT conname, convalidated FROM pg_constraint "
                    f"WHERE conrelid = '{table}'::regclass AND conname = '{table}_{column}_not_null';"
                ),
                notes=[
                    "Uses NOT VALID + VALIDATE pattern to avoid ACCESS EXCLUSIVE lock",
                    "NOT VALID takes a brief lock, VALIDATE runs without blocking DML",
                    "Equivalent to NOT NULL but without rewriting the table",
                ],
            ),
        ]

        return phases, []

    # ── ADD COLUMN (simple) ──────────────────────────────────────────

    def _plan_add_column(self, sql: str) -> tuple[list[MigrationPhase], list[str]]:
        m = re.search(
            r"ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)\s+(\w+)",
            sql,
            re.IGNORECASE,
        )
        table = m.group(1) if m else "unknown_table"
        column = m.group(2) if m else "unknown_column"

        phases = [
            MigrationPhase(
                phase_number=1,
                phase_type=MigrationPhaseType.EXPAND,
                description=f"Add nullable column {column}",
                sql=f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n{sql}",
                rollback_sql=f"ALTER TABLE {table} DROP COLUMN IF EXISTS {column};",
                lock_risk="LOW",
                duration_estimate="< 100ms (metadata only)",
                verification_sql=(
                    f"SELECT column_name FROM information_schema.columns "
                    f"WHERE table_name = '{table}' AND column_name = '{column}';"
                ),
            ),
        ]
        return phases, []

    # ── CREATE INDEX ─────────────────────────────────────────────────

    def _plan_create_index(self, sql: str) -> tuple[list[MigrationPhase], list[str]]:
        # Rewrite to CONCURRENTLY
        concurrent_sql = sql.replace(
            "CREATE INDEX", "CREATE INDEX CONCURRENTLY", 1
        ).replace(
            "CREATE UNIQUE INDEX", "CREATE UNIQUE INDEX CONCURRENTLY", 1
        )

        m = re.search(r"INDEX\s+(?:CONCURRENTLY\s+)?(\w+)", concurrent_sql, re.IGNORECASE)
        idx_name = m.group(1) if m else "unknown_index"

        warnings = ["Original CREATE INDEX blocks writes. Rewritten to CONCURRENTLY."]

        phases = [
            MigrationPhase(
                phase_number=1,
                phase_type=MigrationPhaseType.INDEX,
                description=f"Create index {idx_name} CONCURRENTLY",
                sql=concurrent_sql,
                rollback_sql=f"DROP INDEX CONCURRENTLY IF EXISTS {idx_name};",
                lock_risk="LOW",
                duration_estimate="Depends on table size (non-blocking)",
                verification_sql=(
                    f"SELECT indexname, indexdef FROM pg_indexes "
                    f"WHERE indexname = '{idx_name}';"
                ),
                notes=[
                    "CONCURRENTLY builds the index without blocking writes",
                    "Cannot run inside a transaction",
                    "If interrupted, the index is left in INVALID state — drop and retry",
                ],
            ),
            MigrationPhase(
                phase_number=2,
                phase_type=MigrationPhaseType.VERIFY,
                description=f"Verify index {idx_name} is valid",
                sql=(
                    f"SELECT indexrelid::regclass AS index_name, indisvalid "
                    f"FROM pg_index WHERE indexrelid = '{idx_name}'::regclass;"
                ),
                rollback_sql="-- No rollback needed for verification",
                lock_risk="LOW",
                duration_estimate="< 10ms",
                verification_sql=(
                    f"SELECT indisvalid FROM pg_index "
                    f"WHERE indexrelid = '{idx_name}'::regclass;"
                ),
            ),
        ]
        return phases, warnings

    # ── DROP COLUMN ──────────────────────────────────────────────────

    def _plan_drop_column(self, sql: str) -> tuple[list[MigrationPhase], list[str]]:
        m = re.search(
            r"ALTER\s+TABLE\s+(\w+)\s+DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?(\w+)",
            sql,
            re.IGNORECASE,
        )
        table = m.group(1) if m else "unknown_table"
        column = m.group(2) if m else "unknown_column"

        warnings = [
            f"DROP COLUMN is irreversible. This plan adds a verification phase first.",
        ]

        phases = [
            # Phase 1: Deprecate
            MigrationPhase(
                phase_number=1,
                phase_type=MigrationPhaseType.EXPAND,
                description=f"Mark {column} as deprecated (app-level)",
                sql=(
                    f"COMMENT ON COLUMN {table}.{column} IS "
                    f"'DEPRECATED: scheduled for removal. Do not use in new code.';"
                ),
                rollback_sql=(
                    f"COMMENT ON COLUMN {table}.{column} IS NULL;"
                ),
                lock_risk="LOW",
                duration_estimate="< 10ms",
                requires_app_change=True,
                notes=[
                    "Update application code to stop reading this column",
                    "Monitor pg_stat_user_tables to verify column is unused",
                    "Wait for at least 1 release cycle before dropping",
                ],
            ),
            # Phase 2: Verify unused
            MigrationPhase(
                phase_number=2,
                phase_type=MigrationPhaseType.VERIFY,
                description=f"Verify {column} is no longer queried",
                sql=(
                    f"-- Check pg_stat_statements for queries referencing {column}:\n"
                    f"SELECT query, calls FROM pg_stat_statements\n"
                    f"WHERE query ILIKE '%{column}%' AND query ILIKE '%{table}%'\n"
                    f"ORDER BY calls DESC LIMIT 10;"
                ),
                rollback_sql="-- No rollback needed",
                lock_risk="LOW",
                duration_estimate="< 100ms",
                notes=["If queries still reference this column, do NOT proceed to drop"],
            ),
            # Phase 3: Drop
            MigrationPhase(
                phase_number=3,
                phase_type=MigrationPhaseType.CONTRACT,
                description=f"Drop column {column}",
                sql=(
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"ALTER TABLE {table} DROP COLUMN {column};"
                ),
                rollback_sql=f"-- IRREVERSIBLE: Restore from backup if needed",
                lock_risk="MEDIUM",
                duration_estimate="< 100ms (metadata only)",
                verification_sql=(
                    f"SELECT column_name FROM information_schema.columns "
                    f"WHERE table_name = '{table}' AND column_name = '{column}';"
                ),
                notes=["This is irreversible. Ensure backups are available."],
            ),
        ]
        return phases, warnings

    # ── RENAME COLUMN ────────────────────────────────────────────────

    def _plan_rename_column(self, sql: str) -> tuple[list[MigrationPhase], list[str]]:
        m = re.search(
            r"ALTER\s+TABLE\s+(\w+)\s+RENAME\s+COLUMN\s+(\w+)\s+TO\s+(\w+)",
            sql,
            re.IGNORECASE,
        )
        table = m.group(1) if m else "unknown_table"
        old_col = m.group(2) if m else "old_column"
        new_col = m.group(3) if m else "new_column"

        warnings = [
            "Direct RENAME takes an ACCESS EXCLUSIVE lock. "
            "Using add-copy-swap pattern instead."
        ]

        phases = [
            MigrationPhase(
                phase_number=1,
                phase_type=MigrationPhaseType.EXPAND,
                description=f"Add new column {new_col}",
                sql=(
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"ALTER TABLE {table} ADD COLUMN {new_col} "
                    f"(SELECT data_type FROM information_schema.columns "
                    f"WHERE table_name='{table}' AND column_name='{old_col}');\n"
                    f"-- Copy data type from {old_col}"
                ),
                rollback_sql=f"ALTER TABLE {table} DROP COLUMN IF EXISTS {new_col};",
                lock_risk="LOW",
                duration_estimate="< 100ms",
                requires_app_change=True,
                notes=["Match the data type of the original column"],
            ),
            MigrationPhase(
                phase_number=2,
                phase_type=MigrationPhaseType.MIGRATE,
                description=f"Backfill {new_col} from {old_col}",
                sql=(
                    f"DO $$\n"
                    f"DECLARE affected BIGINT;\n"
                    f"BEGIN\n"
                    f"    LOOP\n"
                    f"        WITH batch AS (\n"
                    f"            SELECT ctid FROM {table}\n"
                    f"            WHERE {new_col} IS NULL AND {old_col} IS NOT NULL\n"
                    f"            LIMIT {self.batch_size}\n"
                    f"            FOR UPDATE SKIP LOCKED\n"
                    f"        )\n"
                    f"        UPDATE {table} SET {new_col} = {old_col}\n"
                    f"        WHERE ctid IN (SELECT ctid FROM batch);\n"
                    f"\n"
                    f"        GET DIAGNOSTICS affected = ROW_COUNT;\n"
                    f"        EXIT WHEN affected = 0;\n"
                    f"        PERFORM pg_sleep(0.1);\n"
                    f"    END LOOP;\n"
                    f"END $$;"
                ),
                rollback_sql=f"UPDATE {table} SET {new_col} = NULL;",
                lock_risk="LOW",
                duration_estimate="Depends on table size",
            ),
            MigrationPhase(
                phase_number=3,
                phase_type=MigrationPhaseType.EXPAND,
                description=f"Add trigger to keep columns in sync",
                sql=(
                    f"CREATE OR REPLACE FUNCTION sync_{table}_{old_col}_{new_col}() "
                    f"RETURNS TRIGGER AS $$\n"
                    f"BEGIN\n"
                    f"    IF NEW.{old_col} IS DISTINCT FROM OLD.{old_col} THEN\n"
                    f"        NEW.{new_col} := NEW.{old_col};\n"
                    f"    END IF;\n"
                    f"    IF NEW.{new_col} IS DISTINCT FROM OLD.{new_col} THEN\n"
                    f"        NEW.{old_col} := NEW.{new_col};\n"
                    f"    END IF;\n"
                    f"    RETURN NEW;\n"
                    f"END;\n"
                    f"$$ LANGUAGE plpgsql;\n\n"
                    f"CREATE TRIGGER trg_sync_{old_col}_{new_col}\n"
                    f"BEFORE INSERT OR UPDATE ON {table}\n"
                    f"FOR EACH ROW EXECUTE FUNCTION sync_{table}_{old_col}_{new_col}();"
                ),
                rollback_sql=(
                    f"DROP TRIGGER IF EXISTS trg_sync_{old_col}_{new_col} ON {table};\n"
                    f"DROP FUNCTION IF EXISTS sync_{table}_{old_col}_{new_col}();"
                ),
                lock_risk="LOW",
                duration_estimate="< 100ms",
                notes=["Keeps both columns in sync during the transition period"],
            ),
            MigrationPhase(
                phase_number=4,
                phase_type=MigrationPhaseType.CONTRACT,
                description=f"Drop old column {old_col} (after app migration)",
                sql=(
                    f"DROP TRIGGER IF EXISTS trg_sync_{old_col}_{new_col} ON {table};\n"
                    f"DROP FUNCTION IF EXISTS sync_{table}_{old_col}_{new_col}();\n"
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"ALTER TABLE {table} DROP COLUMN {old_col};"
                ),
                rollback_sql=f"-- IRREVERSIBLE: old column data is lost",
                lock_risk="MEDIUM",
                duration_estimate="< 100ms",
                requires_app_change=True,
                notes=[
                    "Only run after ALL application code uses the new column name",
                    "Verify with pg_stat_statements that no queries reference old column",
                ],
            ),
        ]
        return phases, warnings

    # ── ALTER TYPE ───────────────────────────────────────────────────

    def _plan_alter_type(self, sql: str) -> tuple[list[MigrationPhase], list[str]]:
        m = re.search(
            r"ALTER\s+TABLE\s+(\w+)\s+ALTER\s+COLUMN\s+(\w+)\s+(?:SET\s+DATA\s+)?TYPE\s+(\w+)",
            sql,
            re.IGNORECASE,
        )
        table = m.group(1) if m else "unknown_table"
        column = m.group(2) if m else "unknown_column"
        new_type = m.group(3) if m else "unknown_type"

        warnings = [
            "ALTER TYPE rewrites the entire table with ACCESS EXCLUSIVE lock. "
            "Using add-new-column-swap pattern instead.",
        ]

        temp_col = f"{column}_new"

        phases = [
            MigrationPhase(
                phase_number=1,
                phase_type=MigrationPhaseType.EXPAND,
                description=f"Add temporary column {temp_col} with new type",
                sql=(
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"ALTER TABLE {table} ADD COLUMN {temp_col} {new_type};"
                ),
                rollback_sql=f"ALTER TABLE {table} DROP COLUMN IF EXISTS {temp_col};",
                lock_risk="LOW",
                duration_estimate="< 100ms",
            ),
            MigrationPhase(
                phase_number=2,
                phase_type=MigrationPhaseType.MIGRATE,
                description=f"Backfill {temp_col} with cast data",
                sql=(
                    f"DO $$\n"
                    f"DECLARE affected BIGINT;\n"
                    f"BEGIN\n"
                    f"    LOOP\n"
                    f"        WITH batch AS (\n"
                    f"            SELECT ctid FROM {table}\n"
                    f"            WHERE {temp_col} IS NULL\n"
                    f"            LIMIT {self.batch_size}\n"
                    f"            FOR UPDATE SKIP LOCKED\n"
                    f"        )\n"
                    f"        UPDATE {table} SET {temp_col} = {column}::{new_type}\n"
                    f"        WHERE ctid IN (SELECT ctid FROM batch);\n"
                    f"\n"
                    f"        GET DIAGNOSTICS affected = ROW_COUNT;\n"
                    f"        EXIT WHEN affected = 0;\n"
                    f"        PERFORM pg_sleep(0.1);\n"
                    f"    END LOOP;\n"
                    f"END $$;"
                ),
                rollback_sql=f"UPDATE {table} SET {temp_col} = NULL;",
                lock_risk="LOW",
                duration_estimate="Depends on table size",
            ),
            MigrationPhase(
                phase_number=3,
                phase_type=MigrationPhaseType.CONTRACT,
                description=f"Swap columns: drop {column}, rename {temp_col}",
                sql=(
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"ALTER TABLE {table} DROP COLUMN {column};\n"
                    f"ALTER TABLE {table} RENAME COLUMN {temp_col} TO {column};"
                ),
                rollback_sql=f"-- IRREVERSIBLE: requires backup restoration",
                lock_risk="MEDIUM",
                duration_estimate="< 100ms (two metadata operations)",
                requires_app_change=True,
                notes=["Ensure no queries are running when swapping"],
            ),
        ]
        return phases, warnings

    # ── ADD CONSTRAINT ───────────────────────────────────────────────

    def _plan_add_constraint(self, sql: str) -> tuple[list[MigrationPhase], list[str]]:
        m = re.search(
            r"ALTER\s+TABLE\s+(\w+)\s+ADD\s+CONSTRAINT\s+(\w+)",
            sql,
            re.IGNORECASE,
        )
        table = m.group(1) if m else "unknown_table"
        constraint = m.group(2) if m else "unknown_constraint"

        # Use NOT VALID + VALIDATE pattern
        not_valid_sql = sql.rstrip(";") + " NOT VALID;"

        phases = [
            MigrationPhase(
                phase_number=1,
                phase_type=MigrationPhaseType.EXPAND,
                description=f"Add constraint {constraint} as NOT VALID",
                sql=(
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"{not_valid_sql}"
                ),
                rollback_sql=f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint};",
                lock_risk="LOW",
                duration_estimate="< 100ms (checks new rows only)",
                notes=[
                    "NOT VALID adds the constraint without scanning existing rows",
                    "New inserts/updates are still validated",
                ],
            ),
            MigrationPhase(
                phase_number=2,
                phase_type=MigrationPhaseType.VERIFY,
                description=f"Validate constraint {constraint} (non-blocking)",
                sql=(
                    f"ALTER TABLE {table} VALIDATE CONSTRAINT {constraint};"
                ),
                rollback_sql=f"-- Constraint stays NOT VALID if interrupted",
                lock_risk="LOW",
                duration_estimate="Depends on table size (SHARE UPDATE EXCLUSIVE lock)",
                verification_sql=(
                    f"SELECT conname, convalidated FROM pg_constraint "
                    f"WHERE conrelid = '{table}'::regclass "
                    f"AND conname = '{constraint}';"
                ),
                notes=[
                    "VALIDATE acquires SHARE UPDATE EXCLUSIVE (allows reads + writes)",
                    "Safe to run during peak traffic",
                ],
            ),
        ]
        return phases, []

    # ── DROP TABLE ───────────────────────────────────────────────────

    def _plan_drop_table(self, sql: str) -> tuple[list[MigrationPhase], list[str]]:
        m = re.search(
            r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)",
            sql,
            re.IGNORECASE,
        )
        table = m.group(1) if m else "unknown_table"

        warnings = [
            f"DROP TABLE is irreversible. This plan renames first for safe rollback.",
        ]

        phases = [
            MigrationPhase(
                phase_number=1,
                phase_type=MigrationPhaseType.EXPAND,
                description=f"Rename {table} to {table}_deprecated",
                sql=(
                    f"SET lock_timeout = '{self.lock_timeout_ms}ms';\n"
                    f"ALTER TABLE {table} RENAME TO {table}_deprecated;"
                ),
                rollback_sql=f"ALTER TABLE {table}_deprecated RENAME TO {table};",
                lock_risk="LOW",
                duration_estimate="< 100ms",
                notes=[
                    "Renaming is instant and reversible",
                    "Application will fail fast with 'table not found' — expected",
                ],
            ),
            MigrationPhase(
                phase_number=2,
                phase_type=MigrationPhaseType.VERIFY,
                description="Verify no application errors for 24-48 hours",
                sql=(
                    f"-- Monitor application logs for errors referencing {table}\n"
                    f"-- Check pg_stat_statements for queries against {table}"
                ),
                rollback_sql=f"ALTER TABLE {table}_deprecated RENAME TO {table};",
                lock_risk="LOW",
                duration_estimate="24-48 hours",
                notes=[
                    "Wait for at least 1 full business cycle",
                    "If errors occur, rollback by renaming back",
                ],
            ),
            MigrationPhase(
                phase_number=3,
                phase_type=MigrationPhaseType.CONTRACT,
                description=f"Drop deprecated table {table}_deprecated",
                sql=f"DROP TABLE IF EXISTS {table}_deprecated;",
                rollback_sql="-- IRREVERSIBLE: restore from backup if needed",
                lock_risk="LOW",
                duration_estimate="< 100ms",
                notes=["Only execute after verification period"],
            ),
        ]
        return phases, warnings

    # ── Helpers ───────────────────────────────────────────────────────

    def _estimate_total_time(self, phases: list[MigrationPhase]) -> str:
        """Rough estimate of total migration time."""
        has_backfill = any(p.phase_type == MigrationPhaseType.MIGRATE for p in phases)
        has_verify_wait = any(
            "24-48 hours" in p.duration_estimate for p in phases
        )

        if has_verify_wait:
            return "24-48 hours (includes verification period)"
        elif has_backfill:
            return "5-60 minutes (depends on table size)"
        else:
            return "< 1 minute"
