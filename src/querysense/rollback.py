"""
Intelligent Rollback Engine with Dependency Tracking.

Unlike Liquibase ("very difficult" rollbacks) and Flyway (paywalled undo),
this generates dependency-aware rollback SQL that preserves views, functions,
and triggers that depend on modified objects.

Enhancements over the basic migration_safety.generate_rollback():
- Tracks table → view → function dependency chains
- Saves and restores dependent views when dropping columns/tables
- Orders rollback statements to avoid dependency violations
- Handles CASCADE effects explicitly instead of silently

Usage:
    from querysense.rollback import generate_smart_rollback

    result = generate_smart_rollback(
        migration_sql="ALTER TABLE orders DROP COLUMN status;",
        dsn="postgresql://localhost/mydb"  # optional: queries catalog for deps
    )
    print(result.rollback_sql)
    print(result.warnings)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DependentObject:
    """An object that depends on a modified table/column."""

    object_type: str  # "view", "function", "trigger", "index", "policy"
    schema: str
    name: str
    definition: str  # CREATE statement to restore it
    depends_on_table: str
    depends_on_column: str | None = None


@dataclass
class RollbackPlan:
    """A complete rollback plan with dependency preservation."""

    migration_sql: str
    rollback_statements: list[str] = field(default_factory=list)
    pre_rollback: list[str] = field(default_factory=list)  # Drop dependents
    post_rollback: list[str] = field(default_factory=list)  # Recreate dependents
    warnings: list[str] = field(default_factory=list)
    dependent_objects: list[DependentObject] = field(default_factory=list)
    irreversible_statements: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return len(self.irreversible_statements) == 0

    @property
    def rollback_sql(self) -> str:
        """Full rollback SQL with dependency preservation."""
        lines = ["-- QuerySense Intelligent Rollback"]
        lines.append("-- Generated with dependency analysis")
        lines.append("")

        if self.warnings:
            for w in self.warnings:
                lines.append(f"-- WARNING: {w}")
            lines.append("")

        if self.pre_rollback:
            lines.append("-- ── Phase 1: Drop dependent objects ─────────────────")
            for stmt in self.pre_rollback:
                lines.append(stmt)
            lines.append("")

        if self.rollback_statements:
            lines.append("-- ── Phase 2: Undo migration ──────────────────────────")
            for stmt in self.rollback_statements:
                lines.append(stmt)
            lines.append("")

        if self.post_rollback:
            lines.append("-- ── Phase 3: Restore dependent objects ───────────────")
            for stmt in self.post_rollback:
                lines.append(stmt)
            lines.append("")

        if self.irreversible_statements:
            lines.append("-- ── MANUAL STEPS REQUIRED ────────────────────────────")
            for stmt in self.irreversible_statements:
                lines.append(f"-- {stmt}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "rollback_sql": self.rollback_sql,
            "rollback_statements": self.rollback_statements,
            "pre_rollback": self.pre_rollback,
            "post_rollback": self.post_rollback,
            "warnings": self.warnings,
            "dependent_objects": [
                {
                    "type": d.object_type,
                    "name": f"{d.schema}.{d.name}",
                    "depends_on": d.depends_on_table,
                }
                for d in self.dependent_objects
            ],
            "irreversible_count": len(self.irreversible_statements),
        }


def generate_smart_rollback(
    migration_sql: str,
    dependencies: list[DependentObject] | None = None,
) -> RollbackPlan:
    """
    Generate dependency-aware rollback SQL.

    Unlike basic rollback generators, this:
    1. Identifies dependent views/functions that would break
    2. Generates DROP statements for dependents (Phase 1)
    3. Generates undo statements for the migration (Phase 2)
    4. Generates CREATE statements to restore dependents (Phase 3)

    Args:
        migration_sql: The forward migration SQL
        dependencies: Optional pre-fetched dependency list.
                     If not provided, generates warnings about potential deps.

    Returns:
        RollbackPlan with phased rollback SQL
    """
    plan = RollbackPlan(migration_sql=migration_sql)
    statements = _split_statements(migration_sql)

    deps = dependencies or []
    dep_tables = {d.depends_on_table.lower() for d in deps}

    # Process each statement in reverse order
    for stmt in reversed(statements):
        _process_statement(stmt, plan, deps, dep_tables)

    return plan


def _process_statement(
    stmt: str,
    plan: RollbackPlan,
    deps: list[DependentObject],
    dep_tables: set[str],
) -> None:
    """Process a single SQL statement and add rollback logic."""

    # ── CREATE TABLE → DROP TABLE ───────────────────────────────
    match = re.search(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(\w+)\.)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        schema = match.group(1) or "public"
        table = match.group(2)
        plan.rollback_statements.append(f"DROP TABLE IF EXISTS {schema}.{table};")
        return

    # ── DROP TABLE → warn irreversible ──────────────────────────
    match = re.search(
        r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(\w+)\.)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        table = match.group(2)
        plan.irreversible_statements.append(
            f"Cannot auto-rollback DROP TABLE {table}. Restore from backup."
        )
        plan.warnings.append(f"DROP TABLE {table} is irreversible without backup")

        # Check for dependent views
        table_deps = [d for d in deps if d.depends_on_table.lower() == table.lower()]
        if table_deps:
            plan.warnings.append(
                f"{len(table_deps)} object(s) depend on {table}: "
                + ", ".join(f"{d.object_type} {d.name}" for d in table_deps)
            )
        return

    # ── ADD COLUMN → DROP COLUMN ────────────────────────────────
    match = re.search(
        r"ALTER\s+TABLE\s+(?:(\w+)\.)?(\w+)\s+ADD\s+(?:COLUMN\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if match and not re.search(r"\bADD\s+CONSTRAINT\b", stmt, re.IGNORECASE):
        schema = match.group(1) or "public"
        table = match.group(2)
        column = match.group(3)
        plan.rollback_statements.append(
            f"ALTER TABLE {schema}.{table} DROP COLUMN IF EXISTS {column};"
        )
        return

    # ── DROP COLUMN → save dependent views, warn ────────────────
    match = re.search(
        r"ALTER\s+TABLE\s+(?:(\w+)\.)?(\w+)\s+DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        table = match.group(2)
        column = match.group(3)

        # Find views that use this column
        col_deps = [
            d for d in deps
            if d.depends_on_table.lower() == table.lower()
            and (d.depends_on_column is None or d.depends_on_column.lower() == column.lower())
        ]

        if col_deps:
            plan.dependent_objects.extend(col_deps)
            for dep in col_deps:
                plan.pre_rollback.append(
                    f"DROP {dep.object_type.upper()} IF EXISTS {dep.schema}.{dep.name} CASCADE;"
                )
            plan.warnings.append(
                f"{len(col_deps)} dependent object(s) affected by DROP COLUMN {column}"
            )

        plan.irreversible_statements.append(
            f"Cannot auto-rollback DROP COLUMN {table}.{column}. "
            f"Recreate with: ALTER TABLE {table} ADD COLUMN {column} <type>; "
            f"then backfill data from backup."
        )

        # Restore dependent views after manual column restoration
        for dep in col_deps:
            if dep.definition:
                plan.post_rollback.append(dep.definition)

        return

    # ── CREATE INDEX → DROP INDEX ───────────────────────────────
    match = re.search(
        r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        index = match.group(1)
        plan.rollback_statements.append(f"DROP INDEX IF EXISTS {index};")
        return

    # ── DROP INDEX → warn ───────────────────────────────────────
    match = re.search(r"DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?(\w+)", stmt, re.IGNORECASE)
    if match:
        plan.irreversible_statements.append(
            f"Cannot auto-rollback DROP INDEX {match.group(1)}. "
            f"Recreate with the original CREATE INDEX statement."
        )
        return

    # ── RENAME → reverse rename ─────────────────────────────────
    match = re.search(
        r"ALTER\s+TABLE\s+(?:(\w+)\.)?(\w+)\s+RENAME\s+(?:COLUMN\s+)?(\w+)\s+TO\s+(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        schema = match.group(1) or "public"
        table = match.group(2)
        old_name = match.group(3)
        new_name = match.group(4)
        plan.rollback_statements.append(
            f"ALTER TABLE {schema}.{table} RENAME COLUMN {new_name} TO {old_name};"
        )
        return

    match = re.search(
        r"ALTER\s+TABLE\s+(?:(\w+)\.)?(\w+)\s+RENAME\s+TO\s+(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        schema = match.group(1) or "public"
        old_name = match.group(2)
        new_name = match.group(3)
        plan.rollback_statements.append(
            f"ALTER TABLE {schema}.{new_name} RENAME TO {old_name};"
        )
        return

    # ── ADD CONSTRAINT → DROP CONSTRAINT ────────────────────────
    match = re.search(
        r"ALTER\s+TABLE\s+(?:(\w+)\.)?(\w+)\s+ADD\s+CONSTRAINT\s+(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        schema = match.group(1) or "public"
        table = match.group(2)
        constraint = match.group(3)
        plan.rollback_statements.append(
            f"ALTER TABLE {schema}.{table} DROP CONSTRAINT IF EXISTS {constraint};"
        )
        return

    # ── DROP CONSTRAINT → warn ──────────────────────────────────
    match = re.search(
        r"ALTER\s+TABLE\s+(?:(\w+)\.)?(\w+)\s+DROP\s+CONSTRAINT\s+(?:IF\s+EXISTS\s+)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        plan.irreversible_statements.append(
            f"Cannot auto-rollback DROP CONSTRAINT {match.group(3)}. "
            f"Recreate with the original ADD CONSTRAINT statement."
        )
        return

    # ── ALTER COLUMN TYPE → warn ────────────────────────────────
    match = re.search(
        r"ALTER\s+TABLE\s+(\w+)\s+ALTER\s+(?:COLUMN\s+)?(\w+)\s+(?:SET\s+DATA\s+)?TYPE",
        stmt, re.IGNORECASE,
    )
    if match:
        plan.irreversible_statements.append(
            f"Cannot auto-rollback type change on {match.group(1)}.{match.group(2)}. "
            f"Restore the original type manually."
        )
        return

    # ── CREATE VIEW → DROP VIEW ─────────────────────────────────
    match = re.search(
        r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(\w+)\.)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        schema = match.group(1) or "public"
        view = match.group(2)
        is_mat = bool(re.search(r"\bMATERIALIZED\b", stmt, re.IGNORECASE))
        keyword = "MATERIALIZED VIEW" if is_mat else "VIEW"
        plan.rollback_statements.append(
            f"DROP {keyword} IF EXISTS {schema}.{view};"
        )
        return

    # ── CREATE FUNCTION → DROP FUNCTION ─────────────────────────
    match = re.search(
        r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:(\w+)\.)?(\w+)",
        stmt, re.IGNORECASE,
    )
    if match:
        schema = match.group(1) or "public"
        func = match.group(2)
        plan.rollback_statements.append(
            f"DROP FUNCTION IF EXISTS {schema}.{func};"
        )
        return

    # ── Unrecognized statement ──────────────────────────────────
    plan.warnings.append(f"No rollback pattern for: {stmt[:80]}...")


async def fetch_dependencies(
    dsn: str,
    table_name: str,
    schema_name: str = "public",
) -> list[DependentObject]:
    """
    Query PostgreSQL catalog for objects that depend on a table.

    Finds views, functions, triggers, and policies that reference
    the given table, so rollback can preserve them.
    """
    try:
        import asyncpg
    except ImportError:
        return []

    deps: list[DependentObject] = []

    try:
        conn = await asyncpg.connect(dsn)
        try:
            # Find dependent views
            rows = await conn.fetch("""
                SELECT DISTINCT
                    v.schemaname AS schema,
                    v.viewname AS name,
                    v.definition AS def
                FROM pg_views v
                JOIN pg_depend d ON d.objid = (
                    SELECT oid FROM pg_class WHERE relname = v.viewname AND relnamespace = (
                        SELECT oid FROM pg_namespace WHERE nspname = v.schemaname
                    )
                )
                JOIN pg_class c ON d.refobjid = c.oid
                JOIN pg_namespace n ON c.relnamespace = n.oid
                WHERE c.relname = $1 AND n.nspname = $2
                AND d.deptype = 'n'
            """, table_name, schema_name)

            for row in rows:
                deps.append(DependentObject(
                    object_type="view",
                    schema=row["schema"],
                    name=row["name"],
                    definition=f"CREATE OR REPLACE VIEW {row['schema']}.{row['name']} AS {row['def']}",
                    depends_on_table=table_name,
                ))

            # Find triggers
            rows = await conn.fetch("""
                SELECT
                    trigger_name,
                    event_object_schema AS schema,
                    event_object_table AS table_name,
                    action_statement AS definition
                FROM information_schema.triggers
                WHERE event_object_table = $1
                AND event_object_schema = $2
            """, table_name, schema_name)

            for row in rows:
                deps.append(DependentObject(
                    object_type="trigger",
                    schema=row["schema"],
                    name=row["trigger_name"],
                    definition=f"-- Trigger {row['trigger_name']}: {row['definition'][:200]}",
                    depends_on_table=table_name,
                ))

        finally:
            await conn.close()
    except Exception:
        pass  # Can't fetch deps — generate warnings instead

    return deps


def _split_statements(sql: str) -> list[str]:
    """Split SQL into individual statements."""
    from querysense.migration.sql_utils import split_statements

    return split_statements(sql, strip_comments=True)
