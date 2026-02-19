"""
Migration File Generator — convert QuerySense fixes to versioned migration files.

Addresses the #1 competitive weakness: QuerySense generates DDL (CREATE INDEX,
ANALYZE, ALTER TABLE) but has no schema change lifecycle. Harness, Liquibase,
and Flyway all version and track schema changes. This module bridges the gap.

Supported formats:
- Flyway:    V{version}__{description}.sql
- Liquibase: YAML changeset with rollback
- Alembic:   Python migration with upgrade() / downgrade()
- Django:    Python migration with RunSQL operations
- Raw SQL:   Plain .sql file with rollback comments
- dbmate:    SQL file with -- migrate:up / -- migrate:down sections

Usage:
    from querysense.migration_gen import MigrationGenerator, MigrationFormat

    gen = MigrationGenerator(output_dir="migrations")
    path = gen.generate(
        fixes=["CREATE INDEX idx_orders_status ON orders(status);"],
        format=MigrationFormat.FLYWAY,
        description="add_orders_status_index",
    )
    print(f"Migration written to {path}")
"""

from __future__ import annotations

import hashlib
import re
import textwrap
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class MigrationFormat(str, Enum):
    """Supported migration framework formats."""
    FLYWAY = "flyway"
    LIQUIBASE = "liquibase"
    ALEMBIC = "alembic"
    DJANGO = "django"
    DBMATE = "dbmate"
    RAW_SQL = "sql"


# Rollback mapping: DDL statement → reverse DDL
_ROLLBACK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # CREATE INDEX → DROP INDEX
    (
        re.compile(
            r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\S+)",
            re.IGNORECASE,
        ),
        r"DROP INDEX IF EXISTS \1;",
    ),
    # CREATE INDEX ON table USING → DROP INDEX
    (
        re.compile(
            r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?ON\s+\S+",
            re.IGNORECASE,
        ),
        "-- Manual rollback required: DROP INDEX <index_name>;",
    ),
]


def _generate_rollback(sql: str) -> str:
    """Generate rollback SQL for a DDL statement."""
    for pattern, replacement in _ROLLBACK_PATTERNS:
        match = pattern.search(sql)
        if match:
            return pattern.sub(replacement, sql)
    return f"-- Manual rollback required for: {sql.strip()[:80]}"


def _slugify(text: str) -> str:
    """Convert text to a safe filename slug."""
    text = re.sub(r"[^\w\s-]", "", text.lower())
    text = re.sub(r"[\s-]+", "_", text)
    return text.strip("_")[:60]


def _next_flyway_version(output_dir: Path) -> str:
    """Determine the next Flyway version number."""
    existing = sorted(output_dir.glob("V*__*.sql"))
    if not existing:
        return "001"

    # Extract highest version
    max_ver = 0
    for f in existing:
        match = re.match(r"V(\d+)__", f.name)
        if match:
            max_ver = max(max_ver, int(match.group(1)))

    return f"{max_ver + 1:03d}"


def _next_alembic_revision() -> str:
    """Generate an Alembic-style revision ID."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    h = hashlib.md5(ts.encode()).hexdigest()[:4]
    return f"{ts}_{h}"


class MigrationGenerator:
    """
    Generates versioned migration files from QuerySense fix DDL.

    Supports Flyway, Liquibase, Alembic, Django, dbmate, and raw SQL.
    Each format includes rollback/downgrade instructions where possible.
    """

    def __init__(self, output_dir: str | Path = "migrations") -> None:
        self.output_dir = Path(output_dir)

    def generate(
        self,
        fixes: list[str],
        format: MigrationFormat,
        description: str = "querysense_performance_fix",
        source_plan: str | None = None,
    ) -> Path:
        """
        Generate a migration file from a list of SQL fix statements.

        Args:
            fixes: List of SQL DDL statements from QuerySense findings
            description: Human-readable description for the migration
            format: Target migration framework format
            source_plan: Optional path to the EXPLAIN plan that triggered these fixes

        Returns:
            Path to the generated migration file
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        slug = _slugify(description)
        now = datetime.now(timezone.utc)

        if format == MigrationFormat.FLYWAY:
            return self._gen_flyway(fixes, slug, source_plan)
        elif format == MigrationFormat.LIQUIBASE:
            return self._gen_liquibase(fixes, slug, now, source_plan)
        elif format == MigrationFormat.ALEMBIC:
            return self._gen_alembic(fixes, slug, now, source_plan)
        elif format == MigrationFormat.DJANGO:
            return self._gen_django(fixes, slug, now, source_plan)
        elif format == MigrationFormat.DBMATE:
            return self._gen_dbmate(fixes, slug, source_plan)
        else:
            return self._gen_raw_sql(fixes, slug, now, source_plan)

    def _gen_flyway(
        self, fixes: list[str], slug: str, source_plan: str | None,
    ) -> Path:
        """Generate Flyway SQL migration: V{NNN}__{description}.sql"""
        version = _next_flyway_version(self.output_dir)
        filename = f"V{version}__{slug}.sql"
        path = self.output_dir / filename

        lines: list[str] = []
        lines.append(f"-- Flyway migration generated by QuerySense")
        lines.append(f"-- Version: {version}")
        lines.append(f"-- Generated: {datetime.now(timezone.utc).isoformat()}")
        if source_plan:
            lines.append(f"-- Source plan: {source_plan}")
        lines.append("")

        for fix in fixes:
            fix = fix.strip()
            if not fix.endswith(";"):
                fix += ";"
            lines.append(fix)
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _gen_liquibase(
        self, fixes: list[str], slug: str, now: datetime, source_plan: str | None,
    ) -> Path:
        """Generate Liquibase YAML changeset with rollback."""
        filename = f"{now.strftime('%Y%m%d%H%M%S')}_{slug}.yaml"
        path = self.output_dir / filename

        changeset_id = now.strftime("%Y%m%d%H%M%S")

        lines: list[str] = []
        lines.append("databaseChangeLog:")

        for i, fix in enumerate(fixes, 1):
            fix = fix.strip().rstrip(";")
            rollback = _generate_rollback(fix)

            lines.append(f"  - changeSet:")
            lines.append(f"      id: querysense-{changeset_id}-{i}")
            lines.append(f"      author: querysense")
            lines.append(f"      comment: \"Performance fix from QuerySense analysis\"")
            if source_plan:
                lines.append(f"      # Source plan: {source_plan}")
            lines.append(f"      changes:")
            lines.append(f"        - sql:")
            lines.append(f"            sql: \"{fix};\"")
            lines.append(f"      rollback:")
            lines.append(f"        - sql:")
            lines.append(f"            sql: \"{rollback}\"")
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _gen_alembic(
        self, fixes: list[str], slug: str, now: datetime, source_plan: str | None,
    ) -> Path:
        """Generate Alembic Python migration with upgrade()/downgrade()."""
        revision = _next_alembic_revision()
        filename = f"{revision}_{slug}.py"
        path = self.output_dir / filename

        upgrade_ops: list[str] = []
        downgrade_ops: list[str] = []

        for fix in fixes:
            fix = fix.strip()
            if not fix.endswith(";"):
                fix += ";"
            escaped = fix.replace("'", "\\'").replace('"', '\\"')
            upgrade_ops.append(f'    op.execute("{escaped}")')

            rollback = _generate_rollback(fix)
            escaped_rb = rollback.replace("'", "\\'").replace('"', '\\"')
            downgrade_ops.append(f'    op.execute("{escaped_rb}")')

        source_comment = f"\n# Source plan: {source_plan}" if source_plan else ""

        content = textwrap.dedent(f'''\
            """Performance fix from QuerySense analysis.

            Revision ID: {revision}
            Create Date: {now.isoformat()}{source_comment}
            """
            from alembic import op

            # Revision identifiers
            revision = "{revision}"
            down_revision = None  # UPDATE: set to previous migration revision
            branch_labels = None
            depends_on = None


            def upgrade() -> None:
                """Apply QuerySense performance fixes."""
            {chr(10).join(upgrade_ops)}


            def downgrade() -> None:
                """Rollback QuerySense performance fixes."""
            {chr(10).join(downgrade_ops)}
        ''')

        path.write_text(content, encoding="utf-8")
        return path

    def _gen_django(
        self, fixes: list[str], slug: str, now: datetime, source_plan: str | None,
    ) -> Path:
        """Generate Django RunSQL migration."""
        ts = now.strftime("%Y%m%d%H%M%S")
        filename = f"{ts}_{slug}.py"
        path = self.output_dir / filename

        operations: list[str] = []
        for fix in fixes:
            fix = fix.strip()
            if not fix.endswith(";"):
                fix += ";"
            rollback = _generate_rollback(fix)

            fix_escaped = fix.replace("'", "\\'")
            rb_escaped = rollback.replace("'", "\\'")

            operations.append(
                f"        migrations.RunSQL(\n"
                f"            sql='{fix_escaped}',\n"
                f"            reverse_sql='{rb_escaped}',\n"
                f"        ),"
            )

        source_comment = f"\n# Source plan: {source_plan}" if source_plan else ""

        content = textwrap.dedent(f'''\
            """Performance fix from QuerySense analysis.

            Generated: {now.isoformat()}{source_comment}
            """

            from django.db import migrations


            class Migration(migrations.Migration):

                dependencies = [
                    # UPDATE: add your last migration here
                    # ("myapp", "0001_initial"),
                ]

                operations = [
            {chr(10).join(operations)}
                ]
        ''')

        path.write_text(content, encoding="utf-8")
        return path

    def _gen_dbmate(
        self, fixes: list[str], slug: str, source_plan: str | None,
    ) -> Path:
        """Generate dbmate migration with migrate:up / migrate:down."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        filename = f"{ts}_{slug}.sql"
        path = self.output_dir / filename

        lines: list[str] = []
        lines.append(f"-- migrate:up")
        lines.append(f"-- QuerySense performance fix")
        if source_plan:
            lines.append(f"-- Source plan: {source_plan}")
        lines.append("")

        for fix in fixes:
            fix = fix.strip()
            if not fix.endswith(";"):
                fix += ";"
            lines.append(fix)
            lines.append("")

        lines.append("-- migrate:down")
        lines.append("")

        for fix in fixes:
            rollback = _generate_rollback(fix.strip())
            lines.append(rollback)
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _gen_raw_sql(
        self, fixes: list[str], slug: str, now: datetime, source_plan: str | None,
    ) -> Path:
        """Generate plain SQL file with rollback comments."""
        ts = now.strftime("%Y%m%d%H%M%S")
        filename = f"{ts}_{slug}.sql"
        path = self.output_dir / filename

        lines: list[str] = []
        lines.append(f"-- QuerySense performance fix")
        lines.append(f"-- Generated: {now.isoformat()}")
        if source_plan:
            lines.append(f"-- Source plan: {source_plan}")
        lines.append(f"-- Apply with: psql < {filename}")
        lines.append("")
        lines.append("BEGIN;")
        lines.append("")

        for fix in fixes:
            fix = fix.strip()
            if not fix.endswith(";"):
                fix += ";"
            lines.append(fix)
            lines.append("")

        lines.append("COMMIT;")
        lines.append("")
        lines.append("-- Rollback:")
        for fix in fixes:
            rollback = _generate_rollback(fix.strip())
            lines.append(f"-- {rollback}")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path
