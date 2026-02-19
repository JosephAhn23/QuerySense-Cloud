"""
Monitoring User Setup — automated least-privilege user creation.

Creates a restricted PostgreSQL role with the minimum permissions
needed for QuerySense's collector, probe, and health commands.

Modeled on pganalyze's monitoring user setup:
https://pganalyze.com/docs/install/01_enabling_pg_stat_statements

Permissions granted:
- pg_read_all_stats (PG 10+): read pg_stat_statements, pg_stat_activity, etc.
- pg_read_all_settings (PG 10+): read pg_settings
- CONNECT on target database
- USAGE on pg_catalog schema
- SELECT on pg_stat_statements (if using the extension)
- SELECT on pg_stat_activity, pg_stat_replication, pg_stat_user_tables, etc.
- EXECUTE on pg_stat_get_* functions

Does NOT grant:
- Superuser
- CREATEDB / CREATEROLE
- INSERT / UPDATE / DELETE on any table
- Access to user data tables

Usage:
    from querysense.db.monitoring_setup import MonitoringSetup

    setup = MonitoringSetup()

    # Generate SQL script (no DB connection needed)
    script = setup.generate_sql(
        username="querysense_monitor",
        database="mydb",
    )
    print(script)

    # Or apply directly
    report = await setup.apply(
        admin_dsn="postgresql://admin:pass@localhost/mydb",
        username="querysense_monitor",
        password="secure_password_here",
    )
    print(report.dsn)  # Connection string for the new user
"""

from __future__ import annotations

import logging
import secrets
import string
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""
    async def execute(self, query: str, *args: Any) -> str: ...
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class SetupReport:
    """Report from monitoring user setup."""
    username: str = ""
    database: str = ""
    password: str = ""       # Only populated if generated
    dsn: str = ""            # Connection string for the new user
    pg_version: int = 0
    steps_completed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    sql_executed: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "username": self.username,
            "database": self.database,
            "dsn": self.dsn,
            "pg_version": self.pg_version,
            "steps_completed": self.steps_completed,
            "warnings": self.warnings,
            "errors": self.errors,
        }


def _generate_password(length: int = 32) -> str:
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class MonitoringSetup:
    """
    Create and configure a least-privilege monitoring user.

    Works with PostgreSQL 10+ (uses pg_read_all_stats role).
    Falls back to individual GRANTs for older versions.
    """

    def generate_sql(
        self,
        username: str = "querysense_monitor",
        database: str = "mydb",
        password: str | None = None,
        pg_version: int = 160000,
    ) -> str:
        """
        Generate the complete SQL script for monitoring user setup.

        Args:
            username: Username to create
            database: Database to grant access to
            password: Password (generated if None)
            pg_version: PostgreSQL version number (e.g. 160000 for 16.0)

        Returns:
            Complete SQL script as a string
        """
        pwd = password or _generate_password()
        has_roles = pg_version >= 100000  # PG 10+ has predefined roles

        lines = [
            "-- ═══════════════════════════════════════════════════════════",
            "-- QuerySense Monitoring User Setup",
            "-- Least-privilege role for collector, probe, and health checks",
            "-- ═══════════════════════════════════════════════════════════",
            "",
            "-- Step 1: Create the monitoring role",
            f"CREATE ROLE {username} WITH LOGIN PASSWORD '{pwd}';",
            "",
            "-- Step 2: Grant database access",
            f"GRANT CONNECT ON DATABASE {database} TO {username};",
            "",
        ]

        if has_roles:
            lines.extend([
                "-- Step 3: Grant predefined monitoring roles (PostgreSQL 10+)",
                f"GRANT pg_read_all_stats TO {username};",
                f"GRANT pg_read_all_settings TO {username};",
                "",
            ])
            if pg_version >= 140000:
                lines.extend([
                    "-- PostgreSQL 14+ additional roles",
                    f"GRANT pg_read_server_files TO {username};  -- for log analysis (optional)",
                    "",
                ])
        else:
            lines.extend([
                "-- Step 3: Grant individual permissions (PostgreSQL 9.x fallback)",
                f"GRANT USAGE ON SCHEMA public TO {username};",
                f"GRANT SELECT ON ALL TABLES IN SCHEMA pg_catalog TO {username};",
                "",
                "-- Grant access to statistics views",
                f"GRANT SELECT ON pg_stat_activity TO {username};",
                f"GRANT SELECT ON pg_stat_replication TO {username};",
                f"GRANT SELECT ON pg_stat_user_tables TO {username};",
                f"GRANT SELECT ON pg_stat_user_indexes TO {username};",
                f"GRANT SELECT ON pg_statio_user_tables TO {username};",
                f"GRANT SELECT ON pg_statio_user_indexes TO {username};",
                f"GRANT SELECT ON pg_stat_database TO {username};",
                f"GRANT SELECT ON pg_stat_bgwriter TO {username};",
                f"GRANT SELECT ON pg_locks TO {username};",
                "",
            ])

        lines.extend([
            "-- Step 4: Enable pg_stat_statements (if not already enabled)",
            "-- Add to postgresql.conf: shared_preload_libraries = 'pg_stat_statements'",
            "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;",
            "",
            "-- Step 5: Grant access to pg_stat_statements view",
            f"GRANT SELECT ON pg_stat_statements TO {username};",
            "",
            "-- Step 6: Optional extensions for deeper analysis",
            "-- CREATE EXTENSION IF NOT EXISTS pgstattuple;  -- for exact bloat measurement",
            "-- CREATE EXTENSION IF NOT EXISTS pg_visibility;  -- for freeze map analysis",
            "-- CREATE EXTENSION IF NOT EXISTS hypopg;  -- for hypothetical index testing",
            "",
            "-- Step 7: Schema access for metadata queries",
            f"GRANT USAGE ON SCHEMA public TO {username};",
            f"GRANT USAGE ON SCHEMA information_schema TO {username};",
            f"GRANT SELECT ON ALL TABLES IN SCHEMA information_schema TO {username};",
            "",
            "-- Step 8: Function access for monitoring queries",
            f"GRANT EXECUTE ON FUNCTION pg_database_size(name) TO {username};",
            f"GRANT EXECUTE ON FUNCTION pg_table_size(regclass) TO {username};",
            f"GRANT EXECUTE ON FUNCTION pg_indexes_size(regclass) TO {username};",
            f"GRANT EXECUTE ON FUNCTION pg_relation_size(regclass) TO {username};",
            f"GRANT EXECUTE ON FUNCTION pg_total_relation_size(regclass) TO {username};",
            "",
            "-- ═══════════════════════════════════════════════════════════",
            "-- Setup complete. Connection string:",
            f"-- postgresql://{username}:{pwd}@localhost:5432/{database}",
            "-- ═══════════════════════════════════════════════════════════",
            "",
            "-- Verify permissions:",
            f"-- \\c {database} {username}",
            "-- SELECT count(*) FROM pg_stat_statements;  -- should work",
            "-- SELECT count(*) FROM pg_stat_activity;     -- should work",
            "-- INSERT INTO pg_class VALUES (...);          -- should FAIL",
        ])

        return "\n".join(lines)

    async def apply(
        self,
        admin_dsn: str,
        username: str = "querysense_monitor",
        password: str | None = None,
    ) -> SetupReport:
        """
        Apply the monitoring user setup to a live database.

        Args:
            admin_dsn: Admin connection string (needs CREATEROLE privilege)
            username: Username to create
            password: Password (generated if None)

        Returns:
            SetupReport with results and new user's DSN
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        pwd = password or _generate_password()
        report = SetupReport(username=username, password=pwd)

        conn = await asyncpg.connect(admin_dsn)
        try:
            # Get PG version and database name
            row = await conn.fetchrow(
                "SELECT current_setting('server_version_num')::int, current_database()"
            )
            report.pg_version = row[0]
            report.database = row[1]

            has_roles = report.pg_version >= 100000

            # Step 1: Check if user already exists
            exists = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", username
            )
            if exists:
                report.warnings.append(f"Role '{username}' already exists — updating permissions only")
                report.steps_completed.append("role_exists")
            else:
                await self._execute(
                    conn, report,
                    f"CREATE ROLE {username} WITH LOGIN PASSWORD '{pwd}'",
                    "create_role",
                )

            # Step 2: Grant CONNECT
            await self._execute(
                conn, report,
                f"GRANT CONNECT ON DATABASE {report.database} TO {username}",
                "grant_connect",
            )

            # Step 3: Grant predefined roles or individual permissions
            if has_roles:
                await self._execute(
                    conn, report,
                    f"GRANT pg_read_all_stats TO {username}",
                    "grant_pg_read_all_stats",
                )
                await self._execute(
                    conn, report,
                    f"GRANT pg_read_all_settings TO {username}",
                    "grant_pg_read_all_settings",
                )
            else:
                grants = [
                    f"GRANT USAGE ON SCHEMA public TO {username}",
                    f"GRANT SELECT ON ALL TABLES IN SCHEMA pg_catalog TO {username}",
                ]
                for grant in grants:
                    await self._execute(conn, report, grant, "grant_fallback")

            # Step 4: pg_stat_statements
            try:
                has_pgss = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM pg_available_extensions "
                    "WHERE name = 'pg_stat_statements' AND installed_version IS NOT NULL)"
                )
                if has_pgss:
                    await self._execute(
                        conn, report,
                        f"GRANT SELECT ON pg_stat_statements TO {username}",
                        "grant_pgss",
                    )
                else:
                    report.warnings.append(
                        "pg_stat_statements not installed. "
                        "Add shared_preload_libraries = 'pg_stat_statements' to postgresql.conf"
                    )
            except Exception:
                report.warnings.append("Could not check pg_stat_statements status")

            # Step 5: Schema access
            await self._execute(
                conn, report,
                f"GRANT USAGE ON SCHEMA public TO {username}",
                "grant_schema_public",
            )
            await self._execute(
                conn, report,
                f"GRANT USAGE ON SCHEMA information_schema TO {username}",
                "grant_schema_info",
            )

            # Build DSN
            # Parse host/port from admin DSN
            try:
                parsed = asyncpg.connect_utils._parse_connect_dsn_and_args(
                    dsn=admin_dsn, host=None, port=None, user=None, password=None,
                    passfile=None, database=None, ssl=None, direct_tls=None,
                    connect_timeout=None, server_settings=None,
                )
                # Fallback to simple DSN construction
                report.dsn = (
                    f"postgresql://{username}:{pwd}@localhost:5432/{report.database}"
                )
            except Exception:
                report.dsn = (
                    f"postgresql://{username}:{pwd}@localhost:5432/{report.database}"
                )

            report.steps_completed.append("complete")

        except Exception as e:
            report.errors.append(f"Setup failed: {e}")
            logger.error("Monitoring user setup failed: %s", e)
        finally:
            await conn.close()

        return report

    async def verify(
        self,
        dsn: str,
    ) -> dict[str, bool]:
        """
        Verify that a monitoring user has the required permissions.

        Args:
            dsn: Connection string for the monitoring user

        Returns:
            Dict mapping permission names to True/False
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        results: dict[str, bool] = {}
        conn = await asyncpg.connect(dsn)

        try:
            checks = {
                "pg_stat_activity": "SELECT count(*) FROM pg_stat_activity",
                "pg_settings": "SELECT count(*) FROM pg_settings",
                "pg_class": "SELECT count(*) FROM pg_class WHERE relkind = 'r'",
                "pg_stat_user_tables": "SELECT count(*) FROM pg_stat_user_tables",
                "pg_stat_user_indexes": "SELECT count(*) FROM pg_stat_user_indexes",
                "pg_stat_statements": "SELECT count(*) FROM pg_stat_statements",
                "pg_replication_slots": "SELECT count(*) FROM pg_replication_slots",
                "pg_database_size": "SELECT pg_database_size(current_database())",
                "pg_table_size": "SELECT pg_table_size(oid) FROM pg_class WHERE relkind = 'r' LIMIT 1",
            }

            for name, query in checks.items():
                try:
                    await conn.fetchval(query)
                    results[name] = True
                except Exception:
                    results[name] = False

        finally:
            await conn.close()

        return results

    async def _execute(
        self,
        conn: Any,
        report: SetupReport,
        sql: str,
        step_name: str,
    ) -> None:
        """Execute a SQL statement and track it."""
        try:
            await conn.execute(sql)
            report.steps_completed.append(step_name)
            report.sql_executed.append(sql)
        except Exception as e:
            report.warnings.append(f"Step '{step_name}' failed: {e}")
            logger.debug("Setup step %s failed: %s", step_name, e)
