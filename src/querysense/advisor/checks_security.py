"""
Security Advisor Checks — PostgreSQL security hardening.

Implements Percona's security advisor pattern with PostgreSQL-specific checks:
    - SSL/TLS configuration
    - Password authentication policies
    - Superuser audit
    - pg_hba.conf trust authentication
    - Extension security
    - Row-level security awareness

All checks are read-only and never modify the database.
"""

from __future__ import annotations

from querysense.advisor.base import (
    AdvisorCategory,
    AdvisorCheck,
    AsyncDBConnection,
    CheckInterval,
    CheckResult,
    CheckSeverity,
    Finding,
)


# ------------------------------------------------------------------
# Individual checks
# ------------------------------------------------------------------


class SSLEnabledCheck(AdvisorCheck):
    """Check if SSL is enabled for client connections."""

    name = "postgres_ssl_enabled"
    title = "SSL/TLS Encryption"
    description = "Verify SSL is enabled for encrypted client connections"
    category = AdvisorCategory.SECURITY
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        ssl = await conn.fetchval("SHOW ssl")
        if str(ssl).lower() != "on":
            result.findings.append(Finding(
                severity=CheckSeverity.CRITICAL,
                title="SSL is disabled",
                description=(
                    "Client connections are not encrypted. All queries, passwords, "
                    "and data travel in plaintext over the network."
                ),
                recommendation="Enable SSL in postgresql.conf and configure certificates.",
                fix_sql="ALTER SYSTEM SET ssl = 'on';\n-- Requires: ssl_cert_file and ssl_key_file",
                rationale=(
                    "Without SSL, credentials and data are vulnerable to network sniffing. "
                    "PCI-DSS and SOC 2 require encryption in transit."
                ),
                tags=["pci-dss", "soc2", "encryption"],
            ))
            result.passed = False
        return result


class PasswordEncryptionCheck(AdvisorCheck):
    """Check password encryption method."""

    name = "postgres_password_encryption"
    title = "Password Encryption Method"
    description = "Verify passwords use scram-sha-256 (not md5)"
    category = AdvisorCategory.SECURITY
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        method = await conn.fetchval("SHOW password_encryption")
        if str(method).lower() != "scram-sha-256":
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"Password encryption uses '{method}' instead of scram-sha-256",
                description=(
                    "MD5 password hashing is cryptographically weak and vulnerable "
                    "to rainbow table attacks."
                ),
                recommendation="Switch to scram-sha-256 and re-set all user passwords.",
                fix_sql=(
                    "ALTER SYSTEM SET password_encryption = 'scram-sha-256';\n"
                    "SELECT pg_reload_conf();\n"
                    "-- Then for each user: ALTER USER username PASSWORD 'new_password';"
                ),
                rationale="SCRAM-SHA-256 (PostgreSQL 10+) is resistant to replay and offline attacks.",
                tags=["authentication", "passwords"],
            ))
            result.passed = False
        return result


class SuperuserAuditCheck(AdvisorCheck):
    """Audit superuser accounts."""

    name = "postgres_superuser_audit"
    title = "Superuser Account Audit"
    description = "Check for excessive superuser privileges"
    category = AdvisorCategory.SECURITY
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        rows = await conn.fetch(
            "SELECT usename, usesuper, passwd IS NOT NULL AS has_password, "
            "valuntil FROM pg_user WHERE usesuper = true ORDER BY usename"
        )

        superuser_count = len(rows)
        if superuser_count > 2:
            names = [r[0] if isinstance(r, (list, tuple)) else getattr(r, "usename", "") for r in rows]
            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"{superuser_count} superuser accounts found",
                description=(
                    f"Superuser accounts: {', '.join(str(n) for n in names)}. "
                    "Each superuser bypasses ALL permission checks."
                ),
                recommendation=(
                    "Reduce superuser accounts to 1-2. Use GRANT for specific privileges. "
                    "Application accounts should NEVER be superusers."
                ),
                evidence={"superusers": [str(n) for n in names]},
                tags=["least-privilege", "access-control"],
            ))
            result.passed = False

        # Check for superusers without passwords
        for row in rows:
            name = row[0] if isinstance(row, (list, tuple)) else getattr(row, "usename", "")
            has_pwd = row[2] if isinstance(row, (list, tuple)) else getattr(row, "has_password", True)
            if not has_pwd:
                result.findings.append(Finding(
                    severity=CheckSeverity.CRITICAL,
                    title=f"Superuser '{name}' has no password",
                    description="A superuser account without a password may allow unauthorized access.",
                    recommendation=f"Set a strong password for '{name}'.",
                    fix_sql=f"ALTER USER {name} PASSWORD 'STRONG_PASSWORD_HERE';",
                    tags=["authentication", "superuser"],
                ))
                result.passed = False

        return result


class TrustAuthenticationCheck(AdvisorCheck):
    """Check for trust authentication in pg_hba.conf."""

    name = "postgres_trust_authentication"
    title = "Trust Authentication"
    description = "Detect dangerous 'trust' authentication entries"
    category = AdvisorCategory.SECURITY
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        # pg_hba_file_rules available in PG 15+
        try:
            rows = await conn.fetch(
                "SELECT line_number, type, database, user_name, address, auth_method "
                "FROM pg_hba_file_rules WHERE auth_method = 'trust' "
                "AND type != 'local' ORDER BY line_number"
            )
        except Exception:
            # Older PostgreSQL without pg_hba_file_rules
            return result

        for row in rows:
            if isinstance(row, (list, tuple)):
                line, conn_type, db, user, addr, method = row[:6]
            else:
                line = getattr(row, "line_number", "?")
                conn_type = getattr(row, "type", "")
                db = getattr(row, "database", "")
                user = getattr(row, "user_name", "")
                addr = getattr(row, "address", "")
                method = getattr(row, "auth_method", "")

            result.findings.append(Finding(
                severity=CheckSeverity.CRITICAL,
                title=f"Trust authentication on line {line}",
                description=(
                    f"pg_hba.conf line {line}: type={conn_type}, db={db}, user={user}, "
                    f"address={addr}, method=trust. "
                    "ANY connection matching this rule can connect WITHOUT a password."
                ),
                recommendation="Replace 'trust' with 'scram-sha-256' or 'cert'.",
                rationale="Trust authentication bypasses all password checks.",
                evidence={"line": line, "type": str(conn_type), "address": str(addr)},
                tags=["pg_hba", "authentication"],
            ))
            result.passed = False

        return result


class LogConnectionsCheck(AdvisorCheck):
    """Check if connection logging is enabled."""

    name = "postgres_log_connections"
    title = "Connection Logging"
    description = "Verify connection/disconnection events are logged"
    category = AdvisorCategory.SECURITY
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        log_conn = await conn.fetchval("SHOW log_connections")
        log_disc = await conn.fetchval("SHOW log_disconnections")

        if str(log_conn).lower() != "on":
            result.findings.append(Finding(
                severity=CheckSeverity.NOTICE,
                title="Connection logging is disabled",
                description="Failed and successful connection attempts are not being logged.",
                recommendation="Enable log_connections for audit trail.",
                fix_sql="ALTER SYSTEM SET log_connections = 'on';",
                tags=["audit", "logging"],
            ))
            result.passed = False

        if str(log_disc).lower() != "on":
            result.findings.append(Finding(
                severity=CheckSeverity.INFO,
                title="Disconnection logging is disabled",
                description="Client disconnection events are not being logged.",
                recommendation="Enable log_disconnections to track session durations.",
                fix_sql="ALTER SYSTEM SET log_disconnections = 'on';",
                tags=["audit", "logging"],
            ))

        return result


class RowLevelSecurityCheck(AdvisorCheck):
    """Check for tables that might benefit from RLS."""

    name = "postgres_row_level_security"
    title = "Row-Level Security"
    description = "Identify tables with user columns that lack RLS"
    category = AdvisorCategory.SECURITY
    interval = CheckInterval.RARE

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        # Find tables with user_id/tenant_id columns that don't have RLS enabled
        try:
            rows = await conn.fetch(
                "SELECT c.relname AS table_name, "
                "       a.attname AS column_name, "
                "       c.relrowsecurity AS rls_enabled "
                "FROM pg_class c "
                "JOIN pg_attribute a ON a.attrelid = c.oid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' "
                "  AND c.relkind = 'r' "
                "  AND a.attname IN ('user_id', 'tenant_id', 'org_id', 'account_id') "
                "  AND NOT c.relrowsecurity "
                "  AND a.attnum > 0 "
                "ORDER BY c.relname"
            )
        except Exception:
            return result

        for row in rows:
            table = row[0] if isinstance(row, (list, tuple)) else getattr(row, "table_name", "")
            col = row[1] if isinstance(row, (list, tuple)) else getattr(row, "column_name", "")

            result.findings.append(Finding(
                severity=CheckSeverity.INFO,
                title=f"Table '{table}' has '{col}' but no RLS",
                description=f"Table '{table}' contains a multi-tenant column '{col}' but RLS is not enabled.",
                recommendation=f"Consider enabling RLS: ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;",
                fix_sql=f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;",
                tags=["multi-tenant", "rls"],
            ))

        return result


class ExtensionSecurityCheck(AdvisorCheck):
    """Audit installed extensions for security implications."""

    name = "postgres_extension_security"
    title = "Extension Security Audit"
    description = "Check for extensions with security implications"
    category = AdvisorCategory.SECURITY
    interval = CheckInterval.RARE

    RISKY_EXTENSIONS = {
        "adminpack": "Provides server-level admin functions (file I/O)",
        "file_fdw": "Allows reading server-side files via SQL",
        "dblink": "Allows connecting to other databases, potential for credential leakage",
    }

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        rows = await conn.fetch(
            "SELECT extname, extversion FROM pg_extension ORDER BY extname"
        )

        for row in rows:
            name = str(row[0] if isinstance(row, (list, tuple)) else getattr(row, "extname", ""))
            version = str(row[1] if isinstance(row, (list, tuple)) else getattr(row, "extversion", ""))

            if name in self.RISKY_EXTENSIONS:
                result.findings.append(Finding(
                    severity=CheckSeverity.NOTICE,
                    title=f"Extension '{name}' v{version} installed",
                    description=self.RISKY_EXTENSIONS[name],
                    recommendation=f"Ensure '{name}' is required. Remove if not needed: DROP EXTENSION {name};",
                    tags=["extensions", "attack-surface"],
                ))

        return result


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------


def get_security_checks() -> list[AdvisorCheck]:
    """Return all security advisor checks."""
    return [
        SSLEnabledCheck(),
        PasswordEncryptionCheck(),
        SuperuserAuditCheck(),
        TrustAuthenticationCheck(),
        LogConnectionsCheck(),
        RowLevelSecurityCheck(),
        ExtensionSecurityCheck(),
    ]
