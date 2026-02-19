"""
Scan for PostgreSQL security vulnerabilities (CVE database).

Based on CVE-2024-4317 (pg_stats_ext information leak) and the pganalyze
security disclosure guidance. Runs detection queries and generates fix
instructions across all databases including templates.

Usage:
    from querysense.security.cve_scanner import CVEScanner

    scanner = CVEScanner(conn)
    result = await scanner.scan()
    for vuln in result.vulnerabilities:
        print(vuln.cve_id, vuln.severity, vuln.title)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Vulnerability:
    """Detected security vulnerability."""
    cve_id: str
    title: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    affected_versions: List[str]
    fixed_versions: List[str]
    requires_user_action: bool
    detection_query: str
    fix_command: Optional[str]
    verified: bool = False


@dataclass
class CVEScanResult:
    """Result of a CVE scan."""
    postgres_version: str
    vulnerabilities: List[Vulnerability]
    patched: bool
    needs_manual_fix: bool
    recommendations: List[str]


# ── CVE Database ─────────────────────────────────────────────────────────

CVE_DATABASE: dict[str, dict[str, Any]] = {
    "CVE-2024-4317": {
        "title": "pg_stats_ext and pg_stats_ext_exprs information leak",
        "description": (
            "Extended statistics on expressions leak MCV data to "
            "unprivileged users via pg_stats_ext / pg_stats_ext_exprs views"
        ),
        "severity": "medium",
        "affected_versions": ["12", "13", "14", "15", "16"],
        "fixed_versions": ["12.19", "13.15", "14.12", "15.7", "16.3"],
        "requires_user_action": True,
        "detection": (
            "SELECT COUNT(*) FROM pg_views "
            "WHERE viewname = 'pg_stats_ext' "
            "AND definition NOT LIKE '%pg_has_role%'"
        ),
        "fix_instructions": (
            "For each database (including template0 and template1):\n"
            "  \\i /usr/share/postgresql/{version}/fix-CVE-2024-4317.sql\n"
            "\n"
            "For template0, temporarily enable connections:\n"
            "  ALTER DATABASE template0 WITH ALLOW_CONNECTIONS true;\n"
            "  -- connect and run fix, then:\n"
            "  ALTER DATABASE template0 WITH ALLOW_CONNECTIONS false;"
        ),
    },
    "CVE-2024-0985": {
        "title": "REFRESH MATERIALIZED VIEW CONCURRENTLY privilege escalation",
        "description": (
            "Late privilege check in REFRESH MATERIALIZED VIEW CONCURRENTLY "
            "allows an attacker to execute arbitrary SQL as the materialized "
            "view owner"
        ),
        "severity": "high",
        "affected_versions": ["12", "13", "14", "15", "16"],
        "fixed_versions": ["12.18", "13.14", "14.11", "15.6", "16.2"],
        "requires_user_action": False,
        "detection": None,
        "fix_instructions": "Upgrade to a patched minor release.",
    },
}


# ── Scanner ──────────────────────────────────────────────────────────────


class CVEScanner:
    """
    Scan a PostgreSQL connection for known CVEs.
    Works with both asyncpg and psycopg-style connections (duck-typed).
    """

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    # -- public API -------------------------------------------------------

    async def scan(self) -> CVEScanResult:
        version_str = await self._fetchval("SELECT version()")
        version_num = self._parse_version(version_str)

        vulnerabilities: list[Vulnerability] = []
        patched = True
        needs_manual = False
        recommendations: list[str] = []

        for cve_id, info in CVE_DATABASE.items():
            if not self._is_affected(version_num, info):
                continue

            patched = False

            if info.get("requires_user_action"):
                is_fixed = await self._check_patch_status(info)
                if not is_fixed:
                    vuln = self._build_vulnerability(cve_id, info, version_num)
                    vulnerabilities.append(vuln)
                    needs_manual = True
                    recommendations.extend(
                        self._recommendations(cve_id, version_num)
                    )
            else:
                vuln = self._build_vulnerability(cve_id, info, version_num)
                vulnerabilities.append(vuln)
                recommendations.append(
                    f"{cve_id}: {info.get('fix_instructions', 'Upgrade to patched release.')}"
                )

        return CVEScanResult(
            postgres_version=version_str,
            vulnerabilities=vulnerabilities,
            patched=len(vulnerabilities) == 0,
            needs_manual_fix=needs_manual,
            recommendations=recommendations,
        )

    async def verify_cve_2024_4317(self) -> dict[str, Any]:
        """Check whether CVE-2024-4317 fix has been applied."""
        row = await self._fetchval(
            "SELECT definition FROM pg_views WHERE viewname = 'pg_stats_ext'"
        )
        if row is None:
            return {"fixed": False, "error": "View pg_stats_ext not found"}
        if "pg_has_role" in str(row):
            return {"fixed": True, "note": "pg_stats_ext includes pg_has_role check"}
        return {"fixed": False, "current_definition": str(row)[:300]}

    # -- helpers ----------------------------------------------------------

    async def _fetchval(self, sql: str) -> Any:
        """Duck-typed single-value fetch."""
        if hasattr(self._conn, "fetchval"):
            return await self._conn.fetchval(sql)
        if hasattr(self._conn, "fetchrow"):
            row = await self._conn.fetchrow(sql)
            return row[0] if row else None
        row = await self._conn.fetch(sql)
        return row[0][0] if row else None

    @staticmethod
    def _parse_version(version_str: str) -> str:
        m = re.search(r"PostgreSQL (\d+\.\d+)", str(version_str))
        return m.group(1) if m else "unknown"

    @staticmethod
    def _is_affected(version: str, info: dict) -> bool:
        if version == "unknown":
            return False
        major = version.split(".")[0]
        if major not in info["affected_versions"]:
            return False
        for fixed in info["fixed_versions"]:
            if fixed.startswith(major + ".") and version >= fixed:
                return False
        return True

    async def _check_patch_status(self, info: dict) -> bool:
        detection = info.get("detection")
        if not detection:
            return False
        try:
            result = await self._fetchval(detection)
            return result == 0
        except Exception:
            return False

    @staticmethod
    def _build_vulnerability(
        cve_id: str, info: dict, version: str
    ) -> Vulnerability:
        major = version.split(".")[0]
        fix_cmd = info.get("fix_instructions", "").replace("{version}", major)
        return Vulnerability(
            cve_id=cve_id,
            title=info["title"],
            description=info["description"],
            severity=info["severity"],
            affected_versions=info["affected_versions"],
            fixed_versions=info["fixed_versions"],
            requires_user_action=info.get("requires_user_action", False),
            detection_query=info.get("detection", ""),
            fix_command=fix_cmd or None,
        )

    @staticmethod
    def _recommendations(cve_id: str, version: str) -> list[str]:
        major = version.split(".")[0]
        if cve_id == "CVE-2024-4317":
            return [
                f"Run the fix script on ALL databases:",
                f"  psql -d postgres -f /usr/share/postgresql/{major}/fix-CVE-2024-4317.sql",
                "  For template0: ALTER DATABASE template0 WITH ALLOW_CONNECTIONS true;",
                "  Run fix on template0, then disable connections again",
                "  Repeat for template1",
                "  Verify: check that pg_stats_ext definition includes 'pg_has_role'",
            ]
        return []


# ── Offline (no-connection) helpers ──────────────────────────────────────


def offline_check(pg_version: str) -> CVEScanResult:
    """
    Check CVEs without a live connection (version string only).
    Useful for CI pipelines where you know the server version.
    """
    version_num = CVEScanner._parse_version(f"PostgreSQL {pg_version}")
    vulns: list[Vulnerability] = []
    recs: list[str] = []

    for cve_id, info in CVE_DATABASE.items():
        if CVEScanner._is_affected(version_num, info):
            vulns.append(CVEScanner._build_vulnerability(cve_id, info, version_num))
            recs.append(
                f"{cve_id} ({info['severity']}): {info['title']} - "
                f"fixed in {', '.join(info['fixed_versions'])}"
            )

    return CVEScanResult(
        postgres_version=pg_version,
        vulnerabilities=vulns,
        patched=len(vulns) == 0,
        needs_manual_fix=any(v.requires_user_action for v in vulns),
        recommendations=recs,
    )
