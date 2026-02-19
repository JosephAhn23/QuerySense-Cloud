"""
QuerySense GitHub App — one-click install, automatic PR analysis.

A full GitHub App that:
- Installs with one click from the GitHub Marketplace
- Automatically analyzes SQL migration files in PRs
- Comments with findings, risk assessment, and fix suggestions
- Checks pass/fail based on configured policies

Architecture:
    GitHub webhook → FastAPI handler → MigrationAnalyzer + AnalysisService
    → PR comment + Check Run status

Setup:
    1. Create a GitHub App at https://github.com/settings/apps
    2. Set webhook URL to your QuerySense server
    3. Configure permissions: pull_requests (write), checks (write), contents (read)
    4. Set environment variables:
       - QUERYSENSE_GITHUB_APP_ID
       - QUERYSENSE_GITHUB_PRIVATE_KEY_PATH
       - QUERYSENSE_GITHUB_WEBHOOK_SECRET

Usage:
    from querysense.github_app import create_github_app_routes

    app = FastAPI()
    create_github_app_routes(app)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── GitHub App Configuration ───────────────────────────────────────────────


@dataclass
class GitHubAppConfig:
    """Configuration for the GitHub App."""

    app_id: str = ""
    private_key_path: str = ""
    webhook_secret: str = ""
    api_base_url: str = "https://api.github.com"

    # Analysis settings
    fail_on_critical: bool = True
    fail_on_high_risk: bool = True
    comment_on_clean: bool = False  # Comment even when no issues found
    analyze_sql_files: bool = True
    analyze_migration_files: bool = True

    # File patterns to analyze
    migration_patterns: tuple[str, ...] = (
        "*.sql",
        "migrations/**/*.sql",
        "db/migrate/**/*.sql",
        "db/changelog/**/*.sql",
        "db/changelog/**/*.yaml",
        "db/changelog/**/*.yml",
        "alembic/versions/**/*.py",
    )


# ── JWT Authentication ─────────────────────────────────────────────────────


def _generate_jwt(app_id: str, private_key_pem: str) -> str:
    """Generate a GitHub App JWT for authentication."""
    try:
        import jwt
    except ImportError:
        raise ImportError("PyJWT required for GitHub App: pip install PyJWT cryptography")

    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),  # 10 minutes
        "iss": app_id,
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def _get_installation_token(
    app_id: str,
    private_key_pem: str,
    installation_id: int,
    api_base: str = "https://api.github.com",
) -> str:
    """Exchange a JWT for an installation access token."""
    import urllib.request

    jwt_token = _generate_jwt(app_id, private_key_pem)

    url = f"{api_base}/app/installations/{installation_id}/access_tokens"
    req = urllib.request.Request(
        url,
        data=b"{}",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())
        return data["token"]


# ── Webhook Verification ──────────────────────────────────────────────────


def verify_webhook_signature(
    payload: bytes,
    signature: str,
    secret: str,
) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not signature.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


# ── PR Analysis ────────────────────────────────────────────────────────────


@dataclass
class PRAnalysisResult:
    """Result of analyzing a PR's database changes."""

    repo: str
    pr_number: int
    files_analyzed: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    migration_risk: str = "low"
    file_results: list[dict[str, Any]] = field(default_factory=list)
    check_conclusion: str = "success"  # success, failure, neutral
    comment_body: str = ""

    @property
    def should_fail(self) -> bool:
        return self.check_conclusion == "failure"


def analyze_pr_files(
    changed_files: list[dict[str, Any]],
    config: GitHubAppConfig,
) -> PRAnalysisResult:
    """
    Analyze changed files in a PR for database performance issues.

    Args:
        changed_files: List of file dicts from GitHub API (filename, patch, etc.)
        config: GitHub App configuration

    Returns:
        PRAnalysisResult with findings and comment body
    """
    import fnmatch

    result = PRAnalysisResult(repo="", pr_number=0)
    sql_files: list[dict[str, Any]] = []

    # Filter to migration/SQL files
    for f in changed_files:
        filename = f.get("filename", "")
        for pattern in config.migration_patterns:
            if fnmatch.fnmatch(filename, pattern):
                sql_files.append(f)
                break

    if not sql_files:
        result.comment_body = ""  # No SQL files, no comment
        return result

    result.files_analyzed = len(sql_files)

    # Analyze each file
    from querysense.migration import MigrationAnalyzer

    analyzer = MigrationAnalyzer()

    for f in sql_files:
        filename = f.get("filename", "")
        patch = f.get("patch", "")

        # Extract SQL from patch (added lines only)
        sql_lines = []
        for line in patch.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                sql_lines.append(line[1:])

        sql_content = "\n".join(sql_lines)
        if not sql_content.strip():
            continue

        try:
            report = analyzer.analyze(sql_content)
            file_result = {
                "filename": filename,
                "risk": report.overall_risk.value,
                "statements": len(report.statements),
                "warnings": report.warnings,
                "lock_analyses": [
                    {
                        "lock_level": la.lock_level.value,
                        "blocks_reads": la.blocks_reads,
                        "blocks_writes": la.blocks_writes,
                        "estimated_duration_ms": la.estimated_duration_ms,
                        "recommendation": la.recommendation,
                    }
                    for la in report.lock_analyses
                ],
                "rollback_available": bool(report.rollback_sql),
                "rollback_sql": report.rollback_sql,
            }
            result.file_results.append(file_result)

            for la in report.lock_analyses:
                result.total_findings += 1
                if la.blocks_reads:
                    result.critical_findings += 1

            if report.overall_risk.value in ("high", "critical"):
                result.migration_risk = report.overall_risk.value

        except Exception as e:
            logger.warning("Failed to analyze %s: %s", filename, e)
            result.file_results.append({
                "filename": filename,
                "error": str(e),
            })

    # Determine check conclusion
    if config.fail_on_critical and result.critical_findings > 0:
        result.check_conclusion = "failure"
    elif config.fail_on_high_risk and result.migration_risk in ("high", "critical"):
        result.check_conclusion = "failure"
    else:
        result.check_conclusion = "success"

    # Build comment
    result.comment_body = _build_pr_comment(result)
    return result


def _build_pr_comment(result: PRAnalysisResult) -> str:
    """Build a formatted PR comment from analysis results."""
    lines: list[str] = []

    # Header
    if result.check_conclusion == "failure":
        lines.append("## :warning: QuerySense Migration Analysis — Issues Found")
    elif result.total_findings > 0:
        lines.append("## :mag: QuerySense Migration Analysis")
    else:
        lines.append("## :white_check_mark: QuerySense Migration Analysis — Clean")

    lines.append("")
    lines.append(
        f"Analyzed **{result.files_analyzed}** file(s) | "
        f"**{result.total_findings}** finding(s) | "
        f"Risk: **{result.migration_risk.upper()}**"
    )
    lines.append("")

    # File details
    for fr in result.file_results:
        filename = fr.get("filename", "unknown")
        error = fr.get("error")

        if error:
            lines.append(f"### `{filename}` :x:")
            lines.append(f"Analysis error: {error}")
            lines.append("")
            continue

        risk = fr.get("risk", "low").upper()
        risk_icon = {
            "LOW": ":white_check_mark:",
            "MEDIUM": ":warning:",
            "HIGH": ":rotating_light:",
            "CRITICAL": ":no_entry:",
        }.get(risk, ":question:")

        lines.append(f"### `{filename}` {risk_icon} {risk}")
        lines.append("")

        # Lock analysis
        for la in fr.get("lock_analyses", []):
            lock_level = la.get("lock_level", "unknown")
            blocks_icon = ":no_entry:" if la.get("blocks_reads") else (
                ":warning:" if la.get("blocks_writes") else ":white_check_mark:"
            )
            dur_ms = la.get("estimated_duration_ms")
            dur_str = f" (~{dur_ms:.0f}ms)" if dur_ms and dur_ms < 1000 else (
                f" (~{dur_ms / 1000:.1f}s)" if dur_ms else ""
            )
            lines.append(f"- {blocks_icon} **{lock_level}**{dur_str}")
            if la.get("recommendation"):
                lines.append(f"  - {la['recommendation']}")

        # Warnings
        for w in fr.get("warnings", []):
            lines.append(f"- :exclamation: {w}")

        # Rollback
        if fr.get("rollback_available"):
            lines.append("")
            lines.append("<details><summary>Rollback SQL</summary>")
            lines.append("")
            lines.append("```sql")
            for sql in fr.get("rollback_sql", []):
                lines.append(sql)
            lines.append("```")
            lines.append("</details>")

        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Analyzed by [QuerySense](https://github.com/JosephAhn23/Query-Sense) — free, offline database performance analyzer*")

    return "\n".join(lines)


# ── FastAPI Route Registration ─────────────────────────────────────────────


def create_github_app_routes(app: Any, config: GitHubAppConfig | None = None) -> None:
    """
    Register GitHub App webhook routes on a FastAPI app.

    Routes:
        POST /github/webhook — Receive GitHub webhook events
        GET  /github/install — Redirect to GitHub App installation
        GET  /github/callback — Handle post-installation callback
    """
    import os

    config = config or GitHubAppConfig(
        app_id=os.environ.get("QUERYSENSE_GITHUB_APP_ID", ""),
        private_key_path=os.environ.get("QUERYSENSE_GITHUB_PRIVATE_KEY_PATH", ""),
        webhook_secret=os.environ.get("QUERYSENSE_GITHUB_WEBHOOK_SECRET", ""),
    )

    try:
        from fastapi import Request, Response
        from fastapi.responses import JSONResponse, RedirectResponse
    except ImportError:
        logger.warning("FastAPI not installed — GitHub App routes not registered")
        return

    @app.post("/github/webhook")
    async def github_webhook(request: Request) -> Response:
        """Handle GitHub webhook events."""
        body = await request.body()

        # Verify signature
        signature = request.headers.get("X-Hub-Signature-256", "")
        if config.webhook_secret:
            if not verify_webhook_signature(body, signature, config.webhook_secret):
                return JSONResponse(
                    {"error": "Invalid signature"}, status_code=401
                )

        event = request.headers.get("X-GitHub-Event", "")
        payload = json.loads(body)

        if event == "pull_request":
            action = payload.get("action", "")
            if action in ("opened", "synchronize", "reopened"):
                # Analyze PR
                await _handle_pr_event(payload, config)

        elif event == "installation":
            action = payload.get("action", "")
            logger.info(
                "GitHub App %s: installation %s",
                action, payload.get("installation", {}).get("id"),
            )

        return JSONResponse({"status": "ok"})

    @app.get("/github/install")
    async def github_install() -> Response:
        """Redirect to GitHub App installation page."""
        if config.app_id:
            return RedirectResponse(
                f"https://github.com/apps/querysense/installations/new"
            )
        return JSONResponse(
            {"error": "GitHub App not configured"}, status_code=503
        )

    @app.get("/github/callback")
    async def github_callback(
        installation_id: int = 0,
        setup_action: str = "",
    ) -> Response:
        """Handle post-installation callback."""
        return JSONResponse({
            "status": "installed",
            "installation_id": installation_id,
            "message": "QuerySense GitHub App installed successfully!",
        })


async def _handle_pr_event(
    payload: dict[str, Any],
    config: GitHubAppConfig,
) -> None:
    """Handle a pull_request webhook event."""
    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {}).get("full_name", "")
    pr_number = pr.get("number", 0)
    installation_id = payload.get("installation", {}).get("id", 0)

    logger.info("Analyzing PR #%d on %s", pr_number, repo)

    # Get installation token
    private_key = ""
    if config.private_key_path:
        key_path = Path(config.private_key_path)
        if key_path.exists():
            private_key = key_path.read_text()

    if not private_key or not config.app_id:
        logger.warning("GitHub App credentials not configured — skipping analysis")
        return

    try:
        token = _get_installation_token(
            config.app_id, private_key, installation_id
        )
    except Exception as e:
        logger.error("Failed to get installation token: %s", e)
        return

    # Fetch changed files
    changed_files = _fetch_pr_files(token, repo, pr_number)
    if not changed_files:
        return

    # Analyze
    result = analyze_pr_files(changed_files, config)
    result.repo = repo
    result.pr_number = pr_number

    if not result.comment_body and not config.comment_on_clean:
        return

    # Post comment
    if result.comment_body:
        _post_comment(token, repo, pr_number, result.comment_body)

    # Create check run
    _create_check_run(token, repo, pr.get("head", {}).get("sha", ""), result)


def _fetch_pr_files(token: str, repo: str, pr_number: int) -> list[dict[str, Any]]:
    """Fetch changed files for a PR."""
    import urllib.request

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.error("Failed to fetch PR files: %s", e)
        return []


def _post_comment(token: str, repo: str, pr_number: int, body: str) -> None:
    """Post a comment on a PR."""
    import urllib.request

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode()

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            logger.info("Posted comment on PR #%d (%d)", pr_number, resp.status)
    except Exception as e:
        logger.error("Failed to post PR comment: %s", e)


def _create_check_run(
    token: str,
    repo: str,
    head_sha: str,
    result: PRAnalysisResult,
) -> None:
    """Create a GitHub Check Run with analysis results."""
    import urllib.request

    url = f"https://api.github.com/repos/{repo}/check-runs"

    summary = (
        f"Analyzed {result.files_analyzed} file(s): "
        f"{result.total_findings} finding(s), "
        f"risk level {result.migration_risk.upper()}"
    )

    data = json.dumps({
        "name": "QuerySense Migration Analysis",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": result.check_conclusion,
        "output": {
            "title": "QuerySense Migration Analysis",
            "summary": summary,
            "text": result.comment_body,
        },
    }).encode()

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            logger.info("Created check run on %s (%d)", head_sha[:8], resp.status)
    except Exception as e:
        logger.error("Failed to create check run: %s", e)
