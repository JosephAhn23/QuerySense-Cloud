"""
GitHub PR comment command: post migration analysis as PR comments.

    $ querysense comment-pr --report report.json --github-token $GITHUB_TOKEN
    $ querysense comment-pr --migration migrations/001.sql --github-token $GITHUB_TOKEN
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register comment-pr command."""

    @app.command(name="comment-pr")
    def comment_pr(
        report_file: Annotated[
            Optional[Path],
            typer.Option(
                "--report", "-r",
                help="Path to QuerySense migration report JSON",
            ),
        ] = None,
        migration_file: Annotated[
            Optional[Path],
            typer.Option(
                "--migration", "-m",
                help="Migration SQL file to analyze and comment on",
            ),
        ] = None,
        github_token: Annotated[
            Optional[str],
            typer.Option(
                "--github-token",
                envvar="GITHUB_TOKEN",
                help="GitHub API token",
            ),
        ] = None,
        repo: Annotated[
            Optional[str],
            typer.Option(
                "--repo",
                envvar="GITHUB_REPOSITORY",
                help="GitHub repository (owner/repo)",
            ),
        ] = None,
        pr_number: Annotated[
            Optional[int],
            typer.Option(
                "--pr",
                help="PR number (auto-detected in GitHub Actions)",
            ),
        ] = None,
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Print comment without posting"),
        ] = False,
    ) -> None:
        """
        Post migration analysis as a GitHub PR comment.

        Can use a pre-generated report JSON or analyze a migration file on the fly.

        Examples:

            $ querysense comment-pr --migration migrations/001.sql --dry-run
            $ querysense comment-pr --report report.json --github-token $GITHUB_TOKEN
        """
        # Get or generate report
        if report_file:
            if not report_file.exists():
                error_console.print(f"[red]Error:[/red] Report not found: {report_file}")
                raise typer.Exit(code=1)

            report_data = json.loads(report_file.read_text(encoding="utf-8"))
            comment_body = _format_comment_from_json(report_data, report_file.name)

        elif migration_file:
            if not migration_file.exists():
                error_console.print(f"[red]Error:[/red] Migration not found: {migration_file}")
                raise typer.Exit(code=1)

            migration_sql = migration_file.read_text(encoding="utf-8")
            from querysense.migration import MigrationAnalyzer

            analyzer = MigrationAnalyzer()
            report = analyzer.analyze(migration_sql)
            comment_body = report.format_pr_comment()

            # Add filename header
            comment_body = (
                f"## QuerySense Migration Analysis\n\n"
                f"**File:** `{migration_file.name}`\n\n"
                + comment_body.split("\n", 2)[-1]  # Skip duplicate header
            )
        else:
            error_console.print(
                "[red]Error:[/red] Provide --report or --migration"
            )
            raise typer.Exit(code=1)

        if dry_run:
            console.print("[cyan][DRY RUN] Would post this PR comment:[/cyan]\n")
            console.print(comment_body)
            return

        # Post to GitHub
        if not github_token:
            error_console.print(
                "[red]Error:[/red] --github-token required (or set GITHUB_TOKEN)"
            )
            raise typer.Exit(code=1)

        # Auto-detect PR info from GitHub Actions environment
        if not repo:
            repo = os.environ.get("GITHUB_REPOSITORY")
        if not pr_number:
            pr_number = _detect_pr_number()

        if not repo or not pr_number:
            error_console.print(
                "[red]Error:[/red] Could not detect repo/PR. "
                "Provide --repo and --pr, or run in GitHub Actions."
            )
            raise typer.Exit(code=1)

        _post_pr_comment(
            token=github_token,
            repo=repo,
            pr_number=pr_number,
            body=comment_body,
        )

        console.print(
            f"[green]Comment posted to PR #{pr_number}[/green]"
        )


def _format_comment_from_json(data: dict, filename: str) -> str:
    """Format a PR comment from a JSON report."""
    lines: list[str] = []
    lines.append("## QuerySense Migration Analysis")
    lines.append("")
    lines.append(f"**File:** `{filename}`")

    risk = data.get("overall_risk", "unknown").upper()
    risk_icon = {
        "LOW": "OK", "MEDIUM": "Warning", "HIGH": "DANGER", "CRITICAL": "CRITICAL",
    }.get(risk, "?")
    lines.append(f"**Risk:** {risk_icon} {risk}")
    lines.append("")

    # Lock analyses
    locks = data.get("lock_analyses", [])
    if locks:
        lines.append("### Lock Analysis")
        for la in locks:
            icon = "!!!" if la.get("blocks_reads") else ("!!" if la.get("blocks_writes") else "OK")
            dur = ""
            ms = la.get("estimated_duration_ms")
            if ms:
                dur = f" (~{ms:.0f}ms)" if ms < 1000 else f" (~{ms / 1000:.1f}s)"
            lines.append(f"- **{icon}** {la.get('lock_level', '?')}{dur}")
            if la.get("recommendation"):
                lines.append(f"  - {la['recommendation']}")
        lines.append("")

    # Performance impacts
    perfs = data.get("performance_impacts", [])
    if perfs:
        lines.append("### Performance Impact")
        for pi in perfs:
            sev = pi.get("severity", "?").upper()
            lines.append(f"- **{sev}** {pi.get('description', '')}")
            if pi.get("recommendation"):
                lines.append(f"  - {pi['recommendation']}")
        lines.append("")

    # Rollback
    rollbacks = data.get("rollback_sql", [])
    if rollbacks:
        lines.append("### Rollback Available")
        lines.append("```sql")
        for r in rollbacks:
            lines.append(r)
        lines.append("```")
        lines.append("")

    # Warnings
    warnings = data.get("warnings", [])
    if warnings:
        lines.append("### Warnings")
        for w in warnings:
            lines.append(f"- {w}")

    return "\n".join(lines)


def _detect_pr_number() -> int | None:
    """Auto-detect PR number from GitHub Actions environment."""
    # GITHUB_REF format: refs/pull/123/merge
    ref = os.environ.get("GITHUB_REF", "")
    if "/pull/" in ref:
        parts = ref.split("/")
        try:
            idx = parts.index("pull")
            return int(parts[idx + 1])
        except (ValueError, IndexError):
            pass

    # GITHUB_EVENT_PATH contains the event payload
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            event = json.loads(Path(event_path).read_text())
            pr = event.get("pull_request", {})
            if pr:
                return pr.get("number")
        except Exception:
            pass

    return None


def _post_pr_comment(
    *,
    token: str,
    repo: str,
    pr_number: int,
    body: str,
) -> None:
    """Post a comment to a GitHub PR via the REST API."""
    import urllib.request
    import urllib.error

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "QuerySense-Migration-Analyzer",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status not in (200, 201):
                raise RuntimeError(f"GitHub API returned {resp.status}")
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API error {e.code}: {body_text}") from e
