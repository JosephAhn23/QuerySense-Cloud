"""
GitOps PR review command: auto-analyze migrations and comment on PRs.

Beats Harness (enterprise complexity) by working out of the box.
Beats Liquibase/Flyway by being free and CI-native.

    $ querysense pr review --repo owner/repo --pr 42 --github-token $GITHUB_TOKEN
    $ querysense pr review --migration-dir migrations/ --pr 42
    $ querysense pr create-fix --pr 42 --migration migration.sql
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register PR subcommands."""

    @app.command()
    def review(
        pr_number: Annotated[
            int,
            typer.Option("--pr", "-p", help="Pull request number"),
        ],
        repo: Annotated[
            Optional[str],
            typer.Option(
                "--repo", "-r",
                help="GitHub repo (owner/name). Auto-detected from git remote.",
                envvar="GITHUB_REPOSITORY",
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
        migration_dir: Annotated[
            str,
            typer.Option(
                "--migration-dir", "-d",
                help="Directory containing migration SQL files",
            ),
        ] = "migrations",
        fail_on: Annotated[
            str,
            typer.Option(
                "--fail-on",
                help="Exit non-zero on: critical, warning, any",
            ),
        ] = "critical",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON for CI"),
        ] = False,
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Analyze without posting comment"),
        ] = False,
    ) -> None:
        """
        Analyze PR migrations and post review comment.

        Auto-detects migration files changed in a PR, runs safety analysis,
        generates rollback SQL, and posts a detailed review comment.

        Works in GitHub Actions automatically with GITHUB_TOKEN and
        GITHUB_REPOSITORY environment variables.

        \\b
        Examples:
            # In GitHub Actions (auto-detects repo and token)
            $ querysense pr review --pr ${{ github.event.pull_request.number }}

            # Manual run
            $ querysense pr review --pr 42 --repo owner/repo --github-token ghp_xxx

            # Analyze specific directory
            $ querysense pr review --pr 42 --migration-dir db/migrations

            # CI mode: fail on critical, output JSON
            $ querysense pr review --pr 42 --fail-on critical --json
        """
        from querysense.migration_safety import check_and_report
        from querysense.rollback import generate_smart_rollback

        # Auto-detect repo from git remote
        if not repo:
            repo = _detect_github_repo()
            if not repo:
                error_console.print(
                    "[red]Error:[/red] Could not detect GitHub repo. "
                    "Use --repo owner/name or set GITHUB_REPOSITORY."
                )
                raise typer.Exit(code=1)

        # Find changed migration files
        migration_files = _find_changed_migrations(migration_dir)
        if not migration_files:
            console.print("[green]No migration files changed in this PR.[/green]")
            return

        console.print(
            f"[bold]Analyzing {len(migration_files)} migration file(s)...[/bold]"
        )

        # Analyze each migration
        results: list[dict] = []
        has_critical = False
        has_warning = False

        for mf in migration_files:
            sql = mf.read_text(encoding="utf-8")
            report = check_and_report(sql)
            rollback_plan = generate_smart_rollback(sql)

            result = {
                "file": str(mf),
                "statements": len(report.statements),
                "safe": report.safe,
                "risks": [
                    {
                        "severity": r.severity,
                        "rule": r.rule,
                        "message": r.message,
                        "suggestion": r.suggestion,
                    }
                    for r in report.risks
                ],
                "rollback_safe": rollback_plan.is_safe,
                "rollback_statements": len(rollback_plan.rollback_statements),
                "irreversible": len(rollback_plan.irreversible_statements),
                "warnings": rollback_plan.warnings,
            }
            results.append(result)

            if report.has_critical:
                has_critical = True
            if any(r.severity == "warning" for r in report.risks):
                has_warning = True

        # JSON output
        if json_output:
            data = {
                "pr": pr_number,
                "repo": repo,
                "migrations_analyzed": len(results),
                "verdict": "FAIL" if has_critical else ("WARN" if has_warning else "PASS"),
                "results": results,
            }
            console.print_json(json.dumps(data, default=str))
        else:
            # Pretty output
            for result in results:
                status = "SAFE" if result["safe"] else "UNSAFE"
                color = "green" if result["safe"] else "red"
                console.print(Panel(
                    f"[{color} bold]{status}[/{color} bold] — "
                    f"{result['statements']} statement(s), "
                    f"{len(result['risks'])} risk(s)\n"
                    f"Rollback: {'✓ Safe' if result['rollback_safe'] else '⚠ ' + str(result['irreversible']) + ' manual step(s)'}",
                    title=f"[bold]{result['file']}[/bold]",
                    border_style=color,
                ))

                if result["risks"]:
                    risk_table = Table()
                    risk_table.add_column("Severity", width=8)
                    risk_table.add_column("Rule")
                    risk_table.add_column("Fix", max_width=40, style="dim")
                    for risk in result["risks"]:
                        sev_style = {
                            "critical": "[red]CRIT[/red]",
                            "warning": "[yellow]WARN[/yellow]",
                            "info": "[blue]INFO[/blue]",
                        }
                        risk_table.add_row(
                            sev_style.get(risk["severity"], risk["severity"]),
                            risk["rule"],
                            risk["suggestion"],
                        )
                    console.print(risk_table)

        # Post PR comment
        if not dry_run and github_token:
            comment_body = _build_pr_comment(results, pr_number)
            success = _post_github_comment(
                repo, pr_number, comment_body, github_token
            )
            if success:
                console.print(
                    f"[green]Posted review comment on PR #{pr_number}[/green]"
                )
            else:
                error_console.print("[red]Failed to post PR comment[/red]")
        elif dry_run:
            console.print("[dim]Dry run: skipping PR comment[/dim]")
        elif not github_token:
            console.print(
                "[dim]No GitHub token provided; skipping PR comment. "
                "Set GITHUB_TOKEN to enable.[/dim]"
            )

        # Exit code
        should_fail = (
            (fail_on == "critical" and has_critical)
            or (fail_on == "warning" and (has_critical or has_warning))
            or (fail_on == "any" and results and any(r["risks"] for r in results))
        )
        if should_fail:
            raise typer.Exit(code=1)

    @app.command(name="create-fix")
    def create_fix(
        pr_number: Annotated[
            int,
            typer.Option("--pr", "-p", help="Pull request number to fix"),
        ],
        migration: Annotated[
            Path,
            typer.Option(
                "--migration", "-m",
                help="Migration file to generate fix for",
                exists=True,
                readable=True,
            ),
        ],
        repo: Annotated[
            Optional[str],
            typer.Option(
                "--repo", "-r",
                help="GitHub repo (owner/name)",
                envvar="GITHUB_REPOSITORY",
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
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Show fix without creating branch/PR"),
        ] = False,
    ) -> None:
        """
        Auto-generate a fix PR for migration issues.

        Analyzes the migration, identifies fixable issues (missing
        CONCURRENTLY, missing NOT VALID, missing lock_timeout), and
        creates a new commit with the fixed migration.

        \\b
        Examples:
            # Preview fix
            $ querysense pr create-fix --pr 42 --migration migration.sql --dry-run

            # Create fix PR
            $ querysense pr create-fix --pr 42 --migration migration.sql
        """
        from querysense.migration_safety import check_and_report

        sql = migration.read_text(encoding="utf-8")
        report = check_and_report(sql)

        if not report.risks:
            console.print("[green]No issues to fix![/green]")
            return

        # Auto-fix known patterns
        fixed_sql = _auto_fix_migration(sql, report.risks)

        if fixed_sql == sql:
            console.print("[yellow]No auto-fixable issues found.[/yellow]")
            console.print(
                "[dim]Manual fixes needed for: "
                + ", ".join(r.rule for r in report.risks)
                + "[/dim]"
            )
            return

        # Show diff
        console.print("[bold]Proposed Fix:[/bold]\n")

        import difflib
        diff = difflib.unified_diff(
            sql.splitlines(keepends=True),
            fixed_sql.splitlines(keepends=True),
            fromfile=f"a/{migration.name}",
            tofile=f"b/{migration.name}",
        )
        diff_text = "".join(diff)

        for line in diff_text.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                console.print(f"[green]{line}[/green]")
            elif line.startswith("-") and not line.startswith("---"):
                console.print(f"[red]{line}[/red]")
            else:
                console.print(line)

        # Re-check
        new_report = check_and_report(fixed_sql)
        fixed_count = len(report.risks) - len(new_report.risks)
        console.print(
            f"\n[bold]Result: Fixed {fixed_count}/{len(report.risks)} issue(s)[/bold]"
        )

        if dry_run:
            console.print("[dim]Dry run: not creating branch or PR[/dim]")
            return

        if not github_token:
            console.print(
                "[dim]Set GITHUB_TOKEN to auto-create fix PR[/dim]"
            )
            # Just write the fix locally
            migration.write_text(fixed_sql, encoding="utf-8")
            console.print(f"[green]Fixed migration written to {migration}[/green]")
            return

        # Create fix branch and PR
        if not repo:
            repo = _detect_github_repo()

        branch_name = f"querysense/fix-migration-pr-{pr_number}"
        try:
            subprocess.run(
                ["git", "checkout", "-b", branch_name],
                check=True, capture_output=True,
            )
            migration.write_text(fixed_sql, encoding="utf-8")
            subprocess.run(
                ["git", "add", str(migration)],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-m",
                 f"fix(migration): auto-fix {fixed_count} issue(s) in {migration.name}\n\n"
                 f"Fixed by QuerySense auto-fix engine.\n"
                 f"Issues resolved: {', '.join(r.rule for r in report.risks[:fixed_count])}"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "push", "-u", "origin", branch_name],
                check=True, capture_output=True,
            )
            console.print(f"[green]Created branch {branch_name}[/green]")
            console.print(
                f"[dim]Create PR manually or use gh: "
                f"gh pr create --base main --head {branch_name}[/dim]"
            )
        except subprocess.CalledProcessError as exc:
            error_console.print(f"[red]Git error: {exc.stderr.decode()[:200]}[/red]")


def _detect_github_repo() -> str | None:
    """Detect GitHub repo from git remote URL."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, check=True,
        )
        url = result.stdout.strip()
        # Parse GitHub URL
        match = re.search(r"github\.com[:/](.+?)(?:\.git)?$", url)
        if match:
            return match.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None


def _find_changed_migrations(migration_dir: str) -> list[Path]:
    """Find migration files changed in current PR/branch."""
    migration_path = Path(migration_dir)

    # Try git diff against main/master
    for base in ("main", "master", "develop"):
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", f"origin/{base}...HEAD"],
                capture_output=True, text=True, check=True,
            )
            changed = result.stdout.strip().splitlines()
            sql_files = [
                Path(f) for f in changed
                if f.endswith(".sql") and Path(f).exists()
            ]
            if sql_files:
                return sql_files
        except subprocess.CalledProcessError:
            continue

    # Fallback: scan migration directory for SQL files
    if migration_path.exists():
        return sorted(migration_path.glob("*.sql"))

    return []


def _auto_fix_migration(sql: str, risks: list) -> str:
    """Apply auto-fixes for known migration anti-patterns."""
    fixed = sql

    for risk in risks:
        if risk.rule == "INDEX_WITHOUT_CONCURRENTLY":
            # Add CONCURRENTLY to CREATE INDEX
            fixed = re.sub(
                r"CREATE\s+(UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)",
                r"CREATE \1INDEX CONCURRENTLY ",
                fixed,
                flags=re.IGNORECASE,
            )

        elif risk.rule == "FOREIGN_KEY_VALIDATES_ALL":
            # Add NOT VALID to foreign key constraints
            if "NOT VALID" not in fixed.upper():
                fixed = re.sub(
                    r"(ADD\s+(?:CONSTRAINT\s+\w+\s+)?FOREIGN\s+KEY\s*\([^)]+\)\s+REFERENCES\s+\w+\s*\([^)]+\))",
                    r"\1 NOT VALID",
                    fixed,
                    flags=re.IGNORECASE,
                )

        elif risk.rule == "CHECK_CONSTRAINT_VALIDATES":
            # Add NOT VALID to check constraints
            if "NOT VALID" not in fixed.upper():
                fixed = re.sub(
                    r"(ADD\s+(?:CONSTRAINT\s+\w+\s+)?CHECK\s*\([^)]+\))",
                    r"\1 NOT VALID",
                    fixed,
                    flags=re.IGNORECASE,
                )

        elif risk.rule == "NO_LOCK_TIMEOUT":
            # Add SET lock_timeout before DDL
            if "lock_timeout" not in fixed.lower():
                fixed = "SET lock_timeout = '5s';\n" + fixed
                fixed += "\nRESET lock_timeout;"

    return fixed


def _build_pr_comment(results: list[dict], pr_number: int) -> str:
    """Build a markdown PR comment from analysis results."""
    lines = [
        "## QuerySense Migration Review",
        "",
    ]

    total_risks = sum(len(r["risks"]) for r in results)
    critical = sum(
        1 for r in results for risk in r["risks"] if risk["severity"] == "critical"
    )

    if critical:
        lines.append(f"> **{critical} critical issue(s) found** across "
                      f"{len(results)} migration(s)")
    elif total_risks:
        lines.append(f"> {total_risks} issue(s) found (no critical)")
    else:
        lines.append("> All migrations look safe!")

    lines.append("")

    for result in results:
        status = "SAFE" if result["safe"] else "UNSAFE"
        emoji = "white_check_mark" if result["safe"] else "x"
        lines.append(
            f"### :{emoji}: `{result['file']}` — {status}"
        )
        lines.append(
            f"- **{result['statements']}** statement(s) analyzed"
        )
        lines.append(
            f"- **Rollback**: "
            f"{'Safe' if result['rollback_safe'] else str(result['irreversible']) + ' manual step(s) needed'}"
        )

        if result["risks"]:
            lines.append("")
            lines.append("| Severity | Rule | Suggestion |")
            lines.append("|----------|------|------------|")
            for risk in result["risks"]:
                sev = risk["severity"].upper()
                lines.append(
                    f"| {sev} | `{risk['rule']}` | {risk['suggestion']} |"
                )

        if result["warnings"]:
            lines.append("")
            for w in result["warnings"]:
                lines.append(f"> :warning: {w}")

        lines.append("")

    lines.append("---")
    lines.append("*Reviewed by [QuerySense](https://github.com/querysense/querysense) — "
                  "free migration analysis for every PR*")

    return "\n".join(lines)


def _post_github_comment(
    repo: str,
    pr_number: int,
    body: str,
    token: str,
) -> bool:
    """Post a comment on a GitHub PR using the REST API."""
    try:
        import urllib.request
        import urllib.error

        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        data = json.dumps({"body": body}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(req)
        return True
    except Exception:
        return False
