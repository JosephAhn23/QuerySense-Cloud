"""CI/CD integration commands: ci analyze, ci report, ci discover, ci gate, ci init."""

from __future__ import annotations

import glob as globmod
import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.table import Table

from querysense.engine import AnalysisService
from querysense.output.pr_comment import CIResult, render_ci_summary_json, render_pr_comment
from querysense.output.renderers import render_text
from querysense.parser import ParseError, parse_explain
from querysense.parser.parser import validate_has_analyze

console = Console()
error_console = Console(stderr=True)


def _is_github_actions() -> bool:
    """Detect if running inside GitHub Actions."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _is_gitlab_ci() -> bool:
    """Detect if running inside GitLab CI."""
    return os.environ.get("GITLAB_CI") == "true"


def _is_ci_environment() -> bool:
    """Detect if running in any CI environment."""
    return (
        _is_github_actions()
        or _is_gitlab_ci()
        or os.environ.get("CI") == "true"
        or os.environ.get("JENKINS_URL") is not None
        or os.environ.get("CIRCLECI") == "true"
        or os.environ.get("BUILDKITE") == "true"
    )


def register(ci_app: typer.Typer) -> None:
    """Register CI commands on the given Typer sub-app."""

    # ── ci gate ────────────────────────────────────────────────────────────

    @ci_app.command("gate")
    def ci_gate(
        plan_pattern: Annotated[
            Optional[str],
            typer.Argument(
                help="Glob pattern for EXPLAIN JSON files. If omitted, reads from .querysense-ci.yml",
            ),
        ] = None,
        fail_on: Annotated[
            Optional[str],
            typer.Option("--fail-on", help="Severity to fail on: critical, warning, info, none"),
        ] = None,
        config_file: Annotated[
            Optional[str],
            typer.Option("--config", "-c", help="Path to .querysense-ci.yml config file"),
        ] = None,
        no_annotations: Annotated[
            bool,
            typer.Option("--no-annotations", help="Disable GitHub Actions annotations"),
        ] = False,
        no_summary: Annotated[
            bool,
            typer.Option("--no-summary", help="Disable GITHUB_STEP_SUMMARY output"),
        ] = False,
        markdown_file: Annotated[
            Optional[str],
            typer.Option("--markdown", "-m", help="Write PR comment Markdown to file"),
        ] = None,
        json_file: Annotated[
            Optional[str],
            typer.Option("--json", "-j", help="Write JSON results to file"),
        ] = None,
        allow_plain: Annotated[
            bool,
            typer.Option("--allow-plain", help="Allow EXPLAIN output without ANALYZE data"),
        ] = False,
    ) -> None:
        """
        One-command CI/CD gate — lint your SQL performance in CI.

        The simplest way to add QuerySense to your pipeline. Reads config from
        .querysense-ci.yml, auto-detects GitHub Actions for annotations,
        and exits with code 1 if issues are found.

        \b
        Quick start (GitHub Actions):
            - run: pip install querysense
            - run: querysense ci gate

        \b
        With explicit pattern:
            $ querysense ci gate "plans/**/*.json"
            $ querysense ci gate "plans/*.json" --fail-on critical

        \b
        Config file (.querysense-ci.yml):
            plans:
              - "plans/**/*.json"
            fail_on: warning
            github:
              annotations: true
              step_summary: true
        """
        from querysense.ci_config import load_ci_config

        # Load config
        try:
            ci_cfg = load_ci_config(config_file)
        except FileNotFoundError as e:
            error_console.print(f"[red]{e}[/red]")
            raise typer.Exit(code=1)
        except ValueError as e:
            error_console.print(f"[red]Invalid config: {e}[/red]")
            raise typer.Exit(code=1)

        # CLI args override config file
        effective_fail_on = fail_on or ci_cfg.fail_on
        effective_patterns = (plan_pattern,) if plan_pattern else ci_cfg.plans
        require_analyze = not allow_plain and ci_cfg.require_analyze

        # Discover plan files
        plan_files: list[str] = []
        for pattern in effective_patterns:
            plan_files.extend(sorted(globmod.glob(pattern, recursive=True)))

        if not plan_files:
            patterns_str = ", ".join(effective_patterns)
            if _is_ci_environment():
                # In CI, no plans is not an error — maybe the PR didn't change queries
                console.print(
                    f"[dim]QuerySense: no plan files matching {patterns_str} — skipping[/dim]"
                )
                raise typer.Exit(code=0)
            else:
                error_console.print(
                    f"[yellow]No files matching: {patterns_str}[/yellow]\n"
                    f"[dim]Create plan files or update patterns in .querysense-ci.yml[/dim]"
                )
                raise typer.Exit(code=0)

        console.print(f"[dim]QuerySense: analyzing {len(plan_files)} plan(s)...[/dim]")

        # Parse all plans
        service = AnalysisService()
        parsed_plans: list[tuple[str, Any, str]] = []
        parse_errors: list[str] = []

        for plan_file in plan_files:
            try:
                explain = parse_explain(plan_file)
                if require_analyze:
                    validate_has_analyze(explain)
                query_id = Path(plan_file).stem
                parsed_plans.append((query_id, explain, plan_file))
            except ParseError as e:
                parse_errors.append(f"{plan_file}: {e.message}")
            except Exception as e:
                parse_errors.append(f"{plan_file}: {e}")

        # Report parse errors
        for err in parse_errors:
            if _is_github_actions():
                print(f"::warning title=QuerySense: Parse Error::{err}")
            else:
                error_console.print(f"[yellow]Parse error:[/yellow] {err}")

        if not parsed_plans:
            error_console.print("[red]No plans could be parsed[/red]")
            raise typer.Exit(code=1)

        # Resolve policy path
        policy_path = ci_cfg.policy

        # Run batch analysis
        batch_report = service.analyze_batch(
            plans=parsed_plans,
            baseline_path=ci_cfg.baseline,
            fail_on=effective_fail_on,
            policy_path=policy_path,
        )

        # Build CI results
        ci_results: list[CIResult] = []
        for report in batch_report.reports:
            ci_results.append(
                CIResult(
                    file_path=report.file_path or "",
                    result=report.result,
                    baseline_diff=report.baseline_diff,
                    verdict=report.verdict,
                    policy_violations=list(report.policy_violations) if report.policy_violations else None,
                )
            )

        if not ci_results:
            error_console.print("[red]No analysis results[/red]")
            raise typer.Exit(code=1)

        # Filter ignored rules from results display (still analyzed for completeness)
        # The findings are already computed; we filter for reporting and exit code
        ignored_rules = ci_cfg.ignore_rules

        # ── Output: GitHub Actions annotations ──
        if _is_github_actions() and ci_cfg.github.annotations and not no_annotations:
            from querysense.output.github_annotations import render_annotations
            annotations = render_annotations(ci_results)
            if annotations:
                # Write directly to stdout — GitHub Actions reads these
                sys.stdout.write(annotations + "\n")
                sys.stdout.flush()

        # ── Output: GITHUB_STEP_SUMMARY ──
        if _is_github_actions() and ci_cfg.github.step_summary and not no_summary:
            from querysense.output.github_annotations import write_step_summary
            write_step_summary(ci_results, fail_on=effective_fail_on)

        # ── Output: GitHub Actions output variables ──
        if _is_github_actions():
            from querysense.output.github_annotations import write_github_outputs
            write_github_outputs(ci_results, fail_on=effective_fail_on)

        # ── Output: Markdown file ──
        if markdown_file:
            md_content = render_pr_comment(ci_results, fail_on=effective_fail_on)
            Path(markdown_file).parent.mkdir(parents=True, exist_ok=True)
            Path(markdown_file).write_text(md_content, encoding="utf-8")
            error_console.print(f"[dim]PR comment written to {markdown_file}[/dim]")

        # ── Output: JSON file ──
        if json_file:
            summary = render_ci_summary_json(ci_results, fail_on=effective_fail_on)
            Path(json_file).parent.mkdir(parents=True, exist_ok=True)
            Path(json_file).write_text(
                json.dumps(summary, indent=2), encoding="utf-8"
            )
            error_console.print(f"[dim]JSON results written to {json_file}[/dim]")

        # ── Output: Terminal summary (always) ──
        summary = render_ci_summary_json(ci_results, fail_on=effective_fail_on)
        s = summary["summary"]

        # Print findings summary to stderr (so stdout stays clean for annotations)
        if s["critical_count"] or s["warning_count"]:
            error_console.print("")
            for finding_data in summary["findings"]:
                sev = finding_data["severity"]
                icon = {"critical": "[red]CRIT[/red]", "warning": "[yellow]WARN[/yellow]", "info": "[blue]INFO[/blue]"}.get(sev, sev)
                title = finding_data["title"]
                file_name = finding_data["file"]
                error_console.print(f"  {icon}  {title}  [dim]({file_name})[/dim]")

        # ── Exit code ──
        has_failures = s["has_failures"]

        if has_failures:
            error_console.print(
                f"\n[red bold]FAILED[/red bold] "
                f"[dim]({s['critical_count']} critical, {s['warning_count']} warnings, "
                f"{s['regression_count']} regressions | threshold: {effective_fail_on})[/dim]"
            )
            raise typer.Exit(code=1)
        else:
            console.print(
                f"[green bold]PASSED[/green bold] "
                f"[dim]({s['total_plans']} plans, no issues at '{effective_fail_on}' or above)[/dim]"
            )

    # ── ci init ────────────────────────────────────────────────────────────

    @ci_app.command("init")
    def ci_init(
        force: Annotated[
            bool,
            typer.Option("--force", help="Overwrite existing config file"),
        ] = False,
    ) -> None:
        """
        Generate a .querysense-ci.yml config and GitHub Action workflow.

        Creates the config file and optionally a GitHub Actions workflow
        file so you can start gating PRs immediately.

        \b
        Usage:
            $ querysense ci init
            $ querysense ci init --force
        """
        from querysense.ci_config import generate_default_ci_config

        # Write .querysense-ci.yml
        config_path = Path(".querysense-ci.yml")
        if config_path.exists() and not force:
            error_console.print(
                f"[yellow]{config_path} already exists. Use --force to overwrite.[/yellow]"
            )
        else:
            config_path.write_text(generate_default_ci_config(), encoding="utf-8")
            console.print(f"[green]Created {config_path}[/green]")

        # Write GitHub Action workflow
        workflow_dir = Path(".github/workflows")
        workflow_path = workflow_dir / "querysense.yml"

        if workflow_path.exists() and not force:
            error_console.print(
                f"[yellow]{workflow_path} already exists. Use --force to overwrite.[/yellow]"
            )
        else:
            workflow_dir.mkdir(parents=True, exist_ok=True)
            workflow_path.write_text(_GITHUB_WORKFLOW_TEMPLATE, encoding="utf-8")
            console.print(f"[green]Created {workflow_path}[/green]")

        # Create plans directory
        plans_dir = Path("plans")
        if not plans_dir.exists():
            plans_dir.mkdir(parents=True, exist_ok=True)
            console.print(f"[green]Created {plans_dir}/ directory[/green]")

        console.print("")
        console.print("[bold]Next steps:[/bold]")
        console.print("  1. Export EXPLAIN plans to plans/ directory")
        console.print("  2. Commit .querysense-ci.yml and .github/workflows/querysense.yml")
        console.print("  3. Push — QuerySense will gate your PRs automatically")
        console.print("")
        console.print("[dim]Tip: Run 'querysense ci gate' locally to test before pushing[/dim]")

    # ── ci analyze (existing) ──────────────────────────────────────────────

    @ci_app.command("analyze")
    def ci_analyze(
        plan_pattern: Annotated[
            str,
            typer.Argument(
                help="Glob pattern for EXPLAIN JSON files (e.g., 'plans/**/*.json')",
            ),
        ],
        fail_on: Annotated[
            str,
            typer.Option("--fail-on", help="Severity level to fail CI: critical, warning, info, none"),
        ] = "warning",
        baseline_file: Annotated[
            str,
            typer.Option("--baseline", help="Path to baseline file for regression detection"),
        ] = ".querysense/baselines.json",
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: json, markdown, text"),
        ] = "text",
        output_file: Annotated[
            Optional[str],
            typer.Option("--output", "-o", help="Write output to file instead of stdout"),
        ] = None,
        allow_plain: Annotated[
            bool,
            typer.Option("--allow-plain", help="Allow EXPLAIN output without ANALYZE data"),
        ] = False,
        policy_file: Annotated[
            Optional[str],
            typer.Option("--policy", "-p", help="Path to policy file for enforcement"),
        ] = None,
    ) -> None:
        """
        Analyze EXPLAIN plans for CI/CD pipeline gating.

        Examples:

            $ querysense ci analyze "plans/**/*.json"
            $ querysense ci analyze "plans/*.json" --fail-on critical --format markdown -o comment.md
        """
        plan_files = sorted(globmod.glob(plan_pattern, recursive=True))

        if not plan_files:
            error_console.print(f"[yellow]No files matching '{plan_pattern}'[/yellow]")
            raise typer.Exit(code=0)

        console.print(f"[dim]Found {len(plan_files)} plan file(s)[/dim]")

        service = AnalysisService()

        parsed_plans: list[tuple[str, Any, str]] = []
        for plan_file in plan_files:
            try:
                explain = parse_explain(plan_file)
                if not allow_plain:
                    validate_has_analyze(explain)
                query_id = Path(plan_file).stem
                parsed_plans.append((query_id, explain, plan_file))
            except ParseError as e:
                error_console.print(f"[red]Error parsing {plan_file}:[/red] {e.message}")
            except Exception as e:
                error_console.print(f"[red]Error analyzing {plan_file}:[/red] {e}")

        if not parsed_plans:
            error_console.print("[red]No plans could be analyzed[/red]")
            raise typer.Exit(code=1)

        # Resolve policy path
        resolved_policy: str | None = policy_file
        if resolved_policy is None:
            default_policy = Path(".querysense/policy.yml")
            if default_policy.exists():
                resolved_policy = str(default_policy)

        batch_report = service.analyze_batch(
            plans=parsed_plans,
            baseline_path=baseline_file,
            fail_on=fail_on,
            policy_path=resolved_policy,
        )

        ci_results: list[CIResult] = []
        for report in batch_report.reports:
            ci_results.append(
                CIResult(
                    file_path=report.file_path or "",
                    result=report.result,
                    baseline_diff=report.baseline_diff,
                )
            )

        if not ci_results:
            error_console.print("[red]No plans could be analyzed[/red]")
            raise typer.Exit(code=1)

        # Generate output
        if output_format == "markdown":
            output_text = render_pr_comment(ci_results, fail_on=fail_on)
        elif output_format == "json":
            summary = render_ci_summary_json(ci_results, fail_on=fail_on)
            output_text = json.dumps(summary, indent=2)
        else:
            parts: list[str] = []
            for report, cr in zip(batch_report.reports, ci_results):
                parts.append(f"--- {cr.file_path} ---")
                parts.append(render_text(cr.result))
                if report.verdict:
                    parts.append(report.verdict.format_summary())
                elif cr.baseline_diff and cr.baseline_diff.status == "CHANGED":
                    parts.append(cr.baseline_diff.summary())
                if report.policy_violations:
                    parts.append("  Policy violations:")
                    for pv in report.policy_violations:
                        parts.append(f"    [{pv.severity.upper()}] {pv.message}")
                parts.append("")
            output_text = "\n".join(parts)

        _write_output(output_text, output_file, output_format)

        # Determine exit code
        summary = render_ci_summary_json(ci_results, fail_on=fail_on)
        has_failures = summary["summary"]["has_failures"]

        s = summary["summary"]
        if has_failures:
            error_console.print(
                f"\n[red bold]FAILED:[/red bold] "
                f"{s['critical_count']} critical, {s['warning_count']} warnings, "
                f"{s['regression_count']} regressions"
            )
            raise typer.Exit(code=1)
        else:
            console.print(
                f"\n[green bold]PASSED:[/green bold] "
                f"{s['total_plans']} plans analyzed, no issues at '{fail_on}' level or above"
            )

    @ci_app.command("report")
    def ci_report(
        results_file: Annotated[
            Path,
            typer.Argument(help="Path to CI results JSON file", exists=True, readable=True),
        ],
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: markdown, text"),
        ] = "markdown",
        output_file: Annotated[
            Optional[str],
            typer.Option("--output", "-o", help="Write output to file"),
        ] = None,
    ) -> None:
        """
        Generate a report from CI results JSON.

        Examples:

            $ querysense ci report results.json --format markdown -o comment.md
        """
        data = json.loads(results_file.read_text(encoding="utf-8"))

        if output_format == "markdown":
            lines: list[str] = []
            summary = data.get("summary", {})

            if summary.get("has_failures"):
                lines.append("## 🔴 QuerySense found performance issues")
            else:
                lines.append("## ✅ QuerySense: all checks passed")

            lines.append("")
            lines.append(
                f"**{summary.get('total_plans', 0)} plans analyzed** | "
                f"🔴 {summary.get('critical_count', 0)} critical | "
                f"🟡 {summary.get('warning_count', 0)} warnings | "
                f"🔵 {summary.get('info_count', 0)} info"
            )
            lines.append("")

            for finding in data.get("findings", []):
                sev = finding.get("severity", "info")
                icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(sev, "⚪")
                lines.append(f"### {icon} {finding.get('title', 'Unknown')}")
                lines.append(
                    f"  File: `{finding.get('file', '')}`  "
                    f"Rule: `{finding.get('rule_id', '')}`"
                )
                lines.append("")
                lines.append(f"> {finding.get('description', '')[:200]}")
                lines.append("")

                if finding.get("suggestion"):
                    lines.append("```sql")
                    lines.append(finding["suggestion"])
                    lines.append("```")
                    lines.append("")

            lines.append("---")
            lines.append(
                "*Powered by [QuerySense](https://github.com/JosephAhn23/Query-Sense)*"
            )
            output_text = "\n".join(lines)
        else:
            output_text = json.dumps(data, indent=2)

        _write_output(output_text, output_file, output_format)

    @ci_app.command("discover")
    def ci_discover(
        root_dir: Annotated[
            str,
            typer.Argument(help="Root directory to scan for migrations"),
        ] = ".",
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: text, json"),
        ] = "text",
    ) -> None:
        """
        Discover SQL migration files across frameworks.

        Auto-detects Flyway, Prisma, Django, Alembic, Rails, and raw SQL migrations.

        Examples:

            $ querysense ci discover .
            $ querysense ci discover --format json
        """
        from querysense.migrations import discover_migrations

        migrations = discover_migrations(root_dir)

        if not migrations:
            console.print("[yellow]No migration files found[/yellow]")
            return

        if output_format == "json":
            output_data = [
                {
                    "path": m.path,
                    "framework": m.framework,
                    "version": m.version,
                    "description": m.description,
                    "has_ddl": m.has_ddl,
                    "has_dml": m.has_dml,
                    "statement_count": len(m.sql_statements),
                }
                for m in migrations
            ]
            console.print_json(json.dumps(output_data, indent=2))
        else:
            table = Table()
            table.add_column("Path", style="cyan")
            table.add_column("Framework")
            table.add_column("Version")
            table.add_column("DDL")
            table.add_column("DML")
            table.add_column("Statements")

            for m in migrations:
                table.add_row(
                    m.path,
                    m.framework,
                    m.version or "-",
                    "[green]yes[/green]" if m.has_ddl else "[dim]no[/dim]",
                    "[green]yes[/green]" if m.has_dml else "[dim]no[/dim]",
                    str(len(m.sql_statements)),
                )

            console.print(table)
            console.print(f"\n[dim]{len(migrations)} migration(s) discovered[/dim]")


def _write_output(text: str, output_file: str | None, output_format: str) -> None:
    """Write output to file or stdout."""
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_text(text, encoding="utf-8")
        error_console.print(f"[dim]Output written to {output_file}[/dim]")
    elif output_format in ("markdown", "json"):
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
    else:
        console.print(text)


# =============================================================================
# GitHub Actions workflow template
# =============================================================================

_GITHUB_WORKFLOW_TEMPLATE = """\
# QuerySense — SQL performance linting in CI
# Docs: https://github.com/JosephAhn23/Query-Sense#ci-cd
#
# This workflow runs QuerySense on every PR to catch slow queries
# before they reach production. It:
#   1. Analyzes EXPLAIN plan JSON files in your repo
#   2. Annotates the PR with findings (inline on files)
#   3. Shows a summary in the Actions tab
#   4. Blocks the PR if critical/warning issues are found

name: QuerySense

on:
  pull_request:
    paths:
      - "plans/**"
      - "migrations/**"
      - ".querysense-ci.yml"

# Prevent concurrent runs on the same PR
concurrency:
  group: querysense-${{ github.head_ref }}
  cancel-in-progress: true

jobs:
  lint-queries:
    name: Lint SQL Performance
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write  # For PR annotations

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install QuerySense
        run: pip install querysense

      - name: Run QuerySense gate
        id: querysense
        run: querysense ci gate

      # Optional: Post PR comment with detailed findings
      # Uncomment the following step and set pr_comment: true in .querysense-ci.yml
      #
      # - name: Post PR comment
      #   if: always() && steps.querysense.outputs.result == 'fail'
      #   run: |
      #     querysense ci gate --markdown comment.md
      #     gh pr comment ${{ github.event.pull_request.number }} --body-file comment.md
      #   env:
      #     GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""
