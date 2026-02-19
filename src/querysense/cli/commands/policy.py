"""Policy management commands: init, evaluate."""

from __future__ import annotations

import glob as globmod
import json
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console

from querysense.engine import AnalysisService
from querysense.parser import ParseError, parse_explain

console = Console()
error_console = Console(stderr=True)


def register(policy_app: typer.Typer) -> None:
    """Register policy commands on the given Typer sub-app."""

    @policy_app.command("init")
    def policy_init(
        output_path: Annotated[
            str,
            typer.Option("--output", "-o", help="Path to write the policy file"),
        ] = ".querysense/policy.yml",
        force: Annotated[
            bool,
            typer.Option("--force", help="Overwrite existing policy file"),
        ] = False,
    ) -> None:
        """
        Generate a default policy file with documentation.

        Examples:

            $ querysense policy init
        """
        from querysense.policy import generate_default_policy

        policy_path = Path(output_path)

        if policy_path.exists() and not force:
            error_console.print(
                f"[yellow]Policy file already exists at {output_path}[/yellow]"
            )
            error_console.print("[dim]Use --force to overwrite[/dim]")
            raise typer.Exit(code=1)

        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(generate_default_policy(), encoding="utf-8")
        console.print(f"[green]Policy file created at {output_path}[/green]")
        console.print(
            "[dim]Edit the file to define your team's performance standards[/dim]"
        )

    @policy_app.command("evaluate")
    def policy_evaluate(
        plan_pattern: Annotated[
            str,
            typer.Argument(help="Glob pattern for EXPLAIN JSON files"),
        ],
        policy_file: Annotated[
            str,
            typer.Option("--policy", "-p", help="Path to policy file"),
        ] = ".querysense/policy.yml",
        baseline_file: Annotated[
            str,
            typer.Option("--baseline", "-b", help="Path to baseline file"),
        ] = ".querysense/baselines.json",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output results as JSON"),
        ] = False,
    ) -> None:
        """
        Evaluate EXPLAIN plans against a policy file.

        Examples:

            $ querysense policy evaluate "plans/**/*.json"
        """
        plan_files = sorted(globmod.glob(plan_pattern, recursive=True))
        if not plan_files:
            error_console.print(f"[yellow]No files matching '{plan_pattern}'[/yellow]")
            raise typer.Exit(code=0)

        # Use AnalysisService for each plan with policy enforcement
        service = AnalysisService()
        all_violations: list[dict[str, Any]] = []
        total_files = 0
        total_violations = 0

        for plan_file in plan_files:
            try:
                explain = parse_explain(plan_file)
                query_id = Path(plan_file).stem

                report = service.analyze_with_baseline(
                    explain,
                    query_id=query_id,
                    baseline_path=baseline_file,
                    policy_path=policy_file,
                )
                total_files += 1

                if report.policy_violations:
                    total_violations += len(report.policy_violations)
                    for v in report.policy_violations:
                        if json_output:
                            all_violations.append({
                                "file": plan_file,
                                "rule": v.rule,
                                "severity": v.severity,
                                "message": v.message,
                                "table": v.table,
                                "query_id": v.query_id,
                            })
                        else:
                            sev_style = (
                                "red bold" if v.severity == "critical" else "yellow"
                            )
                            console.print(
                                f"  [{sev_style}][{v.severity.upper()}][/{sev_style}] "
                                f"{plan_file}: {v.message}"
                            )

            except Exception as e:
                error_console.print(f"  [red]ERROR[/red] {plan_file}: {e}")

        if json_output:
            output_data = {
                "total_files": total_files,
                "total_violations": total_violations,
                "violations": all_violations,
                "policy_file": policy_file,
            }
            console.print_json(json.dumps(output_data, indent=2))
        else:
            console.print(
                f"\n[dim]{total_files} files evaluated, "
                f"{total_violations} violation(s)[/dim]"
            )

        if total_violations > 0:
            raise typer.Exit(code=1)
