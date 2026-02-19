"""Workload command: analyze multiple plans for cross-query optimization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register workload command on the given Typer app."""

    @app.command()
    def workload(
        plan_dir: Annotated[
            Path,
            typer.Argument(
                help="Directory containing EXPLAIN JSON files",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        pattern: Annotated[
            str,
            typer.Option("--pattern", "-p", help="Glob pattern for plan files"),
        ] = "*.json",
        budget: Annotated[
            Optional[float],
            typer.Option(
                "--budget",
                help="Maximum index storage budget in MB",
            ),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        allow_plain: Annotated[
            bool,
            typer.Option(
                "--allow-plain",
                help="Accept plain EXPLAIN (not ANALYZE) output",
            ),
        ] = False,
    ) -> None:
        """
        Analyze multiple EXPLAIN plans for workload-wide optimization.

        Scans a directory of EXPLAIN JSON files and produces cross-query
        index recommendations, redundant index detection, and table hotspots.

        Examples:

            $ querysense workload ./plans/
            $ querysense workload ./plans/ --budget 500 --json
            $ querysense workload ./plans/ --pattern "slow_*.json"
        """
        from querysense.parser import ParseError, parse_explain
        from querysense.workload import WorkloadAdvisor

        plan_files = sorted(plan_dir.glob(pattern))
        if not plan_files:
            error_console.print(
                f"[red]Error:[/red] No files matching '{pattern}' in {plan_dir}"
            )
            raise typer.Exit(code=1)

        advisor = WorkloadAdvisor(storage_budget_mb=budget)
        loaded = 0
        errors: list[str] = []

        for pf in plan_files:
            try:
                explain = parse_explain(pf)
                advisor.add_plan(explain, label=pf.stem)
                loaded += 1
            except (ParseError, Exception) as e:
                errors.append(f"{pf.name}: {e}")

        if loaded == 0:
            error_console.print("[red]Error:[/red] No valid plans could be loaded.")
            for err in errors[:5]:
                error_console.print(f"  [dim]{err}[/dim]")
            raise typer.Exit(code=1)

        console.print(
            f"[dim]Loaded {loaded}/{len(plan_files)} plans"
            f"{f' ({len(errors)} errors)' if errors else ''}[/dim]\n"
        )

        report = advisor.analyze()

        if json_output:
            console.print_json(json.dumps(report.format_json(), indent=2))
            return

        console.print(
            Panel(
                report.format(),
                title="[bold magenta]Workload Analysis[/bold magenta]",
                border_style="magenta",
            )
        )

        if errors:
            console.print(f"\n[dim yellow]Skipped files ({len(errors)}):[/dim yellow]")
            for err in errors[:5]:
                console.print(f"  [dim]{err}[/dim]")
