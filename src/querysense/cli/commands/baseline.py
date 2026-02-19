"""Baseline management commands: update, diff, list."""

from __future__ import annotations

import glob as globmod
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from querysense.engine import AnalysisService
from querysense.parser import ParseError, parse_explain

console = Console()
error_console = Console(stderr=True)


def register(baseline_app: typer.Typer) -> None:
    """Register baseline commands on the given Typer sub-app."""

    @baseline_app.command("update")
    def baseline_update(
        plan_pattern: Annotated[
            str,
            typer.Argument(help="Glob pattern for EXPLAIN JSON files"),
        ],
        baseline_file: Annotated[
            str,
            typer.Option("--output", "-o", help="Path to baseline file"),
        ] = ".querysense/baselines.json",
    ) -> None:
        """
        Update plan baselines from current EXPLAIN output.

        Examples:

            $ querysense baseline update "plans/**/*.json"
        """
        plan_files = sorted(globmod.glob(plan_pattern, recursive=True))

        if not plan_files:
            error_console.print(f"[yellow]No files matching '{plan_pattern}'[/yellow]")
            raise typer.Exit(code=0)

        service = AnalysisService()
        plans: list[tuple[str, object]] = []
        for plan_file in plan_files:
            try:
                explain = parse_explain(plan_file)
                query_id = Path(plan_file).stem
                plans.append((query_id, explain))
            except ParseError as e:
                error_console.print(f"  [red]FAIL[/red] {plan_file}: {e.message}")
            except Exception as e:
                error_console.print(f"  [red]FAIL[/red] {plan_file}: {e}")

        if not plans:
            error_console.print("[red]No baselines could be recorded[/red]")
            raise typer.Exit(code=1)

        results = service.update_baselines(plans, baseline_path=baseline_file)

        for query_id, structure_hash in results.items():
            console.print(f"  [green]OK[/green] {query_id} (hash={structure_hash})")

        console.print(
            f"\n[green]Updated {len(results)} baseline(s) in {baseline_file}[/green]"
        )

    @baseline_app.command("diff")
    def baseline_diff(
        plan_pattern: Annotated[
            str,
            typer.Argument(help="Glob pattern for EXPLAIN JSON files"),
        ],
        baseline_file: Annotated[
            str,
            typer.Option("--baseline", "-b", help="Path to baseline file"),
        ] = ".querysense/baselines.json",
    ) -> None:
        """
        Show differences between current plans and baselines.

        Examples:

            $ querysense baseline diff "plans/**/*.json"
        """
        from querysense.baseline import BaselineStore

        plan_files = sorted(globmod.glob(plan_pattern, recursive=True))

        if not plan_files:
            error_console.print(f"[yellow]No files matching '{plan_pattern}'[/yellow]")
            raise typer.Exit(code=0)

        store = BaselineStore(baseline_file)

        if not store.path.exists():
            error_console.print(
                f"[yellow]No baseline file found at {baseline_file}[/yellow]"
            )
            error_console.print("[dim]Run 'querysense baseline update' first[/dim]")
            raise typer.Exit(code=0)

        changed = 0
        unchanged = 0
        new_queries = 0

        for plan_file in plan_files:
            try:
                explain = parse_explain(plan_file)
                query_id = Path(plan_file).stem
                diff = store.compare(query_id, explain)

                if diff.status == "NO_BASELINE":
                    console.print(f"  [blue]NEW[/blue]       {query_id}")
                    new_queries += 1
                elif diff.status == "UNCHANGED":
                    console.print(f"  [green]UNCHANGED[/green] {query_id}")
                    unchanged += 1
                else:
                    console.print(f"  [red]CHANGED[/red]   {query_id}")
                    if diff.node_type_changes:
                        for change in diff.node_type_changes:
                            console.print(
                                f"    [dim]{change['path']}:[/dim] "
                                f"[red]{change['before']}[/red] → "
                                f"[green]{change['after']}[/green]"
                            )
                    if diff.has_cost_regression:
                        console.print(
                            f"    [dim]Cost:[/dim] {diff.cost_before:.0f} → "
                            f"{diff.cost_after:.0f} "
                            f"({diff.cost_change_percent:+.1f}%)"
                        )
                    changed += 1

            except ParseError as e:
                error_console.print(
                    f"  [red]ERROR[/red]     {plan_file}: {e.message}"
                )
            except Exception as e:
                error_console.print(f"  [red]ERROR[/red]     {plan_file}: {e}")

        console.print(
            f"\n[dim]{unchanged} unchanged, {changed} changed, {new_queries} new[/dim]"
        )

        if changed > 0:
            raise typer.Exit(code=1)

    @baseline_app.command("list")
    def baseline_list(
        baseline_file: Annotated[
            str,
            typer.Option("--baseline", "-b", help="Path to baseline file"),
        ] = ".querysense/baselines.json",
    ) -> None:
        """
        List all stored baselines.

        Examples:

            $ querysense baseline list
        """
        from querysense.baseline import BaselineStore

        store = BaselineStore(baseline_file)

        if not store.path.exists():
            console.print(f"[yellow]No baseline file at {baseline_file}[/yellow]")
            raise typer.Exit(code=0)

        queries = store.queries
        if not queries:
            console.print("[yellow]No baselines recorded[/yellow]")
            raise typer.Exit(code=0)

        table = Table()
        table.add_column("Query ID", style="cyan")
        table.add_column("Structure Hash")
        table.add_column("Nodes")
        table.add_column("Cost")
        table.add_column("Recorded At")

        for query_id, data in sorted(queries.items()):
            table.add_row(
                query_id,
                data.get("structure_hash", "?")[:12],
                str(data.get("node_count", "?")),
                f"{data.get('total_cost', 0):.0f}",
                data.get("recorded_at", "?")[:19],
            )

        console.print(table)
        console.print(f"\n[dim]{len(queries)} baseline(s) in {baseline_file}[/dim]")
