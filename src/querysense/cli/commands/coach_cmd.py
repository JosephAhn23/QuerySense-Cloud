"""
CLI command for the QuerySense Coach — step-by-step optimization wizard.

    querysense coach explain.json
    querysense coach explain.json --sql "SELECT ..."
    querysense coach explain.json --json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register(parent: typer.Typer) -> None:
    """Register the coach command."""
    parent.command(name="coach")(coach)


def coach(
    explain_file: Annotated[Path, typer.Argument(help="EXPLAIN JSON file to coach")],
    sql: Annotated[str, typer.Option("--sql", help="SQL text for classification")] = "",
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-V", help="Show educational context")] = False,
) -> None:
    """
    Step-by-step optimization wizard (the "Ultimate Optimization Algorithm").

    Walks through 10 systematic steps to optimize any query, based on
    "PostgreSQL Query Optimization" (Dombrovskaya et al. 2024).

    Each step explains the WHY behind each recommendation, building
    developer knowledge alongside fixing the immediate problem.
    """
    from querysense.coach import Coach
    from querysense.parser.parser import parse_explain
    from querysense.engine import AnalysisService

    # Parse the plan
    plan = parse_explain(explain_file)

    # Run full analysis to feed findings to the coach
    service = AnalysisService()
    analysis = service.analyze(plan, sql=sql)

    # Run the coach
    coach_engine = Coach()
    session = coach_engine.start(plan, sql=sql, analysis_result=analysis)

    if json_output:
        console.print_json(json.dumps(session.to_dict(), indent=2))
        return

    # Rich output
    status_icon = {"pass": "✅", "warning": "⚠️", "fail": "❌", "skip": "⏭️"}
    status_color = {"pass": "green", "warning": "yellow", "fail": "red", "skip": "dim"}

    overall_color = status_color.get(session.overall_status.value, "white")
    console.print(Panel(
        f"[bold]Overall: [{overall_color}]{session.overall_status.value.upper()}"
        f"[/{overall_color}][/bold]  |  "
        f"{session.pass_count} passed  |  "
        f"{session.issue_count} need attention  |  "
        f"{len(session.priority_actions)} priority actions",
        title="[bold]QuerySense Coach — Ultimate Optimization Algorithm[/bold]",
        subtitle="Based on PostgreSQL Query Optimization (Dombrovskaya 2024)",
    ))

    console.print()

    for step in session.steps:
        icon = status_icon.get(step.status.value, "?")
        color = status_color.get(step.status.value, "white")

        console.print(
            f"  {icon} [bold]Step {step.number}:[/bold] "
            f"[{color}]{step.title}[/{color}]"
        )

        if verbose:
            console.print(f"     [dim]{step.explanation}[/dim]")
            if step.reference:
                console.print(f"     [dim italic]📖 {step.reference}[/dim italic]")

        for finding in step.findings:
            console.print(f"     • {finding}")

        for action in step.actions:
            if action.sql:
                sql_preview = action.sql.split("\n")[0][:70]
                console.print(f"     → [cyan]{action.description}[/cyan]")
                console.print(f"       [dim]{sql_preview}[/dim]")
            else:
                console.print(f"     → [cyan]{action.description}[/cyan]")

        console.print()

    # Priority actions summary
    if session.priority_actions:
        console.print("[bold]Priority Actions:[/bold]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("#", width=4)
        table.add_column("Priority", width=8)
        table.add_column("Action")
        table.add_column("SQL", width=50)

        for i, action in enumerate(session.priority_actions, 1):
            sql_preview = action.sql.split("\n")[0][:50] if action.sql else "-"
            table.add_row(
                str(i),
                str(action.priority),
                action.description[:40],
                sql_preview,
            )

        console.print(table)

    console.print(f"\n[dim]Run with --verbose for educational context on each step.[/dim]")

    if session.overall_status.value == "fail":
        raise typer.Exit(1)
