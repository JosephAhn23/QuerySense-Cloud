"""
CLI command for the Safe Migration Planner.

    querysense migration-plan migration.sql
    querysense migration-plan --stdin
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()


def register(parent: typer.Typer) -> None:
    """Register the migration-plan command."""
    parent.command(name="migration-plan")(migration_plan)


def migration_plan(
    sql_file: Annotated[Path, typer.Argument(help="SQL migration file to analyze")] = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read SQL from stdin")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    markdown: Annotated[bool, typer.Option("--markdown", help="Output full Markdown plan")] = False,
) -> None:
    """
    Generate a safe, phased migration plan with replication awareness.

    Analyzes DDL statements and produces:
    - Lock level assessment for each statement
    - Replication compatibility warnings
    - Phased execution order (additive → indexes → breaking)
    - Rollback plan for each step
    - Validation queries

    Based on "Mastering PostgreSQL 13" (Schönig 2020).
    """
    from querysense.safe_migration import SafeMigrationPlanner

    # Read SQL
    if stdin:
        sql = sys.stdin.read()
    elif sql_file and sql_file.exists():
        sql = sql_file.read_text()
    else:
        console.print("[red]Provide a SQL file or --stdin[/red]")
        raise typer.Exit(1)

    planner = SafeMigrationPlanner()
    plan = planner.plan(sql)

    if markdown:
        console.print(Markdown(plan.to_markdown()))
        return

    if json_output:
        data = {
            "overall_risk": plan.overall_risk.value,
            "requires_downtime": plan.requires_downtime,
            "replication_warnings": plan.replication_warnings,
            "phases": [
                {
                    "order": p.order,
                    "title": p.title,
                    "risk": p.risk_level.value,
                    "requires_maintenance_window": p.requires_maintenance_window,
                    "steps": [
                        {
                            "order": s.order,
                            "sql": s.sql,
                            "lock_level": s.lock_level.value,
                            "duration": s.estimated_duration,
                            "safe_on_replica": s.safe_on_replica,
                        }
                        for s in p.steps
                    ],
                }
                for p in plan.phases
            ],
        }
        console.print_json(json.dumps(data, indent=2))
        return

    # Rich output
    risk_color = {"low": "green", "medium": "yellow", "high": "red", "critical": "red bold"}
    color = risk_color.get(plan.overall_risk.value, "white")

    console.print(Panel(
        f"[bold]Risk: [{color}]{plan.overall_risk.value.upper()}[/{color}][/bold]  |  "
        f"Downtime: {'Required' if plan.requires_downtime else 'None'}  |  "
        f"Phases: {len(plan.phases)}",
        title="[bold]QuerySense Safe Migration Plan[/bold]",
    ))

    if plan.replication_warnings:
        console.print("\n[bold yellow]Replication Warnings:[/bold yellow]")
        for w in plan.replication_warnings:
            console.print(f"  ⚠️  {w}")

    for phase in plan.phases:
        pcolor = risk_color.get(phase.risk_level.value, "white")
        mw = " [red](MAINTENANCE WINDOW)[/red]" if phase.requires_maintenance_window else ""
        console.print(
            f"\n[bold]Phase {phase.order}: {phase.title}[/bold] "
            f"[{pcolor}]{phase.risk_level.value}[/{pcolor}]{mw}"
        )

        for step in phase.steps:
            console.print(f"  {step.order}. [{pcolor}]{step.description}[/{pcolor}]")
            console.print(f"     Lock: {step.lock_level.value} | Duration: {step.estimated_duration}")
            console.print(f"     [cyan]{step.sql}[/cyan]")
            if step.notes:
                for note in step.notes:
                    console.print(f"     [dim]📝 {note}[/dim]")
            if step.rollback_sql:
                console.print(f"     [dim]↩ Rollback: {step.rollback_sql}[/dim]")

    console.print(
        f"\nRun with [bold cyan]--markdown[/bold cyan] for a full exportable plan."
    )

    if plan.requires_downtime:
        raise typer.Exit(1)
