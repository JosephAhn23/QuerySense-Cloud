"""
CLI command: querysense zero-downtime

Decompose risky DDL into safe zero-downtime migration phases.

Usage:
    querysense zero-downtime "ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"
    querysense zero-downtime --file migration.sql --json
    querysense zero-downtime "DROP TABLE legacy_data" --batch-size 5000
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


def register(app: typer.Typer) -> None:
    @app.command("zero-downtime")
    def zero_downtime(
        sql: Annotated[
            str,
            typer.Argument(help="DDL SQL to decompose (or use --file)"),
        ] = "",
        file: Annotated[
            str,
            typer.Option("--file", "-f", help="Read SQL from file"),
        ] = "",
        batch_size: Annotated[
            int,
            typer.Option("--batch-size", help="Batch size for backfill operations"),
        ] = 10000,
        lock_timeout: Annotated[
            int,
            typer.Option("--lock-timeout", help="Lock timeout in milliseconds"),
        ] = 5000,
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Decompose DDL into zero-downtime migration phases."""
        from querysense.migration import ZeroDowntimePlanner

        # Get SQL
        if file:
            p = Path(file)
            if not p.exists():
                console.print(f"[red]File not found: {file}[/red]")
                raise typer.Exit(1)
            sql = p.read_text(encoding="utf-8").strip()

        if not sql:
            console.print("[red]Provide SQL as argument or use --file[/red]")
            raise typer.Exit(1)

        planner = ZeroDowntimePlanner(
            lock_timeout_ms=lock_timeout,
            batch_size=batch_size,
        )
        plan = planner.plan(sql)

        if output_json:
            console.print(plan.to_json())
            return

        # Rich output
        risk_color = {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "red",
        }

        console.print(Panel(
            f"[bold]ZERO-DOWNTIME MIGRATION PLAN[/bold]\n"
            f"Phases: {plan.total_phases} | "
            f"Time: {plan.estimated_total_time} | "
            f"Max risk: [{risk_color.get(plan.max_lock_risk, 'white')}]{plan.max_lock_risk}[/]",
            border_style="cyan",
        ))

        if plan.warnings:
            for w in plan.warnings:
                console.print(f"  [yellow]! {w}[/yellow]")
            console.print()

        for phase in plan.phases:
            color = risk_color.get(phase.lock_risk, "white")
            table = Table(
                title=f"Phase {phase.phase_number}: {phase.phase_type.value.upper()} — {phase.description}",
                show_header=False,
                title_style=f"bold {color}",
            )
            table.add_column("", style="bold", width=12)
            table.add_column("")

            table.add_row("SQL", phase.sql[:300])
            table.add_row("Rollback", phase.rollback_sql[:200])
            table.add_row("Lock Risk", f"[{color}]{phase.lock_risk}[/]")
            table.add_row("Duration", phase.duration_estimate)
            if phase.verification_sql:
                table.add_row("Verify", phase.verification_sql[:200])
            if phase.requires_app_change:
                table.add_row("App Change", "[yellow]Required[/yellow]")
            for note in phase.notes:
                table.add_row("Note", note)

            console.print(table)
            console.print()
