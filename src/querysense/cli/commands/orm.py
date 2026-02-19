"""CLI command: querysense orm-detect — ORM anti-pattern detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register the orm-detect command."""

    @app.command("orm-detect")
    def orm_detect(
        log_file: Annotated[
            Optional[Path],
            typer.Argument(
                help="Path to SQL query log file (one query per line, or semicolon-separated)",
            ),
        ] = None,
        plan_file: Annotated[
            Optional[Path],
            typer.Option(
                "--plan", "-p",
                help="EXPLAIN JSON file for plan-level ORM pattern detection",
            ),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Detect ORM anti-patterns in SQL query logs or EXPLAIN plans.

        Finds N+1 queries, SELECT *, unnecessary DISTINCT, missing pagination,
        and eager loading abuse. These are the most common performance killers
        in ORM-generated code.

        \\b
        Examples:
            $ querysense orm-detect queries.log
            $ querysense orm-detect --plan plan.json
            $ querysense orm-detect queries.log --plan plan.json --json

        \\b
        Query log format (one per line):
            SELECT * FROM users WHERE id = 1;
            SELECT * FROM users WHERE id = 2;
            SELECT * FROM users WHERE id = 3;
        """
        from querysense.orm_detector import detect_orm_patterns

        queries: list[str] | None = None
        plan: dict | None = None

        if log_file:
            if not log_file.exists():
                error_console.print(f"[red]File not found: {log_file}[/red]")
                raise typer.Exit(code=2)

            text = log_file.read_text(encoding="utf-8")
            # Parse queries: one per line or semicolon-separated
            raw_queries = []
            for line in text.split("\n"):
                line = line.strip()
                if line and not line.startswith("--") and not line.startswith("#"):
                    # Split by semicolons
                    for part in line.split(";"):
                        part = part.strip()
                        if part:
                            raw_queries.append(part)
            queries = raw_queries

        if plan_file:
            if not plan_file.exists():
                error_console.print(f"[red]File not found: {plan_file}[/red]")
                raise typer.Exit(code=2)

            plan_data = json.loads(plan_file.read_text(encoding="utf-8"))
            if isinstance(plan_data, list) and plan_data:
                plan = plan_data[0].get("Plan", plan_data[0])
            elif isinstance(plan_data, dict):
                plan = plan_data.get("Plan", plan_data)

        if not queries and not plan:
            error_console.print(
                "[yellow]Provide either a query log file or --plan flag.[/yellow]"
            )
            raise typer.Exit(code=2)

        report = detect_orm_patterns(queries=queries, plan=plan)

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2))
            return

        # Rich output
        if not report.patterns:
            console.print()
            console.print(Panel(
                "[green]No ORM anti-patterns detected![/green]\n\n"
                f"Analyzed {report.queries_analyzed} queries.",
                title="QuerySense ORM Detector",
                border_style="green",
            ))
            console.print()
            return

        console.print()
        console.print(Panel(
            f"[yellow bold]{len(report.patterns)} ORM anti-pattern(s) detected[/yellow bold]\n\n"
            f"Queries analyzed: {report.queries_analyzed}\n"
            f"Total impact: {report.total_impact:.1f}",
            title="QuerySense ORM Detector",
            border_style="yellow",
        ))

        for pattern in report.patterns:
            sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(
                pattern.severity, "white"
            )
            console.print(
                f"\n  [{sev_color} bold]{pattern.pattern_name}[/{sev_color} bold] "
                f"(impact: {pattern.impact_score:.1f}/10)"
            )
            console.print(f"  {pattern.description}")

            if pattern.affected_table:
                console.print(f"  [dim]Table: {pattern.affected_table}[/dim]")
            if pattern.affected_queries > 1:
                console.print(f"  [dim]Affected queries: {pattern.affected_queries}[/dim]")

            if pattern.suggestion:
                console.print(f"\n  [bold]Fix:[/bold]")
                for line in pattern.suggestion.split("\n"):
                    console.print(f"  {line}")

            if pattern.example_fix:
                console.print(f"\n  [bold]Example:[/bold]")
                for line in pattern.example_fix.split("\n"):
                    console.print(f"  [dim]{line}[/dim]")

        console.print()
