"""CLI command: querysense wizard — step-by-step optimization coaching."""

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
    """Register the wizard command."""

    @app.command()
    def wizard(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN JSON file",
                exists=True,
                readable=True,
            ),
        ],
        sql_file: Annotated[
            Optional[Path],
            typer.Option(
                "--sql", "-s",
                help="Optional SQL file for additional context",
                exists=True,
                readable=True,
            ),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Step-by-step optimization wizard for your query.

        The wizard walks you through fixing your slow query in priority order:
        1. Check if statistics are stale (most common root cause)
        2. Identify missing indexes (biggest impact for OLTP)
        3. Fix disk spill and memory issues
        4. Suggest SQL rewrites
        5. Recommend configuration changes
        6. Tell you how to verify the improvement

        Based on the Ultimate Optimization Algorithm from
        "PostgreSQL Query Optimization" (Dombrovskaya et al., 2024).

        \\b
        Examples:
            $ querysense wizard plan.json
            $ querysense wizard plan.json --sql query.sql
            $ querysense wizard plan.json --json
        """
        from querysense.parser import parse_explain
        from querysense.engine import AnalysisService
        from querysense.wizard import run_wizard

        try:
            explain = parse_explain(explain_file)
        except Exception as e:
            error_console.print(f"[red]Parse error:[/red] {e}")
            raise typer.Exit(code=2)

        sql = sql_file.read_text(encoding="utf-8") if sql_file else None

        # Run analysis first
        service = AnalysisService()
        result = service.analyze(explain, sql=sql)

        # Run wizard
        wizard_result = run_wizard(
            plan=explain.plan,
            findings=result.findings,
            sql=sql,
        )

        if json_output:
            console.print_json(json.dumps(wizard_result.to_dict(), indent=2))
            return

        # Rich output
        class_color = {
            "short": "cyan",
            "long": "magenta",
            "mixed": "yellow",
        }.get(wizard_result.query_class, "white")

        console.print()
        console.print(Panel(
            f"[bold]Query Type: [{class_color}]{wizard_result.query_class.upper()}[/{class_color}][/bold]\n\n"
            f"Total steps: {wizard_result.total_steps}\n"
            f"Critical actions: {wizard_result.critical_steps}",
            title="QuerySense Optimization Wizard",
            border_style="blue",
        ))

        for step in wizard_result.steps:
            if step.status == "done":
                icon = "[green][x][/green]"
                style = "dim"
            elif step.status == "skipped":
                icon = "[dim][-][/dim]"
                style = "dim"
            else:
                icon = "[yellow][ ][/yellow]"
                style = ""

            cat_badge = {
                "index": "[red]INDEX[/red]",
                "statistics": "[magenta]STATS[/magenta]",
                "config": "[blue]CONFIG[/blue]",
                "rewrite": "[cyan]REWRITE[/cyan]",
                "verify": "[green]VERIFY[/green]",
                "analyze": "[dim]INFO[/dim]",
            }.get(step.category, step.category)

            console.print(
                f"\n  {icon} [bold]Step {step.number}[/bold]: {step.title} {cat_badge}"
            )
            console.print(f"     [{style}]{step.explanation}[/{style}]" if style else f"     {step.explanation}")

            if step.action_sql:
                console.print(f"     [bold green]SQL:[/bold green] {step.action_sql}")
            if step.action_config:
                console.print(f"     [bold blue]Config:[/bold blue] {step.action_config}")
            if step.action_manual:
                console.print(f"     [bold]Action:[/bold] {step.action_manual}")
            if step.expected_improvement:
                console.print(f"     [bold yellow]Expected:[/bold yellow] {step.expected_improvement}")

        if wizard_result.summary:
            console.print(f"\n  [bold]Summary:[/bold] {wizard_result.summary}")
        if wizard_result.estimated_total_improvement:
            console.print(f"  {wizard_result.estimated_total_improvement}")

        console.print()

    @app.command("classify")
    def classify(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN JSON file",
                exists=True,
                readable=True,
            ),
        ],
        sql_file: Annotated[
            Optional[Path],
            typer.Option("--sql", "-s", help="Optional SQL file"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Classify a query as SHORT (OLTP) or LONG (OLAP) and show optimization path.

        Short queries need indexes and low latency.
        Long queries need parallelism and memory.

        \\b
        Examples:
            $ querysense classify plan.json
            $ querysense classify plan.json --sql query.sql
        """
        from querysense.parser import parse_explain
        from querysense.query_classifier import classify_query

        try:
            explain = parse_explain(explain_file)
        except Exception as e:
            error_console.print(f"[red]Parse error:[/red] {e}")
            raise typer.Exit(code=2)

        sql = sql_file.read_text(encoding="utf-8") if sql_file else None
        classification = classify_query(explain.plan, sql=sql)

        if json_output:
            console.print_json(json.dumps(classification.to_dict(), indent=2))
            return

        class_color = {
            "short": "cyan",
            "long": "magenta",
            "mixed": "yellow",
        }.get(classification.query_class.value, "white")

        console.print()
        console.print(Panel(
            f"[{class_color} bold]{classification.query_class.value.upper()} QUERY[/{class_color} bold]\n\n"
            f"Confidence: {classification.confidence:.0%}\n"
            f"Tables: {classification.tables_touched} | "
            f"Rows: {classification.estimated_rows:,} | "
            f"Max scan: {classification.max_scan_rows:,}\n"
            f"Aggregation: {'Yes' if classification.has_aggregation else 'No'} | "
            f"Sorting: {'Yes' if classification.has_sorting else 'No'} | "
            f"Joins: {'Yes' if classification.has_joins else 'No'}",
            title="Query Classification",
            border_style=class_color,
        ))

        if classification.signals:
            console.print("[bold]Signals:[/bold]")
            for signal in classification.signals:
                console.print(f"  - {signal}")

        if classification.optimization_path:
            console.print(f"\n[bold]Optimization Path ({classification.query_class.value.upper()}):[/bold]")
            for step in classification.optimization_path:
                priority_color = {"required": "red", "recommended": "yellow", "optional": "dim"}.get(step.priority, "")
                console.print(
                    f"  {step.order}. [{priority_color}][{step.priority}][/{priority_color}] {step.action}"
                )
                if step.sql_example:
                    console.print(f"     [dim]{step.sql_example[:80]}[/dim]")
                if step.config_change:
                    console.print(f"     [dim]{step.config_change[:80]}[/dim]")

        console.print()
