"""CLI command: querysense cost-compare — show what competitors would charge."""

from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register(app: typer.Typer) -> None:
    """Register cost-compare command."""

    @app.command("cost-compare")
    def cost_compare(
        hosts: Annotated[
            int,
            typer.Option("--hosts", "-h", help="Number of database hosts"),
        ] = 5,
        queries: Annotated[
            int,
            typer.Option("--queries", "-q", help="Average queries per day"),
        ] = 50_000,
        months: Annotated[
            int,
            typer.Option("--months", "-m", help="Months you've been using QuerySense"),
        ] = 12,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        social: Annotated[
            bool,
            typer.Option("--social", help="Include shareable summary for social media"),
        ] = False,
        markdown: Annotated[
            bool,
            typer.Option("--markdown", help="Output as Markdown table"),
        ] = False,
    ) -> None:
        """
        Show what database monitoring competitors would charge for your workload.

        QuerySense is free forever. See how much you're saving.

        \\b
        Examples:
            $ querysense cost-compare --hosts 5 --queries 50000
            $ querysense cost-compare --hosts 10 --queries 200000 --social
            $ querysense cost-compare --json
        """
        from querysense.cost_compare import (
            calculate_savings,
            format_report,
            format_report_markdown,
        )

        report = calculate_savings(
            hosts=hosts,
            queries_per_day=queries,
            months_using=months,
        )

        if json_output:
            console.print_json(report.to_json())
            return

        if markdown:
            console.print(format_report_markdown(report))
            return

        # Rich terminal output
        console.print()
        console.print(Panel(
            "[bold green]WHAT COMPETITORS WOULD CHARGE[/bold green]",
            title="QuerySense Cost Calculator",
            border_style="green",
        ))

        console.print(
            f"\n  [bold]Your workload:[/bold] {queries:,} queries/day, {hosts} hosts\n"
        )

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Competitor", style="white")
        table.add_column("Monthly", justify="right", style="red")
        table.add_column("Annual", justify="right", style="red")
        table.add_column("Notes", style="dim", max_width=45)

        for comp in sorted(report.competitors, key=lambda c: -c.annual_cost):
            if comp.monthly_cost > 0:
                table.add_row(
                    comp.competitor,
                    f"${comp.monthly_cost:,.0f}",
                    f"${comp.annual_cost:,.0f}",
                    comp.notes[:45] if comp.notes else "",
                )

        table.add_row(
            "[bold green]QuerySense[/bold green]",
            "[bold green]$0[/bold green]",
            "[bold green]$0[/bold green]",
            "[green]Free forever, open source[/green]",
            style="green",
        )

        console.print(table)

        console.print(
            f"\n  [bold green]Maximum annual savings: "
            f"${report.total_max_annual_savings:,.0f}[/bold green]"
        )
        console.print(
            f"  [green]Average annual savings: "
            f"${report.total_avg_annual_savings:,.0f}[/green]"
        )

        if months > 0:
            cumulative = report.total_avg_annual_savings * (months / 12)
            console.print(
                f"  [bold]Since you started: ~${cumulative:,.0f} saved "
                f"over {months} months[/bold]"
            )

        if social:
            console.print()
            top = sorted(report.competitors, key=lambda c: -c.annual_cost)[0]
            console.print(Panel(
                f'[bold]"Switched from {top.competitor} to QuerySense.\n'
                f'Saving ${top.annual_savings:,.0f}/year.\n'
                f'Same features. Zero cost. #QuerySense #OpenSource"[/bold]',
                title="Share This",
                border_style="blue",
            ))

        console.print()
