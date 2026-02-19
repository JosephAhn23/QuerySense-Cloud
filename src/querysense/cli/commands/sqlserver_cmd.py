"""
SQL Server CLI commands — native execution plan analysis and DMV-based optimization.

Commands:
    querysense sqlserver analyze <plan.xml>
    querysense sqlserver top-queries --dsn "..."
    querysense sqlserver missing-indexes --dsn "..."
    querysense sqlserver index-usage --dsn "..."
    querysense sqlserver waits --dsn "..."
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()


def register(parent: typer.Typer) -> None:
    """Register SQL Server commands."""

    @parent.command(name="analyze")
    def sqlserver_analyze(
        file: Annotated[Path, typer.Argument(help="SQL Server plan XML file (.sqlplan)")],
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Analyze a SQL Server execution plan (XML format)."""
        from querysense.sqlserver import SQLServerPlanParser, SQLServerAnalyzer

        xml_text = file.read_text(encoding="utf-8")
        parser = SQLServerPlanParser()
        plan = parser.parse(xml_text)

        if not plan.root_operator:
            console.print("[red]Could not parse execution plan.[/]")
            raise typer.Exit(1)

        analyzer = SQLServerAnalyzer()
        findings = analyzer.analyze(plan)

        if output_json:
            data = {
                "statement": plan.statement_text[:200],
                "total_cost": plan.total_subtree_cost,
                "operators": plan.total_operators,
                "parallelism": plan.degree_of_parallelism,
                "missing_indexes": len(plan.missing_indexes),
                "findings": [
                    {"title": f.title, "severity": f.severity,
                     "description": f.description, "fix": f.remediation}
                    for f in findings
                ],
            }
            console.print_json(json.dumps(data, default=str))
            return

        # Plan overview
        console.print(Panel(
            f"[bold]Statement:[/] {plan.statement_text[:120] or 'N/A'}...\n"
            f"[bold]Total cost:[/] {plan.total_subtree_cost:.4f}\n"
            f"[bold]Operators:[/] {plan.total_operators}\n"
            f"[bold]Parallelism:[/] DOP={plan.degree_of_parallelism}\n"
            f"[bold]Memory grant:[/] {plan.memory_grant_kb // 1024}MB\n"
            f"[bold]Missing indexes:[/] {len(plan.missing_indexes)}\n"
            f"[bold]Warnings:[/] {'YES' if plan.has_warnings else 'None'}",
            title="SQL Server Plan Analysis",
        ))

        # Missing indexes
        if plan.missing_indexes:
            console.print("\n[bold cyan]Missing Index Suggestions[/]")
            for mi in plan.missing_indexes:
                console.print(
                    f"  [yellow]Impact: {mi.impact:.1f}%[/] on "
                    f"[{mi.schema}].[{mi.table}]"
                )
                console.print(f"  [green]{mi.command}[/]")
                console.print()

        # Findings
        if findings:
            table = Table(title="Findings")
            table.add_column("Severity", style="bold")
            table.add_column("Title")
            table.add_column("Fix")

            severity_colors = {
                "critical": "red",
                "warning": "yellow",
                "notice": "blue",
                "info": "white",
            }

            for f in findings:
                color = severity_colors.get(f.severity, "white")
                table.add_row(
                    f"[{color}]{f.severity.upper()}[/{color}]",
                    f.title,
                    f.remediation[:80] if f.remediation else "-",
                )

            console.print(table)
        else:
            console.print("[green]No issues found — plan looks efficient.[/]")

    @parent.command(name="top-queries")
    def sqlserver_top_queries(
        dsn: Annotated[str, typer.Option("--dsn", help="SQL Server connection string")],
        top_n: Annotated[int, typer.Option("--top", help="Number of top queries")] = 25,
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Get top queries by elapsed time from DMVs."""
        from querysense.sqlserver import SQLServerProbe

        probe = SQLServerProbe(dsn)
        queries = asyncio.run(probe.get_top_queries(top_n=top_n))

        if output_json:
            console.print_json(json.dumps(queries, default=str))
            return

        if not queries:
            console.print("[yellow]No queries found (or DMV access denied).[/]")
            return

        table = Table(title=f"Top {top_n} Queries by Elapsed Time")
        table.add_column("Avg Time", style="red", justify="right")
        table.add_column("Calls", justify="right")
        table.add_column("Avg Reads", justify="right")
        table.add_column("Query", max_width=60)

        for q in queries:
            avg_ms = q.get("avg_elapsed_us", 0) / 1000
            table.add_row(
                f"{avg_ms:.1f}ms",
                f"{q.get('execution_count', 0):,}",
                f"{q.get('avg_logical_reads', 0):,}",
                str(q.get("query_text", ""))[:60],
            )

        console.print(table)

    @parent.command(name="missing-indexes")
    def sqlserver_missing_indexes(
        dsn: Annotated[str, typer.Option("--dsn", help="SQL Server connection string")],
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Get missing index suggestions from SQL Server DMVs."""
        from querysense.sqlserver import SQLServerProbe

        probe = SQLServerProbe(dsn)
        indexes = asyncio.run(probe.get_missing_indexes())

        if output_json:
            console.print_json(json.dumps(indexes, default=str))
            return

        if not indexes:
            console.print("[green]No missing index suggestions from SQL Server.[/]")
            return

        table = Table(title="SQL Server Missing Index Suggestions")
        table.add_column("Impact", justify="right", style="red")
        table.add_column("Table", style="cyan")
        table.add_column("Equality Cols", style="green")
        table.add_column("Inequality Cols")
        table.add_column("Include Cols")

        for idx in indexes:
            table.add_row(
                f"{idx.get('improvement_measure', 0):,.0f}",
                str(idx.get("full_table", "")),
                str(idx.get("equality_columns", "")),
                str(idx.get("inequality_columns", "")),
                str(idx.get("included_columns", "")),
            )

        console.print(table)

    @parent.command(name="index-usage")
    def sqlserver_index_usage(
        dsn: Annotated[str, typer.Option("--dsn", help="SQL Server connection string")],
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Audit SQL Server index usage statistics."""
        from querysense.sqlserver import SQLServerProbe

        probe = SQLServerProbe(dsn)
        usage = asyncio.run(probe.get_index_usage())

        if output_json:
            console.print_json(json.dumps(usage, default=str))
            return

        table = Table(title="SQL Server Index Usage")
        table.add_column("Table", style="cyan")
        table.add_column("Index", style="green")
        table.add_column("Seeks", justify="right")
        table.add_column("Scans", justify="right")
        table.add_column("Lookups", justify="right")
        table.add_column("Updates", justify="right")
        table.add_column("Status", style="bold")

        for u in usage:
            status = str(u.get("status", ""))
            status_style = "red" if status == "UNUSED" else "green"
            table.add_row(
                str(u.get("table_name", "")),
                str(u.get("index_name", "")),
                f"{u.get('user_seeks', 0):,}",
                f"{u.get('user_scans', 0):,}",
                f"{u.get('user_lookups', 0):,}",
                f"{u.get('user_updates', 0):,}",
                f"[{status_style}]{status}[/{status_style}]",
            )

        console.print(table)

    @parent.command(name="waits")
    def sqlserver_waits(
        dsn: Annotated[str, typer.Option("--dsn", help="SQL Server connection string")],
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Show SQL Server wait statistics for performance diagnosis."""
        from querysense.sqlserver import SQLServerProbe

        probe = SQLServerProbe(dsn)
        waits = asyncio.run(probe.get_wait_stats())

        if output_json:
            console.print_json(json.dumps(waits, default=str))
            return

        table = Table(title="SQL Server Wait Statistics")
        table.add_column("Wait Type", style="cyan")
        table.add_column("Count", justify="right")
        table.add_column("Wait (ms)", justify="right", style="red")
        table.add_column("Signal (ms)", justify="right")
        table.add_column("Resource (ms)", justify="right")

        for w in waits:
            table.add_row(
                str(w.get("wait_type", "")),
                f"{w.get('waiting_tasks_count', 0):,}",
                f"{w.get('wait_time_ms', 0):,}",
                f"{w.get('signal_wait_time_ms', 0):,}",
                f"{w.get('resource_wait_ms', 0):,}",
            )

        console.print(table)
