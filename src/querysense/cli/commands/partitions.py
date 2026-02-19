"""
Partition advisor CLI command.

Analyzes tables for partitioning opportunities and checks existing partition health.
Closes the pganalyze gap: "Partition advisor — suggests partitioning strategies
based on query patterns."

    $ querysense audit partitions --dsn postgresql://localhost/mydb
    $ querysense audit partitions --dsn $DB_URL --json
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(audit_app: typer.Typer) -> None:
    """Register partition advisor command on the audit sub-app."""

    @audit_app.command(name="partitions")
    def audit_partitions(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        min_rows: Annotated[
            int,
            typer.Option("--min-rows", help="Minimum rows to consider for partitioning"),
        ] = 1_000_000,
    ) -> None:
        """
        Analyze tables for partitioning opportunities.

        Detects large unpartitioned tables, suggests RANGE/LIST/HASH strategies
        based on column types and access patterns. Also checks existing
        partitioned tables for health issues (imbalance, too many partitions).

        Equivalent to pganalyze's Partition Advisor — but free and CLI-first.

        \b
        Examples:
            # Full partition analysis
            $ querysense audit partitions --dsn postgresql://localhost/mydb

            # Lower threshold for smaller databases
            $ querysense audit partitions --dsn $DB_URL --min-rows 100000
        """
        from querysense.partition_advisor import PartitionAdvisor

        async def _run() -> dict:
            try:
                import asyncpg
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg required.\n"
                    "Install: pip install querysense[db]"
                )
                raise typer.Exit(code=1)

            try:
                conn = await asyncpg.connect(dsn)
            except Exception as e:
                error_console.print(f"[red]Connection failed:[/red] {e}")
                raise typer.Exit(code=1)

            try:
                advisor = PartitionAdvisor()
                advisor.MIN_ROWS_FOR_PARTITION = min_rows
                queries = advisor.get_catalog_queries()

                table_stats = [dict(r) for r in await conn.fetch(queries["large_tables"])]
                columns = [dict(r) for r in await conn.fetch(queries["columns"])]
                partitioned = [dict(r) for r in await conn.fetch(queries["partitioned"])]

                report = advisor.analyze_from_data(table_stats, columns, partitioned)
                return report.to_dict()
            finally:
                await conn.close()

        result = asyncio.run(_run())

        if json_output:
            console.print_json(json.dumps(result, indent=2, default=str))
            return

        # Rich output
        console.print(Panel(
            f"[bold]{result.get('summary', '')}[/bold]",
            title="[bold]QuerySense Partition Advisor[/bold]",
            subtitle="Closes pganalyze partition advisor gap",
        ))

        candidates = result.get("candidates", [])
        if candidates:
            console.print("\n[bold]Partition Candidates:[/bold]\n")

            for c in candidates:
                severity = c.get("severity", "info")
                sev_style = {"critical": "red bold", "warning": "yellow", "info": "blue"}.get(severity, "white")

                console.print(
                    f"  [{sev_style}][{severity.upper()}][/{sev_style}] "
                    f"[cyan]{c.get('table', '')}[/cyan] — "
                    f"{c.get('rows', 0):,} rows ({c.get('size_mb', 0):.0f}MB)"
                )
                console.print(f"    Strategy: [bold]{c.get('strategy', '').upper()}[/bold] on [{c.get('partition_key', '')}]")
                console.print(f"    {c.get('rationale', '')}")
                console.print(f"    [green]{c.get('improvement', '')}[/green]")

                sql_lines = c.get("sql", [])
                if sql_lines:
                    console.print()
                    sql_text = "\n".join(sql_lines)
                    console.print(Syntax(sql_text, "sql", theme="monokai", line_numbers=False))
                console.print()
        else:
            console.print("\n[green]✓ No tables need partitioning.[/green]")

        issues = result.get("issues", [])
        if issues:
            console.print("\n[bold]Partition Health Issues:[/bold]\n")
            for issue in issues:
                sev = issue.get("severity", "info")
                style = {"critical": "red bold", "warning": "yellow"}.get(sev, "blue")
                console.print(
                    f"  [{style}][{sev.upper()}][/{style}] "
                    f"[cyan]{issue.get('table', '')}[/cyan] — {issue.get('description', '')}"
                )
                console.print(f"    Fix: {issue.get('fix', '')}")
