"""
Predict command: migration impact prediction.

The killer feature — analyze a migration SQL before running it.

    $ querysense predict "ALTER TABLE orders ADD COLUMN user_id INT;"
    $ querysense predict --file migration.sql
    $ querysense predict --file migration.sql --dsn postgresql://localhost/mydb
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register predict command on the given Typer app."""

    @app.command()
    def predict(
        sql: Annotated[
            Optional[str],
            typer.Argument(
                help="SQL migration statement(s) to analyze",
            ),
        ] = None,
        file: Annotated[
            Optional[Path],
            typer.Option(
                "--file", "-f",
                help="Path to migration SQL file",
            ),
        ] = None,
        dsn: Annotated[
            Optional[str],
            typer.Option(
                "--dsn",
                help="PostgreSQL DSN for refined estimates (reads table sizes)",
                envvar="QUERYSENSE_DSN",
            ),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        generate_safe: Annotated[
            bool,
            typer.Option(
                "--safe/--no-safe",
                help="Generate safe migration plan",
            ),
        ] = True,
    ) -> None:
        """
        Predict the impact of a SQL migration before running it.

        Analyzes lock duration, data impact, performance changes,
        and generates a safe migration plan with rollback SQL.

        Examples:

            $ querysense predict "ALTER TABLE orders ADD COLUMN user_id INT NOT NULL;"
            $ querysense predict --file migrations/001_add_users.sql
            $ querysense predict --file migration.sql --dsn postgresql://prod/app --json
        """
        # Get SQL input
        migration_sql = sql
        if file:
            if not file.exists():
                error_console.print(f"[red]Error:[/red] File not found: {file}")
                raise typer.Exit(code=1)
            migration_sql = file.read_text(encoding="utf-8")

        if not migration_sql:
            error_console.print(
                "[red]Error:[/red] Provide SQL as an argument or via --file"
            )
            raise typer.Exit(code=1)

        # Get table sizes from live DB if DSN provided
        table_sizes: dict[str, int] = {}
        if dsn:
            import asyncio
            try:
                table_sizes = asyncio.run(_fetch_table_sizes(dsn))
                console.print(
                    f"[dim]Connected to database, loaded {len(table_sizes)} table sizes[/dim]\n"
                )
            except Exception as e:
                console.print(
                    f"[yellow]Warning:[/yellow] Could not connect to database: {e}\n"
                    f"[dim]Continuing with offline estimates[/dim]\n"
                )

        # Analyze
        from querysense.migration import MigrationAnalyzer

        analyzer = MigrationAnalyzer(table_sizes=table_sizes)
        report = analyzer.analyze(migration_sql)

        # Output
        if json_output:
            console.print_json(json.dumps(report.format_json(), indent=2))
            return

        _render_report(report, generate_safe)


def _render_report(report: "MigrationReport", show_safe_plan: bool) -> None:  # type: ignore[name-defined]
    """Rich terminal output for migration report."""
    from querysense.migration import RiskLevel

    # Risk banner
    risk_colors = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "red bold",
    }
    risk_color = risk_colors.get(report.overall_risk.value, "white")

    console.print(
        Panel(
            f"[{risk_color}]Overall Risk: {report.overall_risk.value.upper()}[/{risk_color}]\n"
            f"Statements: {len(report.statements)}",
            title="[bold cyan]MIGRATION IMPACT PREDICTION[/bold cyan]",
            border_style="cyan",
        )
    )

    # Lock Analysis
    if report.lock_analyses:
        lock_table = Table(title="Lock Analysis")
        lock_table.add_column("Table", style="cyan")
        lock_table.add_column("Lock Level")
        lock_table.add_column("Duration")
        lock_table.add_column("Blocks")
        lock_table.add_column("Impact")

        for la in report.lock_analyses:
            if la.blocks_reads:
                blocks = "[red bold]READS + WRITES[/red bold]"
            elif la.blocks_writes:
                blocks = "[yellow]WRITES[/yellow]"
            else:
                blocks = "[green]none[/green]"

            dur = "unknown"
            if la.estimated_duration_ms is not None:
                if la.estimated_duration_ms < 100:
                    dur = f"[green]{la.estimated_duration_ms:.0f}ms[/green]"
                elif la.estimated_duration_ms < 5000:
                    dur = f"[yellow]{la.estimated_duration_ms:.0f}ms[/yellow]"
                else:
                    dur = f"[red]{la.estimated_duration_ms / 1000:.1f}s[/red]"

            lock_table.add_row(
                la.affected_table or "?",
                la.lock_level.value,
                dur,
                blocks,
                la.concurrent_query_impact[:60],
            )

        console.print(lock_table)
        console.print()

        # Recommendations
        for la in report.lock_analyses:
            if la.recommendation:
                console.print(f"  [bold]Recommendation:[/bold] {la.recommendation}")

    # Data Impact
    if report.data_impacts:
        console.print("\n[bold]Data Impact[/bold]")
        for di in report.data_impacts:
            if di.data_loss_risk:
                icon = "[red bold][DANGER][/red bold]"
            elif di.requires_rewrite:
                icon = "[yellow][!!][/yellow]"
            else:
                icon = "[green][OK][/green]"

            console.print(f"  {icon} {di.operation} on {di.table}")
            if di.column:
                console.print(f"      Column: {di.column}")
            if di.details:
                console.print(f"      [dim]{di.details}[/dim]")

    # Performance Impact
    if report.performance_impacts:
        console.print("\n[bold]Performance Impact[/bold]")
        for pi in report.performance_impacts:
            color = {
                "low": "green", "medium": "yellow",
                "high": "red", "critical": "red bold",
            }.get(pi.severity.value, "white")
            console.print(f"  [{color}][{pi.severity.value.upper()}][/{color}] {pi.description}")
            if pi.recommendation:
                console.print(f"      [bold]Fix:[/bold] {pi.recommendation}")

    # Rollback SQL
    if report.rollback_sql:
        console.print("\n[bold]Rollback SQL[/bold]")
        rollback = "\n".join(report.rollback_sql)
        console.print(Syntax(rollback, "sql", theme="monokai"))

    # Safe Migration Plan
    if show_safe_plan and report.safe_plan:
        console.print()
        console.print(
            Panel(
                _format_safe_plan(report.safe_plan),
                title="[bold magenta]GENERATED SAFE MIGRATION[/bold magenta]",
                border_style="magenta",
            )
        )

    # Warnings
    if report.warnings:
        console.print("\n[bold yellow]Warnings[/bold yellow]")
        for w in report.warnings:
            console.print(f"  [yellow][!!][/yellow] {w}")


def _format_safe_plan(steps: list) -> str:
    """Format safe migration plan as text."""
    lines: list[str] = []
    for step in steps:
        lines.append(f"Phase {step.phase}: {step.description}")
        lines.append(f"  Lock: {step.lock_level} | Duration: {step.estimated_duration}")
        for sql_line in step.sql.split("\n"):
            lines.append(f"  {sql_line}")
        if step.notes:
            lines.append(f"  Note: {step.notes}")
        lines.append("")
    return "\n".join(lines)


async def _fetch_table_sizes(dsn: str) -> dict[str, int]:
    """Fetch table row counts from a live database."""
    from querysense.db import DBBudget, get_probe

    budget = DBBudget(max_queries=10, max_time_seconds=10.0)
    probe = await get_probe(dsn, budget=budget)

    sizes: dict[str, int] = {}
    if hasattr(probe, "_pool") and probe._pool is not None:  # type: ignore[union-attr]
        async with probe._pool.acquire() as conn:  # type: ignore[union-attr]
            rows = await conn.fetch(
                "SELECT relname, reltuples::BIGINT AS row_count "
                "FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid "
                "WHERE n.nspname = 'public' AND c.relkind = 'r'"
            )
            for row in rows:
                sizes[row["relname"]] = max(0, row["row_count"])

    return sizes
