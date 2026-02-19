"""
CLI commands for the unified advisor framework.

Commands:
    querysense advisor run [--all | --category=SECURITY | --check=postgres_ssl]
    querysense advisor list [--category=VACUUM]
    querysense advisor status
"""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)

advisor_app = typer.Typer(
    name="advisor",
    help="Unified advisor framework — Percona-grade automated health checks",
    no_args_is_help=True,
)


def register_advisor(app: typer.Typer) -> None:
    """Register advisor commands."""

    @app.command()
    def run(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        category: Annotated[
            str | None,
            typer.Option("--category", "-c", help="Filter by category (security, configuration, vacuum, replication, performance)"),
        ] = None,
        check_name: Annotated[
            str | None,
            typer.Option("--check", help="Run a specific check by name"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        verbose: Annotated[
            bool,
            typer.Option("--verbose", "-v", help="Show detailed findings"),
        ] = False,
        fail_on_critical: Annotated[
            bool,
            typer.Option("--fail-on-critical", help="Exit code 1 if critical issues found (CI mode)"),
        ] = False,
    ) -> None:
        """
        Run advisor checks against a PostgreSQL database.

        By default runs ALL checks. Use --category or --check to filter.

        \\b
        Categories:
            security       — SSL, passwords, superusers, pg_hba
            configuration  — Memory, WAL, connections, planner, logging
            vacuum         — Bloat, XID wraparound, autovacuum tuning
            replication    — Lag, stale slots, WAL archiver
            performance    — Cache hit ratio, lock contention, temp files

        \\b
        Examples:
            # Run all checks
            $ querysense advisor run --dsn $DB_URL

            # Security audit only
            $ querysense advisor run --dsn $DB_URL --category security

            # Single check
            $ querysense advisor run --dsn $DB_URL --check postgres_ssl_enabled

            # CI mode (exit 1 on critical)
            $ querysense advisor run --dsn $DB_URL --fail-on-critical --json
        """
        import asyncio

        from querysense.advisor.base import AdvisorCategory
        from querysense.advisor.registry import AdvisorRegistry

        registry = AdvisorRegistry()
        registry.auto_discover()

        async def _run() -> None:
            try:
                import asyncpg  # type: ignore[import-untyped]
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg required. Install with: pip install asyncpg"
                )
                raise typer.Exit(code=1)

            conn = await asyncpg.connect(dsn)
            try:
                if check_name:
                    result = await registry.run_check(check_name, conn)
                    report_results = [result]
                    # Wrap in a minimal report
                    from querysense.advisor.registry import AdvisorReport
                    report = AdvisorReport(results=report_results)
                elif category:
                    try:
                        cat = AdvisorCategory(category.lower())
                    except ValueError:
                        error_console.print(
                            f"[red]Error:[/red] Unknown category '{category}'. "
                            f"Options: {', '.join(c.value for c in AdvisorCategory)}"
                        )
                        raise typer.Exit(code=1)
                    report = await registry.run_category(cat, conn)
                else:
                    report = await registry.run_all(conn)
            finally:
                await conn.close()

            # Output
            if json_output:
                console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            else:
                _display_report(report, verbose)

            if fail_on_critical and report.critical_count > 0:
                raise typer.Exit(code=1)

        asyncio.run(_run())

    @app.command(name="list")
    def list_checks(
        category: Annotated[
            str | None,
            typer.Option("--category", "-c", help="Filter by category"),
        ] = None,
    ) -> None:
        """
        List all available advisor checks.

        Shows check name, category, interval, and description.
        """
        from querysense.advisor.base import AdvisorCategory
        from querysense.advisor.registry import AdvisorRegistry

        registry = AdvisorRegistry()
        registry.auto_discover()

        cat_filter = None
        if category:
            try:
                cat_filter = AdvisorCategory(category.lower())
            except ValueError:
                error_console.print(f"[red]Error:[/red] Unknown category '{category}'")
                raise typer.Exit(code=1)

        checks = registry.list_checks(category=cat_filter)

        table = Table(title=f"Advisor Checks ({len(checks)} total)")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Category", style="bold")
        table.add_column("Interval", style="dim")
        table.add_column("Description")

        cat_colors = {
            "security": "red",
            "configuration": "yellow",
            "vacuum": "magenta",
            "replication": "blue",
            "performance": "green",
            "query": "cyan",
            "schema": "dim",
        }

        for c in checks:
            cat_color = cat_colors.get(c.category.value, "dim")
            table.add_row(
                c.name,
                f"[{cat_color}]{c.category.value}[/{cat_color}]",
                c.interval.value,
                c.description,
            )

        console.print(table)
        console.print(f"\n[dim]Run a check: querysense advisor run --check <name> --dsn $DB_URL[/dim]")

    @app.command()
    def status() -> None:
        """
        Show advisor framework status and check counts.
        """
        from querysense.advisor.base import AdvisorCategory
        from querysense.advisor.registry import AdvisorRegistry

        registry = AdvisorRegistry()
        registry.auto_discover()

        console.print(Panel.fit(
            f"[bold]Total checks:[/bold] {registry.check_count}\n"
            f"[bold]Categories:[/bold] {len(AdvisorCategory)}\n"
            f"\n[bold]By category:[/bold]",
            title="Advisor Framework Status",
            border_style="blue",
        ))

        for cat in AdvisorCategory:
            checks = registry.list_checks(category=cat)
            if checks:
                console.print(f"  [{cat.value:15}] {len(checks):2d} checks")

        console.print(f"\n[dim]Run: querysense advisor run --dsn $DB_URL[/dim]")


# ------------------------------------------------------------------
# Display helpers
# ------------------------------------------------------------------


def _display_report(report: "AdvisorReport", verbose: bool) -> None:
    """Render advisor report with Rich formatting."""
    from querysense.advisor.base import CheckSeverity
    from querysense.advisor.registry import AdvisorReport

    # Header
    score = report.score
    grade = report.grade
    if score >= 90:
        score_color = "green"
    elif score >= 70:
        score_color = "yellow"
    else:
        score_color = "red"

    console.print()
    console.print(Panel.fit(
        f"[bold]Health Score:[/bold] [{score_color}]{score}/100 ({grade})[/{score_color}]\n"
        f"[bold]Checks run:[/bold] {report.checks_run}\n"
        f"[bold]Passed:[/bold] [green]{report.passed_count}[/green] | "
        f"[bold]Failed:[/bold] [red]{report.failed_count}[/red]\n"
        f"[bold]Critical:[/bold] [red]{report.critical_count}[/red] | "
        f"[bold]Warnings:[/bold] [yellow]{report.warning_count}[/yellow]\n"
        f"[bold]Time:[/bold] {report.elapsed_ms:.0f}ms",
        title="QuerySense Advisor Report",
        border_style="blue",
    ))

    # Results table
    severity_icons = {
        "emergency": "[red bold]!!![/red bold]",
        "critical": "[red]!!![/red]",
        "warning": "[yellow]!![/yellow]",
        "notice": "[cyan]![/cyan]",
        "info": "[dim]i[/dim]",
        "pass": "[green]OK[/green]",
    }

    # Group by category
    for cat_name, results in sorted(report.by_category().items()):
        console.print(f"\n[bold]{cat_name.upper()}[/bold]")

        table = Table(show_header=True, box=None, pad_edge=False)
        table.add_column("", width=4)
        table.add_column("Check", style="cyan", no_wrap=True)
        table.add_column("Status", width=30)
        table.add_column("Time", justify="right", style="dim")

        for r in results:
            icon = severity_icons.get(r.severity.value, "[dim]?[/dim]")
            if r.error:
                status = f"[red]ERROR: {r.error[:40]}[/red]"
            elif r.passed:
                status = "[green]Passed[/green]"
            else:
                status = r.summary
            table.add_row(icon, r.check_name, status, f"{r.elapsed_ms:.0f}ms")

        console.print(table)

    # Verbose: show all findings
    if verbose:
        console.print("\n[bold]Detailed Findings:[/bold]")
        for r in report.results:
            for f in r.findings:
                sev_icon = severity_icons.get(f.severity.value, "")
                console.print(f"\n  {sev_icon} [bold]{f.title}[/bold]")
                console.print(f"    {f.description}")
                if f.recommendation:
                    console.print(f"    [green]Fix:[/green] {f.recommendation}")
                if f.fix_sql:
                    console.print(f"    [cyan]SQL:[/cyan] {f.fix_sql}")

    console.print()


# ------------------------------------------------------------------
# Stub registrations expected by main.py
# ------------------------------------------------------------------


def register_log_parser(app: typer.Typer) -> None:
    """Register PostgreSQL log parser commands (placeholder)."""

    @app.command()
    def parse_log(
        log_file: Annotated[
            str,
            typer.Argument(help="Path to PostgreSQL log file"),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Parse PostgreSQL log file for slow queries and errors (coming soon)."""
        console.print(f"[dim]Log parsing for {log_file} — coming soon.[/dim]")


def register_patroni(app: typer.Typer) -> None:
    """Register Patroni HA cluster commands (placeholder)."""

    @app.command()
    def cluster_status(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
    ) -> None:
        """Show Patroni cluster status (coming soon)."""
        console.print("[dim]Patroni cluster status — coming soon.[/dim]")
