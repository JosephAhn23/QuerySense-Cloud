"""
Migration safety check command: analyze DDL for risks and generate rollback SQL.

    $ querysense migrate-check --sql "ALTER TABLE orders ADD COLUMN status TEXT NOT NULL;"
    $ querysense migrate-check --file migration.sql
    $ querysense migrate-check --file migration.sql --rollback -o rollback.sql
"""

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
    """Register the migrate-check command on the given Typer app."""

    @app.command(name="migrate-check")
    def migrate_check(
        sql: Annotated[
            Optional[str],
            typer.Option("--sql", "-s", help="SQL migration to check"),
        ] = None,
        file: Annotated[
            Optional[Path],
            typer.Option(
                "--file", "-f",
                help="Path to migration SQL file",
                exists=True,
                readable=True,
            ),
        ] = None,
        rollback: Annotated[
            bool,
            typer.Option("--rollback", "-r", help="Generate rollback SQL"),
        ] = False,
        output_file: Annotated[
            Optional[Path],
            typer.Option("--output", "-o", help="Write rollback SQL to file"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        fail_on_critical: Annotated[
            bool,
            typer.Option("--fail-on-critical", help="Exit code 1 if critical risks found"),
        ] = False,
    ) -> None:
        """
        Check migration SQL for safety risks and generate rollback.

        Analyzes DDL statements for:
        - Exclusive locks (ADD COLUMN NOT NULL without DEFAULT)
        - Missing CONCURRENTLY on index creation
        - Irreversible operations (DROP TABLE/COLUMN)
        - Type changes that require table rewrites
        - Missing lock_timeout settings
        - Foreign key validation overhead

        \b
        Examples:
            # Check inline SQL
            $ querysense migrate-check --sql "ALTER TABLE orders ADD COLUMN status TEXT NOT NULL;"

            # Check migration file
            $ querysense migrate-check --file migration.sql

            # Generate rollback script
            $ querysense migrate-check --file migration.sql --rollback -o rollback.sql

            # CI mode: fail on critical risks
            $ querysense migrate-check --file migration.sql --fail-on-critical --json
        """
        from querysense.migration_safety import (
            check_and_report,
            generate_rollback,
        )
        from querysense.lock_analyzer import LockAnalyzer

        # Get SQL input
        if sql:
            migration_sql = sql
        elif file:
            migration_sql = file.read_text(encoding="utf-8")
        else:
            error_console.print("[red]Error:[/red] Provide --sql or --file")
            raise typer.Exit(code=1)

        report = check_and_report(migration_sql)

        # Lock analysis (P0 feature: van Kampen Thesis 2022)
        lock_analyzer = LockAnalyzer()
        lock_report = lock_analyzer.analyze(migration_sql)

        # JSON output
        if json_output:
            data = report.to_dict()
            data["lock_analysis"] = lock_report.to_dict()
            if rollback:
                data["rollback_sql_text"] = generate_rollback(migration_sql)
            console.print_json(json.dumps(data, default=str))
            if fail_on_critical and (report.has_critical or lock_report.has_critical):
                raise typer.Exit(code=1)
            return

        # Rollback output
        if rollback:
            rb_sql = generate_rollback(migration_sql)
            if output_file:
                output_file.write_text(rb_sql, encoding="utf-8")
                console.print(f"[green]Rollback SQL written to {output_file}[/green]")
            else:
                console.print("[bold]Rollback SQL:[/bold]")
                console.print(rb_sql)
            if not report.risks:
                return

        # Pretty terminal output
        status = "SAFE" if report.safe else "UNSAFE"
        status_color = "green" if report.safe else "red"
        console.print(Panel(
            f"[{status_color} bold]{status}[/{status_color} bold] - "
            f"{len(report.statements)} statement(s) analyzed\n"
            f"{len(report.risks)} risk(s) found",
            title="Migration Safety Check",
            border_style=status_color,
        ))

        if report.risks:
            risk_table = Table(title="Risks Identified")
            risk_table.add_column("Severity", style="bold")
            risk_table.add_column("Rule")
            risk_table.add_column("Message", max_width=50)
            risk_table.add_column("Suggestion", max_width=40, style="dim")

            severity_styles = {
                "critical": "[red]CRIT[/red]",
                "warning": "[yellow]WARN[/yellow]",
                "info": "[blue]INFO[/blue]",
            }

            for risk in report.risks:
                risk_table.add_row(
                    severity_styles.get(risk.severity, risk.severity),
                    risk.rule,
                    risk.message,
                    risk.suggestion,
                )

            console.print(risk_table)

        if not report.risks:
            console.print("[green]No safety risks identified.[/green]")

        # ── Lock Analysis Report (P0: addresses van Kampen 2022) ──────
        if lock_report.statements:
            console.print()
            lock_color = {"critical": "red", "warning": "yellow", "safe": "green", "info": "blue"}
            overall_color = lock_color.get(lock_report.overall_risk, "white")

            console.print(Panel(
                f"[{overall_color} bold]{lock_report.overall_risk.upper()}[/{overall_color} bold] - "
                f"Estimated downtime: {lock_report.total_estimated_downtime}",
                title="[bold]Lock Impact Analysis[/bold]",
                subtitle="(Based on van Kampen 2022 — Zero-Downtime Migrations)",
                border_style=overall_color,
            ))

            lock_table = Table(title="Lock Analysis Per Statement", show_lines=True)
            lock_table.add_column("Risk", width=8)
            lock_table.add_column("Lock Type", width=20)
            lock_table.add_column("Blocks", width=20)
            lock_table.add_column("Duration", width=20)
            lock_table.add_column("Statement", max_width=40)

            for lr in lock_report.statements:
                risk_style = lock_color.get(lr.risk_level, "white")
                lock_table.add_row(
                    f"[{risk_style}]{lr.risk_level.upper()}[/{risk_style}]",
                    lr.lock_type,
                    lr.lock_blocks,
                    lr.estimated_duration,
                    lr.statement[:80],
                )

            console.print(lock_table)

            # Show safe alternatives
            for lr in lock_report.statements:
                if lr.safe_alternative:
                    console.print(f"\n  [yellow]⚠ {lr.statement[:60]}...[/yellow]")
                    console.print(f"    [green]Safe alternative:[/green] {lr.safe_alternative}")

            # Show phased plans for critical statements
            critical_stmts = [lr for lr in lock_report.statements if lr.phased_plan and lr.risk_level in ("critical", "warning")]
            if critical_stmts:
                console.print(f"\n[bold cyan]Expand-Contract Phased Plans (Zero-Downtime):[/bold cyan]")
                for lr in critical_stmts:
                    console.print(f"\n  [bold]For: {lr.statement[:60]}...[/bold]")
                    for line in lr.phased_plan:
                        if line.startswith("--"):
                            console.print(f"    [dim]{line}[/dim]")
                        elif line.strip():
                            console.print(f"    [cyan]{line}[/cyan]")
                        else:
                            console.print()

            # Recommendations
            if lock_report.recommendations:
                console.print(f"\n[bold]Recommendations:[/bold]")
                for rec in lock_report.recommendations:
                    console.print(f"  • {rec}")

        if report.rollback_sql:
            console.print(f"\n[dim]{len(report.rollback_sql)} rollback statement(s) available. "
                          f"Use --rollback to see them.[/dim]")

        if fail_on_critical and (report.has_critical or lock_report.has_critical):
            raise typer.Exit(code=1)
