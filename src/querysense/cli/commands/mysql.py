"""
MySQL analysis commands — production-ready MySQL/MariaDB support.

    $ querysense mysql analyze explain.json
    $ querysense mysql fix explain.json --flyway
    $ querysense mysql scan --dsn mysql://localhost/mydb
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
    """Register MySQL commands on the given Typer app."""

    @app.command()
    def analyze(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to MySQL EXPLAIN FORMAT=JSON output",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Analyze a MySQL EXPLAIN FORMAT=JSON plan.

        Detects full table scans, missing indexes, filesort, temporary tables,
        and row examination inefficiencies.

        Examples:

            $ querysense mysql analyze mysql_plan.json
            $ querysense mysql analyze mysql_plan.json --json
        """
        from querysense.parser.mysql_parser import parse_mysql_explain, ParseError
        from querysense.analyzer.rules.mysql_rules import MySQLAnalyzer

        try:
            plan = parse_mysql_explain(explain_file)
        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            if e.detail:
                error_console.print(f"\n[dim]{e.detail}[/dim]")
            raise typer.Exit(code=1)

        analyzer = MySQLAnalyzer()
        findings = analyzer.analyze(plan)

        if json_output:
            data = {
                "engine": "mysql",
                "total_cost": plan.total_cost,
                "tables": plan.tables_accessed,
                "findings_count": len(findings),
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "title": f.title,
                        "description": f.description,
                        "suggestion": f.suggestion,
                        "table": f.table_name,
                        "impact_score": f.impact_score,
                        "metrics": f.metrics,
                    }
                    for f in findings
                ],
            }
            console.print_json(json.dumps(data, indent=2))
            return

        # Rich output
        console.print(Panel(
            f"[bold]MySQL EXPLAIN Analysis[/bold]\n"
            f"Query cost: [cyan]{plan.total_cost:,.1f}[/cyan] | "
            f"Tables: [cyan]{len(plan.tables_accessed)}[/cyan] | "
            f"Findings: [cyan]{len(findings)}[/cyan]",
            border_style="blue",
        ))

        if not findings:
            console.print("[green]No performance issues found.[/green]")
            return

        for f in findings:
            sev_style = {
                "critical": "red bold",
                "warning": "yellow",
                "info": "blue",
            }.get(f.severity, "white")

            console.print(
                f"[{sev_style}][{f.severity.upper()}][/{sev_style}] {f.title}"
            )

            # Impact bar
            if f.impact_score > 0:
                filled = int(f.impact_score)
                bar = "█" * filled + "░" * (10 - filled)
                score_color = "red" if f.impact_score >= 7 else (
                    "yellow" if f.impact_score >= 4 else "blue"
                )
                console.print(
                    f"   [{score_color}]Impact: {bar} {f.impact_score:.1f}/10[/{score_color}]"
                )

            console.print(f"   [dim]{f.description}[/dim]")

            if f.suggestion:
                console.print(f"\n   [bold]Fix:[/bold]")
                for line in f.suggestion.split("\n"):
                    if line.strip().startswith("--"):
                        console.print(f"   [dim]{line}[/dim]")
                    elif line.strip():
                        console.print(f"   [green]{line}[/green]")

            console.print()

    @app.command()
    def fix(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to MySQL EXPLAIN FORMAT=JSON output",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        flyway: Annotated[
            bool, typer.Option("--flyway", help="Generate Flyway migration"),
        ] = False,
        liquibase: Annotated[
            bool, typer.Option("--liquibase", help="Generate Liquibase changeset"),
        ] = False,
        migration_dir: Annotated[
            str, typer.Option("--migration-dir", "-d"),
        ] = "migrations",
        description: Annotated[
            str, typer.Option("--desc"),
        ] = "mysql_performance_fix",
    ) -> None:
        """
        Output SQL fixes for MySQL performance issues.

        Supports migration generation for Flyway and Liquibase.

        Examples:

            $ querysense mysql fix mysql_plan.json
            $ querysense mysql fix mysql_plan.json --flyway
            $ querysense mysql fix mysql_plan.json | mysql -u root mydb
        """
        from querysense.parser.mysql_parser import parse_mysql_explain, ParseError
        from querysense.analyzer.rules.mysql_rules import MySQLAnalyzer

        try:
            plan = parse_mysql_explain(explain_file)
        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            raise typer.Exit(code=1)

        analyzer = MySQLAnalyzer()
        findings = analyzer.analyze(plan)

        sql_fixes = [
            f.suggestion for f in findings
            if f.suggestion and not f.suggestion.strip().startswith("-- No action")
        ]

        if not sql_fixes:
            console.print("-- No MySQL fixes to apply.")
            return

        # Migration generation
        if flyway or liquibase:
            from querysense.migration_gen import MigrationFormat, MigrationGenerator

            fmt = MigrationFormat.FLYWAY if flyway else MigrationFormat.LIQUIBASE
            gen = MigrationGenerator(output_dir=migration_dir)
            path = gen.generate(
                fixes=sql_fixes,
                format=fmt,
                description=description,
                source_plan=str(explain_file),
            )
            console.print(f"[green bold]Migration generated:[/green bold] {path}")
            return

        # Plain output
        console.print("-- QuerySense MySQL Fixes")
        console.print(f"-- {len(findings)} issue(s) detected\n")

        for f in findings:
            if f.suggestion:
                console.print(f"-- [{f.severity.upper()}] {f.title}")
                for line in f.suggestion.split("\n"):
                    if line.strip():
                        console.print(line)
                console.print()

        console.print("-- End of fixes")
        console.print("-- Run with: mysql < fixes.sql")
