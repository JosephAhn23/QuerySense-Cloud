"""CLI command: querysense import — migrate from competitor tools."""

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
    """Register the import command on the Typer app."""

    @app.command("import")
    def import_cmd(
        file: Annotated[
            Path,
            typer.Argument(
                help="Path to export file from competitor tool",
                exists=True,
                readable=True,
            ),
        ],
        source: Annotated[
            Optional[str],
            typer.Option(
                "--from", "-f",
                help="Source tool: pganalyze, eversql, datadog, liquibase, flyway, pgmustard (auto-detected if omitted)",
            ),
        ] = None,
        output_dir: Annotated[
            Optional[Path],
            typer.Option(
                "--output", "-o",
                help="Directory to write imported plans/queries",
            ),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        analyze: Annotated[
            bool,
            typer.Option("--analyze", "-a", help="Run QuerySense analysis on imported plans"),
        ] = False,
        compare: Annotated[
            bool,
            typer.Option("--compare", help="Side-by-side comparison showing what QuerySense finds that the competitor missed"),
        ] = False,
    ) -> None:
        """
        Import queries, plans, and migrations from competitor tools.

        Supports pganalyze, EverSQL, Datadog, Liquibase, Flyway, and pgMustard.
        Auto-detects format if --from is not specified.

        Use --compare to generate an instant comparison report showing
        what QuerySense found that the competitor tool missed.

        \\b
        Examples:
            $ querysense import pganalyze-export.json
            $ querysense import --from=pganalyze export.json --compare
            $ querysense import --from=eversql queries.sql --analyze
            $ querysense import --from=liquibase changelog.xml
            $ querysense import --from=datadog dashboard.json --json
        """
        from querysense.competitor_import import (
            detect_format,
            format_import_result,
            import_and_compare,
            import_from,
        )

        # Detect or use specified source
        detected = detect_format(file) if source is None else source
        if source is None:
            console.print(f"[dim]Auto-detected format: {detected}[/dim]")

        # Import
        try:
            result = import_from(file, source=detected)
        except Exception as e:
            error_console.print(f"[red]Import error:[/red] {e}")
            raise typer.Exit(code=2)

        if json_output:
            console.print_json(result.to_json())
            return

        # Rich output
        console.print()
        console.print(Panel(
            f"[bold green]IMPORTED FROM {result.source.upper()}[/bold green]",
            title="QuerySense Import",
            border_style="green",
        ))

        # Summary stats
        table = Table(show_header=True, header_style="bold")
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right", style="bold")

        if result.queries:
            table.add_row("Queries", str(len(result.queries)))
            plans = sum(1 for q in result.queries if q.plan_json)
            if plans:
                table.add_row("  With EXPLAIN plans", str(plans))

        if result.indexes:
            table.add_row("Index recommendations", str(len(result.indexes)))

        if result.migrations:
            table.add_row("Migrations", str(len(result.migrations)))
            with_rb = sum(1 for m in result.migrations if m.rollback_sql)
            table.add_row("  With rollback SQL", str(with_rb))
            table.add_row("  Missing rollback", str(len(result.migrations) - with_rb))

        console.print(table)

        # Show imported queries
        if result.queries:
            console.print(f"\n[bold]Imported queries:[/bold]")
            for i, q in enumerate(result.queries[:10], 1):
                sql_preview = q.sql[:80].replace("\n", " ")
                has_plan = " [green](with plan)[/green]" if q.plan_json else ""
                time_str = f" [{q.execution_time_ms:.0f}ms]" if q.execution_time_ms else ""
                console.print(f"  {i}. {sql_preview}...{has_plan}{time_str}")
            if len(result.queries) > 10:
                console.print(f"  ... and {len(result.queries) - 10} more")

        # Show indexes
        if result.indexes:
            console.print(f"\n[bold]Index recommendations:[/bold]")
            for idx in result.indexes[:10]:
                if idx.create_sql:
                    console.print(f"  {idx.create_sql[:100]}")
                else:
                    cols = ", ".join(idx.columns)
                    console.print(f"  {idx.table}({cols})")

        # Show migrations
        if result.migrations:
            console.print(f"\n[bold]Migrations:[/bold]")
            for m in result.migrations[:10]:
                rb = "[green]+rollback[/green]" if m.rollback_sql else "[red]-rollback[/red]"
                console.print(f"  {m.id}: {m.sql[:60]}... {rb}")

        # Warnings
        if result.warnings:
            console.print()
            for w in result.warnings:
                console.print(f"  [yellow]Warning: {w}[/yellow]")

        # Write output files
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

            # Write plans as individual JSON files
            for i, q in enumerate(result.queries):
                if q.plan_json:
                    plan_path = output_dir / f"plan_{i:03d}.json"
                    plan_path.write_text(
                        json.dumps([q.plan_json], indent=2),
                        encoding="utf-8",
                    )

            # Write SQL queries
            if result.queries:
                queries_path = output_dir / "queries.sql"
                queries_path.write_text(
                    "\n\n".join(
                        f"-- Query {i} (from {q.source_tool})\n{q.sql};"
                        for i, q in enumerate(result.queries, 1)
                    ),
                    encoding="utf-8",
                )

            # Write migrations
            for m in result.migrations:
                mig_path = output_dir / f"migration_{m.id}.sql"
                mig_path.write_text(m.sql, encoding="utf-8")
                if m.rollback_sql:
                    rb_path = output_dir / f"rollback_{m.id}.sql"
                    rb_path.write_text(m.rollback_sql, encoding="utf-8")

            console.print(f"\n[green]Files written to {output_dir}/[/green]")

        # Analyze imported plans
        if analyze:
            plans = [q for q in result.queries if q.plan_json]
            if plans:
                console.print(f"\n[bold]Running QuerySense analysis on {len(plans)} plan(s)...[/bold]\n")

                from querysense.engine import AnalysisService
                from querysense.parser import parse_explain

                service = AnalysisService()
                total_findings = 0

                for i, q in enumerate(plans, 1):
                    try:
                        plan_data = q.plan_json
                        if isinstance(plan_data, dict) and "Plan" in plan_data:
                            plan_data = [plan_data]
                        elif isinstance(plan_data, dict):
                            plan_data = [{"Plan": plan_data}]

                        explain = parse_explain(plan_data)
                        analysis = service.analyze(explain, sql=q.sql or None)

                        if analysis.findings:
                            total_findings += len(analysis.findings)
                            console.print(
                                f"  Plan {i}: [yellow]{len(analysis.findings)} finding(s)[/yellow]"
                            )
                            for f in analysis.findings[:3]:
                                sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(
                                    f.severity.value, "white"
                                )
                                console.print(f"    [{sev_color}]{f.title}[/{sev_color}]")
                        else:
                            console.print(f"  Plan {i}: [green]No issues[/green]")
                    except Exception as e:
                        console.print(f"  Plan {i}: [red]Analysis error: {e}[/red]")

                console.print(f"\n  [bold]Total: {total_findings} findings across {len(plans)} plans[/bold]")

                comp_name = result.source
                if total_findings > 0:
                    console.print(
                        f"  [bold green]QuerySense found {total_findings} issues "
                        f"that {comp_name} missed![/bold green]"
                    )
            else:
                console.print(
                    "[yellow]No EXPLAIN plans to analyze. "
                    "Import plans from pganalyze or pgMustard for analysis.[/yellow]"
                )

        # Side-by-side comparison report
        if compare:
            console.print()
            console.print(Panel(
                "[bold]Generating comparison report...[/bold]",
                title="QuerySense vs " + result.source.upper(),
                border_style="blue",
            ))

            _, switch_report = import_and_compare(file, source=detected)

            if json_output:
                console.print_json(switch_report.to_json())
            else:
                # Rich comparison output
                console.print()
                comp_table = Table(
                    title=f"QuerySense vs {result.source}",
                    show_header=True,
                    header_style="bold",
                )
                comp_table.add_column("Metric", style="cyan")
                comp_table.add_column(result.source, justify="right")
                comp_table.add_column("QuerySense", justify="right", style="bold green")

                comp_table.add_row(
                    "Recommendations",
                    str(switch_report.competitor_recommendations),
                    str(switch_report.querysense_findings),
                )
                comp_table.add_row(
                    "Analysis time",
                    "N/A (cloud)",
                    f"{switch_report.time_to_analyze_ms:.0f}ms",
                )
                comp_table.add_row(
                    "Price",
                    switch_report.competitor_pricing or "Paid",
                    "[bold green]Free forever[/bold green]",
                )
                comp_table.add_row(
                    "Works offline",
                    "No",
                    "[bold green]Yes[/bold green]",
                )

                console.print(comp_table)

                if switch_report.new_findings > 0:
                    console.print()
                    console.print(Panel(
                        f"[bold green]QuerySense found {switch_report.new_findings} issue(s) "
                        f"that {result.source} missed![/bold green]\n\n"
                        + "\n".join(
                            f"  {i}. [{d['severity'].upper()}] {d['title']}"
                            for i, d in enumerate(switch_report.finding_details[:10], 1)
                        ),
                        title="[bold]New Findings[/bold]",
                        border_style="green",
                    ))

                if switch_report.performance_insights:
                    console.print()
                    for insight in switch_report.performance_insights:
                        console.print(f"  [yellow]>[/yellow] {insight}")

                console.print()
                console.print(
                    f"  [bold]{switch_report._verdict()}[/bold]"
                )

        # Next steps
        console.print(f"\n[bold]Next steps:[/bold]")
        if result.queries:
            console.print("  querysense analyze <plan_file>")
        if compare:
            console.print("  querysense validate  # Run full benchmark suite")
        if result.migrations:
            console.print("  querysense migrate-check <migration.sql>")
        console.print()
