"""
Rewrite command: automatically optimize SQL queries.

Implements `querysense rewrite` which takes a SQL query and optional
EXPLAIN findings, then produces a rewritten query with performance
optimizations applied.

Usage:
    querysense rewrite --sql "SELECT * FROM orders WHERE id IN (SELECT ...)"
    querysense rewrite --file query.sql --plan explain.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register the rewrite command on the given Typer app."""

    @app.command()
    def rewrite(
        sql: Annotated[
            Optional[str],
            typer.Option("--sql", "-s", help="SQL query to rewrite"),
        ] = None,
        sql_file: Annotated[
            Optional[Path],
            typer.Option(
                "--file", "-f",
                help="Path to SQL file",
                exists=True,
                readable=True,
            ),
        ] = None,
        plan_file: Annotated[
            Optional[Path],
            typer.Option(
                "--plan", "-p",
                help="EXPLAIN JSON for finding-guided rewrites",
                exists=True,
                readable=True,
            ),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        output_file: Annotated[
            Optional[Path],
            typer.Option("--output", "-o", help="Write rewritten SQL to file"),
        ] = None,
        sandbox: Annotated[
            bool,
            typer.Option(
                "--sandbox",
                help="Test rewrite against a real DB (read-only transaction, auto-rollback)",
            ),
        ] = False,
        dsn: Annotated[
            str,
            typer.Option(
                "--dsn",
                help="Database connection string for sandbox testing",
                envvar="QUERYSENSE_DSN",
            ),
        ] = "postgresql://localhost:5432/postgres",
    ) -> None:
        """
        Rewrite SQL for better performance.

        Applies safe, deterministic transformations:
        - IN (subquery) to JOIN
        - NOT IN to NOT EXISTS (NULL-safe)
        - OR across columns to UNION ALL
        - SELECT DISTINCT * removal
        - COUNT(*) on large tables to approximate count
        - UNION to UNION ALL (when safe)
        - Multiple OR to IN clause
        - Non-sargable patterns to indexed alternatives

        Add --sandbox to test the rewrite against a real database in a
        read-only rolled-back transaction. Verifies result correctness
        and shows before/after performance comparison.

        \\b
        Examples:
            # Rewrite inline SQL
            $ querysense rewrite --sql "SELECT * FROM orders WHERE id IN (SELECT order_id FROM returns)"

            # Rewrite from file with EXPLAIN-guided optimizations
            $ querysense rewrite --file slow_query.sql --plan explain.json

            # Save rewritten query
            $ querysense rewrite --file query.sql --output optimized.sql

            # Test rewrite safety against a real database
            $ querysense rewrite --sql "..." --sandbox --dsn postgresql://localhost/mydb
        """
        from querysense.rewriter import rewrite_query

        # Get SQL input
        if sql:
            original_sql = sql
        elif sql_file:
            original_sql = sql_file.read_text(encoding="utf-8")
        else:
            error_console.print(
                "[red]Error:[/red] Provide --sql or --file"
            )
            raise typer.Exit(code=1)

        # Get findings if plan provided
        findings = None
        if plan_file:
            from querysense.engine import AnalysisService
            from querysense.parser import ParseError, parse_explain

            try:
                output = parse_explain(plan_file)
                service = AnalysisService()
                result = service.analyze(output, sql=original_sql)
                findings = list(result.findings)
            except ParseError as e:
                error_console.print(
                    f"[yellow]Warning:[/yellow] Could not parse plan: {e.message}"
                )

        # Perform rewrite
        result = rewrite_query(original_sql, findings)

        # Sandbox testing
        if sandbox and result.was_rewritten:
            import asyncio
            from querysense.rewrite_sandbox import RewriteSandbox

            console.print(Panel(
                "[bold]Sandbox Mode[/bold] — Testing rewrite against live database\n"
                f"DSN: [dim]{dsn[:40]}...[/dim]\n"
                "All queries run inside a rolled-back transaction. No data is modified.",
                title="Sandbox",
                border_style="cyan",
            ))

            try:
                sb = RewriteSandbox(dsn=dsn)
                sb_result = asyncio.run(sb.test_rewrite(
                    original_sql=original_sql,
                    rewritten_sql=result.rewritten_sql,
                ))

                if sb_result.error:
                    error_console.print(
                        f"[red]Sandbox error:[/red] {sb_result.error}"
                    )
                else:
                    # Results comparison
                    if sb_result.results_match:
                        console.print("[green bold]Results MATCH[/green bold] — Rewrite is safe")
                    else:
                        console.print(
                            f"[red bold]Results DIFFER[/red bold] — "
                            f"Original: {sb_result.row_count_original} rows, "
                            f"Rewritten: {sb_result.row_count_rewritten} rows"
                        )

                    # Performance comparison
                    from rich.table import Table as RichTable
                    perf_table = RichTable(title="Performance Comparison")
                    perf_table.add_column("Metric")
                    perf_table.add_column("Original", style="red")
                    perf_table.add_column("Rewritten", style="green")
                    perf_table.add_column("Change")

                    perf_table.add_row(
                        "Cost",
                        f"{sb_result.original_cost:,.0f}",
                        f"{sb_result.rewritten_cost:,.0f}",
                        f"{sb_result.cost_reduction_pct:+.1f}%",
                    )
                    perf_table.add_row(
                        "Time",
                        f"{sb_result.original_time_ms:.1f}ms",
                        f"{sb_result.rewritten_time_ms:.1f}ms",
                        f"{sb_result.speedup:.1f}x faster",
                    )
                    perf_table.add_row(
                        "Plan",
                        sb_result.original_plan_type,
                        sb_result.rewritten_plan_type,
                        "Changed" if sb_result.plan_changed else "Same",
                    )
                    console.print(perf_table)

                    for w in sb_result.warnings:
                        console.print(f"[yellow]Warning:[/yellow] {w}")

                    if sb_result.is_safe:
                        console.print(
                            "\n[green bold]VERDICT: Safe to apply[/green bold]"
                        )
                    else:
                        console.print(
                            "\n[red bold]VERDICT: NOT safe — results differ[/red bold]"
                        )

                console.print()

            except Exception as e:
                error_console.print(f"[red]Sandbox failed:[/red] {e}")
                console.print("[dim]Continuing with rewrite output...[/dim]\n")

        if json_output:
            data = {
                "original": result.original_sql,
                "rewritten": result.rewritten_sql,
                "was_rewritten": result.was_rewritten,
                "rewrites": [
                    {
                        "name": r.name,
                        "description": r.description,
                        "rule_id": r.rule_id,
                        "confidence": r.confidence,
                    }
                    for r in result.rewrites
                ],
                "warnings": result.warnings,
            }
            console.print_json(json.dumps(data, default=str))
            return

        if output_file:
            output_file.write_text(result.format_sql(), encoding="utf-8")
            console.print(
                f"[green]Rewritten SQL written to {output_file}[/green]"
            )
            if result.rewrites:
                console.print(f"  {len(result.rewrites)} optimization(s) applied")
            return

        # Pretty terminal output
        if not result.was_rewritten:
            console.print(Panel(
                "[green]No optimizations applicable.[/green]\n"
                "The query is already in good shape, or patterns are too complex for auto-rewrite.",
                title="QuerySense Rewriter",
                border_style="green",
            ))
            return

        console.print(Panel(
            f"[bold]{len(result.rewrites)} optimization(s) applied[/bold]",
            title="QuerySense Rewriter",
            border_style="yellow",
        ))

        for r in result.rewrites:
            conf_bar = "█" * int(r.confidence * 10) + "░" * (10 - int(r.confidence * 10))
            console.print(
                f"  [{r.rule_id}] [bold]{r.name}[/bold] "
                f"[dim]confidence: {conf_bar} {r.confidence:.0%}[/dim]"
            )
            console.print(f"    {r.description}")
            console.print()

        console.print("[bold]Rewritten SQL:[/bold]")
        syntax = Syntax(result.rewritten_sql, "sql", theme="monokai")
        console.print(syntax)
