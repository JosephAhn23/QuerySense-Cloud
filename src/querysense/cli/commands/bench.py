"""
CLI command: querysense bench

Concurrency benchmark — find your database's breaking point.

Usage:
    querysense bench --queries queries.sql --levels 1,5,10,20,50
    querysense bench --simulate --base-latency 5 --max-connections 100
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

console = Console()


def register(app: typer.Typer) -> None:
    @app.command("bench")
    def bench(
        queries_file: Annotated[
            str,
            typer.Option("--queries", "-q", help="File with SQL queries (one per line)"),
        ] = "",
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string for live benchmarking"),
        ] = "",
        levels: Annotated[
            str,
            typer.Option("--levels", "-l", help="Comma-separated concurrency levels"),
        ] = "1,5,10,20,50",
        simulate: Annotated[
            bool,
            typer.Option("--simulate", help="Simulation mode (no real DB required)"),
        ] = False,
        base_latency: Annotated[
            float,
            typer.Option("--base-latency", help="Base latency in ms (simulation mode)"),
        ] = 5.0,
        max_connections: Annotated[
            int,
            typer.Option("--max-connections", help="Max connections (simulation mode)"),
        ] = 100,
        duration: Annotated[
            int,
            typer.Option("--duration", "-d", help="Test duration in seconds"),
        ] = 30,
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output results as JSON"),
        ] = False,
    ) -> None:
        """Benchmark database performance under concurrent load."""
        from querysense.bench import ConcurrencyTester

        # Parse concurrency levels
        try:
            concurrency_levels = [int(x.strip()) for x in levels.split(",")]
        except ValueError:
            console.print("[red]Invalid --levels format. Use comma-separated integers.[/red]")
            raise typer.Exit(1)

        # Load queries
        queries: list[str] = []
        if queries_file:
            p = Path(queries_file)
            if not p.exists():
                console.print(f"[red]File not found: {queries_file}[/red]")
                raise typer.Exit(1)
            raw = p.read_text(encoding="utf-8").strip()
            queries = [q.strip() for q in raw.split(";") if q.strip()]

        tester = ConcurrencyTester(dsn=dsn)

        if simulate or not dsn:
            console.print("[bold]Running concurrency simulation...[/bold]")
            report = tester.simulate_workload(
                queries=queries or None,
                concurrency_levels=concurrency_levels,
                base_latency_ms=base_latency,
                max_connections=max_connections,
                duration_seconds=duration,
            )
        else:
            import asyncio
            console.print(f"[bold]Benchmarking {dsn[:30]}... at levels {concurrency_levels}[/bold]")
            report = asyncio.run(tester.test_workload(
                queries=queries,
                concurrency_levels=concurrency_levels,
                duration_seconds=duration,
            ))

        if output_json:
            console.print(report.to_json())
        else:
            console.print(report.format_text())

        # Exit code based on results
        if report.breaking_point and report.breaking_point <= concurrency_levels[0]:
            raise typer.Exit(2)  # Failed at lowest concurrency
