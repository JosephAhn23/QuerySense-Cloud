"""
CLI commands for log-based query collection.

    querysense log parse     — Parse PostgreSQL log files for slow queries
    querysense log stats     — Show aggregated query statistics from logs
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register_log(log_app: typer.Typer) -> None:
    """Register log collection commands."""

    @log_app.command(name="parse")
    def parse_log(
        log_file: Annotated[
            str,
            typer.Argument(help="Path to PostgreSQL log file"),
        ],
        min_duration: Annotated[
            float,
            typer.Option("--min-duration", help="Minimum query duration in ms"),
        ] = 0.0,
        max_entries: Annotated[
            int,
            typer.Option("--max-entries", help="Maximum log entries to parse"),
        ] = 100_000,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Parse a PostgreSQL log file for slow queries and errors.

        Auto-detects CSV log vs stderr format. Extracts query durations,
        errors, and aggregates statistics by query fingerprint.

        \\b
        Supports:
          - PostgreSQL CSV log format (log_destination = 'csvlog')
          - PostgreSQL stderr format (standard text logs)
          - Duration extraction from log_min_duration_statement output

        \\b
        Zero database connections required — works entirely from log files.

        \\b
        Examples:
            $ querysense log parse /var/log/postgresql/postgresql-16-main.log
            $ querysense log parse /var/log/pg.csv --min-duration 100
            $ querysense log parse pg.log --json > report.json
        """
        from querysense.log_collector import LogCollector

        path = Path(log_file)
        if not path.exists():
            console.print(f"[red]Error: File not found: {log_file}[/red]")
            raise typer.Exit(code=1)

        collector = LogCollector(
            min_duration_ms=min_duration,
            max_entries=max_entries,
        )
        result = collector.parse_file(path)

        if json_output:
            console.print_json(json.dumps(result.to_dict(), indent=2, default=str))
            return

        # Summary
        console.print(Panel(
            f"[bold]File:[/bold] {result.file_path}\n"
            f"[bold]Format:[/bold] {result.format_detected}\n"
            f"[bold]Lines parsed:[/bold] {result.total_lines:,}\n"
            f"[bold]Entries:[/bold] {result.entries_parsed:,} "
            f"(errors: {result.parse_errors})\n"
            f"[bold]Time range:[/bold] {result.first_timestamp} → "
            f"{result.last_timestamp}\n"
            f"[bold]Slow queries:[/bold] {len(result.slow_queries):,}\n"
            f"[bold]Errors:[/bold] {len(result.errors):,}\n"
            f"[bold]Warnings:[/bold] {len(result.warnings):,}\n"
            f"[bold]Unique query fingerprints:[/bold] {result.unique_queries}",
            title="Log Parse Results",
            border_style="cyan",
        ))

        # Top slow queries by total time
        if result.query_stats:
            top = sorted(
                result.query_stats.values(),
                key=lambda x: x.total_duration_ms,
                reverse=True,
            )[:15]

            tbl = Table(title="Top Slow Queries (by total time)")
            tbl.add_column("Calls", justify="right")
            tbl.add_column("Total", justify="right")
            tbl.add_column("Avg", justify="right")
            tbl.add_column("Max", justify="right")
            tbl.add_column("Query", max_width=60)

            for qs in top:
                tbl.add_row(
                    str(qs.total_calls),
                    f"{qs.total_duration_ms / 1000:.1f}s",
                    f"{qs.avg_duration_ms:.0f}ms",
                    f"{qs.max_duration_ms:.0f}ms",
                    qs.example_query[:60],
                )

            console.print(tbl)

        # Errors
        if result.errors:
            console.print(f"\n[red bold]Errors ({len(result.errors)}):[/red bold]")
            for err in result.errors[:10]:
                console.print(
                    f"  [red]{err.log_level}[/red] "
                    f"[dim]{err.timestamp}[/dim] "
                    f"{err.message[:80]}"
                )
            if len(result.errors) > 10:
                console.print(f"  ... and {len(result.errors) - 10} more")

    @log_app.command(name="stats")
    def log_stats(
        log_file: Annotated[
            str,
            typer.Argument(help="Path to PostgreSQL log file"),
        ],
        top_n: Annotated[
            int,
            typer.Option("--top", "-n", help="Top N queries to show"),
        ] = 20,
        sort_by: Annotated[
            str,
            typer.Option("--sort", help="Sort by: total, avg, max, calls"),
        ] = "total",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Show aggregated query statistics from log files.

        Groups queries by fingerprint (parameterized form) and shows
        execution statistics.

        \\b
        Examples:
            $ querysense log stats /var/log/pg.log --top 30
            $ querysense log stats /var/log/pg.log --sort avg
        """
        from querysense.log_collector import LogCollector

        path = Path(log_file)
        if not path.exists():
            console.print(f"[red]Error: File not found: {log_file}[/red]")
            raise typer.Exit(code=1)

        collector = LogCollector()
        result = collector.parse_file(path)

        sort_keys = {
            "total": lambda x: x.total_duration_ms,
            "avg": lambda x: x.avg_duration_ms,
            "max": lambda x: x.max_duration_ms,
            "calls": lambda x: x.total_calls,
        }
        sort_fn = sort_keys.get(sort_by, sort_keys["total"])
        top = sorted(result.query_stats.values(), key=sort_fn, reverse=True)[:top_n]

        if json_output:
            console.print_json(json.dumps(
                [qs.to_dict() for qs in top], indent=2, default=str
            ))
            return

        tbl = Table(title=f"Query Statistics (sorted by {sort_by}, top {top_n})")
        tbl.add_column("#", justify="right", width=4)
        tbl.add_column("Calls", justify="right")
        tbl.add_column("Total", justify="right")
        tbl.add_column("Avg", justify="right")
        tbl.add_column("Min", justify="right")
        tbl.add_column("Max", justify="right")
        tbl.add_column("Query", max_width=55)

        for i, qs in enumerate(top, 1):
            tbl.add_row(
                str(i),
                str(qs.total_calls),
                f"{qs.total_duration_ms / 1000:.1f}s",
                f"{qs.avg_duration_ms:.0f}ms",
                f"{qs.min_duration_ms:.0f}ms",
                f"{qs.max_duration_ms:.0f}ms",
                qs.example_query[:55],
            )

        console.print(tbl)
