"""
Watch-files command: re-analyze EXPLAIN plans on file change.

Like a linter for SQL — watches JSON/SQL files and re-runs analysis
automatically when they change. Gives instant feedback during development.

    querysense watch-files plans/
    querysense watch-files query.json --interval 2
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register the watch-files command on the given Typer app."""

    @app.command("watch-files")
    def watch_files(
        path: Annotated[
            Path,
            typer.Argument(
                help="File or directory to watch for EXPLAIN JSON files",
                exists=True,
            ),
        ],
        pattern: Annotated[
            str,
            typer.Option("--pattern", "-p", help="Glob pattern within directory"),
        ] = "**/*.json",
        interval: Annotated[
            float,
            typer.Option("--interval", "-i", help="Check interval in seconds"),
        ] = 1.0,
        fail_on: Annotated[
            Optional[str],
            typer.Option("--fail-on", help="Exit with error on severity: critical, warning, info"),
        ] = None,
        clear: Annotated[
            bool,
            typer.Option("--clear", help="Clear screen on re-analysis"),
        ] = True,
        sql_file: Annotated[
            Optional[Path],
            typer.Option("--sql", "-s", help="SQL file to include in analysis"),
        ] = None,
    ) -> None:
        """
        Watch files and re-analyze on change — like a SQL linter.

        Monitors EXPLAIN JSON files and re-runs QuerySense analysis whenever
        they change. Perfect for development workflows where you're iterating
        on query performance.

        \\b
        Examples:
            # Watch a directory
            $ querysense watch-files plans/

            # Watch a single file
            $ querysense watch-files query_plan.json

            # Watch with SQL context
            $ querysense watch-files plans/ --sql queries/slow.sql

            # Fail on critical issues (useful in dev)
            $ querysense watch-files plans/ --fail-on critical
        """
        from querysense.engine import AnalysisService
        from querysense.output.renderers import render_text
        from querysense.parser import ParseError, parse_explain

        service = AnalysisService()

        # Build file list
        if path.is_file():
            watch_files_list = [path]
        else:
            watch_files_list = sorted(path.glob(pattern))

        if not watch_files_list:
            error_console.print(f"[yellow]No files matching '{pattern}' in {path}[/yellow]")
            raise typer.Exit(code=1)

        console.print(
            f"[bold]QuerySense Watch[/bold] — monitoring "
            f"{len(watch_files_list)} file{'s' if len(watch_files_list) > 1 else ''}"
        )
        console.print(f"[dim]Interval: {interval}s | Path: {path} | Press Ctrl+C to stop[/dim]")
        console.print()

        # Track file hashes for change detection
        file_hashes: dict[str, str] = {}
        last_results: dict[str, str] = {}

        sql_text = None
        sql_hash = ""
        if sql_file and sql_file.exists():
            sql_text = sql_file.read_text(encoding="utf-8")
            sql_hash = hashlib.md5(sql_text.encode()).hexdigest()

        def _hash_file(fp: Path) -> str:
            try:
                return hashlib.md5(fp.read_bytes()).hexdigest()
            except OSError:
                return ""

        def _analyze_file(fp: Path) -> tuple[str, int, int, int]:
            """Analyze a single file, return (summary_text, critical, warning, info)."""
            try:
                explain = parse_explain(fp)
                result = service.analyze(explain, sql=sql_text)
                text = render_text(result)

                critical = len(result.findings_by_severity(
                    __import__("querysense.analyzer.models", fromlist=["Severity"]).Severity.CRITICAL
                ))
                warning = len(result.findings_by_severity(
                    __import__("querysense.analyzer.models", fromlist=["Severity"]).Severity.WARNING
                ))
                info_count = len(result.findings_by_severity(
                    __import__("querysense.analyzer.models", fromlist=["Severity"]).Severity.INFO
                ))

                return text, critical, warning, info_count
            except ParseError as e:
                return f"[red]Parse error:[/red] {e.message}", 0, 0, 0
            except Exception as e:
                return f"[red]Error:[/red] {e}", 0, 0, 0

        # Initial analysis
        total_critical = 0
        total_warning = 0
        for fp in watch_files_list:
            h = _hash_file(fp)
            file_hashes[str(fp)] = h
            text, c, w, i = _analyze_file(fp)
            last_results[str(fp)] = text
            total_critical += c
            total_warning += w

        _render_watch_status(watch_files_list, last_results, total_critical, total_warning)

        # Watch loop
        try:
            while True:
                time.sleep(interval)

                # Check SQL file changes
                if sql_file and sql_file.exists():
                    new_sql_hash = hashlib.md5(sql_file.read_bytes()).hexdigest()
                    if new_sql_hash != sql_hash:
                        sql_hash = new_sql_hash
                        sql_text = sql_file.read_text(encoding="utf-8")
                        # Re-analyze all files with new SQL
                        for fp in watch_files_list:
                            file_hashes[str(fp)] = ""  # Force re-analysis

                # Re-scan directory for new files
                if path.is_dir():
                    current_files = sorted(path.glob(pattern))
                    if set(str(f) for f in current_files) != set(str(f) for f in watch_files_list):
                        watch_files_list = current_files
                        console.print(f"[dim]File list changed: {len(watch_files_list)} files[/dim]")

                changed = False
                total_critical = 0
                total_warning = 0

                for fp in watch_files_list:
                    h = _hash_file(fp)
                    key = str(fp)
                    if h != file_hashes.get(key, ""):
                        file_hashes[key] = h
                        text, c, w, i = _analyze_file(fp)
                        last_results[key] = text
                        changed = True
                        total_critical += c
                        total_warning += w
                        ts = time.strftime("%H:%M:%S")
                        console.print(f"[dim]{ts}[/dim] [bold]Changed:[/bold] {fp.name}")
                    else:
                        # Count existing results
                        pass

                if changed:
                    if clear:
                        os.system("cls" if os.name == "nt" else "clear")
                    _render_watch_status(watch_files_list, last_results, total_critical, total_warning)

                    # Check fail_on
                    if fail_on == "critical" and total_critical > 0:
                        error_console.print(f"\n[red]Critical issues detected — exiting.[/red]")
                        raise typer.Exit(code=1)
                    elif fail_on == "warning" and (total_critical + total_warning) > 0:
                        error_console.print(f"\n[yellow]Warning+ issues detected — exiting.[/yellow]")
                        raise typer.Exit(code=1)

        except KeyboardInterrupt:
            console.print("\n[yellow]Watch stopped.[/yellow]")


def _render_watch_status(
    files: list[Path],
    results: dict[str, str],
    critical: int,
    warning: int,
) -> None:
    """Render the current watch status."""
    ts = time.strftime("%H:%M:%S")
    console.print(f"\n[bold]QuerySense Watch[/bold] [dim]{ts}[/dim]")

    if critical > 0:
        console.print(f"[red bold]  {critical} critical[/red bold]", end="")
    if warning > 0:
        console.print(f"  [yellow]{warning} warnings[/yellow]", end="")
    if critical == 0 and warning == 0:
        console.print(f"  [green]✓ No issues[/green]", end="")
    console.print(f"  [dim]({len(files)} files)[/dim]")
    console.print()

    for fp in files:
        key = str(fp)
        if key in results:
            console.print(f"[dim]─── {fp.name} ───[/dim]")
            console.print(results[key])
            console.print()
