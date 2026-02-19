"""
CLI commands for the three new planner/optimizer features:

    querysense partial-count --sql "SELECT COUNT(*) FROM ..."
    querysense out-of-range  --sql "SELECT * FROM t WHERE ts > 999" --stats stats.json
    querysense pg16-upgrade  --sql "SELECT DISTINCT ... ORDER BY ..." [--json]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register_partial_count(parent: typer.Typer) -> None:
    """Register the partial-count command."""

    @parent.command(name="partial-count")
    def partial_count(
        sql: Annotated[Optional[str], typer.Option("--sql", "-s", help="COUNT query to optimize")] = None,
        file: Annotated[Optional[Path], typer.Option("--file", "-f", help="SQL file")] = None,
        threshold: Annotated[int, typer.Option("--threshold", "-t", help="Partial count threshold")] = 100,
        plan_file: Annotated[Optional[Path], typer.Option("--plan", help="EXPLAIN JSON for speedup estimate")] = None,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
        sql_function: Annotated[bool, typer.Option("--sql-function", help="Print CREATE FUNCTION script")] = False,
    ) -> None:
        """
        Optimize COUNT queries with LIMIT subqueries.

        Rewrites COUNT(*) into a LIMIT-bounded subquery so the database
        stops after N+1 rows.  The UI shows "N+" when the exact count
        exceeds the threshold.  Based on pganalyze's 35 ms -> 5 ms example.

        \\b
        Examples:
            querysense partial-count --sql "SELECT COUNT(*) FROM orders WHERE active"
            querysense partial-count --threshold 50 --file slow_counts.sql --json
        """
        from querysense.optimizers.partial_count import PartialCountOptimizer

        opt = PartialCountOptimizer(threshold=threshold)

        if sql_function:
            console.print(Panel(opt.generate_sql_function(), title="partial_count() SQL Function", border_style="green"))
            return

        query = _read_sql(sql, file)
        if not query:
            error_console.print("[red]Provide --sql or --file[/red]")
            raise typer.Exit(code=1)

        plan = json.loads(plan_file.read_text()) if plan_file and plan_file.exists() else None
        suggestion = opt.analyze(query, plan)

        if suggestion is None:
            console.print("[dim]Not a COUNT query or not a candidate for partial-count optimization.[/dim]")
            raise typer.Exit()

        if json_output:
            console.print_json(json.dumps(suggestion.to_dict()))
            return

        console.print(Panel(suggestion.optimized, title="Optimized Query", border_style="green"))
        tbl = Table(show_lines=True)
        tbl.add_column("Metric")
        tbl.add_column("Value", style="bold")
        tbl.add_row("Threshold", f"{suggestion.threshold}+")
        tbl.add_row("Estimated Speedup", f"{suggestion.estimated_speedup:.1f}x")
        if suggestion.current_time_ms > 0:
            tbl.add_row("Current Time", f"{suggestion.current_time_ms:.2f} ms")
            tbl.add_row("Estimated Time", f"{suggestion.estimated_time_ms:.2f} ms")
        tbl.add_row("Explanation", suggestion.explanation)
        console.print(tbl)


def register_out_of_range(parent: typer.Typer) -> None:
    """Register the out-of-range command."""

    @parent.command(name="out-of-range")
    def out_of_range(
        sql: Annotated[Optional[str], typer.Option("--sql", "-s", help="Query with range predicates")] = None,
        file: Annotated[Optional[Path], typer.Option("--file", "-f", help="SQL file")] = None,
        stats_file: Annotated[Optional[Path], typer.Option("--stats", help="Column ranges JSON file")] = None,
        plan_file: Annotated[Optional[Path], typer.Option("--plan", help="EXPLAIN JSON")] = None,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """
        Detect predicates outside histogram bounds.

        When a WHERE clause references a value beyond what ANALYZE has
        seen, PostgreSQL may call get_actual_variable_range() during
        planning, which can be slow on tables with dead tuples.

        \\b
        Examples:
            querysense out-of-range \\
                --sql "SELECT * FROM events WHERE ts > 1700000000" \\
                --stats column_stats.json
        """
        from querysense.planner.out_of_range import OutOfRangeDetector, ColumnRange

        query = _read_sql(sql, file)
        if not query:
            error_console.print("[red]Provide --sql or --file[/red]")
            raise typer.Exit(code=1)

        plan = json.loads(plan_file.read_text()) if plan_file and plan_file.exists() else None

        ranges: list[ColumnRange] = []
        if stats_file and stats_file.exists():
            for item in json.loads(stats_file.read_text()):
                ranges.append(ColumnRange(**item))

        detector = OutOfRangeDetector()
        issues = detector.check_query(query, ranges, plan)

        if json_output:
            console.print_json(json.dumps([i.to_dict() for i in issues]))
            return

        if not issues:
            console.print("[green]No out-of-range predicates detected.[/green]")
            raise typer.Exit()

        for issue in issues:
            severity_color = "red" if issue.severity == "critical" else "yellow"
            console.print(Panel(
                f"[bold]{issue.column}[/bold] {issue.operator} {issue.search_value}\n"
                f"Stats range: {issue.stats_min} .. {issue.stats_max}\n"
                f"Misestimate: {issue.misestimate_factor:.1f}x\n"
                f"[dim]{issue.recommendation}[/dim]",
                title=f"[{severity_color}]{issue.severity.upper()}[/{severity_color}] "
                      f"{issue.table}.{issue.column}",
                border_style=severity_color,
            ))


def register_pg16_upgrade(parent: typer.Typer) -> None:
    """Register the pg16-upgrade command."""

    @parent.command(name="pg16-upgrade")
    def pg16_upgrade(
        sql: Annotated[Optional[str], typer.Option("--sql", "-s", help="Query to analyze")] = None,
        file: Annotated[Optional[Path], typer.Option("--file", "-f", help="SQL file or JSON array of queries")] = None,
        plan_file: Annotated[Optional[Path], typer.Option("--plan", help="EXPLAIN JSON")] = None,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
        report: Annotated[bool, typer.Option("--report", help="Generate full Markdown upgrade report")] = False,
    ) -> None:
        """
        Analyze queries for PostgreSQL 16 planner improvements.

        Detects 10 planner optimizations (Incremental Sort for DISTINCT,
        Presorted Aggregates, Right Anti Join, Window optimizations, …)
        and estimates the expected speedup from upgrading.

        \\b
        Examples:
            querysense pg16-upgrade --sql "SELECT DISTINCT a FROM t ORDER BY a"
            querysense pg16-upgrade --file workload.json --report
        """
        from querysense.planner.pg16_analyzer import PG16PlannerAnalyzer

        analyzer = PG16PlannerAnalyzer()
        plan = json.loads(plan_file.read_text()) if plan_file and plan_file.exists() else None

        if file and file.exists():
            raw = file.read_text()
            try:
                items = json.loads(raw)
            except json.JSONDecodeError:
                items = [{"query": raw, "name": file.name}]

            if report:
                md = analyzer.generate_report(items)
                console.print(Panel(md, title="PG 16 Upgrade Report", border_style="cyan"))
                return

            if json_output:
                results = [analyzer.estimate_improvement(i["query"], i.get("plan")) for i in items]
                console.print_json(json.dumps(results))
                return

            for item in items:
                _print_improvement(analyzer, item["query"], item.get("plan"), item.get("name"))
            return

        query = _read_sql(sql, None)
        if not query:
            error_console.print("[red]Provide --sql or --file[/red]")
            raise typer.Exit(code=1)

        if json_output:
            console.print_json(json.dumps(analyzer.estimate_improvement(query, plan)))
            return

        _print_improvement(analyzer, query, plan)


def _print_improvement(analyzer: Any, query: str, plan: Any = None, name: str | None = None) -> None:
    from querysense.planner.pg16_analyzer import PG16PlannerAnalyzer

    est = analyzer.estimate_improvement(query, plan)
    if est["improvement"] == "none":
        console.print(f"[dim]{name or query[:60]}: no PG 16-specific improvements[/dim]")
        return

    tbl = Table(title=name or query[:60], show_lines=True)
    tbl.add_column("Feature")
    tbl.add_column("Speedup", style="bold green")
    tbl.add_column("Description", style="dim")
    for f in est["features"]:
        tbl.add_row(f["description"], f"{f['expected_speedup']}x", f["pg16_improvement"])
    console.print(tbl)
    console.print(f"  [bold]Combined speedup: {est['combined_speedup']}x[/bold]\n")


# ── Helpers ───────────────────────────────────────────────────────────

from typing import Any  # noqa: E402


def _read_sql(sql: str | None, file: Path | None) -> str:
    if file and file.exists():
        return file.read_text().strip()
    return (sql or "").strip()
