"""
History commands: track analyses, view trends, detect regressions.

Implements `querysense track` and `querysense trends` commands that
store every analysis in a local SQLite database and show 30-day
trends/regressions without any cloud infrastructure.

Usage:
    querysense track explain.json --db production
    querysense trends --table orders --days 30
    querysense history stats
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from querysense.engine import AnalysisService
from querysense.parser import ParseError, parse_explain
from querysense.parser.parser import validate_has_analyze

console = Console()
error_console = Console(stderr=True)

_DEFAULT_DB = "~/.querysense/history.db"


def register(app: typer.Typer) -> None:
    """Register history commands on the given Typer app."""

    @app.command()
    def track(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        db: Annotated[
            str,
            typer.Option("--db", help="Database name for history (used as DB file name)"),
        ] = "default",
        query_id: Annotated[
            Optional[str],
            typer.Option("--query-id", "-q", help="Stable query identifier for trend tracking"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output result as JSON"),
        ] = False,
    ) -> None:
        """
        Analyze and store results in local history database.

        Every analysis is tracked with timestamps so you can see trends
        over time. Uses a local SQLite file — no cloud required.

        \\b
        Examples:
            # Track an analysis
            $ querysense track explain.json --db production

            # Track with a stable query ID for trend analysis
            $ querysense track explain.json --query-id "users_by_email"

            # Track in CI pipeline
            $ querysense track explain.json --db ci --query-id "$QUERY_NAME" --json
        """
        from querysense.temporal.sqlite_store import SQLiteTemporalStore
        from querysense.temporal.store import PlanSnapshot
        from datetime import datetime, timezone

        db_path = Path(f"~/.querysense/{db}.db").expanduser()
        store = SQLiteTemporalStore(db_path)

        try:
            output = parse_explain(explain_file)
            service = AnalysisService()
            result = service.analyze(output)

            # Enrich findings with speedup estimates
            from querysense.analyzer.speedup import enrich_with_speedup
            enriched_result = result.model_copy(
                update={"findings": enrich_with_speedup(result.findings)}
            )

            # Store analysis
            analysis_id = enriched_result.reproducibility.analysis_id
            effective_query_id = query_id or str(explain_file.name)

            store.store_analysis(
                analysis_id=analysis_id,
                file_path=str(explain_file),
                query_id=effective_query_id,
                result=enriched_result,
            )

            # Store snapshot for temporal tracking
            snapshot = PlanSnapshot(
                query_id=effective_query_id,
                timestamp=datetime.now(timezone.utc),
                structure_hash=enriched_result.reproducibility.plan_hash,
                cost_total=output.plan.total_cost,
                node_count=enriched_result.metadata.node_count,
                latency_p50_ms=(
                    output.execution_time if output.execution_time else None
                ),
            )
            store.store(snapshot)

            # Check for regressions
            regression = store.regression_check(
                effective_query_id,
                output.plan.total_cost,
            )

            if json_output:
                data = {
                    "analysis_id": analysis_id,
                    "query_id": effective_query_id,
                    "findings": enriched_result.summary(),
                    "tracked": True,
                    "db_path": str(db_path),
                    "regression": regression,
                }
                console.print_json(json.dumps(data, default=str))
            else:
                summary = enriched_result.summary()
                console.print(f"[bold]Tracked:[/bold] {explain_file.name}")
                console.print(
                    f"  Findings: {summary['critical']} critical, "
                    f"{summary['warning']} warning, {summary['info']} info"
                )
                console.print(f"  Query ID: {effective_query_id}")
                console.print(f"  DB: {db_path}")

                if regression:
                    console.print(
                        f"\n  [red bold]REGRESSION:[/red bold] {regression['message']}"
                    )

                # Show speedup estimates for top findings
                for finding in enriched_result.findings[:3]:
                    speedup = finding.metrics.get("estimated_speedup", "")
                    if speedup:
                        console.print(
                            f"  [yellow]{finding.title}[/yellow] — {speedup}"
                        )

        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            raise typer.Exit(code=1)

    @app.command()
    def trends(
        query_id: Annotated[
            Optional[str],
            typer.Option("--query-id", "-q", help="Filter by query ID"),
        ] = None,
        table_name: Annotated[
            Optional[str],
            typer.Option("--table", "-t", help="Filter by table name in file path"),
        ] = None,
        days: Annotated[
            int,
            typer.Option("--days", "-d", help="Number of days to look back"),
        ] = 30,
        db: Annotated[
            str,
            typer.Option("--db", help="Database name"),
        ] = "default",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Show analysis trends over time with regression detection.

        Displays performance trends with sparklines, regression markers,
        and root-cause analysis. Like pganalyze trends, but offline and free.

        \\b
        Examples:
            # Show 30-day trends for all queries
            $ querysense trends --days 30

            # Filter by query ID
            $ querysense trends --query-id "users_by_email"

            # Show trends for a specific database
            $ querysense trends --db production --days 7
        """
        from querysense.temporal.sqlite_store import SQLiteTemporalStore
        from rich.panel import Panel

        db_path = Path(f"~/.querysense/{db}.db").expanduser()

        if not db_path.exists():
            error_console.print(
                f"[yellow]No history database found at {db_path}[/yellow]\n"
                f"Run 'querysense track <file>' first to start tracking."
            )
            raise typer.Exit(code=1)

        store = SQLiteTemporalStore(db_path)
        file_filter = table_name if table_name else None
        trend_data = store.trends(
            query_id=query_id,
            file_path=file_filter,
            days=days,
        )

        if json_output:
            # Enhance JSON with regression info
            enhanced = _enrich_trends_with_regressions(trend_data)
            console.print_json(json.dumps(enhanced, default=str))
            return

        if not trend_data:
            console.print(f"[dim]No analyses found in the last {days} days.[/dim]")
            return

        # ── Summary panel ────────────────────────────────────
        total = len(trend_data)
        crits = sum(e["critical_count"] for e in trend_data)
        warnings = sum(e["warning_count"] for e in trend_data)
        regressions = _detect_regressions(trend_data)

        status_color = "green" if not regressions else "red"
        status = "STABLE" if not regressions else f"{len(regressions)} REGRESSION(S)"

        console.print(Panel(
            f"[{status_color} bold]{status}[/{status_color} bold]\n"
            f"{total} analyses over {days} days | "
            f"{crits} critical | {warnings} warning",
            title=f"[bold]Trends ({db})[/bold]",
            border_style=status_color,
        ))

        # ── Sparkline for exec time ──────────────────────────
        exec_times = [
            e["execution_time_ms"] for e in trend_data
            if e.get("execution_time_ms")
        ]
        if exec_times and len(exec_times) >= 2:
            sparkline = _render_sparkline(exec_times)
            console.print(f"  Exec time: {sparkline}")
            console.print(
                f"  [dim]Min: {min(exec_times):.1f}ms | "
                f"Max: {max(exec_times):.1f}ms | "
                f"Avg: {sum(exec_times)/len(exec_times):.1f}ms[/dim]"
            )
            console.print()

        # ── Main trend table ─────────────────────────────────
        table = Table(title=f"Analysis Trends (last {days} days)")
        table.add_column("Date", style="dim")
        table.add_column("Query ID", style="cyan")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("Warning", justify="right", style="yellow")
        table.add_column("Info", justify="right", style="blue")
        table.add_column("Nodes", justify="right")
        table.add_column("Exec Time", justify="right")
        table.add_column("Status", justify="center")

        regression_ids = {r["index"] for r in regressions}
        prev_crits = 0

        for i, entry in enumerate(trend_data):
            ts = entry["timestamp"][:16]
            exec_time = (
                f"{entry['execution_time_ms']:.1f}ms"
                if entry.get("execution_time_ms")
                else "—"
            )

            # Determine status marker
            status_mark = ""
            if i in regression_ids:
                status_mark = "[red bold]⚠ REGRESS[/red bold]"
            elif entry["critical_count"] > prev_crits and prev_crits > 0:
                status_mark = "[yellow]↑[/yellow]"
            elif entry["critical_count"] < prev_crits:
                status_mark = "[green]✓ Fixed[/green]"
            elif entry["critical_count"] == 0 and entry["warning_count"] == 0:
                status_mark = "[green]✓[/green]"

            prev_crits = entry["critical_count"]

            table.add_row(
                ts,
                entry["query_id"] or "—",
                str(entry["critical_count"]),
                str(entry["warning_count"]),
                str(entry["info_count"]),
                str(entry["node_count"]),
                exec_time,
                status_mark,
            )

        console.print(table)

        # ── Regression details ───────────────────────────────
        if regressions:
            console.print()
            console.print("[bold red]Regressions Detected:[/bold red]")
            for reg in regressions:
                console.print(
                    f"  [red]⚠[/red]  {reg['timestamp'][:16]} — {reg['message']}"
                )
                if reg.get("root_cause"):
                    console.print(f"     [dim]Root cause: {reg['root_cause']}[/dim]")
                if reg.get("suggestion"):
                    console.print(f"     [dim]Fix: {reg['suggestion']}[/dim]")

        # ── Prevention tips ──────────────────────────────────
        if regressions:
            console.print()
            console.print(
                "[dim]Prevention: Add 'querysense check --baseline main.json "
                "--current pr.json' to your CI pipeline[/dim]"
            )

    @app.command(name="stats")
    def history_stats(
        db: Annotated[
            str,
            typer.Option("--db", help="Database name"),
        ] = "default",
    ) -> None:
        """Show history database statistics."""
        from querysense.temporal.sqlite_store import SQLiteTemporalStore

        db_path = Path(f"~/.querysense/{db}.db").expanduser()

        if not db_path.exists():
            console.print(f"[dim]No history database at {db_path}[/dim]")
            raise typer.Exit(code=1)

        store = SQLiteTemporalStore(db_path)
        stats = store.summary_stats()

        console.print("[bold]History Database Stats:[/bold]")
        console.print(f"  Database: {stats['db_path']}")
        console.print(f"  Total analyses: {stats['total_analyses']}")
        console.print(f"  Unique queries: {stats['unique_queries']}")
        console.print(f"  Last 7 days: {stats['analyses_last_7d']}")


def _render_sparkline(values: list[float], width: int = 40) -> str:
    """Render a Unicode sparkline for a series of values."""
    if not values:
        return ""

    bars = "▁▂▃▄▅▆▇█"
    mn, mx = min(values), max(values)
    rng = mx - mn if mx != mn else 1.0

    # Resample if too many values
    if len(values) > width:
        step = len(values) / width
        sampled = []
        for i in range(width):
            idx = int(i * step)
            sampled.append(values[min(idx, len(values) - 1)])
        values = sampled

    chars = []
    for v in values:
        idx = int(((v - mn) / rng) * (len(bars) - 1))
        idx = max(0, min(idx, len(bars) - 1))
        chars.append(bars[idx])

    return "".join(chars)


def _detect_regressions(
    trend_data: list[dict],
    exec_time_threshold: float = 2.0,
    findings_threshold: int = 2,
) -> list[dict]:
    """
    Detect regressions in trend data.

    Checks for:
    - Execution time spikes (>2x previous)
    - Critical finding count increases
    - Node count changes (plan structure change)
    """
    regressions: list[dict] = []

    for i in range(1, len(trend_data)):
        curr = trend_data[i]
        prev = trend_data[i - 1]

        # Execution time spike
        curr_time = curr.get("execution_time_ms") or 0
        prev_time = prev.get("execution_time_ms") or 0

        if prev_time > 0 and curr_time > 0:
            ratio = curr_time / prev_time
            if ratio >= exec_time_threshold:
                root_cause = ""
                suggestion = ""

                # Try to identify root cause
                if curr.get("node_count", 0) != prev.get("node_count", 0):
                    root_cause = (
                        f"Plan structure changed "
                        f"({prev['node_count']} → {curr['node_count']} nodes)"
                    )
                    suggestion = (
                        "A schema or statistics change may have caused "
                        "the optimizer to choose a different plan"
                    )

                regressions.append({
                    "index": i,
                    "timestamp": curr["timestamp"],
                    "query_id": curr.get("query_id", ""),
                    "type": "execution_time",
                    "message": (
                        f"Execution time {ratio:.1f}x increase "
                        f"({prev_time:.1f}ms → {curr_time:.1f}ms)"
                    ),
                    "root_cause": root_cause,
                    "suggestion": suggestion,
                })

        # Critical findings increase
        curr_crits = curr.get("critical_count", 0)
        prev_crits = prev.get("critical_count", 0)
        new_crits = curr_crits - prev_crits

        if new_crits >= findings_threshold:
            regressions.append({
                "index": i,
                "timestamp": curr["timestamp"],
                "query_id": curr.get("query_id", ""),
                "type": "findings",
                "message": f"{new_crits} new critical finding(s)",
                "root_cause": "",
                "suggestion": (
                    f"Run 'querysense analyze {curr.get('file_path', '<file>')}' "
                    f"for details"
                ),
            })

    return regressions


def _enrich_trends_with_regressions(trend_data: list[dict]) -> list[dict]:
    """Enrich trend data with regression flags for JSON output."""
    regressions = _detect_regressions(trend_data)
    regression_indices = {r["index"]: r for r in regressions}

    enriched = []
    for i, entry in enumerate(trend_data):
        e = dict(entry)
        if i in regression_indices:
            e["regression"] = True
            e["regression_type"] = regression_indices[i]["type"]
            e["regression_message"] = regression_indices[i]["message"]
        else:
            e["regression"] = False
        enriched.append(e)

    return enriched
