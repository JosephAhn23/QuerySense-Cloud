"""
Scan command: one-shot database analysis via pg_stat_statements.

Connects to a live PostgreSQL database, discovers the slowest queries,
captures their EXPLAIN plans, runs full QuerySense analysis, and optionally
generates rewritten SQL.

This is the "pganalyze in one command" feature:
    $ querysense scan --dsn postgresql://localhost/mydb

How it works:
1. Connect to the database (read-only, statement_timeout enforced)
2. Query pg_stat_statements for top N slowest queries
3. Run EXPLAIN (FORMAT JSON) for each query
4. Run QuerySense analysis on each plan
5. Optionally run the rewrite engine
6. Optionally run the workload-wide index advisor
7. Output combined report
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register scan command on the given Typer app."""

    @app.command()
    def scan(
        dsn: Annotated[
            str,
            typer.Option(
                "--dsn",
                help="PostgreSQL connection string",
                envvar="QUERYSENSE_DSN",
            ),
        ] = "postgresql://localhost:5432/postgres",
        top_queries: Annotated[
            int,
            typer.Option(
                "--top", "-n",
                help="Number of top queries to analyze",
            ),
        ] = 20,
        min_calls: Annotated[
            int,
            typer.Option("--min-calls", help="Minimum call count to consider"),
        ] = 5,
        order_by: Annotated[
            str,
            typer.Option(
                "--order-by",
                help="Sort by: total_time, mean_time, or calls",
            ),
        ] = "total_time",
        rewrite: Annotated[
            bool,
            typer.Option(
                "--rewrite/--no-rewrite",
                help="Generate rewritten SQL for detected issues",
            ),
        ] = False,
        workload: Annotated[
            bool,
            typer.Option(
                "--workload/--no-workload",
                help="Run workload-wide index advisor across all queries",
            ),
        ] = True,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        html_output: Annotated[
            Optional[str],
            typer.Option("--html", help="Generate HTML report to file"),
        ] = None,
        save_plans: Annotated[
            Optional[str],
            typer.Option(
                "--save-plans",
                help="Directory to save captured EXPLAIN plans",
            ),
        ] = None,
        timeout: Annotated[
            float,
            typer.Option(
                "--timeout",
                help="Per-query statement timeout in seconds",
            ),
        ] = 5.0,
        budget_queries: Annotated[
            int,
            typer.Option(
                "--budget-queries",
                help="Maximum number of DB queries to run",
            ),
        ] = 100,
        disable_tablestats_limit: Annotated[
            int,
            typer.Option(
                "--disable-tablestats-limit",
                help="Skip per-table stats when table count exceeds this limit "
                     "(reduces overhead on large instances, Percona PMM parity). "
                     "Set to 0 to always collect per-table stats.",
            ),
        ] = 0,
    ) -> None:
        """
        Scan a live PostgreSQL database for slow queries and analyze them.

        Connects to pg_stat_statements, finds the slowest queries,
        captures their EXPLAIN plans, and runs full analysis.

        For large instances (>1000 tables), use --disable-tablestats-limit
        to skip per-table pg_stat_user_tables queries and reduce overhead.

        Examples:

            $ querysense scan --dsn postgresql://localhost/mydb
            $ querysense scan --dsn postgresql://prod/app --top 50 --rewrite
            $ querysense scan --dsn $DATABASE_URL --workload --html report.html
            $ querysense scan --dsn $DATABASE_URL --disable-tablestats-limit 2000
        """
        try:
            results = asyncio.run(
                _scan_database(
                    dsn=dsn,
                    top_queries=top_queries,
                    min_calls=min_calls,
                    order_by=order_by,
                    timeout=timeout,
                    budget_queries=budget_queries,
                    do_rewrite=rewrite,
                    do_workload=workload,
                    save_plans_dir=save_plans,
                    disable_tablestats_limit=disable_tablestats_limit,
                )
            )
        except Exception as e:
            error_console.print(f"[red]Error connecting to database:[/red] {e}")
            error_console.print(
                "\n[dim]Ensure pg_stat_statements is enabled:\n"
                "  shared_preload_libraries = 'pg_stat_statements'\n"
                "  CREATE EXTENSION IF NOT EXISTS pg_stat_statements;[/dim]"
            )
            raise typer.Exit(code=1)

        if json_output:
            console.print_json(json.dumps(results.to_json(), indent=2))
            return

        if html_output:
            html = results.to_html()
            Path(html_output).write_text(html, encoding="utf-8")
            console.print(f"[green]HTML report written to {html_output}[/green]")
            return

        # Rich terminal output
        _render_scan_results(results)


class ScanResults:
    """Container for scan results."""

    def __init__(self) -> None:
        self.queries_found: int = 0
        self.queries_analyzed: int = 0
        self.query_results: list[QueryResult] = []
        self.workload_report: object | None = None
        self.errors: list[str] = []

    def to_json(self) -> dict:
        return {
            "queries_found": self.queries_found,
            "queries_analyzed": self.queries_analyzed,
            "query_results": [qr.to_json() for qr in self.query_results],
            "workload_report": (
                self.workload_report.format_json()  # type: ignore[union-attr]
                if self.workload_report
                else None
            ),
            "errors": self.errors,
        }

    def to_html(self) -> str:
        """Generate combined HTML report."""
        parts = [
            "<!DOCTYPE html><html><head>",
            "<meta charset='utf-8'>",
            "<title>QuerySense Scan Report</title>",
            "<style>",
            "body{font-family:system-ui;background:#1a1a2e;color:#e0e0e0;margin:2rem;}",
            "h1{color:#00d4ff;}h2{color:#7c4dff;}h3{color:#ff6b6b;}",
            "pre{background:#16213e;padding:1rem;border-radius:8px;overflow-x:auto;}",
            "code{color:#a5d6a7;}.severity-critical{color:#ff6b6b;font-weight:bold;}",
            ".severity-warning{color:#ffa726;}.severity-info{color:#42a5f5;}",
            "table{border-collapse:collapse;width:100%;}th,td{border:1px solid #333;padding:8px;text-align:left;}",
            "th{background:#16213e;}.card{background:#16213e;border-radius:8px;padding:1.5rem;margin:1rem 0;}",
            "</style></head><body>",
            "<h1>QuerySense Scan Report</h1>",
            f"<p>Queries found: {self.queries_found} | Analyzed: {self.queries_analyzed}</p>",
        ]

        for qr in self.query_results:
            sev_class = f"severity-{qr.max_severity}" if qr.max_severity else ""
            parts.append(f"<div class='card'><h2 class='{sev_class}'>{qr.label}</h2>")
            parts.append(f"<p><strong>Calls:</strong> {qr.calls} | "
                         f"<strong>Mean time:</strong> {qr.mean_time_ms:.1f}ms | "
                         f"<strong>Findings:</strong> {qr.finding_count}</p>")
            if qr.sql_preview:
                parts.append(f"<pre><code>{qr.sql_preview}</code></pre>")
            for finding_data in qr.findings_data:
                sev = finding_data.get("severity", "info")
                parts.append(
                    f"<p class='severity-{sev}'>[{sev.upper()}] "
                    f"{finding_data.get('title', '')}</p>"
                )
                if finding_data.get("suggestion"):
                    parts.append(f"<pre><code>{finding_data['suggestion']}</code></pre>")
            if qr.rewritten_sql:
                parts.append("<h3>Rewritten SQL</h3>")
                parts.append(f"<pre><code>{qr.rewritten_sql}</code></pre>")
            parts.append("</div>")

        if self.workload_report:
            parts.append("<h2>Workload-Wide Index Recommendations</h2>")
            parts.append(f"<pre>{self.workload_report.format()}</pre>")  # type: ignore[union-attr]

        parts.append("</body></html>")
        return "\n".join(parts)


class QueryResult:
    """Result for a single query in the scan."""

    def __init__(self) -> None:
        self.label: str = ""
        self.sql_preview: str = ""
        self.calls: int = 0
        self.mean_time_ms: float = 0.0
        self.total_time_ms: float = 0.0
        self.finding_count: int = 0
        self.max_severity: str = ""
        self.findings_data: list[dict] = []
        self.rewritten_sql: str | None = None

    def to_json(self) -> dict:
        return {
            "label": self.label,
            "sql": self.sql_preview,
            "calls": self.calls,
            "mean_time_ms": round(self.mean_time_ms, 2),
            "total_time_ms": round(self.total_time_ms, 2),
            "findings": self.findings_data,
            "rewritten_sql": self.rewritten_sql,
        }


async def _scan_database(
    *,
    dsn: str,
    top_queries: int,
    min_calls: int,
    order_by: str,
    timeout: float,
    budget_queries: int,
    do_rewrite: bool,
    do_workload: bool,
    save_plans_dir: str | None,
    disable_tablestats_limit: int = 0,
) -> ScanResults:
    """Core scan logic — connects, discovers, analyzes."""
    from querysense.db import DBBudget, get_probe
    from querysense.engine import AnalysisService
    from querysense.parser import parse_explain

    results = ScanResults()

    # Connect with budget controls
    budget = DBBudget(
        max_queries=budget_queries,
        max_time_seconds=timeout * top_queries,
        statement_timeout_ms=int(timeout * 1000),
    )

    probe = await get_probe(dsn, budget=budget)

    # Table stats limit check (Percona PMM parity)
    if disable_tablestats_limit > 0:
        try:
            table_count = await probe.conn.fetchval(
                "SELECT count(*) FROM pg_stat_user_tables"
            )
            if table_count > disable_tablestats_limit:
                probe._skip_table_stats = True  # type: ignore[attr-defined]
                results.info = (
                    f"Per-table stats disabled: {table_count:,} tables exceeds "
                    f"limit of {disable_tablestats_limit:,}. Using aggregated stats only."
                )
        except Exception:
            pass  # Silently continue — table count check is best-effort

    # Step 1: Get top queries from pg_stat_statements
    top = await probe.top_queries(
        limit=top_queries,
        order_by=order_by,
        min_calls=min_calls,
    )

    results.queries_found = len(top)

    if not top:
        return results

    service = AnalysisService()

    # Prepare workload advisor if requested
    workload_advisor = None
    if do_workload:
        from querysense.workload import WorkloadAdvisor
        workload_advisor = WorkloadAdvisor()

    # Step 2: For each query, get EXPLAIN and analyze
    for i, entry in enumerate(top):
        qr = QueryResult()
        qr.label = f"query_{i + 1}"
        qr.sql_preview = entry.query_text[:200]
        qr.calls = entry.calls
        qr.mean_time_ms = entry.mean_time_ms
        qr.total_time_ms = entry.total_time_ms

        # Get EXPLAIN plan for this query
        try:
            explain_json = await _get_explain_plan(probe, entry.query_text, timeout)
            if not explain_json:
                results.errors.append(f"Could not EXPLAIN query {i + 1}")
                continue

            # Parse the EXPLAIN output
            explain = parse_explain(explain_json)

            # Save plan if requested
            if save_plans_dir:
                save_dir = Path(save_plans_dir)
                save_dir.mkdir(parents=True, exist_ok=True)
                plan_file = save_dir / f"query_{i + 1}.json"
                plan_file.write_text(
                    json.dumps(explain_json, indent=2), encoding="utf-8"
                )

            # Analyze the plan
            analysis = service.analyze(explain)
            qr.finding_count = len(analysis.findings)

            if analysis.findings:
                qr.max_severity = analysis.findings[0].severity.value

            for finding in analysis.findings:
                qr.findings_data.append({
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "description": finding.description,
                    "suggestion": finding.suggestion or "",
                })

            # Run rewriter if requested
            if do_rewrite and entry.query_text:
                from querysense.rewriter import rewrite_query
                rewrite_result = rewrite_query(
                    entry.query_text, list(analysis.findings)
                )
                if rewrite_result.was_rewritten:
                    qr.rewritten_sql = rewrite_result.format_sql()

            # Add to workload advisor
            if workload_advisor:
                workload_advisor.add_plan(
                    explain,
                    sql=entry.query_text,
                    frequency=entry.calls,
                    label=qr.label,
                )

            results.queries_analyzed += 1
            results.query_results.append(qr)

        except Exception as e:
            results.errors.append(f"Error analyzing query {i + 1}: {e}")
            results.query_results.append(qr)

    # Step 3: Run workload advisor
    if workload_advisor and results.queries_analyzed > 0:
        try:
            results.workload_report = workload_advisor.analyze()
        except Exception as e:
            results.errors.append(f"Workload analysis error: {e}")

    return results


async def _get_explain_plan(
    probe: object, query_text: str, timeout: float
) -> list | None:
    """Run EXPLAIN (FORMAT JSON) on a query via the probe connection."""
    # Use the probe's underlying connection to run EXPLAIN
    # This is safe because we're only running EXPLAIN (not executing)
    explain_sql = f"EXPLAIN (FORMAT JSON) {query_text}"

    try:
        # Access the probe's connection pool
        if hasattr(probe, "_pool") and probe._pool is not None:  # type: ignore[union-attr]
            async with probe._pool.acquire() as conn:  # type: ignore[union-attr]
                row = await conn.fetchval(explain_sql)
                if row:
                    if isinstance(row, str):
                        return json.loads(row)
                    return row
        elif hasattr(probe, "_conn") and probe._conn is not None:  # type: ignore[union-attr]
            row = await probe._conn.fetchval(explain_sql)  # type: ignore[union-attr]
            if row:
                if isinstance(row, str):
                    return json.loads(row)
                return row
    except Exception:
        pass

    return None


def _render_scan_results(results: ScanResults) -> None:
    """Render scan results with rich terminal output."""
    if not results.query_results:
        console.print(
            Panel(
                f"[yellow]No queries found in pg_stat_statements.[/yellow]\n\n"
                f"Ensure pg_stat_statements is enabled and queries have been executed.\n"
                f"Queries found: {results.queries_found}",
                title="QuerySense Scan",
                border_style="yellow",
            )
        )
        return

    # Summary panel
    total_findings = sum(qr.finding_count for qr in results.query_results)
    critical = sum(
        1 for qr in results.query_results if qr.max_severity == "critical"
    )
    warnings = sum(
        1 for qr in results.query_results if qr.max_severity == "warning"
    )

    console.print(
        Panel(
            f"[bold]Queries scanned:[/bold] {results.queries_analyzed}/{results.queries_found}\n"
            f"[bold]Total findings:[/bold] {total_findings}\n"
            f"[red]Critical:[/red] {critical} | "
            f"[yellow]Warning:[/yellow] {warnings}",
            title="[bold cyan]QuerySense Scan Results[/bold cyan]",
            border_style="cyan",
        )
    )

    # Top issues table
    table = Table(title="Query Analysis Summary")
    table.add_column("#", style="dim", width=4)
    table.add_column("Mean Time", justify="right", style="cyan")
    table.add_column("Calls", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Severity", width=10)
    table.add_column("SQL Preview", max_width=60)

    for i, qr in enumerate(results.query_results[:20], 1):
        severity_style = {
            "critical": "[red bold]CRITICAL[/red bold]",
            "warning": "[yellow]WARNING[/yellow]",
            "info": "[blue]INFO[/blue]",
        }.get(qr.max_severity, "[dim]OK[/dim]")

        table.add_row(
            str(i),
            f"{qr.mean_time_ms:.1f}ms",
            str(qr.calls),
            str(qr.finding_count),
            severity_style,
            qr.sql_preview[:60] + ("..." if len(qr.sql_preview) > 60 else ""),
        )

    console.print(table)

    # Show detailed findings for queries with issues
    for qr in results.query_results:
        if not qr.findings_data:
            continue

        console.print(f"\n[bold]{qr.label}[/bold] ({qr.mean_time_ms:.1f}ms, {qr.calls} calls)")
        console.print(f"[dim]{qr.sql_preview[:100]}[/dim]\n")

        for fd in qr.findings_data:
            sev = fd["severity"]
            if sev == "critical":
                style = "red bold"
            elif sev == "warning":
                style = "yellow"
            else:
                style = "blue"

            console.print(f"  [{style}][{sev.upper()}][/{style}] {fd['title']}")
            if fd.get("suggestion"):
                for line in fd["suggestion"].split("\n")[:3]:
                    console.print(f"    [green]{line}[/green]")

        if qr.rewritten_sql:
            console.print(f"\n  [bold magenta]Rewritten SQL:[/bold magenta]")
            for line in qr.rewritten_sql.split("\n")[:10]:
                console.print(f"    {line}")

    # Workload report
    if results.workload_report:
        console.print()
        console.print(
            Panel(
                results.workload_report.format(),  # type: ignore[union-attr]
                title="[bold]Workload-Wide Index Advisor[/bold]",
                border_style="magenta",
            )
        )

    # Errors
    if results.errors:
        console.print(f"\n[dim yellow]Warnings ({len(results.errors)}):[/dim yellow]")
        for err in results.errors[:5]:
            console.print(f"  [dim]{err}[/dim]")
