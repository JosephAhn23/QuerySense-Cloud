"""
Health command: comprehensive database health analysis.

Combines wait event analysis, vacuum advisor, long-running query detection,
redundant index detection, and infrastructure metrics into a single
diagnostic command.

    $ querysense health --dsn postgresql://localhost/mydb
    $ querysense health --dsn postgresql://prod/app --json
    $ querysense health --dsn $DB_URL --check vacuum
    $ querysense health --dsn $DB_URL --check indexes
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register health command on the given Typer app."""

    @app.command()
    def health(
        dsn: Annotated[
            str,
            typer.Option(
                "--dsn",
                help="PostgreSQL connection string",
                envvar="QUERYSENSE_DSN",
            ),
        ] = "postgresql://localhost:5432/postgres",
        check: Annotated[
            Optional[str],
            typer.Option(
                "--check", "-c",
                help="Specific check: 'all', 'vacuum', 'indexes', 'waits', 'queries', 'infra'",
            ),
        ] = "all",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        long_query_threshold: Annotated[
            float,
            typer.Option("--long-query-threshold", help="Long query threshold in seconds"),
        ] = 30.0,
        fail_on_critical: Annotated[
            bool,
            typer.Option("--fail-on-critical", help="Exit 1 if critical issues found"),
        ] = False,
    ) -> None:
        """
        Comprehensive database health analysis.

        Runs multiple diagnostic checks and produces an actionable report.
        This is the "Percona PMM advisor" equivalent — but CLI-first.

        Checks included:
        - Wait event analysis (like Datadog DBM)
        - Vacuum health + autovacuum tuning (like pganalyze)
        - Long-running query detection (like PgHero)
        - Redundant index detection (like EverSQL)
        - Infrastructure metrics correlation

        \b
        Examples:
            # Full health check
            $ querysense health --dsn postgresql://localhost/mydb

            # Just vacuum health
            $ querysense health --dsn $DB_URL --check vacuum

            # CI mode
            $ querysense health --dsn $DB_URL --fail-on-critical --json
        """
        checks = check or "all"

        async def _run() -> dict:
            try:
                import asyncpg
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg is required.\n"
                    "Install with: pip install querysense[db]"
                )
                raise typer.Exit(code=1)

            try:
                conn = await asyncpg.connect(dsn)
            except Exception as e:
                error_console.print(f"[red]Connection failed:[/red] {e}")
                raise typer.Exit(code=1)

            results: dict = {"checks": {}, "critical_count": 0}

            try:
                # Wait events
                if checks in ("all", "waits"):
                    from querysense.db.wait_events import collect_wait_events
                    we = await collect_wait_events(conn)
                    results["checks"]["wait_events"] = we.to_dict()
                    results["critical_count"] += sum(
                        1 for w in we.health_warnings()
                        if "saturated" in w.lower() or "contention" in w.lower()
                    )

                # Vacuum health
                if checks in ("all", "vacuum"):
                    from querysense.db.vacuum_advisor import collect_vacuum_health
                    vac = await collect_vacuum_health(conn)
                    results["checks"]["vacuum"] = vac.to_dict()
                    results["critical_count"] += vac.critical_count

                # Long-running queries
                if checks in ("all", "queries"):
                    from querysense.db.long_queries import detect_long_queries
                    lq = await detect_long_queries(
                        conn, threshold_seconds=long_query_threshold,
                    )
                    results["checks"]["long_queries"] = lq.to_dict()
                    results["critical_count"] += lq.critical_count

                # Redundant indexes
                if checks in ("all", "indexes"):
                    from querysense.db.index_bloat import detect_redundant_indexes
                    idx = await detect_redundant_indexes(conn)
                    results["checks"]["indexes"] = idx.to_dict()

                # Infrastructure metrics
                if checks in ("all", "infra"):
                    from querysense.db.infra_metrics import collect_infra_metrics
                    infra = await collect_infra_metrics(conn)
                    results["checks"]["infra"] = infra.to_dict()
                    results["critical_count"] += sum(
                        1 for w in infra.health_summary()
                        if "deadlock" in w.lower() or "fsync" in w.lower()
                    )

            finally:
                await conn.close()

            return results

        results = asyncio.run(_run())

        if json_output:
            console.print_json(json.dumps(results, default=str))
            if fail_on_critical and results["critical_count"] > 0:
                raise typer.Exit(code=1)
            return

        # Pretty output
        console.print(Panel(
            "[bold]QuerySense Database Health Report[/bold]",
            border_style="cyan",
        ))

        has_critical = False

        # Wait events
        if "wait_events" in results["checks"]:
            we_data = results["checks"]["wait_events"]
            we_table = Table(title="Wait Events")
            we_table.add_column("Type", style="cyan")
            we_table.add_column("Event")
            we_table.add_column("Sessions", justify="right")
            we_table.add_column("Category")

            for evt in we_data.get("top_wait_events", [])[:8]:
                we_table.add_row(
                    evt["type"], evt["event"],
                    str(evt["count"]), evt["category"],
                )
            console.print(we_table)

            for w in we_data.get("health_warnings", []):
                console.print(f"  [yellow]!![/yellow] {w}")

        # Vacuum
        if "vacuum" in results["checks"]:
            vac_data = results["checks"]["vacuum"]
            console.print(f"\n[bold]Vacuum Health:[/bold] {vac_data.get('summary', '')}")

            vac_issues = vac_data.get("issues", [])
            if vac_issues:
                vac_table = Table(title="Vacuum Issues")
                vac_table.add_column("Severity", style="bold")
                vac_table.add_column("Table", style="cyan")
                vac_table.add_column("Issue")
                vac_table.add_column("Fix", style="dim")

                sev_styles = {
                    "critical": "[red]CRIT[/red]",
                    "warning": "[yellow]WARN[/yellow]",
                    "info": "[blue]INFO[/blue]",
                }

                for issue in vac_issues[:15]:
                    if issue["severity"] == "critical":
                        has_critical = True
                    vac_table.add_row(
                        sev_styles.get(issue["severity"], issue["severity"]),
                        issue["table"],
                        issue["message"],
                        issue.get("suggestion", ""),
                    )
                console.print(vac_table)

            for rec in vac_data.get("recommendations", []):
                console.print(f"  [cyan]>>>[/cyan] {rec}")

        # Long queries
        if "long_queries" in results["checks"]:
            lq_data = results["checks"]["long_queries"]
            console.print(f"\n[bold]Long-Running Queries:[/bold] {lq_data.get('summary', '')}")

            for q in lq_data.get("queries", [])[:10]:
                sev = q.get("severity", "info")
                style = "[red]" if sev == "critical" else "[yellow]"
                if sev == "critical":
                    has_critical = True
                console.print(
                    f"  {style}PID {q['pid']}[/{style[1:]}] "
                    f"{q['duration_seconds']:.0f}s "
                    f"{'[BLOCKED]' if q.get('is_blocked') else ''} "
                    f"{q['query'][:80]}"
                )

            for q in lq_data.get("idle_in_transaction", [])[:5]:
                console.print(
                    f"  [yellow]PID {q['pid']}[/yellow] "
                    f"idle-in-txn {q['duration_seconds']:.0f}s "
                    f"{q['query'][:60]}"
                )

        # Indexes
        if "indexes" in results["checks"]:
            idx_data = results["checks"]["indexes"]
            console.print(f"\n[bold]Index Health:[/bold] {idx_data.get('summary', '')}")

            for issue in idx_data.get("issues", [])[:10]:
                sev = issue.get("severity", "info")
                icon = "[red]!![/red]" if sev == "critical" else (
                    "[yellow]![/yellow]" if sev == "warning" else "[dim]-[/dim]"
                )
                console.print(
                    f"  {icon} {issue['type']}: {issue['index']} "
                    f"on {issue['table']} - {issue['message']}"
                )
                if issue.get("drop_sql"):
                    console.print(f"    [dim]Fix: {issue['drop_sql']}[/dim]")

        # Infrastructure
        if "infra" in results["checks"]:
            infra_data = results["checks"]["infra"]
            db_data = infra_data.get("database", {})
            if db_data:
                cache_ratio = db_data.get("cache_hit_ratio", 1.0)
                cache_status = "[green]OK[/green]" if cache_ratio >= 0.99 else "[red]LOW[/red]"
                console.print(
                    f"\n[bold]Infrastructure:[/bold] "
                    f"Cache: {cache_ratio:.2%} {cache_status} | "
                    f"Deadlocks: {db_data.get('deadlocks', 0)} | "
                    f"Temp Files: {db_data.get('temp_files', 0)}"
                )

        # Summary
        total_critical = results.get("critical_count", 0)
        if total_critical > 0:
            console.print(
                f"\n[red bold]{total_critical} critical issue(s) found.[/red bold]"
            )
        else:
            console.print("\n[green]No critical issues found.[/green]")

        if fail_on_critical and has_critical:
            raise typer.Exit(code=1)

    @app.command(name="auto-explain")
    def auto_explain(
        log_file: Annotated[
            str,
            typer.Argument(help="Path to PostgreSQL log file with auto_explain output"),
        ],
        min_duration: Annotated[
            float,
            typer.Option("--min-duration", "-d", help="Minimum duration in ms to include"),
        ] = 100.0,
        max_entries: Annotated[
            int,
            typer.Option("--max-entries", "-n", help="Maximum entries to process"),
        ] = 100,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Analyze auto_explain log output from PostgreSQL.

        Parses plans captured by the auto_explain module and runs
        QuerySense analysis on each one. Like pganalyze Log Insights
        but offline and free.

        \b
        PostgreSQL setup:
            shared_preload_libraries = 'auto_explain'
            auto_explain.log_min_duration = '100ms'
            auto_explain.log_format = 'json'
            auto_explain.log_analyze = true

        \b
        Examples:
            $ querysense auto-explain /var/log/postgresql/postgresql.log
            $ querysense auto-explain pg.log --min-duration 500 --json
        """
        from pathlib import Path
        from querysense.auto_explain_parser import (
            parse_auto_explain_log,
            analyze_auto_explain_entries,
        )

        try:
            entries = parse_auto_explain_log(
                log_file,
                min_duration_ms=min_duration,
                max_entries=max_entries,
            )
        except FileNotFoundError:
            error_console.print(f"[red]Error:[/red] File not found: {log_file}")
            raise typer.Exit(code=1)

        if not entries:
            console.print("[dim]No auto_explain entries found matching criteria.[/dim]")
            return

        console.print(f"[bold]Found {len(entries)} auto_explain entries[/bold]")

        # Analyze entries with JSON plans
        json_entries = [e for e in entries if e.has_json_plan]
        if json_entries:
            results = analyze_auto_explain_entries(json_entries)

            if json_output:
                console.print_json(json.dumps(results, default=str))
                return

            # Pretty output
            result_table = Table(title=f"Auto-Explain Analysis ({len(results)} plans)")
            result_table.add_column("Duration", justify="right", style="cyan")
            result_table.add_column("Findings", justify="right")
            result_table.add_column("Top Issue", max_width=40)
            result_table.add_column("Query", max_width=50, style="dim")

            for r in sorted(results, key=lambda x: x.get("duration_ms", 0), reverse=True)[:20]:
                dur = f"{r['duration_ms']:.0f}ms"
                total = r.get("findings_total", 0)
                crit = r.get("findings_critical", 0)
                findings_str = f"{total}"
                if crit:
                    findings_str = f"[red]{total} ({crit} crit)[/red]"
                top = r.get("top_finding") or r.get("error", "")
                if len(top) > 40:
                    top = top[:37] + "..."
                query = r.get("query", "")[:50]

                result_table.add_row(dur, findings_str, top, query)

            console.print(result_table)
        else:
            if json_output:
                data = [e.to_dict() for e in entries]
                console.print_json(json.dumps(data, default=str))
            else:
                console.print(
                    f"[yellow]{len(entries)} entries found but none have JSON plans.[/yellow]\n"
                    f"Ensure auto_explain.log_format = 'json' in postgresql.conf"
                )
