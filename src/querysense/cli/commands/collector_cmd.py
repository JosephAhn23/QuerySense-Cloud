"""
CLI commands for the Stats Collector, Monitoring Setup, and VACUUM History.

Commands:
    querysense collect              -- Run one collection snapshot
    querysense collect run          -- Start continuous collection daemon
    querysense monitor setup        -- Create monitoring user (SQL script or live)
    querysense monitor verify       -- Verify monitoring user permissions
    querysense vacuum-history record   -- Record a vacuum snapshot
    querysense vacuum-history trends   -- Analyze vacuum trends
    querysense vacuum-history predict  -- Predict future bloat
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register_collect(app: typer.Typer) -> None:
    """Register collector commands on the given Typer app."""

    @app.command("collect")
    def collect(
        dsn: Annotated[
            str,
            typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        explain_top_n: Annotated[
            int,
            typer.Option("--explain-top", help="Number of top queries to EXPLAIN"),
        ] = 20,
        continuous: Annotated[
            bool,
            typer.Option("--continuous", "-c", help="Run continuously (daemon mode)"),
        ] = False,
        interval: Annotated[
            int,
            typer.Option("--interval", help="Collection interval in seconds (for --continuous)"),
        ] = 600,
        max_iterations: Annotated[
            int,
            typer.Option("--max-iterations", help="Stop after N iterations (0=forever)"),
        ] = 0,
    ) -> None:
        """
        Collect pg_stat_statements snapshots and EXPLAIN plans.

        Reverse-engineered from pganalyze/collector (BSD-3-Clause).
        Captures query stats, runs EXPLAIN on top queries, detects regressions.

        Single snapshot:  querysense collect --dsn postgresql://...
        Continuous:       querysense collect --dsn postgresql://... --continuous
        """
        from querysense.collector import CollectorConfig, StatsCollector

        config = CollectorConfig(
            dsn=dsn,
            explain_top_n=explain_top_n,
            interval_seconds=interval,
        )

        async def _run() -> None:
            collector = StatsCollector(config)

            if continuous:
                console.print(Panel(
                    f"[bold]QuerySense Stats Collector[/bold]\n"
                    f"Interval: {interval}s | EXPLAIN top {explain_top_n} queries\n"
                    f"Press Ctrl+C to stop",
                    border_style="blue",
                ))
                await collector.run(max_iterations=max_iterations)
            else:
                snapshot = await collector.collect_once()

                if json_output:
                    console.print_json(json.dumps(snapshot.to_dict(), indent=2, default=str))
                    return

                console.print()
                console.print(Panel(
                    f"[bold]Collection Snapshot[/bold]\n"
                    f"Queries: {snapshot.query_count} | "
                    f"EXPLAINs: {len(snapshot.explains)} | "
                    f"Regressions: {len(snapshot.regressions)} | "
                    f"Time: {snapshot.duration_ms:.0f}ms",
                    border_style="green",
                ))

                if snapshot.regressions:
                    console.print()
                    console.print("[bold red]Regressions Detected:[/bold red]")
                    for r in snapshot.regressions:
                        console.print(
                            f"  [{r.alert_type}] {r.detail}"
                        )
                        console.print(f"    Query: {r.query[:100]}...")
                        console.print()

                if snapshot.queries:
                    console.print("[bold cyan]Top Queries by Time:[/bold cyan]")
                    table = Table(show_header=True, header_style="bold")
                    table.add_column("Query", max_width=60)
                    table.add_column("Calls", justify="right")
                    table.add_column("Total Time", justify="right")
                    table.add_column("Mean", justify="right")
                    table.add_column("Cache Hit", justify="right")

                    for q in sorted(snapshot.queries, key=lambda q: q.delta_total_time_ms, reverse=True)[:10]:
                        table.add_row(
                            q.query[:60].replace("\n", " "),
                            f"{q.delta_calls:,}",
                            f"{q.delta_total_time_ms:,.0f}ms",
                            f"{q.mean_exec_time_ms:.1f}ms",
                            f"{q.cache_hit_ratio:.1%}",
                        )
                    console.print(table)

                if snapshot.errors:
                    for err in snapshot.errors:
                        error_console.print(f"[red]Error:[/red] {err}")

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Collection stopped.[/yellow]")


def register_monitor(app: typer.Typer) -> None:
    """Register monitoring setup commands."""

    @app.command("monitor-setup")
    def monitor_setup(
        dsn: Annotated[
            Optional[str],
            typer.Option("--dsn", "-d", help="Admin DSN to apply setup (omit for SQL-only output)"),
        ] = None,
        username: Annotated[
            str,
            typer.Option("--username", "-u", help="Monitoring username to create"),
        ] = "querysense_monitor",
        database: Annotated[
            str,
            typer.Option("--database", help="Database name (for SQL output)"),
        ] = "mydb",
        password: Annotated[
            Optional[str],
            typer.Option("--password", "-p", help="Password (auto-generated if omitted)"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Create a least-privilege monitoring user for QuerySense.

        Without --dsn: prints a SQL script you can run manually.
        With --dsn: applies the setup directly using admin credentials.

        The monitoring user gets pg_read_all_stats (PG 10+) or
        individual GRANTs for pg_stat_statements, pg_stat_activity, etc.
        """
        from querysense.db.monitoring_setup import MonitoringSetup

        setup = MonitoringSetup()

        if dsn:
            async def _apply() -> None:
                report = await setup.apply(
                    admin_dsn=dsn,
                    username=username,
                    password=password,
                )

                if json_output:
                    console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
                    return

                if report.success:
                    console.print(Panel(
                        f"[bold green]Monitoring user created successfully![/bold green]\n\n"
                        f"Username: {report.username}\n"
                        f"Database: {report.database}\n"
                        f"PG Version: {report.pg_version}\n"
                        f"DSN: {report.dsn}\n\n"
                        f"Steps: {', '.join(report.steps_completed)}",
                        border_style="green",
                    ))
                else:
                    error_console.print(f"[red]Setup failed:[/red]")
                    for err in report.errors:
                        error_console.print(f"  {err}")

                for warning in report.warnings:
                    console.print(f"[yellow]Warning:[/yellow] {warning}")

            import asyncio
            asyncio.run(_apply())
        else:
            sql = setup.generate_sql(
                username=username,
                database=database,
                password=password,
            )
            if json_output:
                console.print_json(json.dumps({"sql": sql}))
            else:
                console.print(sql)

    @app.command("monitor-verify")
    def monitor_verify(
        dsn: Annotated[
            str,
            typer.Option("--dsn", "-d", help="Monitoring user DSN to verify", envvar="QUERYSENSE_DSN"),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Verify that a monitoring user has the required permissions.

        Tests access to pg_stat_statements, pg_stat_activity,
        pg_settings, and other required views.
        """
        from querysense.db.monitoring_setup import MonitoringSetup

        setup = MonitoringSetup()

        async def _verify() -> None:
            results = await setup.verify(dsn)

            if json_output:
                console.print_json(json.dumps(results, indent=2))
                return

            table = Table(
                title="Permission Verification",
                show_header=True,
                header_style="bold",
            )
            table.add_column("Permission", min_width=25)
            table.add_column("Status", width=10)

            all_ok = True
            for name, ok in results.items():
                status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
                if not ok:
                    all_ok = False
                table.add_row(name, status)

            console.print(table)

            if all_ok:
                console.print("\n[bold green]All permissions verified.[/bold green]")
            else:
                failed = [k for k, v in results.items() if not v]
                console.print(f"\n[bold red]{len(failed)} permission(s) missing.[/bold red]")
                console.print("Run: querysense monitor-setup --dsn <admin_dsn>")

        import asyncio
        asyncio.run(_verify())


def register_vacuum_history(app: typer.Typer) -> None:
    """Register vacuum history commands."""

    @app.command("vacuum-snapshot")
    def vacuum_snapshot(
        dsn: Annotated[
            str,
            typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ],
        db_path: Annotated[
            str,
            typer.Option("--db", help="SQLite database path for history"),
        ] = ".querysense/vacuum_history.db",
    ) -> None:
        """
        Record a vacuum health snapshot for trend tracking.

        Run periodically (e.g., hourly via cron) to build history:
            querysense vacuum-snapshot --dsn postgresql://...

        Then analyze trends:
            querysense vacuum-trends --days 30
        """
        from querysense.db.vacuum_history import VacuumHistoryTracker

        tracker = VacuumHistoryTracker(db_path=db_path)

        async def _record() -> None:
            import asyncpg
            conn = await asyncpg.connect(dsn)
            try:
                count = await tracker.record_snapshot(conn)
                console.print(f"[green]Recorded snapshot: {count} tables[/green]")
            finally:
                await conn.close()

        import asyncio
        asyncio.run(_record())

    @app.command("vacuum-trends")
    def vacuum_trends(
        days: Annotated[
            int,
            typer.Option("--days", help="Number of days to analyze"),
        ] = 30,
        db_path: Annotated[
            str,
            typer.Option("--db", help="SQLite database path"),
        ] = ".querysense/vacuum_history.db",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Analyze vacuum trends over time.

        Shows which tables are degrading, improving, or stable.
        Requires prior vacuum-snapshot runs.
        """
        from querysense.db.vacuum_history import VacuumHistoryTracker

        tracker = VacuumHistoryTracker(db_path=db_path)
        trends = tracker.analyze_trends(days=days)

        if json_output:
            console.print_json(json.dumps([t.to_dict() for t in trends], indent=2, default=str))
            return

        if not trends:
            console.print("[yellow]No vacuum history data found. Run 'querysense vacuum-snapshot' first.[/yellow]")
            return

        console.print(Panel(
            f"[bold]VACUUM Trend Analysis ({days} days)[/bold]",
            border_style="blue",
        ))

        table = Table(show_header=True, header_style="bold")
        table.add_column("Table", min_width=25)
        table.add_column("Direction", width=12)
        table.add_column("Bloat", justify="right")
        table.add_column("Change", justify="right")
        table.add_column("Vacuum Freq", justify="right")
        table.add_column("Freeze Rate", justify="right")
        table.add_column("Points", justify="right", width=6)

        for t in trends:
            direction_color = {
                "critical": "bold red",
                "degrading": "yellow",
                "stable": "dim",
                "improving": "green",
            }.get(t.direction, "white")

            change_str = f"{t.bloat_change_pct:+.1f}%"
            freq_str = f"every {t.avg_hours_between_vacuums:.0f}h" if t.avg_hours_between_vacuums > 0 else "none"
            freeze_str = f"{t.freeze_rate_per_day:,.0f}/day" if t.freeze_rate_per_day > 0 else "—"

            table.add_row(
                t.full_name,
                f"[{direction_color}]{t.direction}[/{direction_color}]",
                f"{t.bloat_pct_end:.1f}%",
                change_str,
                freq_str,
                freeze_str,
                str(t.data_points),
            )

        console.print(table)

        degrading = [t for t in trends if t.direction in ("degrading", "critical")]
        if degrading:
            console.print(f"\n[bold yellow]{len(degrading)} table(s) need attention:[/bold yellow]")
            for t in degrading[:5]:
                console.print(f"  {t.full_name}: {t.recommendation}" if hasattr(t, 'recommendation') else f"  {t.full_name}: bloat {t.bloat_change_pct:+.1f}% over {t.period_days} days")

    @app.command("vacuum-predict")
    def vacuum_predict(
        days_ahead: Annotated[
            int,
            typer.Option("--days", help="Days ahead to predict"),
        ] = 7,
        db_path: Annotated[
            str,
            typer.Option("--db", help="SQLite database path"),
        ] = ".querysense/vacuum_history.db",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Predict future bloat levels based on historical trends.

        Warns when tables are on track to exceed critical bloat thresholds.
        """
        from querysense.db.vacuum_history import VacuumHistoryTracker

        tracker = VacuumHistoryTracker(db_path=db_path)
        predictions = tracker.predict_bloat(days_ahead=days_ahead)

        if json_output:
            console.print_json(json.dumps([p.to_dict() for p in predictions], indent=2, default=str))
            return

        if not predictions:
            console.print("[green]No bloat predictions to report — all tables look healthy.[/green]")
            return

        console.print(Panel(
            f"[bold]Bloat Predictions ({days_ahead} days ahead)[/bold]",
            border_style="blue",
        ))

        for p in predictions:
            severity_color = "red" if p.predicted_bloat_pct > 50 else "yellow" if p.predicted_bloat_pct > 30 else "dim"
            console.print(
                f"  [{severity_color}]{p.full_name}[/{severity_color}]: "
                f"{p.current_bloat_pct:.1f}% → [bold]{p.predicted_bloat_pct:.1f}%[/bold] "
                f"(confidence: {p.confidence:.0%})"
            )
            if p.days_until_critical is not None:
                console.print(f"    Critical in ~{p.days_until_critical:.0f} days")
            if p.recommendation:
                console.print(f"    {p.recommendation}")
            console.print()
