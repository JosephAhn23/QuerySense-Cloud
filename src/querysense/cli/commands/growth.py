"""
Table growth tracking CLI command.

Monitor table sizes over time, detect anomalies, project capacity needs.
Closes the pganalyze gap: "Table growth trends — size over time, bloat estimates."

    $ querysense growth snapshot --dsn postgresql://localhost/mydb
    $ querysense growth trends --days 30
    $ querysense growth project --days 90
    $ querysense growth anomalies
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


def register(growth_app: typer.Typer) -> None:
    """Register growth tracking commands."""

    @growth_app.command(name="snapshot")
    def growth_snapshot(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        db_path: Annotated[
            Optional[str],
            typer.Option("--db", help="SQLite database path for history"),
        ] = None,
    ) -> None:
        """
        Record a table size snapshot (run daily via cron).

        Stores current table sizes, row counts, and bloat metrics in local
        SQLite for trend analysis. Run daily via cron or CI/CD.

        \b
        Example crontab entry:
            0 6 * * * querysense growth snapshot --dsn $DB_URL
        """
        from querysense.table_growth import TableGrowthTracker

        async def _run() -> int:
            try:
                import asyncpg
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg required.\n"
                    "Install: pip install querysense[db]"
                )
                raise typer.Exit(code=1)

            try:
                conn = await asyncpg.connect(dsn)
            except Exception as e:
                error_console.print(f"[red]Connection failed:[/red] {e}")
                raise typer.Exit(code=1)

            try:
                query = TableGrowthTracker.get_catalog_query()
                rows = await conn.fetch(query)
                data = [dict(r) for r in rows]
            finally:
                await conn.close()

            tracker = TableGrowthTracker(db_path=db_path)
            return tracker.record_snapshot(data)

        count = asyncio.run(_run())
        console.print(f"[green]✓[/green] Recorded snapshot for {count} tables")
        console.print(f"[dim]Stored in: {db_path or '~/.querysense/growth.db'}[/dim]")

    @growth_app.command(name="trends")
    def growth_trends(
        days: Annotated[
            int,
            typer.Option("--days", "-d", help="Number of days to analyze"),
        ] = 30,
        table_name: Annotated[
            Optional[str],
            typer.Option("--table", "-t", help="Specific table to analyze"),
        ] = None,
        db_path: Annotated[
            Optional[str],
            typer.Option("--db", help="SQLite database path"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Show table growth trends over time.

        Displays growth rate (MB/day), row changes, and bloat trends.
        Like pganalyze's table growth charts — but local and free.

        \b
        Examples:
            $ querysense growth trends --days 30
            $ querysense growth trends --table orders --days 7
        """
        from querysense.table_growth import TableGrowthTracker

        tracker = TableGrowthTracker(db_path=db_path)
        trends = tracker.get_trends(table=table_name, days=days)

        if json_output:
            data = [
                {
                    "table": f"{t.schema}.{t.table}",
                    "period_days": t.period_days,
                    "current_size_mb": round(t.current_size_mb, 1),
                    "growth_mb_day": round(t.growth_rate_mb_per_day, 2),
                    "growth_pct": round(t.growth_pct, 1),
                    "rows": t.current_rows,
                    "bloat_ratio": round(t.current_bloat_ratio, 3),
                    "bloat_trend": t.bloat_trend,
                }
                for t in trends
            ]
            console.print_json(json.dumps(data, indent=2))
            return

        if not trends:
            console.print("[yellow]No trend data available. Run 'querysense growth snapshot' first.[/yellow]")
            return

        console.print(Panel(
            f"[bold]Growth trends for last {days} days[/bold]",
            title="[bold]QuerySense Table Growth[/bold]",
        ))

        tbl = Table()
        tbl.add_column("Table", style="cyan")
        tbl.add_column("Current Size", justify="right")
        tbl.add_column("Change", justify="right")
        tbl.add_column("Growth/Day", justify="right")
        tbl.add_column("Rows", justify="right")
        tbl.add_column("Bloat", justify="right")
        tbl.add_column("Trend")

        for t in trends:
            # Size formatting
            if t.current_size_mb >= 1024:
                size_str = f"{t.current_size_mb / 1024:.1f}GB"
            else:
                size_str = f"{t.current_size_mb:.1f}MB"

            # Growth formatting
            if t.growth_rate_mb_per_day > 0:
                change_style = "red" if t.growth_rate_mb_per_day > 10 else "yellow"
                change = f"[{change_style}]+{t.size_change_mb:.1f}MB[/{change_style}]"
                rate = f"[{change_style}]+{t.growth_rate_mb_per_day:.2f}MB/d[/{change_style}]"
            elif t.growth_rate_mb_per_day < 0:
                change = f"[green]{t.size_change_mb:.1f}MB[/green]"
                rate = f"[green]{t.growth_rate_mb_per_day:.2f}MB/d[/green]"
            else:
                change = "0MB"
                rate = "0MB/d"

            # Bloat
            bloat_pct = t.current_bloat_ratio * 100
            if bloat_pct > 20:
                bloat_str = f"[red]{bloat_pct:.1f}%[/red]"
            elif bloat_pct > 10:
                bloat_str = f"[yellow]{bloat_pct:.1f}%[/yellow]"
            else:
                bloat_str = f"[green]{bloat_pct:.1f}%[/green]"

            # Trend indicator
            trend_icon = {"increasing": "📈", "decreasing": "📉", "stable": "➡️"}.get(t.bloat_trend, "")

            tbl.add_row(
                f"{t.schema}.{t.table}",
                size_str,
                change,
                rate,
                f"{t.current_rows:,}",
                bloat_str,
                f"{trend_icon} {t.bloat_trend}",
            )

        console.print(tbl)

    @growth_app.command(name="project")
    def growth_project(
        days: Annotated[
            int,
            typer.Option("--days", "-d", help="Project N days into the future"),
        ] = 90,
        db_path: Annotated[
            Optional[str],
            typer.Option("--db", help="SQLite database path"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Project future table growth for capacity planning.

        Estimates when tables will reach 1GB, 10GB, 100GB milestones.
        Like pganalyze's capacity planning — but free.

        \b
        Example:
            $ querysense growth project --days 365
        """
        from querysense.table_growth import TableGrowthTracker

        tracker = TableGrowthTracker(db_path=db_path)
        projections = tracker.project_growth(days=days)

        if json_output:
            data = [
                {
                    "table": f"{p.schema}.{p.table}",
                    "current_mb": round(p.current_size_mb, 1),
                    "30d_mb": round(p.projected_size_mb_30d, 1),
                    "90d_mb": round(p.projected_size_mb_90d, 1),
                    "365d_mb": round(p.projected_size_mb_365d, 1),
                    "growth_rate": round(p.growth_rate_mb_per_day, 2),
                    "days_until_10gb": p.days_until_10gb,
                    "warning": p.warning,
                }
                for p in projections
            ]
            console.print_json(json.dumps(data, indent=2))
            return

        if not projections:
            console.print("[yellow]No projection data. Run 'querysense growth snapshot' daily.[/yellow]")
            return

        console.print(Panel(
            "[bold]Capacity projections based on recent growth[/bold]",
            title="[bold]QuerySense Growth Projections[/bold]",
        ))

        tbl = Table()
        tbl.add_column("Table", style="cyan")
        tbl.add_column("Now", justify="right")
        tbl.add_column("30d", justify="right")
        tbl.add_column("90d", justify="right")
        tbl.add_column("1yr", justify="right")
        tbl.add_column("Rate", justify="right")
        tbl.add_column("Warning")

        for p in projections:
            def fmt_mb(mb: float) -> str:
                if mb >= 1024:
                    return f"{mb / 1024:.1f}GB"
                return f"{mb:.0f}MB"

            warning = p.warning or ""
            if warning:
                warning = f"[yellow]{warning}[/yellow]"

            tbl.add_row(
                f"{p.schema}.{p.table}",
                fmt_mb(p.current_size_mb),
                fmt_mb(p.projected_size_mb_30d),
                fmt_mb(p.projected_size_mb_90d),
                fmt_mb(p.projected_size_mb_365d),
                f"{p.growth_rate_mb_per_day:.2f}MB/d",
                warning,
            )

        console.print(tbl)

    @growth_app.command(name="anomalies")
    def growth_anomalies(
        threshold: Annotated[
            float,
            typer.Option("--threshold", help="% change to flag as anomaly"),
        ] = 20.0,
        db_path: Annotated[
            Optional[str],
            typer.Option("--db", help="SQLite database path"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Detect sudden size changes (deployment impact, bulk operations).

        Flags tables where size changed >20% between snapshots.

        \b
        Example:
            $ querysense growth anomalies --threshold 10
        """
        from querysense.table_growth import TableGrowthTracker

        tracker = TableGrowthTracker(db_path=db_path)
        anomalies = tracker.detect_anomalies(threshold_pct=threshold)

        if json_output:
            console.print_json(json.dumps(anomalies, indent=2))
            return

        if not anomalies:
            console.print("[green]✓ No growth anomalies detected.[/green]")
            return

        console.print(Panel(
            f"[bold]{len(anomalies)} anomalies detected (>{threshold}% change)[/bold]",
            title="[bold]QuerySense Growth Anomalies[/bold]",
        ))

        tbl = Table()
        tbl.add_column("Table", style="cyan")
        tbl.add_column("Time")
        tbl.add_column("Before", justify="right")
        tbl.add_column("After", justify="right")
        tbl.add_column("Change", justify="right")
        tbl.add_column("Type")
        tbl.add_column("Suggestion")

        for a in anomalies:
            change_pct = a.get("change_pct", 0)
            style = "red" if change_pct > 0 else "green"
            tbl.add_row(
                a.get("table", ""),
                a.get("timestamp", "")[:19],
                f"{a.get('previous_size_mb', 0):.1f}MB",
                f"{a.get('current_size_mb', 0):.1f}MB",
                f"[{style}]{change_pct:+.1f}%[/{style}]",
                a.get("type", ""),
                a.get("suggestion", ""),
            )

        console.print(tbl)
