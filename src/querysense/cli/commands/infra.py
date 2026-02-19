"""
Infrastructure metrics command: collect and export PostgreSQL system metrics.

    $ querysense infra --dsn postgresql://localhost/mydb
    $ querysense infra --dsn postgresql://prod/app --prometheus
    $ querysense infra --dsn postgresql://prod/app --json
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Optional
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register the infra command on the given Typer app."""

    @app.command()
    def infra(
        dsn: Annotated[
            str,
            typer.Option(
                "--dsn",
                help="PostgreSQL connection string",
                envvar="QUERYSENSE_DSN",
            ),
        ] = "postgresql://localhost:5432/postgres",
        prometheus: Annotated[
            bool,
            typer.Option("--prometheus", "-p", help="Output in Prometheus exposition format"),
        ] = False,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        output_file: Annotated[
            Optional[Path],
            typer.Option("--output", "-o", help="Write metrics to file"),
        ] = None,
        correlate: Annotated[
            Optional[Path],
            typer.Option(
                "--correlate",
                help="EXPLAIN JSON to correlate with infra metrics",
            ),
        ] = None,
    ) -> None:
        """
        Collect PostgreSQL infrastructure metrics.

        Reads pg_stat_database, pg_stat_bgwriter, connection stats,
        and replication lag. Outputs health warnings and optional
        Prometheus format for monitoring stack integration.

        \b
        Examples:
            # Quick health check
            $ querysense infra --dsn postgresql://localhost/mydb

            # Export Prometheus metrics
            $ querysense infra --dsn postgresql://prod/app --prometheus

            # Correlate infra with slow query
            $ querysense infra --dsn $DB_URL --correlate slow_query.json

            # Save metrics JSON for trending
            $ querysense infra --dsn $DB_URL --json -o metrics.json
        """
        async def _collect() -> None:
            try:
                import asyncpg
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg is required.\n"
                    "Install with: pip install querysense[db]"
                )
                raise typer.Exit(code=1)

            from querysense.db.infra_metrics import collect_infra_metrics

            try:
                conn = await asyncpg.connect(dsn)
            except Exception as e:
                error_console.print(f"[red]Connection failed:[/red] {e}")
                raise typer.Exit(code=1)

            try:
                metrics = await collect_infra_metrics(conn)
            finally:
                await conn.close()

            # Prometheus output
            if prometheus:
                prom_output = metrics.to_prometheus()
                if output_file:
                    output_file.write_text(prom_output, encoding="utf-8")
                    console.print(f"[green]Prometheus metrics written to {output_file}[/green]")
                else:
                    console.print(prom_output)
                return

            # JSON output
            if json_output:
                data = metrics.to_dict()
                if correlate:
                    data["correlation"] = _correlate_with_plan(metrics, correlate)
                text = json.dumps(data, indent=2, default=str)
                if output_file:
                    output_file.write_text(text, encoding="utf-8")
                    console.print(f"[green]Metrics JSON written to {output_file}[/green]")
                else:
                    console.print_json(text)
                return

            # Pretty terminal output
            db = metrics.database
            bg = metrics.bgwriter
            cn = metrics.connections

            console.print(Panel(
                f"[bold]PostgreSQL {metrics.pg_version}[/bold]\n"
                f"Database: {db.datname} | "
                f"Uptime: {metrics.uptime_seconds / 3600:.0f}h",
                title="Infrastructure Metrics",
                border_style="cyan",
            ))

            # Database stats table
            db_table = Table(title="Database Stats (pg_stat_database)")
            db_table.add_column("Metric", style="cyan")
            db_table.add_column("Value", justify="right")
            db_table.add_column("Health")

            cache_status = "[green]OK[/green]" if db.cache_hit_ratio >= 0.99 else "[red]LOW[/red]"
            db_table.add_row("Cache Hit Ratio", f"{db.cache_hit_ratio:.4f}", cache_status)

            commit_status = "[green]OK[/green]" if db.commit_ratio >= 0.95 else "[yellow]WARN[/yellow]"
            db_table.add_row("Commit Ratio", f"{db.commit_ratio:.4f}", commit_status)

            db_table.add_row("Backends", str(db.numbackends), "")
            db_table.add_row("Blocks Read", f"{db.blks_read:,}", "")
            db_table.add_row("Blocks Hit", f"{db.blks_hit:,}", "")
            db_table.add_row("Tuples Returned", f"{db.tup_returned:,}", "")
            db_table.add_row("Tuples Fetched", f"{db.tup_fetched:,}", "")
            db_table.add_row("Temp Files", f"{db.temp_files:,}",
                             "[yellow]HIGH[/yellow]" if db.temp_files > 100 else "")
            db_table.add_row("Temp Bytes", f"{db.temp_bytes:,}", "")

            dl_status = "[red]!!![/red]" if db.deadlocks > 0 else ""
            db_table.add_row("Deadlocks", str(db.deadlocks), dl_status)

            db_table.add_row("DB Size", f"{db.db_size_bytes / (1024**2):,.0f} MB", "")
            console.print(db_table)

            # BGWriter stats
            bg_table = Table(title="Background Writer (pg_stat_bgwriter)")
            bg_table.add_column("Metric", style="cyan")
            bg_table.add_column("Value", justify="right")
            bg_table.add_column("Health")

            ckpt_status = "[yellow]WARN[/yellow]" if bg.checkpoint_request_ratio > 0.5 else ""
            bg_table.add_row("Checkpoints (timed)", str(bg.checkpoints_timed), "")
            bg_table.add_row("Checkpoints (requested)", str(bg.checkpoints_req), ckpt_status)
            bg_table.add_row("Backend Writes", str(bg.buffers_backend),
                             "[yellow]HIGH[/yellow]" if bg.backend_write_ratio > 0.3 else "")

            fsync_status = "[red]!!![/red]" if bg.buffers_backend_fsync > 0 else "[green]OK[/green]"
            bg_table.add_row("Backend Fsyncs", str(bg.buffers_backend_fsync), fsync_status)
            console.print(bg_table)

            # Connection stats
            conn_usage = cn.total / max(cn.max_connections, 1)
            conn_status = "[red]HIGH[/red]" if conn_usage > 0.8 else (
                "[yellow]MODERATE[/yellow]" if conn_usage > 0.5 else "[green]OK[/green]"
            )
            conn_table = Table(title="Connections")
            conn_table.add_column("Metric", style="cyan")
            conn_table.add_column("Value", justify="right")
            conn_table.add_row("Total", f"{cn.total} / {cn.max_connections}")
            conn_table.add_row("Active", str(cn.active))
            conn_table.add_row("Idle", str(cn.idle))
            conn_table.add_row("Idle in Txn", str(cn.idle_in_transaction))
            conn_table.add_row("Usage", f"{conn_usage:.0%} {conn_status}")
            console.print(conn_table)

            # Health warnings
            warnings = metrics.health_summary()
            if warnings:
                console.print("\n[bold yellow]Health Warnings:[/bold yellow]")
                for w in warnings:
                    console.print(f"  [yellow]!![/yellow] {w}")
            else:
                console.print("\n[green]No health warnings detected.[/green]")

            # Infrastructure correlation
            if correlate:
                _print_correlation(metrics, correlate)

            if metrics.errors:
                console.print(f"\n[dim]Collection errors: {len(metrics.errors)}[/dim]")
                for e in metrics.errors:
                    console.print(f"  [dim]{e}[/dim]")

        asyncio.run(_collect())


def _correlate_with_plan(metrics: "Any", plan_file: Path) -> dict:
    """Correlate infrastructure metrics with plan analysis."""
    from querysense.engine import AnalysisService
    from querysense.parser import parse_explain

    try:
        explain = parse_explain(plan_file)
        service = AnalysisService()
        result = service.analyze(explain)
    except Exception:
        return {"error": "Could not analyze plan file"}

    warnings: list[str] = []
    db = metrics.database

    # Correlation logic
    if db.cache_hit_ratio < 0.99:
        for f in result.findings:
            if "Seq Scan" in f.title or "SEQ_SCAN" in f.rule_id:
                warnings.append(
                    f"Sequential scan on {f.context.relation_name or 'table'} "
                    f"combined with low cache hit ratio ({db.cache_hit_ratio:.2%}) "
                    f"means heavy disk I/O"
                )

    if db.temp_files > 10:
        for f in result.findings:
            if "SPILL" in f.rule_id or "sort" in f.title.lower():
                warnings.append(
                    f"Sort/hash spilling ({f.title}) correlates with "
                    f"{db.temp_files} temp files; increase work_mem"
                )

    if db.deadlocks > 0:
        warnings.append(
            f"Deadlocks detected ({db.deadlocks}); "
            f"check lock ordering in application"
        )

    return {
        "plan_findings": len(result.findings),
        "infra_warnings": len(metrics.health_summary()),
        "correlations": warnings,
    }


def _print_correlation(metrics: "Any", plan_file: Path) -> None:
    """Print correlation analysis."""
    from rich.console import Console
    console = Console()
    corr = _correlate_with_plan(metrics, plan_file)

    if corr.get("error"):
        console.print(f"[yellow]Could not correlate: {corr['error']}[/yellow]")
        return

    correlations = corr.get("correlations", [])
    if correlations:
        console.print("\n[bold]Infrastructure Correlations:[/bold]")
        for c in correlations:
            console.print(f"  [red]!!![/red] {c}")
    else:
        console.print(
            "\n[green]No infrastructure-query correlations found.[/green]"
        )
