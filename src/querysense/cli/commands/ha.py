"""
CLI commands for HA / Replication / Patroni monitoring.

    querysense ha status     — Show cluster membership, lag, WAL metrics
    querysense ha patroni    — Query Patroni REST API for cluster state
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

console = Console()


def register_ha(ha_app: typer.Typer) -> None:
    """Register HA/replication commands."""

    @ha_app.command()
    def status(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        lag_warning: Annotated[
            float,
            typer.Option("--lag-warning", help="Lag warning threshold (seconds)"),
        ] = 10.0,
        lag_critical: Annotated[
            float,
            typer.Option("--lag-critical", help="Lag critical threshold (seconds)"),
        ] = 30.0,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Show HA cluster status — members, replication lag, WAL metrics.

        Queries pg_stat_replication, pg_stat_bgwriter, and WAL position
        to provide a complete view of the cluster.

        \\b
        Examples:
            $ querysense ha status --dsn postgresql://primary:5432/mydb
            $ querysense ha status --lag-critical 60 --json
        """
        from querysense.patroni_monitor import PatroniMonitor

        monitor = PatroniMonitor()
        report = asyncio.run(
            monitor.analyze(dsn, lag_warning, lag_critical)
        )

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        # Header
        health_icon = "[green]HEALTHY[/green]" if report.is_healthy else "[red]DEGRADED[/red]"
        console.print(Panel(
            f"[bold]Cluster:[/bold] {report.cluster_name}\n"
            f"[bold]Status:[/bold] {health_icon}\n"
            f"[bold]Members:[/bold] {len(report.members)} "
            f"({report.unhealthy_members} unhealthy)\n"
            f"[bold]Max Lag:[/bold] {report.max_lag_seconds:.1f}s / "
            f"{report.max_lag_bytes / 1024 / 1024:.1f}MB",
            title="HA Cluster Status",
            border_style="green" if report.is_healthy else "red",
        ))

        # Members table
        tbl = Table(title="Cluster Members")
        tbl.add_column("Name", style="bold")
        tbl.add_column("Role")
        tbl.add_column("State")
        tbl.add_column("Host")
        tbl.add_column("Lag", justify="right")
        tbl.add_column("Health", justify="center")

        for m in report.members:
            role_style = "green bold" if m.role.value == "leader" else "cyan"
            state_style = "green" if m.state.value in ("running", "streaming") else "yellow"
            health = "[green]✓[/green]" if m.is_healthy else "[red]✗[/red]"

            tbl.add_row(
                m.name,
                f"[{role_style}]{m.role.value.upper()}[/{role_style}]",
                f"[{state_style}]{m.state.value}[/{state_style}]",
                f"{m.host}:{m.port}",
                m.lag_human,
                health,
            )

        console.print(tbl)

        # WAL/Checkpoint metrics
        wal = report.wal_metrics
        if wal.checkpoints_timed + wal.checkpoints_req > 0:
            console.print()
            wal_panel = (
                f"[bold]Timed checkpoints:[/bold] {wal.checkpoints_timed}\n"
                f"[bold]Forced checkpoints:[/bold] {wal.checkpoints_req}\n"
                f"[bold]Forced ratio:[/bold] {wal.checkpoint_request_ratio:.1%}\n"
                f"[bold]WAL dir size:[/bold] {wal.wal_directory_size_mb:.0f}MB\n"
                f"[bold]Backend buffer writes:[/bold] "
                f"{wal.buffers_backend:,}"
            )
            if wal.avg_checkpoint_interval_sec > 0:
                wal_panel += (
                    f"\n[bold]Avg checkpoint interval:[/bold] "
                    f"{wal.avg_checkpoint_interval_sec / 60:.1f}min"
                )

            border = "yellow" if wal.is_checkpoint_pressure else "dim"
            console.print(Panel(
                wal_panel,
                title="WAL & Checkpoints",
                border_style=border,
            ))

        # Recommendations
        if report.recommendations:
            console.print()
            for rec in report.recommendations:
                if rec.startswith("CRITICAL"):
                    console.print(f"  [red bold]{rec}[/red bold]")
                elif rec.startswith("WARNING"):
                    console.print(f"  [yellow]{rec}[/yellow]")
                else:
                    console.print(f"  [dim]{rec}[/dim]")

    @ha_app.command()
    def patroni(
        url: Annotated[
            str,
            typer.Option("--url", help="Patroni REST API base URL"),
        ] = "http://localhost:8008",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Query Patroni REST API for cluster state.

        Requires Patroni to be running with REST API enabled.

        \\b
        Examples:
            $ querysense ha patroni --url http://patroni-node:8008
            $ querysense ha patroni --json
        """
        from querysense.patroni_monitor import PatroniMonitor

        monitor = PatroniMonitor()
        report = asyncio.run(monitor.analyze_patroni(url))

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        if not report.members:
            console.print("[yellow]No cluster members found. "
                          "Check the Patroni API URL.[/yellow]")
            for rec in report.recommendations:
                console.print(f"  [dim]{rec}[/dim]")
            return

        health_icon = "[green]HEALTHY[/green]" if report.is_healthy else "[red]DEGRADED[/red]"
        console.print(Panel(
            f"[bold]Cluster:[/bold] {report.cluster_name}\n"
            f"[bold]Patroni:[/bold] v{report.patroni_version}\n"
            f"[bold]Status:[/bold] {health_icon}\n"
            f"[bold]Members:[/bold] {len(report.members)}",
            title="Patroni Cluster",
            border_style="green" if report.is_healthy else "red",
        ))

        tbl = Table(title="Members")
        tbl.add_column("Name", style="bold")
        tbl.add_column("Role")
        tbl.add_column("State")
        tbl.add_column("Timeline", justify="right")
        tbl.add_column("Lag", justify="right")
        tbl.add_column("Health", justify="center")

        for m in report.members:
            role_style = "green bold" if m.role.value == "leader" else "cyan"
            health = "[green]✓[/green]" if m.is_healthy else "[red]✗[/red]"

            tbl.add_row(
                m.name,
                f"[{role_style}]{m.role.value.upper()}[/{role_style}]",
                m.state.value,
                str(m.timeline),
                m.lag_human,
                health,
            )

        console.print(tbl)
