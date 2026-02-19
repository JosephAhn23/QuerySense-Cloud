"""
RDS/CloudWatch metrics command.

Pull real-time performance metrics from AWS CloudWatch for RDS/Aurora instances.
Inspired by pganalyze's "full integration with Amazon RDS, including CloudWatch."

Usage:
    querysense rds metrics --instance my-postgres-db --region us-east-1
    querysense rds metrics --instance my-aurora-cluster --aurora --json
    querysense rds history --instance my-db --hours 6
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
    """Register rds commands on the given Typer app."""

    rds_app = typer.Typer(
        name="rds",
        help="AWS RDS/Aurora CloudWatch metrics integration",
        no_args_is_help=True,
    )
    app.add_typer(rds_app, name="rds")

    @rds_app.command("metrics")
    def rds_metrics(
        instance: Annotated[
            str,
            typer.Option("--instance", "-i", help="RDS instance or Aurora cluster identifier"),
        ],
        region: Annotated[
            str,
            typer.Option("--region", "-r", help="AWS region"),
        ] = "us-east-1",
        aurora: Annotated[
            bool,
            typer.Option("--aurora", help="Instance is an Aurora cluster"),
        ] = False,
        cluster: Annotated[
            bool,
            typer.Option("--cluster", help="Use DBClusterIdentifier dimension"),
        ] = False,
        profile: Annotated[
            Optional[str],
            typer.Option("--profile", help="AWS credentials profile name"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Collect current RDS/Aurora performance metrics from CloudWatch."""
        from querysense.db.rds_cloudwatch import RDSConfig, RDSMetricsCollector

        config = RDSConfig(
            instance_id=instance,
            region=region,
            is_aurora=aurora or cluster,
            is_cluster=cluster or aurora,
            aws_profile=profile,
        )
        collector = RDSMetricsCollector(config)

        with console.status(f"Collecting metrics for {instance}..."):
            try:
                snapshot = asyncio.run(collector.collect())
            except RuntimeError as e:
                error_console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)

        if json_output:
            console.print_json(json.dumps(snapshot.to_dict(), indent=2, default=str))
        else:
            console.print(snapshot.format_text())

            status_color = {
                "healthy": "green",
                "warning": "yellow",
                "degraded": "red",
            }.get(snapshot.health_status, "white")

            console.print(
                Panel(
                    f"[{status_color}]{snapshot.health_status.upper()}[/{status_color}]",
                    title=f"RDS Health: {instance}",
                )
            )

    @rds_app.command("history")
    def rds_history(
        instance: Annotated[
            str,
            typer.Option("--instance", "-i", help="RDS instance identifier"),
        ],
        hours: Annotated[
            int,
            typer.Option("--hours", help="Hours of history to retrieve"),
        ] = 6,
        region: Annotated[
            str,
            typer.Option("--region", "-r", help="AWS region"),
        ] = "us-east-1",
        aurora: Annotated[
            bool,
            typer.Option("--aurora", help="Instance is an Aurora cluster"),
        ] = False,
        profile: Annotated[
            Optional[str],
            typer.Option("--profile", help="AWS credentials profile name"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Retrieve historical CloudWatch metrics for an RDS instance."""
        from querysense.db.rds_cloudwatch import RDSConfig, RDSMetricsCollector

        config = RDSConfig(
            instance_id=instance,
            region=region,
            is_aurora=aurora,
            is_cluster=aurora,
            aws_profile=profile,
        )
        collector = RDSMetricsCollector(config)

        with console.status(f"Fetching {hours}h of metrics for {instance}..."):
            try:
                history = asyncio.run(collector.collect_range(hours=hours))
            except RuntimeError as e:
                error_console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)

        if json_output:
            console.print_json(json.dumps(history.to_dict(), indent=2, default=str))
        else:
            table = Table(title=f"RDS Metrics History: {instance} (last {hours}h)")
            table.add_column("Metric", style="cyan")
            table.add_column("Data Points", justify="right")
            table.add_column("Summary", justify="right")

            table.add_row(
                "CPU Utilization",
                str(len(history.cpu_utilization)),
                f"avg {history.avg_cpu:.1f}%, max {history.max_cpu:.1f}%",
            )
            table.add_row(
                "Database Connections",
                str(len(history.database_connections)),
                f"avg {history.avg_connections:.0f}",
            )
            ri = history.read_iops
            table.add_row(
                "Read IOPS",
                str(len(ri)),
                f"{sum(p.value for p in ri) / max(len(ri), 1):.0f} avg",
            )
            wi = history.write_iops
            table.add_row(
                "Write IOPS",
                str(len(wi)),
                f"{sum(p.value for p in wi) / max(len(wi), 1):.0f} avg",
            )

            console.print(table)

    @rds_app.command("alarms")
    def rds_alarms(
        instance: Annotated[
            str,
            typer.Option("--instance", "-i", help="RDS instance identifier"),
        ],
        region: Annotated[
            str,
            typer.Option("--region", "-r", help="AWS region"),
        ] = "us-east-1",
        profile: Annotated[
            Optional[str],
            typer.Option("--profile", help="AWS credentials profile name"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Check active CloudWatch alarms for an RDS instance."""
        from querysense.db.rds_cloudwatch import RDSConfig, RDSMetricsCollector

        config = RDSConfig(
            instance_id=instance,
            region=region,
            aws_profile=profile,
        )
        collector = RDSMetricsCollector(config)

        with console.status(f"Checking alarms for {instance}..."):
            try:
                alarms = asyncio.run(collector.check_alarms())
            except RuntimeError as e:
                error_console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)

        if json_output:
            console.print_json(json.dumps(alarms, indent=2))
        elif not alarms:
            console.print(f"[green]No active alarms for {instance}[/green]")
        else:
            table = Table(title=f"Active Alarms: {instance}")
            table.add_column("Alarm", style="red")
            table.add_column("Metric")
            table.add_column("Threshold")
            table.add_column("Reason")

            for alarm in alarms:
                table.add_row(
                    alarm["name"],
                    alarm["metric"],
                    str(alarm.get("threshold", "")),
                    alarm.get("reason", "")[:80],
                )
            console.print(table)
