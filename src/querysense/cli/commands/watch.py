"""Watch command: real-time plan regression monitoring."""

from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console

console = Console()


def register(app: typer.Typer) -> None:
    """Register watch command on the given Typer app."""

    @app.command()
    def watch(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        interval: Annotated[
            int,
            typer.Option("--interval", "-i", help="Polling interval in seconds"),
        ] = 60,
        top_queries: Annotated[
            int,
            typer.Option("--top-queries", "-n", help="Number of top queries to monitor"),
        ] = 100,
        threshold: Annotated[
            float,
            typer.Option("--threshold", help="Time increase factor to trigger alert"),
        ] = 2.0,
        min_severity: Annotated[
            int,
            typer.Option("--min-severity", help="Minimum severity score (0-100) to alert on"),
        ] = 30,
        slack_webhook: Annotated[
            Optional[str],
            typer.Option("--slack-webhook", envvar="QUERYSENSE_SLACK_WEBHOOK", help="Slack webhook URL"),
        ] = None,
        pagerduty_key: Annotated[
            Optional[str],
            typer.Option("--pagerduty-key", envvar="QUERYSENSE_PAGERDUTY_KEY", help="PagerDuty routing key"),
        ] = None,
        webhook_url: Annotated[
            Optional[str],
            typer.Option("--webhook", envvar="QUERYSENSE_WEBHOOK_URL", help="Generic webhook URL for alerts"),
        ] = None,
        state_file: Annotated[
            str,
            typer.Option("--state-file", help="Path to watch state file"),
        ] = ".querysense/watch_state.json",
    ) -> None:
        """
        Watch PostgreSQL for plan regressions in real-time.

        Examples:

            $ querysense watch --dsn postgresql://localhost/mydb
            $ querysense watch --dsn postgresql://prod:5432/app --slack-webhook https://hooks.slack.com/...
        """
        from querysense.watch import WatchConfig, WatchDaemon

        config = WatchConfig(
            dsn=dsn,
            interval_seconds=interval,
            top_queries=top_queries,
            time_increase_threshold=threshold,
            min_severity=min_severity,
            storage_path=state_file,
            slack_webhook=slack_webhook,
            pagerduty_routing_key=pagerduty_key,
            webhook_url=webhook_url,
        )

        console.print(
            f"[bold]QuerySense Watch[/bold] — monitoring "
            f"{dsn.split('@')[-1] if '@' in dsn else dsn}"
        )
        console.print(
            f"[dim]Interval: {interval}s | Threshold: {threshold}x | "
            f"Min severity: {min_severity} | Top queries: {top_queries}[/dim]"
        )

        daemon = WatchDaemon(config)

        try:
            daemon.run_sync()
        except KeyboardInterrupt:
            console.print("\n[yellow]Watch stopped.[/yellow]")
        except SystemExit:
            raise
