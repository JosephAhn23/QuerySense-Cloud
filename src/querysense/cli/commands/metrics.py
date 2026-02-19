"""
Metrics commands: export QuerySense data to Prometheus/Grafana.

What Datadog charges $70/host/month for, you get free.

    $ querysense metrics export --db production
    $ querysense metrics serve --port 9187
    $ querysense metrics push --gateway http://pushgateway:9091
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register metrics subcommands."""

    @app.command()
    def export(
        db: Annotated[
            str,
            typer.Option("--db", help="History database name"),
        ] = "default",
        days: Annotated[
            int,
            typer.Option("--days", "-d", help="Days of history to export"),
        ] = 7,
        output: Annotated[
            Optional[Path],
            typer.Option("--output", "-o", help="Write metrics to file"),
        ] = None,
        format_type: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: prometheus, json"),
        ] = "prometheus",
    ) -> None:
        """
        Export QuerySense metrics in Prometheus exposition format.

        Reads from local SQLite history and outputs metrics that can be
        scraped by Prometheus, pushed to a pushgateway, or piped to
        any monitoring tool.

        \\b
        Examples:
            # Export to stdout (pipe to file or monitoring tool)
            $ querysense metrics export --db production

            # Export to file for Prometheus node_exporter textfile collector
            $ querysense metrics export -o /var/lib/prometheus/querysense.prom

            # Export as JSON
            $ querysense metrics export --format json

            # Export last 30 days
            $ querysense metrics export --days 30
        """
        from querysense.metrics.prometheus import PrometheusExporter
        from querysense import __version__

        db_path = Path(f"~/.querysense/{db}.db").expanduser()

        if not db_path.exists():
            error_console.print(
                f"[yellow]No history database at {db_path}[/yellow]\n"
                f"Run 'querysense history track <file>' first."
            )
            raise typer.Exit(code=1)

        exporter = PrometheusExporter()
        exporter.record_build_info(__version__)
        exporter.from_history_db(str(db_path), days=days)

        if format_type == "json":
            # Convert samples to JSON
            data = [
                {
                    "name": s.name,
                    "value": s.value,
                    "labels": s.labels,
                    "timestamp_ms": s.timestamp_ms,
                }
                for s in exporter._samples
            ]
            text = json.dumps(data, indent=2)
        else:
            text = exporter.render()

        if output:
            output.write_text(text, encoding="utf-8")
            console.print(f"[green]Metrics written to {output}[/green]")
            console.print(f"  Format: {format_type}")
            console.print(f"  Samples: {len(exporter._samples)}")
        else:
            console.print(text)

    @app.command()
    def serve(
        port: Annotated[
            int,
            typer.Option("--port", "-p", help="Port to serve metrics on"),
        ] = 9187,
        db: Annotated[
            str,
            typer.Option("--db", help="History database name"),
        ] = "default",
        refresh_seconds: Annotated[
            int,
            typer.Option("--refresh", help="Refresh interval in seconds"),
        ] = 30,
    ) -> None:
        """
        Serve metrics at /metrics for Prometheus scraping.

        Starts a lightweight HTTP server that Prometheus can scrape.
        Metrics are refreshed from the local history database on each
        request.

        \\b
        Examples:
            # Start metrics server
            $ querysense metrics serve --port 9187

            # With custom database and refresh
            $ querysense metrics serve --port 9187 --db production --refresh 60

        \\b
        Prometheus scrape config:
            scrape_configs:
              - job_name: 'querysense'
                static_configs:
                  - targets: ['localhost:9187']
        """
        import http.server
        import threading
        import time

        from querysense.metrics.prometheus import PrometheusExporter
        from querysense import __version__

        db_path = Path(f"~/.querysense/{db}.db").expanduser()

        # Shared state
        metrics_text = ""
        lock = threading.Lock()

        def refresh_metrics() -> None:
            nonlocal metrics_text
            exporter = PrometheusExporter()
            exporter.record_build_info(__version__)
            if db_path.exists():
                exporter.from_history_db(str(db_path), days=7)
            with lock:
                metrics_text = exporter.render()

        # Initial refresh
        refresh_metrics()

        # Background refresh thread
        def refresh_loop() -> None:
            while True:
                time.sleep(refresh_seconds)
                try:
                    refresh_metrics()
                except Exception:
                    pass

        thread = threading.Thread(target=refresh_loop, daemon=True)
        thread.start()

        class MetricsHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/metrics":
                    with lock:
                        body = metrics_text.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/health":
                    self.send_response(200)
                    body = b'{"status":"ok"}'
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress request logs

        # Need Any import for type hint
        from typing import Any

        server = http.server.HTTPServer(("0.0.0.0", port), MetricsHandler)

        console.print(f"[bold]QuerySense Metrics Server[/bold]")
        console.print(f"  Endpoint: http://localhost:{port}/metrics")
        console.print(f"  Health:   http://localhost:{port}/health")
        console.print(f"  Database: {db_path}")
        console.print(f"  Refresh:  every {refresh_seconds}s")
        console.print(f"\n[dim]Press Ctrl+C to stop[/dim]\n")

        # Add Prometheus scrape config suggestion
        console.print("[dim]Add to prometheus.yml:[/dim]")
        console.print(f"[dim]  scrape_configs:[/dim]")
        console.print(f"[dim]    - job_name: 'querysense'[/dim]")
        console.print(f"[dim]      static_configs:[/dim]")
        console.print(f"[dim]        - targets: ['localhost:{port}'][/dim]")
        console.print()

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[dim]Shutting down...[/dim]")
            server.shutdown()

    @app.command()
    def push(
        gateway: Annotated[
            str,
            typer.Option("--gateway", "-g", help="Prometheus Pushgateway URL"),
        ],
        db: Annotated[
            str,
            typer.Option("--db", help="History database name"),
        ] = "default",
        job: Annotated[
            str,
            typer.Option("--job", help="Prometheus job name"),
        ] = "querysense",
        days: Annotated[
            int,
            typer.Option("--days", "-d", help="Days of history to push"),
        ] = 7,
    ) -> None:
        """
        Push metrics to a Prometheus Pushgateway.

        Useful for batch jobs and CI pipelines where a scrape
        endpoint isn't practical.

        \\b
        Examples:
            $ querysense metrics push --gateway http://pushgateway:9091
            $ querysense metrics push --gateway http://pushgateway:9091 --job ci-build
        """
        import urllib.request
        import urllib.error

        from querysense.metrics.prometheus import PrometheusExporter
        from querysense import __version__

        db_path = Path(f"~/.querysense/{db}.db").expanduser()

        exporter = PrometheusExporter()
        exporter.record_build_info(__version__)
        if db_path.exists():
            exporter.from_history_db(str(db_path), days=days)

        metrics_text = exporter.render()

        # Push to gateway
        url = f"{gateway.rstrip('/')}/metrics/job/{job}"
        try:
            req = urllib.request.Request(
                url,
                data=metrics_text.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
                method="POST",
            )
            urllib.request.urlopen(req)
            console.print(f"[green]Pushed {len(exporter._samples)} metrics to {gateway}[/green]")
        except urllib.error.URLError as e:
            error_console.print(f"[red]Push failed:[/red] {e}")
            raise typer.Exit(code=1)
