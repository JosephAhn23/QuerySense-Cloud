"""
Web command: launch a local web dashboard for QuerySense.

Addresses weakness #8 (vs PgHero): "No web interface — QuerySense is
CLI-only, requiring terminal access and JSON file handling."

Starts a local HTTP server that serves the QuerySense web interface,
providing a browser-based dashboard for plan analysis, history
viewing, and finding exploration.

Usage:
    querysense web
    querysense web --port 8080
    querysense web --host 0.0.0.0 --port 9000
"""

from __future__ import annotations

import webbrowser
from typing import Annotated

import typer
from rich.console import Console

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register web command on the given Typer app."""

    @app.command()
    def web(
        host: Annotated[
            str,
            typer.Option("--host", "-h", help="Host to bind to"),
        ] = "127.0.0.1",
        port: Annotated[
            int,
            typer.Option("--port", "-p", help="Port to listen on"),
        ] = 7000,
        no_open: Annotated[
            bool,
            typer.Option("--no-open", help="Don't auto-open browser"),
        ] = False,
    ) -> None:
        """
        Launch QuerySense web dashboard in your browser.

        Starts a local web server with a full-featured dashboard for:
        - Drag-and-drop plan analysis
        - Visual plan tree exploration
        - Finding cards with severity coloring
        - History trend charts
        - Side-by-side plan comparison

        No data leaves your machine — the server runs locally.

        \b
        Examples:
            $ querysense web
            $ querysense web --port 8080
            $ querysense web --host 0.0.0.0 --port 9000
        """
        try:
            import uvicorn
        except ImportError:
            error_console.print(
                "[red]uvicorn required for web dashboard.[/red]\n"
                "[dim]Install with: pip install querysense[cloud][/dim]"
            )
            raise typer.Exit(code=1)

        url = f"http://{host}:{port}"
        console.print(
            f"[bold]QuerySense Web Dashboard[/bold]\n\n"
            f"  Local:   [cyan]{url}[/cyan]\n"
            f"  Network: [dim]http://0.0.0.0:{port}[/dim]\n"
        )
        console.print(
            "[dim]Your query plans never leave your machine. "
            "The server runs 100% locally.[/dim]\n"
        )

        if not no_open:
            webbrowser.open(url)

        try:
            from querysense.cloud.app import create_app

            app_instance = create_app()
            uvicorn.run(
                app_instance,
                host=host,
                port=port,
                log_level="warning",
            )
        except ImportError as e:
            # Fallback: serve a minimal dashboard
            error_console.print(
                f"[yellow]Cloud module not fully available: {e}[/yellow]\n"
                "[dim]Starting minimal dashboard...[/dim]\n"
            )
            _run_minimal_dashboard(host, port)
        except KeyboardInterrupt:
            console.print("\n[yellow]Dashboard stopped.[/yellow]")


def _run_minimal_dashboard(host: str, port: int) -> None:
    """Run a minimal HTTP server with the HTML report generator."""
    import http.server
    import json
    import socketserver
    import urllib.parse

    from querysense.engine import AnalysisService
    from querysense.output.html_report import render_html
    from querysense.parser import parse_explain

    class DashboardHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/" or self.path == "/index":
                self._serve_landing()
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path == "/analyze":
                self._handle_analyze()
            else:
                self.send_error(404)

        def _serve_landing(self):
            html = _LANDING_HTML
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        def _handle_analyze(self):
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")

            try:
                # Parse the EXPLAIN JSON from the POST body
                plan_json = json.loads(body)

                # Write to temp file for parser
                import tempfile
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                ) as f:
                    json.dump(plan_json, f)
                    tmp_path = f.name

                explain = parse_explain(tmp_path)
                service = AnalysisService()
                result = service.analyze(explain)
                html = render_html(result, explain=explain)

                import os
                os.unlink(tmp_path)

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))

            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(f"Error: {e}".encode("utf-8"))

        def log_message(self, format, *args):
            pass  # Suppress default logging

    with socketserver.TCPServer((host, port), DashboardHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[yellow]Dashboard stopped.[/yellow]")


_LANDING_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QuerySense Dashboard</title>
<style>
:root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #e6edf3; --accent: #58a6ff; --success: #3fb950; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px; }
h1 { font-size: 32px; margin-bottom: 8px; }
.subtitle { color: #8b949e; margin-bottom: 32px; }
.drop-zone { width: 100%; max-width: 600px; border: 2px dashed var(--border); border-radius: 12px; padding: 48px 24px; text-align: center; cursor: pointer; transition: all 0.2s; }
.drop-zone:hover, .drop-zone.dragover { border-color: var(--accent); background: rgba(88,166,255,0.05); }
.drop-zone p { font-size: 18px; margin-bottom: 8px; }
.drop-zone small { color: #8b949e; }
textarea { width: 100%; max-width: 600px; min-height: 200px; margin-top: 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; color: var(--text); padding: 12px; font-family: 'SF Mono', monospace; font-size: 13px; resize: vertical; }
button { margin-top: 16px; padding: 12px 32px; background: var(--accent); color: #fff; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; font-weight: 600; }
button:hover { opacity: 0.9; }
.secure { margin-top: 32px; font-size: 12px; color: #8b949e; }
#result { margin-top: 24px; width: 100%; max-width: 800px; }
</style>
</head>
<body>
<h1>QuerySense</h1>
<p class="subtitle">Paste your EXPLAIN JSON, get copy-paste SQL fixes</p>

<div class="drop-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
    <p>Drop EXPLAIN JSON file here</p>
    <small>or click to browse</small>
    <input type="file" id="fileInput" accept=".json" hidden>
</div>

<textarea id="planInput" placeholder="...or paste EXPLAIN (FORMAT JSON) output here"></textarea>

<button onclick="analyze()">Analyze</button>

<p class="secure">Your plans never leave your machine. This runs 100% locally.</p>

<div id="result"></div>

<script>
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const planInput = document.getElementById('planInput');

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) readFile(file);
});
fileInput.addEventListener('change', e => { if (e.target.files[0]) readFile(e.target.files[0]); });

function readFile(file) {
    const reader = new FileReader();
    reader.onload = e => { planInput.value = e.target.result; };
    reader.readAsText(file);
}

async function analyze() {
    const plan = planInput.value.trim();
    if (!plan) { alert('Paste or drop an EXPLAIN JSON plan first.'); return; }
    try {
        const parsed = JSON.parse(plan);
        const resp = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(parsed),
        });
        if (resp.ok) {
            const html = await resp.text();
            const w = window.open('', '_blank');
            w.document.write(html);
            w.document.close();
        } else {
            const err = await resp.text();
            alert('Analysis failed: ' + err);
        }
    } catch (e) {
        alert('Invalid JSON: ' + e.message);
    }
}
</script>
</body>
</html>
"""
