"""
Graph command: Generate Graphviz DOT plan visualizations.

    $ querysense graph explain.json --output plan.dot
    $ querysense graph explain.json --output plan.svg
    $ querysense graph explain.json --annotate  # includes analysis findings
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register graph command on the given Typer app."""

    @app.command()
    def graph(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        output: Annotated[
            Path,
            typer.Option("--output", "-o", help="Output file (.dot, .svg, .png, .pdf)"),
        ] = Path("plan.dot"),
        annotate: Annotated[
            bool,
            typer.Option("--annotate", "-a", help="Include analysis findings as annotations"),
        ] = False,
        title: Annotated[
            str,
            typer.Option("--title", "-t", help="Graph title"),
        ] = "Query Plan",
    ) -> None:
        """
        Generate a Graphviz DOT graph of a query plan.

        Produces a .dot file that can be rendered with Graphviz tools
        (dot, neato, fdp) into SVG, PNG, or PDF.

        If the output extension is .svg, .png, or .pdf and the `dot`
        command is available, QuerySense will render automatically.

        \b
        Examples:
            # Generate DOT file
            $ querysense graph explain.json -o plan.dot

            # Auto-render to SVG (requires Graphviz installed)
            $ querysense graph explain.json -o plan.svg

            # Include findings annotations
            $ querysense graph explain.json -o plan.svg --annotate

            # Custom title
            $ querysense graph explain.json -o plan.pdf --title "Slow Query #42"
        """
        from querysense.output.graphviz import render_dot, render_dot_from_result
        from querysense.parser import ParseError, parse_explain

        try:
            explain = parse_explain(explain_file)
        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            raise typer.Exit(code=1)

        if annotate:
            from querysense.engine import AnalysisService

            service = AnalysisService()
            result = service.analyze(explain)
            dot_content = render_dot_from_result(result, explain, title=title)
            console.print(
                f"[dim]{len(result.findings)} finding(s) annotated on graph[/dim]"
            )
        else:
            dot_content = render_dot(explain.plan, title=title)

        suffix = output.suffix.lower()

        if suffix == ".dot":
            output.write_text(dot_content, encoding="utf-8")
            console.print(f"[green]DOT graph written to {output}[/green]")
            console.print("[dim]Render with: dot -Tsvg plan.dot -o plan.svg[/dim]")
            return

        # Try auto-render for image formats
        if suffix in (".svg", ".png", ".pdf"):
            dot_file = output.with_suffix(".dot")
            dot_file.write_text(dot_content, encoding="utf-8")

            fmt = suffix.lstrip(".")
            try:
                subprocess.run(
                    ["dot", f"-T{fmt}", str(dot_file), "-o", str(output)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                console.print(f"[green]Graph rendered to {output}[/green]")
                # Clean up intermediate .dot
                dot_file.unlink(missing_ok=True)
            except FileNotFoundError:
                console.print(
                    f"[yellow]Graphviz not found.[/yellow] DOT file saved to {dot_file}\n"
                    f"Install Graphviz and run: dot -T{fmt} {dot_file} -o {output}"
                )
            except subprocess.CalledProcessError as e:
                error_console.print(f"[red]Graphviz error:[/red] {e.stderr}")
                console.print(f"DOT file saved to {dot_file}")
            return

        # Unknown format — just write DOT
        output.write_text(dot_content, encoding="utf-8")
        console.print(f"[green]DOT graph written to {output}[/green]")
