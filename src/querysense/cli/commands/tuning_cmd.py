"""
CLI commands for the Tuning Toolkit:

    querysense workbook extract-params --sql "SELECT ... WHERE id = $1"
    querysense workbook plan-diff --before plan_a.json --after plan_b.json
    querysense translate-hints --query "SELECT /*+ FULL(t) */ * FROM t"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


# ── Workbook sub-commands (registered on workbook_app) ────────────────


def register_workbook_extras(workbook_app: typer.Typer) -> None:
    """Register parameter extraction and plan diff commands on the workbook group."""

    @workbook_app.command(name="extract-params")
    def extract_params(
        sql: Annotated[str, typer.Option("--sql", "-s", help="Parameterized SQL query")] = "",
        file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Read SQL from file")] = None,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """
        Extract named parameters from a parameterized query.

        Analyzes column context around $1, $2, … placeholders and
        generates meaningful parameter names.

        \\b
        Examples:
            querysense workbook extract-params \\
                --sql "SELECT * FROM orders WHERE user_id = \\$1 AND status = \\$2"
        """
        from querysense.tuning.parameters import ParameterExtractor

        query = _read_sql(sql, file)
        if not query:
            error_console.print("[red]Provide --sql or --file[/red]")
            raise typer.Exit(code=1)

        ext = ParameterExtractor()
        normalized, params = ext.normalize_query(query)

        if json_output:
            console.print_json(json.dumps({
                "original": query,
                "normalized": normalized,
                "parameters": [p.to_dict() for p in params],
            }))
            return

        console.print(Panel(normalized, title="Normalized Query", border_style="cyan"))
        if not params:
            console.print("[dim]No positional parameters found.[/dim]")
            return

        tbl = Table(title="Extracted Parameters", show_lines=True)
        tbl.add_column("Position", style="dim")
        tbl.add_column("Name", style="bold cyan")
        tbl.add_column("Type", style="green")
        for p in params:
            tbl.add_row(f"${p.position}", p.name, p.pg_type)
        console.print(tbl)

    @workbook_app.command(name="from-sample")
    def from_sample(
        query: Annotated[str, typer.Option("--query", "-q", help="Concrete SQL sample")],
        template: Annotated[Optional[str], typer.Option("--template", "-t", help="Template with $N placeholders")] = None,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """
        Extract a parameter set from a concrete query sample.

        If --template is given, maps inline literal values to
        template positions. Otherwise, extracts all literals directly.

        \\b
        Examples:
            querysense workbook from-sample \\
                --query "SELECT * FROM orders WHERE id = 42 AND status = 'pending'" \\
                --template "SELECT * FROM orders WHERE id = \\$1 AND status = \\$2"
        """
        from querysense.tuning.parameters import ParameterExtractor

        ext = ParameterExtractor()
        ps = ext.from_sample(query, template=template)

        if json_output:
            console.print_json(json.dumps(ps.to_dict()))
            return

        tbl = Table(title=f"Parameter Set: {ps.name}", show_lines=True)
        tbl.add_column("Name", style="bold cyan")
        tbl.add_column("Value")
        tbl.add_column("PG Type", style="green")
        tbl.add_column("Source", style="dim")
        for p in ps.parameters:
            tbl.add_row(p.name, str(p.value), p.pg_type, p.source)
        console.print(tbl)

    @workbook_app.command(name="plan-diff")
    def plan_diff(
        before: Annotated[Path, typer.Option("--before", "-a", help="Baseline plan JSON file")],
        after: Annotated[Path, typer.Option("--after", "-b", help="New plan JSON file")],
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """
        Diff two EXPLAIN plans structurally.

        Ignores cost/timing noise and focuses on plan shape:
        node type changes, join reorders, scan method swaps.

        \\b
        Examples:
            querysense workbook plan-diff \\
                --before baseline.json --after optimized.json
        """
        from querysense.tuning.plan_diff import EnhancedPlanDiff

        plan_a = json.loads(before.read_text())
        plan_b = json.loads(after.read_text())

        differ = EnhancedPlanDiff()
        result = differ.diff(plan_a, plan_b)

        if json_output:
            console.print_json(json.dumps(result.to_dict()))
            return

        console.print(Panel(result.to_markdown(), title="Plan Diff", border_style="cyan"))


# ── Top-level hint translation command (registered on app) ────────────


def register_hint_translator(parent: typer.Typer) -> None:
    """Register the translate-hints command on the root app."""

    @parent.command(name="translate-hints")
    def translate_hints(
        query: Annotated[Optional[str], typer.Option("--query", "-q", help="Oracle SQL with hints")] = None,
        file: Annotated[Optional[Path], typer.Option("--file", "-f", help="SQL file to translate")] = None,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """
        Translate Oracle optimizer hints to pg_hint_plan syntax.

        Provides per-hint confidence scoring (high / medium / low / none)
        and migration guidance for hints with no PostgreSQL equivalent.

        \\b
        Examples:
            querysense translate-hints \\
                --query "SELECT /*+ FULL(t) USE_HASH(t u) */ * FROM t JOIN u ..."
        """
        from querysense.migration.hint_translator import OracleHintTranslator

        sql = _read_sql(query or "", file)
        if not sql:
            error_console.print("[red]Provide --query or --file[/red]")
            raise typer.Exit(code=1)

        translator = OracleHintTranslator()
        result = translator.translate_query(sql)

        if json_output:
            console.print_json(json.dumps(result.to_dict()))
            return

        # Show translated query
        console.print(Panel(result.translated_query, title="Translated Query", border_style="green"))

        # Per-hint table
        if result.hints:
            tbl = Table(title="Hint Translation Details", show_lines=True)
            tbl.add_column("Oracle Hint", style="bold")
            tbl.add_column("pg_hint_plan")
            tbl.add_column("Confidence")
            tbl.add_column("Notes", style="dim")

            _CONF_COLORS = {"high": "green", "medium": "yellow", "low": "red", "none": "dim"}
            for h in result.hints:
                color = _CONF_COLORS.get(h.confidence.value, "white")
                tbl.add_row(
                    h.original,
                    h.pg_hint or "[dim]—[/dim]",
                    f"[{color}]{h.confidence.value}[/{color}]",
                    h.notes,
                )
            console.print(tbl)

        # Summary
        console.print(Panel(
            f"Total: {result.total} | "
            f"[green]High: {result.high_confidence}[/green] | "
            f"[yellow]Medium: {result.medium_confidence}[/yellow] | "
            f"[red]Low: {result.low_confidence}[/red] | "
            f"[dim]Unsupported: {result.unsupported}[/dim] | "
            f"Coverage: {result.coverage_pct:.0f}%",
            title="Summary",
            border_style="cyan",
        ))


# ── Helpers ───────────────────────────────────────────────────────────


def _read_sql(sql: str, file: Optional[Path]) -> str:
    if file and file.exists():
        return file.read_text()
    return sql.strip()
