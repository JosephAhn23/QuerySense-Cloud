"""
Verify command: test index recommendations with HypoPG before creating them.

Addresses weakness #7 (vs Dexter): "No index simulation — Dexter creates
hypothetical indexes to test impact before creation; QuerySense only
recommends based on static rules."

This command connects to PostgreSQL, creates hypothetical indexes via
HypoPG, re-runs EXPLAIN, and shows the before/after impact — all without
actually creating the index.

Usage:
    querysense verify --dsn postgresql://localhost/mydb plan.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from querysense.engine import AnalysisService
from querysense.parser import ParseError, parse_explain

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register verify command on the given Typer app."""

    @app.command()
    def verify(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        dsn: Annotated[
            str,
            typer.Option(
                "--dsn",
                help="PostgreSQL connection string (needs HypoPG extension)",
                envvar="QUERYSENSE_DSN",
            ),
        ] = "postgresql://localhost:5432/postgres",
        query_sql: Annotated[
            Optional[str],
            typer.Option("--sql", "-s", help="The SQL query to re-EXPLAIN with hypothetical indexes"),
        ] = None,
        query_file: Annotated[
            Optional[Path],
            typer.Option("--sql-file", "-f", help="File containing the SQL query"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Test index recommendations using HypoPG hypothetical indexes.

        Analyzes the plan, extracts index recommendations, creates
        hypothetical indexes via HypoPG, re-explains the query, and
        shows whether each index would actually help.

        Requires:
        - HypoPG extension: CREATE EXTENSION hypopg;
        - The SQL query (via --sql or --sql-file)

        \b
        Examples:
            $ querysense verify plan.json --dsn postgresql://localhost/mydb \\
                --sql "SELECT * FROM orders WHERE status = 'pending'"

            $ querysense verify plan.json --dsn $DATABASE_URL --sql-file query.sql
        """
        import asyncio

        try:
            explain = parse_explain(explain_file)
        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            raise typer.Exit(code=1)

        # Get SQL query
        sql = query_sql
        if query_file and not sql:
            sql = query_file.read_text(encoding="utf-8").strip()

        if not sql:
            error_console.print(
                "[red]SQL query required.[/red] Provide via --sql or --sql-file.\n"
                "[dim]The query is needed to re-EXPLAIN with hypothetical indexes.[/dim]"
            )
            raise typer.Exit(code=1)

        console.print("[bold]QuerySense Verify[/bold] — hypothetical index testing\n")

        # Analyze and extract index suggestions
        service = AnalysisService()
        result = service.analyze(explain)

        index_suggestions: list[dict] = []
        for finding in result.findings:
            if not finding.suggestion:
                continue
            for line in finding.suggestion.split("\n"):
                stripped = line.strip()
                if stripped.upper().startswith("CREATE INDEX"):
                    index_suggestions.append({
                        "sql": stripped.rstrip(";") + ";",
                        "rule_id": finding.rule_id,
                        "title": finding.title,
                    })

        if not index_suggestions:
            console.print("[green]No index recommendations to verify.[/green]")
            raise typer.Exit(code=0)

        console.print(f"[dim]Found {len(index_suggestions)} index recommendation(s) to test[/dim]\n")

        # Test each index with HypoPG
        try:
            results = asyncio.run(
                _verify_indexes(dsn, sql, index_suggestions)
            )
        except Exception as e:
            error_console.print(f"[red]Verification failed:[/red] {e}")
            error_console.print(
                "\n[dim]Ensure HypoPG is installed: CREATE EXTENSION hypopg;[/dim]"
            )
            raise typer.Exit(code=1)

        if json_output:
            console.print_json(json.dumps(results, indent=2, default=str))
            return

        # Render results
        _render_verification_results(results)


async def _verify_indexes(
    dsn: str,
    sql: str,
    suggestions: list[dict],
) -> list[dict]:
    """Test hypothetical indexes and return before/after comparison."""
    try:
        import asyncpg
    except ImportError:
        raise RuntimeError(
            "asyncpg required for verification. Install: pip install querysense[db]"
        )

    conn = await asyncpg.connect(dsn)

    try:
        # Check HypoPG availability
        has_hypopg = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'hypopg')"
        )
        if not has_hypopg:
            raise RuntimeError(
                "HypoPG extension not installed. Run: CREATE EXTENSION hypopg;"
            )

        # Get before plan cost
        before_plan = await conn.fetchval(
            f"EXPLAIN (FORMAT JSON, COSTS) {sql}"
        )
        import json as json_mod
        before_data = json_mod.loads(before_plan)
        before_cost = before_data[0]["Plan"]["Total Cost"]

        results: list[dict] = []

        for suggestion in suggestions:
            idx_sql = suggestion["sql"]

            try:
                # Create hypothetical index
                hypo_result = await conn.fetch(
                    "SELECT * FROM hypopg_create_index($1)", idx_sql
                )

                if not hypo_result:
                    results.append({
                        **suggestion,
                        "status": "failed",
                        "error": "Could not create hypothetical index",
                    })
                    continue

                oid = hypo_result[0][0]

                # Get estimated size
                try:
                    size_bytes = await conn.fetchval(
                        "SELECT hypopg_relation_size($1)", oid
                    )
                except Exception:
                    size_bytes = 0

                # Re-explain with hypothetical index
                after_plan = await conn.fetchval(
                    f"EXPLAIN (FORMAT JSON, COSTS) {sql}"
                )
                after_data = json_mod.loads(after_plan)
                after_cost = after_data[0]["Plan"]["Total Cost"]

                improvement_pct = (
                    ((before_cost - after_cost) / before_cost * 100)
                    if before_cost > 0 else 0.0
                )

                # Check if the hypothetical index is used
                plan_text = await conn.fetchval(f"EXPLAIN {sql}")
                index_used = "hypopg" in (plan_text or "").lower()

                results.append({
                    **suggestion,
                    "status": "tested",
                    "before_cost": round(before_cost, 2),
                    "after_cost": round(after_cost, 2),
                    "improvement_pct": round(improvement_pct, 2),
                    "index_used": index_used,
                    "estimated_size": _fmt_bytes(size_bytes or 0),
                })

                # Clean up this hypothetical index
                await conn.execute("SELECT hypopg_reset()")

            except Exception as e:
                results.append({
                    **suggestion,
                    "status": "error",
                    "error": str(e),
                })
                # Reset on error too
                try:
                    await conn.execute("SELECT hypopg_reset()")
                except Exception:
                    pass

        return results

    finally:
        await conn.close()


def _render_verification_results(results: list[dict]) -> None:
    """Render verification results to console."""
    table = Table(title="Index Verification Results")
    table.add_column("Index", style="cyan", max_width=50)
    table.add_column("Status")
    table.add_column("Before Cost", justify="right")
    table.add_column("After Cost", justify="right")
    table.add_column("Improvement", justify="right")
    table.add_column("Used?")
    table.add_column("Size")

    for r in results:
        if r["status"] == "tested":
            imp = r["improvement_pct"]
            imp_style = "green bold" if imp > 50 else ("green" if imp > 10 else ("yellow" if imp > 0 else "red"))
            used = "[green]Yes[/green]" if r["index_used"] else "[red]No[/red]"

            table.add_row(
                r["sql"][:50],
                "[green]tested[/green]",
                f"{r['before_cost']:,.0f}",
                f"{r['after_cost']:,.0f}",
                f"[{imp_style}]{imp:+.1f}%[/{imp_style}]",
                used,
                r.get("estimated_size", "?"),
            )
        elif r["status"] == "failed":
            table.add_row(r["sql"][:50], "[red]failed[/red]", "", "", "", "", "")
        else:
            table.add_row(
                r["sql"][:50],
                f"[red]error[/red]",
                "", "", "", "", "",
            )

    console.print(table)

    # Summary
    tested = [r for r in results if r["status"] == "tested"]
    helpful = [r for r in tested if r["improvement_pct"] > 5]
    console.print(
        f"\n[dim]{len(tested)} tested, {len(helpful)} would improve performance[/dim]"
    )

    if helpful:
        console.print("\n[bold]Recommended indexes to create:[/bold]")
        for r in sorted(helpful, key=lambda x: x["improvement_pct"], reverse=True):
            console.print(f"  [green]{r['sql']}[/green]")
            console.print(
                f"  [dim]  → {r['improvement_pct']:+.1f}% improvement, "
                f"~{r.get('estimated_size', '?')} on disk[/dim]"
            )


def _fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b}B"
    if b < 1024 ** 2:
        return f"{b / 1024:.1f}KB"
    if b < 1024 ** 3:
        return f"{b / (1024 ** 2):.1f}MB"
    return f"{b / (1024 ** 3):.1f}GB"
