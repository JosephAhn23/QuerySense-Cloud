"""
Simulate command: test index recommendations without committing.

Implements `querysense simulate` which creates indexes inside a
transaction, measures the plan improvement, then rolls back.

Usage:
    querysense simulate --index "CREATE INDEX ON orders(customer_id)" \
                        --query "SELECT * FROM orders WHERE customer_id = 42" \
                        --dsn "postgresql://localhost/mydb"
"""

from __future__ import annotations

import json
from typing import Annotated, Optional

import typer
from rich.console import Console

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register the simulate command on the given Typer app."""

    @app.command()
    def simulate(
        index_sql: Annotated[
            str,
            typer.Option("--index", "-i", help="CREATE INDEX SQL to test"),
        ],
        query_sql: Annotated[
            str,
            typer.Option("--query", "-q", help="SELECT query to measure"),
        ],
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string"),
        ] = "postgresql://localhost/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output result as JSON"),
        ] = False,
    ) -> None:
        """
        Test an index recommendation without committing it.

        Creates the index inside a transaction, measures the EXPLAIN cost
        change, then rolls back. The index is never persisted.

        \\b
        Examples:
            # Test an index recommendation
            $ querysense simulate \\
                --index "CREATE INDEX ON orders(customer_id)" \\
                --query "SELECT * FROM orders WHERE customer_id = 42" \\
                --dsn "postgresql://localhost/mydb"

            # JSON output for automation
            $ querysense simulate --index "..." --query "..." --json
        """
        import asyncio

        async def _run() -> None:
            try:
                import asyncpg
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg is required for simulation.\n"
                    "Install with: pip install querysense[db]"
                )
                raise typer.Exit(code=1)

            from querysense.verification.index_simulator import (
                IndexSimulator,
                format_simulation_results,
            )

            try:
                conn = await asyncpg.connect(dsn)
            except Exception as e:
                error_console.print(f"[red]Connection failed:[/red] {e}")
                raise typer.Exit(code=1)

            try:
                simulator = IndexSimulator(conn)
                result = await simulator.simulate(index_sql, query_sql)

                if json_output:
                    console.print_json(json.dumps(result.to_dict(), default=str))
                else:
                    console.print(format_simulation_results([result]))
            finally:
                await conn.close()

        asyncio.run(_run())

    @app.command(name="simulate-findings")
    def simulate_findings(
        explain_file: Annotated[
            str,
            typer.Option("--plan", "-p", help="Path to EXPLAIN JSON file"),
        ],
        query_sql: Annotated[
            str,
            typer.Option("--query", "-q", help="The original query SQL"),
        ],
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string"),
        ] = "postgresql://localhost/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Simulate all index recommendations from an analysis.

        Analyzes the EXPLAIN file, extracts CREATE INDEX suggestions,
        and tests each one via transaction-based simulation.

        \\b
        Examples:
            $ querysense simulate-findings \\
                --plan explain.json \\
                --query "SELECT * FROM orders WHERE status = 'pending'" \\
                --dsn "postgresql://localhost/mydb"
        """
        import asyncio
        from pathlib import Path

        from querysense.engine import AnalysisService
        from querysense.parser import ParseError, parse_explain

        try:
            output = parse_explain(Path(explain_file))
        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            raise typer.Exit(code=1)

        service = AnalysisService()
        result = service.analyze(output)

        if not result.findings:
            console.print("[green]No findings to simulate.[/green]")
            return

        async def _run() -> None:
            try:
                import asyncpg
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg required. "
                    "Install with: pip install querysense[db]"
                )
                raise typer.Exit(code=1)

            from querysense.verification.index_simulator import (
                IndexSimulator,
                format_simulation_results,
            )

            conn = await asyncpg.connect(dsn)
            try:
                simulator = IndexSimulator(conn)
                results = await simulator.simulate_from_findings(
                    list(result.findings), query_sql
                )

                if json_output:
                    data = [r.to_dict() for r in results]
                    console.print_json(json.dumps(data, default=str))
                else:
                    if results:
                        console.print(format_simulation_results(results))
                    else:
                        console.print(
                            "[dim]No CREATE INDEX suggestions found in findings.[/dim]"
                        )
            finally:
                await conn.close()

        asyncio.run(_run())
