"""
Index optimizer CLI command.

Constraint-based index selection: solve for the optimal set of indexes
given a storage budget and workload. Closes the pganalyze "secret sauce" gap.

    $ querysense optimize indexes --dsn postgresql://localhost/mydb --budget 500
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register optimize command."""

    @app.command(name="optimize-indexes")
    def optimize_indexes(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        budget: Annotated[
            float,
            typer.Option("--budget", "-b", help="Storage budget in MB for new indexes"),
        ] = 500.0,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        use_ip: Annotated[
            bool,
            typer.Option("--integer-programming", help="Use integer programming solver (requires pulp)"),
        ] = False,
        top_queries: Annotated[
            int,
            typer.Option("--top", help="Number of top queries to analyze"),
        ] = 50,
    ) -> None:
        """
        Constraint-based index optimization — solve for the optimal index set.

        Models index selection as a knapsack problem: maximize query speedup
        within a storage budget. Considers column order, covering indexes,
        and index interactions.

        This is pganalyze's "secret sauce" — constraint programming for
        index selection. QuerySense gives it to you free.

        \b
        Examples:
            # Optimize with 500MB budget
            $ querysense optimize-indexes --dsn $DB_URL --budget 500

            # Use integer programming for optimal solution (requires pulp)
            $ querysense optimize-indexes --dsn $DB_URL --integer-programming

            # JSON for CI/CD
            $ querysense optimize-indexes --dsn $DB_URL --json
        """
        from querysense.index_optimizer import (
            CandidateIndex,
            IndexOptimizer,
            QueryWorkload,
        )

        async def _run() -> dict:
            try:
                import asyncpg
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg required.\n"
                    "Install: pip install querysense[db]"
                )
                raise typer.Exit(code=1)

            try:
                conn = await asyncpg.connect(dsn)
            except Exception as e:
                error_console.print(f"[red]Connection failed:[/red] {e}")
                raise typer.Exit(code=1)

            try:
                # Get top queries from pg_stat_statements
                try:
                    query_rows = await conn.fetch(f"""
                        SELECT
                            queryid::text AS query_id,
                            query AS sql_fingerprint,
                            calls AS frequency,
                            mean_exec_time AS avg_cost,
                            rows AS avg_rows
                        FROM pg_stat_statements
                        WHERE calls > 10
                        ORDER BY total_exec_time DESC
                        LIMIT {top_queries}
                    """)
                except Exception:
                    error_console.print(
                        "[yellow]Warning:[/yellow] pg_stat_statements not available.\n"
                        "Enable with: CREATE EXTENSION pg_stat_statements;"
                    )
                    return {"error": "pg_stat_statements not available"}

                # Build workload from query stats
                workload = []
                for row in query_rows:
                    sql = row["sql_fingerprint"] or ""
                    # Simple column extraction from SQL
                    tables, filters, joins, orders, groups = _extract_columns(sql)
                    if not tables:
                        continue

                    workload.append(QueryWorkload(
                        query_id=row["query_id"],
                        sql_fingerprint=sql[:500],
                        frequency=row["frequency"],
                        avg_cost=row["avg_cost"],
                        tables=tables,
                        filter_columns=filters,
                        join_columns=joins,
                        order_columns=orders,
                        group_columns=groups,
                    ))

                if not workload:
                    return {"error": "No queries found in pg_stat_statements"}

                # Generate candidates and optimize
                optimizer = IndexOptimizer()
                candidates = optimizer.generate_candidates(workload)
                result = optimizer.optimize(
                    workload=workload,
                    candidates=candidates,
                    storage_budget_mb=budget,
                    prefer_ip=use_ip,
                )
                return result.to_dict()

            finally:
                await conn.close()

        result = asyncio.run(_run())

        if result.get("error"):
            error_console.print(f"[red]Error:[/red] {result['error']}")
            raise typer.Exit(code=1)

        if json_output:
            console.print_json(json.dumps(result, indent=2, default=str))
            return

        # Rich output
        console.print(Panel(
            f"[bold]{result.get('summary', '')}[/bold]",
            title="[bold]QuerySense Index Optimizer[/bold]",
            subtitle="Constraint-based index selection (pganalyze secret sauce, free)",
        ))

        indexes = result.get("indexes", [])
        if indexes:
            console.print("\n[bold]Recommended Indexes:[/bold]\n")

            tbl = Table()
            tbl.add_column("#", justify="right", style="dim")
            tbl.add_column("Table", style="cyan")
            tbl.add_column("Columns", style="bold")
            tbl.add_column("Size", justify="right")
            tbl.add_column("Benefit", justify="right")
            tbl.add_column("Queries Helped", justify="right")

            for i, idx in enumerate(indexes, 1):
                tbl.add_row(
                    str(i),
                    idx.get("table", ""),
                    ", ".join(idx.get("columns", [])),
                    f"{idx.get('size_mb', 0):.1f}MB",
                    f"{idx.get('benefit', 0):.2f}",
                    str(len(idx.get("queries_helped", []))),
                )

            console.print(tbl)

            # Show CREATE statements
            console.print("\n[bold]Implementation SQL:[/bold]\n")
            sql_parts = [idx.get("create_sql", "") for idx in indexes]
            sql = "\n".join(sql_parts)
            console.print(Syntax(sql, "sql", theme="monokai", line_numbers=False))

        dropped = result.get("dropped_indexes", [])
        if dropped:
            console.print("\n[bold]Indexes to Drop (redundant):[/bold]\n")
            for d in dropped:
                console.print(f"  [red]{d}[/red]")

        console.print(
            f"\n[dim]Method: {result.get('method', 'greedy')} | "
            f"Storage: {result.get('storage_used_mb', 0):.0f}MB / "
            f"{result.get('storage_budget_mb', 0):.0f}MB[/dim]"
        )


def _extract_columns(sql: str) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    """Simple column/table extraction from SQL fingerprint.

    Returns (tables, filter_cols, join_cols, order_cols, group_cols).
    This is a best-effort regex parser for pg_stat_statements normalized SQL.
    """
    import re

    sql_upper = sql.upper()
    tables: list[str] = []
    filters: list[str] = []
    joins: list[str] = []
    orders: list[str] = []
    groups: list[str] = []

    # Extract tables from FROM/JOIN
    from_match = re.findall(r'\bFROM\s+(\w+)', sql, re.IGNORECASE)
    join_match = re.findall(r'\bJOIN\s+(\w+)', sql, re.IGNORECASE)
    tables = list(set(from_match + join_match))

    # Extract WHERE columns
    where_match = re.findall(r'\bWHERE\s+.*?(\w+)\s*[=<>!]', sql, re.IGNORECASE)
    and_match = re.findall(r'\bAND\s+(\w+)\s*[=<>!]', sql, re.IGNORECASE)
    filters = list(set(where_match + and_match))

    # Extract JOIN ON columns
    on_match = re.findall(r'\bON\s+\w+\.(\w+)\s*=\s*\w+\.(\w+)', sql, re.IGNORECASE)
    for left, right in on_match:
        joins.extend([left, right])
    joins = list(set(joins))

    # Extract ORDER BY columns
    order_match = re.findall(r'\bORDER\s+BY\s+([\w\s,\.]+?)(?:ASC|DESC|LIMIT|\)|$)', sql, re.IGNORECASE)
    if order_match:
        for col in order_match[0].split(","):
            col = col.strip().split(".")[-1].strip()
            if col and col.upper() not in ("ASC", "DESC"):
                orders.append(col)

    # Extract GROUP BY columns
    group_match = re.findall(r'\bGROUP\s+BY\s+([\w\s,\.]+?)(?:HAVING|ORDER|LIMIT|\)|$)', sql, re.IGNORECASE)
    if group_match:
        for col in group_match[0].split(","):
            col = col.strip().split(".")[-1].strip()
            if col:
                groups.append(col)

    return tables, filters, joins, orders, groups
