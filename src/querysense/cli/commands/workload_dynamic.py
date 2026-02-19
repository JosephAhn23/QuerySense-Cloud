"""
CLI command for the Dynamic Query Workload Advisor.

    querysense workload-advisor --dsn postgresql://...
    querysense workload-advisor --plans ./plan_dir
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register(parent: typer.Typer) -> None:
    """Register the workload advisor command."""
    parent.command(name="workload-advisor")(workload_advisor)


def workload_advisor(
    dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN (reads from pg_stat_statements)")] = "",
    plan_dir: Annotated[str, typer.Option("--plans", help="Directory of SQL files or EXPLAIN JSON")] = "",
    budget_mb: Annotated[float, typer.Option("--budget", help="Max index storage budget in MB")] = 500.0,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
) -> None:
    """
    Dynamic Query Workload Advisor — analyze query families for optimal indexes.

    Analyzes the entire application's query set (from pg_stat_statements or
    plan files) and recommends a minimal set of covering indexes. Unlike
    single-query optimization, this considers all query variants together.

    Based on "PostgreSQL Query Optimization" (Dombrovskaya et al. 2024).
    """
    from querysense.workload_advisor import DynamicWorkloadAdvisor

    advisor = DynamicWorkloadAdvisor(storage_budget_mb=budget_mb)

    if dsn:
        stats = asyncio.run(_fetch_workload_stats(dsn))
        advisor.add_from_pg_stat_statements(stats)
    elif plan_dir:
        plan_path = Path(plan_dir)
        for f in plan_path.glob("*.sql"):
            advisor.add_query(f.read_text(), calls=1)
        for f in plan_path.glob("*.json"):
            data = json.loads(f.read_text())
            if isinstance(data, dict) and "query" in data:
                advisor.add_query(data["query"], calls=data.get("calls", 1))
    else:
        console.print("[red]Provide either --dsn or --plans[/red]")
        raise typer.Exit(1)

    result = advisor.analyze()

    if json_output:
        console.print_json(json.dumps(result.to_dict(), indent=2))
        return

    console.print(Panel(
        f"[bold]Query families: {len(result.families)}[/bold]  |  "
        f"Total calls: {result.total_query_calls:,}  |  "
        f"Tables: {result.tables_analyzed}  |  "
        f"Recommended indexes: {len(result.recommendations)}",
        title="[bold]QuerySense Dynamic Workload Advisor[/bold]",
    ))

    if not result.recommendations:
        console.print("[green]✓ No additional indexes needed![/green]")
        return

    # Show query families
    console.print("\n[bold]Top Query Families:[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Table", width=20)
    table.add_column("Filter Columns", width=30)
    table.add_column("Calls", width=10)
    table.add_column("Variants", width=10)
    table.add_column("Hot?", width=6)

    for fam in sorted(result.families, key=lambda f: f.total_calls, reverse=True)[:15]:
        table.add_row(
            fam.table or "-",
            ", ".join(fam.filter_columns[:4]) or "(none)",
            f"{fam.total_calls:,}",
            str(fam.variant_count),
            "[red]🔥[/red]" if fam.is_hot else "",
        )
    console.print(table)

    # Show recommendations
    console.print("\n[bold]Index Recommendations:[/bold]")
    for i, rec in enumerate(result.recommendations, 1):
        console.print(
            f"  [bold]{i}.[/bold] Covers {rec.families_covered} families, "
            f"{rec.total_calls_covered:,} calls"
        )
        console.print(f"    [cyan]{rec.create_index_sql}[/cyan]")
        console.print()


async def _fetch_workload_stats(dsn: str) -> list[dict]:
    """Fetch workload from pg_stat_statements."""
    import asyncpg
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch("""
            SELECT query, calls, mean_exec_time AS mean_time_ms, rows
            FROM pg_stat_statements
            WHERE calls > 5
            ORDER BY calls DESC
            LIMIT 500
        """)
        return [dict(row) for row in rows]
    finally:
        await conn.close()
