"""
Lock monitoring CLI command.

Detects blocking queries, deadlocks, and lock contention in real-time.
Closes the pganalyze gap: "Lock analysis — shows blocking queries, deadlock traces."

    $ querysense locks --dsn postgresql://localhost/mydb
    $ querysense locks --dsn $DB_URL --json
    $ querysense locks --dsn $DB_URL --kill-threshold 60
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register lock monitoring command."""

    @app.command()
    def locks(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        kill_threshold: Annotated[
            Optional[float],
            typer.Option("--kill-threshold", help="Suggest pg_terminate_backend for blockers older than N seconds"),
        ] = None,
        fail_on_deadlock: Annotated[
            bool,
            typer.Option("--fail-on-deadlock", help="Exit 1 if deadlock detected (for CI)"),
        ] = False,
    ) -> None:
        """
        Real-time lock monitoring — detect blocking queries and deadlocks.

        Shows blocking chains (who is blocking whom), lock wait durations,
        and provides actionable kill commands for stuck queries.

        Equivalent to pganalyze's lock analysis — but free and CLI-first.

        \b
        Examples:
            # Check for blocking queries
            $ querysense locks --dsn postgresql://localhost/mydb

            # JSON output for CI/CD
            $ querysense locks --dsn $DB_URL --json --fail-on-deadlock

            # Show kill suggestions for blockers > 30s
            $ querysense locks --dsn $DB_URL --kill-threshold 30
        """
        from querysense.lock_monitor import LockMonitor

        async def _run() -> dict:
            try:
                import asyncpg
            except ImportError:
                error_console.print(
                    "[red]Error:[/red] asyncpg is required for lock monitoring.\n"
                    "Install with: pip install querysense[db]"
                )
                raise typer.Exit(code=1)

            try:
                conn = await asyncpg.connect(dsn)
            except Exception as e:
                error_console.print(f"[red]Connection failed:[/red] {e}")
                raise typer.Exit(code=1)

            try:
                monitor = LockMonitor()
                queries = monitor.get_catalog_queries()

                # Fetch blocking data
                blocking_rows = await conn.fetch(queries["blocking"])
                blocking_data = [dict(r) for r in blocking_rows]

                # Fetch lock distribution
                dist_rows = await conn.fetch(queries["distribution"])
                dist_data = [dict(r) for r in dist_rows]

                report = monitor.analyze_from_data(blocking_data, dist_data)
                return report.to_dict()
            finally:
                await conn.close()

        result = asyncio.run(_run())

        if json_output:
            console.print_json(json.dumps(result, indent=2, default=str))
            if fail_on_deadlock and result.get("deadlock"):
                raise typer.Exit(code=1)
            return

        # Rich output
        summary = result.get("summary", "No data")
        deadlock = result.get("deadlock", False)

        if deadlock:
            status_color = "red"
            status_text = "DEADLOCK DETECTED"
        elif result.get("total_blocking", 0) > 0:
            status_color = "yellow"
            status_text = "BLOCKING DETECTED"
        else:
            status_color = "green"
            status_text = "HEALTHY"

        console.print(Panel(
            f"[bold]Status: [{status_color}]{status_text}[/{status_color}][/bold]\n"
            f"{summary}",
            title="[bold]QuerySense Lock Monitor[/bold]",
            subtitle="Closes pganalyze lock analysis gap",
        ))

        # Lock type distribution
        lock_types = result.get("lock_types", {})
        if lock_types:
            dist_table = Table(title="Lock Type Distribution")
            dist_table.add_column("Lock Type", style="cyan")
            dist_table.add_column("Count", justify="right")
            for lock_type, count in sorted(lock_types.items(), key=lambda x: -x[1]):
                style = "red bold" if "Exclusive" in lock_type else ""
                dist_table.add_row(lock_type, str(count), style=style)
            console.print(dist_table)

        # Blocking chains
        chains = result.get("chains", [])
        if chains:
            console.print()
            console.print("[bold]Blocking Chains:[/bold]")

            for chain in chains:
                severity = chain.get("severity", "info")
                sev_style = {"critical": "red bold", "warning": "yellow", "info": "blue"}.get(severity, "white")

                holder = chain.get("holder", {})
                tree = Tree(
                    f"[{sev_style}][{severity.upper()}][/{sev_style}] "
                    f"PID {holder.get('pid', '?')} ({holder.get('state', '?')}) "
                    f"[dim]running {holder.get('duration_sec', 0):.0f}s[/dim]"
                )
                tree.add(f"[dim]Lock:[/dim] {holder.get('lock_type', '?')} on {holder.get('relation', '?')}")
                tree.add(f"[dim]Query:[/dim] {holder.get('query', '?')[:120]}")

                if chain.get("is_deadlock"):
                    tree.add("[red bold]⚠ DEADLOCK — this PID is also blocked![/red bold]")

                waiters = chain.get("waiters", [])
                waiters_branch = tree.add(f"[bold]Blocking {len(waiters)} query(ies):[/bold]")
                for waiter in waiters:
                    w_node = waiters_branch.add(
                        f"PID {waiter.get('pid', '?')} — waiting {waiter.get('wait_sec', 0):.0f}s"
                    )
                    w_node.add(f"[dim]{waiter.get('query', '?')[:100]}[/dim]")

                console.print(tree)
                console.print()

                # Kill suggestion
                if kill_threshold and holder.get("duration_sec", 0) > kill_threshold:
                    console.print(
                        f"  [red]Kill suggestion:[/red] "
                        f"SELECT pg_terminate_backend({holder.get('pid', '?')});"
                    )
        else:
            console.print("\n[green]✓ No blocking queries detected — lock health is good.[/green]")

        # Recommendations
        recs = result.get("recommendations", [])
        if recs:
            console.print()
            for rec in recs:
                console.print(f"  💡 {rec}")

        if fail_on_deadlock and deadlock:
            raise typer.Exit(code=1)
