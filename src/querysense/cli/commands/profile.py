"""
Profile commands: init, check, list, record.

Implements the "QuerySense Profiles" feature — the git diff for
database performance.

Usage:
    querysense profile init --name production --connection $DATABASE_URL
    querysense profile record --name production --query-id "users_by_email" plan.json
    querysense check --profile production --against new_plan.json
    querysense profile list
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register profile commands on the given Typer app."""

    @app.command(name="init")
    def profile_init(
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Profile name (e.g., production, staging)"),
        ],
        connection: Annotated[
            Optional[str],
            typer.Option("--connection", "-c", help="PostgreSQL connection DSN"),
        ] = None,
        description: Annotated[
            str,
            typer.Option("--description", "-d", help="Profile description"),
        ] = "",
    ) -> None:
        """
        Initialize a new QuerySense profile.

        A profile tracks a database's performance baseline over time,
        enabling regression detection when queries change.

        \\b
        Examples:
            $ querysense profile init --name production --connection $DATABASE_URL
            $ querysense profile init --name staging -d "Staging environment"
        """
        from querysense.profile import ProfileStore

        store = ProfileStore()
        profile = store.create(name, connection, description)

        console.print(Panel(
            f"[green]Profile '{name}' created![/green]\n\n"
            f"Next steps:\n"
            f"  1. Record baselines: querysense profile record --name {name} --query-id <id> plan.json\n"
            f"  2. Check regressions: querysense check --profile {name} --against new_plan.json",
            title="QuerySense Profile",
            border_style="green",
        ))

    @app.command(name="record")
    def profile_record(
        plan_file: Annotated[
            Path,
            typer.Argument(
                help="EXPLAIN JSON file to record",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Profile name"),
        ],
        query_id: Annotated[
            str,
            typer.Option("--query-id", "-q", help="Stable query identifier"),
        ],
    ) -> None:
        """
        Record a plan snapshot into a profile.

        \\b
        Examples:
            $ psql -c "EXPLAIN (ANALYZE, FORMAT JSON) SELECT ..." > plan.json
            $ querysense profile record plan.json --name production --query-id "users_by_email"
        """
        from querysense.engine import AnalysisService
        from querysense.parser import ParseError, parse_explain
        from querysense.profile import ProfileStore

        store = ProfileStore()
        profile = store.get(name)
        if not profile:
            error_console.print(
                f"[red]Profile '{name}' not found.[/red]\n"
                f"Create it with: querysense profile init --name {name}"
            )
            raise typer.Exit(code=1)

        try:
            explain = parse_explain(plan_file)
        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            raise typer.Exit(code=1)

        # Analyze and record
        service = AnalysisService()
        result = service.analyze(explain)

        raw_json = json.loads(plan_file.read_text(encoding="utf-8"))
        profile.record_snapshot(query_id, raw_json[0] if isinstance(raw_json, list) else raw_json, result)

        console.print(
            f"[green]Recorded:[/green] {query_id} into profile '{name}'\n"
            f"  Cost: {explain.plan.total_cost:,.0f}\n"
            f"  Nodes: {len(explain.all_nodes)}\n"
            f"  Findings: {len(result.findings)}"
        )

    @app.command(name="list")
    def profile_list() -> None:
        """List all QuerySense profiles."""
        from querysense.profile import ProfileStore

        store = ProfileStore()
        profiles = store.list_profiles()

        if not profiles:
            console.print("[dim]No profiles found. Create one with: querysense profile init --name <name>[/dim]")
            return

        table = Table(title="QuerySense Profiles")
        table.add_column("Name", style="cyan bold")
        table.add_column("Description")
        table.add_column("Created")
        table.add_column("Connection")

        for p in profiles:
            dsn_display = "configured" if p.connection_dsn else "—"
            table.add_row(
                p.name,
                p.description or "—",
                p.created_at[:16] if p.created_at else "—",
                dsn_display,
            )

        console.print(table)


def register_check(app: typer.Typer) -> None:
    """Register the top-level check command."""

    @app.command(name="check")
    def check(
        plan_file: Annotated[
            Path,
            typer.Argument(
                help="EXPLAIN JSON file to check",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        profile_name: Annotated[
            str,
            typer.Option("--profile", "-p", help="Profile to check against"),
        ],
        query_id: Annotated[
            str,
            typer.Option("--query-id", "-q", help="Query identifier"),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        fail_on_regression: Annotated[
            bool,
            typer.Option("--fail-on-regression", help="Exit code 1 if regression detected"),
        ] = False,
    ) -> None:
        """
        Check a plan against a profile for regressions.

        Compares the new EXPLAIN plan against the profile's historical
        baseline and outputs whether performance improved, regressed,
        or stayed the same.

        This is the "git diff for database performance" — designed
        to run in CI when someone opens a PR.

        \\b
        Examples:
            # Check a new plan against production baseline
            $ querysense check new_plan.json --profile production --query-id "users_by_email"

            # In CI pipeline
            $ querysense check plan.json --profile production --query-id "$QUERY" \\
                --fail-on-regression --json
        """
        from querysense.parser import ParseError, parse_explain
        from querysense.profile import ProfileStore

        store = ProfileStore()
        profile = store.get(profile_name)
        if not profile:
            error_console.print(
                f"[red]Profile '{profile_name}' not found.[/red]"
            )
            raise typer.Exit(code=1)

        try:
            raw_json = json.loads(plan_file.read_text(encoding="utf-8"))
            explain_dict = raw_json[0] if isinstance(raw_json, list) else raw_json
        except (json.JSONDecodeError, ParseError) as e:
            error_console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(code=1)

        result = profile.check(query_id, explain_dict)

        if json_output:
            console.print_json(json.dumps(result.to_dict(), default=str))
        else:
            if result.is_regression:
                console.print(Panel(
                    f"[red bold]REGRESSION DETECTED[/red bold]\n\n"
                    f"{result.message}\n\n"
                    f"Cost: {result.cost_before:,.0f} → {result.cost_after:,.0f} "
                    f"({result.cost_change_pct:+.1f}%)\n"
                    f"Findings: {result.findings_after}",
                    title=f"QuerySense Check: {query_id} vs {profile_name}",
                    border_style="red",
                ))
            elif result.is_improvement:
                console.print(Panel(
                    f"[green bold]IMPROVEMENT[/green bold]\n\n"
                    f"{result.message}\n\n"
                    f"Cost: {result.cost_before:,.0f} → {result.cost_after:,.0f} "
                    f"({result.speedup_ratio:.1f}x faster)",
                    title=f"QuerySense Check: {query_id} vs {profile_name}",
                    border_style="green",
                ))
            else:
                console.print(Panel(
                    f"[green]No significant change.[/green]\n\n{result.message}",
                    title=f"QuerySense Check: {query_id} vs {profile_name}",
                    border_style="green",
                ))

        if fail_on_regression and result.is_regression:
            raise typer.Exit(code=1)
