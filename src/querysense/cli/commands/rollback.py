"""
Intelligent rollback command: dependency-aware rollback generation.

Beats Liquibase Pro ("very difficult" rollbacks) and Flyway Teams (paywalled undo)
by providing free, dependency-aware rollback SQL.

    $ querysense rollback generate --migration add_users.sql
    $ querysense rollback generate --migration add_users.sql --dsn postgresql://prod/app
    $ querysense rollback generate --migration add_users.sql -o rollback.sql
    $ querysense rollback preview --migration add_users.sql
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register rollback subcommands."""

    @app.command()
    def generate(
        migration: Annotated[
            Path,
            typer.Option(
                "--migration", "-m",
                help="Path to migration SQL file",
                exists=True,
                readable=True,
            ),
        ],
        dsn: Annotated[
            Optional[str],
            typer.Option(
                "--dsn",
                help="PostgreSQL DSN to query actual dependencies",
                envvar="QUERYSENSE_DSN",
            ),
        ] = None,
        output: Annotated[
            Optional[Path],
            typer.Option("--output", "-o", help="Write rollback SQL to file"),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Show what would be generated without writing"),
        ] = False,
    ) -> None:
        """
        Generate intelligent rollback SQL with dependency preservation.

        Unlike Liquibase and Flyway, this:
        - Tracks view, function, and trigger dependencies
        - Orders rollback in 3 phases (drop deps → undo → restore deps)
        - Warns about irreversible operations with clear instructions
        - Connects to your database (optional) to find real dependencies

        \\b
        Examples:
            # Basic rollback generation
            $ querysense rollback generate --migration migration.sql

            # With live dependency analysis
            $ querysense rollback generate --migration migration.sql --dsn postgresql://prod/app

            # Save to file
            $ querysense rollback generate --migration migration.sql -o rollback.sql

            # CI-friendly JSON output
            $ querysense rollback generate --migration migration.sql --json
        """
        from querysense.rollback import (
            generate_smart_rollback,
            fetch_dependencies,
            DependentObject,
        )

        migration_sql = migration.read_text(encoding="utf-8")

        # Fetch real dependencies if DSN provided
        deps: list[DependentObject] = []
        if dsn:
            console.print("[dim]Querying database for dependencies...[/dim]")
            try:
                # Extract table names from migration
                import re
                table_matches = re.findall(
                    r"(?:ALTER|DROP)\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:\w+\.)?(\w+)",
                    migration_sql,
                    re.IGNORECASE,
                )
                for table in set(table_matches):
                    table_deps = asyncio.run(fetch_dependencies(dsn, table))
                    deps.extend(table_deps)
                if deps:
                    console.print(
                        f"[yellow]Found {len(deps)} dependent object(s)[/yellow]"
                    )
                else:
                    console.print("[green]No dependent objects found[/green]")
            except Exception as exc:
                error_console.print(
                    f"[yellow]Warning: Could not query dependencies: {exc}[/yellow]"
                )

        plan = generate_smart_rollback(migration_sql, dependencies=deps or None)

        # JSON output
        if json_output:
            console.print_json(json.dumps(plan.to_dict(), default=str))
            return

        # Pretty output
        if plan.is_safe:
            console.print(Panel(
                "[green bold]SAFE ROLLBACK[/green bold]\n"
                f"All {len(plan.rollback_statements)} operation(s) are fully reversible",
                title="Rollback Analysis",
                border_style="green",
            ))
        else:
            console.print(Panel(
                f"[yellow bold]PARTIAL ROLLBACK[/yellow bold]\n"
                f"{len(plan.rollback_statements)} reversible, "
                f"{len(plan.irreversible_statements)} require manual steps",
                title="Rollback Analysis",
                border_style="yellow",
            ))

        # Show dependency info
        if plan.dependent_objects:
            dep_table = Table(title="Dependent Objects Affected")
            dep_table.add_column("Type", style="cyan")
            dep_table.add_column("Object", style="bold")
            dep_table.add_column("Depends On")
            for dep in plan.dependent_objects:
                dep_table.add_row(
                    dep.object_type,
                    f"{dep.schema}.{dep.name}",
                    dep.depends_on_table,
                )
            console.print(dep_table)

        # Show warnings
        if plan.warnings:
            console.print()
            for w in plan.warnings:
                console.print(f"  [yellow]⚠[/yellow]  {w}")
            console.print()

        # Show rollback SQL
        rollback_sql = plan.rollback_sql
        console.print()
        console.print(Syntax(rollback_sql, "sql", theme="monokai", line_numbers=True))

        # Write to file
        if output and not dry_run:
            output.write_text(rollback_sql, encoding="utf-8")
            console.print(f"\n[green]Rollback SQL written to {output}[/green]")
        elif dry_run:
            console.print(f"\n[dim]Dry run: would write to {output or 'stdout'}[/dim]")

    @app.command()
    def preview(
        migration: Annotated[
            Path,
            typer.Option(
                "--migration", "-m",
                help="Path to migration SQL file",
                exists=True,
                readable=True,
            ),
        ],
    ) -> None:
        """
        Quick preview of rollback without dependency analysis.

        Shows what rollback statements would be generated for each
        migration statement, with color-coded safety indicators.

        \\b
        Example:
            $ querysense rollback preview --migration migration.sql
        """
        from querysense.rollback import generate_smart_rollback

        migration_sql = migration.read_text(encoding="utf-8")
        plan = generate_smart_rollback(migration_sql)

        table = Table(title="Rollback Preview")
        table.add_column("#", style="dim", width=3)
        table.add_column("Forward", max_width=50)
        table.add_column("Rollback", max_width=50)
        table.add_column("Safe", width=4, justify="center")

        statements = [s.strip() for s in migration_sql.split(";") if s.strip()]
        rollback_stmts = plan.rollback_statements[:]
        irreversible = {s[:60] for s in plan.irreversible_statements}

        for i, stmt in enumerate(statements, 1):
            # Find corresponding rollback
            rb = ""
            safe = "[green]✓[/green]"
            if any(stmt[:40].lower() in irr.lower() for irr in irreversible):
                rb = "[red]Irreversible — manual restore required[/red]"
                safe = "[red]✗[/red]"
            elif rollback_stmts:
                rb = rollback_stmts.pop(0)

            table.add_row(
                str(i),
                stmt[:50] + ("..." if len(stmt) > 50 else ""),
                str(rb)[:50] + ("..." if len(str(rb)) > 50 else ""),
                safe,
            )

        console.print(table)

        if plan.is_safe:
            console.print("\n[green bold]All operations are safely reversible.[/green bold]")
        else:
            console.print(
                f"\n[yellow bold]{len(plan.irreversible_statements)} operation(s) "
                f"require manual intervention.[/yellow bold]"
            )
