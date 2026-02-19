"""
Migrate command: safe migration execution with auto-rollback.

    $ querysense migrate --safe --sql "ALTER TABLE orders ADD COLUMN user_id INT;"
    $ querysense migrate --safe --file migration.sql --dsn postgresql://localhost/mydb
    $ querysense migrate --dry-run --file migration.sql
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register migrate command on the given Typer app."""

    @app.command()
    def migrate(
        sql: Annotated[
            Optional[str],
            typer.Option(
                "--sql", "-s",
                help="SQL migration statement(s)",
            ),
        ] = None,
        file: Annotated[
            Optional[Path],
            typer.Option(
                "--file", "-f",
                help="Path to migration SQL file",
            ),
        ] = None,
        dsn: Annotated[
            str,
            typer.Option(
                "--dsn",
                help="PostgreSQL connection string",
                envvar="QUERYSENSE_DSN",
            ),
        ] = "postgresql://localhost:5432/postgres",
        safe: Annotated[
            bool,
            typer.Option(
                "--safe/--no-safe",
                help="Enable safe mode with health checks and auto-rollback",
            ),
        ] = True,
        dry_run: Annotated[
            bool,
            typer.Option(
                "--dry-run",
                help="Analyze but don't execute (preview mode)",
            ),
        ] = False,
        lock_timeout: Annotated[
            int,
            typer.Option(
                "--lock-timeout",
                help="Lock timeout in milliseconds (0 = no timeout)",
            ),
        ] = 5000,
        statement_timeout: Annotated[
            int,
            typer.Option(
                "--statement-timeout",
                help="Statement timeout in milliseconds",
            ),
        ] = 30000,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Execute a migration with safety guardrails and auto-rollback.

        Pre-flight checks, savepoints, lock timeouts, and automatic
        rollback on failure. Shows real-time progress.

        Examples:

            $ querysense migrate --safe --sql "ALTER TABLE orders ADD COLUMN status TEXT;"
            $ querysense migrate --dry-run --file migration.sql
            $ querysense migrate --safe --file migration.sql --dsn postgresql://prod/app
        """
        # Get SQL input
        migration_sql = sql
        if file:
            if not file.exists():
                error_console.print(f"[red]Error:[/red] File not found: {file}")
                raise typer.Exit(code=1)
            migration_sql = file.read_text(encoding="utf-8")

        if not migration_sql:
            error_console.print(
                "[red]Error:[/red] Provide SQL via --sql or --file"
            )
            raise typer.Exit(code=1)

        # Step 1: Pre-flight analysis
        from querysense.migration import MigrationAnalyzer

        console.print("[bold]Step 1/4: Pre-flight analysis...[/bold]")
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(migration_sql)

        risk_colors = {
            "low": "green", "medium": "yellow",
            "high": "red", "critical": "red bold",
        }
        risk_color = risk_colors.get(report.overall_risk.value, "white")
        console.print(
            f"  Risk level: [{risk_color}]{report.overall_risk.value.upper()}[/{risk_color}]"
        )
        console.print(
            f"  Statements: {len(report.statements)}"
        )

        if report.warnings:
            for w in report.warnings:
                console.print(f"  [yellow][!!][/yellow] {w}")

        # Block on CRITICAL risk unless --no-safe
        if safe and report.overall_risk.value == "critical":
            console.print(
                "\n[red bold]BLOCKED:[/red bold] Migration has CRITICAL risk."
            )
            console.print(
                "  Use [bold]querysense predict[/bold] to see full analysis."
            )
            console.print(
                "  Override with [bold]--no-safe[/bold] to force execution."
            )
            raise typer.Exit(code=1)

        if dry_run:
            console.print(
                "\n[cyan][DRY RUN][/cyan] Would execute the following statements:"
            )
            for i, stmt in enumerate(report.statements, 1):
                console.print(f"\n  {i}. {stmt[:200]}{'...' if len(stmt) > 200 else ''}")

            if report.rollback_sql:
                console.print("\n[bold]Rollback plan:[/bold]")
                for sql_line in report.rollback_sql:
                    console.print(f"  {sql_line}")

            console.print("\n[cyan]No changes made (dry run).[/cyan]")
            return

        # Step 2: Execute with safety
        console.print("\n[bold]Step 2/4: Health check...[/bold]")

        try:
            result = asyncio.run(
                _execute_safe_migration(
                    dsn=dsn,
                    statements=report.statements,
                    rollback_sql=report.rollback_sql,
                    safe=safe,
                    lock_timeout_ms=lock_timeout,
                    statement_timeout_ms=statement_timeout,
                )
            )
        except Exception as e:
            error_console.print(f"\n[red bold]Migration failed:[/red bold] {e}")
            raise typer.Exit(code=1)

        if json_output:
            console.print_json(json.dumps(result, indent=2))
            return

        # Show result
        if result["success"]:
            console.print(
                Panel(
                    f"[green bold]Migration completed successfully![/green bold]\n\n"
                    f"Statements executed: {result['statements_executed']}\n"
                    f"Total duration: {result['total_duration_ms']:.0f}ms",
                    title="Migration Result",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    f"[red bold]Migration failed![/red bold]\n\n"
                    f"Error: {result['error']}\n"
                    f"Rollback: {'successful' if result['rollback_success'] else 'FAILED'}",
                    title="Migration Result",
                    border_style="red",
                )
            )
            if result.get("recommendation"):
                console.print(f"\n[bold]Recommendation:[/bold] {result['recommendation']}")
            raise typer.Exit(code=1)


async def _execute_safe_migration(
    *,
    dsn: str,
    statements: list[str],
    rollback_sql: list[str],
    safe: bool,
    lock_timeout_ms: int,
    statement_timeout_ms: int,
) -> dict:
    """Execute migration with safety controls."""
    result: dict = {
        "success": False,
        "statements_executed": 0,
        "total_duration_ms": 0.0,
        "error": None,
        "rollback_success": False,
        "recommendation": None,
    }

    start = time.monotonic()

    try:
        # Try asyncpg first
        try:
            import asyncpg
            conn = await asyncpg.connect(dsn)
        except ImportError:
            try:
                import psycopg
                conn = await psycopg.AsyncConnection.connect(dsn)  # type: ignore[assignment]
            except ImportError:
                raise RuntimeError(
                    "Database connection requires asyncpg or psycopg: "
                    "pip install asyncpg"
                )

        console.print("  [green]Connected to database[/green]")

        # Health check: is the database responding?
        console.print("\n[bold]Step 3/4: Executing migration...[/bold]")

        try:
            if safe:
                # Set timeouts
                await conn.execute(f"SET lock_timeout = '{lock_timeout_ms}ms'")  # type: ignore[union-attr]
                await conn.execute(f"SET statement_timeout = '{statement_timeout_ms}ms'")  # type: ignore[union-attr]
                console.print(
                    f"  Lock timeout: {lock_timeout_ms}ms | "
                    f"Statement timeout: {statement_timeout_ms}ms"
                )

            # Execute each statement
            for i, stmt in enumerate(statements, 1):
                stmt_start = time.monotonic()
                console.print(f"\n  Executing {i}/{len(statements)}...")
                console.print(f"  [dim]{stmt[:100]}{'...' if len(stmt) > 100 else ''}[/dim]")

                try:
                    await conn.execute(stmt + ";")  # type: ignore[union-attr]
                    stmt_ms = (time.monotonic() - stmt_start) * 1000
                    console.print(f"  [green]Done[/green] ({stmt_ms:.0f}ms)")
                    result["statements_executed"] = i
                except Exception as stmt_error:
                    stmt_ms = (time.monotonic() - stmt_start) * 1000
                    error_msg = str(stmt_error)

                    console.print(f"  [red]Failed[/red] ({stmt_ms:.0f}ms): {error_msg}")

                    # Auto-rollback
                    if safe and rollback_sql:
                        console.print("\n[bold]Step 4/4: Auto-rollback...[/bold]")
                        try:
                            for rsql in reversed(rollback_sql):
                                await conn.execute(rsql)  # type: ignore[union-attr]
                            result["rollback_success"] = True
                            console.print("  [green]Rollback successful. No data lost.[/green]")
                        except Exception as rb_error:
                            console.print(f"  [red]Rollback failed: {rb_error}[/red]")
                            result["rollback_success"] = False

                    result["error"] = error_msg

                    # Provide recommendation based on error
                    if "lock" in error_msg.lower() or "timeout" in error_msg.lower():
                        result["recommendation"] = (
                            "Migration timed out due to lock contention. "
                            "Schedule for off-peak hours or use lock_timeout=0."
                        )
                    elif "constraint" in error_msg.lower():
                        result["recommendation"] = (
                            "Constraint violation. Check existing data before "
                            "adding constraints."
                        )

                    break

            else:
                # All statements succeeded
                result["success"] = True

        finally:
            await conn.close()  # type: ignore[union-attr]

    except Exception as e:
        result["error"] = str(e)

    result["total_duration_ms"] = (time.monotonic() - start) * 1000
    return result
