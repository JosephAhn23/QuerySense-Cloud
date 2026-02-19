"""
Schema command group: drift detection and comparison.

    $ querysense schema snapshot --dsn postgresql://prod/app --output prod.json
    $ querysense schema compare --source prod.json --target staging.json
    $ querysense schema sync --from prod.json --to staging.json --dry-run
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

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register schema subcommands."""

    @app.command()
    def snapshot(
        dsn: Annotated[
            str,
            typer.Option(
                "--dsn",
                help="PostgreSQL connection string",
                envvar="QUERYSENSE_DSN",
            ),
        ] = "postgresql://localhost:5432/postgres",
        output: Annotated[
            Path,
            typer.Option(
                "--output", "-o",
                help="Output file for schema snapshot",
            ),
        ] = Path("schema_snapshot.json"),
        label: Annotated[
            str,
            typer.Option("--label", "-l", help="Label for this snapshot"),
        ] = "",
    ) -> None:
        """
        Capture a schema snapshot from a live database.

        Examples:

            $ querysense schema snapshot --dsn postgresql://prod/app -o prod.json
            $ querysense schema snapshot --dsn postgresql://staging/app -o staging.json
        """
        from querysense.schema import capture_schema

        console.print(f"[dim]Connecting to {dsn.split('@')[-1] if '@' in dsn else dsn}...[/dim]")

        try:
            snap = asyncio.run(capture_schema(dsn))
            if label:
                snap.label = label
            snap.save(output)
            table_count = len(snap.tables)
            col_count = sum(len(t.columns) for t in snap.tables.values())
            idx_count = sum(len(t.indexes) for t in snap.tables.values())
            console.print(
                f"[green]Snapshot saved:[/green] {output}\n"
                f"  Tables: {table_count} | Columns: {col_count} | Indexes: {idx_count}"
            )
        except Exception as e:
            error_console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(code=1)

    @app.command()
    def compare(
        source: Annotated[
            Path,
            typer.Option(
                "--source", "-s",
                help="Source schema snapshot (the 'truth')",
            ),
        ] = ...,
        target: Annotated[
            Path,
            typer.Option(
                "--target", "-t",
                help="Target schema snapshot to check",
            ),
        ] = ...,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        fix: Annotated[
            bool,
            typer.Option("--fix", help="Generate SQL to fix differences"),
        ] = False,
    ) -> None:
        """
        Compare two schema snapshots and show differences.

        Examples:

            $ querysense schema compare --source prod.json --target staging.json
            $ querysense schema compare -s prod.json -t staging.json --fix
        """
        from querysense.schema import SchemaSnapshot, compare_schemas

        if not source.exists():
            error_console.print(f"[red]Error:[/red] Source file not found: {source}")
            raise typer.Exit(code=1)
        if not target.exists():
            error_console.print(f"[red]Error:[/red] Target file not found: {target}")
            raise typer.Exit(code=1)

        src = SchemaSnapshot.load(source)
        tgt = SchemaSnapshot.load(target)

        diff = compare_schemas(src, tgt)

        if json_output:
            console.print_json(json.dumps(diff.format_json(), indent=2))
            return

        if not diff.has_differences:
            console.print(
                Panel(
                    "[green]Schemas are identical![/green]",
                    title="Schema Comparison",
                    border_style="green",
                )
            )
            return

        # Summary
        console.print(
            Panel(
                f"[bold]{len(diff.differences)} difference(s) found[/bold]\n"
                f"Source: {diff.source_label}\n"
                f"Target: {diff.target_label}",
                title="[bold cyan]Schema Differences[/bold cyan]",
                border_style="cyan",
            )
        )

        # Differences table
        diff_table = Table()
        diff_table.add_column("Table", style="cyan")
        diff_table.add_column("Type")
        diff_table.add_column("Change")
        diff_table.add_column("Object")
        diff_table.add_column("Details", max_width=40)

        for d in diff.differences:
            change_style = {
                "added": "[green]+[/green]",
                "removed": "[red]-[/red]",
                "modified": "[yellow]~[/yellow]",
            }.get(d.change_type, "?")

            sev_style = {
                "critical": "[red bold]",
                "warning": "[yellow]",
                "info": "[dim]",
            }.get(d.severity, "")
            sev_end = "[/red bold]" if d.severity == "critical" else (
                "[/yellow]" if d.severity == "warning" else "[/dim]"
            )

            detail = d.source_value or d.target_value
            if len(detail) > 40:
                detail = detail[:37] + "..."

            diff_table.add_row(
                d.table,
                d.category,
                change_style,
                f"{sev_style}{d.object_name}{sev_end}",
                detail,
            )

        console.print(diff_table)

        # Fix SQL
        if fix:
            fix_sqls = diff.generate_sync_sql()
            if fix_sqls:
                console.print("\n[bold]Fix SQL (sync target to source):[/bold]")
                for s in fix_sqls:
                    console.print(f"  [green]{s}[/green]")
            else:
                console.print("\n[dim]No auto-fix SQL available.[/dim]")

    @app.command()
    def sync(
        source: Annotated[
            Path,
            typer.Option(
                "--from", "-s",
                help="Source schema snapshot (the 'truth')",
            ),
        ] = ...,
        target: Annotated[
            Path,
            typer.Option(
                "--to", "-t",
                help="Target schema snapshot",
            ),
        ] = ...,
        dsn: Annotated[
            Optional[str],
            typer.Option(
                "--dsn",
                help="Target database DSN to apply fixes",
                envvar="QUERYSENSE_DSN",
            ),
        ] = None,
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Show SQL without executing"),
        ] = True,
        output: Annotated[
            Optional[Path],
            typer.Option("--output", "-o", help="Save sync SQL to file"),
        ] = None,
    ) -> None:
        """
        Generate or apply SQL to sync target schema to match source.

        Examples:

            $ querysense schema sync --from prod.json --to staging.json --dry-run
            $ querysense schema sync --from prod.json --to staging.json -o sync.sql
        """
        from querysense.schema import SchemaSnapshot, compare_schemas

        if not source.exists() or not target.exists():
            error_console.print("[red]Error:[/red] Snapshot file not found")
            raise typer.Exit(code=1)

        src = SchemaSnapshot.load(source)
        tgt = SchemaSnapshot.load(target)
        diff = compare_schemas(src, tgt)

        if not diff.has_differences:
            console.print("[green]Schemas are already in sync.[/green]")
            return

        sync_sql = diff.generate_sync_sql()
        if not sync_sql:
            console.print("[yellow]Differences found but no auto-fix SQL available.[/yellow]")
            return

        if output:
            output.write_text("\n".join(sync_sql), encoding="utf-8")
            console.print(f"[green]Sync SQL written to {output}[/green]")
            return

        if dry_run:
            console.print(
                f"[cyan][DRY RUN][/cyan] Would execute {len(sync_sql)} statement(s):\n"
            )
            for s in sync_sql:
                console.print(f"  {s}")
            console.print(
                "\n[dim]Run without --dry-run and with --dsn to apply.[/dim]"
            )
            return

        if not dsn:
            error_console.print(
                "[red]Error:[/red] Provide --dsn to apply sync SQL"
            )
            raise typer.Exit(code=1)

        # Execute sync
        console.print(f"[bold]Applying {len(sync_sql)} changes...[/bold]")
        try:
            asyncio.run(_apply_sync(dsn, sync_sql))
            console.print("[green]Schema sync complete.[/green]")
        except Exception as e:
            error_console.print(f"[red]Error applying sync:[/red] {e}")
            raise typer.Exit(code=1)


async def _apply_sync(dsn: str, statements: list[str]) -> None:
    """Apply sync SQL to target database."""
    try:
        import asyncpg
        conn = await asyncpg.connect(dsn)
    except ImportError:
        raise RuntimeError("asyncpg required: pip install asyncpg")

    try:
        for stmt in statements:
            await conn.execute(stmt)
            console.print(f"  [green]OK[/green] {stmt[:80]}")
    finally:
        await conn.close()
