"""
CLI commands for the Interactive Query Tuning Workbook.

    querysense workbook init --sql "SELECT..." --name my_optimization
    querysense workbook add-params --name my_optimization --set "user_id=1,status=shipped"
    querysense workbook baseline --name my_optimization --dsn $DATABASE_URL
    querysense workbook add-variant --name my_optimization --variant composite_idx --index-sql "CREATE INDEX ..."
    querysense workbook test --name my_optimization --dsn $DATABASE_URL
    querysense workbook compare --name my_optimization
    querysense workbook apply --name my_optimization --variant composite_idx
    querysense workbook list
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(workbook_app: typer.Typer) -> None:
    """Register workbook commands."""

    @workbook_app.command(name="init")
    def wb_init(
        sql: Annotated[
            str,
            typer.Option("--sql", "-s", help="SQL query to optimize"),
        ],
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Workbook name (auto-generated if omitted)"),
        ] = "",
    ) -> None:
        """
        Create a new Query Tuning Workbook for a SQL query.

        This creates a persistent workspace to systematically test
        parameter sets, index variants, and config changes.

        \b
        Examples:
            $ querysense workbook init --sql "SELECT * FROM orders WHERE user_id = \\$1 AND status = \\$2 ORDER BY created_at DESC LIMIT 10"
            $ querysense workbook init --sql "SELECT count(*) FROM events WHERE org_id = \\$1" --name events_count
        """
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        try:
            wb_id = mgr.init(sql, name)
        except Exception as e:
            error_console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

        wb = mgr._get_workbook(wb_id)
        console.print(Panel(
            f"[bold green]Workbook created![/bold green]\n\n"
            f"  Name: [cyan]{wb['name']}[/cyan]\n"
            f"  ID: {wb_id}\n"
            f"  SQL: [dim]{sql[:100]}{'...' if len(sql) > 100 else ''}[/dim]\n\n"
            f"Next steps:\n"
            f"  1. [bold]querysense workbook add-params --name {wb['name']} --set \"user_id=1,status=shipped\"[/bold]\n"
            f"  2. [bold]querysense workbook baseline --name {wb['name']} --dsn $DATABASE_URL[/bold]\n"
            f"  3. [bold]querysense workbook add-variant --name {wb['name']} --variant composite_idx ...[/bold]\n"
            f"  4. [bold]querysense workbook test --name {wb['name']} --dsn $DATABASE_URL[/bold]\n"
            f"  5. [bold]querysense workbook compare --name {wb['name']}[/bold]",
            title="Query Tuning Workbook",
            border_style="blue",
        ))

    @workbook_app.command(name="add-params")
    def wb_add_params(
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Workbook name"),
        ],
        param_set: Annotated[
            str,
            typer.Option("--set", "-s", help="Parameter set: key=value,key=value"),
        ],
        label: Annotated[
            str,
            typer.Option("--label", "-l", help="Optional label for this set"),
        ] = "",
    ) -> None:
        """
        Add a parameter set to test the query with.

        Different parameter values often cause wildly different plans
        (parameter sniffing). Testing multiple sets reveals this.

        \b
        Examples:
            $ querysense workbook add-params --name my_wb --set "user_id=1,status=shipped"
            $ querysense workbook add-params --name my_wb --set "user_id=50000,status=pending"
        """
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        wb = mgr.get_workbook_by_name(name)
        if not wb:
            error_console.print(f"[red]Workbook '{name}' not found[/red]")
            raise typer.Exit(1)

        params: dict[str, str] = {}
        for pair in param_set.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip()] = v.strip()

        ps_id = mgr.add_params(wb["id"], params, label)
        console.print(
            f"[green]Parameter set added[/green]: {params} "
            f"(id={ps_id}, workbook={name})"
        )

    @workbook_app.command(name="baseline")
    def wb_baseline(
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Workbook name"),
        ],
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ],
    ) -> None:
        """
        Run the baseline query with all parameter sets.

        Executes EXPLAIN (ANALYZE, BUFFERS) for each parameter set
        and records execution time, plan type, and I/O statistics.

        \b
        Examples:
            $ querysense workbook baseline --name my_wb --dsn postgresql://localhost/mydb
        """
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        wb = mgr.get_workbook_by_name(name)
        if not wb:
            error_console.print(f"[red]Workbook '{name}' not found[/red]")
            raise typer.Exit(1)

        results = asyncio.run(mgr.run_baseline(wb["id"], dsn))

        tbl = Table(title=f"Baseline Results ({name})")
        tbl.add_column("Parameters", max_width=30)
        tbl.add_column("Time", justify="right")
        tbl.add_column("Plan Type", max_width=20)
        tbl.add_column("Rows", justify="right")
        tbl.add_column("Cache %", justify="right")
        tbl.add_column("Status")

        for r in results:
            time_style = "green" if r.execution_time_ms < 100 else ("yellow" if r.execution_time_ms < 1000 else "red")
            tbl.add_row(
                r.param_label,
                f"[{time_style}]{r.execution_time_ms:.0f}ms[/{time_style}]",
                r.node_type,
                f"{r.rows_returned:,}",
                f"{r.cache_hit_pct:.0f}%",
                "[red]ERROR[/red]" if r.error else "[green]OK[/green]",
            )
            if r.error:
                console.print(f"  [red dim]{r.error}[/red dim]")

        console.print(tbl)

    @workbook_app.command(name="add-variant")
    def wb_add_variant(
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Workbook name"),
        ],
        variant: Annotated[
            str,
            typer.Option("--variant", "-v", help="Variant name"),
        ],
        sql: Annotated[
            str,
            typer.Option("--sql", "-s", help="Alternative SQL query"),
        ] = "",
        index_sql: Annotated[
            str,
            typer.Option("--index-sql", "-i", help="CREATE INDEX statement to apply before testing"),
        ] = "",
        config_sql: Annotated[
            str,
            typer.Option("--config-sql", "-c", help="SET commands to apply (semicolon-separated)"),
        ] = "",
        description: Annotated[
            str,
            typer.Option("--desc", "-d", help="Description of this variant"),
        ] = "",
    ) -> None:
        """
        Add a query variant to test.

        Variants can be: SQL rewrites, new indexes, or config changes.
        Each variant is tested against all parameter sets.

        \b
        Examples:
            $ querysense workbook add-variant --name my_wb --variant composite_idx \\
                --index-sql "CREATE INDEX idx_orders_covering ON orders(user_id, status, created_at DESC)"

            $ querysense workbook add-variant --name my_wb --variant rewrite \\
                --sql "SELECT id, user_id, status FROM orders WHERE user_id = \\$1 AND status = \\$2 ORDER BY created_at DESC LIMIT 10"

            $ querysense workbook add-variant --name my_wb --variant high_work_mem \\
                --config-sql "SET work_mem = '256MB'"
        """
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        wb = mgr.get_workbook_by_name(name)
        if not wb:
            error_console.print(f"[red]Workbook '{name}' not found[/red]")
            raise typer.Exit(1)

        v_id = mgr.add_variant(
            wb["id"], variant, sql=sql, index_sql=index_sql,
            config_sql=config_sql, description=description,
        )
        console.print(
            f"[green]Variant '{variant}' added[/green] (id={v_id})"
        )

    @workbook_app.command(name="test")
    def wb_test(
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Workbook name"),
        ],
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ],
    ) -> None:
        """
        Test all variants against all parameter sets.

        Applies each variant (index, config, rewrite) and runs
        EXPLAIN (ANALYZE, BUFFERS) for every parameter set.

        \b
        Examples:
            $ querysense workbook test --name my_wb --dsn postgresql://localhost/mydb
        """
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        wb = mgr.get_workbook_by_name(name)
        if not wb:
            error_console.print(f"[red]Workbook '{name}' not found[/red]")
            raise typer.Exit(1)

        results = asyncio.run(mgr.run_variants(wb["id"], dsn))

        tbl = Table(title=f"Variant Test Results ({name})")
        tbl.add_column("Variant", style="cyan")
        tbl.add_column("Parameters", max_width=25)
        tbl.add_column("Time", justify="right")
        tbl.add_column("Plan Type", max_width=20)
        tbl.add_column("Cache %", justify="right")
        tbl.add_column("Status")

        for r in results:
            time_style = "green" if r.execution_time_ms < 100 else ("yellow" if r.execution_time_ms < 1000 else "red")
            tbl.add_row(
                r.variant_name,
                r.param_label,
                f"[{time_style}]{r.execution_time_ms:.0f}ms[/{time_style}]",
                r.node_type,
                f"{r.cache_hit_pct:.0f}%",
                "[red]ERROR[/red]" if r.error else "[green]OK[/green]",
            )

        console.print(tbl)
        console.print("[dim]Run 'querysense workbook compare' to see the winner matrix.[/dim]")

    @workbook_app.command(name="compare")
    def wb_compare(
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Workbook name"),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Compare all variants across all parameter sets.

        Shows a winner matrix: which variant is fastest for each
        parameter set, and the overall winner.

        \b
        Examples:
            $ querysense workbook compare --name my_wb
            $ querysense workbook compare --name my_wb --json
        """
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        wb = mgr.get_workbook_by_name(name)
        if not wb:
            error_console.print(f"[red]Workbook '{name}' not found[/red]")
            raise typer.Exit(1)

        report = mgr.compare(wb["id"])

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        # Winner banner
        console.print(Panel(
            f"[bold green]Overall Winner: {report.overall_winner}[/bold green]",
            title=f"Workbook: {name}",
            border_style="green",
        ))

        # Comparison matrix
        tbl = Table(title="Results Comparison")
        tbl.add_column("Parameter Set", max_width=25)

        for vn in report.variant_names:
            tbl.add_column(vn, justify="right")
        tbl.add_column("Winner", style="bold")

        for param in report.param_labels:
            row: list[str] = [param]
            param_winner = ""

            for vn in report.variant_names:
                cell = report.get_cell(vn, param)
                if not cell or cell.error:
                    row.append("[dim]error[/dim]")
                    continue

                time_style = "green" if cell.time_ms < 100 else ("yellow" if cell.time_ms < 1000 else "red")
                speedup_str = ""
                if cell.speedup > 1.1 and vn != "baseline":
                    speedup_str = f" ({cell.speedup:.0f}x)"

                entry = f"[{time_style}]{cell.time_ms:.0f}ms{speedup_str}[/{time_style}]"
                if cell.is_winner:
                    entry += " [bold green]W[/bold green]"
                    param_winner = vn
                row.append(entry)

            row.append(param_winner)
            tbl.add_row(*row)

        console.print(tbl)

    @workbook_app.command(name="apply")
    def wb_apply(
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Workbook name"),
        ],
        variant: Annotated[
            str,
            typer.Option("--variant", "-v", help="Variant name to apply"),
        ] = "",
        output: Annotated[
            str,
            typer.Option("--output", "-o", help="Output file for migration SQL"),
        ] = "",
    ) -> None:
        """
        Generate migration SQL for the winning variant.

        \b
        Examples:
            $ querysense workbook apply --name my_wb --variant composite_idx
            $ querysense workbook apply --name my_wb --output migration.sql
        """
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        wb = mgr.get_workbook_by_name(name)
        if not wb:
            error_console.print(f"[red]Workbook '{name}' not found[/red]")
            raise typer.Exit(1)

        if not variant:
            report = mgr.compare(wb["id"])
            variant = report.overall_winner
            console.print(f"[dim]Using overall winner: {variant}[/dim]")

        sql = mgr.generate_migration(wb["id"], variant)

        if output:
            from pathlib import Path
            Path(output).write_text(sql, encoding="utf-8")
            console.print(f"[green]Migration written to {output}[/green]")
        else:
            console.print(sql)

    @workbook_app.command(name="list")
    def wb_list(
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """List all workbooks."""
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        workbooks = mgr.list_workbooks()

        if json_output:
            console.print_json(json.dumps([w.to_dict() for w in workbooks], default=str))
            return

        if not workbooks:
            console.print("[dim]No workbooks found. Create one with 'querysense workbook init'.[/dim]")
            return

        tbl = Table(title="Query Tuning Workbooks")
        tbl.add_column("ID", justify="right")
        tbl.add_column("Name", style="cyan")
        tbl.add_column("SQL", max_width=40, style="dim")
        tbl.add_column("Params", justify="right")
        tbl.add_column("Variants", justify="right")
        tbl.add_column("Runs", justify="right")
        tbl.add_column("Created")

        for w in workbooks:
            tbl.add_row(
                str(w.id),
                w.name,
                w.sql[:40] + ("..." if len(w.sql) > 40 else ""),
                str(w.param_count),
                str(w.variant_count),
                str(w.run_count),
                w.created_at[:10],
            )

        console.print(tbl)

    @workbook_app.command(name="delete")
    def wb_delete(
        name: Annotated[
            str,
            typer.Option("--name", "-n", help="Workbook name to delete"),
        ],
    ) -> None:
        """Delete a workbook and all its data."""
        from querysense.workbook_interactive import WorkbookManager

        mgr = WorkbookManager()
        wb = mgr.get_workbook_by_name(name)
        if not wb:
            error_console.print(f"[red]Workbook '{name}' not found[/red]")
            raise typer.Exit(1)

        mgr.delete_workbook(wb["id"])
        console.print(f"[green]Workbook '{name}' deleted.[/green]")
