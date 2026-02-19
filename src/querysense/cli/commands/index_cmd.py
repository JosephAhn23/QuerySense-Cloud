"""
CLI commands for the Constraint Programming Index Advisor.

Implements `querysense index` subcommands:
    querysense index recommend  - Recommend optimal indexes using CP
    querysense index explore    - Compare read/write/balanced configurations
    querysense index solve      - Solve from pganalyze-format JSON files
    querysense index override   - Save configuration overrides for a table
    querysense index status     - Show current index configurations
    querysense index iwo        - Calculate index write overhead

Usage:
    # Solve from pganalyze-format data
    querysense index solve --data examples/data.json --settings examples/settings.json

    # Explore all configurations
    querysense index solve --data examples/data.json --explore

    # Show IWO analysis
    querysense index iwo --data examples/data.json
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


def register(index_app: typer.Typer) -> None:
    """Register index advisor commands on the given Typer app."""

    @index_app.command()
    def solve(
        data_file: Annotated[
            str,
            typer.Option("--data", "-d", help="Path to problem data JSON (pganalyze format)"),
        ],
        settings_file: Annotated[
            Optional[str],
            typer.Option("--settings", "-s", help="Path to settings JSON (goals and rules)"),
        ] = None,
        time_limit: Annotated[
            float,
            typer.Option("--time-limit", "-t", help="Solver time limit in seconds"),
        ] = 10.0,
        explore: Annotated[
            bool,
            typer.Option("--explore", "-e", help="Show all configuration options"),
        ] = False,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output result as JSON"),
        ] = False,
    ) -> None:
        """
        Solve an index selection problem using constraint programming.

        Uses Google OR-Tools CP-SAT solver to find the globally optimal
        set of indexes, implementing pganalyze's Index Advisor 3.0 approach.

        \\b
        Input format (pganalyze PGCon 2023):
            {
                "Scans": [
                    {"Name": "scan_A", "Sequential Cost": 35,
                     "Index Costs": [{"Index": "idx_1", "Cost": 15}, ...]}
                ],
                "Existing Indexes": ["idx_1"],
                "Index Write Overhead": {"idx_1": 10, ...}
            }

        \\b
        Examples:
            # Solve with default settings
            $ querysense index solve --data data.json

            # Solve with custom goals and rules
            $ querysense index solve --data data.json --settings settings.json

            # Explore all configurations (read/write/balanced)
            $ querysense index solve --data data.json --explore

            # JSON output for automation
            $ querysense index solve --data data.json --json
        """
        try:
            from querysense.index.advisor import ConstraintProgrammingIndexAdvisor
        except ImportError:
            error_console.print(
                "[red]Error:[/red] Google OR-Tools is required for the CP index advisor.\n"
                "Install with: pip install ortools"
            )
            raise typer.Exit(code=1)

        data_path = Path(data_file)
        if not data_path.exists():
            error_console.print(f"[red]Error:[/red] Data file not found: {data_file}")
            raise typer.Exit(code=1)

        data = json.loads(data_path.read_text(encoding="utf-8"))
        settings = None
        if settings_file:
            settings_path = Path(settings_file)
            if not settings_path.exists():
                error_console.print(f"[red]Error:[/red] Settings file not found: {settings_file}")
                raise typer.Exit(code=1)
            settings = json.loads(settings_path.read_text(encoding="utf-8"))

        advisor = ConstraintProgrammingIndexAdvisor()

        if explore:
            _display_explore(advisor, data, time_limit, json_output)
        else:
            solution = advisor.solve_from_data(data, settings, time_limit)
            if json_output:
                console.print_json(json.dumps(solution.to_dict(), indent=2))
            else:
                _display_solution(solution)

    @index_app.command()
    def override(
        table: Annotated[
            str,
            typer.Option("--table", "-t", help="Table to configure"),
        ],
        config_file: Annotated[
            str,
            typer.Option("--config", "-c", help="Configuration JSON file"),
        ],
        reason: Annotated[
            Optional[str],
            typer.Option("--reason", "-r", help="Reason for override"),
        ] = None,
    ) -> None:
        """
        Save a configuration override for a table.

        Overrides the automatic classification (read/write/balanced)
        with a custom configuration.

        \\b
        Example config:
            {
                "primary_goal": "Minimal Cost",
                "secondary_goal": "Minimal Indexes",
                "tolerance": 0.1,
                "max_indexes": 4
            }

        \\b
        Examples:
            $ querysense index override --table orders --config config.json
            $ querysense index override --table orders --config config.json --reason "High-traffic table"
        """
        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor

        config_path = Path(config_file)
        if not config_path.exists():
            error_console.print(f"[red]Error:[/red] Config file not found: {config_file}")
            raise typer.Exit(code=1)

        config = json.loads(config_path.read_text(encoding="utf-8"))
        if reason:
            config["reason"] = reason

        path = ConstraintProgrammingIndexAdvisor.save_configuration_override(
            table, config
        )
        console.print(f"[green]Configuration saved[/green] for [bold]{table}[/bold]")
        console.print(f"  Override file: {path}")

    @index_app.command()
    def status() -> None:
        """
        Show current index configuration overrides.

        Displays all saved configuration overrides across tables.
        """
        from querysense.index.advisor import ConstraintProgrammingIndexAdvisor

        overrides = ConstraintProgrammingIndexAdvisor.load_configuration_overrides()

        if not overrides:
            console.print("[dim]No configuration overrides found.[/dim]")
            console.print("Use [bold]querysense index override[/bold] to set one.")
            return

        table = Table(title="Index Configuration Overrides")
        table.add_column("Table", style="cyan")
        table.add_column("Configuration", style="green")
        table.add_column("Max Indexes", justify="right")
        table.add_column("User", style="dim")
        table.add_column("Date", style="dim")
        table.add_column("Reason")

        for tbl, info in overrides.items():
            config = info.get("config", {})
            table.add_row(
                tbl,
                config.get("primary_goal", "default"),
                str(config.get("max_indexes", "-")),
                info.get("user", "unknown"),
                info.get("date", "")[:10],
                config.get("reason", ""),
            )

        console.print(table)

    @index_app.command()
    def check(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        schema: Annotated[
            str,
            typer.Option("--schema", "-s", help="Schema to check"),
        ] = "public",
        max_indexes: Annotated[
            int,
            typer.Option("--max-indexes-per-table", help="Max indexes per table"),
        ] = 8,
        top_queries: Annotated[
            int,
            typer.Option("--top-queries", help="Number of top queries to analyze"),
        ] = 100,
        no_hypopg: Annotated[
            bool,
            typer.Option("--no-hypopg", help="Skip HypoPG verification"),
        ] = False,
        verbose: Annotated[
            bool,
            typer.Option("--verbose", "-v", help="Show solver decision process"),
        ] = False,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output only CREATE INDEX statements"),
        ] = False,
    ) -> None:
        """
        Check if the database schema has optimal indexes (CI/CD gate).

        Returns exit code 0 if the schema is optimal (no missing indexes),
        or exit code 1 with CREATE INDEX statements if indexes are missing.

        Modelled after `pganalyze_lint`: a CI-friendly check that can be
        added to your deployment pipeline.

        \\b
        Full pipeline:
            1. Extract scans from pg_stat_statements
            2. Classify tables (read/write/balanced/ignore)
            3. Calculate IWO (Index Write Overhead)
            4. Filter candidates with HOT update guard
            5. (Optional) Cost candidates with HypoPG
            6. Solve with CP-SAT (OR-Tools constraint programming)
            7. (Optional) Verify with HypoPG
            8. Output CREATE/DROP INDEX statements

        \\b
        Examples:
            # CI/CD gate (exit 1 if indexes are missing)
            $ querysense index check --dsn $DB_URL

            # Verbose output with solver details
            $ querysense index check --dsn $DB_URL -v

            # Just the fix SQL for piping
            $ querysense index check --dsn $DB_URL --fix-script | psql $DB_URL

            # JSON for automation
            $ querysense index check --dsn $DB_URL --json
        """
        import asyncio

        try:
            from querysense.index.advisor_pipeline import IndexAdvisorPipeline
        except ImportError:
            error_console.print(
                "[red]Error:[/red] Google OR-Tools is required.\n"
                "Install with: pip install ortools"
            )
            raise typer.Exit(code=1)

        pipeline = IndexAdvisorPipeline(
            max_indexes_per_table=max_indexes,
            use_hypopg=not no_hypopg,
            top_queries=top_queries,
        )

        result = asyncio.run(pipeline.advise(dsn, schema=schema))

        has_recommendations = len(result.recommended_indexes) > 0
        has_drops = len(result.dropped_indexes) > 0
        needs_changes = has_recommendations or has_drops

        if fix_script:
            if needs_changes:
                lines = []
                lines.append("-- QuerySense Index Check: Fix Script")
                lines.append(f"-- Generated by: querysense index check --dsn ... --schema {schema}")
                lines.append("")
                if result.dropped_indexes:
                    lines.append("-- Drop redundant/unused indexes")
                    for idx_name in result.dropped_indexes:
                        lines.append(f"DROP INDEX CONCURRENTLY IF EXISTS {idx_name};")
                    lines.append("")
                if result.recommended_indexes:
                    lines.append("-- Create missing indexes")
                    for idx in result.recommended_indexes:
                        lines.append(idx.create_sql)
                    lines.append("")
                console.print("\n".join(lines))
            raise typer.Exit(code=1 if needs_changes else 0)

        if json_output:
            output = result.to_dict()
            output["exit_code"] = 1 if needs_changes else 0
            output["needs_changes"] = needs_changes
            console.print_json(json.dumps(output, indent=2, default=str))
            raise typer.Exit(code=1 if needs_changes else 0)

        # Rich output
        if not needs_changes:
            console.print(
                "[green bold]✓ Schema is optimal — no missing indexes detected.[/green bold]"
            )
            if verbose:
                console.print(f"  Tables analyzed: {result.tables_analyzed}")
                console.print(f"  Scans extracted: {result.scans_extracted}")
                console.print(f"  Pipeline time: {result.total_time_ms:.0f}ms")
            raise typer.Exit(code=0)

        # Exit code 1: changes needed
        console.print(
            f"[red bold]✗ Schema needs {len(result.recommended_indexes)} new index(es) "
            f"and {len(result.dropped_indexes)} drop(s).[/red bold]"
        )

        if verbose:
            console.print(Panel(
                f"Tables analyzed: {result.tables_analyzed}\n"
                f"Scans extracted: {result.scans_extracted}\n"
                f"Candidates generated: {result.candidates_generated}\n"
                f"Candidates after IWO filter: {result.candidates_after_iwo}\n"
                f"Total cost reduction: {result.total_cost_reduction_pct:.1f}%\n"
                f"Total IWO: {result.total_iwo:.2f}\n"
                f"Pipeline time: {result.total_time_ms:.0f}ms",
                title="Solver Details",
                border_style="dim",
            ))

        if result.dropped_indexes:
            console.print("\n[bold red]DROP (redundant/unused):[/bold red]")
            for idx_name in result.dropped_indexes:
                console.print(f"  [red]-[/red] DROP INDEX CONCURRENTLY IF EXISTS {idx_name};")

        if result.recommended_indexes:
            console.print("\n[bold green]CREATE (missing):[/bold green]")
            tbl = Table()
            tbl.add_column("Table", style="cyan")
            tbl.add_column("Columns", style="bold")
            tbl.add_column("Scans", justify="right")
            tbl.add_column("Freq", justify="right")
            tbl.add_column("Improvement", justify="right")
            tbl.add_column("IWO", justify="right")
            if not no_hypopg:
                tbl.add_column("Verified", justify="center")

            for idx in result.recommended_indexes:
                row = [
                    idx.table,
                    ", ".join(idx.columns),
                    str(idx.scans_covered),
                    f"{idx.total_frequency:,}",
                    f"{idx.improvement_ratio:.0%}",
                    f"{idx.iwo_score:.2f}",
                ]
                if not no_hypopg:
                    row.append("[green]✓[/green]" if idx.hypopg_verified else "[dim]—[/dim]")
                tbl.add_row(*row)

            console.print(tbl)

            console.print("\n[bold]SQL:[/bold]")
            for idx in result.recommended_indexes:
                console.print(f"  {idx.create_sql}")

        raise typer.Exit(code=1)

    @index_app.command()
    def iwo(
        data_file: Annotated[
            str,
            typer.Option("--data", "-d", help="Path to problem data JSON"),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Calculate Index Write Overhead (IWO) for candidate indexes.

        Shows the write cost of maintaining each index, helping decide
        which indexes are too expensive for write-heavy tables.
        """
        from querysense.index.cp_model import IndexSelectionProblem
        from querysense.index.workload_classifier import TableStats
        from querysense.index.write_overhead import IndexWriteOverheadCalculator

        data_path = Path(data_file)
        if not data_path.exists():
            error_console.print(f"[red]Error:[/red] File not found: {data_file}")
            raise typer.Exit(code=1)

        data = json.loads(data_path.read_text(encoding="utf-8"))
        problem = IndexSelectionProblem.from_dict(data)

        calculator = IndexWriteOverheadCalculator()
        # Use basic stats if not provided
        stats = TableStats(
            table_name="<from data>",
            n_tup_ins=1000,
            n_tup_upd=500,
            n_tup_del=100,
            stats_reset_seconds=3600,
        )

        results = []
        for idx in problem.indexes:
            overhead = problem.index_write_overheads.get(idx.id, idx.write_overhead)
            iwo = calculator.calculate(
                idx.name or idx.id,
                idx.table or "<unknown>",
                list(idx.columns) if idx.columns else [idx.id],
                idx.index_type,
                stats,
            )
            results.append(iwo)

        if json_output:
            console.print_json(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            console.print(calculator.format_summary(results))


# ------------------------------------------------------------------
# Display helpers
# ------------------------------------------------------------------


def _display_solution(solution: "IndexSelectionSolution") -> None:
    """Display solution using Rich formatting."""
    from querysense.index.cp_model import IndexSelectionSolution

    status_color = {
        "OPTIMAL": "green",
        "FEASIBLE": "yellow",
        "INFEASIBLE": "red",
        "UNKNOWN": "dim",
    }.get(solution.status, "dim")

    console.print()
    console.print(
        Panel.fit(
            f"[bold]Status:[/bold] [{status_color}]{solution.status}[/{status_color}]\n"
            f"[bold]Total cost:[/bold] {solution.total_cost}\n"
            f"[bold]Indexes:[/bold] {solution.total_indexes}\n"
            f"[bold]Coverage:[/bold] {solution.coverage_pct:.1f}% "
            f"({solution.scans_covered}/{solution.total_scans})\n"
            f"[bold]IWO:[/bold] {solution.total_write_overhead:.1f}\n"
            f"[bold]Solve time:[/bold] {solution.solve_time_ms:.1f}ms",
            title="CP Index Advisor Result",
            border_style="blue",
        )
    )

    if solution.selected_indexes:
        console.print("\n[bold]Selected Indexes:[/bold]")
        for idx_id in solution.selected_indexes:
            console.print(f"  [green]+[/green] {idx_id}")

    if solution.scan_results:
        scan_table = Table(title="\nScan Coverage")
        scan_table.add_column("Scan", style="cyan")
        scan_table.add_column("Cost", justify="right")
        scan_table.add_column("Index", style="green")
        scan_table.add_column("Type", style="dim")

        for sr in solution.scan_results:
            scan_table.add_row(
                sr.scan_id,
                str(sr.cost),
                sr.covering_index or "-",
                "seq" if sr.is_sequential else "idx",
            )

        console.print(scan_table)

    console.print()


def _display_explore(
    advisor: "ConstraintProgrammingIndexAdvisor",
    data: dict,
    time_limit: float,
    json_output: bool,
) -> None:
    """Display explore results comparing all configurations."""
    from querysense.index.cp_model import (
        Goal,
        GoalName,
        IndexSelectionProblem,
        SolverSettings,
    )
    from querysense.index.workload_classifier import CONFIGURATIONS, TableConfiguration

    configs = {
        "Read-Optimized": CONFIGURATIONS[TableConfiguration.READ_OPTIMIZED],
        "Write-Optimized": CONFIGURATIONS[TableConfiguration.WRITE_OPTIMIZED],
        "Balanced": CONFIGURATIONS[TableConfiguration.BALANCED],
    }

    results = {}
    for name, config in configs.items():
        settings = config.to_solver_settings(time_limit)
        problem = IndexSelectionProblem.from_dict(data, settings)
        solution = advisor._solve(problem)
        results[name] = solution

    if json_output:
        out = {name: sol.to_dict() for name, sol in results.items()}
        console.print_json(json.dumps(out, indent=2))
        return

    console.print()
    console.print(
        Panel.fit(
            "[bold]Configuration Explorer[/bold]\n"
            "Compare read-optimized, write-optimized, and balanced settings",
            title="CP Index Advisor",
            border_style="blue",
        )
    )

    table = Table()
    table.add_column("Configuration", style="cyan")
    table.add_column("Indexes", justify="right")
    table.add_column("Total Cost", justify="right")
    table.add_column("Coverage", justify="right")
    table.add_column("IWO", justify="right")
    table.add_column("Status", style="dim")
    table.add_column("Selected")

    for name, sol in results.items():
        table.add_row(
            name,
            str(sol.total_indexes),
            str(sol.total_cost),
            f"{sol.coverage_pct:.1f}%",
            f"{sol.total_write_overhead:.1f}",
            sol.status,
            ", ".join(sol.selected_indexes) if sol.selected_indexes else "-",
        )

    console.print(table)
    console.print()

def register_extra(index_app: typer.Typer) -> None:
    """Register additional index commands (design, design-query, suggest)."""

    # ── Index Design Advisor ─────────────────────────────────────────

    @index_app.command()
    def design(
        table: Annotated[
            str,
            typer.Option("--table", "-t", help="Table name to design index for"),
        ],
        columns: Annotated[
            str,
            typer.Option(
                "--columns", "-c",
                help="Comma-separated columns to include (e.g., organization_id,occurred_at)",
            ),
        ],
        order: Annotated[
            Optional[str],
            typer.Option(
                "--order", "-o",
                help="ORDER BY columns with direction (e.g., occurred_at:DESC,created_at:ASC)",
            ),
        ] = None,
        where: Annotated[
            Optional[str],
            typer.Option(
                "--where", "-w",
                help="WHERE equality columns (comma-separated)",
            ),
        ] = None,
        range_cols: Annotated[
            Optional[str],
            typer.Option(
                "--range",
                help="Range filter columns: >, <, BETWEEN (comma-separated)",
            ),
        ] = None,
        select: Annotated[
            Optional[str],
            typer.Option(
                "--select", "-s",
                help="SELECT columns for covering index (comma-separated)",
            ),
        ] = None,
        dsn: Annotated[
            Optional[str],
            typer.Option(
                "--dsn",
                help="PostgreSQL DSN — fetch cardinality from pg_stats (optional)",
                envvar="QUERYSENSE_DSN",
            ),
        ] = None,
        schema: Annotated[
            str,
            typer.Option("--schema", help="Schema name"),
        ] = "public",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Design an optimal multi-column index with educational explanation.

        Explains *why* columns should be ordered a certain way based on
        cardinality, query patterns, and B-tree mechanics. Acts as a
        teaching tool, not just a recommendation engine.

        Core principles (pganalyze Efficient Search p.17-18):
          1. Equality columns first (highest cardinality first)
          2. Range columns next
          3. ORDER BY columns last (sort elimination)
          4. INCLUDE for index-only scans

        \b
        Examples:
            $ querysense index design --table product_events \\
                --columns organization_id,occurred_at \\
                --order occurred_at:DESC \\
                --where organization_id

            $ querysense index design --table orders \\
                --columns status,created_at,amount \\
                --where status --range created_at \\
                --select id,total --json

            # With live cardinality from database:
            $ querysense index design --table events \\
                --columns org_id,type,ts \\
                --where org_id,type --order ts:DESC \\
                --dsn postgresql://localhost/mydb
        """
        import asyncio
        from querysense.analysis.index_design import IndexDesignAdvisor

        advisor = IndexDesignAdvisor()

        # Parse column list
        col_list = [c.strip() for c in columns.split(",") if c.strip()]

        # Parse ORDER BY
        order_dict: dict[str, str] = {}
        if order:
            for part in order.split(","):
                part = part.strip()
                if ":" in part:
                    col, direction = part.split(":", 1)
                    order_dict[col.strip()] = direction.strip().upper()
                else:
                    order_dict[part] = "ASC"

        # Parse WHERE columns
        where_cols = [c.strip() for c in (where or "").split(",") if c.strip()]
        range_list = [c.strip() for c in (range_cols or "").split(",") if c.strip()]
        select_cols = [c.strip() for c in (select or "").split(",") if c.strip()]

        # If DSN provided, fetch cardinality live
        if dsn:
            try:
                import asyncpg  # noqa: F811

                async def _fetch_design() -> "IndexDesign":
                    conn = await asyncpg.connect(dsn)
                    try:
                        # Fetch cardinalities
                        cardinalities: dict[str, int] = {}
                        table_rows = 0
                        stats = await conn.fetch(
                            "SELECT attname, n_distinct FROM pg_stats "
                            "WHERE schemaname = $1 AND tablename = $2 AND attname = ANY($3)",
                            schema, table, col_list,
                        )
                        for row in stats:
                            nd = float(row["n_distinct"])
                            if nd < 0:
                                rc = await conn.fetchval(
                                    "SELECT reltuples::bigint FROM pg_class WHERE relname = $1", table,
                                )
                                table_rows = int(rc or 0)
                                nd = abs(nd) * table_rows
                            cardinalities[row["attname"]] = max(1, int(nd))

                        if not table_rows:
                            rc = await conn.fetchval(
                                "SELECT reltuples::bigint FROM pg_class WHERE relname = $1", table,
                            )
                            table_rows = int(rc or 0)

                        return advisor.design(
                            table=table, columns=col_list, cardinalities=cardinalities,
                            order=order_dict, where_columns=where_cols,
                            range_columns=range_list, select_columns=select_cols,
                            schema=schema, table_rows=table_rows,
                        )
                    finally:
                        await conn.close()

                result = asyncio.run(_fetch_design())

            except ImportError:
                error_console.print("[yellow]asyncpg not available, using offline design[/yellow]")
                result = advisor.design(
                    table=table, columns=col_list, order=order_dict,
                    where_columns=where_cols, range_columns=range_list,
                    select_columns=select_cols, schema=schema,
                )
            except Exception as e:
                error_console.print(f"[yellow]Could not connect to DB: {e}[/yellow]")
                error_console.print("[dim]Falling back to offline design (no cardinality data)[/dim]")
                result = advisor.design(
                    table=table, columns=col_list, order=order_dict,
                    where_columns=where_cols, range_columns=range_list,
                    select_columns=select_cols, schema=schema,
                )
        else:
            result = advisor.design(
                table=table, columns=col_list, order=order_dict,
                where_columns=where_cols, range_columns=range_list,
                select_columns=select_cols, schema=schema,
            )

        if json_output:
            console.print_json(json.dumps(result.to_dict(), indent=2))
            return

        # Rich output
        console.print()
        console.print(Panel(
            "[bold]INDEX DESIGN ANALYSIS[/bold]",
            border_style="blue",
        ))
        console.print()

        # Column analysis table
        if result.column_analysis:
            col_table = Table(title="Column Analysis")
            col_table.add_column("#", justify="right", style="dim")
            col_table.add_column("Column", style="cyan bold")
            col_table.add_column("Details")

            for i, line in enumerate(result.column_analysis, 1):
                col_table.add_row(str(i), line.split("(")[0].strip(), "(" + line.split("(", 1)[1] if "(" in line else "")
            console.print(col_table)

        # Recommended order
        if result.recommended_columns:
            console.print()
            order_str = ", ".join(
                f"[cyan bold]{name}[/cyan bold] {d}" for name, d in result.recommended_columns
            )
            console.print(f"  Recommended Order: ({order_str})")

        # Why this order
        if result.ordering_rationale:
            console.print()
            console.print("[bold]Why this order:[/bold]")
            for line in result.ordering_rationale:
                console.print(f"  {line}")

        # Performance notes
        if result.performance_notes:
            console.print()
            console.print("[bold]Performance Impact:[/bold]")
            for line in result.performance_notes:
                console.print(f"  [green]{line}[/green]")

        # Sort elimination badge
        if result.sort_eliminated:
            console.print()
            console.print("  [green bold]Sort Elimination: YES[/green bold]")
            console.print(
                "  [dim]The index provides pre-sorted output — the Sort node disappears.[/dim]"
            )

        # Covering index badge
        if result.covers_query:
            console.print()
            console.print("  [green bold]Index-Only Scan: POSSIBLE[/green bold]")
            console.print(
                "  [dim]All selected columns covered — no heap fetches needed.[/dim]"
            )

        # Estimated speedup
        if result.estimated_speedup:
            console.print()
            console.print(f"  [bold]Estimated Improvement:[/bold] [green]{result.estimated_speedup}[/green]")

        # SQL
        console.print()
        console.print("[bold]Generated SQL:[/bold]")
        console.print(f"  [green]{result.sql}[/green]")
        console.print()

    @index_app.command(name="design-query")
    def design_query(
        sql: Annotated[
            str,
            typer.Argument(help="SQL query to design an index for"),
        ],
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN for live cardinality", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        schema: Annotated[
            str,
            typer.Option("--schema", help="Schema name"),
        ] = "public",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Design an optimal index by analyzing a SQL query.

        Parses the query to extract WHERE, ORDER BY, and SELECT columns,
        fetches cardinality from pg_stats, and recommends the optimal
        multi-column index with full educational explanation.

        \b
        Examples:
            $ querysense index design-query \\
                "SELECT id, name FROM events WHERE org_id = 1 ORDER BY ts DESC" \\
                --dsn postgresql://localhost/mydb

            $ querysense index design-query \\
                "SELECT * FROM orders WHERE status = 'pending' AND created_at > '2025-01-01'"
        """
        import asyncio
        from querysense.analysis.index_design import IndexDesignAdvisor

        advisor = IndexDesignAdvisor()

        async def _run() -> None:
            try:
                import asyncpg
                conn = await asyncpg.connect(dsn)
                try:
                    result = await advisor.design_from_query(conn, sql, schema)
                finally:
                    await conn.close()
            except ImportError:
                error_console.print("[yellow]asyncpg not available[/yellow]")
                raise typer.Exit(code=1)
            except Exception as e:
                error_console.print(f"[red]Connection error: {e}[/red]")
                raise typer.Exit(code=1)

            if json_output:
                console.print_json(json.dumps(result.to_dict(), indent=2))
            else:
                console.print(result.explanation)

        asyncio.run(_run())

    # ── querysense index suggest ─────────────────────────────────────

    @index_app.command()
    def suggest(
        sql: Annotated[
            str,
            typer.Option("--sql", "-s", help="SQL query to suggest indexes for"),
        ] = "",
        file: Annotated[
            Optional[Path],
            typer.Option("--file", "-f", help="File containing SQL query"),
        ] = None,
        show_partial: Annotated[
            bool,
            typer.Option("--partial", help="Highlight partial index opportunities"),
        ] = False,
        show_expression: Annotated[
            bool,
            typer.Option("--expression", help="Highlight expression index opportunities"),
        ] = False,
        show_covering: Annotated[
            bool,
            typer.Option("--covering", help="Highlight covering index (INCLUDE) opportunities"),
        ] = False,
        show_type: Annotated[
            bool,
            typer.Option("--type", help="Highlight index type selection rationale"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output only CREATE INDEX SQL"),
        ] = False,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Suggest optimal indexes for a SQL query.

        Analyzes operators, column types, WHERE constants, function calls,
        SELECT columns, and ORDER BY to produce a complete index recommendation
        including type (BTREE/GIN/GiST/BRIN), partial WHERE, expression,
        covering INCLUDE, and multi-column ordering.

        Based on Lukas Fittl's "Effective Indexing in Postgres" (pganalyze).

        \b
        Examples:
            # Basic: auto-detect everything
            querysense index suggest --sql "SELECT * FROM orders WHERE status = 'shipped'"

            # Show partial index opportunities
            querysense index suggest --sql "..." --partial

            # Show expression index for function calls
            querysense index suggest --sql "SELECT * FROM users WHERE lower(email) = 'x@y.com'" --expression

            # Covering index with INCLUDE
            querysense index suggest --sql "SELECT id, name FROM users WHERE status = 'active'" --covering

            # Output just SQL for piping to psql
            querysense index suggest --sql "..." --fix-script > create_index.sql
        """
        import sys
        import textwrap

        from querysense.index.suggest import UnifiedSuggestor

        query = sql
        if not query and file:
            if not file.exists():
                error_console.print(f"[red]Error:[/red] File not found: {file}")
                raise typer.Exit(code=1)
            query = file.read_text(encoding="utf-8").strip()
        if not query and not sys.stdin.isatty():
            query = sys.stdin.read().strip()
        if not query:
            error_console.print("[red]Error:[/red] Provide --sql, --file, or pipe SQL via stdin")
            raise typer.Exit(code=1)

        suggestor = UnifiedSuggestor()
        result = suggestor.suggest(query)

        if json_output:
            console.print_json(json.dumps(result.to_dict(), indent=2))
            return

        if fix_script:
            if result.primary_suggestion:
                console.print(result.primary_suggestion.create_sql)
            return

        if not result.primary_suggestion:
            console.print("[yellow]No index recommendations for this query.[/yellow]")
            if result.notes:
                for note in result.notes:
                    console.print(f"  [dim]{note}[/dim]")
            return

        ps = result.primary_suggestion
        show_all = not (show_partial or show_expression or show_covering or show_type)

        # Header
        console.print()
        console.print(Panel(
            f"[bold]INDEX RECOMMENDATION[/bold]\n"
            f"Table: {ps.table or '<unknown>'}\n"
            f"Summary: {ps.summary}\n"
            f"Estimated speedup: [bold green]{ps.estimated_speedup}[/bold green]",
            border_style="green",
        ))

        # CREATE INDEX
        console.print(f"\n[bold cyan]CREATE INDEX:[/bold cyan]")
        console.print(f"  [cyan]{ps.create_sql}[/cyan]")

        # Index type rationale
        if (show_all or show_type) and ps.type_suggestion:
            ts = ps.type_suggestion
            console.print(f"\n[bold]Index Type: {ts.index_type.value.upper()}[/bold]")
            for line in textwrap.wrap(ts.rationale, width=70):
                console.print(f"  {line}")
            if ts.alternative:
                console.print(f"  [dim]Alternative: {ts.alternative}[/dim]")
            if ts.textbook_ref:
                console.print(f"  [dim]Ref: {ts.textbook_ref}[/dim]")

        # Expression indexes
        if (show_all or show_expression) and ps.expression_suggestions:
            console.print(f"\n[bold yellow]Expression Index Detected:[/bold yellow]")
            for expr in ps.expression_suggestions:
                console.print(f"  Function: {expr.function_name}({expr.original_column})")
                for line in textwrap.wrap(expr.rationale, width=70):
                    console.print(f"  {line}")

        # Partial indexes
        if (show_all or show_partial) and ps.partial_suggestions:
            console.print(f"\n[bold yellow]Partial Index Opportunity:[/bold yellow]")
            for p in ps.partial_suggestions:
                console.print(f"  WHERE {p.where_clause}")
                console.print(f"  Selectivity: ~{p.estimated_selectivity:.0%} of rows match")
                console.print(f"  Size reduction: [green]{p.size_reduction_pct:.0f}%[/green] smaller index")
                for line in textwrap.wrap(p.rationale, width=70):
                    console.print(f"  {line}")

        # Covering index
        if (show_all or show_covering) and ps.covering_suggestion:
            cov = ps.covering_suggestion
            console.print(f"\n[bold yellow]Covering Index (INCLUDE):[/bold yellow]")
            console.print(f"  INCLUDE columns: {', '.join(cov.include_columns)}")
            if cov.enables_index_only_scan:
                console.print(f"  [green]Enables index-only scans (no heap access)[/green]")
            for line in textwrap.wrap(cov.rationale, width=70):
                console.print(f"  {line}")

        # Column ordering
        if show_all and ps.ordering_rationale:
            console.print(f"\n[bold]Column Order:[/bold]")
            for r in ps.ordering_rationale:
                console.print(f"  {r}")

        # Alternatives
        if result.alternatives:
            console.print(f"\n[bold dim]Alternatives:[/bold dim]")
            for i, alt in enumerate(result.alternatives, 1):
                console.print(f"\n  [dim]{i}. {alt.summary}[/dim]")
                console.print(f"     [dim]{alt.create_sql.strip()}[/dim]")
                if alt.notes:
                    console.print(f"     [dim]{alt.notes[0]}[/dim]")
                if alt.estimated_speedup:
                    console.print(f"     [dim]Speedup: {alt.estimated_speedup}[/dim]")

        console.print()
