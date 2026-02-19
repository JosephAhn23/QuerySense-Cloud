"""
CLI commands for advanced index features:
- Cross-database index comparison
- Deduplication analysis
- CP-SAT tradeoff analysis
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
    """Register advanced index commands on the index sub-app."""

    @parent.command(name="cross-db")
    def cross_db_compare(
        query: Annotated[str, typer.Argument(help="Query pattern to analyze")],
        source: Annotated[str, typer.Option("--source", "-s", help="Source database engine")] = "postgresql",
        target: Annotated[str, typer.Option("--target", "-t", help="Target database engine")] = "sql_server",
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Compare index behavior across PostgreSQL, SQL Server, MySQL, Oracle.

        Example:
            querysense index cross-db "SELECT * FROM orders WHERE status = 'pending'" -s postgresql -t sql_server
        """
        from querysense.index.cross_db_comparison import (
            CrossDBIndexAdvisor,
            DatabaseEngine,
        )

        engine_map = {
            "postgresql": DatabaseEngine.POSTGRESQL,
            "pg": DatabaseEngine.POSTGRESQL,
            "sql_server": DatabaseEngine.SQL_SERVER,
            "sqlserver": DatabaseEngine.SQL_SERVER,
            "mssql": DatabaseEngine.SQL_SERVER,
            "mysql": DatabaseEngine.MYSQL,
            "oracle": DatabaseEngine.ORACLE,
        }

        src = engine_map.get(source.lower())
        tgt = engine_map.get(target.lower())

        if not src or not tgt:
            console.print(f"[red]Unknown engine. Valid: {', '.join(engine_map)}[/red]")
            raise typer.Exit(1)

        advisor = CrossDBIndexAdvisor()
        rec = advisor.get_index_recommendation(query, src, tgt)

        if output_json:
            console.print_json(json.dumps({
                "source": rec.source_database,
                "target": rec.target_database,
                "pattern": rec.query_pattern,
                "source_type": rec.source_index_type,
                "target_type": rec.target_index_type,
                "size_delta": rec.size_delta_multiplier,
                "notes": rec.migration_notes,
            }))
            return

        console.print(Panel(
            f"[bold]Query pattern:[/bold] {rec.query_pattern}\n"
            f"[bold]Source:[/bold] {rec.source_database} -> {rec.source_index_type}\n"
            f"[bold]Target:[/bold] {rec.target_database} -> {rec.target_index_type}\n"
            f"[bold]Storage delta:[/bold] {rec.size_delta_multiplier}x",
            title="Cross-Database Index Migration",
        ))

        console.print(f"\n[bold]Source syntax:[/bold]\n  {rec.source_syntax}")
        console.print(f"[bold]Target syntax:[/bold]\n  {rec.target_syntax}")

        if rec.migration_notes:
            console.print("\n[bold yellow]Migration notes:[/bold yellow]")
            for note in rec.migration_notes:
                console.print(f"  {note}")

    @parent.command(name="compare-engines")
    def compare_engines(
        engine_a: Annotated[str, typer.Option("--a", help="First engine")] = "postgresql",
        engine_b: Annotated[str, typer.Option("--b", help="Second engine")] = "sql_server",
    ) -> None:
        """Compare full index capability matrix between two engines.

        Example:
            querysense index compare-engines --a postgresql --b sql_server
        """
        from querysense.index.cross_db_comparison import (
            CrossDBIndexAdvisor,
            DatabaseEngine,
        )

        engine_map = {
            "postgresql": DatabaseEngine.POSTGRESQL,
            "pg": DatabaseEngine.POSTGRESQL,
            "sql_server": DatabaseEngine.SQL_SERVER,
            "sqlserver": DatabaseEngine.SQL_SERVER,
            "mysql": DatabaseEngine.MYSQL,
            "oracle": DatabaseEngine.ORACLE,
        }

        a = engine_map.get(engine_a.lower())
        b = engine_map.get(engine_b.lower())
        if not a or not b:
            console.print("[red]Unknown engine.[/red]")
            raise typer.Exit(1)

        advisor = CrossDBIndexAdvisor()
        rows = advisor.compare_engines(a, b)

        table = Table(title=f"Index Capabilities: {a.value} vs {b.value}")
        table.add_column("Index Type", style="bold")
        table.add_column(a.value, justify="center")
        table.add_column(b.value, justify="center")
        table.add_column("Dedup A", justify="center")
        table.add_column("Dedup B", justify="center")

        for row in rows:
            cap_a = row.get(a.value, {})
            cap_b = row.get(b.value, {})
            sup_a = "[green]Yes[/green]" if cap_a.get("supported") else "[red]No[/red]"
            sup_b = "[green]Yes[/green]" if cap_b.get("supported") else "[red]No[/red]"
            ded_a = "[green]Yes[/green]" if cap_a.get("dedup") else "-"
            ded_b = "[green]Yes[/green]" if cap_b.get("dedup") else "-"
            table.add_row(row["index_type"], sup_a, sup_b, ded_a, ded_b)

        console.print(table)

    @parent.command(name="dedup")
    def dedup_analysis(
        dsn: Annotated[str, typer.Option("--dsn", envvar="DATABASE_URL", help="PostgreSQL DSN")],
        table: Annotated[str, typer.Option("--table", "-t", help="Table to analyze")] = "",
        schema: Annotated[str, typer.Option("--schema", help="Schema")] = "public",
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Analyze deduplication savings for indexes (PG13+).

        Example:
            querysense index dedup --dsn postgresql://localhost/mydb --table orders
        """
        from querysense.index.deduplication_advisor import DeduplicationAdvisor

        advisor = DeduplicationAdvisor()
        report = asyncio.get_event_loop().run_until_complete(
            advisor.analyze(dsn, schema, table or None)
        )

        if output_json:
            console.print_json(json.dumps(report.to_dict()))
            return

        if not report.dedup_available:
            console.print("[yellow]Deduplication requires PostgreSQL 13+[/yellow]")

        console.print(Panel(
            f"[bold]Potential savings:[/bold] {report.total_potential_savings_mb:.1f} MB",
            title=f"Deduplication Analysis — {report.table or 'All Tables'}",
        ))

        if report.existing_index_savings:
            tbl = Table(title="Existing Indexes with Dedup Benefit")
            tbl.add_column("Columns", style="bold")
            tbl.add_column("Size w/ Dedup", justify="right")
            tbl.add_column("Size w/o Dedup", justify="right")
            tbl.add_column("Savings", justify="right")
            tbl.add_column("Benefit")

            for s in report.existing_index_savings:
                color = {"critical": "red", "high": "yellow", "moderate": "cyan"}.get(s.benefit_level, "white")
                tbl.add_row(
                    ", ".join(s.columns),
                    f"{s.size_with_dedup_mb:.1f} MB",
                    f"{s.size_without_dedup_mb:.1f} MB",
                    f"{s.savings_percent:.0f}%",
                    f"[{color}]{s.benefit_level}[/{color}]",
                )
            console.print(tbl)

    @parent.command(name="tradeoffs")
    def tradeoff_analysis(
        dsn: Annotated[str, typer.Option("--dsn", envvar="DATABASE_URL", help="PostgreSQL DSN")],
        table: Annotated[str, typer.Option("--table", "-t", help="Table to analyze")] = "",
        max_indexes: Annotated[int, typer.Option("--max", help="Max index limit to test")] = 8,
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Analyze cost vs. index count tradeoffs using CP-SAT.

        Generates a Pareto curve showing diminishing returns from adding indexes.

        Example:
            querysense index tradeoffs --dsn postgresql://localhost/mydb --table orders
        """
        from querysense.index.tradeoff_analyzer import TradeoffAnalyzer

        analyzer = TradeoffAnalyzer()
        result = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze_tradeoffs(dsn, table=table or None, max_index_limit=max_indexes)
        )

        if output_json:
            console.print_json(json.dumps(result.to_dict()))
            return

        console.print(Panel(
            f"[bold]Base cost (no indexes):[/bold] {result.base_cost:.0f}\n"
            f"[bold]Recommendation:[/bold] {result.recommendation}",
            title=f"Index Tradeoff Analysis — {result.table}",
        ))

        if result.points:
            tbl = Table(title="Cost vs. Index Count")
            tbl.add_column("Indexes", justify="right")
            tbl.add_column("Total Cost", justify="right")
            tbl.add_column("Reduction", justify="right")
            tbl.add_column("Size (MB)", justify="right")
            tbl.add_column("", justify="center")

            for p in result.points:
                is_knee = result.knee_point and p.selected_count == result.knee_point.selected_count
                marker = "[bold green]<-- optimal[/bold green]" if is_knee else ""
                tbl.add_row(
                    str(p.selected_count),
                    f"{p.total_cost:.0f}",
                    f"{p.cost_reduction_pct:.1f}%",
                    f"{p.total_size_mb:.1f}",
                    marker,
                )

            console.print(tbl)

        if result.sensitivity:
            console.print("\n[bold]Sensitivity Analysis:[/bold]")
            for s in result.sensitivity:
                console.print(
                    f"  {s['from_indexes']} -> {s['to_indexes']} indexes: "
                    f"+{s['additional_reduction_pct']:.1f}% reduction "
                    f"({s['marginal_improvement_per_index']:.1f}%/index)"
                )
