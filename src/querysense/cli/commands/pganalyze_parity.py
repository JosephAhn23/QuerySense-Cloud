"""
CLI commands for pganalyze-parity features.

    querysense audit hot       — HOT update detection
    querysense audit iwo       — Index Write Overhead analysis
    querysense audit deps      — Functional dependency detection
    querysense audit vacuum-full — Complete 4-category VACUUM advisor
    querysense index advise    — Full CP-SAT index advisor pipeline
    querysense scan-workload   — Extract scan patterns from live workload
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


def register_audit_extras(parent: typer.Typer) -> None:
    """Register additional audit commands on the audit sub-app."""

    @parent.command(name="hot")
    def audit_hot(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
        schema: Annotated[str, typer.Option("--schema")] = "public",
        min_updates: Annotated[int, typer.Option("--min-updates")] = 1000,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
        fix_script: Annotated[bool, typer.Option("--fix-script", help="Output fix SQL")] = False,
    ) -> None:
        """Detect indexes blocking HOT (Heap-Only Tuple) updates."""
        from querysense.hot_update_detector import HOTDetector

        detector = HOTDetector()
        analysis = asyncio.run(detector.analyze(dsn, schema=schema, min_updates=min_updates))

        if json_output:
            import dataclasses
            console.print_json(json.dumps(dataclasses.asdict(analysis), default=str))
            return

        if fix_script:
            console.print(analysis.fix_script)
            return

        console.print(Panel.fit(
            f"[bold]HOT Update Analysis[/bold]\n"
            f"Tables analyzed: {analysis.tables_analyzed}\n"
            f"Tables with low HOT ratio: {analysis.tables_with_low_hot}\n"
            f"Tables with improvement potential: {analysis.potential_improvement_tables}",
            border_style="cyan",
        ))

        if not analysis.findings:
            console.print("[green]All tables have healthy HOT update ratios.[/green]")
            return

        table = Table(title="HOT Update Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Table")
        table.add_column("Index")
        table.add_column("HOT Ratio")
        table.add_column("Updated Columns")
        table.add_column("Description")

        for f in analysis.findings:
            sev_style = {"critical": "red", "warning": "yellow", "info": "cyan"}.get(f.severity, "white")
            table.add_row(
                f"[{sev_style}]{f.severity.upper()}[/{sev_style}]",
                f.table,
                f.index_name or "-",
                f"{f.hot_update_ratio:.0%}" if f.hot_update_ratio else "-",
                ", ".join(f.updated_columns) if f.updated_columns else "-",
                f.description[:80],
            )

        console.print(table)

    @parent.command(name="iwo")
    def audit_iwo(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
        table_name: Annotated[str, typer.Option("--table", help="Specific table (all if omitted)")] = "",
        schema: Annotated[str, typer.Option("--schema")] = "public",
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
        fix_script: Annotated[bool, typer.Option("--fix-script", help="Output fix SQL")] = False,
    ) -> None:
        """Calculate Index Write Overhead (IWO) for all indexes."""
        from querysense.iwo_calculator import IWOCalculator

        calculator = IWOCalculator()
        report = asyncio.run(
            calculator.calculate(dsn, table=table_name or None, schema=schema)
        )

        if json_output:
            import dataclasses
            console.print_json(json.dumps(dataclasses.asdict(report), default=str))
            return

        if fix_script:
            console.print(report.fix_script)
            return

        console.print(Panel.fit(
            f"[bold]Index Write Overhead Report[/bold]\n"
            f"Tables analyzed: {report.total_tables}\n"
            f"Tables with high IWO: {report.tables_with_high_iwo}",
            border_style="cyan",
        ))

        for tbl in report.tables:
            if not tbl.indexes:
                continue

            tbl_table = Table(title=f"{tbl.schema}.{tbl.table} (Total IWO: {tbl.total_iwo:.2f})")
            tbl_table.add_column("Index")
            tbl_table.add_column("Columns")
            tbl_table.add_column("IWO Score", justify="right")
            tbl_table.add_column("Write:Read", justify="right")
            tbl_table.add_column("Size")
            tbl_table.add_column("Scans", justify="right")

            for idx in sorted(tbl.indexes, key=lambda i: i.iwo_score, reverse=True):
                wr = idx.write_to_read_ratio
                wr_style = "red" if wr > 5 else "yellow" if wr > 2 else "green"
                tbl_table.add_row(
                    idx.index_name,
                    ", ".join(idx.columns[:3]),
                    f"{idx.iwo_score:.2f}",
                    f"[{wr_style}]{wr:.1f}[/{wr_style}]",
                    f"{idx.size_bytes // 1024}KB",
                    str(idx.scan_count),
                )

            console.print(tbl_table)
            console.print()

    @parent.command(name="deps")
    def audit_deps(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
        schema: Annotated[str, typer.Option("--schema")] = "public",
        min_rows: Annotated[int, typer.Option("--min-rows")] = 10000,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
        fix_script: Annotated[bool, typer.Option("--fix-script", help="Output CREATE STATISTICS SQL")] = False,
    ) -> None:
        """Detect functional dependencies and recommend extended statistics."""
        from querysense.functional_deps import FunctionalDepDetector

        detector = FunctionalDepDetector()
        analysis = asyncio.run(detector.analyze(dsn, schema=schema, min_rows=min_rows))

        if json_output:
            import dataclasses
            console.print_json(json.dumps(dataclasses.asdict(analysis), default=str))
            return

        if fix_script:
            console.print(analysis.fix_script)
            return

        console.print(Panel.fit(
            f"[bold]Functional Dependency Analysis[/bold]\n"
            f"Tables analyzed: {analysis.tables_analyzed}\n"
            f"Dependencies found: {len(analysis.dependencies)}\n"
            f"Existing extended stats: {len(analysis.existing_stats)}\n"
            f"Recommendations: {len(analysis.recommendations)}",
            border_style="cyan",
        ))

        if analysis.dependencies:
            dep_table = Table(title="Functional Dependencies")
            dep_table.add_column("Table")
            dep_table.add_column("Source → Dependent")
            dep_table.add_column("Degree", justify="right")
            dep_table.add_column("Distinct Values")

            for dep in analysis.dependencies[:20]:
                dep_table.add_row(
                    dep.table,
                    f"{dep.source_column} → {dep.dependent_column}",
                    f"{dep.dependency_degree:.0%}",
                    f"{dep.distinct_source:,} → {dep.distinct_dependent:,}",
                )
            console.print(dep_table)

        if analysis.recommendations:
            rec_table = Table(title="Recommendations")
            rec_table.add_column("Priority", justify="center")
            rec_table.add_column("Table")
            rec_table.add_column("Stat Type")
            rec_table.add_column("Columns")
            rec_table.add_column("Reason")

            for rec in analysis.recommendations:
                rec_table.add_row(
                    f"P{rec.priority}",
                    rec.table,
                    rec.stat_type,
                    ", ".join(rec.columns),
                    rec.reason[:60],
                )
            console.print(rec_table)

    @parent.command(name="vacuum-full")
    def audit_vacuum_full(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
        schema: Annotated[str, typer.Option("--schema")] = "public",
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
        fix_script: Annotated[bool, typer.Option("--fix-script", help="Output fix SQL")] = False,
    ) -> None:
        """Complete 4-category VACUUM advisor (Bloat + Freezing + Performance + Activity)."""
        from querysense.vacuum_advisor import VacuumAdvisor

        advisor = VacuumAdvisor()
        report = asyncio.run(advisor.full_report(dsn, schema=schema))

        if json_output:
            import dataclasses
            console.print_json(json.dumps(dataclasses.asdict(report), default=str))
            return

        if fix_script:
            console.print(report.fix_script)
            return

        console.print(Panel.fit(
            f"[bold]VACUUM Advisor Report[/bold]\n"
            f"Autovacuum workers: {report.autovacuum_workers_running}/{report.autovacuum_max_workers}\n"
            f"Total dead tuples: {report.total_dead_tuples:,}\n"
            f"Total bloat: {report.total_bloat_mb:.0f}MB\n"
            f"Tables at freeze risk: {report.tables_at_freeze_risk}",
            border_style="cyan",
        ))

        # Group recommendations by category
        categories = {"bloat": [], "freezing": [], "performance": [], "activity": []}
        for rec in report.recommendations:
            categories.get(rec.category, []).append(rec)

        for cat, recs in categories.items():
            if not recs:
                continue

            cat_table = Table(title=f"Category: {cat.upper()}")
            cat_table.add_column("Severity", style="bold")
            cat_table.add_column("Title")
            cat_table.add_column("Impact")

            for rec in recs:
                sev_style = {"critical": "red", "warning": "yellow", "info": "cyan"}.get(rec.severity, "white")
                cat_table.add_row(
                    f"[{sev_style}]{rec.severity.upper()}[/{sev_style}]",
                    rec.title,
                    rec.impact or rec.description[:60],
                )

            console.print(cat_table)
            console.print()


def register_index_advise(parent: typer.Typer) -> None:
    """Register the full index advisor pipeline command."""

    @parent.command(name="advise")
    def index_advise(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
        schema: Annotated[str, typer.Option("--schema")] = "public",
        tables: Annotated[str, typer.Option("--tables", help="Comma-separated tables (auto if empty)")] = "",
        max_indexes: Annotated[int, typer.Option("--max-indexes-per-table")] = 8,
        max_iwo: Annotated[float, typer.Option("--max-iwo", help="Max IWO budget")] = 50.0,
        top_queries: Annotated[int, typer.Option("--top-queries")] = 100,
        no_hypopg: Annotated[bool, typer.Option("--no-hypopg", help="Skip HypoPG verification")] = False,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
        fix_script: Annotated[bool, typer.Option("--fix-script", help="Output fix SQL")] = False,
    ) -> None:
        """CP-SAT optimized index advisor (pganalyze-grade, globally optimal)."""
        from querysense.index.advisor_pipeline import IndexAdvisorPipeline

        table_list = [t.strip() for t in tables.split(",") if t.strip()] if tables else None

        pipeline = IndexAdvisorPipeline(
            max_indexes_per_table=max_indexes,
            max_iwo=max_iwo,
            use_hypopg=not no_hypopg,
            top_queries=top_queries,
        )
        result = asyncio.run(pipeline.advise(dsn, schema=schema, tables=table_list))

        if json_output:
            console.print_json(json.dumps(result.to_dict(), default=str))
            return

        if fix_script:
            console.print(result.fix_script)
            return

        console.print(Panel.fit(
            f"[bold]CP-SAT Index Advisor Results[/bold]\n"
            f"Tables analyzed: {result.tables_analyzed}\n"
            f"Scans extracted: {result.scans_extracted}\n"
            f"Candidates generated: {result.candidates_generated}\n"
            f"Candidates after IWO filter: {result.candidates_after_iwo}\n"
            f"Recommended indexes: {len(result.recommended_indexes)}\n"
            f"Indexes to drop: {len(result.dropped_indexes)}\n"
            f"Total cost reduction: {result.total_cost_reduction_pct:.1f}%\n"
            f"Total IWO: {result.total_iwo:.2f}\n"
            f"Pipeline time: {result.total_time_ms:.0f}ms",
            border_style="green",
        ))

        if result.dropped_indexes:
            console.print("\n[bold red]Indexes to DROP (redundant/unused):[/bold red]")
            for idx_name in result.dropped_indexes:
                console.print(f"  DROP INDEX CONCURRENTLY IF EXISTS {idx_name};")

        if result.recommended_indexes:
            idx_table = Table(title="Recommended Indexes")
            idx_table.add_column("Table")
            idx_table.add_column("Columns")
            idx_table.add_column("Scans Covered", justify="right")
            idx_table.add_column("Frequency", justify="right")
            idx_table.add_column("Improvement", justify="right")
            idx_table.add_column("IWO", justify="right")
            idx_table.add_column("HypoPG", justify="center")

            for idx in result.recommended_indexes:
                idx_table.add_row(
                    idx.table,
                    ", ".join(idx.columns),
                    str(idx.scans_covered),
                    f"{idx.total_frequency:,}",
                    f"{idx.improvement_ratio:.0%}",
                    f"{idx.iwo_score:.2f}",
                    "[green]✓[/green]" if idx.hypopg_verified else "[dim]—[/dim]",
                )

            console.print(idx_table)
            console.print()
            console.print("[bold]CREATE INDEX statements:[/bold]")
            for idx in result.recommended_indexes:
                console.print(f"  {idx.create_sql}")
        else:
            console.print("[green]No additional indexes recommended.[/green]")


def register_scan_workload(parent: typer.Typer) -> None:
    """Register the scan workload extraction command."""

    @parent.command(name="scan-workload")
    def scan_workload(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
        top_n: Annotated[int, typer.Option("--top")] = 100,
        min_calls: Annotated[int, typer.Option("--min-calls")] = 5,
        json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """Extract scan patterns from the live database workload."""
        from querysense.scan_extractor import ScanExtractor

        extractor = ScanExtractor()
        workload = asyncio.run(extractor.extract_from_database(dsn, top_n=top_n, min_calls=min_calls))

        if json_output:
            data = {
                "total_queries": workload.total_queries,
                "total_scans": len(workload.scans),
                "tables": list(workload.tables),
                "scans": [
                    {
                        "scan_id": s.scan_id,
                        "table": s.table,
                        "scan_type": s.scan_type,
                        "filter_columns": [c.column for c in s.filter_columns],
                        "join_columns": [c.column for c in s.join_columns],
                        "order_columns": [c.column for c in s.order_columns],
                        "sequential_cost": s.sequential_cost,
                        "frequency": s.frequency,
                        "is_sequential": s.is_sequential,
                    }
                    for s in workload.scans
                ],
            }
            console.print_json(json.dumps(data, default=str))
            return

        console.print(Panel.fit(
            f"[bold]Workload Scan Extraction[/bold]\n"
            f"Total queries: {workload.total_queries}\n"
            f"Scans extracted: {len(workload.scans)}\n"
            f"Tables: {len(workload.tables)}\n"
            f"Hot tables: {', '.join(workload.hot_tables[:5]) or 'none'}",
            border_style="cyan",
        ))

        scan_table = Table(title="Extracted Scans")
        scan_table.add_column("Table")
        scan_table.add_column("Scan Type")
        scan_table.add_column("Filter Columns")
        scan_table.add_column("Frequency", justify="right")
        scan_table.add_column("Cost", justify="right")

        for s in sorted(workload.scans, key=lambda x: x.frequency, reverse=True)[:30]:
            filters = ", ".join(c.column for c in s.filter_columns) or "-"
            stype_style = "red" if s.is_sequential else "green"
            scan_table.add_row(
                s.table,
                f"[{stype_style}]{s.scan_type}[/{stype_style}]",
                filters[:40],
                f"{s.frequency:,}",
                f"{s.sequential_cost:.0f}",
            )

        console.print(scan_table)
