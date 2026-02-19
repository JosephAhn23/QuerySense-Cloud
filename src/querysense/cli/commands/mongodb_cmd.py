"""
MongoDB CLI commands — the first open-source MongoDB query optimizer.

Commands:
    querysense mongodb analyze --uri mongodb://...
    querysense mongodb indexes --uri mongodb://...
    querysense mongodb schema --uri mongodb://...
    querysense mongodb explain <json-file>
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
    """Register MongoDB commands."""

    @parent.command(name="analyze")
    def mongodb_analyze(
        uri: Annotated[str, typer.Option("--uri", help="MongoDB connection URI")] = "mongodb://localhost:27017",
        database: Annotated[str, typer.Option("--database", "-d", help="Database name")] = "",
        min_slow_ms: Annotated[int, typer.Option("--min-slow-ms", help="Minimum slow query threshold (ms)")] = 100,
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Full MongoDB analysis: indexes, schema, slow queries."""
        from querysense.mongodb import MongoDBAnalyzer

        analyzer = MongoDBAnalyzer(uri=uri, database=database)
        report = asyncio.run(analyzer.full_analysis(min_slow_ms=min_slow_ms))

        if output_json:
            console.print_json(json.dumps(report.to_dict(), default=str))
            return

        console.print(Panel(
            f"[bold]Database:[/] {report.database}\n"
            f"[bold]Collections:[/] {report.collections_analyzed}\n"
            f"[bold]Analysis time:[/] {report.total_time_ms:.0f}ms",
            title="MongoDB Analysis Report",
        ))

        # Index recommendations
        if report.index_recommendations:
            table = Table(title="Index Recommendations")
            table.add_column("Collection", style="cyan")
            table.add_column("Key Pattern", style="green")
            table.add_column("Reason", style="yellow")
            table.add_column("Command", style="white")

            for rec in report.index_recommendations:
                keys = json.dumps(rec.key_pattern) if rec.key_pattern else "-"
                table.add_row(rec.collection, keys, rec.reason[:80], rec.command)

            console.print(table)

        # Unused indexes
        unused = report.unused_indexes
        if unused:
            table = Table(title="Unused Indexes")
            table.add_column("Collection", style="cyan")
            table.add_column("Index", style="red")
            table.add_column("Drop Command", style="white")

            for audit in unused:
                table.add_row(audit.collection, audit.index_name, audit.drop_command)

            console.print(table)

        # Redundant indexes
        redundant = report.redundant_indexes
        if redundant:
            table = Table(title="Redundant Indexes")
            table.add_column("Collection", style="cyan")
            table.add_column("Index", style="red")
            table.add_column("Redundant With", style="green")

            for audit in redundant:
                table.add_row(audit.collection, audit.index_name, audit.redundant_with)

            console.print(table)

        # Schema findings
        if report.schema_findings:
            table = Table(title="Schema Findings")
            table.add_column("Collection", style="cyan")
            table.add_column("Severity", style="yellow")
            table.add_column("Title", style="white")
            table.add_column("Remediation", style="green")

            for finding in report.schema_findings:
                table.add_row(
                    finding.collection, finding.severity,
                    finding.title, finding.remediation[:60],
                )

            console.print(table)

        # Slow queries
        if report.slow_queries:
            console.print(f"\n[bold yellow]{len(report.slow_queries)} slow queries found[/]")
            for sq in report.slow_queries[:10]:
                console.print(
                    f"  [{sq.get('millis', 0)}ms] {sq.get('ns', '')} — "
                    f"docs: {sq.get('docsExamined', 0)}, "
                    f"plan: {sq.get('planSummary', 'N/A')}"
                )

        if not any([
            report.index_recommendations, unused, redundant,
            report.schema_findings, report.slow_queries,
        ]):
            console.print("[green]No issues found — database looks healthy.[/]")

    @parent.command(name="indexes")
    def mongodb_indexes(
        uri: Annotated[str, typer.Option("--uri", help="MongoDB connection URI")] = "mongodb://localhost:27017",
        database: Annotated[str, typer.Option("--database", "-d", help="Database name")] = "",
        output_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    ) -> None:
        """Audit MongoDB indexes: find unused, redundant, and missing."""
        from querysense.mongodb import MongoDBAnalyzer

        analyzer = MongoDBAnalyzer(uri=uri, database=database)
        report = asyncio.run(analyzer.full_analysis())

        if output_json:
            data = {
                "recommendations": [
                    {"collection": r.collection, "key": r.key_pattern,
                     "reason": r.reason, "command": r.command}
                    for r in report.index_recommendations
                ],
                "unused": [
                    {"collection": a.collection, "index": a.index_name,
                     "drop": a.drop_command}
                    for a in report.unused_indexes
                ],
                "redundant": [
                    {"collection": a.collection, "index": a.index_name,
                     "with": a.redundant_with}
                    for a in report.redundant_indexes
                ],
            }
            console.print_json(json.dumps(data))
            return

        console.print(Panel(
            f"[bold]Recommendations:[/] {len(report.index_recommendations)}\n"
            f"[bold]Unused:[/] {len(report.unused_indexes)}\n"
            f"[bold]Redundant:[/] {len(report.redundant_indexes)}",
            title="MongoDB Index Audit",
        ))

        for rec in report.index_recommendations:
            console.print(f"  [yellow]CREATE:[/] {rec.command}")
            console.print(f"         Reason: {rec.reason}")

        for audit in report.unused_indexes:
            console.print(f"  [red]DROP:[/] {audit.drop_command}")

    @parent.command(name="schema")
    def mongodb_schema(
        uri: Annotated[str, typer.Option("--uri", help="MongoDB connection URI")] = "mongodb://localhost:27017",
        database: Annotated[str, typer.Option("--database", "-d", help="Database name")] = "",
    ) -> None:
        """Analyze MongoDB schema for anti-patterns."""
        from querysense.mongodb import MongoDBAnalyzer

        analyzer = MongoDBAnalyzer(uri=uri, database=database)
        report = asyncio.run(analyzer.full_analysis())

        if not report.schema_findings:
            console.print("[green]No schema anti-patterns detected.[/]")
            return

        for finding in report.schema_findings:
            severity_color = {
                "critical": "red",
                "warning": "yellow",
                "notice": "blue",
                "info": "white",
            }.get(finding.severity, "white")

            console.print(Panel(
                f"[bold]{finding.title}[/]\n\n"
                f"{finding.description}\n\n"
                f"[green]Fix:[/] {finding.remediation}",
                title=f"[{severity_color}]{finding.severity.upper()}[/] — {finding.collection}",
            ))

    @parent.command(name="explain")
    def mongodb_explain(
        file: Annotated[Path, typer.Argument(help="MongoDB explain() JSON file")],
    ) -> None:
        """Parse and analyze a MongoDB explain() output."""
        from querysense.mongodb import MongoExplainParser

        data = json.loads(file.read_text())
        parser = MongoExplainParser()
        result = parser.parse(data)

        console.print(Panel(
            f"[bold]Namespace:[/] {result.namespace}\n"
            f"[bold]Returned:[/] {result.n_returned:,}\n"
            f"[bold]Docs examined:[/] {result.total_docs_examined:,}\n"
            f"[bold]Keys examined:[/] {result.total_keys_examined:,}\n"
            f"[bold]Execution time:[/] {result.execution_time_ms}ms\n"
            f"[bold]Collection scan:[/] {'YES' if result.is_collection_scan else 'No'}\n"
            f"[bold]Covered query:[/] {'YES' if result.is_covered_query else 'No'}\n"
            f"[bold]In-memory sort:[/] {'YES' if result.sort_in_memory else 'No'}\n"
            f"[bold]Used index:[/] {result.used_index or 'None'}\n"
            f"[bold]Efficiency:[/] {result.efficiency_ratio:.1f}x "
            f"(1.0 = perfect)",
            title="MongoDB Explain Analysis",
        ))

        if result.is_collection_scan:
            console.print("[red]COLLECTION SCAN detected — add an index![/]")
        if result.sort_in_memory:
            console.print("[yellow]In-memory sort — consider indexing sort columns.[/]")
        if result.efficiency_ratio > 10:
            console.print(
                f"[yellow]Examining {result.efficiency_ratio:.0f}x more docs "
                f"than returned — index may need tuning.[/]"
            )
