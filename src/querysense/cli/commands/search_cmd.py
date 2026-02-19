"""
CLI commands for the Search Optimization Advisor.

Automates the decision matrix from pganalyze "Efficient Search in Rails
with PostgreSQL" (2024). Given any search query, recommends optimal index
type, extension, rewrite, and expected speedup.

Commands:
    querysense search classify    -- Classify search type and recommend index
    querysense search index       -- Generate optimal index CREATE statements
    querysense search audit       -- Scan workload for unindexed search patterns
    querysense search optimize    -- Rewrite search queries for performance
    querysense search monitor     -- Track search query performance over time
    querysense search extensions  -- Check required extensions (pg_trgm, etc.)
    querysense search benchmark   -- Generate realistic search test data
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()
error_console = Console(stderr=True)

search_app = typer.Typer(
    name="search",
    help="Search query optimization — classify, index, audit, optimize, monitor",
    no_args_is_help=True,
)


# ── classify ─────────────────────────────────────────────────────────────


@search_app.command()
def classify(
    sql: Annotated[
        str,
        typer.Option("--sql", "-s", help="SQL query to classify"),
    ] = "",
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="File containing SQL query"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Classify a search query and recommend the optimal index type.

    Implements the decision matrix from pganalyze "Efficient Search
    in Rails with PostgreSQL" (p.3): exact, prefix, wildcard, trigram,
    full-text, regex, JSONB, and array search patterns.

    \b
    Examples:
        querysense search classify --sql "SELECT * FROM users WHERE name LIKE '%john%'"
        querysense search classify --file slow_query.sql
        echo "SELECT * FROM t WHERE col ILIKE '%val%'" | querysense search classify
    """
    from querysense.search_advisor import SearchClassifier

    query = _resolve_sql(sql, file)
    if not query:
        error_console.print("[red]Error:[/red] Provide --sql, --file, or pipe SQL via stdin")
        raise typer.Exit(code=1)

    classifier = SearchClassifier()
    result = classifier.classify(query)

    if json_output:
        console.print_json(json.dumps(result.to_dict(), indent=2))
        return

    console.print()

    if not result.patterns:
        console.print("[yellow]No search patterns detected in this query.[/yellow]")
        console.print("[dim]Tip: This command detects LIKE, ILIKE, FTS, trigram, regex, JSONB, and array patterns.[/dim]")
        return

    # Header
    console.print(Panel(
        f"[bold]SEARCH QUERY CLASSIFICATION[/bold]\n"
        f"Query type: {result.search_type_label}\n"
        f"Indexable: {'Yes' if result.is_indexable else 'No'}",
        border_style="blue",
    ))

    # Patterns detected
    for i, p in enumerate(result.patterns, 1):
        table_col = f"{p.table}.{p.column}" if p.table else p.column

        console.print(f"\n[bold cyan]Pattern {i}:[/bold cyan] {p.search_type.value}")
        console.print(f"  Column: {table_col}")
        if p.pattern_value:
            console.print(f"  Pattern: {p.pattern_value}")
        if p.is_case_insensitive:
            console.print("  Case: [yellow]insensitive[/yellow]")
        if p.has_leading_wildcard:
            console.print("  Leading wildcard: [red]Yes[/red] (BTREE cannot help)")
        if p.original_fragment:
            console.print(f"  Fragment: [dim]{p.original_fragment.strip()}[/dim]")

    # Recommendations
    for i, rec in enumerate(result.recommendations, 1):
        sev_color = {
            "critical": "red",
            "warning": "yellow",
            "info": "cyan",
            "ok": "green",
        }.get(rec.severity.value, "white")

        console.print(f"\n[bold {sev_color}]Recommendation {i}: {rec.index_type.value}[/bold {sev_color}]")
        console.print(f"  Estimated speedup: [bold green]{rec.estimated_speedup}[/bold green]")
        console.print()
        console.print(f"  [bold]Index:[/bold]")
        console.print(f"  [cyan]{rec.create_sql}[/cyan]")

        if rec.prerequisite_sql:
            console.print(f"\n  [bold]Prerequisite:[/bold]")
            console.print(f"  [yellow]{rec.prerequisite_sql}[/yellow]")

        console.print(f"\n  [bold]Why:[/bold]")
        for line in textwrap.wrap(rec.explanation, width=70):
            console.print(f"  {line}")

        if rec.textbook_ref:
            console.print(f"\n  [dim]Reference: {rec.textbook_ref}[/dim]")

        if rec.alternative_approaches:
            console.print(f"\n  [bold]Alternatives:[/bold]")
            for j, alt in enumerate(rec.alternative_approaches, 1):
                console.print(f"  {j}. {alt}")

    console.print()


# ── index ────────────────────────────────────────────────────────────────


@search_app.command("index")
def search_index(
    sql: Annotated[
        str,
        typer.Option("--sql", "-s", help="SQL query to generate index for"),
    ] = "",
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="File containing SQL query"),
    ] = None,
    index_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Force index type: exact, trigram, fts, prefix, lower"),
    ] = "",
    fix_script: Annotated[
        bool,
        typer.Option("--fix-script", help="Output only SQL (for piping to file)"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Generate optimal search indexes for a query.

    Auto-detects the search pattern and recommends the best index type.
    Use --type to override (exact, trigram, fts, prefix, lower).

    \b
    Examples:
        querysense search index --sql "SELECT * FROM t WHERE name LIKE '%val%'"
        querysense search index --sql "..." --type=trigram
        querysense search index --sql "..." --fix-script > create_indexes.sql
    """
    from querysense.search_advisor import SearchClassifier, IndexType

    query = _resolve_sql(sql, file)
    if not query:
        error_console.print("[red]Error:[/red] Provide --sql or --file")
        raise typer.Exit(code=1)

    classifier = SearchClassifier()
    result = classifier.classify(query)

    if not result.recommendations:
        if fix_script:
            console.print("-- No search index recommendations for this query")
        elif json_output:
            console.print_json(json.dumps({"recommendations": []}))
        else:
            console.print("[yellow]No search patterns detected — no indexes to suggest.[/yellow]")
        return

    # Filter by type if specified
    type_map = {
        "exact": IndexType.BTREE,
        "trigram": IndexType.GIN_TRGM,
        "fts": IndexType.GIN_TSVECTOR,
        "prefix": IndexType.BTREE_PREFIX,
        "lower": IndexType.BTREE_LOWER,
        "jsonb": IndexType.GIN_JSONB,
        "array": IndexType.GIN_ARRAY,
    }
    if index_type:
        target = type_map.get(index_type.lower())
        if target:
            result.recommendations = [
                r for r in result.recommendations if r.index_type == target
            ]
            if not result.recommendations:
                # Force the type anyway
                from querysense.search_advisor import IndexRecommendation, _DECISION_MATRIX
                for p in result.patterns:
                    for st, matrix in _DECISION_MATRIX.items():
                        if matrix["index_type"] == target:
                            table = p.table or "<table>"
                            col = p.column or "<column>"
                            result.recommendations.append(IndexRecommendation(
                                index_type=target,
                                create_sql=classifier._build_create_index(target, table, col),
                                explanation=matrix["explanation"],
                                estimated_speedup=matrix["speedup"],
                                prerequisite_sql=(
                                    f"CREATE EXTENSION IF NOT EXISTS {matrix['extension']};"
                                    if matrix.get("extension") else ""
                                ),
                            ))
                            break

    if fix_script:
        # Output just SQL
        for rec in result.recommendations:
            if rec.prerequisite_sql:
                console.print(rec.prerequisite_sql)
            console.print(rec.create_sql)
        return

    if json_output:
        console.print_json(json.dumps({
            "recommendations": [
                {
                    "index_type": r.index_type.value,
                    "create_sql": r.create_sql,
                    "prerequisite_sql": r.prerequisite_sql,
                    "estimated_speedup": r.estimated_speedup,
                    "explanation": r.explanation,
                }
                for r in result.recommendations
            ]
        }, indent=2))
        return

    console.print()
    console.print(Panel("[bold]SEARCH INDEX RECOMMENDATIONS[/bold]", border_style="green"))

    for i, rec in enumerate(result.recommendations, 1):
        console.print(f"\n[bold green]{i}. {rec.index_type.value}[/bold green] (speedup: {rec.estimated_speedup})")
        if rec.prerequisite_sql:
            console.print(f"   [yellow]{rec.prerequisite_sql}[/yellow]")
        console.print(f"   [cyan]{rec.create_sql}[/cyan]")

    console.print()
    console.print("[dim]Tip: Use --fix-script to output SQL only, pipe to psql[/dim]")


# ── audit ────────────────────────────────────────────────────────────────


@search_app.command("audit")
def search_audit(
    dsn: Annotated[
        str,
        typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
    ] = "",
    top_n: Annotated[
        int,
        typer.Option("--top", help="Number of queries to audit"),
    ] = 50,
    like_only: Annotated[
        bool,
        typer.Option("--like", help="Only audit LIKE/ILIKE patterns"),
    ] = False,
    fix_script: Annotated[
        bool,
        typer.Option("--fix-script", help="Output only fix SQL"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Scan pg_stat_statements for unindexed search patterns.

    Finds LIKE, ILIKE, FTS, trigram, and regex queries that are
    missing appropriate indexes, sorted by total execution time.

    \b
    Examples:
        querysense search audit --dsn postgresql://localhost/mydb
        querysense search audit --dsn ... --like  # Only LIKE/ILIKE
        querysense search audit --dsn ... --fix-script > fixes.sql
    """
    if not dsn:
        error_console.print("[red]Error:[/red] --dsn required")
        raise typer.Exit(code=1)

    from querysense.search_advisor import SearchPatternDetector

    detector = SearchPatternDetector()

    async def _run() -> None:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        try:
            result = await detector.audit(conn, top_n=top_n)
        finally:
            await conn.close()

        if json_output:
            console.print_json(json.dumps(result.to_dict(), indent=2))
            return

        if fix_script:
            seen: set[str] = set()
            for c in result.top_offenders:
                for rec in c.recommendations:
                    if rec.create_sql not in seen:
                        if rec.prerequisite_sql:
                            console.print(rec.prerequisite_sql)
                        console.print(rec.create_sql)
                        seen.add(rec.create_sql)
            return

        console.print()
        console.print(Panel(
            f"[bold]SEARCH PATTERN AUDIT[/bold]\n"
            f"Search queries found: {result.search_queries}\n"
            f"Unindexed patterns: [red]{result.unindexed_count}[/red]",
            border_style="blue",
        ))

        if result.top_offenders:
            console.print(f"\n[bold red]Top Unindexed Search Queries:[/bold red]\n")

            for i, c in enumerate(result.top_offenders[:15], 1):
                pattern = c.patterns[0] if c.patterns else None
                if not pattern:
                    continue

                if like_only and pattern.search_type.value not in (
                    "wildcard", "ilike_wildcard", "suffix", "prefix",
                    "ilike_prefix", "ilike_exact",
                ):
                    continue

                console.print(f"  [bold]{i}.[/bold] {pattern.search_type.value} on "
                              f"{pattern.table}.{pattern.column}")
                console.print(f"     SQL: [dim]{c.sql[:80]}...[/dim]")
                if c.recommendations:
                    rec = c.recommendations[0]
                    console.print(f"     Fix: [cyan]{rec.create_sql}[/cyan]")
                    console.print(f"     Speedup: [green]{rec.estimated_speedup}[/green]")
                console.print()
        else:
            console.print("\n[green]All search queries appear to have appropriate indexes.[/green]")

    asyncio.run(_run())


# ── optimize ─────────────────────────────────────────────────────────────


@search_app.command("optimize")
def search_optimize(
    sql: Annotated[
        str,
        typer.Option("--sql", "-s", help="SQL query to optimize"),
    ] = "",
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="File containing SQL query"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Rewrite search queries for better performance.

    Converts LIKE '%val%' to trigram or full-text alternatives,
    ILIKE to lower() expressions, and more.

    \b
    Examples:
        querysense search optimize --sql "SELECT * FROM t WHERE name LIKE '%Apple%'"
        querysense search optimize --file slow_search.sql
    """
    from querysense.search_advisor import SearchRewriter

    query = _resolve_sql(sql, file)
    if not query:
        error_console.print("[red]Error:[/red] Provide --sql or --file")
        raise typer.Exit(code=1)

    rewriter = SearchRewriter()
    rewrites = rewriter.rewrite(query)

    if json_output:
        console.print_json(json.dumps(
            [r.to_dict() for r in rewrites], indent=2
        ))
        return

    console.print()

    if not rewrites:
        console.print("[green]No rewrites needed — query is already optimal for search.[/green]")
        return

    console.print(Panel("[bold]SEARCH QUERY REWRITES[/bold]", border_style="green"))
    console.print(f"\n[dim]Original:[/dim]")
    console.print(f"  {query[:200]}")

    for i, rw in enumerate(rewrites, 1):
        console.print(f"\n[bold green]Option {i}: {rw.rewrite_type}[/bold green] "
                      f"(speedup: {rw.estimated_speedup})")
        console.print(f"  [dim]Rewritten:[/dim]")
        console.print(f"  [cyan]{rw.rewritten_sql[:200]}[/cyan]")

        if rw.prerequisite_sql:
            console.print(f"  [yellow]Prerequisite: {rw.prerequisite_sql}[/yellow]")
        if rw.index_sql:
            console.print(f"  [bold]Index: {rw.index_sql}[/bold]")

        console.print(f"\n  [dim]Why:[/dim] {rw.explanation}")

    console.print()


# ── monitor ──────────────────────────────────────────────────────────────


@search_app.command("monitor")
def search_monitor(
    dsn: Annotated[
        str,
        typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
    ] = "",
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Monitor search query performance from pg_stat_statements.

    Breaks down search performance by type (exact, LIKE, ILIKE, FTS,
    trigram, regex) and recommends indexes for slow categories.

    \b
    Examples:
        querysense search monitor --dsn postgresql://localhost/mydb
        querysense search monitor --dsn ... --json
    """
    if not dsn:
        error_console.print("[red]Error:[/red] --dsn required")
        raise typer.Exit(code=1)

    from querysense.search_advisor import SearchMonitor

    monitor = SearchMonitor()

    async def _run() -> None:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        try:
            result = await monitor.monitor(conn)
        finally:
            await conn.close()

        if json_output:
            console.print_json(json.dumps(result.to_dict(), indent=2))
            return

        console.print()
        console.print(Panel(
            f"[bold]SEARCH PERFORMANCE MONITOR[/bold]\n"
            f"Total search queries: {result.total_search_queries:,}\n"
            f"Average latency: {result.avg_latency_ms:.0f}ms\n"
            f"P95 latency: {result.p95_latency_ms:.0f}ms\n"
            f"P99 latency: {result.p99_latency_ms:.0f}ms",
            border_style="blue",
        ))

        if result.by_type:
            console.print("\n[bold]Search Patterns:[/bold]\n")

            table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
            table.add_column("Type", min_width=10)
            table.add_column("Queries", justify="right")
            table.add_column("Calls", justify="right")
            table.add_column("% Calls", justify="right")
            table.add_column("Avg ms", justify="right")
            table.add_column("P95 ms", justify="right")
            table.add_column("Indexed?", justify="center")

            for cat, data in result.by_type.items():
                indexed = data.get("likely_indexed", False)
                idx_str = "[green]Yes[/green]" if indexed else "[red]No[/red]"
                avg_color = "green" if data["avg_ms"] < 100 else "yellow" if data["avg_ms"] < 500 else "red"

                table.add_row(
                    cat,
                    str(data["query_count"]),
                    f"{data['total_calls']:,}",
                    f"{data['pct_of_calls']:.1f}%",
                    f"[{avg_color}]{data['avg_ms']:.0f}[/{avg_color}]",
                    f"{data['p95_ms']:.0f}",
                    idx_str,
                )

            console.print(table)

        if result.recommendations:
            console.print("\n[bold yellow]Recommendations:[/bold yellow]\n")
            for i, rec in enumerate(result.recommendations, 1):
                sev_color = "red" if rec.severity.value == "critical" else "yellow"
                console.print(f"  [{sev_color}]{i}.[/{sev_color}] {rec.explanation}")
                console.print(f"     [cyan]{rec.create_sql.strip()}[/cyan]")
                if rec.prerequisite_sql:
                    console.print(f"     [yellow]{rec.prerequisite_sql}[/yellow]")
                console.print(f"     Speedup: [green]{rec.estimated_speedup}[/green]")
                console.print()
        else:
            console.print("\n[green]All search queries appear well-indexed.[/green]")

    asyncio.run(_run())


# ── extensions ───────────────────────────────────────────────────────────


@search_app.command("extensions")
def search_extensions(
    dsn: Annotated[
        str,
        typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
    ] = "",
    fix_script: Annotated[
        bool,
        typer.Option("--fix-script", help="Output only install SQL"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Check search-related PostgreSQL extensions.

    Verifies pg_trgm, unaccent, pg_bigm, fuzzystrmatch are installed
    and available. Outputs install commands for missing extensions.

    \b
    Examples:
        querysense search extensions --dsn postgresql://localhost/mydb
        querysense search extensions --dsn ... --fix-script > install_ext.sql
    """
    if not dsn:
        error_console.print("[red]Error:[/red] --dsn required")
        raise typer.Exit(code=1)

    from querysense.search_advisor import ExtensionChecker

    checker = ExtensionChecker()

    async def _run() -> None:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        try:
            report = await checker.check(conn)
        finally:
            await conn.close()

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2))
            return

        if fix_script:
            for ext in report.extensions:
                if not ext.installed and ext.available:
                    console.print(ext.install_sql)
            return

        console.print()
        console.print(Panel("[bold]SEARCH EXTENSIONS[/bold]", border_style="blue"))

        table = Table(show_header=True, header_style="bold")
        table.add_column("Extension", min_width=15)
        table.add_column("Installed")
        table.add_column("Available")
        table.add_column("Version")
        table.add_column("Purpose", max_width=50)

        for ext in report.extensions:
            inst = "[green]Yes[/green]" if ext.installed else "[red]No[/red]"
            avail = "[green]Yes[/green]" if ext.available else "[yellow]No[/yellow]"
            table.add_row(
                ext.name,
                inst,
                avail,
                ext.version or "—",
                ext.purpose[:50],
            )

        console.print(table)

        missing = [e for e in report.extensions if not e.installed and e.available]
        if missing:
            console.print(f"\n[yellow]{len(missing)} extension(s) available but not installed:[/yellow]")
            for ext in missing:
                console.print(f"  {ext.install_sql}")
        elif report.all_installed:
            console.print("\n[green]All search extensions installed.[/green]")

    asyncio.run(_run())


# ── benchmark ────────────────────────────────────────────────────────────


@search_app.command("benchmark")
def search_benchmark(
    rows: Annotated[
        int,
        typer.Option("--rows", "-r", help="Number of company rows to generate"),
    ] = 250_000,
    seed: Annotated[
        int,
        typer.Option("--seed", help="Random seed for deterministic generation"),
    ] = 42,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Output file (default: stdout)"),
    ] = None,
) -> None:
    """
    Generate a realistic search benchmark dataset.

    Creates tables (companies, exchanges, stock_prices) with realistic
    data for testing search optimization strategies. Based on pganalyze
    ebook's test dataset (p.4).

    \b
    Examples:
        querysense search benchmark > benchmark.sql
        querysense search benchmark --rows 500000 --output benchmark.sql
        querysense search benchmark | psql -d testdb
    """
    from querysense.search_advisor import BenchmarkGenerator, BenchmarkSpec

    spec = BenchmarkSpec(row_count=rows, seed=seed)
    generator = BenchmarkGenerator()
    sql = generator.generate_sql(spec)

    if output:
        output.write_text(sql, encoding="utf-8")
        console.print(f"[green]Benchmark SQL written to {output}[/green]")
        console.print(f"  Tables: companies ({rows:,}), exchanges (3), stock_prices (~{min(rows*4, 1_000_000):,})")
        console.print(f"  Load: psql -d <database> -f {output}")
    else:
        # Write to stdout directly (for piping)
        sys.stdout.write(sql)


# ── Registration ─────────────────────────────────────────────────────────


def register(app: typer.Typer) -> None:
    """Register search commands as a subcommand group."""
    app.add_typer(search_app, name="search")


# ── Helpers ──────────────────────────────────────────────────────────────


import textwrap


def _resolve_sql(sql: str, file: Optional[Path]) -> str:
    """Resolve SQL from --sql, --file, or stdin."""
    if sql:
        return sql
    if file:
        if not file.exists():
            error_console.print(f"[red]Error:[/red] File not found: {file}")
            raise typer.Exit(code=1)
        return file.read_text(encoding="utf-8").strip()
    # Try stdin (non-interactive)
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return ""
