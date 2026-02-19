"""
CLI commands for query classification and ORM detection.

    querysense classify explain.json
    querysense orm-detect --dsn postgresql://...
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register(parent: typer.Typer) -> None:
    """Register classification commands."""
    parent.command(name="classify")(classify)
    parent.command(name="orm-detect")(orm_detect)


def classify(
    explain_file: Annotated[Path, typer.Argument(help="EXPLAIN JSON file")] = None,
    sql: Annotated[str, typer.Option("--sql", help="SQL text to classify")] = "",
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
) -> None:
    """
    Classify a query as OLTP or OLAP with tailored recommendations.

    OLTP queries get index-focused recommendations; OLAP queries get
    parallelism and work_mem tuning. Based on "PostgreSQL Query Optimization"
    (Dombrovskaya et al. 2024).
    """
    from querysense.query_classifier import QueryClassifier

    classifier = QueryClassifier()

    if explain_file and explain_file.exists():
        from querysense.parser.parser import parse_explain
        plan = parse_explain(explain_file)
        result = classifier.classify(plan)
    elif sql:
        result = classifier.classify_sql(sql)
    else:
        console.print("[red]Provide either an EXPLAIN JSON file or --sql[/red]")
        raise typer.Exit(1)

    if json_output:
        console.print_json(json.dumps(result.to_dict(), indent=2))
        return

    type_style = {
        "oltp": "green",
        "olap": "blue",
        "mixed": "yellow",
        "unknown": "dim",
    }
    color = type_style.get(result.query_type.value, "white")

    console.print(Panel(
        f"[bold]Type: [{color}]{result.query_type.value.upper()}[/{color}][/bold]  |  "
        f"Complexity: {result.complexity.value}  |  "
        f"Confidence: {result.confidence:.0%}",
        title="[bold]QuerySense Query Classifier[/bold]",
    ))

    if result.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in result.recommendations:
            console.print(f"  • {rec}")

    if result.tuning:
        console.print("\n[bold]Tuning Parameters:[/bold]")
        for param, value in result.tuning.items():
            console.print(f"  [cyan]{param}[/cyan] = {value}")


def orm_detect(
    dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "",
    plan_dir: Annotated[str, typer.Option("--plans", help="Directory of EXPLAIN JSON files")] = "",
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
) -> None:
    """
    Detect ORM anti-patterns (N+1, SELECT *, eager loading abuse).

    Connects to pg_stat_statements to analyze the full query workload,
    or scans EXPLAIN plans from a directory.
    """
    import asyncio
    from querysense.orm_detector import ORMDetector

    detector = ORMDetector()
    stats = None

    if dsn:
        # Fetch from pg_stat_statements
        stats = asyncio.run(_fetch_stats(dsn))
        patterns = detector.detect(query_stats=stats)
    elif plan_dir:
        # Scan plan files
        from querysense.parser.parser import parse_explain
        plan_path = Path(plan_dir)
        if not plan_path.exists():
            console.print(f"[red]Directory not found: {plan_dir}[/red]")
            raise typer.Exit(1)
        sql_queries = []
        for f in plan_path.glob("*.json"):
            raw = json.loads(f.read_text())
            if isinstance(raw, dict) and "query" in raw:
                sql_queries.append(raw["query"])
        patterns = detector.detect(sql_queries=sql_queries)
    else:
        console.print("[red]Provide either --dsn or --plans[/red]")
        raise typer.Exit(1)

    if json_output:
        data = [p.to_dict() for p in patterns]
        console.print_json(json.dumps(data, indent=2))
        return

    if not patterns:
        console.print("[green]✓ No ORM anti-patterns detected![/green]")
        return

    console.print(Panel(
        f"[bold]{len(patterns)} ORM anti-pattern(s) detected[/bold]",
        title="[bold]QuerySense ORM Pitfall Detector[/bold]",
    ))

    for p in patterns:
        sev_style = {"critical": "red bold", "warning": "yellow", "info": "blue"}
        style = sev_style.get(p.severity, "white")
        console.print(
            f"\n  [{style}]{p.severity.upper()}[/{style}] "
            f"[bold]{p.pattern_name}[/bold] (impact: {p.impact_score:.1f}/10)"
        )
        console.print(f"    {p.description}")
        console.print(f"    [bold]SQL fix:[/bold] {p.sql_fix.split(chr(10))[0]}")
        console.print(f"    [bold]ORM fix:[/bold]")
        for line in p.orm_fix.split("\n")[:4]:
            console.print(f"      [cyan]{line}[/cyan]")

    critical = [p for p in patterns if p.severity == "critical"]
    if critical:
        raise typer.Exit(1)


async def _fetch_stats(dsn: str) -> list[dict]:
    """Fetch query stats from pg_stat_statements."""
    import asyncpg
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch("""
            SELECT query, calls, mean_exec_time AS mean_time_ms, rows
            FROM pg_stat_statements
            WHERE calls > 5
            ORDER BY calls DESC
            LIMIT 200
        """)
        return [dict(row) for row in rows]
    finally:
        await conn.close()
