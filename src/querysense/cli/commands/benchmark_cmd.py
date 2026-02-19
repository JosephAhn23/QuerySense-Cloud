"""
CLI commands for the benchmark module.

Commands:
    querysense benchmark saop      -- Analyze EXPLAIN JSON for IN-list / SAOP issues
    querysense benchmark run       -- Run query under controlled cache conditions
    querysense benchmark compare   -- HOT vs WARM side-by-side comparison
    querysense benchmark cache     -- Show shared buffer cache contents
    querysense benchmark evict     -- Evict relation from shared buffers
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
error_console = Console(stderr=True)

benchmark_app = typer.Typer(
    name="benchmark",
    help="Cache-aware benchmarking, SAOP analysis, and double-buffer detection (pganalyze-grade)",
    no_args_is_help=True,
)


# ── saop ─────────────────────────────────────────────────────────────────


@benchmark_app.command()
def saop(
    plan_file: Annotated[
        Path,
        typer.Argument(help="EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) plan file"),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Analyze an EXPLAIN plan for IN-list / ANY= (SAOP) inefficiencies.

    Detects queries that generate excessive primitive B-tree index scans
    and flags Postgres 17 upgrade opportunities.

    \b
    Examples:
        querysense benchmark saop plan.json
        querysense benchmark saop plan.json --json
    """
    from querysense.benchmark import SAOPAnalyzer

    if not plan_file.exists():
        error_console.print(f"[red]Error:[/red] File not found: {plan_file}")
        raise typer.Exit(code=1)

    plan = json.loads(plan_file.read_text(encoding="utf-8"))
    analyzer = SAOPAnalyzer()
    findings = analyzer.analyze(plan)

    if json_output:
        console.print_json(json.dumps(
            [dataclasses.asdict(f) for f in findings], indent=2
        ))
        return

    if not findings:
        console.print("[green]No IN-list / ANY= issues detected in this plan.[/green]")
        return

    console.print()
    console.print(Panel("[bold]SAOP ANALYSIS[/bold]", border_style="blue"))

    for f in findings:
        sev_color = {"CRITICAL": "red", "WARNING": "yellow", "INFO": "cyan"}.get(f.severity, "white")
        pg17_tag = " [dim][PG17 fix][/dim]" if f.pg17_win else ""

        console.print(f"\n  [{sev_color}][{f.severity}][/{sev_color}] {f.title}{pg17_tag}")
        console.print(f"  Score: {f.score}/10")
        console.print(f"  {f.detail}")
        console.print(f"  [green]Fix:[/green] {f.suggestion}")

    console.print()
    console.print(analyzer.pg17_candidate_report(findings))


# ── run ──────────────────────────────────────────────────────────────────


@benchmark_app.command("run")
def benchmark_run(
    sql: Annotated[
        str,
        typer.Option("--sql", "-s", help="SQL query to benchmark"),
    ],
    dsn: Annotated[
        str,
        typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
    ],
    mode: Annotated[
        str,
        typer.Option("--mode", "-m", help="Cache mode: hot, warm, cold"),
    ] = "hot",
    relation: Annotated[
        Optional[str],
        typer.Option("--relation", "-r", help="Table/index to pre-warm or evict"),
    ] = None,
    iterations: Annotated[
        int,
        typer.Option("--iterations", "-n", help="Number of iterations"),
    ] = 1,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Run a query under controlled cache conditions.

    HOT  = shared buffers + OS page cache both warm.
    WARM = shared buffers evicted, OS page cache intact.
    COLD = both caches empty (requires filesystem access).

    \b
    Examples:
        querysense benchmark run --sql "SELECT * FROM orders WHERE id = 1" --dsn $DSN
        querysense benchmark run --sql "..." --dsn $DSN --mode warm --relation orders
    """
    from querysense.benchmark import BenchmarkRunner, CacheMode

    try:
        cache_mode = CacheMode(mode.lower())
    except ValueError:
        error_console.print(f"[red]Error:[/red] Unknown mode '{mode}'. Choose: hot, warm, cold")
        raise typer.Exit(code=1)

    async def _run():
        import asyncpg
        pool = await asyncpg.create_pool(dsn)
        try:
            runner = BenchmarkRunner(pool)
            await runner.setup()
            return await runner.run(sql, cache_mode, relation, iterations)
        finally:
            await pool.close()

    try:
        result = asyncio.run(_run())
    except RuntimeError as e:
        console.print(str(e))
        return

    if json_output:
        console.print_json(json.dumps(dataclasses.asdict(result), indent=2, default=str))
        return

    console.print()
    console.print(Panel("[bold]BENCHMARK RESULT[/bold]", border_style="green"))
    console.print(str(result))


# ── compare ──────────────────────────────────────────────────────────────


@benchmark_app.command()
def compare(
    sql: Annotated[
        str,
        typer.Option("--sql", "-s", help="SQL query to benchmark"),
    ],
    dsn: Annotated[
        str,
        typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
    ],
    relation: Annotated[
        Optional[str],
        typer.Option("--relation", "-r", help="Table to pre-warm/evict"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Run a query in HOT and WARM mode side-by-side.

    Shows the speedup from shared buffer cache and detects
    double-buffering (OS page cache masking disk latency).

    \b
    Examples:
        querysense benchmark compare --sql "SELECT * FROM orders" --dsn $DSN --relation orders
    """
    from querysense.benchmark import BenchmarkRunner, DoubleBufferProbe

    async def _run():
        import asyncpg
        pool = await asyncpg.create_pool(dsn)
        try:
            runner = BenchmarkRunner(pool)
            await runner.setup()
            return await runner.compare(sql, relation)
        finally:
            await pool.close()

    results = asyncio.run(_run())

    if json_output:
        out = {k: dataclasses.asdict(v) for k, v in results.items()}
        console.print_json(json.dumps(out, indent=2, default=str))
        return

    hot = results.get("hot")
    warm = results.get("warm")

    console.print()
    console.print(Panel("[bold]CACHE BENCHMARK COMPARISON[/bold]", border_style="blue"))

    if hot and warm:
        speedup = warm.execution_time_ms / max(hot.execution_time_ms, 0.001)

        table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
        table.add_column("Metric", min_width=20)
        table.add_column("HOT", justify="right")
        table.add_column("WARM", justify="right")
        table.add_column("Ratio", justify="right")

        table.add_row(
            "Planning (ms)",
            f"{hot.planning_time_ms:.3f}",
            f"{warm.planning_time_ms:.3f}",
            "",
        )
        table.add_row(
            "Execution (ms)",
            f"{hot.execution_time_ms:.3f}",
            f"{warm.execution_time_ms:.3f}",
            f"{speedup:.1f}x",
        )
        table.add_row(
            "Shared hit",
            f"{hot.buffers.shared_hit:,}",
            f"{warm.buffers.shared_hit:,}",
            "",
        )
        table.add_row(
            "Shared read",
            f"{hot.buffers.shared_read:,}",
            f"{warm.buffers.shared_read:,}",
            "",
        )
        table.add_row(
            "Hit rate",
            f"{hot.buffers.hit_rate:.1%}",
            f"{warm.buffers.hit_rate:.1%}",
            "",
        )

        console.print(table)

        probe = DoubleBufferProbe()
        for label, r in [("HOT", hot), ("WARM", warm)]:
            for w in probe.analyze(r):
                console.print(f"\n[yellow]WARNING [{label}]:[/yellow] {w}")

        if speedup > 2.0:
            console.print(
                f"\n[green]Clear cache benefit: shared buffers provide {speedup:.1f}x speedup.[/green]"
            )
        else:
            console.print(
                "\n[yellow]Minimal HOT/WARM difference. OS page cache may be masking disk latency.[/yellow]"
            )


# ── cache ────────────────────────────────────────────────────────────────


@benchmark_app.command()
def cache(
    dsn: Annotated[
        str,
        typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
    ],
    top_n: Annotated[
        int,
        typer.Option("--top", help="Number of top relations to show"),
    ] = 20,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
) -> None:
    """
    Show what's currently in the PostgreSQL shared buffer cache.

    Requires pg_buffercache extension.

    \b
    Examples:
        querysense benchmark cache --dsn $DSN
        querysense benchmark cache --dsn $DSN --top 50 --json
    """
    from querysense.benchmark import BufferCacheEvict

    async def _run():
        import asyncpg
        pool = await asyncpg.create_pool(dsn)
        try:
            evict = BufferCacheEvict(pool)
            await evict.ensure_extension()
            supported, msg = await evict.check_version()
            contents = await evict.buffer_contents(top_n)
            return supported, msg, contents
        finally:
            await pool.close()

    supported, msg, contents = asyncio.run(_run())

    if json_output:
        console.print_json(json.dumps({
            "pg17_evict_supported": supported,
            "message": msg,
            "top_relations": contents,
        }, indent=2, default=str))
        return

    console.print()
    console.print(Panel(
        f"[bold]SHARED BUFFER CACHE[/bold]\n"
        f"pg_buffercache_evict: {'[green]supported[/green]' if supported else '[yellow]not supported (PG17+ required)[/yellow]'}",
        border_style="blue",
    ))

    table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    table.add_column("Schema", min_width=12)
    table.add_column("Relation", min_width=25)
    table.add_column("Kind", width=6)
    table.add_column("Buffers", justify="right")
    table.add_column("Size MB", justify="right")

    kind_map = {"r": "table", "i": "index", "S": "seq", "t": "toast"}
    for row in contents:
        table.add_row(
            str(row.get("schema", "")),
            str(row.get("relation", "")),
            kind_map.get(str(row.get("kind", "")), str(row.get("kind", ""))),
            f"{row.get('buffers', 0):,}",
            f"{row.get('size_mb', 0):,}",
        )

    console.print(table)


# ── evict ────────────────────────────────────────────────────────────────


@benchmark_app.command()
def evict(
    dsn: Annotated[
        str,
        typer.Option("--dsn", "-d", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
    ],
    relation: Annotated[
        Optional[str],
        typer.Option("--relation", "-r", help="Table or index to evict"),
    ] = None,
    all_relations: Annotated[
        bool,
        typer.Option("--all", help="Evict all relations from shared buffers"),
    ] = False,
) -> None:
    """
    Evict a table/index from PostgreSQL shared buffer cache.

    Requires pg_buffercache extension and Postgres 17+.
    Intended for benchmarking only.

    \b
    Examples:
        querysense benchmark evict --dsn $DSN --relation orders
        querysense benchmark evict --dsn $DSN --all
    """
    from querysense.benchmark import BufferCacheEvict, DoubleBufferProbe

    if not relation and not all_relations:
        error_console.print("[red]Error:[/red] Specify --relation <name> or --all")
        raise typer.Exit(code=1)

    async def _run():
        import asyncpg
        pool = await asyncpg.create_pool(dsn)
        try:
            ev = BufferCacheEvict(pool)
            await ev.ensure_extension()
            supported, msg = await ev.check_version()
            if not supported:
                return None, msg
            if all_relations:
                result = await ev.evict_all()
            else:
                result = await ev.evict_relation(relation)
            return result, None
        finally:
            await pool.close()

    result, err = asyncio.run(_run())

    if err:
        error_console.print(f"[red]Error:[/red] {err}")
        raise typer.Exit(code=1)

    target = relation if relation else "all relations"
    console.print(f"[green]Evicted {result['evicted']:,} / {result['total']:,} buffers for {target}[/green]")
    console.print()
    console.print("[dim]Note: OS page cache is unaffected. To flush it:[/dim]")
    if relation:
        console.print(DoubleBufferProbe.os_evict_commands("<data_dir>", "<pg_relation_filepath>"))


# ── Registration ─────────────────────────────────────────────────────────


def register(app: typer.Typer) -> None:
    """Register benchmark commands as a subcommand group."""
    app.add_typer(benchmark_app, name="benchmark")
