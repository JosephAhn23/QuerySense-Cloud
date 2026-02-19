"""
Probe command: connect to a live database for infrastructure-correlated analysis.

Addresses weakness #2 (vs Datadog): "No infrastructure correlation — no
visibility beyond the EXPLAIN plan."

This command connects to a PostgreSQL instance, pulls system stats
(table sizes, index health, stats freshness, key settings), and
produces an infrastructure health report alongside EXPLAIN analysis.

Usage:
    querysense probe --dsn postgresql://localhost/mydb plan.json
    querysense probe --dsn $DATABASE_URL plan.json --json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from querysense.engine import AnalysisService
from querysense.parser import ParseError, parse_explain

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register probe command on the given Typer app."""

    @app.command()
    def probe(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        dsn: Annotated[
            str,
            typer.Option(
                "--dsn",
                help="PostgreSQL connection string",
                envvar="QUERYSENSE_DSN",
            ),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        timeout: Annotated[
            float,
            typer.Option("--timeout", help="DB query timeout in seconds"),
        ] = 10.0,
    ) -> None:
        """
        Analyze a plan WITH live database infrastructure correlation.

        Connects to PostgreSQL to pull table stats, index health,
        configuration settings, and bloat estimates — then cross-references
        with EXPLAIN findings to show the full picture.

        Like Datadog DBM, but offline and without agent infrastructure.

        \b
        Examples:
            $ querysense probe plan.json --dsn postgresql://localhost/mydb
            $ querysense probe plan.json --dsn $DATABASE_URL
            $ querysense probe plan.json --dsn postgresql://prod/app --json
        """
        import asyncio

        try:
            explain = parse_explain(explain_file)
        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            raise typer.Exit(code=1)

        console.print(
            f"[bold]QuerySense Probe[/bold] — "
            f"infrastructure-correlated analysis\n"
        )

        # Run analysis first (always works offline)
        service = AnalysisService()
        result = service.analyze(explain)

        # Collect tables mentioned in the plan
        tables = _extract_tables(explain)

        # Probe the database
        try:
            infra_data = asyncio.run(_probe_database(dsn, tables, timeout))
        except Exception as e:
            error_console.print(
                f"[yellow]DB connection failed:[/yellow] {e}\n"
                f"[dim]Showing plan analysis without infrastructure data.[/dim]\n"
            )
            infra_data = None

        if json_output:
            output = {
                "analysis": {
                    "findings_count": len(result.findings),
                    "findings": [
                        {
                            "rule_id": f.rule_id,
                            "severity": f.severity.value,
                            "title": f.title,
                            "suggestion": f.suggestion,
                        }
                        for f in result.findings
                    ],
                },
                "infrastructure": infra_data,
            }
            console.print_json(json.dumps(output, indent=2, default=str))
            return

        # Render infrastructure report
        if infra_data:
            _render_infra_report(infra_data, result)
        else:
            console.print("[dim]No infrastructure data available.[/dim]\n")

        # Render findings
        if result.findings:
            console.print(f"\n[bold]Findings ({len(result.findings)}):[/bold]\n")
            for f in result.findings:
                sev = f.severity.value.upper()
                style = {"CRITICAL": "red bold", "WARNING": "yellow", "INFO": "blue"}.get(sev, "dim")
                console.print(f"  [{style}][{sev}][/{style}] {f.title}")
                if f.suggestion:
                    first_sql = next(
                        (l for l in f.suggestion.split("\n") if l.strip() and not l.strip().startswith("--")),
                        None,
                    )
                    if first_sql:
                        console.print(f"    [green]{first_sql.strip()}[/green]")
                console.print()
        else:
            console.print("[green]No performance issues found.[/green]")


def _extract_tables(explain) -> list[str]:
    """Extract unique table names from an EXPLAIN output."""
    tables: set[str] = set()
    for node in explain.all_nodes:
        if node.relation_name:
            tables.add(node.relation_name)
    return sorted(tables)


async def _probe_database(
    dsn: str,
    tables: list[str],
    timeout: float,
) -> dict:
    """Probe database for infrastructure data."""
    try:
        import asyncpg
    except ImportError:
        raise RuntimeError(
            "asyncpg is required for database probing. "
            "Install with: pip install querysense[db]"
        )

    conn = await asyncpg.connect(dsn, timeout=timeout)

    try:
        infra: dict = {
            "connection": {"status": "connected", "dsn_host": dsn.split("@")[-1].split("/")[0] if "@" in dsn else "localhost"},
            "settings": {},
            "tables": {},
            "server_version": "",
        }

        # Server version
        try:
            version = await conn.fetchval("SHOW server_version")
            infra["server_version"] = version
        except Exception:
            pass

        # Key settings that affect query performance
        settings_to_check = [
            "work_mem", "shared_buffers", "effective_cache_size",
            "random_page_cost", "seq_page_cost", "cpu_tuple_cost",
            "max_parallel_workers_per_gather", "max_parallel_workers",
            "default_statistics_target", "effective_io_concurrency",
            "jit", "enable_seqscan", "enable_indexscan",
        ]

        for setting in settings_to_check:
            try:
                val = await conn.fetchval(f"SHOW {setting}")
                infra["settings"][setting] = val
            except Exception:
                pass

        # Table stats
        for table in tables[:20]:  # Cap at 20 tables
            try:
                row = await conn.fetchrow(
                    """
                    SELECT
                        pg_total_relation_size($1::regclass) as total_bytes,
                        pg_table_size($1::regclass) as table_bytes,
                        pg_indexes_size($1::regclass) as index_bytes,
                        n_live_tup,
                        n_dead_tup,
                        last_vacuum,
                        last_autovacuum,
                        last_analyze,
                        last_autoanalyze
                    FROM pg_stat_user_tables
                    WHERE relname = $1
                    """,
                    table,
                )

                if row:
                    dead = row["n_dead_tup"] or 0
                    live = row["n_live_tup"] or 0
                    bloat_ratio = dead / (live + dead) if (live + dead) > 0 else 0

                    infra["tables"][table] = {
                        "total_size": _fmt_bytes(row["total_bytes"]),
                        "table_size": _fmt_bytes(row["table_bytes"]),
                        "index_size": _fmt_bytes(row["index_bytes"]),
                        "live_rows": live,
                        "dead_rows": dead,
                        "bloat_ratio": round(bloat_ratio, 4),
                        "last_vacuum": str(row["last_vacuum"] or row["last_autovacuum"] or "never"),
                        "last_analyze": str(row["last_analyze"] or row["last_autoanalyze"] or "never"),
                    }

                    # Check indexes
                    idx_rows = await conn.fetch(
                        """
                        SELECT indexname, indexdef,
                               pg_relation_size(indexrelid) as size_bytes,
                               idx_scan, idx_tup_read, idx_tup_fetch
                        FROM pg_stat_user_indexes
                        JOIN pg_indexes ON indexname = pg_stat_user_indexes.indexrelname
                            AND schemaname = pg_stat_user_indexes.schemaname
                        WHERE pg_stat_user_indexes.relname = $1
                        ORDER BY idx_scan DESC
                        """,
                        table,
                    )

                    infra["tables"][table]["indexes"] = [
                        {
                            "name": r["indexname"],
                            "definition": r["indexdef"],
                            "size": _fmt_bytes(r["size_bytes"]),
                            "scans": r["idx_scan"],
                            "tuples_read": r["idx_tup_read"],
                        }
                        for r in idx_rows
                    ]

            except Exception as e:
                infra["tables"][table] = {"error": str(e)}

        return infra

    finally:
        await conn.close()


def _render_infra_report(infra: dict, result) -> None:
    """Render infrastructure report to console."""
    # Server info
    version = infra.get("server_version", "unknown")
    console.print(f"[dim]PostgreSQL {version}[/dim]\n")

    # Settings that matter
    settings = infra.get("settings", {})
    if settings:
        st = Table(title="Key Settings", show_header=True)
        st.add_column("Setting", style="cyan")
        st.add_column("Value")
        st.add_column("Note")

        notes = {
            "work_mem": lambda v: "[yellow]Low — sorts/hashes may spill to disk[/yellow]" if _parse_mem(v) < 16 else "[green]OK[/green]",
            "shared_buffers": lambda v: "[yellow]Check sizing[/yellow]" if _parse_mem(v) < 256 else "[green]OK[/green]",
            "random_page_cost": lambda v: "[yellow]High for SSD[/yellow]" if float(v) > 1.5 else "[green]OK for SSD[/green]",
            "max_parallel_workers_per_gather": lambda v: "[yellow]Parallelism disabled[/yellow]" if int(v) == 0 else f"[green]{v} workers[/green]",
            "default_statistics_target": lambda v: "[yellow]Low — consider 200+[/yellow]" if int(v) < 100 else "[green]OK[/green]",
            "jit": lambda v: "[green]Enabled[/green]" if v == "on" else "[dim]Disabled[/dim]",
        }

        for key, val in settings.items():
            note_fn = notes.get(key)
            note = ""
            if note_fn:
                try:
                    note = note_fn(val)
                except (ValueError, TypeError):
                    note = ""
            st.add_row(key, str(val), note)

        console.print(st)
        console.print()

    # Table health
    tables = infra.get("tables", {})
    if tables:
        tt = Table(title="Table Health", show_header=True)
        tt.add_column("Table", style="cyan")
        tt.add_column("Size", justify="right")
        tt.add_column("Rows", justify="right")
        tt.add_column("Dead Rows", justify="right")
        tt.add_column("Bloat", justify="right")
        tt.add_column("Last ANALYZE")
        tt.add_column("Indexes", justify="right")

        for tname, tdata in tables.items():
            if "error" in tdata:
                tt.add_row(tname, "[red]error[/red]", "", "", "", "", "")
                continue

            bloat = tdata.get("bloat_ratio", 0)
            bloat_style = "red" if bloat > 0.2 else ("yellow" if bloat > 0.1 else "green")

            tt.add_row(
                tname,
                tdata.get("total_size", "?"),
                f"{tdata.get('live_rows', 0):,}",
                f"{tdata.get('dead_rows', 0):,}",
                f"[{bloat_style}]{bloat:.1%}[/{bloat_style}]",
                tdata.get("last_analyze", "never")[:19],
                str(len(tdata.get("indexes", []))),
            )

        console.print(tt)

        # Cross-reference: flag stale stats for tables in findings
        finding_tables = {
            f.context.relation_name
            for f in result.findings
            if f.context and f.context.relation_name
        }

        stale_tables = []
        for tname in finding_tables:
            tdata = tables.get(tname, {})
            if tdata.get("last_analyze", "never") == "never":
                stale_tables.append(tname)

        if stale_tables:
            console.print(
                f"\n[yellow bold]Warning:[/yellow bold] Tables with findings "
                f"that have NEVER been analyzed: {', '.join(stale_tables)}"
            )
            console.print("[dim]Run: ANALYZE " + ", ".join(stale_tables) + ";[/dim]")


def _fmt_bytes(b: int | None) -> str:
    if b is None:
        return "?"
    if b < 1024:
        return f"{b}B"
    if b < 1024 ** 2:
        return f"{b / 1024:.1f}KB"
    if b < 1024 ** 3:
        return f"{b / (1024 ** 2):.1f}MB"
    return f"{b / (1024 ** 3):.1f}GB"


def _parse_mem(val: str) -> int:
    """Parse PostgreSQL memory setting to MB."""
    val = val.strip().upper()
    if val.endswith("GB"):
        return int(float(val[:-2]) * 1024)
    if val.endswith("MB"):
        return int(float(val[:-2]))
    if val.endswith("KB"):
        return int(float(val[:-2]) / 1024)
    try:
        return int(val) // (1024 * 1024)
    except ValueError:
        return 0
