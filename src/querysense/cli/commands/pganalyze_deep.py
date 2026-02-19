"""
CLI commands for pganalyze deep parity features:
- querysense whatif -- planner what-if simulation
- querysense xmin-horizon -- xmin horizon tracking
- querysense bloat -- ideal-size bloat estimation
- querysense index-interactions -- index conflict/redundancy/synergy analysis
- querysense autovacuum-status -- worker utilization and queue analysis
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

console = Console()


def _load_plans(paths: list[Path]) -> list[dict]:
    plans = []
    for p in paths:
        if not p.exists():
            continue
        try:
            plans.append(json.loads(p.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            pass
    return plans


def register(app: typer.Typer) -> None:

    @app.command("whatif")
    def whatif(
        plan_file: Annotated[
            Path,
            typer.Argument(help="EXPLAIN ANALYZE JSON plan file"),
        ],
        add_index: Annotated[
            str,
            typer.Option("--add-index", "-i", help="Columns to index: table.col1,col2"),
        ] = "",
        knob: Annotated[
            str,
            typer.Option("--knob", "-k", help="Knob to change: name=value"),
        ] = "",
        selectivity: Annotated[
            float,
            typer.Option("--selectivity", "-s", help="Filter selectivity (0-1)"),
        ] = 0.01,
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Planner what-if simulation -- predict cost changes for hypothetical indexes and knobs."""
        from querysense.planner_whatif import PlannerWhatIf

        if not plan_file.exists():
            console.print(f"[red]File not found: {plan_file}[/red]")
            raise typer.Exit(1)

        plan = json.loads(plan_file.read_text(encoding="utf-8"))
        engine = PlannerWhatIf()
        table_stats_list = engine.collect_stats_from_plan(plan)

        if not table_stats_list:
            console.print("[yellow]No table statistics found in plan.[/yellow]")
            raise typer.Exit(1)

        scenarios: list[dict] = []

        # Add index scenario
        if add_index:
            parts = add_index.split(".")
            if len(parts) == 2:
                table_name = parts[0]
                columns = parts[1].split(",")
                scenarios.append({
                    "type": "add_index",
                    "columns": columns,
                    "selectivity": selectivity,
                })

        # Knob scenario
        if knob and "=" in knob:
            k, v = knob.split("=", 1)
            scenarios.append({
                "type": "knob",
                "knob": k.strip(),
                "value": v.strip(),
                "selectivity": selectivity,
            })

        # Default: test index on first table's filter columns
        if not scenarios:
            for ts in table_stats_list:
                for col, sel in ts.column_selectivities.items():
                    scenarios.append({
                        "type": "add_index",
                        "columns": [col],
                        "selectivity": sel,
                    })

        if not scenarios:
            console.print("[yellow]No scenarios to simulate. Use --add-index or --knob.[/yellow]")
            raise typer.Exit(1)

        ts = table_stats_list[0]
        result = engine.simulate_batch(ts, scenarios)

        if output_json:
            console.print(result.to_json())
        else:
            console.print(result.format_text())

    @app.command("xmin-horizon")
    def xmin_horizon(
        dsn: Annotated[
            str,
            typer.Argument(help="PostgreSQL connection string"),
        ],
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Track xmin horizon -- identify what's blocking VACUUM from cleaning dead tuples."""
        import asyncio
        from querysense.xmin_horizon import XminHorizonTracker

        tracker = XminHorizonTracker()
        report = asyncio.run(tracker.analyze(dsn))

        if output_json:
            console.print(report.to_json())
        else:
            console.print(report.format_text())

        if report.pct_to_wraparound > 0.5:
            raise typer.Exit(1)

    @app.command("bloat")
    def bloat(
        dsn: Annotated[
            str,
            typer.Argument(help="PostgreSQL connection string"),
        ] = "",
        schema: Annotated[
            str,
            typer.Option("--schema", help="Schema to analyze"),
        ] = "public",
        offline_file: Annotated[
            str,
            typer.Option("--file", "-f", help="JSON file with table stats for offline analysis"),
        ] = "",
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Ideal-size bloat estimation -- compare statistical ideal vs actual table sizes."""
        from querysense.bloat_estimator import IdealSizeBloatEstimator

        estimator = IdealSizeBloatEstimator()

        if offline_file:
            p = Path(offline_file)
            if not p.exists():
                console.print(f"[red]File not found: {offline_file}[/red]")
                raise typer.Exit(1)
            tables = json.loads(p.read_text(encoding="utf-8"))
            report = estimator.estimate_offline(tables)
        elif dsn:
            import asyncio
            report = asyncio.run(estimator.estimate(dsn, schema=schema))
        else:
            console.print("[red]Provide DSN or --file for offline analysis.[/red]")
            raise typer.Exit(1)

        if output_json:
            console.print(report.to_json())
        else:
            console.print(report.format_text())

    @app.command("index-interactions")
    def index_interactions(
        dsn: Annotated[
            str,
            typer.Argument(help="PostgreSQL connection string"),
        ] = "",
        schema: Annotated[
            str,
            typer.Option("--schema", help="Schema to analyze"),
        ] = "public",
        offline_file: Annotated[
            str,
            typer.Option("--file", "-f", help="JSON file with index info"),
        ] = "",
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Analyze index interactions -- find redundancies, conflicts, and synergies."""
        from querysense.index_interactions import IndexInteractionAnalyzer, IndexInfo

        analyzer = IndexInteractionAnalyzer()

        if offline_file:
            p = Path(offline_file)
            if not p.exists():
                console.print(f"[red]File not found: {offline_file}[/red]")
                raise typer.Exit(1)
            data = json.loads(p.read_text(encoding="utf-8"))
            indexes = [
                IndexInfo(
                    name=i["name"],
                    table=i["table"],
                    columns=tuple(i["columns"]),
                    index_type=i.get("index_type", "btree"),
                    is_unique=i.get("is_unique", False),
                    size_bytes=i.get("size_bytes", 0),
                )
                for i in data
            ]
            report = analyzer.analyze(indexes)
        elif dsn:
            import asyncio
            indexes = asyncio.run(_fetch_indexes(dsn, schema))
            report = analyzer.analyze(indexes)
        else:
            console.print("[red]Provide DSN or --file.[/red]")
            raise typer.Exit(1)

        if output_json:
            console.print(report.to_json())
        else:
            console.print(report.format_text())

    @app.command("autovacuum-status")
    def autovacuum_status(
        dsn: Annotated[
            str,
            typer.Argument(help="PostgreSQL connection string"),
        ],
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Autovacuum worker utilization -- saturation, queue depth, I/O budget."""
        import asyncio
        from querysense.autovacuum_utilization import AutovacuumAnalyzer

        analyzer = AutovacuumAnalyzer()
        report = asyncio.run(analyzer.analyze(dsn))

        if output_json:
            console.print(report.to_json())
        else:
            console.print(report.format_text())

        if report.saturation_pct >= 100:
            raise typer.Exit(1)


async def _fetch_indexes(dsn: str, schema: str) -> list:
    """Fetch index information from PostgreSQL."""
    from querysense.index_interactions import IndexInfo

    try:
        import asyncpg
    except ImportError:
        raise RuntimeError("asyncpg required: pip install asyncpg")

    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch("""
            SELECT
                i.relname AS index_name,
                t.relname AS table_name,
                array_agg(a.attname ORDER BY x.ordinality) AS columns,
                am.amname AS index_type,
                i.reltuples,
                pg_relation_size(i.oid) AS size_bytes,
                ix.indisunique
            FROM pg_index ix
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_class t ON t.oid = ix.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_am am ON am.oid = i.relam
            CROSS JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS x(attnum, ordinality)
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = x.attnum
            WHERE n.nspname = $1
              AND NOT ix.indisprimary
            GROUP BY i.relname, t.relname, am.amname, i.reltuples, i.oid, ix.indisunique
            ORDER BY pg_relation_size(i.oid) DESC;
        """, schema)

        return [
            IndexInfo(
                name=row["index_name"],
                table=row["table_name"],
                columns=tuple(row["columns"]),
                index_type=row["index_type"],
                is_unique=row["indisunique"],
                size_bytes=row["size_bytes"] or 0,
            )
            for row in rows
        ]
    finally:
        await conn.close()


def register_protocol(app: typer.Typer) -> None:
    """Register extended protocol and query store commands."""

    @app.command("protocol-explain")
    def protocol_explain(
        query: Annotated[
            str,
            typer.Argument(help="Parameterized SQL query with $1, $2, ... placeholders"),
        ],
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN for type detection", envvar="QUERYSENSE_DSN"),
        ] = "",
        type_hints: Annotated[
            str,
            typer.Option("--types", "-t", help="Manual type hints: 1=int4,2=text"),
        ] = "",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Prepare a parameterized query ($1, $2) for EXPLAIN.

        Detects parameter types from PostgreSQL and substitutes safe sample
        values so you can run EXPLAIN on extended-protocol queries.

        \b
        Examples:
            $ querysense protocol-explain "SELECT * FROM users WHERE id = \\$1" --dsn $DB_URL
            $ querysense protocol-explain "SELECT * FROM orders WHERE user_id = \\$1 AND status = \\$2" --types "1=int4,2=text"
        """
        from querysense.extended_protocol import ExtendedProtocolParser

        parser = ExtendedProtocolParser()

        if dsn:
            import asyncio
            import asyncpg

            async def _detect():
                conn = await asyncpg.connect(dsn)
                try:
                    return await parser.detect_types(query, conn)
                finally:
                    await conn.close()

            pq = asyncio.run(_detect())
        else:
            hints: dict[int, str] = {}
            if type_hints:
                for pair in type_hints.split(","):
                    if "=" in pair:
                        pos, typ = pair.split("=", 1)
                        hints[int(pos.strip())] = typ.strip()

            pq = parser.normalize(query)
            for pos, typ in hints.items():
                if pos in pq.param_positions:
                    pq.param_types[pos] = typ
                    pq.param_samples[pos] = parser._sample_for_type(typ)

        if json_output:
            console.print_json(json.dumps(pq.to_dict(), indent=2))
            return

        from rich.panel import Panel
        from rich.table import Table

        console.print(Panel(
            f"[bold]Extended Protocol Query[/bold]\n\n"
            f"Original: [dim]{pq.original}[/dim]\n"
            f"Parameters: {pq.param_count}\n"
            f"Fingerprint: [cyan]{pq.normalized}[/cyan]",
            title="Protocol Parser",
            border_style="blue",
        ))

        if pq.param_positions:
            tbl = Table(title="Parameter Types")
            tbl.add_column("Position", justify="right")
            tbl.add_column("Type")
            tbl.add_column("Sample Value")

            for pos in pq.param_positions:
                tbl.add_row(
                    f"${pos}",
                    pq.param_types.get(pos, "[dim]unknown[/dim]"),
                    pq.param_samples.get(pos, "NULL"),
                )
            console.print(tbl)

        console.print(f"\n[bold]EXPLAIN-ready SQL:[/bold]")
        console.print(f"[green]{pq.explain_ready_sql}[/green]")

    @app.command("query-store")
    def query_store_cmd(
        action: Annotated[
            str,
            typer.Argument(help="Action: store, get, stats, cleanup"),
        ] = "stats",
        query: Annotated[
            str,
            typer.Option("--query", "-q", help="Query text to store"),
        ] = "",
        query_hash: Annotated[
            str,
            typer.Option("--hash", help="Query hash to retrieve"),
        ] = "",
        max_age: Annotated[
            int,
            typer.Option("--max-age", help="Max age in days for cleanup"),
        ] = 90,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Manage the compressed query text store (unlimited query length).

        pg_stat_statements truncates at 1-4KB. This stores full query text
        with zstd/zlib compression and SHA-256 hash lookup.

        \b
        Examples:
            $ querysense query-store stats
            $ querysense query-store store --query "SELECT ... (very long SQL)"
            $ querysense query-store get --hash abc123def456
            $ querysense query-store cleanup --max-age 60
        """
        from querysense.storage.large_query import LargeQueryStore

        store = LargeQueryStore()

        if action == "store":
            if not query:
                console.print("[red]--query required for store action[/red]")
                raise typer.Exit(1)
            qhash = store.store(query)
            console.print(f"[green]Stored[/green]: hash={qhash}, length={len(query):,} bytes")

        elif action == "get":
            if not query_hash:
                console.print("[red]--hash required for get action[/red]")
                raise typer.Exit(1)
            text = store.get(query_hash)
            if text is None:
                console.print(f"[red]Query {query_hash} not found[/red]")
                raise typer.Exit(1)
            console.print(text)

        elif action == "cleanup":
            removed = store.cleanup(max_age)
            console.print(f"[green]Removed {removed} queries older than {max_age} days[/green]")

        else:
            stats = store.stats()
            if json_output:
                console.print_json(json.dumps(stats.to_dict()))
                return
            from rich.panel import Panel
            console.print(Panel(
                f"[bold]Query Store Statistics[/bold]\n\n"
                f"Total queries: {stats.total_queries:,}\n"
                f"Raw size: {stats.total_raw_bytes / 1024:.0f} KB\n"
                f"Compressed: {stats.total_compressed_bytes / 1024:.0f} KB\n"
                f"Compression ratio: {stats.avg_compression_ratio:.1f}x\n"
                f"Largest query: {stats.largest_query_bytes / 1024:.0f} KB\n"
                f"DB size: {stats.db_size_bytes / 1024:.0f} KB",
                title="Large Query Store",
                border_style="cyan",
            ))

    @app.command("obfuscate")
    def obfuscate_cmd(
        plan_file: Annotated[
            str,
            typer.Option("--plan", "-p", help="EXPLAIN JSON plan file to obfuscate"),
        ] = "",
        query: Annotated[
            str,
            typer.Option("--query", "-q", help="SQL query to obfuscate"),
        ] = "",
        salt: Annotated[
            str,
            typer.Option("--salt", "-s", help="Salt for deterministic hashing"),
        ] = "",
        disable: Annotated[
            str,
            typer.Option("--disable", help="Comma-separated pattern names to disable"),
        ] = "",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Obfuscate PII in EXPLAIN plans or SQL queries.

        Detects and masks email, SSN, credit card, phone, IP, UUID.
        Uses deterministic hashing so the same value always maps to
        the same token (useful for correlation without exposing PII).

        \b
        Examples:
            $ querysense obfuscate --query "SELECT * FROM users WHERE email = 'john@example.com'"
            $ querysense obfuscate --plan explain.json --salt mysecret
            $ querysense obfuscate --query "WHERE ssn = '123-45-6789'" --disable ipv4,uuid
        """
        from querysense.security.pii_obfuscator import PIIObfuscator

        disabled_set = {d.strip() for d in disable.split(",") if d.strip()} if disable else set()
        obfuscator = PIIObfuscator(
            salt=salt,
            deterministic=bool(salt),
            disabled_patterns=disabled_set or None,
        )

        if plan_file:
            path = Path(plan_file)
            if not path.exists():
                console.print(f"[red]File not found: {plan_file}[/red]")
                raise typer.Exit(1)

            plan = json.loads(path.read_text(encoding="utf-8"))
            safe_plan, report = obfuscator.obfuscate_plan_with_report(plan)

            if json_output:
                console.print_json(json.dumps({
                    "plan": safe_plan,
                    "obfuscation_report": report.to_dict(),
                }, indent=2))
            else:
                console.print_json(json.dumps(safe_plan, indent=2))
                from rich.panel import Panel
                console.print(Panel(
                    f"[bold]PII Obfuscation Report[/bold]\n\n"
                    f"Fields processed: {report.fields_processed}\n"
                    f"PII matches found: {report.total_matches}\n"
                    f"Matches by type: {report.matches_by_type}",
                    border_style="yellow",
                ))

        elif query:
            safe = obfuscator.obfuscate_query(query)
            if json_output:
                console.print_json(json.dumps({"original_length": len(query), "obfuscated": safe}))
            else:
                console.print(f"[dim]Original:[/dim]  {query}")
                console.print(f"[green]Obfuscated:[/green] {safe}")

        else:
            console.print("[yellow]Provide --plan or --query to obfuscate.[/yellow]")
            raise typer.Exit(1)

    @app.command("audit-verify")
    def audit_verify(
        log_file: Annotated[
            str,
            typer.Option("--log", "-l", help="Path to audit log file"),
        ] = "",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Verify the integrity of the SOC2 audit chain.

        Reads the audit log file and validates that every event's
        hash correctly chains to the previous event (tamper detection).

        \b
        Examples:
            $ querysense audit-verify --log ~/.querysense/audit.jsonl
        """
        from querysense.audit.logger import AuditLogger

        if not log_file:
            default = Path.home() / ".querysense" / "audit.jsonl"
            if default.exists():
                log_file = str(default)
            else:
                console.print("[yellow]No audit log found. Specify --log path.[/yellow]")
                raise typer.Exit(1)

        logger = AuditLogger(log_file=log_file)
        valid, count, errors = logger.verify_file_chain()

        if json_output:
            console.print_json(json.dumps({
                "valid": valid,
                "events_checked": count,
                "errors": errors,
            }))
            return

        from rich.panel import Panel
        if valid:
            console.print(Panel(
                f"[bold green]CHAIN VALID[/bold green]\n\n"
                f"Events verified: {count:,}\n"
                f"Tamper evidence: None detected\n"
                f"File: {log_file}",
                title="SOC2 Audit Chain Verification",
                border_style="green",
            ))
        else:
            console.print(Panel(
                f"[bold red]CHAIN INTEGRITY FAILURE[/bold red]\n\n"
                f"Events checked: {count:,}\n"
                f"Errors: {len(errors)}\n"
                f"File: {log_file}",
                title="SOC2 Audit Chain Verification",
                border_style="red",
            ))
            for err in errors[:10]:
                console.print(f"  [red]{err}[/red]")
            if len(errors) > 10:
                console.print(f"  [dim]... and {len(errors) - 10} more errors[/dim]")
            raise typer.Exit(1)
