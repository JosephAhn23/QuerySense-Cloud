"""
CLI commands for pganalyze roadmap features.

Commands:
    querysense pg18 async-io --dsn postgresql://...
    querysense audit uuids --dsn postgresql://... [--v7] [--generate-sql]
    querysense audit connections --pooler --dsn postgresql://...
    querysense audit checkpoints --predict --dsn postgresql://...
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register_pg18_async_io(parent: typer.Typer) -> None:
    """Register PG18 async I/O profiling command."""

    @parent.command(name="async-io")
    def pg18_async_io(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        output_json: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Profile async I/O readiness and recommend optimal io_method.

        Analyzes top queries by I/O wait, detects storage type, and recommends
        io_method (sync/worker/io_uring) for PostgreSQL 18.

        \\b
        Examples:
            $ querysense pg18 async-io --dsn $DATABASE_URL
            $ querysense pg18 async-io --dsn $DATABASE_URL --json
        """
        from querysense.async_io_profiler import AsyncIOProfiler

        profiler = AsyncIOProfiler()
        report = asyncio.run(profiler.analyze(dsn))

        if output_json:
            console.print_json(json.dumps(report.to_dict(), default=str))
            return

        console.print(report.format_text())

        if report.top_io_queries:
            table = Table(title="Top Queries by I/O Wait")
            table.add_column("#", style="dim", width=4)
            table.add_column("I/O %", justify="right", style="red")
            table.add_column("I/O (ms)", justify="right")
            table.add_column("Total (ms)", justify="right")
            table.add_column("Cache Hit", justify="right")
            table.add_column("Query", max_width=50)

            for i, q in enumerate(report.top_io_queries[:10], 1):
                chr_color = "green" if q.cache_hit_ratio > 0.99 else "yellow" if q.cache_hit_ratio > 0.9 else "red"
                table.add_row(
                    str(i),
                    f"{q.io_wait_pct:.1f}%",
                    f"{q.blk_read_time_ms:,.0f}",
                    f"{q.total_exec_time_ms:,.0f}",
                    f"[{chr_color}]{q.cache_hit_ratio:.4f}[/{chr_color}]",
                    q.query[:50],
                )

            console.print(table)

        for finding in report.findings:
            sev = finding.get("severity", "info")
            color = {"critical": "red", "warning": "yellow", "notice": "blue"}.get(sev, "white")
            console.print(Panel(
                f"{finding['title']}\n\n[green]Fix:[/] {finding.get('fix', 'N/A')}",
                title=f"[{color}]{sev.upper()}[/{color}]",
            ))


def register_uuid_audit(parent: typer.Typer) -> None:
    """Register UUID audit command on the audit app."""

    @parent.command(name="uuids")
    def audit_uuids(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        v7: Annotated[
            bool,
            typer.Option("--v7", help="Focus on UUIDv4→v7 migration opportunities"),
        ] = False,
        generate_sql: Annotated[
            bool,
            typer.Option("--generate-sql", help="Output migration SQL script"),
        ] = False,
        output_json: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        batch_size: Annotated[
            int,
            typer.Option("--batch-size", help="Batch size for migration INSERT"),
        ] = 10000,
    ) -> None:
        """
        Audit UUID primary keys and generate UUIDv7 migration plan.

        UUIDv4 keys cause random B-tree insertions → index bloat + poor cache.
        UUIDv7 is time-sorted → sequential inserts, 30% faster INSERTs.

        \\b
        Examples:
            $ querysense audit uuids --dsn $DATABASE_URL --v7
            $ querysense audit uuids --dsn $DATABASE_URL --v7 --generate-sql > migrate.sql
        """
        from querysense.uuid_migrator import UUIDMigrator

        migrator = UUIDMigrator()
        plan = asyncio.run(migrator.analyze(dsn))

        if output_json:
            console.print_json(json.dumps(plan.to_dict(), default=str))
            return

        if generate_sql:
            console.print(plan.generate_migration_sql(batch_size=batch_size))
            return

        console.print(plan.format_text())

        if plan.columns:
            table = Table(title="UUID Primary Keys")
            table.add_column("Table", style="cyan")
            table.add_column("Column")
            table.add_column("Version", justify="center")
            table.add_column("Size (MB)", justify="right")
            table.add_column("Bloat %", justify="right")
            table.add_column("Rows", justify="right")
            table.add_column("FK Refs", justify="right")

            for col in sorted(plan.columns, key=lambda c: -c.table_size_bytes):
                if not col.is_primary_key:
                    continue
                ver_color = "red" if col.uuid_version == "v4" else "green" if col.uuid_version == "v7" else "yellow"
                table.add_row(
                    f"{col.schema}.{col.table}",
                    col.column,
                    f"[{ver_color}]{col.uuid_version}[/{ver_color}]",
                    f"{col.table_size_mb:.1f}",
                    f"{col.index_bloat_estimate_pct:.1f}%",
                    f"{col.row_count:,}",
                    str(len(col.fk_references)),
                )

            console.print(table)


def register_pool_tuner(parent: typer.Typer) -> None:
    """Register connection pool tuning command on the audit app."""

    @parent.command(name="pool")
    def audit_pool(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        pgbouncer_ini: Annotated[
            bool,
            typer.Option("--pgbouncer-ini", help="Output PgBouncer config"),
        ] = False,
        output_json: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Analyze connection usage and recommend pool configuration.

        Checks max_connections utilization, idle connection waste,
        idle-in-transaction sessions, and memory overhead. Generates
        PgBouncer configuration when requested.

        \\b
        Examples:
            $ querysense audit pool --dsn $DATABASE_URL
            $ querysense audit pool --dsn $DATABASE_URL --pgbouncer-ini > pgbouncer.ini
        """
        from querysense.connection_pool_tuner import ConnectionPoolTuner

        tuner = ConnectionPoolTuner()
        report = asyncio.run(tuner.analyze(dsn))

        if output_json:
            console.print_json(json.dumps(report.to_dict(), default=str))
            return

        if pgbouncer_ini:
            console.print(report.generate_pgbouncer_ini())
            return

        console.print(report.format_text())

        for finding in report.findings:
            sev = finding.get("severity", "info")
            color = {"critical": "red", "warning": "yellow", "notice": "blue"}.get(sev, "white")
            console.print(Panel(
                f"{finding.get('description', finding['title'])}\n\n"
                f"[green]Fix:[/] {finding.get('fix', 'N/A')}",
                title=f"[{color}]{sev.upper()}[/{color}] {finding['title']}",
            ))


def register_checkpoint_predict(parent: typer.Typer) -> None:
    """Register checkpoint prediction command on the audit app."""

    @parent.command(name="checkpoint-predict")
    def audit_checkpoint_predict(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        output_json: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Predict when checkpoints will become a bottleneck.

        Measures WAL generation rate, computes fill ratio (WAL per timeout
        vs max_wal_size), and predicts checkpoint frequency, I/O overhead,
        and days until critical.

        \\b
        Examples:
            $ querysense audit checkpoint-predict --dsn $DATABASE_URL
        """
        import asyncpg

        from querysense.audit.checkpoint_predictor import CheckpointPredictor

        async def _run():
            conn = await asyncpg.connect(dsn)
            try:
                predictor = CheckpointPredictor()
                return await predictor.predict(conn)
            finally:
                await conn.close()

        forecast = asyncio.run(_run())

        if output_json:
            console.print_json(json.dumps(forecast.to_dict(), default=str))
            return

        console.print(forecast.format_text())

        risk_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}
        color = risk_colors.get(forecast.risk_level, "white")
        console.print(Panel(
            f"[bold]Risk Level:[/] [{color}]{forecast.risk_level.upper()}[/{color}]\n"
            f"[bold]WAL Rate:[/] {forecast.wal_rate_mb_per_min:.1f} MB/min\n"
            f"[bold]Fill Ratio:[/] {forecast.fill_ratio:.2f}\n"
            f"[bold]Predicted Checkpoints/hr:[/] {forecast.predicted_checkpoints_per_hour:.1f}",
            title="Checkpoint Forecast Summary",
        ))
