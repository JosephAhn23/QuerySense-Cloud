"""
CLI commands for the audit log analysis suite.

    querysense audit checkpoints --dsn $DSN
    querysense audit deadlocks --log /var/log/postgresql/*.log
    querysense audit connections --log postgresql.log
    querysense audit tempfiles --dsn $DSN
    querysense audit vacuum-tracker --dsn $DSN
    querysense audit plan-history --dsn $DSN
    querysense audit table-health --dsn $DSN
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
from rich.tree import Tree

console = Console()
error_console = Console(stderr=True)


def register(parent: typer.Typer) -> None:
    """Register audit log commands on the audit app."""

    # ------------------------------------------------------------------
    # querysense audit checkpoints
    # ------------------------------------------------------------------

    @parent.command(name="checkpoints")
    def audit_checkpoints(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output runnable SQL fix script"),
        ] = False,
    ) -> None:
        """
        Analyze checkpoint frequency and I/O impact.

        Queries pg_stat_bgwriter to measure checkpoint frequency, WAL volume,
        and whether backends are doing excessive direct writes.

        \\b
        Examples:
            $ querysense audit checkpoints --dsn $DB_URL
            $ querysense audit checkpoints --dsn $DB_URL --fix-script | psql $DB_URL
        """
        from querysense.audit.checkpoints import CheckpointAuditor

        async def _run() -> None:
            import asyncpg  # type: ignore[import-untyped]
            conn = await asyncpg.connect(dsn)
            try:
                auditor = CheckpointAuditor()
                report = await auditor.analyze(conn)
            finally:
                await conn.close()

            if fix_script:
                for f in report.findings:
                    if f.fix_sql:
                        console.print(f"-- {f.title}")
                        console.print(f.fix_sql)
                        console.print()
                return

            if json_output:
                console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
                return

            # Rich output
            status = "[green]HEALTHY[/green]" if report.is_healthy else "[red]NEEDS ATTENTION[/red]"
            console.print(Panel.fit(
                f"[bold]Status:[/bold] {status}\n"
                f"[bold]Frequency:[/bold] every {report.checkpoint_frequency_seconds:.0f}s "
                f"({report.checkpoints_per_hour:.1f}/hour)\n"
                f"[bold]Total checkpoints:[/bold] {report.total_checkpoints}\n"
                f"[bold]Forced (requested):[/bold] {report.pct_requested:.0f}%\n"
                f"[bold]Backend direct writes:[/bold] {report.buffers_backend_pct:.0f}%",
                title="Checkpoint Analysis",
                border_style="blue",
            ))

            if report.current_settings:
                console.print("\n[bold]Current Settings:[/bold]")
                for k, v in report.current_settings.items():
                    console.print(f"  {k} = {v}")

            if report.findings:
                console.print()
                for f in report.findings:
                    sev_color = {"critical": "red", "warning": "yellow"}.get(f.severity, "dim")
                    console.print(f"[{sev_color}][{f.severity.upper()}][/{sev_color}] {f.title}")
                    console.print(f"  {f.description}")
                    if f.fix_sql:
                        console.print(f"  [green]Fix:[/green] {f.fix_sql.splitlines()[0]}")

            if report.recommended_settings:
                console.print("\n[bold]Recommended Changes:[/bold]")
                for k, v in report.recommended_settings.items():
                    current = report.current_settings.get(k, "?")
                    console.print(f"  {k}: {current} -> [green]{v}[/green]")

        asyncio.run(_run())

    # ------------------------------------------------------------------
    # querysense audit deadlocks
    # ------------------------------------------------------------------

    @parent.command(name="deadlocks")
    def audit_deadlocks(
        log_file: Annotated[
            str,
            typer.Option("--log", "-l", help="Path to PostgreSQL log file"),
        ] = "",
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN (for live deadlock count)", envvar="QUERYSENSE_DSN"),
        ] = "",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Analyze deadlocks from PostgreSQL logs or live database.

        Parses log files for deadlock events, builds dependency graphs,
        detects patterns, and suggests fixes.

        \\b
        Examples:
            $ querysense audit deadlocks --log /var/log/postgresql/postgresql.log
            $ querysense audit deadlocks --dsn $DB_URL
        """
        if log_file:
            from querysense.audit.deadlocks import DeadlockParser

            parser = DeadlockParser()
            log_path = Path(log_file)
            if not log_path.exists():
                # Try glob
                report = parser.analyze_file(log_path)
            else:
                report = parser.analyze_file(log_path)

            if json_output:
                console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
                return

            if not report.deadlocks:
                console.print("[green]No deadlocks found in log file.[/green]")
                return

            console.print(Panel.fit(
                f"[bold]Total deadlocks:[/bold] {report.total_count}\n"
                f"[bold]Time range:[/bold] {report.time_range}",
                title="Deadlock Analysis",
                border_style="red",
            ))

            for i, dl in enumerate(report.deadlocks[:10], 1):
                console.print(f"\n[bold red]Deadlock #{i}[/bold red] ({dl.timestamp})")
                console.print(f"  Cycle: {dl.cycle_description}")
                console.print(f"  Tables: {', '.join(dl.tables_involved) or 'unknown'}")
                for p in dl.processes:
                    console.print(f"  PID {p.pid}: {p.query[:100] or 'N/A'}")

            if report.patterns:
                console.print("\n[bold]Patterns Detected:[/bold]")
                for p in report.patterns:
                    console.print(f"  {p.description}")
                    console.print(f"  [green]Fix:[/green] {p.fix_suggestion}")

        elif dsn:
            # Live deadlock count from pg_stat_database
            async def _run() -> None:
                import asyncpg  # type: ignore[import-untyped]
                conn = await asyncpg.connect(dsn)
                try:
                    rows = await conn.fetch(
                        "SELECT datname, deadlocks FROM pg_stat_database "
                        "WHERE deadlocks > 0 ORDER BY deadlocks DESC"
                    )
                finally:
                    await conn.close()

                if json_output:
                    data = [{"database": str(r[0]), "deadlocks": int(r[1])} for r in rows]
                    console.print_json(json.dumps(data, indent=2))
                    return

                if not rows:
                    console.print("[green]No deadlocks recorded since stats reset.[/green]")
                    return

                table = Table(title="Deadlock Counts (since stats reset)")
                table.add_column("Database", style="cyan")
                table.add_column("Deadlocks", justify="right", style="red bold")
                for r in rows:
                    table.add_row(str(r[0]), str(r[1]))
                console.print(table)
                console.print("\n[dim]For detailed analysis, use --log with a PostgreSQL log file.[/dim]")

            asyncio.run(_run())
        else:
            error_console.print("[red]Error:[/red] Provide --log or --dsn")
            raise typer.Exit(code=1)

    # ------------------------------------------------------------------
    # querysense audit connections
    # ------------------------------------------------------------------

    @parent.command(name="connections")
    def audit_connections(
        log_file: Annotated[
            str,
            typer.Option("--log", "-l", help="Path to PostgreSQL log file"),
        ] = "",
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN (for live analysis)", envvar="QUERYSENSE_DSN"),
        ] = "",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Audit connection events for security and compliance.

        Detects authentication failures, brute force attempts,
        credential scanning, and unusual connection patterns.

        \\b
        Examples:
            $ querysense audit connections --log /var/log/postgresql/postgresql.log
            $ querysense audit connections --dsn $DB_URL
        """
        from querysense.audit.connections import ConnectionAuditor

        auditor = ConnectionAuditor()

        if log_file:
            report = auditor.analyze_file(log_file)
        elif dsn:
            async def _run():
                import asyncpg
                conn = await asyncpg.connect(dsn)
                try:
                    return await auditor.analyze_live(conn)
                finally:
                    await conn.close()
            report = asyncio.run(_run())
        else:
            error_console.print("[red]Error:[/red] Provide --log or --dsn")
            raise typer.Exit(code=1)

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        status = "[green]CLEAN[/green]" if report.is_clean else "[red]ISSUES FOUND[/red]"
        console.print(Panel.fit(
            f"[bold]Status:[/bold] {status}\n"
            f"[bold]Total connections:[/bold] {report.summary.total_connections}\n"
            f"[bold]Auth failures:[/bold] [red]{report.summary.total_auth_failures}[/red]\n"
            f"[bold]Unique users:[/bold] {report.summary.unique_users}\n"
            f"[bold]Unique IPs:[/bold] {report.summary.unique_client_ips}",
            title="Connection Audit",
            border_style="blue",
        ))

        if report.auth_failures:
            console.print(f"\n[bold red]Authentication Failures ({len(report.auth_failures)}):[/bold red]")
            table = Table()
            table.add_column("Time")
            table.add_column("User", style="cyan")
            table.add_column("IP", style="yellow")
            table.add_column("Reason")
            for f in report.auth_failures[:20]:
                table.add_row(
                    str(f.timestamp)[:19] if f.timestamp else "",
                    f.user,
                    f.client_addr,
                    f.reason[:60],
                )
            console.print(table)

        for f in report.findings:
            sev_color = {"critical": "red", "warning": "yellow"}.get(f.severity, "dim")
            console.print(f"\n[{sev_color}][{f.severity.upper()}][/{sev_color}] {f.title}")
            console.print(f"  {f.recommendation}")

    # ------------------------------------------------------------------
    # querysense audit tempfiles
    # ------------------------------------------------------------------

    @parent.command(name="tempfiles")
    def audit_tempfiles(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "",
        log_file: Annotated[
            str,
            typer.Option("--log", "-l", help="Path to PostgreSQL log file"),
        ] = "",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output runnable SQL fix"),
        ] = False,
    ) -> None:
        """
        Detect queries spilling to temporary files.

        When work_mem is too low, sorts and hash operations create temp files
        that are 10-100x slower than in-memory operations.

        \\b
        Examples:
            $ querysense audit tempfiles --dsn $DB_URL
            $ querysense audit tempfiles --log /var/log/postgresql/postgresql.log
        """
        from querysense.audit.tempfiles import TempFileAuditor

        auditor = TempFileAuditor()

        if dsn:
            async def _run():
                import asyncpg
                conn = await asyncpg.connect(dsn)
                try:
                    return await auditor.analyze_live(conn)
                finally:
                    await conn.close()
            report = asyncio.run(_run())
        elif log_file:
            report = auditor.analyze_file(log_file)
        else:
            error_console.print("[red]Error:[/red] Provide --dsn or --log")
            raise typer.Exit(code=1)

        if fix_script:
            for f in report.findings:
                if f.fix_sql:
                    console.print(f"-- {f.title}")
                    console.print(f.fix_sql)
                    console.print()
            return

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        status = "[green]HEALTHY[/green]" if report.is_healthy else "[yellow]NEEDS ATTENTION[/yellow]"
        console.print(Panel.fit(
            f"[bold]Status:[/bold] {status}\n"
            f"[bold]Temp files:[/bold] {report.total_temp_files:,}\n"
            f"[bold]Total size:[/bold] {report.total_temp_mb:.0f}MB\n"
            f"[bold]work_mem:[/bold] {report.current_work_mem or 'N/A'}",
            title="Temp File Analysis",
            border_style="blue",
        ))

        if report.databases:
            table = Table(title="Temp Files by Database")
            table.add_column("Database", style="cyan")
            table.add_column("Files", justify="right")
            table.add_column("Size", justify="right")
            for db, stats in report.databases.items():
                table.add_row(
                    db,
                    f"{stats['files']:,}",
                    f"{stats['bytes'] / (1024 * 1024):.0f}MB",
                )
            console.print(table)

        if report.events:
            console.print("\n[bold]Top Queries Creating Temp Files:[/bold]")
            for ev in report.events[:5]:
                size_mb = ev.size_bytes / (1024 * 1024)
                console.print(f"  [{size_mb:.0f}MB] {ev.query[:80]}...")

        for f in report.findings:
            sev_color = {"critical": "red", "warning": "yellow"}.get(f.severity, "dim")
            console.print(f"\n[{sev_color}][{f.severity.upper()}][/{sev_color}] {f.title}")
            console.print(f"  {f.recommendation}")

    # ------------------------------------------------------------------
    # querysense audit vacuum-tracker
    # ------------------------------------------------------------------

    @parent.command(name="vacuum-tracker")
    def audit_vacuum_tracker(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output runnable SQL fix script"),
        ] = False,
        top: Annotated[
            int,
            typer.Option("--top", "-n", help="Show top N tables"),
        ] = 20,
    ) -> None:
        """
        Per-table autovacuum threshold analysis.

        Shows whether vacuum will trigger for each table, how far each is
        from the threshold, and recommends scale_factor tuning for large tables
        where the default 0.2 means vacuum may never trigger.

        This is the exact problem pganalyze solved for Autotrader UK: a 135M row
        table where autovacuum never ran because the default threshold was too high.

        \\b
        Examples:
            $ querysense audit vacuum-tracker --dsn $DB_URL
            $ querysense audit vacuum-tracker --dsn $DB_URL --fix-script | psql $DB_URL
        """
        from querysense.audit.vacuum_tracker import VacuumTracker

        async def _run():
            import asyncpg
            conn = await asyncpg.connect(dsn)
            try:
                tracker = VacuumTracker()
                return await tracker.analyze(conn)
            finally:
                await conn.close()

        report = asyncio.run(_run())

        if fix_script:
            for finding in report.findings:
                if finding.fix_sql:
                    console.print(f"-- {finding.title}")
                    console.print(finding.fix_sql)
                    console.print()
            return

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        status = "[green]HEALTHY[/green]" if report.is_healthy else "[yellow]NEEDS ATTENTION[/yellow]"
        console.print(Panel.fit(
            f"[bold]Status:[/bold] {status}\n"
            f"[bold]Tables analyzed:[/bold] {len(report.tables)}\n"
            f"[bold]Total dead tuples:[/bold] {report.total_dead_tuples:,}\n"
            f"[bold]Tables needing vacuum:[/bold] [red]{report.tables_needing_vacuum}[/red]\n"
            f"[bold]Large tables at risk:[/bold] [yellow]{report.tables_vacuum_never_triggers}[/yellow]",
            title="Autovacuum Threshold Analysis",
            border_style="blue",
        ))

        if report.global_settings:
            console.print("\n[bold]Global Settings:[/bold]")
            for k, v in report.global_settings.items():
                console.print(f"  {k} = {v}")

        tbl = Table(title=f"Top {top} Tables by Vacuum Urgency")
        tbl.add_column("Table", style="cyan")
        tbl.add_column("Rows", justify="right")
        tbl.add_column("Dead", justify="right")
        tbl.add_column("Threshold", justify="right")
        tbl.add_column("% to Trigger", justify="right")
        tbl.add_column("Scale Factor")
        tbl.add_column("Status")

        for t in report.tables[:top]:
            pct_color = "red" if t.pct_to_threshold >= 90 else "yellow" if t.pct_to_threshold >= 50 else "green"
            grade_color = "red" if t.severity == "critical" else "yellow" if t.severity == "warning" else "green"

            tbl.add_row(
                t.qualified_name,
                f"{t.n_live_tup:,}",
                f"{t.n_dead_tup:,}",
                f"{t.vacuum_trigger_threshold:,}",
                f"[{pct_color}]{t.pct_to_threshold:.0f}%[/{pct_color}]",
                f"{t.vacuum_scale_factor}" + (
                    f" -> [green]{t.recommended_scale_factor}[/green]"
                    if t.recommended_scale_factor else ""
                ),
                f"[{grade_color}]{t.severity.upper()}[/{grade_color}]",
            )
        console.print(tbl)

        for finding in report.findings:
            sev_color = {"critical": "red", "warning": "yellow"}.get(finding.severity, "dim")
            console.print(f"\n[{sev_color}][{finding.severity.upper()}][/{sev_color}] {finding.title}")
            console.print(f"  {finding.recommendation}")
            if finding.fix_sql:
                console.print(f"  [green]Fix:[/green] {finding.fix_sql.splitlines()[0]}")

    # ------------------------------------------------------------------
    # querysense audit plan-history
    # ------------------------------------------------------------------

    @parent.command(name="plan-history")
    def audit_plan_history(
        storage: Annotated[
            str,
            typer.Option("--storage", "-s", help="Path to plan history JSON file"),
        ] = "plan_history.json",
        cost_threshold: Annotated[
            float,
            typer.Option("--cost-threshold", help="Cost increase % to flag as regression"),
        ] = 50.0,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Detect EXPLAIN plan regressions over time.

        Compares stored plan snapshots to detect cost increases,
        plan type changes, and query instability.

        Record plans with: querysense audit plan-record --dsn $DB_URL --query "SELECT ..."
        Then detect regressions with this command.

        \\b
        Examples:
            $ querysense audit plan-history
            $ querysense audit plan-history --cost-threshold 25
        """
        from querysense.audit.plan_history import PlanHistoryTracker

        tracker = PlanHistoryTracker(storage)
        report = tracker.detect_regressions(cost_threshold_pct=cost_threshold)

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        console.print(Panel.fit(
            f"[bold]Tracked queries:[/bold] {report.total_queries}\n"
            f"[bold]Total snapshots:[/bold] {report.total_snapshots}\n"
            f"[bold]Regressions:[/bold] [red]{len(report.regressions)}[/red]\n"
            f"[bold]Improved:[/bold] [green]{len(report.improved)}[/green]\n"
            f"[bold]Unstable plans:[/bold] {len(report.unstable)}",
            title="EXPLAIN Plan History",
            border_style="blue",
        ))

        if report.regressions:
            console.print("\n[bold red]Regressions:[/bold red]")
            for reg in report.regressions:
                sev_color = "red" if reg.severity == "critical" else "yellow"
                console.print(f"  [{sev_color}]{reg.title}[/{sev_color}]")
                console.print(f"    {reg.description}")
                if reg.before and reg.after:
                    console.print(
                        f"    Before: cost={reg.before.total_cost:.0f} "
                        f"time={reg.before.actual_time_ms:.1f}ms "
                        f"({reg.before.plan_type})"
                    )
                    console.print(
                        f"    After:  cost={reg.after.total_cost:.0f} "
                        f"time={reg.after.actual_time_ms:.1f}ms "
                        f"({reg.after.plan_type})"
                    )

        if report.improved:
            console.print("\n[bold green]Improved:[/bold green]")
            for imp in report.improved:
                console.print(f"  [green]{imp.title}[/green]")

        if report.unstable:
            console.print(f"\n[bold yellow]Unstable plans ({len(report.unstable)}):[/bold yellow]")
            for qh in report.unstable[:10]:
                console.print(f"  Query {qh[:8]}: plan type keeps changing")

        if not report.regressions and not report.improved:
            console.print("\n[green]No regressions detected.[/green]")

    @parent.command(name="plan-record")
    def audit_plan_record(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        query: Annotated[
            str,
            typer.Option("--query", "-q", help="SQL query to explain and record"),
        ] = "",
        storage: Annotated[
            str,
            typer.Option("--storage", "-s", help="Path to plan history JSON file"),
        ] = "plan_history.json",
    ) -> None:
        """
        Record an EXPLAIN ANALYZE plan snapshot for regression tracking.

        \\b
        Examples:
            $ querysense audit plan-record --dsn $DB_URL -q "SELECT * FROM orders WHERE status = 'pending'"
        """
        if not query:
            error_console.print("[red]Error:[/red] --query is required")
            raise typer.Exit(code=1)

        from querysense.audit.plan_history import PlanHistoryTracker, capture_plan

        async def _run():
            import asyncpg
            conn = await asyncpg.connect(dsn)
            try:
                plans = await capture_plan(conn, query)
                tracker = PlanHistoryTracker(storage)
                plan = plans[0] if plans else {}
                return tracker.record(query, plan)
            finally:
                await conn.close()

        snapshot = asyncio.run(_run())
        console.print(f"[green]Recorded plan snapshot for query {snapshot.query_hash[:8]}[/green]")
        console.print(f"  Cost: {snapshot.total_cost:.0f}")
        console.print(f"  Time: {snapshot.actual_time_ms:.1f}ms")
        console.print(f"  Plan: {snapshot.plan_type}")
        console.print(f"  Stored in: {storage}")

    # ------------------------------------------------------------------
    # querysense audit table-health
    # ------------------------------------------------------------------

    @parent.command(name="table-health")
    def audit_table_health(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        top: Annotated[
            int,
            typer.Option("--top", "-n", help="Show top N tables"),
        ] = 30,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output runnable SQL fix script"),
        ] = False,
    ) -> None:
        """
        Per-table health dashboard with A-F grades.

        Shows every table's size, live/dead tuples, index usage ratio,
        modification rate, vacuum history, and assigns A-F health grades.

        \\b
        Examples:
            $ querysense audit table-health --dsn $DB_URL
            $ querysense audit table-health --dsn $DB_URL --top 50
        """
        from querysense.audit.table_health import TableHealthDashboard

        async def _run():
            import asyncpg
            conn = await asyncpg.connect(dsn)
            try:
                dashboard = TableHealthDashboard()
                return await dashboard.analyze(conn)
            finally:
                await conn.close()

        report = asyncio.run(_run())

        if fix_script:
            for finding in report.findings:
                if finding.fix_sql:
                    console.print(f"-- {finding.title}")
                    console.print(finding.fix_sql)
                    console.print()
            return

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        grades = report.grade_distribution
        console.print(Panel.fit(
            f"[bold]Tables:[/bold] {report.total_tables}\n"
            f"[bold]Total size:[/bold] {report.total_size_mb:.0f}MB\n"
            f"[bold]Grades:[/bold] "
            f"[green]A={grades.get('A', 0)}[/green] "
            f"[green]B={grades.get('B', 0)}[/green] "
            f"[yellow]C={grades.get('C', 0)}[/yellow] "
            f"[red]D={grades.get('D', 0)}[/red] "
            f"[red bold]F={grades.get('F', 0)}[/red bold]",
            title="Table Health Dashboard",
            border_style="blue",
        ))

        tbl = Table(title=f"Top {top} Tables (worst first)")
        tbl.add_column("Grade", justify="center")
        tbl.add_column("Table", style="cyan")
        tbl.add_column("Size", justify="right")
        tbl.add_column("Live", justify="right")
        tbl.add_column("Dead", justify="right")
        tbl.add_column("Dead%", justify="right")
        tbl.add_column("Idx Usage", justify="right")
        tbl.add_column("Mods/hr", justify="right")
        tbl.add_column("Last Vacuum")

        for t in report.tables[:top]:
            gc = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red bold"}
            grade_style = gc.get(t.health_grade, "dim")
            dead_pct = f"{t.dead_tuple_ratio:.0%}" if t.dead_tuple_ratio > 0 else "0%"
            dead_color = "red" if t.dead_tuple_ratio > 0.2 else "yellow" if t.dead_tuple_ratio > 0.1 else "green"
            idx_color = "red" if t.index_usage_ratio < 0.5 else "yellow" if t.index_usage_ratio < 0.8 else "green"
            last_vac = t.last_autovacuum or t.last_vacuum or "[red]never[/red]"
            if last_vac and len(last_vac) > 19:
                last_vac = last_vac[:19]

            tbl.add_row(
                f"[{grade_style}]{t.health_grade}[/{grade_style}]",
                t.qualified_name,
                f"{t.table_size_mb:.0f}MB",
                f"{t.n_live_tup:,}",
                f"{t.n_dead_tup:,}",
                f"[{dead_color}]{dead_pct}[/{dead_color}]",
                f"[{idx_color}]{t.index_usage_ratio:.0%}[/{idx_color}]",
                f"{t.modifications_per_hour:,.0f}",
                last_vac,
            )
        console.print(tbl)

        if report.findings:
            console.print(f"\n[bold]Findings ({len(report.findings)}):[/bold]")
            for finding in report.findings[:15]:
                sev_color = {"critical": "red", "warning": "yellow", "notice": "dim"}.get(finding.severity, "dim")
                console.print(f"  [{sev_color}][{finding.severity.upper()}][/{sev_color}] {finding.title}")
                if finding.fix_sql:
                    console.print(f"    [green]Fix:[/green] {finding.fix_sql.splitlines()[0]}")

    # ------------------------------------------------------------------
    # querysense audit cost-model
    # ------------------------------------------------------------------

    @parent.command(name="cost-model")
    def audit_cost_model(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output ALTER SYSTEM SQL script"),
        ] = False,
    ) -> None:
        """
        Calibrate PostgreSQL cost model against actual storage.

        Connects to the database, detects storage type (NVMe SSD, SATA SSD,
        HDD, cloud EBS), and recommends optimal random_page_cost, seq_page_cost,
        and effective_io_concurrency settings.

        Based on pganalyze "Best Practices" (p.5-6): "random_page_cost=4.0
        assumes spinning disks. On SSDs, set it to 1.1."

        \b
        Examples:
            $ querysense audit cost-model --dsn postgresql://localhost/mydb
            $ querysense audit cost-model --dsn $DB_URL --fix-script | psql $DB_URL
        """
        from querysense.audit.cost_model import CostModelAuditor

        auditor = CostModelAuditor()
        report = asyncio.run(auditor.audit(dsn))

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        if fix_script:
            console.print(report.fix_script)
            return

        storage = report.storage
        color = "green" if not report.needs_changes else "yellow"
        console.print(Panel(
            f"[bold]COST MODEL CALIBRATION[/bold]\n\n"
            f"PostgreSQL {report.pg_version}\n"
            f"shared_buffers: {report.shared_buffers}\n"
            f"effective_cache_size: {report.effective_cache_size}\n\n"
            f"[bold]Storage Detection:[/bold]\n"
            f"  Type: [{color}]{storage.storage_type}[/{color}]\n"
            f"  Method: {storage.detection_method}\n"
            f"  Random/Seq Ratio: {storage.random_seq_ratio:.1f}x\n"
            f"  Issues: {report.total_issues}",
            title="Cost Model Audit",
            border_style=color,
        ))

        tbl = Table(title="Cost Settings")
        tbl.add_column("Setting", style="cyan")
        tbl.add_column("Current", justify="right")
        tbl.add_column("Recommended", justify="right")
        tbl.add_column("Action", max_width=40)

        for s in report.settings:
            if s.needs_change:
                tbl.add_row(
                    s.name,
                    f"[red]{s.current_value}[/red]",
                    f"[green]{s.recommended_value}[/green]",
                    s.reason[:40],
                )
            else:
                tbl.add_row(
                    s.name,
                    f"[green]{s.current_value}[/green]",
                    s.recommended_value,
                    "[dim]OK[/dim]",
                )

        console.print(tbl)

        if report.needs_changes:
            console.print(
                "\n[bold]Run [cyan]querysense audit cost-model --dsn $DSN --fix-script | psql $DSN[/cyan] "
                "to apply changes.[/bold]"
            )

    # ------------------------------------------------------------------
    # querysense audit dependencies (focused per-column-pair)
    # ------------------------------------------------------------------

    @parent.command(name="dependencies")
    def audit_dependencies(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        table: Annotated[
            str,
            typer.Option("--table", "-t", help="Table to analyze"),
        ] = "",
        columns: Annotated[
            str,
            typer.Option("--columns", "-c", help="Comma-separated columns to check"),
        ] = "",
        schema: Annotated[
            str,
            typer.Option("--schema", help="Schema name"),
        ] = "public",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output CREATE STATISTICS SQL"),
        ] = False,
    ) -> None:
        """
        Detect functional dependencies between specific columns.

        Samples actual data to find correlations that cause the planner
        to produce wrong row estimates (assuming column independence).
        Generates CREATE STATISTICS to fix estimation errors.

        Based on pganalyze "Best Practices" (p.6-7): the 20,000%%
        improvement from fixing correlated column estimates.

        \b
        Examples:
            $ querysense audit dependencies --table orders --columns user_id,status --dsn $DB_URL
            $ querysense audit dependencies --table events --columns org_id,type,action --fix-script
        """
        if not table or not columns:
            error_console.print(
                "[red]Error:[/red] --table and --columns are required.\n"
                "Example: querysense audit dependencies --table orders --columns user_id,status"
            )
            raise typer.Exit(1)

        from querysense.audit.dependencies import ColumnDependencyDetector

        col_list = [c.strip() for c in columns.split(",") if c.strip()]
        if len(col_list) < 2:
            error_console.print("[red]Error:[/red] Need at least 2 columns.")
            raise typer.Exit(1)

        detector = ColumnDependencyDetector()
        report = asyncio.run(detector.analyze(dsn, table, col_list, schema))

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        if fix_script:
            console.print(report.create_stats_sql)
            return

        console.print(Panel(
            f"[bold]COLUMN DEPENDENCY ANALYSIS[/bold]\n\n"
            f"Table: {schema}.{table} ({report.row_count:,} rows)\n"
            f"Columns: {', '.join(col_list)}\n"
            f"Correlations found: {sum(1 for p in report.pair_analyses if p.has_correlation)}",
            title="Dependency Detector",
            border_style="cyan" if report.has_correlations else "green",
        ))

        for pair in report.pair_analyses:
            if pair.has_correlation:
                sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(pair.severity, "dim")
                console.print(
                    f"\n[{sev_color}][{pair.severity}][/{sev_color}] "
                    f"[bold]{pair.col_a} <-> {pair.col_b}[/bold]: "
                    f"[{sev_color}]{pair.overestimate_ratio:.0f}x overestimate[/{sev_color}]"
                )
                console.print(
                    f"  Distinct: {pair.col_a}={pair.distinct_a:,}, "
                    f"{pair.col_b}={pair.distinct_b:,}, "
                    f"combined={pair.distinct_combined:,}"
                )
                console.print(
                    f"  Independence estimate: {pair.independent_estimate:,} "
                    f"(actual: {pair.distinct_combined:,})"
                )
                console.print(
                    f"  Dependency degree: {pair.dependency_degree:.0%}"
                )

                if pair.is_functionally_dependent:
                    console.print(
                        f"  [bold cyan]Functional dependency:[/bold cyan] "
                        f"{pair.col_a} -> {pair.col_b}"
                    )

                if pair.top_combinations:
                    console.print("  Top combinations:")
                    for combo in pair.top_combinations[:3]:
                        console.print(
                            f"    {pair.col_a}={combo['a']}, "
                            f"{pair.col_b}={combo['b']}: "
                            f"{combo['count']:,} rows ({combo['pct']:.1f}%)"
                        )
            else:
                console.print(
                    f"\n[green]OK[/green] {pair.col_a} <-> {pair.col_b}: "
                    f"ratio={pair.overestimate_ratio:.1f}x (independent)"
                )

        if report.has_correlations:
            console.print("\n[bold]Recommendation:[/bold]")
            console.print(f"[green]{report.create_stats_sql}[/green]")

            max_ratio = max(p.overestimate_ratio for p in report.pair_analyses if p.has_correlation)
            console.print(
                f"\n[bold]Expected improvement:[/bold] up to {max_ratio:.0f}x for affected queries"
            )

        if report.existing_stats:
            console.print(f"\n[dim]Existing extended statistics: {', '.join(report.existing_stats)}[/dim]")

    # ------------------------------------------------------------------
    # querysense audit gin
    # ------------------------------------------------------------------

    @parent.command(name="gin")
    def audit_gin(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output runnable SQL fix script"),
        ] = False,
    ) -> None:
        """
        GIN/JSONB index advisor — detect suboptimal operator classes.

        Finds GIN indexes using the default jsonb_ops operator class on JSONB
        columns. If queries only use @> containment, switching to jsonb_path_ops
        can give 2-8x speedups (Notion saw 733% improvement).

        \\b
        Examples:
            $ querysense audit gin --dsn $DB_URL
            $ querysense audit gin --fix-script | psql $DB_URL
        """
        from querysense.audit.gin_advisor import GINIndexAdvisor

        async def _run():
            import asyncpg
            conn = await asyncpg.connect(dsn)
            try:
                advisor = GINIndexAdvisor()
                return await advisor.analyze(conn)
            finally:
                await conn.close()

        report = asyncio.run(_run())

        if fix_script:
            for finding in report.findings:
                if finding.fix_sql:
                    console.print(f"-- {finding.title}")
                    console.print(finding.fix_sql)
                    console.print()
            return

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        status = "[green]HEALTHY[/green]" if report.is_healthy else "[yellow]NEEDS ATTENTION[/yellow]"
        console.print(Panel.fit(
            f"[bold]Status:[/bold] {status}\n"
            f"[bold]GIN indexes:[/bold] {report.total_gin_indexes}\n"
            f"[bold]Total size:[/bold] {report.total_gin_size_mb:.0f}MB\n"
            f"[bold]Suboptimal operator class:[/bold] "
            f"[yellow]{report.suboptimal_opclass_count}[/yellow]\n"
            f"[bold]Unused:[/bold] [red]{report.unused_count}[/red]",
            title="GIN/JSONB Index Advisor",
            border_style="blue",
        ))

        if report.indexes:
            tbl = Table(title="GIN Indexes")
            tbl.add_column("Index", style="cyan")
            tbl.add_column("Table")
            tbl.add_column("Size", justify="right")
            tbl.add_column("Scans", justify="right")
            tbl.add_column("OpClass")
            tbl.add_column("Status")

            for idx in report.indexes:
                opclass_style = "red" if idx.uses_default_jsonb_ops else "green"
                status_style = "red" if idx.is_unused else "green"

                tbl.add_row(
                    idx.index_name,
                    idx.qualified_table,
                    f"{idx.index_size_mb:.0f}MB",
                    f"{idx.idx_scan:,}",
                    f"[{opclass_style}]{idx.operator_class}[/{opclass_style}]",
                    f"[{status_style}]{'UNUSED' if idx.is_unused else 'active'}[/{status_style}]",
                )
            console.print(tbl)

        for finding in report.findings:
            sev_color = {"critical": "red", "warning": "yellow"}.get(finding.severity, "dim")
            console.print(f"\n[{sev_color}][{finding.severity.upper()}][/{sev_color}] {finding.title}")
            console.print(f"  {finding.recommendation}")
            if finding.impact_estimate:
                console.print(f"  [green]Impact:[/green] {finding.impact_estimate}")

    # ------------------------------------------------------------------
    # querysense audit query-load
    # ------------------------------------------------------------------

    @parent.command(name="query-load")
    def audit_query_load(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        top: Annotated[
            int,
            typer.Option("--top", "-n", help="Show top N queries"),
        ] = 15,
        by_table: Annotated[
            bool,
            typer.Option("--by-table", help="Show load grouped by table"),
        ] = False,
    ) -> None:
        """
        Query workload profiler — top queries by % of total CPU time.

        Shows which queries consume what percentage of total database time,
        identifies resource hogs, and provides table-level workload attribution.

        \\b
        Examples:
            $ querysense audit query-load --dsn $DB_URL
            $ querysense audit query-load --dsn $DB_URL --by-table
        """
        from querysense.audit.query_load import QueryLoadProfiler

        async def _run():
            import asyncpg
            conn = await asyncpg.connect(dsn)
            try:
                profiler = QueryLoadProfiler(top_n=top)
                return await profiler.analyze(conn)
            finally:
                await conn.close()

        report = asyncio.run(_run())

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        console.print(Panel.fit(
            f"[bold]Unique queries:[/bold] {report.total_queries}\n"
            f"[bold]Total calls:[/bold] {report.total_calls:,}\n"
            f"[bold]Total CPU time:[/bold] {report.total_time_ms / 1000:.0f}s",
            title="Query Load Profile",
            border_style="blue",
        ))

        if by_table and report.table_load:
            tbl = Table(title="Load by Table")
            tbl.add_column("Table", style="cyan")
            tbl.add_column("% Time", justify="right")
            tbl.add_column("Queries", justify="right")
            tbl.add_column("Calls", justify="right")
            tbl.add_column("Time", justify="right")

            for t in report.table_load[:top]:
                pct_color = "red" if t.pct_total_time > 30 else "yellow" if t.pct_total_time > 10 else "green"
                tbl.add_row(
                    t.table,
                    f"[{pct_color}]{t.pct_total_time:.1f}%[/{pct_color}]",
                    str(t.query_count),
                    f"{t.total_calls:,}",
                    f"{t.total_time_ms / 1000:.1f}s",
                )
            console.print(tbl)
        elif report.top_by_time:
            tbl = Table(title=f"Top {top} Queries by Total Time")
            tbl.add_column("% Time", justify="right")
            tbl.add_column("Calls", justify="right")
            tbl.add_column("Mean", justify="right")
            tbl.add_column("Max", justify="right")
            tbl.add_column("Query")

            for q in report.top_by_time[:top]:
                pct_color = "red" if q.pct_total_time > 20 else "yellow" if q.pct_total_time > 5 else "green"
                tbl.add_row(
                    f"[{pct_color}]{q.pct_total_time:.1f}%[/{pct_color}]",
                    f"{q.calls:,}",
                    f"{q.mean_time_ms:.1f}ms",
                    f"{q.max_time_ms:.0f}ms",
                    q.query[:70] + ("..." if len(q.query) > 70 else ""),
                )
            console.print(tbl)

        for finding in report.findings:
            sev_color = {"critical": "red", "warning": "yellow"}.get(finding.severity, "dim")
            console.print(f"\n[{sev_color}][{finding.severity.upper()}][/{sev_color}] {finding.title}")
            console.print(f"  {finding.description}")

    # ------------------------------------------------------------------
    # querysense audit index-bloat
    # ------------------------------------------------------------------

    @parent.command(name="index-bloat")
    def audit_index_bloat(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL DSN", envvar="QUERYSENSE_DSN"),
        ] = "postgresql://localhost:5432/postgres",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="JSON output"),
        ] = False,
        fix_script: Annotated[
            bool,
            typer.Option("--fix-script", help="Output runnable SQL fix script"),
        ] = False,
        top: Annotated[
            int,
            typer.Option("--top", "-n", help="Show top N indexes"),
        ] = 20,
    ) -> None:
        """
        Index bloat impact calculator — quantify the cost of each index.

        Shows per-index bloat estimates, write overhead costs (writes/hour),
        and potential storage savings from dropping unused indexes or reindexing.

        \\b
        Examples:
            $ querysense audit index-bloat --dsn $DB_URL
            $ querysense audit index-bloat --fix-script | psql $DB_URL
        """
        from querysense.audit.index_bloat import IndexBloatCalculator

        async def _run():
            import asyncpg
            conn = await asyncpg.connect(dsn)
            try:
                calc = IndexBloatCalculator()
                return await calc.analyze(conn)
            finally:
                await conn.close()

        report = asyncio.run(_run())

        if fix_script:
            for finding in report.findings:
                if finding.fix_sql:
                    console.print(f"-- {finding.title}")
                    console.print(finding.fix_sql)
                    console.print()
            return

        if json_output:
            console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
            return

        console.print(Panel.fit(
            f"[bold]Total indexes:[/bold] {report.total_indexes}\n"
            f"[bold]Total index size:[/bold] {report.total_index_size_mb:.0f}MB\n"
            f"[bold]Estimated bloat:[/bold] [yellow]{report.total_bloat_mb:.0f}MB[/yellow]\n"
            f"[bold]Unused indexes:[/bold] [red]{report.unused_count} "
            f"({report.unused_size_mb:.0f}MB)[/red]\n"
            f"[bold]Potential savings:[/bold] [green]{report.potential_savings_mb:.0f}MB[/green]",
            title="Index Bloat Impact",
            border_style="blue",
        ))

        tbl = Table(title=f"Top {top} Indexes by Cost Score")
        tbl.add_column("Index", style="cyan")
        tbl.add_column("Table")
        tbl.add_column("Size", justify="right")
        tbl.add_column("Bloat", justify="right")
        tbl.add_column("Scans", justify="right")
        tbl.add_column("Writes/hr", justify="right")
        tbl.add_column("Status")

        for e in report.indexes[:top]:
            if e.is_primary:
                status = "[blue]PK[/blue]"
            elif e.is_unique:
                status = "[blue]UQ[/blue]"
            elif e.is_unused:
                status = "[red]UNUSED[/red]"
            else:
                status = "[green]active[/green]"

            bloat_color = "red" if e.estimated_bloat_ratio > 0.5 else "yellow" if e.estimated_bloat_ratio > 0.2 else "green"

            tbl.add_row(
                e.index_name[:30],
                e.table,
                f"{e.index_size_mb:.0f}MB",
                f"[{bloat_color}]{e.bloat_mb:.0f}MB[/{bloat_color}]",
                f"{e.idx_scan:,}",
                f"{e.writes_per_hour:,.0f}",
                status,
            )
        console.print(tbl)

        for finding in report.findings[:10]:
            sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(finding.severity, "dim")
            console.print(f"\n[{sev_color}][{finding.severity.upper()}][/{sev_color}] {finding.title}")
            if finding.savings_mb > 0:
                console.print(f"  [green]Savings: {finding.savings_mb:.0f}MB[/green]")
            if finding.fix_sql:
                console.print(f"  [green]Fix:[/green] {finding.fix_sql.splitlines()[0]}")
