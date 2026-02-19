"""
Unified VACUUM Advisor CLI -- pganalyze's crown jewel, free forever.

Commands:
    querysense vacuum --full          Full 4-category report (bloat + freezing + performance + activity)
    querysense vacuum --bloat         Table and index bloat analysis
    querysense vacuum --freezing      XID wraparound risk monitoring
    querysense vacuum --workers       Autovacuum worker saturation and queue depth
    querysense vacuum --throttling    Cost-based throttling tuner
    querysense vacuum --tune          Per-table autovacuum tuner
    querysense vacuum --history       Vacuum activity history
    querysense vacuum --fix-script    Generate SQL fix script

    querysense txns --blocking-vacuum Transactions blocking VACUUM cleanup
    querysense hot                    HOT update efficiency analysis
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ── querysense vacuum ──────────────────────────────────────────────

vacuum_app = typer.Typer(name="vacuum", help="VACUUM Advisor -- 4-category autovacuum intelligence")


def _human_bytes(b: int | float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}PB"


def _severity_style(sev: str) -> str:
    return {"critical": "bold red", "warning": "yellow", "info": "cyan"}.get(sev, "white")


def _pct_bar(pct: float, width: int = 20) -> str:
    filled = int(min(pct, 100) / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


@vacuum_app.callback(invoke_without_command=True)
def vacuum_main(
    ctx: typer.Context,
    dsn: Annotated[str, typer.Option("--dsn", envvar="QUERYSENSE_DSN", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
    schema: Annotated[str, typer.Option("--schema", help="Schema to analyze")] = "public",
    full: Annotated[bool, typer.Option("--full", help="Full 4-category report")] = False,
    bloat: Annotated[bool, typer.Option("--bloat", help="Table and index bloat analysis")] = False,
    freezing: Annotated[bool, typer.Option("--freezing", help="XID wraparound risk")] = False,
    workers: Annotated[bool, typer.Option("--workers", help="Worker saturation and queue depth")] = False,
    throttling: Annotated[bool, typer.Option("--throttling", help="Cost-based throttling tuner")] = False,
    tune: Annotated[bool, typer.Option("--tune", help="Per-table autovacuum tuner")] = False,
    table: Annotated[Optional[str], typer.Option("--table", help="Specific table for --tune")] = None,
    history: Annotated[bool, typer.Option("--history", help="Vacuum activity tracker")] = False,
    fix_script: Annotated[bool, typer.Option("--fix-script", help="Output SQL fix script")] = False,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="JSON output")] = False,
    per_table: Annotated[bool, typer.Option("--per-table", help="Generate ALTER TABLE commands for all hot tables")] = False,
) -> None:
    """
    VACUUM Advisor -- complete autovacuum intelligence.

    Implements all 4 categories from pganalyze's VACUUM Advisor:
    Bloat, Freezing, Performance, and Activity.

    Examples:

        $ querysense vacuum --full --dsn postgresql://localhost/mydb
        $ querysense vacuum --bloat --dsn $DB_URL
        $ querysense vacuum --freezing
        $ querysense vacuum --workers
        $ querysense vacuum --tune --table orders
        $ querysense vacuum --fix-script > vacuum_fixes.sql
    """
    if ctx.invoked_subcommand is not None:
        return

    # Default to full report if no flags specified
    if not any([full, bloat, freezing, workers, throttling, tune, history, per_table]):
        full = True

    async def _run() -> None:
        from querysense.vacuum_advisor import VacuumAdvisor, VacuumReport

        advisor = VacuumAdvisor()
        report = await advisor.full_report(dsn, schema=schema)

        if fix_script:
            console.print(report.fix_script)
            return

        if json_output:
            import dataclasses
            console.print_json(json.dumps(dataclasses.asdict(report), default=str))
            return

        if full:
            _render_full_report(report, dsn)
        else:
            if bloat:
                _render_bloat(report)
            if freezing:
                _render_freezing(report)
            if workers or throttling:
                await _render_workers(dsn, schema)
            if tune or per_table:
                _render_per_table_tuning(report, table)
            if history:
                _render_activity(report)

    asyncio.run(_run())


def _render_full_report(report: Any, dsn: str) -> None:
    """Render the complete 4-category VACUUM health report."""
    # Health assessment
    issues = len([r for r in report.recommendations if r.severity in ("critical", "warning")])
    if issues == 0:
        health = "[bold green]Healthy[/bold green]"
    elif any(r.severity == "critical" for r in report.recommendations):
        health = "[bold red]CRITICAL[/bold red]"
    else:
        health = "[bold yellow]Needs Attention[/bold yellow]"

    console.print()
    console.print(Panel.fit(
        f"[bold]VACUUM HEALTH REPORT[/bold]\n"
        f"Overall vacuum health: {health}\n"
        f"Workers: {report.autovacuum_workers_running}/{report.autovacuum_max_workers} | "
        f"Dead tuples: {report.total_dead_tuples:,} | "
        f"Bloat: {report.total_bloat_mb:.0f}MB | "
        f"Freeze risk: {report.tables_at_freeze_risk} table(s)",
        border_style="cyan",
        title="querysense vacuum --full",
    ))
    console.print()

    _render_bloat(report)
    _render_freezing(report)
    _render_performance(report)
    _render_activity(report)
    _render_cost_throttling(report)
    _render_toast(report)
    _render_never_vacuumed(report)

    # Fix script summary
    fix_recs = [r for r in report.recommendations if r.fix_sql and r.severity in ("critical", "warning")]
    if fix_recs:
        console.print(Panel.fit(
            f"[bold]{len(fix_recs)} fix(es) available[/bold]\n"
            f"Generate fix script: querysense vacuum --fix-script --dsn <DSN>",
            border_style="green",
            title="FIX SCRIPT",
        ))
        console.print()


def _render_bloat(report: Any) -> None:
    """Category 1: Bloat."""
    bloats = report.bloat_estimates
    if not bloats:
        console.print("[dim]No bloat data available[/dim]")
        return

    console.print("[bold blue]BLOAT[/bold blue]")
    console.print("-" * 60)

    tbl = Table(show_header=True, show_lines=False)
    tbl.add_column("Table", style="bold")
    tbl.add_column("Bloat %", justify="right")
    tbl.add_column("Wasted", justify="right")
    tbl.add_column("Dead Tuples", justify="right")
    tbl.add_column("Last Vacuum", justify="right")
    tbl.add_column("Status")

    for b in sorted(bloats, key=lambda x: x.bloat_ratio, reverse=True)[:15]:
        pct = f"{b.bloat_ratio:.0%}"
        wasted = _human_bytes(b.estimated_bloat_bytes)
        dead = f"{b.dead_tuples:,}"
        last_vac = f"{b.days_since_vacuum:.0f}d ago" if b.days_since_vacuum < 999 else "NEVER"

        if b.is_critical:
            status = "[bold red]CRITICAL[/bold red]"
        elif b.bloat_ratio > 0.2:
            status = "[yellow]WARNING[/yellow]"
        else:
            status = "[green]OK[/green]"

        tbl.add_row(f"{b.schema}.{b.table}", pct, wasted, dead, last_vac, status)

    console.print(tbl)

    # Fix recommendations
    critical_bloat = [b for b in bloats if b.is_critical]
    if critical_bloat:
        console.print()
        for b in critical_bloat[:3]:
            console.print(f"  [red]FIX:[/red] VACUUM (VERBOSE) {b.schema}.{b.table};")
            console.print(f"  [dim]  Or for severe bloat: pg_repack -t {b.schema}.{b.table}[/dim]")
    console.print()


def _render_freezing(report: Any) -> None:
    """Category 2: Freezing / XID Wraparound."""
    risks = report.freeze_risks
    if not risks:
        console.print("[dim]No freeze risk data available[/dim]")
        return

    console.print("[bold cyan]FREEZING (XID Wraparound Risk)[/bold cyan]")
    console.print("-" * 60)

    tbl = Table(show_header=True, show_lines=False)
    tbl.add_column("Table", style="bold")
    tbl.add_column("XID Age", justify="right")
    tbl.add_column("% to Limit", justify="right")
    tbl.add_column("Days to Freeze", justify="right")
    tbl.add_column("Freeze Map", justify="right")
    tbl.add_column("MXID %", justify="right")
    tbl.add_column("Status")

    for r in sorted(risks, key=lambda x: x.pct_to_wraparound, reverse=True)[:15]:
        age_str = f"{r.age_xid:,}"
        pct_str = f"{r.pct_to_wraparound:.0%}"
        days_str = f"{r.estimated_days_to_freeze:.0f}"
        fm_str = f"{r.freeze_map_coverage:.0%}"
        mxid_str = f"{r.mxid_pct_to_wraparound:.0%}"

        if r.pct_to_wraparound > 0.75:
            status = "[bold red]CRITICAL[/bold red]"
        elif r.pct_to_wraparound > 0.5:
            status = "[yellow]WARNING[/yellow]"
        else:
            status = "[green]OK[/green]"

        if r.is_anti_wraparound:
            status += " [red](anti-wraparound!)[/red]"

        tbl.add_row(f"{r.schema}.{r.table}", age_str, pct_str, days_str, fm_str, mxid_str, status)

    console.print(tbl)

    critical = [r for r in risks if r.pct_to_wraparound > 0.75]
    if critical:
        console.print()
        for r in critical[:3]:
            console.print(f"  [red]FIX:[/red] VACUUM (FREEZE, VERBOSE) {r.schema}.{r.table};")
            console.print(f"  [dim]  Database will SHUT DOWN at 2B transactions to prevent corruption![/dim]")
    console.print()


def _render_performance(report: Any) -> None:
    """Category 3: Performance / worker saturation + cost tuning."""
    console.print("[bold magenta]PERFORMANCE[/bold magenta]")
    console.print("-" * 60)

    sat_pct = (report.autovacuum_workers_running / max(report.autovacuum_max_workers, 1)) * 100
    bar = _pct_bar(sat_pct)

    if sat_pct >= 100:
        sat_label = "[bold red]SATURATED[/bold red]"
    elif sat_pct >= 75:
        sat_label = "[yellow]HIGH[/yellow]"
    else:
        sat_label = "[green]OK[/green]"

    console.print(f"  Autovacuum workers: {report.autovacuum_workers_running}/{report.autovacuum_max_workers} {bar} {sat_pct:.0f}% {sat_label}")
    console.print(f"  Total dead tuples: {report.total_dead_tuples:,}")
    console.print(f"  Tables at freeze risk: {report.tables_at_freeze_risk}")

    if sat_pct >= 100:
        rec = report.autovacuum_max_workers + 2
        console.print()
        console.print(f"  [red]FIX:[/red] Workers fully saturated -- tables are waiting for vacuum!")
        console.print(f"  ALTER SYSTEM SET autovacuum_max_workers = {rec};")
        console.print(f"  SELECT pg_reload_conf();")

    if report.tuning_recommendations:
        console.print()
        console.print("  [bold]Per-Table Tuning Needed:[/bold]")
        for t in report.tuning_recommendations[:5]:
            console.print(f"    {t.schema}.{t.table}: {t.parameter} {t.current_value} -> {t.recommended_value}")
            console.print(f"    [dim]{t.reason[:80]}[/dim]")

    console.print()


def _render_activity(report: Any) -> None:
    """Category 4: Activity / current vacuums."""
    console.print("[bold green]ACTIVITY[/bold green]")
    console.print("-" * 60)

    if report.active_vacuums:
        for v in report.active_vacuums:
            bar = _pct_bar(v.progress_pct)
            elapsed_min = v.elapsed_seconds / 60
            eta_min = v.estimated_remaining_seconds / 60
            console.print(
                f"  {v.table}: {v.phase} {bar} {v.progress_pct:.1f}% "
                f"({elapsed_min:.0f}min elapsed, ~{eta_min:.0f}min remaining)"
            )
    else:
        console.print("  [dim]No active vacuums running[/dim]")

    # Recommendations for activity
    activity_recs = [r for r in report.recommendations if r.category == "activity"]
    if activity_recs:
        console.print()
        for r in activity_recs:
            console.print(f"  [{_severity_style(r.severity)}]{r.severity.upper()}[/{_severity_style(r.severity)}] {r.title}")
            console.print(f"  [dim]{r.description[:100]}[/dim]")

    console.print()


def _render_cost_throttling(report: Any) -> None:
    """Extended: Cost-based throttling analysis."""
    ct = report.cost_throttling
    if not ct:
        return

    needs_tuning = ct.vacuum_cost_delay_ms > 10 or ct.vacuum_cost_limit < 400

    if not needs_tuning:
        return

    console.print("[bold]COST THROTTLING[/bold]")
    console.print("-" * 60)

    ssd_label = " [green](SSD detected)[/green]" if ct.is_ssd_likely else ""
    console.print(f"  Cost delay: {ct.vacuum_cost_delay_ms}ms{ssd_label}")
    console.print(f"  Cost limit: {ct.vacuum_cost_limit}")
    console.print(f"  Effective I/O: {ct.effective_io_pages_sec:.0f} pages/sec")
    if ct.reason:
        console.print(f"  [yellow]Issue: {ct.reason}[/yellow]")

    console.print(f"\n  [green]FIX:[/green]")
    console.print(f"    ALTER SYSTEM SET autovacuum_vacuum_cost_delay = {ct.recommended_cost_delay};  -- was {ct.vacuum_cost_delay_ms}ms")
    console.print(f"    ALTER SYSTEM SET autovacuum_vacuum_cost_limit = {ct.recommended_cost_limit};  -- was {ct.vacuum_cost_limit}")
    console.print(f"    SELECT pg_reload_conf();")
    console.print()


def _render_toast(report: Any) -> None:
    """Extended: TOAST bloat analysis."""
    toast = report.toast_bloat
    if not toast:
        return

    significant = [t for t in toast if t.toast_ratio > 0.3]
    if not significant:
        return

    console.print("[bold]TOAST ANALYSIS[/bold]")
    console.print("-" * 60)

    tbl = Table(show_header=True, show_lines=False)
    tbl.add_column("Table", style="bold")
    tbl.add_column("TOAST Size", justify="right")
    tbl.add_column("Main Size", justify="right")
    tbl.add_column("TOAST %", justify="right")
    tbl.add_column("Large Columns")

    for t in significant:
        toast_mb = t.toast_size_bytes / 1024 / 1024
        main_mb = t.main_size_bytes / 1024 / 1024
        cols = ", ".join(t.large_column_names[:4]) if t.large_column_names else "-"
        tbl.add_row(
            f"{t.schema}.{t.table}",
            f"{toast_mb:.0f}MB",
            f"{main_mb:.0f}MB",
            f"{t.toast_ratio:.0%}",
            cols,
        )

    console.print(tbl)
    console.print()


def _render_never_vacuumed(report: Any) -> None:
    """Extended: Tables that have never been vacuumed."""
    tables = report.never_vacuumed_tables
    if not tables:
        return

    console.print("[bold yellow]NEVER VACUUMED[/bold yellow]")
    console.print("-" * 60)
    for t in tables:
        console.print(f"  [yellow]WARNING[/yellow] {t}: never vacuumed (manual or auto)")
    console.print(f"\n  [green]FIX:[/green]")
    for t in tables[:5]:
        console.print(f"    VACUUM (ANALYZE, VERBOSE) {t};")
    if len(tables) > 5:
        console.print(f"    -- ... and {len(tables) - 5} more")
    console.print()


async def _render_workers(dsn: str, schema: str) -> None:
    """Detailed worker saturation and I/O throttling analysis."""
    from querysense.autovacuum_utilization import AutovacuumAnalyzer

    analyzer = AutovacuumAnalyzer()
    report = await analyzer.analyze(dsn, schema=schema)

    console.print("[bold magenta]WORKER SATURATION & THROTTLING[/bold magenta]")
    console.print("-" * 60)

    sat_bar = _pct_bar(report.saturation_pct)
    console.print(f"  Workers: {report.active_workers}/{report.max_workers} {sat_bar} {report.saturation_pct:.0f}%")
    console.print(f"  Queue depth: {report.queue_depth} tables waiting")
    console.print(f"  I/O budget: {report.io_budget_pct:.0f}%")
    console.print(f"  Cost settings: cost_limit={report.vacuum_cost_limit}, cost_delay={report.vacuum_cost_delay_ms}ms")
    console.print()

    if report.workers:
        tbl = Table(title="Active Workers")
        tbl.add_column("PID")
        tbl.add_column("Table")
        tbl.add_column("Phase")
        tbl.add_column("Progress", justify="right")
        tbl.add_column("Elapsed", justify="right")

        for w in report.workers:
            tbl.add_row(
                str(w.pid),
                w.table,
                w.phase,
                f"{w.progress_pct:.1f}%",
                f"{w.elapsed_seconds:.0f}s",
            )
        console.print(tbl)
        console.print()

    if report.queued_tables:
        tbl = Table(title="Vacuum Queue (most urgent first)")
        tbl.add_column("Urgency")
        tbl.add_column("Table")
        tbl.add_column("Dead Tuples", justify="right")
        tbl.add_column("Dead %", justify="right")
        tbl.add_column("ETA", justify="right")

        for q in report.queued_tables[:15]:
            urg_style = {"critical": "bold red", "high": "yellow", "normal": "dim"}.get(q.urgency, "white")
            tbl.add_row(
                f"[{urg_style}]{q.urgency.upper()}[/{urg_style}]",
                q.table,
                f"{q.dead_tuples:,}",
                f"{q.dead_ratio:.1%}",
                f"{q.estimated_wait_minutes:.0f}min",
            )
        console.print(tbl)
        console.print()

    # Throttling recommendations
    if report.vacuum_cost_delay_ms > 10:
        console.print("  [yellow]FIX:[/yellow] Cost delay too conservative for modern SSDs:")
        console.print(f"    ALTER SYSTEM SET autovacuum_vacuum_cost_delay = 2;  -- was {report.vacuum_cost_delay_ms}ms")
    if report.vacuum_cost_limit < 400:
        console.print("  [yellow]FIX:[/yellow] Cost limit too low:")
        console.print(f"    ALTER SYSTEM SET autovacuum_vacuum_cost_limit = 1000;  -- was {report.vacuum_cost_limit}")
    if report.saturation_pct >= 100:
        new_max = report.max_workers + 2
        console.print(f"  [red]FIX:[/red] Workers saturated:")
        console.print(f"    ALTER SYSTEM SET autovacuum_max_workers = {new_max};")
    if report.vacuum_cost_delay_ms > 10 or report.vacuum_cost_limit < 400 or report.saturation_pct >= 100:
        console.print("    SELECT pg_reload_conf();")

    console.print()


def _render_per_table_tuning(report: Any, target_table: str | None) -> None:
    """Per-table autovacuum parameter tuner."""
    console.print("[bold]PER-TABLE AUTOVACUUM TUNING[/bold]")
    console.print("-" * 60)

    tunings = report.tuning_recommendations
    if target_table:
        tunings = [t for t in tunings if t.table == target_table or f".{target_table}" in f"{t.schema}.{t.table}"]
        if not tunings:
            console.print(f"  [dim]No tuning recommendations for '{target_table}'[/dim]")
            console.print(f"  [dim]Table may already have optimal settings, or has <10K rows[/dim]")
            console.print()
            return

    if not tunings:
        console.print("  [green]All tables have acceptable autovacuum settings[/green]")
        console.print()
        return

    # Group by table
    by_table: dict[str, list] = {}
    for t in tunings:
        key = f"{t.schema}.{t.table}"
        by_table.setdefault(key, []).append(t)

    for table_name, table_tunings in by_table.items():
        console.print(f"\n  [bold]{table_name}[/bold]")
        for t in table_tunings:
            console.print(f"    {t.parameter}: {t.current_value} -> [green]{t.recommended_value}[/green]")
            console.print(f"    [dim]{t.reason[:100]}[/dim]")

        # Generate combined ALTER TABLE
        console.print(f"\n  [bold]ALTER TABLE {table_name} SET ([/bold]")
        for i, t in enumerate(table_tunings):
            comma = "," if i < len(table_tunings) - 1 else ""
            console.print(f"    {t.parameter} = {t.recommended_value}{comma}")
        console.print("  [bold]);[/bold]")

    console.print()


# ── querysense txns ────────────────────────────────────────────────

txns_app = typer.Typer(name="txns", help="Transaction analysis -- find vacuum blockers")


@txns_app.command(name="blocking-vacuum")
def txns_blocking_vacuum(
    dsn: Annotated[str, typer.Option("--dsn", envvar="QUERYSENSE_DSN", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
    json_output: Annotated[bool, typer.Option("--json", "-j", help="JSON output")] = False,
) -> None:
    """
    Find transactions blocking VACUUM from cleaning dead tuples.

    Identifies idle-in-transaction sessions, long-running queries, replication
    slots, and prepared transactions holding back the xmin horizon.

    Examples:

        $ querysense txns blocking-vacuum --dsn postgresql://localhost/mydb
    """
    async def _run() -> None:
        from querysense.xmin_horizon import XminHorizonTracker

        tracker = XminHorizonTracker()
        report = await tracker.analyze(dsn)

        if json_output:
            data = {
                "horizon_age_seconds": report.horizon_age_seconds,
                "dead_tuples_blocked": report.dead_tuples_blocked,
                "estimated_bloat_mb": report.estimated_bloat_mb,
                "blockers": [b.to_dict() for b in report.blockers],
            }
            console.print_json(json.dumps(data, default=str))
            return

        console.print()
        console.print(Panel.fit(
            "[bold]TRANSACTIONS BLOCKING VACUUM[/bold]",
            border_style="red" if report.blockers else "green",
        ))

        if not report.blockers:
            console.print("  [green]No transactions blocking vacuum cleanup[/green]")
            console.print()
            return

        console.print(f"  Found [bold]{len(report.blockers)}[/bold] blocker(s) preventing vacuum from cleaning dead tuples\n")

        for i, b in enumerate(report.blockers, 1):
            sev_style = _severity_style(b.severity)
            console.print(f"  [{sev_style}]BLOCKER #{i}[/{sev_style}] (PID {b.pid})" if b.pid else f"  [{sev_style}]BLOCKER #{i}[/{sev_style}]")
            console.print(f"  {'-' * 40}")
            console.print(f"  Source: {b.source}")

            if b.duration_seconds:
                mins = b.duration_seconds / 60
                console.print(f"  Age: {mins:.0f} minutes ({b.duration_seconds:.0f}s)")

            if b.state:
                state_color = "red" if "idle" in b.state else "yellow"
                console.print(f"  State: [{state_color}]{b.state}[/{state_color}]")

            if b.query:
                q = b.query[:200] + ("..." if len(b.query) > 200 else "")
                console.print(f"  Query: {q}")

            if b.slot_name:
                console.print(f"  Slot: {b.slot_name}")

            console.print(f"  Xmin age: {b.xmin_age:,} XIDs")
            console.print(f"  {b.description}")

            if b.fix_sql:
                console.print(f"\n  [green]FIX:[/green]")
                for line in b.fix_sql.split("\n"):
                    console.print(f"    {line}")
            if b.fix_description:
                console.print(f"  [dim]{b.fix_description}[/dim]")

            console.print()

        # Impact summary
        console.print(Panel.fit(
            f"[bold]IMPACT SUMMARY[/bold]\n"
            f"Dead tuples stuck: {report.dead_tuples_blocked:,}\n"
            f"Estimated bloat: {report.estimated_bloat_mb:.1f}MB\n"
            f"Wraparound risk: {report.pct_to_wraparound:.1%}",
            border_style="yellow",
        ))
        console.print()

    asyncio.run(_run())


# ── querysense hot ─────────────────────────────────────────────────

hot_app = typer.Typer(name="hot", help="HOT (Heap-Only Tuple) update efficiency analysis")


@hot_app.callback(invoke_without_command=True)
def hot_main(
    ctx: typer.Context,
    dsn: Annotated[str, typer.Option("--dsn", envvar="QUERYSENSE_DSN", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
    schema: Annotated[str, typer.Option("--schema", help="Schema to analyze")] = "public",
    tables: Annotated[bool, typer.Option("--tables", help="Show per-table HOT analysis")] = True,
    min_updates: Annotated[int, typer.Option("--min-updates", help="Min updates to consider")] = 1000,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="JSON output")] = False,
    fix_script: Annotated[bool, typer.Option("--fix-script", help="Output fix SQL script")] = False,
) -> None:
    """
    Analyze HOT (Heap-Only Tuple) update efficiency.

    HOT updates skip index maintenance -- 10-100x faster writes. This finds indexes
    that block HOT and suggests restructuring to maximize HOT ratio.

    Examples:

        $ querysense hot --dsn postgresql://localhost/mydb
        $ querysense hot --fix-script > hot_fixes.sql
    """
    if ctx.invoked_subcommand is not None:
        return

    async def _run() -> None:
        from querysense.hot_update_detector import HOTDetector

        detector = HOTDetector()
        analysis = await detector.analyze(
            dsn=dsn, schema=schema, min_updates=min_updates,
        )

        if fix_script:
            console.print(analysis.fix_script)
            return

        if json_output:
            import dataclasses
            console.print_json(json.dumps(dataclasses.asdict(analysis), default=str))
            return

        console.print()
        console.print(Panel.fit(
            f"[bold]HEAP-ONLY TUPLE (HOT) ANALYSIS[/bold]\n"
            f"HOT updates avoid index maintenance = 10-100x faster writes\n\n"
            f"Tables analyzed: {analysis.tables_analyzed}\n"
            f"Tables with low HOT ratio: {analysis.tables_with_low_hot}\n"
            f"Tables improvable: {analysis.potential_improvement_tables}",
            border_style="red" if analysis.tables_with_low_hot > 0 else "green",
            title="querysense hot",
        ))
        console.print()

        if not analysis.findings:
            console.print("  [green]All tables have healthy HOT update ratios[/green]")
            console.print()
            return

        # Group findings by table
        by_table: dict[str, list] = {}
        for f in analysis.findings:
            by_table.setdefault(f.table, []).append(f)

        for table_name, findings in by_table.items():
            hot_ratio = findings[0].hot_update_ratio if findings else 0

            if hot_ratio >= 0.8:
                ratio_style = "green"
            elif hot_ratio >= 0.5:
                ratio_style = "yellow"
            else:
                ratio_style = "red"

            console.print(f"  [bold]{table_name}[/bold]: [{ratio_style}]{hot_ratio:.0%} HOT updates[/{ratio_style}]")
            console.print()

            for f in findings:
                sev_style = _severity_style(f.severity)
                console.print(f"    [{sev_style}]{f.severity.upper()}[/{sev_style}] {f.description}")

                if f.index_name:
                    console.print(f"    [dim]Index: {f.index_name} ({', '.join(f.index_columns)})[/dim]")
                if f.updated_columns:
                    console.print(f"    [dim]Updated columns: {', '.join(f.updated_columns)}[/dim]")
                if f.estimated_speedup:
                    console.print(f"    [green]Expected: {f.estimated_speedup}[/green]")
                if f.impact:
                    console.print(f"    Impact: {f.impact}")

                if f.fix_command:
                    console.print(f"\n    [green]FIX:[/green]")
                    for line in f.fix_command.split("\n"):
                        console.print(f"      {line.strip()}")

                console.print()

    asyncio.run(_run())


# ── Registration ──────────────────────────────────────────────────


def register_vacuum(app: typer.Typer) -> None:
    """Register vacuum, txns, and hot commands on the main app."""
    app.add_typer(vacuum_app, name="vacuum")
    app.add_typer(txns_app, name="txns")
    app.add_typer(hot_app, name="hot")
