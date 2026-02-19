"""
CLI commands for the QuerySense audit suite.

    querysense audit config   — Server configuration audit
    querysense audit indexes  — Holistic index management
    querysense audit vacuum   — Autovacuum health monitor
    querysense audit txn      — Long-running transaction monitor
    querysense audit repl     — Replication impact analysis
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
app = typer.Typer(no_args_is_help=True)


def register(parent: typer.Typer) -> None:
    """Register all audit subcommands."""
    parent.add_typer(app, name="audit", help="Database health audits (config, indexes, vacuum, transactions, replication)")


@app.command(name="config")
def audit_config(
    dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    fix_script: Annotated[bool, typer.Option("--fix-script", help="Output runnable SQL fix script")] = False,
) -> None:
    """
    Audit server configuration against best practices.

    Compares live PostgreSQL settings against evidence-based recommendations
    and outputs specific ALTER SYSTEM commands. Based on "PostgreSQL Mistakes
    and How to Avoid Them" (Angelakos 2025).
    """
    from querysense.config_auditor import ConfigAuditor

    auditor = ConfigAuditor()
    result = asyncio.run(auditor.audit(dsn))

    if json_output:
        data = {
            "risk_score": result.risk_score,
            "settings_checked": result.settings_checked,
            "critical": result.critical_count,
            "warnings": result.warning_count,
            "findings": [
                {
                    "setting": f.setting,
                    "current": f.current,
                    "recommended": f.recommended,
                    "severity": f.severity.value,
                    "category": f.category,
                    "description": f.description,
                    "fix_command": f.fix_command,
                    "impact": f.impact,
                }
                for f in result.findings
            ],
        }
        console.print_json(json.dumps(data, indent=2))
        return

    if fix_script:
        console.print(result.fix_script)
        return

    # Rich output
    risk_color = "green" if result.risk_score < 3 else "yellow" if result.risk_score < 6 else "red"
    console.print(Panel(
        f"[bold]Risk Score: [{risk_color}]{result.risk_score:.1f}/10[/{risk_color}][/bold]  |  "
        f"Settings checked: {result.settings_checked}  |  "
        f"[red]{result.critical_count} critical[/red]  |  "
        f"[yellow]{result.warning_count} warnings[/yellow]",
        title="[bold]QuerySense Configuration Audit[/bold]",
        subtitle="Based on PostgreSQL Mistakes (Angelakos 2025)",
    ))

    if not result.findings:
        console.print("[green]✓ All settings look good![/green]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Setting", width=30)
    table.add_column("Current", width=15)
    table.add_column("Recommended", width=20)
    table.add_column("Impact")

    for f in result.findings:
        sev_style = {"critical": "red bold", "warning": "yellow", "info": "blue", "ok": "green"}
        style = sev_style.get(f.severity.value, "white")
        table.add_row(
            f"[{style}]{f.severity.value.upper()}[/{style}]",
            f.setting,
            f.current,
            f.recommended,
            f.impact[:60],
        )

    console.print(table)
    console.print()

    # Print fix commands
    console.print("[bold]Fix commands:[/bold]")
    for f in result.findings:
        if f.severity.value in ("critical", "warning"):
            console.print(f"  [dim]{f.setting}:[/dim]")
            console.print(f"    [cyan]{f.fix_command}[/cyan]")

    console.print(f"\nRun [bold cyan]querysense audit config --fix-script[/bold cyan] to get a runnable SQL script.")

    if result.critical_count > 0:
        raise typer.Exit(1)


@app.command(name="indexes")
def audit_indexes(
    dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
    schema: Annotated[str, typer.Option("--schema", help="Schema to audit")] = "public",
    min_scans: Annotated[int, typer.Option("--min-scans", help="Minimum scans to consider 'used'")] = 50,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    fix_script: Annotated[bool, typer.Option("--fix-script", help="Output DROP INDEX script")] = False,
) -> None:
    """
    Holistic index audit — find redundant, unused, and duplicate indexes.

    Connects to a live database and analyzes all indexes for optimization.
    Suggests new indexes (partial, expression, covering) and flags waste.
    """
    from querysense.index_manager import IndexManager

    manager = IndexManager()
    result = asyncio.run(manager.audit(dsn, schema, min_scans))

    if json_output:
        data = {
            "indexes_audited": result.indexes_audited,
            "tables_audited": result.tables_audited,
            "total_index_size_mb": result.total_index_size_bytes // 1024 // 1024,
            "potential_savings_mb": result.potential_savings_bytes // 1024 // 1024,
            "redundant": result.redundant_count,
            "unused": result.unused_count,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "title": f.title,
                    "table": f.table,
                    "fix_command": f.fix_command,
                    "savings_mb": f.savings_bytes // 1024 // 1024,
                }
                for f in result.findings
            ],
        }
        console.print_json(json.dumps(data, indent=2))
        return

    if fix_script:
        console.print(result.fix_script)
        return

    # Rich output
    console.print(Panel(
        f"[bold]Indexes: {result.indexes_audited}[/bold]  |  "
        f"Tables: {result.tables_audited}  |  "
        f"Total size: {result.total_index_size_bytes // 1024 // 1024}MB  |  "
        f"[green]Potential savings: {result.potential_savings_bytes // 1024 // 1024}MB[/green]",
        title="[bold]QuerySense Index Audit[/bold]",
    ))

    if not result.findings:
        console.print("[green]✓ No index issues found![/green]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Type", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Index/Finding", width=40)
    table.add_column("Savings")
    table.add_column("Fix")

    for f in result.findings:
        sev_style = {"critical": "red bold", "warning": "yellow", "info": "blue"}
        style = sev_style.get(f.severity, "white")
        savings = f"{f.savings_bytes // 1024 // 1024}MB" if f.savings_bytes > 0 else "-"
        table.add_row(
            f.category.upper(),
            f"[{style}]{f.severity.upper()}[/{style}]",
            f.title[:40],
            savings,
            f.fix_command.split("\n")[0][:40],
        )

    console.print(table)

    if result.redundant_count > 0:
        console.print(
            f"\n[yellow]⚠ {result.redundant_count} redundant index(es) found. "
            f"Run with --fix-script to generate DROP commands.[/yellow]"
        )


@app.command(name="vacuum")
def audit_vacuum(
    dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    fix_script: Annotated[bool, typer.Option("--fix-script", help="Output fix script")] = False,
) -> None:
    """
    Autovacuum health monitor — detect bloat, dead tuples, wraparound risk.

    Provides exact ALTER TABLE SET commands for per-table tuning. Based on
    "PostgreSQL Mistakes and How to Avoid Them" (Angelakos 2025).
    """
    from querysense.autovacuum_monitor import AutovacuumMonitor

    monitor = AutovacuumMonitor()
    health = asyncio.run(monitor.check(dsn))

    if json_output:
        data = {
            "overall_health": health.overall_health,
            "total_dead_tuples": health.total_dead_tuples,
            "total_bloat_mb": health.total_bloat_bytes // 1024 // 1024,
            "autovacuum_workers": f"{health.autovacuum_workers_running}/{health.autovacuum_max_workers}",
            "wraparound_danger_tables": health.wraparound_danger_tables,
            "alerts": [
                {
                    "severity": a.severity,
                    "category": a.category,
                    "table": a.table,
                    "message": a.message,
                    "fix_command": a.fix_command,
                }
                for a in health.alerts
            ],
        }
        console.print_json(json.dumps(data, indent=2))
        return

    if fix_script:
        console.print(health.fix_script)
        return

    health_color = {"healthy": "green", "degraded": "yellow", "critical": "red"}
    color = health_color.get(health.overall_health, "white")
    console.print(Panel(
        f"[bold]Health: [{color}]{health.overall_health.upper()}[/{color}][/bold]  |  "
        f"Dead tuples: {health.total_dead_tuples:,}  |  "
        f"Workers: {health.autovacuum_workers_running}/{health.autovacuum_max_workers}  |  "
        f"Wraparound risk: {health.wraparound_danger_tables} table(s)",
        title="[bold]QuerySense Autovacuum Health[/bold]",
        subtitle="Based on PostgreSQL Mistakes (Angelakos 2025)",
    ))

    if not health.alerts:
        console.print("[green]✓ Autovacuum is healthy![/green]")
        return

    for alert in health.alerts:
        sev_style = {"critical": "red bold", "warning": "yellow", "info": "blue"}
        style = sev_style.get(alert.severity, "white")
        console.print(f"  [{style}]{alert.severity.upper()}[/{style}] {alert.table}: {alert.message}")
        console.print(f"    [cyan]Fix: {alert.fix_command.split(chr(10))[0]}[/cyan]")

    if health.overall_health == "critical":
        raise typer.Exit(1)


@app.command(name="txn")
def audit_transactions(
    dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
    idle_threshold: Annotated[float, typer.Option("--idle-threshold", help="Idle-in-transaction threshold (seconds)")] = 300.0,
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    fix_script: Annotated[bool, typer.Option("--fix-script", help="Output kill script")] = False,
) -> None:
    """
    Detect long-running idle transactions with one-click termination.

    Shows PIDs, durations, blocking relationships, and generates
    pg_terminate_backend() commands with safety context.
    """
    from querysense.txn_monitor import TransactionMonitor

    monitor = TransactionMonitor()
    health = asyncio.run(monitor.check(dsn, idle_threshold))

    if json_output:
        data = {
            "total_connections": health.total_connections,
            "idle_in_transaction": health.idle_in_transaction,
            "active_queries": health.active_queries,
            "prepared_transactions": health.prepared_transactions,
            "long_running": [
                {
                    "pid": t.pid,
                    "state": t.state,
                    "duration_seconds": t.duration_seconds,
                    "query": t.query[:200],
                    "application": t.application_name,
                    "blocked_queries": t.blocked_queries,
                    "severity": t.severity,
                    "kill_command": t.kill_command,
                }
                for t in health.long_running
            ],
            "locks": [
                {
                    "blocking_pid": l.blocking_pid,
                    "blocked_pid": l.blocked_pid,
                    "lock_type": l.lock_type,
                    "relation": l.relation,
                    "duration_seconds": l.duration_seconds,
                }
                for l in health.locks
            ],
        }
        console.print_json(json.dumps(data, indent=2))
        return

    if fix_script:
        console.print(health.fix_script)
        return

    console.print(Panel(
        f"[bold]Connections: {health.total_connections}[/bold]  |  "
        f"[yellow]Idle-in-txn: {health.idle_in_transaction}[/yellow]  |  "
        f"Active: {health.active_queries}  |  "
        f"Prepared: {health.prepared_transactions}",
        title="[bold]QuerySense Transaction Monitor[/bold]",
    ))

    if not health.long_running:
        console.print("[green]✓ No problematic transactions![/green]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("PID", width=8)
    table.add_column("State", width=20)
    table.add_column("Duration", width=12)
    table.add_column("App", width=15)
    table.add_column("Blocking", width=10)
    table.add_column("Severity", width=10)

    for t in health.long_running:
        sev_style = {"critical": "red bold", "warning": "yellow", "info": "blue"}
        style = sev_style.get(t.severity, "white")
        duration = f"{t.duration_seconds:.0f}s"
        if t.duration_seconds > 3600:
            duration = f"{t.duration_seconds / 3600:.1f}h"
        table.add_row(
            str(t.pid),
            t.state,
            duration,
            t.application_name[:15],
            str(t.blocked_queries) if t.blocked_queries else "-",
            f"[{style}]{t.severity.upper()}[/{style}]",
        )

    console.print(table)

    # Lock contention
    if health.locks:
        console.print(f"\n[bold]Lock Contention ({len(health.locks)} blocked):[/bold]")
        for lk in health.locks[:5]:
            console.print(
                f"  PID {lk.blocking_pid} → blocks PID {lk.blocked_pid} "
                f"({lk.lock_type}/{lk.lock_mode} on {lk.relation}) for {lk.duration_seconds:.0f}s"
            )

    console.print(f"\nRun with [bold cyan]--fix-script[/bold cyan] to get pg_terminate_backend commands.")

    critical = [t for t in health.long_running if t.severity == "critical"]
    if critical:
        raise typer.Exit(1)


@app.command(name="repl")
def audit_replication(
    dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")] = "postgresql://localhost:5432/postgres",
    json_output: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    fix_script: Annotated[bool, typer.Option("--fix-script", help="Output fix script")] = False,
) -> None:
    """
    Replication impact analysis — detect WAL bloat, replica lag, slot issues.

    Identifies queries causing excessive WAL and provides batching strategies.
    Based on "Mastering PostgreSQL 13" (Schönig 2020).
    """
    from querysense.replication_analyzer import ReplicationAnalyzer

    analyzer = ReplicationAnalyzer()
    health = asyncio.run(analyzer.check(dsn))

    if json_output:
        data = {
            "is_primary": health.is_primary,
            "wal_level": health.wal_level,
            "replicas": len(health.replicas),
            "max_replay_lag_seconds": health.max_replay_lag_seconds,
            "replication_slots": health.replication_slots,
            "alerts": [
                {"severity": a.severity, "category": a.category, "message": a.message}
                for a in health.alerts
            ],
        }
        console.print_json(json.dumps(data, indent=2))
        return

    if fix_script:
        console.print(health.fix_script)
        return

    role = "Primary" if health.is_primary else "Replica"
    console.print(Panel(
        f"[bold]Role: {role}[/bold]  |  "
        f"WAL level: {health.wal_level}  |  "
        f"Replicas: {len(health.replicas)}  |  "
        f"Max lag: {health.max_replay_lag_seconds:.1f}s  |  "
        f"Slots: {health.replication_slots}",
        title="[bold]QuerySense Replication Analysis[/bold]",
    ))

    if health.replicas:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Replica", width=20)
        table.add_column("State", width=12)
        table.add_column("Write Lag", width=12)
        table.add_column("Flush Lag", width=12)
        table.add_column("Replay Lag", width=12)
        table.add_column("Sync", width=8)

        for r in health.replicas:
            lag_style = "green" if r.replay_lag_seconds < 5 else "yellow" if r.replay_lag_seconds < 30 else "red"
            table.add_row(
                r.client_addr,
                r.state,
                f"{r.write_lag_seconds:.1f}s",
                f"{r.flush_lag_seconds:.1f}s",
                f"[{lag_style}]{r.replay_lag_seconds:.1f}s[/{lag_style}]",
                r.sync_state,
            )
        console.print(table)

    if health.alerts:
        console.print(f"\n[bold]Alerts ({len(health.alerts)}):[/bold]")
        for alert in health.alerts:
            sev_style = {"critical": "red bold", "warning": "yellow", "info": "blue"}
            style = sev_style.get(alert.severity, "white")
            console.print(f"  [{style}]{alert.severity.upper()}[/{style}] {alert.message}")
    else:
        console.print("[green]✓ Replication is healthy![/green]")
