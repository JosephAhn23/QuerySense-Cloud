"""Core analysis commands: analyze, fix, rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from querysense.analyzer import Severity
from querysense.engine import AnalysisService
from querysense.output.renderers import OutputFormat, render
from querysense.parser import ParseError, parse_explain
from querysense.parser.parser import validate_has_analyze

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register core commands on the given Typer app."""

    @app.command()
    def analyze(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        require_analyze: Annotated[
            bool,
            typer.Option(
                "--require-analyze/--allow-plain",
                help="Require EXPLAIN ANALYZE output",
            ),
        ] = True,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output results as JSON"),
        ] = False,
        html_output: Annotated[
            Optional[str],
            typer.Option("--html", help="Generate self-contained HTML report to file"),
        ] = None,
        open_html: Annotated[
            bool,
            typer.Option("--open", help="Auto-open HTML report in browser (use with --html)"),
        ] = False,
        flamegraph_output: Annotated[
            Optional[str],
            typer.Option("--flamegraph", help="Generate D3.js flame graph HTML report"),
        ] = None,
        markdown_output: Annotated[
            bool,
            typer.Option("--markdown", "-m", help="Output results as Markdown"),
        ] = False,
        ascii_output: Annotated[
            bool,
            typer.Option("--ascii", "-a", help="Output as ASCII art with plan tree"),
        ] = False,
        simple_output: Annotated[
            bool,
            typer.Option("--simple", help="Beginner-friendly output: top 3 issues in plain English"),
        ] = False,
        eli5_output: Annotated[
            bool,
            typer.Option("--eli5", "--human", help="Explain findings in plain English with analogies (Explain Like I'm 5)"),
        ] = False,
        classify: Annotated[
            bool,
            typer.Option("--classify", help="Show OLTP/OLAP classification and adjusted recommendations"),
        ] = False,
        buffers: Annotated[
            bool,
            typer.Option(
                "--buffers",
                help="Show I/O heatmap: per-node cache hit/read ratios, disk reads, and savings estimates",
            ),
        ] = False,
        buffers_all: Annotated[
            bool,
            typer.Option(
                "--buffers-all",
                help="Show buffer stats for ALL nodes (not just hotspots)",
            ),
        ] = False,
        memory: Annotated[
            bool,
            typer.Option("--memory", help="Estimate peak RAM usage and warn before execution"),
        ] = False,
        threshold: Annotated[
            int,
            typer.Option(
                "--threshold",
                "-t",
                help="Minimum rows to trigger sequential scan warning",
            ),
        ] = 10_000,
        engine: Annotated[
            Optional[str],
            typer.Option(
                "--engine", "-e",
                help="Database engine: postgresql, mysql, sqlserver, oracle, duckdb, sqlite, clickhouse (auto-detected if omitted)",
            ),
        ] = None,
    ) -> None:
        """
        Analyze execution plans from PostgreSQL, MySQL, SQL Server, Oracle, DuckDB, SQLite, or ClickHouse.

        Auto-detects the database engine from the plan format, or use --engine to specify.

        Examples:

            $ querysense analyze explain.json                      # PostgreSQL (auto)
            $ querysense analyze showplan.xml --engine sqlserver    # SQL Server
            $ querysense analyze dbms_xplan.txt --engine oracle     # Oracle
            $ querysense analyze plan.json --engine duckdb          # DuckDB
            $ querysense analyze explain.json --buffers
            $ querysense analyze explain.json --ascii
            $ querysense analyze explain.json --flamegraph report.html
        """
        try:
            if engine:
                from querysense.parser.multidb import parse_any
                output = parse_any(explain_file, engine=engine)
            else:
                output = parse_explain(explain_file)

            if require_analyze:
                validate_has_analyze(output)

            service = AnalysisService()
            result = service.analyze(output)

            # Enrich findings with speedup estimates
            from querysense.analyzer.speedup import enrich_with_speedup
            result = result.model_copy(
                update={"findings": enrich_with_speedup(result.findings)}
            )

            findings = result.findings

            # ── BUFFERS I/O Heatmap ──────────────────────────────────
            if buffers or buffers_all:
                from querysense.analysis.buffers import BufferHeatmap

                heatmap = BufferHeatmap()
                try:
                    buf_report = heatmap.analyze_from_explain(output)
                except (TypeError, ValueError):
                    # Fallback to raw JSON
                    plan_data = json.loads(explain_file.read_text(encoding="utf-8"))
                    buf_report = heatmap.analyze(plan_data)

                if not buf_report.has_buffer_data:
                    console.print(Panel(
                        "[yellow]No BUFFERS data found in this plan.[/yellow]\n\n"
                        "Run with BUFFERS to see I/O statistics:\n"
                        "[green]EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT ...;[/green]",
                        title="[bold]I/O Heatmap[/bold]",
                        border_style="yellow",
                    ))
                else:
                    # Summary panel
                    summary = buf_report.summary()
                    hit_pct = summary["overall_hit_pct"]
                    hit_color = "green" if hit_pct >= 95 else ("yellow" if hit_pct >= 80 else "red")

                    console.print(Panel(
                        f"[{hit_color} bold]Overall Cache Hit: {hit_pct:.1f}%[/{hit_color} bold]\n"
                        f"Shared Hit: {summary['total_shared_hit']:,} blocks  |  "
                        f"Shared Read: {summary['total_shared_read']:,} blocks\n"
                        f"Disk Read: {summary['total_disk_read_mb']:.1f}MB  |  "
                        f"Total I/O: {summary['total_io_mb']:.1f}MB\n"
                        f"Dirtied: {summary['total_shared_dirtied']:,}  |  "
                        f"Written: {summary['total_shared_written']:,}  |  "
                        f"Temp Spill: {summary['total_temp_spill_blocks']:,} blocks"
                        + (f"\nI/O Time: {summary['io_time_ms']:.1f}ms" if summary['io_time_ms'] > 0 else "")
                        + (f"\nEstimated I/O Savings: ~{summary['estimated_savings_ms']:.0f}ms (if fully cached)" if summary['estimated_savings_ms'] > 1 else ""),
                        title="[bold]I/O HEATMAP — BUFFERS Analysis[/bold]",
                        border_style=hit_color,
                    ))

                    # Per-node table
                    nodes = buf_report.nodes if buffers_all else buf_report.hotspots[:15]
                    nodes = [n for n in nodes if n.has_buffer_data]

                    if nodes:
                        io_table = Table(title="Per-Node I/O Breakdown")
                        io_table.add_column("Node", max_width=30)
                        io_table.add_column("Table", max_width=20, style="cyan")
                        io_table.add_column("Hit", justify="right")
                        io_table.add_column("Read", justify="right")
                        io_table.add_column("Hit %", justify="right")
                        io_table.add_column("Disk MB", justify="right")
                        io_table.add_column("Severity", justify="center")
                        io_table.add_column("Root Cause", max_width=20)

                        for n in nodes:
                            sev_style = {
                                "CRITICAL": "red bold",
                                "HIGH": "red",
                                "MEDIUM": "yellow",
                                "LOW": "green",
                            }.get(n.severity, "dim")
                            hit_style = "green" if n.cache_hit_pct >= 95 else ("yellow" if n.cache_hit_pct >= 80 else "red")

                            io_table.add_row(
                                n.node_type,
                                n.table or "-",
                                f"{n.shared_hit:,}",
                                f"{n.shared_read:,}",
                                f"[{hit_style}]{n.cache_hit_pct:.0f}%[/{hit_style}]",
                                f"{n.disk_read_mb:.1f}",
                                f"[{sev_style}]{n.severity}[/{sev_style}]",
                                n.root_cause.replace("_", " "),
                            )

                        console.print(io_table)

                    # Show recommendations for critical nodes
                    critical = buf_report.critical_nodes[:5]
                    if critical:
                        console.print("\n[bold]Recommendations:[/bold]")
                        for n in critical:
                            console.print(
                                f"\n  [{('red' if n.severity == 'CRITICAL' else 'yellow')}]"
                                f"[{n.severity}][/] {n.label}: "
                                f"{n.cache_miss_pct:.0f}% cache miss "
                                f"({n.shared_read:,} reads, {n.disk_read_mb:.1f}MB)"
                            )
                            for rec in n.recommendations():
                                console.print(f"    [green]-> {rec}[/green]")

                    console.print()

                if json_output:
                    console.print_json(json.dumps(buf_report.to_dict(), default=str))
                    return
                # If only --buffers was requested, show findings too (fall through)

            # Query classification (Dombrovskaya et al. 2024)
            classification = None
            if classify:
                from querysense.query_classifier import QueryClassifier
                classifier = QueryClassifier()
                sql_text = getattr(output, "sql_text", None) or ""
                classification = classifier.classify(explain=output, sql=sql_text)

            # ELI5 human explanations
            if eli5_output and findings:
                from querysense.explainer import HumanExplainer
                explainer = HumanExplainer()

                if classification:
                    cls_color = {"OLTP": "cyan", "OLAP": "magenta", "HYBRID": "yellow", "DDL": "blue", "DML": "green"}
                    c = cls_color.get(classification.query_class.value, "white")
                    console.print(Panel(
                        f"[{c} bold]{classification.query_class.value}[/{c} bold] "
                        f"(confidence: {classification.confidence:.0%})\n\n"
                        + "\n".join(f"  • {k}: {v}" for k, v in classification.recommendation_adjustments.items()),
                        title="Query Classification",
                        border_style=c,
                    ))
                    console.print()

                console.print(Panel(
                    f"[bold]{len(findings)} issue(s) explained in plain English[/bold]",
                    title="QuerySense — Explain Like I'm 5",
                    border_style="cyan",
                ))
                console.print()

                for i, finding in enumerate(findings):
                    exp = explainer.translate(finding)
                    severity_style = {"critical": "red bold", "warning": "yellow", "info": "blue"}
                    style = severity_style.get(finding.severity.value, "blue")

                    console.print(f"[{style}]{'━' * 60}[/{style}]")
                    console.print(f"[{style}][{finding.severity.value.upper()}][/{style}] [bold]{finding.title}[/bold]")
                    console.print()

                    console.print(f"  [bold cyan]🔍 What happened:[/bold cyan]")
                    console.print(f"     {exp.what_happened}")
                    console.print()

                    console.print(f"  [bold yellow]💥 Why it matters:[/bold yellow]")
                    console.print(f"     {exp.why_it_matters}")
                    console.print()

                    if exp.analogy:
                        console.print(f"  [bold magenta]📖 Analogy:[/bold magenta]")
                        console.print(f"     [italic]{exp.analogy}[/italic]")
                        console.print()

                    console.print(f"  [bold green]🛠️  How to fix:[/bold green] ({exp.difficulty}, ~{exp.time_to_fix})")
                    console.print(f"     {exp.how_to_fix}")
                    console.print()

                    console.print(f"  [bold]📈 Expected result:[/bold] [green]{exp.estimated_impact}[/green]")
                    console.print()

                console.print(
                    f"[dim]Analyzed {result.metadata.node_count} nodes "
                    f"with {result.metadata.rules_run} rule(s)[/dim]"
                )
                return

            # Memory estimation (P2: addresses Gartner "memory runs out" pain point)
            if memory:
                from querysense.memory_estimator import MemoryEstimator
                try:
                    plan_data = json.loads(explain_file.read_text(encoding="utf-8"))
                    mem_est = MemoryEstimator()
                    mem_report = mem_est.estimate(plan_data)

                    # Show memory panel
                    mem_color = "green" if not mem_report.warnings else ("red" if mem_report.peak_memory_mb > 256 else "yellow")
                    console.print(Panel(
                        f"[{mem_color} bold]Peak Memory: {mem_report.peak_memory_mb:.1f}MB[/{mem_color} bold]\n"
                        f"Current work_mem: {mem_report.work_mem_setting}\n"
                        f"Operations: {len(mem_report.operations)}",
                        title="[bold]Memory Estimate[/bold]",
                        subtitle="(Estimated from plan — run querysense analyze --memory)",
                        border_style=mem_color,
                    ))

                    if mem_report.operations:
                        mem_table = Table(title="Memory-Intensive Operations")
                        mem_table.add_column("Operation", width=20)
                        mem_table.add_column("Table", width=20)
                        mem_table.add_column("Rows", width=12, justify="right")
                        mem_table.add_column("Memory", width=12, justify="right")
                        mem_table.add_column("Description", max_width=40)

                        for op in mem_report.operations[:10]:
                            mem_style = "red" if op.estimated_mb > 64 else ("yellow" if op.estimated_mb > 4 else "green")
                            mem_table.add_row(
                                op.node_type,
                                op.relation or "-",
                                f"{op.estimated_rows:,}",
                                f"[{mem_style}]{op.estimated_mb:.1f}MB[/{mem_style}]",
                                op.description[:60],
                            )

                        console.print(mem_table)

                    for warning in mem_report.warnings:
                        console.print(f"  [yellow]⚠ {warning}[/yellow]")

                    for rec in mem_report.recommendations:
                        console.print(f"  [cyan]→ {rec}[/cyan]")

                    console.print()
                except Exception as e:
                    console.print(f"[dim]Memory estimation unavailable: {e}[/dim]")

            # JSON output via unified renderer
            if json_output:
                console.print_json(render(result, format=OutputFormat.JSON))
                return

            # Flame graph HTML report
            if flamegraph_output:
                from querysense.output.flamegraph import render_flamegraph_html
                html_content = render_flamegraph_html(result, explain=output)
                Path(flamegraph_output).write_text(html_content, encoding="utf-8")
                console.print(f"[green]Flame graph report written to {flamegraph_output}[/green]")
                return

            # HTML report
            if html_output:
                from querysense.output.html_report import render_html
                html_content = render_html(result, explain=output)
                Path(html_output).write_text(html_content, encoding="utf-8")
                console.print(f"[green]HTML report written to {html_output}[/green]")
                if open_html:
                    import webbrowser
                    webbrowser.open(f"file://{Path(html_output).resolve()}")
                return

            # Markdown output
            if markdown_output:
                console.print(render(result, format=OutputFormat.MARKDOWN))
                return

            # Simple / beginner-friendly output
            if simple_output:
                from querysense.output.simple import render_simple
                console.print(render_simple(result, explain=output))
                return

            # ASCII art output with plan tree
            if ascii_output:
                from querysense.output.ascii import render_ascii
                console.print(render_ascii(result, explain=output))
                return

            # Pretty output (default)
            if not findings:
                console.print(
                    Panel(
                        "[green]No performance issues found![/green]\n\n"
                        f"Analyzed {result.metadata.node_count} nodes.",
                        title="QuerySense",
                        border_style="green",
                    )
                )
                return

            # Show findings with speedup estimates
            console.print(f"[bold]Found {len(findings)} issue(s):[/bold]\n")

            for finding in findings:
                if finding.severity == Severity.CRITICAL:
                    severity_style = "red bold"
                elif finding.severity == Severity.WARNING:
                    severity_style = "yellow"
                else:
                    severity_style = "blue"

                speedup = finding.metrics.get("estimated_speedup", "")
                speedup_str = f" [green]{speedup}[/green]" if speedup else ""

                console.print(
                    f"[{severity_style}][{finding.severity.value.upper()}]"
                    f"[/{severity_style}] {finding.title}{speedup_str}"
                )

                # Impact score bar
                score = finding.impact_score
                if score > 0:
                    filled = int(score)
                    bar = "█" * filled + "░" * (10 - filled)
                    score_color = "red" if score >= 7 else ("yellow" if score >= 4 else "blue")
                    console.print(
                        f"   [{score_color}]Impact: {bar} {score:.1f}/10[/{score_color}]"
                    )

                console.print(f"   [dim]{finding.description}[/dim]")

                if finding.suggestion:
                    console.print(f"\n   [bold]Fix:[/bold]")
                    for line in finding.suggestion.split("\n"):
                        if line.startswith("--"):
                            console.print(f"   [dim]{line}[/dim]")
                        else:
                            console.print(f"   [green]{line}[/green]")

                console.print()

            console.print(
                f"[dim]Analyzed {result.metadata.node_count} nodes "
                f"with {result.metadata.rules_run} rule(s)[/dim]"
            )

        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            if e.detail:
                error_console.print(f"\n[dim]{e.detail}[/dim]")
            raise typer.Exit(code=1)

    @app.command()
    def fix(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        require_analyze: Annotated[
            bool,
            typer.Option(
                "--require-analyze/--allow-plain",
                help="Require EXPLAIN ANALYZE output",
            ),
        ] = True,
        flyway: Annotated[
            bool,
            typer.Option(
                "--flyway",
                help="Generate Flyway migration file (V{NNN}__{desc}.sql)",
            ),
        ] = False,
        liquibase: Annotated[
            bool,
            typer.Option(
                "--liquibase",
                help="Generate Liquibase YAML changeset with rollback",
            ),
        ] = False,
        alembic: Annotated[
            bool,
            typer.Option(
                "--alembic",
                help="Generate Alembic Python migration (upgrade/downgrade)",
            ),
        ] = False,
        django: Annotated[
            bool,
            typer.Option(
                "--django",
                help="Generate Django RunSQL migration",
            ),
        ] = False,
        dbmate: Annotated[
            bool,
            typer.Option(
                "--dbmate",
                help="Generate dbmate migration (migrate:up/down)",
            ),
        ] = False,
        migration_dir: Annotated[
            str,
            typer.Option(
                "--migration-dir", "-d",
                help="Output directory for migration files",
            ),
        ] = "migrations",
        description: Annotated[
            str,
            typer.Option(
                "--desc",
                help="Migration description (used in filename)",
            ),
        ] = "querysense_performance_fix",
        track: Annotated[
            bool,
            typer.Option(
                "--track/--no-track",
                help="Track generated fixes in .querysense/fixes.json",
            ),
        ] = True,
    ) -> None:
        """
        Output copy-paste SQL fixes for performance issues.

        Unlike 'analyze', this outputs ONLY the SQL statements needed
        to fix detected issues. Add a migration flag to generate a
        versioned migration file for your framework.

        Examples:

            $ querysense fix slow_query.json | psql
            $ querysense fix slow_query.json > fixes.sql
            $ querysense fix slow_query.json --flyway
            $ querysense fix slow_query.json --liquibase -d db/changelog
            $ querysense fix slow_query.json --alembic --desc add_orders_index
            $ querysense fix slow_query.json --django --desc optimize_search
        """
        from querysense.migration_gen import MigrationFormat, MigrationGenerator
        from querysense.fix_tracker import FixTracker

        try:
            output = parse_explain(explain_file)

            if require_analyze:
                validate_has_analyze(output)

            service = AnalysisService()
            result = service.analyze(output)
            findings = result.findings

            if not findings:
                console.print("-- No performance issues found. Nothing to fix.")
                return

            # ── Extract SQL fixes ──────────────────────────────────────
            seen_fixes: set[str] = set()
            all_sql_fixes: list[str] = []
            fix_metadata: list[dict] = []  # parallel list for tracker

            for finding in findings:
                if not finding.suggestion:
                    continue

                sql_lines: list[str] = []
                for line in finding.suggestion.split("\n"):
                    stripped = line.strip()
                    if stripped and not stripped.startswith("--"):
                        sql_lines.append(stripped)

                if not sql_lines:
                    continue

                fix_key = "\n".join(sql_lines)
                if fix_key in seen_fixes:
                    continue
                seen_fixes.add(fix_key)

                all_sql_fixes.append(fix_key)
                fix_metadata.append({
                    "rule": finding.rule_id,
                    "title": finding.title,
                    "impact": finding.impact_score,
                })

            if not all_sql_fixes:
                console.print("-- Issues found but no SQL fixes available.")
                return

            # ── Determine migration format ─────────────────────────────
            fmt: MigrationFormat | None = None
            if flyway:
                fmt = MigrationFormat.FLYWAY
            elif liquibase:
                fmt = MigrationFormat.LIQUIBASE
            elif alembic:
                fmt = MigrationFormat.ALEMBIC
            elif django:
                fmt = MigrationFormat.DJANGO
            elif dbmate:
                fmt = MigrationFormat.DBMATE

            # ── Generate migration file if format selected ─────────────
            if fmt:
                gen = MigrationGenerator(output_dir=migration_dir)
                migration_path = gen.generate(
                    fixes=all_sql_fixes,
                    format=fmt,
                    description=description,
                    source_plan=str(explain_file),
                )

                console.print(
                    f"[green bold]Migration generated:[/green bold] {migration_path}"
                )
                console.print(
                    f"  Format: [cyan]{fmt.value}[/cyan] | "
                    f"Fixes: [cyan]{len(all_sql_fixes)}[/cyan] | "
                    f"Dir: [dim]{migration_dir}[/dim]"
                )

                # Track fixes
                if track:
                    from querysense.fix_tracker import FixStatus
                    tracker = FixTracker()
                    for sql, meta in zip(all_sql_fixes, fix_metadata):
                        tracker.record_fix(
                            sql=sql,
                            finding_rule=meta["rule"],
                            migration_path=str(migration_path),
                            migration_format=fmt.value,
                            source_plan=str(explain_file),
                            impact_score=meta["impact"],
                            finding_title=meta["title"],
                        )
                    pending = len(tracker.get_by_status(FixStatus.PENDING))
                    console.print(
                        f"  Tracked: [dim]{len(all_sql_fixes)} fix(es) "
                        f"({pending} total pending)[/dim]"
                    )

                console.print(
                    f"\n[dim]Tip: Run 'querysense fix-status' to see all tracked fixes[/dim]"
                )
                return

            # ── Default: plain SQL output ──────────────────────────────
            console.print("-- QuerySense Fixes")
            console.print(f"-- {len(findings)} issue(s) detected\n")

            for finding in findings:
                if not finding.suggestion:
                    continue
                # Only print findings that contributed fixes
                sql_lines = [
                    l.strip() for l in finding.suggestion.split("\n")
                    if l.strip() and not l.strip().startswith("--")
                ]
                if not sql_lines:
                    continue

                console.print(
                    f"-- [{finding.severity.value.upper()}] {finding.title}"
                )
                for line in finding.suggestion.split("\n"):
                    if line.strip():
                        console.print(line)
                console.print()

            console.print("-- End of fixes")
            console.print("-- Run with: psql < fixes.sql")
            console.print(
                "\n[dim]Tip: Add --flyway, --liquibase, --alembic, or --django "
                "to generate a versioned migration file[/dim]"
            )

        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            if e.detail:
                error_console.print(f"\n[dim]{e.detail}[/dim]")
            raise typer.Exit(code=1)

    @app.command(name="fix-status")
    def fix_status(
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        status_filter: Annotated[
            Optional[str],
            typer.Option(
                "--status", "-s",
                help="Filter by status: pending, applied, skipped, failed",
            ),
        ] = None,
    ) -> None:
        """
        Show the lifecycle status of all tracked fixes.

        Displays which QuerySense fixes have been generated, applied,
        or skipped. Commit .querysense/fixes.json to share with your team.

        Examples:

            $ querysense fix-status
            $ querysense fix-status --status pending
            $ querysense fix-status --json
        """
        from querysense.fix_tracker import FixTracker, FixStatus

        tracker = FixTracker()
        all_fixes = tracker.get_all()

        if status_filter:
            try:
                target_status = FixStatus(status_filter.lower())
            except ValueError:
                error_console.print(
                    f"[red]Invalid status:[/red] {status_filter}. "
                    f"Choose from: pending, applied, skipped, failed, superseded"
                )
                raise typer.Exit(code=1)
            all_fixes = [f for f in all_fixes if f.status == target_status]

        if not all_fixes:
            console.print("[dim]No tracked fixes found.[/dim]")
            console.print(
                "[dim]Generate migration files with: "
                "querysense fix plan.json --flyway[/dim]"
            )
            return

        if json_output:
            import json as json_mod
            console.print_json(
                json_mod.dumps([f.to_dict() for f in all_fixes], indent=2)
            )
            return

        # Summary bar
        summary = tracker.summary()
        parts = []
        for s, count in sorted(summary.items()):
            color = {
                "pending": "yellow",
                "applied": "green",
                "skipped": "dim",
                "failed": "red",
                "superseded": "blue",
            }.get(s, "white")
            parts.append(f"[{color}]{s}: {count}[/{color}]")
        console.print(f"[bold]Fix Tracker[/bold]  {' | '.join(parts)}\n")

        # Table
        table = Table(show_lines=True)
        table.add_column("Status", width=10)
        table.add_column("Rule", style="cyan", width=20)
        table.add_column("Fix SQL", width=50)
        table.add_column("Migration", style="dim", width=30)
        table.add_column("Impact", width=8)

        status_styles = {
            "pending": "yellow",
            "applied": "green",
            "skipped": "dim",
            "failed": "red bold",
            "superseded": "blue",
        }

        for fix in all_fixes:
            style = status_styles.get(fix.status.value, "white")
            sql_preview = fix.sql[:47] + "..." if len(fix.sql) > 50 else fix.sql
            migration_name = Path(fix.migration_path).name if fix.migration_path else "-"
            impact_str = f"{fix.impact_score:.1f}/10" if fix.impact_score else "-"

            table.add_row(
                f"[{style}]{fix.status.value.upper()}[/{style}]",
                fix.finding_rule,
                sql_preview,
                migration_name,
                impact_str,
            )

        console.print(table)
        console.print(
            f"\n[dim]State file: .querysense/fixes.json "
            f"(commit this for team visibility)[/dim]"
        )

    @app.command(name="fix-apply")
    def fix_apply(
        fix_id: Annotated[
            str,
            typer.Argument(help="Fix ID to mark as applied (from fix-status output)"),
        ],
    ) -> None:
        """
        Mark a tracked fix as applied.

        After you've run the migration in your database, mark it as applied
        so QuerySense knows not to suggest it again.

        Examples:

            $ querysense fix-apply MISSING_INDEX_a1b2c3d4
        """
        from querysense.fix_tracker import FixTracker

        tracker = FixTracker()
        if tracker.mark_applied(fix_id):
            console.print(f"[green]Marked as applied:[/green] {fix_id}")
        else:
            error_console.print(
                f"[red]Fix not found:[/red] {fix_id}\n"
                "Run 'querysense fix-status' to see available fix IDs."
            )
            raise typer.Exit(code=1)

    @app.command(name="fix-skip")
    def fix_skip(
        fix_id: Annotated[
            str,
            typer.Argument(help="Fix ID to mark as skipped"),
        ],
    ) -> None:
        """
        Mark a tracked fix as intentionally skipped.

        Use this when a suggested fix isn't appropriate for your use case.

        Examples:

            $ querysense fix-skip MISSING_INDEX_a1b2c3d4
        """
        from querysense.fix_tracker import FixTracker

        tracker = FixTracker()
        if tracker.mark_skipped(fix_id):
            console.print(f"[dim]Marked as skipped:[/dim] {fix_id}")
        else:
            error_console.print(
                f"[red]Fix not found:[/red] {fix_id}\n"
                "Run 'querysense fix-status' to see available fix IDs."
            )
            raise typer.Exit(code=1)

    @app.command()
    def rules() -> None:
        """List all available detection rules."""
        from querysense.analyzer.registry import get_registry

        console.print("[bold]PostgreSQL Rules:[/bold]\n")

        registry = get_registry()
        all_rules = registry.all()

        table = Table()
        table.add_column("Rule ID", style="cyan")
        table.add_column("Severity")
        table.add_column("Description")

        for rule_cls in sorted(all_rules, key=lambda r: r.rule_id):
            severity = rule_cls.severity.value.upper()
            if severity == "CRITICAL":
                sev_style = "red bold"
            elif severity == "WARNING":
                sev_style = "yellow"
            else:
                sev_style = "blue"

            table.add_row(
                rule_cls.rule_id,
                f"[{sev_style}]{severity}[/{sev_style}]",
                rule_cls.description,
            )

        console.print(table)
        console.print(f"\n[dim]{len(all_rules)} rules available[/dim]")

    @app.command(name="buffers-diff")
    def buffers_diff(
        before_file: Annotated[
            Path,
            typer.Argument(
                help="EXPLAIN (ANALYZE, BUFFERS) output BEFORE optimization",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        after_file: Annotated[
            Path,
            typer.Argument(
                help="EXPLAIN (ANALYZE, BUFFERS) output AFTER optimization",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Compare I/O between two plan executions (before/after).

        Shows per-node and total disk read changes — proving exactly how
        much I/O was eliminated by an optimization (index, partition, etc).

        \b
        Examples:
            $ querysense buffers-diff before.json after.json
            $ querysense buffers-diff slow_plan.json optimized_plan.json --json
        """
        from querysense.analysis.buffers import BufferDiff

        differ = BufferDiff()
        try:
            report = differ.compare(before_file, after_file)
        except Exception as e:
            error_console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(code=1)

        if json_output:
            console.print_json(json.dumps(report.to_dict(), default=str))
            return

        # Overall improvement
        improvement = report.overall_improvement
        imp_color = "green" if "fewer" in improvement else ("red" if "more" in improvement else "yellow")
        console.print(Panel(
            f"[{imp_color} bold]{improvement}[/{imp_color} bold]",
            title="[bold]BUFFERS DIFF — I/O Comparison[/bold]",
            border_style=imp_color,
        ))

        # Before/After summary
        if report.before and report.after:
            summary_table = Table(title="Plan-Level I/O Summary")
            summary_table.add_column("Metric", style="bold")
            summary_table.add_column("Before", justify="right")
            summary_table.add_column("After", justify="right")
            summary_table.add_column("Delta", justify="right")

            b = report.before.summary()
            a = report.after.summary()

            def _delta_str(before_val: float, after_val: float, unit: str = "", lower_is_better: bool = True) -> str:
                delta = after_val - before_val
                if delta == 0:
                    return "[dim]--[/dim]"
                direction = delta < 0 if lower_is_better else delta > 0
                color = "green" if direction else "red"
                sign = "+" if delta > 0 else ""
                return f"[{color}]{sign}{delta:,.1f}{unit}[/{color}]"

            summary_table.add_row(
                "Shared Hit",
                f"{b['total_shared_hit']:,}",
                f"{a['total_shared_hit']:,}",
                _delta_str(b['total_shared_hit'], a['total_shared_hit'], "", lower_is_better=False),
            )
            summary_table.add_row(
                "Shared Read",
                f"{b['total_shared_read']:,}",
                f"{a['total_shared_read']:,}",
                _delta_str(b['total_shared_read'], a['total_shared_read']),
            )
            summary_table.add_row(
                "Disk Read MB",
                f"{b['total_disk_read_mb']:.1f}",
                f"{a['total_disk_read_mb']:.1f}",
                _delta_str(b['total_disk_read_mb'], a['total_disk_read_mb'], "MB"),
            )
            summary_table.add_row(
                "Cache Hit %",
                f"{b['overall_hit_pct']:.1f}%",
                f"{a['overall_hit_pct']:.1f}%",
                _delta_str(b['overall_hit_pct'], a['overall_hit_pct'], "%", lower_is_better=False),
            )

            console.print(summary_table)

        # Per-node diffs
        significant = [n for n in report.node_diffs if n.read_delta != 0 or n.hit_delta != 0]
        if significant:
            diff_table = Table(title="Per-Node I/O Changes")
            diff_table.add_column("Node", max_width=25)
            diff_table.add_column("Table", max_width=20, style="cyan")
            diff_table.add_column("Before Read", justify="right")
            diff_table.add_column("After Read", justify="right")
            diff_table.add_column("Delta", justify="right")
            diff_table.add_column("Impact")

            for n in significant[:20]:
                delta_color = "green" if n.read_delta < 0 else ("red" if n.read_delta > 0 else "dim")
                sign = "+" if n.read_delta > 0 else ""

                diff_table.add_row(
                    n.node_type,
                    n.table or "-",
                    f"{n.before_read:,}",
                    f"{n.after_read:,}",
                    f"[{delta_color}]{sign}{n.read_delta:,}[/{delta_color}]",
                    f"[{delta_color}]{n.improvement}[/{delta_color}]",
                )

            console.print(diff_table)
        else:
            console.print("[dim]No significant I/O changes detected between plans.[/dim]")
