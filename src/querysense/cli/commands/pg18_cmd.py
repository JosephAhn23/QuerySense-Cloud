"""
CLI commands for PG18 Advisor, pg_stat_plans, Cloud Cost, and Query Advisor.

Commands:
    querysense pg18 analyze --dsn postgresql://...
    querysense plans track --dsn postgresql://...
    querysense cloud-cost compare --instance db.r6g.xlarge ...
    querysense query-advisor run --dsn postgresql://...
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


def register_pg18(parent: typer.Typer) -> None:
    """Register PG18 advisor commands."""

    @parent.command(name="analyze")
    def pg18_analyze(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")],
        output_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """Analyze PG18 readiness and recommend upgrades."""
        from querysense.pg18_advisor import PG18Advisor

        advisor = PG18Advisor()
        report = asyncio.run(advisor.analyze(dsn))

        if output_json:
            console.print_json(json.dumps(report.to_dict(), default=str))
            return

        status = "[green]PG18+[/]" if report.is_pg18_or_later else f"[yellow]PG{report.major_version}[/]"
        console.print(Panel(
            f"[bold]Version:[/] {report.current_version[:60]}\n"
            f"[bold]Status:[/] {status}\n"
            f"[bold]Findings:[/] {report.total_findings}\n"
            f"[bold]UUID tables:[/] {len(report.uuid_tables)}\n"
            f"[bold]Skip Scan candidates:[/] {len(report.skip_scan_candidates)}",
            title="PostgreSQL 18 Readiness Report",
        ))

        severity_colors = {"critical": "red", "warning": "yellow", "notice": "blue", "info": "white"}

        for finding in report.findings:
            color = severity_colors.get(finding.severity, "white")
            console.print(Panel(
                f"{finding.description}\n\n"
                f"[green]Recommendation:[/] {finding.recommendation}"
                + (f"\n\n[cyan]SQL:[/]\n{finding.sql_command}" if finding.sql_command else "")
                + (f"\n\n[yellow]Impact:[/] {finding.impact}" if finding.impact else ""),
                title=f"[{color}]{finding.severity.upper()}[/{color}] [{finding.category}] {finding.title}",
            ))


def register_plans(parent: typer.Typer) -> None:
    """Register pg_stat_plans commands."""

    @parent.command(name="track")
    def plans_track(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")],
        top_n: Annotated[int, typer.Option("--top", help="Top N queries")] = 50,
        output_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """Track plan-level metrics and detect plan changes."""
        from querysense.pg_stat_plans import PlanTracker

        tracker = PlanTracker()
        report = asyncio.run(tracker.analyze(dsn, top_n=top_n))

        if output_json:
            console.print_json(json.dumps(report.to_dict(), default=str))
            return

        ext_status = "[green]pg_stat_plans installed[/]" if report.has_pg_stat_plans else "[yellow]fallback mode (pg_stat_statements)[/]"
        console.print(Panel(
            f"[bold]Extension:[/] {ext_status}\n"
            f"[bold]Plans tracked:[/] {report.total_plans}\n"
            f"[bold]Queries:[/] {report.total_queries}\n"
            f"[bold]Multi-plan queries:[/] {len(report.queries_with_multiple_plans)}\n"
            f"[bold]Plan changes:[/] {len(report.plan_changes)}\n"
            f"[bold]Volatile queries:[/] {len(report.top_volatile_queries)}",
            title="Plan Tracker Report",
        ))

        if report.queries_with_multiple_plans:
            table = Table(title="Queries With Multiple Plans")
            table.add_column("QueryID", style="cyan")
            table.add_column("Plans", justify="right")
            table.add_column("Time Variance (ms)", justify="right", style="red")
            table.add_column("Query", max_width=50)

            for q in report.queries_with_multiple_plans:
                table.add_row(
                    str(q["queryid"]),
                    str(q["plan_count"]),
                    f"{q['time_variance']:.1f}",
                    q["query"][:50],
                )
            console.print(table)

        if report.plan_changes:
            table = Table(title="Plan Changes Detected")
            table.add_column("QueryID", style="cyan")
            table.add_column("Old Plan", style="dim")
            table.add_column("New Plan", style="green")
            table.add_column("Change", style="bold")
            table.add_column("Regression?", style="red")

            for c in report.plan_changes:
                pct_str = f"{c.regression_pct:+.1f}%"
                table.add_row(
                    str(c.queryid),
                    c.old_plan_id[:12],
                    c.new_plan_id[:12],
                    pct_str,
                    "YES" if c.is_regression else "no",
                )
            console.print(table)

        if report.top_volatile_queries:
            table = Table(title="Volatile Queries (Possible Plan Flapping)")
            table.add_column("QueryID", style="cyan")
            table.add_column("Mean (ms)", justify="right")
            table.add_column("Max (ms)", justify="right", style="red")
            table.add_column("Variance", justify="right")
            table.add_column("Query", max_width=50)

            for q in report.top_volatile_queries:
                table.add_row(
                    str(q["queryid"]),
                    f"{q['mean_ms']:.1f}",
                    f"{q['max_ms']:.1f}",
                    f"{q['variance_ratio']:.0f}x",
                    q["query"][:50],
                )
            console.print(table)


def register_cloud_cost(parent: typer.Typer) -> None:
    """Register cloud cost advisor commands."""

    @parent.command(name="compare")
    def cloud_cost_compare(
        instance: Annotated[str, typer.Option("--instance", help="Instance type")] = "db.r6g.xlarge",
        storage_gb: Annotated[int, typer.Option("--storage", help="Storage in GB")] = 500,
        iops: Annotated[int, typer.Option("--iops", help="Provisioned IOPS")] = 3000,
        io_millions: Annotated[float, typer.Option("--io-millions", help="Monthly I/O requests (millions)")] = 100,
        replicas: Annotated[int, typer.Option("--replicas", help="Read replicas")] = 0,
        output_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """Compare RDS vs Aurora vs EKS deployment costs."""
        from querysense.cloud_cost_advisor import CloudCostAdvisor

        advisor = CloudCostAdvisor()
        report = advisor.compare_deployments(
            instance_type=instance,
            storage_gb=storage_gb,
            iops=iops,
            monthly_io_requests_millions=io_millions,
            replicas=replicas,
        )

        if output_json:
            console.print_json(json.dumps(report.to_dict(), default=str))
            return

        table = Table(title=f"Cloud Cost Comparison ({instance}, {storage_gb}GB, {io_millions}M I/O/mo)")
        table.add_column("Deployment", style="cyan")
        table.add_column("Compute", justify="right")
        table.add_column("Storage", justify="right")
        table.add_column("I/O", justify="right")
        table.add_column("Monthly Total", justify="right", style="bold")
        table.add_column("Annual", justify="right")
        table.add_column("w/ Savings Plan", justify="right", style="green")

        for d in report.deployments:
            name = {
                "rds": "RDS PostgreSQL",
                "aurora_standard": "Aurora Standard",
                "aurora_io_optimized": "Aurora I/O-Opt",
                "eks_cnpg": "EKS + CloudNativePG",
            }.get(d.deployment, d.deployment)

            is_cheapest = d.deployment == report.cheapest
            name_str = f"[green]{name} *[/]" if is_cheapest else name

            table.add_row(
                name_str,
                f"${d.compute_monthly:,.0f}",
                f"${d.storage_monthly:,.0f}",
                f"${d.io_monthly:,.0f}",
                f"${d.total_monthly:,.0f}",
                f"${d.total_annual:,.0f}",
                f"${d.savings_plan_annual:,.0f}",
            )

        console.print(table)

        console.print(f"\n[bold]Recommendation:[/] {report.recommendation}")
        console.print(
            f"\n[dim]Aurora I/O-Optimized breakeven: "
            f"{report.aurora_io_breakeven}M I/O requests/month[/]"
        )

    @parent.command(name="savings-plan")
    def savings_plan(
        monthly_spend: Annotated[float, typer.Option("--monthly", help="Current monthly spend ($)")],
        term: Annotated[int, typer.Option("--term", help="Commitment term (1 or 3 years)")] = 1,
    ) -> None:
        """Calculate AWS Database Savings Plans savings."""
        from querysense.cloud_cost_advisor import CloudCostAdvisor

        advisor = CloudCostAdvisor()
        result = advisor.savings_plan_calculator(monthly_spend, term)

        console.print(Panel(
            f"[bold]Current monthly:[/] ${result['current_monthly']:,.2f}\n"
            f"[bold]Current annual:[/] ${result['current_annual']:,.2f}\n\n"
            f"[green]With {term}-year Savings Plan:[/]\n"
            f"  Monthly: ${result['with_savings_plan_monthly']:,.2f}\n"
            f"  Annual: ${result['with_savings_plan_annual']:,.2f}\n"
            f"  [green]Savings: ${result['savings_annual']:,.2f}/year ({result['discount_pct']:.0f}% off)[/]\n\n"
            f"[bold]Total commitment:[/] ${result['total_commitment']:,.2f} over {term} year(s)",
            title="AWS Database Savings Plan Calculator",
        ))


def register_query_advisor(parent: typer.Typer) -> None:
    """Register Query Advisor commands."""

    @parent.command(name="run")
    def query_advisor_run(
        dsn: Annotated[str, typer.Option("--dsn", help="PostgreSQL DSN")],
        min_time: Annotated[float, typer.Option("--min-time", help="Min exec time (ms)")] = 50,
        min_calls: Annotated[int, typer.Option("--min-calls", help="Min call count")] = 5,
        output_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
    ) -> None:
        """Automatically detect slow queries and suggest rewrites."""
        from querysense.query_advisor import QueryAdvisor

        advisor = QueryAdvisor()
        report = asyncio.run(advisor.analyze(dsn, min_exec_time_ms=min_time, min_calls=min_calls))

        if output_json:
            console.print_json(json.dumps(report.to_dict(), default=str))
            return

        console.print(Panel(
            f"[bold]Queries analyzed:[/] {report.queries_analyzed}\n"
            f"[bold]Plans inspected:[/] {report.queries_with_plans}\n"
            f"[bold]Insights found:[/] {len(report.insights)}\n"
            f"[bold]Potential savings:[/] {report.total_potential_savings_ms:,.0f}ms total",
            title="Query Advisor Report",
        ))

        severity_colors = {"critical": "red", "warning": "yellow", "notice": "blue", "info": "white"}

        for i, insight in enumerate(report.insights[:20], 1):
            color = severity_colors.get(insight.severity, "white")

            body = f"{insight.description}\n"
            if insight.rewrite_sql:
                body += f"\n[green]Fix:[/]\n{insight.rewrite_sql}\n"
            if insight.config_change:
                body += f"\n[cyan]Config:[/]\n{insight.config_change}\n"
            if insight.estimated_improvement:
                body += f"\n[yellow]Expected improvement:[/] {insight.estimated_improvement}"

            console.print(Panel(
                body,
                title=(
                    f"[{color}]#{i}[/{color}] {insight.title} "
                    f"({insight.mean_exec_time_ms:.1f}ms avg, {insight.calls:,} calls)"
                ),
            ))

        if report.top_offenders:
            table = Table(title="Top Offenders by Total Time")
            table.add_column("#", style="bold")
            table.add_column("Total (ms)", justify="right", style="red")
            table.add_column("Insight")
            table.add_column("Query", max_width=50)

            for i, off in enumerate(report.top_offenders[:10], 1):
                table.add_row(
                    str(i),
                    f"{off['time_ms']:,.0f}",
                    off["insight"],
                    off["query"][:50],
                )

            console.print(table)
