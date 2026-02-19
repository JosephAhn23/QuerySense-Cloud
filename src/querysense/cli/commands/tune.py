"""
Tune command — automated Query Tuning Workbook (Ch. 16).

Implements Dombrovskaya's "Ultimate Optimization Algorithm" as a CLI command:
    querysense tune explain.json --sql query.sql
    querysense tune explain.json --sql query.sql --dsn postgresql://localhost/mydb

Offline mode (no DB): generates hypotheses, variants, and predicted improvements.
Online mode (with --dsn): actually tests variants against the database.
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
    """Register tune commands."""

    @app.command()
    def tune(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        sql_file: Annotated[
            Optional[Path],
            typer.Option(
                "--sql", "-s",
                help="Path to SQL file containing the query",
            ),
        ] = None,
        sql_inline: Annotated[
            Optional[str],
            typer.Option(
                "--query", "-q",
                help="Inline SQL query string",
            ),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        max_variants: Annotated[
            int,
            typer.Option("--max-variants", help="Maximum number of variants to generate"),
        ] = 10,
    ) -> None:
        """
        Run the automated Query Tuning Workbook.

        Implements the scientific method for query optimization
        (Dombrovskaya et al. 2024, Chapter 16):

        1. BASELINE — capture current plan metrics
        2. DIAGNOSE — run 35+ QuerySense rules
        3. HYPOTHESIZE — generate optimization hypotheses with planner behavior explanations
        4. PLAN — create concrete variants (rewrites, indexes, config changes)
        5. PREDICT — estimate impact before execution
        6. RECOMMEND — rank variants by predicted improvement

        pganalyze Workbooks require manual variant creation. QuerySense automates it.
        """
        from querysense.workbook import TuningWorkbook

        # Load explain
        raw = explain_file.read_text(encoding="utf-8")

        # Load SQL
        sql = ""
        if sql_file and sql_file.exists():
            sql = sql_file.read_text(encoding="utf-8")
        elif sql_inline:
            sql = sql_inline

        # Run workbook
        try:
            wb = TuningWorkbook(max_variants=max_variants)
            plan_data = json.loads(raw)
            result = wb.run(plan_data, sql=sql)
        except json.JSONDecodeError:
            error_console.print("[red]Error:[/red] Invalid JSON in explain file")
            raise typer.Exit(1)
        except Exception as e:
            error_console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

        if json_output:
            console.print_json(json.dumps(result.to_dict(), indent=2, default=str))
            return

        # Rich output
        console.print()
        console.print(Panel(
            "[bold]QuerySense Tuning Workbook[/bold]\n"
            "Automated implementation of the Ultimate Optimization Algorithm\n"
            "(Dombrovskaya et al. 2024, Chapter 16)",
            border_style="blue",
        ))
        console.print()

        # Baseline
        if result.baseline:
            b = result.baseline
            console.print("[bold cyan]Baseline[/bold cyan]")
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_row("Total Cost:", f"{b.total_cost:,.1f}")
            if b.execution_time_ms:
                table.add_row("Execution Time:", f"{b.execution_time_ms:.2f} ms")
            table.add_row("Plan Nodes:", str(b.node_count))
            table.add_row("Findings:", f"{b.findings_count} ({b.critical_count} critical)")
            console.print(table)
            console.print()

        # Hypotheses
        if result.hypotheses:
            console.print("[bold cyan]Hypotheses[/bold cyan]")
            hyp_table = Table(
                show_header=True,
                header_style="bold",
                border_style="dim",
            )
            hyp_table.add_column("#", width=3)
            hyp_table.add_column("Hypothesis", min_width=30)
            hyp_table.add_column("Impact", width=10)
            hyp_table.add_column("Confidence", width=10)

            for i, h in enumerate(result.hypotheses, 1):
                impact_color = {"major": "red", "moderate": "yellow", "minor": "dim"}.get(h.expected_impact, "white")
                hyp_table.add_row(
                    str(i),
                    h.hypothesis,
                    f"[{impact_color}]{h.expected_impact}[/{impact_color}]",
                    f"{h.confidence:.0%}",
                )
            console.print(hyp_table)
            console.print()

        # Recommendations
        if result.recommendations:
            console.print("[bold cyan]Recommendations (ranked by impact)[/bold cyan]")
            for i, v in enumerate(result.recommendations, 1):
                risk_color = {
                    "none": "green", "low": "green",
                    "medium": "yellow", "high": "red",
                }.get(v.risk.value, "white")

                console.print(
                    f"  [bold]{i}.[/bold] {v.name}  "
                    f"[green]+{v.improvement_pct:.1f}%[/green]  "
                    f"[{risk_color}]{v.risk.value} risk[/{risk_color}]"
                )
                console.print(f"     [dim]{v.hypothesis.mechanism[:100]}...[/dim]")

                if v.rewritten_sql:
                    console.print(f"     [bold]SQL:[/bold]")
                    for line in v.rewritten_sql.split("\n")[:3]:
                        console.print(f"       {line}")

                if v.index_ddl:
                    console.print(f"     [bold]DDL:[/bold] {v.index_ddl}")

                if v.planner_settings:
                    for k, val in v.planner_settings.items():
                        console.print(f"     [bold]SET[/bold] {k} = {val};")

                if v.config_commands:
                    for cmd in v.config_commands:
                        console.print(f"     {cmd}")

                console.print()
        else:
            console.print("[green]No optimization opportunities found — query is well-tuned![/green]")

        # Summary
        console.print(Panel(
            f"Hypotheses: {len(result.hypotheses)} | "
            f"Variants: {len(result.variants)} | "
            f"Recommendations: {len(result.recommendations)} | "
            f"Best improvement: {result.total_potential_improvement:+.1f}% | "
            f"Time: {result.total_time_ms:.0f}ms",
            title="Summary",
            border_style="green",
        ))

    @app.command()
    def explain_planner(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
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
        Explain WHY PostgreSQL chose each plan decision.

        For every node in the execution plan, shows:
        - What the planner chose and why
        - The decision factors (cost model, settings, statistics)
        - What alternatives were rejected and why
        - How to change the planner's behavior

        Based on Peng & Peng Ch. 5 and Dombrovskaya Ch. 4-5.
        """
        from querysense.planner_insight import explain_plan_choices

        raw = explain_file.read_text(encoding="utf-8")

        try:
            plan_data = json.loads(raw)
            insights = explain_plan_choices(plan_data)
        except json.JSONDecodeError:
            error_console.print("[red]Error:[/red] Invalid JSON in explain file")
            raise typer.Exit(1)
        except Exception as e:
            error_console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

        if json_output:
            console.print_json(json.dumps(
                [i.to_dict() for i in insights],
                indent=2,
                default=str,
            ))
            return

        console.print()
        console.print(Panel(
            "[bold]PostgreSQL Planner Behavior Analysis[/bold]\n"
            "Why the planner chose each operator",
            border_style="blue",
        ))
        console.print()

        for insight in insights:
            color = "yellow" if "Seq Scan" in insight.node_type else "cyan"
            console.print(f"[bold {color}]{insight.node_type}[/bold {color}]"
                          f"{' on ' + insight.relation if insight.relation else ''}")
            console.print(f"  {insight.explanation}")

            for factor in insight.decision_factors:
                console.print(f"    [dim]>[/dim] {factor.factor}")
                console.print(f"      Value: {factor.value}")
                console.print(f"      Influence: {factor.influence}")
                if factor.adjustable and factor.fix_hint:
                    console.print(f"      [green]Fix: {factor.fix_hint}[/green]")

            if insight.alternative_paths:
                console.print(f"    [dim]Rejected:[/dim] {', '.join(insight.alternative_paths[:2])}")

            if insight.textbook_ref:
                console.print(f"    [dim]Ref: {insight.textbook_ref}[/dim]")

            console.print()

    @app.command()
    def advise_config(
        explain_file: Annotated[
            Path,
            typer.Argument(
                help="Path to EXPLAIN output file (JSON format)",
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
        Get query-specific PostgreSQL configuration recommendations.

        Analyzes the EXPLAIN plan to identify which settings
        are causing suboptimal plan choices for THIS specific query.

        Unlike static config auditing, this connects plan-level
        problems to their configuration root causes.
        """
        from querysense.config_advisor import QueryConfigAdvisor

        raw = explain_file.read_text(encoding="utf-8")

        try:
            plan_data = json.loads(raw)
            advisor = QueryConfigAdvisor()
            result = advisor.analyze(plan_data)
        except json.JSONDecodeError:
            error_console.print("[red]Error:[/red] Invalid JSON in explain file")
            raise typer.Exit(1)
        except Exception as e:
            error_console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

        if json_output:
            console.print_json(json.dumps(result.to_dict(), indent=2, default=str))
            return

        console.print()
        console.print(Panel(
            "[bold]Query-Aware Configuration Advisor[/bold]\n"
            f"Plan: {result.plan_summary}",
            border_style="blue",
        ))
        console.print()

        if not result.recommendations:
            console.print("[green]No configuration issues found for this query.[/green]")
            return

        for i, rec in enumerate(result.recommendations, 1):
            risk_color = {
                "none": "green", "low": "green",
                "medium": "yellow", "high": "red",
            }.get(rec.risk, "white")

            console.print(
                f"  [bold]{i}.[/bold] [cyan]{rec.parameter}[/cyan]: "
                f"{rec.current_value} -> [green]{rec.recommended_value}[/green]  "
                f"[{risk_color}]{rec.risk} risk[/{risk_color}]"
            )
            console.print(f"     {rec.reason}")
            console.print(f"     [dim]{rec.mechanism[:120]}[/dim]")
            console.print(f"     [bold]Apply:[/bold] {rec.apply_sql.split(chr(10))[0]}")
            if rec.textbook_ref:
                console.print(f"     [dim]Ref: {rec.textbook_ref}[/dim]")
            console.print()
