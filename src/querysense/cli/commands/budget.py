"""
Budget command: check query performance against declared budgets.

    $ querysense budget check
    $ querysense budget check --query get_user_by_id
    $ querysense budget init
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register budget commands on the given Typer app."""

    @app.command()
    def check(
        budget_file: Annotated[
            str,
            typer.Option(
                "--budget", "-b",
                help="Path to query-performance.yml",
            ),
        ] = "query-performance.yml",
        plan_dir: Annotated[
            str,
            typer.Option(
                "--plans", "-p",
                help="Directory of EXPLAIN JSON plans to check",
            ),
        ] = "plans",
        query: Annotated[
            Optional[str],
            typer.Option(
                "--query", "-q",
                help="Check a specific budget by name",
            ),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
        fail_on_violation: Annotated[
            bool,
            typer.Option(
                "--fail/--no-fail",
                help="Exit code 1 on any blocking violation",
            ),
        ] = True,
    ) -> None:
        """
        Check query plans against performance budgets.

        Loads budgets from query-performance.yml and checks EXPLAIN plans
        in the plans/ directory against them.

        Examples:

            $ querysense budget check
            $ querysense budget check --budget my-budgets.yml --plans ./explain-plans
            $ querysense budget check --query get_user_by_id --json
        """
        from querysense.budget import load_budgets, BudgetViolation

        try:
            engine = load_budgets(budget_file)
        except FileNotFoundError:
            error_console.print(
                f"[red]Budget file not found:[/red] {budget_file}\n"
                f"Run [bold]querysense budget init[/bold] to create one."
            )
            raise typer.Exit(code=1)
        except Exception as e:
            error_console.print(f"[red]Error loading budgets:[/red] {e}")
            raise typer.Exit(code=1)

        # Collect plan files
        plan_path = Path(plan_dir)
        all_violations: list[BudgetViolation] = []

        if plan_path.exists() and plan_path.is_dir():
            from querysense.parser import parse_explain, ParseError
            from querysense.engine import AnalysisService

            service = AnalysisService()
            plan_files = sorted(plan_path.glob("**/*.json"))

            if not plan_files:
                console.print(f"[dim]No plan files found in {plan_dir}/[/dim]")

            for pf in plan_files:
                plan_name = pf.stem
                if query and plan_name != query:
                    continue

                try:
                    output = parse_explain(pf)
                    result = service.analyze(output)

                    total_cost = output.plan.total_cost if hasattr(output.plan, 'total_cost') else 0
                    exec_time = output.execution_time or 0

                    has_seq = any(
                        n.node_type == "Seq Scan"
                        for n in output.all_nodes
                    )
                    max_seq_rows = max(
                        (n.actual_rows or n.plan_rows or 0
                         for n in output.all_nodes
                         if n.node_type == "Seq Scan"),
                        default=0,
                    )
                    has_idx = any(
                        "Index" in (n.node_type or "")
                        for n in output.all_nodes
                    )
                    criticals = sum(
                        1 for f in result.findings
                        if f.severity.value == "critical"
                    )

                    violations = engine.check(
                        query_name=plan_name,
                        total_cost=total_cost,
                        execution_time_ms=exec_time,
                        findings_count=len(result.findings),
                        critical_findings_count=criticals,
                        has_seq_scan=has_seq,
                        seq_scan_rows=max_seq_rows,
                        has_index_scan=has_idx,
                    )
                    all_violations.extend(violations)

                except Exception as e:
                    console.print(f"[yellow]Skipping {pf.name}:[/yellow] {e}")

        # Also check budgets with plan_file references
        for name, budget in engine.budgets.items():
            if query and name != query:
                continue
            if budget.plan_file:
                pf = Path(budget.plan_file)
                if pf.exists():
                    try:
                        from querysense.parser import parse_explain
                        from querysense.engine import AnalysisService

                        output = parse_explain(pf)
                        service = AnalysisService()
                        result = service.analyze(output)

                        total_cost = output.plan.total_cost if hasattr(output.plan, 'total_cost') else 0

                        violations = engine.check(
                            query_name=name,
                            total_cost=total_cost,
                            execution_time_ms=output.execution_time or 0,
                            findings_count=len(result.findings),
                        )
                        all_violations.extend(violations)
                    except Exception as e:
                        console.print(f"[yellow]Skipping {name}:[/yellow] {e}")

        # Output
        if json_output:
            console.print_json(json.dumps(
                [
                    {
                        "budget": v.budget_name,
                        "constraint": v.constraint,
                        "actual": v.actual_value,
                        "budget_value": v.budget_value,
                        "alert": v.alert.value,
                        "message": v.message,
                        "blocking": v.is_blocking,
                    }
                    for v in all_violations
                ],
                indent=2,
            ))

            if fail_on_violation and any(v.is_blocking for v in all_violations):
                raise typer.Exit(code=1)
            return

        if not all_violations:
            console.print(Panel(
                "[green bold]All budgets passing[/green bold]\n"
                f"Checked against {budget_file}",
                border_style="green",
            ))
            return

        # Table output
        table = Table(title="Budget Violations")
        table.add_column("Alert", width=10)
        table.add_column("Budget", style="cyan")
        table.add_column("Constraint")
        table.add_column("Actual")
        table.add_column("Budget")
        table.add_column("Message")

        blocking_count = 0
        for v in all_violations:
            style = {
                "info": "blue",
                "warning": "yellow",
                "critical": "red",
                "blocking": "red bold",
            }.get(v.alert.value, "white")

            if v.is_blocking:
                blocking_count += 1

            table.add_row(
                f"[{style}]{v.alert.value.upper()}[/{style}]",
                v.budget_name,
                v.constraint,
                f"{v.actual_value:,.1f}",
                f"{v.budget_value:,.1f}",
                v.message,
            )

        console.print(table)

        if blocking_count > 0:
            console.print(
                f"\n[red bold]{blocking_count} blocking violation(s) — CI will fail[/red bold]"
            )
            if fail_on_violation:
                raise typer.Exit(code=1)
        else:
            console.print(
                f"\n[yellow]{len(all_violations)} violation(s) — non-blocking[/yellow]"
            )

    @app.command()
    def init(
        output: Annotated[
            str,
            typer.Option("--output", "-o"),
        ] = "query-performance.yml",
    ) -> None:
        """
        Create a starter query-performance.yml budget file.

        Examples:

            $ querysense budget init
            $ querysense budget init -o my-budgets.yml
        """
        example = Path(__file__).parent.parent.parent.parent / "query-performance.example.yml"

        if Path(output).exists():
            error_console.print(
                f"[yellow]{output} already exists.[/yellow] "
                "Remove it first or use --output to write elsewhere."
            )
            raise typer.Exit(code=1)

        if example.exists():
            shutil.copy(example, output)
        else:
            # Inline minimal template
            Path(output).write_text(
                "# QuerySense Performance Budgets\n"
                "version: '1.0'\n\n"
                "defaults:\n"
                "  max_cost: 50000\n"
                "  max_time_ms: 500\n"
                "  deny_seq_scan_above: 10000\n\n"
                "budgets:\n"
                "  example_query:\n"
                "    sql_pattern: 'SELECT.*FROM.*'\n"
                "    max_cost: 10000\n"
                "    max_time_ms: 100\n"
                "    alert: warning\n",
                encoding="utf-8",
            )

        console.print(f"[green]Created {output}[/green]")
        console.print(
            "[dim]Edit this file to define budgets, then commit to your repo.\n"
            "Run 'querysense budget check' to validate.[/dim]"
        )
