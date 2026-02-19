"""
CLI command: querysense validate

Validation Hub -- prove QuerySense's claims with reproducible benchmarks.

Usage:
    querysense validate                          # Standard corpus benchmark
    querysense validate ./plans/                 # Custom plan directory
    querysense validate --compare pganalyze      # Compare with specific competitor
    querysense validate --json > results.json    # Machine-readable output
    querysense validate --iterations 500         # Higher-precision throughput
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register(app: typer.Typer) -> None:
    @app.command("validate")
    def validate(
        plan_dir: Annotated[
            Optional[Path],
            typer.Argument(
                help="Directory of .json plan files (uses built-in corpus if omitted)",
            ),
        ] = None,
        compare: Annotated[
            str,
            typer.Option(
                "--compare", "-c",
                help="Competitors to compare: all, pganalyze, eversql, pgmustard, datadog",
            ),
        ] = "all",
        iterations: Annotated[
            int,
            typer.Option(
                "--iterations", "-n",
                help="Iterations for throughput measurement (higher = more precise)",
            ),
        ] = 100,
        min_throughput: Annotated[
            float,
            typer.Option(
                "--min-throughput",
                help="Minimum plans/sec to pass (default: 200)",
            ),
        ] = 200.0,
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON"),
        ] = False,
    ) -> None:
        """
        Run the QuerySense Validation Hub -- reproducible benchmarks with proof.

        Measures throughput (plans/sec), rule coverage, and competitive comparison
        on standardized EXPLAIN plan corpora. Use this to prove QuerySense's
        claims to skeptics, or to gate CI on performance regression.

        \\b
        Examples:
            $ querysense validate                     # Standard benchmark
            $ querysense validate ./my-plans/          # Custom plans
            $ querysense validate --compare pganalyze  # Specific competitor
            $ querysense validate --json > report.json # CI-friendly output
        """
        from querysense.validation_hub import ValidationHub

        hub = ValidationHub(min_plans_per_sec=min_throughput)

        # Determine comparisons
        compare_with: list[str] | None = None
        if compare != "all":
            compare_with = [c.strip() for c in compare.split(",")]

        if not json_output:
            corpus_desc = str(plan_dir) if plan_dir else "built-in standard corpus (10 plans)"
            console.print()
            console.print(Panel(
                f"[bold]QuerySense Validation Hub[/bold]\n"
                f"Corpus: {corpus_desc}\n"
                f"Iterations: {iterations}\n"
                f"Min throughput: {min_throughput:.0f} plans/sec",
                title="[bold blue]Benchmark Starting[/bold blue]",
                border_style="blue",
            ))
            console.print()

        # Run benchmark
        report = hub.run_benchmark(
            plan_dir=plan_dir,
            compare_with=compare_with,
            iterations=iterations,
        )

        if json_output:
            console.print(report.to_json())
            if not report.passed:
                raise typer.Exit(1)
            return

        # Rich output
        # Throughput
        console.print(Panel(
            f"[bold green]{report.throughput.plans_per_sec:,.1f} plans/sec[/bold green]\n"
            f"Avg: {report.throughput.avg_analysis_ms:.3f}ms  |  "
            f"P95: {report.throughput.p95_analysis_ms:.3f}ms  |  "
            f"P99: {report.throughput.p99_analysis_ms:.3f}ms\n"
            f"Total: {report.throughput.total_plans:,} analyses in {report.throughput.total_time_sec:.2f}s",
            title="[bold]Throughput[/bold]",
            border_style="green" if report.throughput.plans_per_sec >= min_throughput else "red",
        ))
        console.print()

        # Coverage
        coverage_table = Table(title="Rule Coverage", show_header=True, header_style="bold")
        coverage_table.add_column("Metric", style="cyan")
        coverage_table.add_column("Value", justify="right", style="bold")
        coverage_table.add_row("Rules available", str(report.coverage.total_rules_available))
        coverage_table.add_row("Rules fired", str(report.coverage.rules_fired))
        coverage_table.add_row("Total findings", str(report.coverage.total_findings))
        coverage_table.add_row("Avg per plan", f"{report.coverage.avg_findings_per_plan:.1f}")
        console.print(coverage_table)
        console.print()

        # Findings breakdown
        if report.coverage.findings_by_rule:
            findings_table = Table(title="Findings by Rule", show_header=True, header_style="bold")
            findings_table.add_column("Rule ID", style="cyan")
            findings_table.add_column("Count", justify="right", style="bold")
            for rule_id, count in sorted(
                report.coverage.findings_by_rule.items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                findings_table.add_row(rule_id, str(count))
            console.print(findings_table)
            console.print()

        # Competitor comparison
        if report.comparisons:
            comp_table = Table(
                title="Competitive Comparison",
                show_header=True,
                header_style="bold",
            )
            comp_table.add_column("Tool", style="cyan")
            comp_table.add_column("Price", style="yellow")
            comp_table.add_column("Est. Findings", justify="right")
            comp_table.add_column("QS Findings", justify="right", style="bold green")
            comp_table.add_column("QS Advantage", justify="right", style="bold")

            for comp in report.comparisons:
                advantage_str = f"+{comp.finding_advantage}" if comp.finding_advantage > 0 else str(comp.finding_advantage)
                comp_table.add_row(
                    comp.competitor_name,
                    comp.competitor_pricing,
                    str(comp.competitor_estimated_findings),
                    str(comp.querysense_findings),
                    advantage_str,
                )

            # Add QuerySense row
            comp_table.add_row(
                "[bold]QuerySense[/bold]",
                "[bold green]Free forever[/bold green]",
                "-",
                str(report.coverage.total_findings),
                "[bold green]Baseline[/bold green]",
            )

            console.print(comp_table)
            console.print()

            # Capability advantages
            for comp in report.comparisons:
                if comp.capability_advantages:
                    console.print(
                        f"  [bold]vs {comp.competitor_name}[/bold]: "
                        f"QS advantages: {', '.join(comp.capability_advantages[:5])}"
                    )

            console.print()

        # Pass/Fail
        if report.passed:
            console.print(Panel(
                "[bold green]ALL CHECKS PASSED[/bold green]\n"
                f"Throughput: {report.throughput.plans_per_sec:,.1f} plans/sec "
                f"(min: {min_throughput:.0f})\n"
                f"Findings: {report.coverage.total_findings} across {report.corpus_size} plans",
                title="[bold green]VALIDATION RESULT[/bold green]",
                border_style="green",
            ))
        else:
            console.print(Panel(
                "[bold red]VALIDATION FAILED[/bold red]\n"
                + "\n".join(f"  - {f}" for f in report.failures),
                title="[bold red]VALIDATION RESULT[/bold red]",
                border_style="red",
            ))
            raise typer.Exit(1)

        # Reproducibility note
        console.print(
            f"\n[dim]Corpus hash: {report.corpus_hash[:16]}  |  "
            f"Reproduce: querysense validate --iterations {iterations}[/dim]\n"
        )
