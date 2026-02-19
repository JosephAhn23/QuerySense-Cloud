"""Upgrade validation commands: validate, snapshot, compare, knowledge."""

from __future__ import annotations

import glob as globmod
import json
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.table import Table

from querysense.engine import AnalysisService
from querysense.output.renderers import render_upgrade_markdown, render_upgrade_text
from querysense.parser import ParseError, parse_explain

console = Console()
error_console = Console(stderr=True)


def register(upgrade_app: typer.Typer) -> None:
    """Register upgrade commands on the given Typer sub-app."""

    @upgrade_app.command("validate")
    def upgrade_validate(
        plan_pattern: Annotated[
            str,
            typer.Argument(help="Glob pattern for post-upgrade EXPLAIN JSON files"),
        ],
        baseline_file: Annotated[
            str,
            typer.Option("--baseline", "-b", help="Path to pre-upgrade baseline file"),
        ] = ".querysense/baselines.json",
        before_version: Annotated[
            str,
            typer.Option("--before-version", help="PostgreSQL version before upgrade"),
        ] = "",
        after_version: Annotated[
            str,
            typer.Option("--after-version", help="PostgreSQL version after upgrade"),
        ] = "",
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: text, json, markdown"),
        ] = "text",
        output_file: Annotated[
            Optional[str],
            typer.Option("--output", "-o", help="Write output to file"),
        ] = None,
    ) -> None:
        """
        Validate query plans after a PostgreSQL version upgrade.

        Examples:

            $ querysense upgrade-check validate "plans/**/*.json" --before-version 15.4 --after-version 16.1
        """
        plan_files = sorted(globmod.glob(plan_pattern, recursive=True))

        if not plan_files:
            error_console.print(f"[yellow]No files matching '{plan_pattern}'[/yellow]")
            raise typer.Exit(code=0)

        console.print(
            f"[dim]Upgrade validation: {before_version or '?'} -> "
            f"{after_version or '?'} ({len(plan_files)} plans)[/dim]"
        )

        service = AnalysisService()
        parsed_plans: list[tuple[str, Any, str | None]] = []

        for plan_file in plan_files:
            try:
                explain = parse_explain(plan_file)
                query_id = Path(plan_file).stem
                parsed_plans.append((query_id, explain, plan_file))
            except ParseError as e:
                error_console.print(f"[red]Error parsing {plan_file}:[/red] {e.message}")
            except Exception as e:
                error_console.print(f"[red]Error:[/red] {plan_file}: {e}")

        if not parsed_plans:
            error_console.print("[red]No plans could be parsed[/red]")
            raise typer.Exit(code=1)

        report = service.validate_upgrade(
            plans=parsed_plans,
            baseline_path=baseline_file,
            before_version=before_version,
            after_version=after_version,
        )

        # Generate output using unified renderers
        if output_format == "json":
            output_text = json.dumps(report.to_summary_dict(), indent=2)
        elif output_format == "markdown":
            output_text = render_upgrade_markdown(report)
        else:
            output_text = render_upgrade_text(report)

        _write_output(output_text, output_file, output_format)

        if not report.safe_to_upgrade:
            error_console.print(
                f"\n[red bold]UPGRADE RISK:[/red bold] "
                f"{report.critical_regression_count} critical/high regression(s) detected"
            )
            raise typer.Exit(code=1)
        else:
            console.print(
                f"\n[green bold]UPGRADE SAFE:[/green bold] "
                f"{report.total_queries} queries checked, "
                f"{report.regression_count} minor regression(s)"
            )

    @upgrade_app.command("snapshot")
    def upgrade_snapshot(
        plan_pattern: Annotated[
            str,
            typer.Argument(help="Glob pattern for EXPLAIN JSON files to snapshot"),
        ],
        baseline_file: Annotated[
            str,
            typer.Option("--output", "-o", help="Path to write the baseline snapshot"),
        ] = ".querysense/baselines.json",
    ) -> None:
        """
        Capture a pre-upgrade baseline snapshot.

        Examples:

            $ querysense upgrade-check snapshot "plans/**/*.json"
        """
        service = AnalysisService()
        plan_files = sorted(globmod.glob(plan_pattern, recursive=True))

        if not plan_files:
            error_console.print(f"[yellow]No files matching '{plan_pattern}'[/yellow]")
            raise typer.Exit(code=0)

        plans: list[tuple[str, object]] = []
        for plan_file in plan_files:
            try:
                explain = parse_explain(plan_file)
                query_id = Path(plan_file).stem
                plans.append((query_id, explain))
            except ParseError as e:
                error_console.print(f"  [red]FAIL[/red] {plan_file}: {e.message}")
            except Exception as e:
                error_console.print(f"  [red]FAIL[/red] {plan_file}: {e}")

        if not plans:
            error_console.print("[red]No baselines could be recorded[/red]")
            raise typer.Exit(code=1)

        results = service.update_baselines(plans, baseline_path=baseline_file)

        for query_id, structure_hash in results.items():
            console.print(f"  [green]OK[/green] {query_id} (hash={structure_hash})")

        console.print(
            f"\n[green]Pre-upgrade snapshot: {len(results)} baseline(s) saved to "
            f"{baseline_file}[/green]"
        )
        console.print(
            "[dim]After upgrading, run: querysense upgrade-check validate[/dim]"
        )

    @upgrade_app.command("compare")
    def upgrade_compare(
        source: Annotated[
            str,
            typer.Option("--source", help="Source PostgreSQL connection string (old version)"),
        ] = "",
        target: Annotated[
            str,
            typer.Option("--target", help="Target PostgreSQL connection string (new version)"),
        ] = "",
        top_queries: Annotated[
            int,
            typer.Option("--top-queries", "-n", help="Number of top queries to compare"),
        ] = 100,
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: text, json, markdown"),
        ] = "text",
        output_file: Annotated[
            Optional[str],
            typer.Option("--output", "-o", help="Write output to file"),
        ] = None,
    ) -> None:
        """
        Compare query plans across PostgreSQL version upgrades.

        Examples:

            $ querysense upgrade compare --source postgresql://pg15/app --target postgresql://pg16/app
        """
        if not source or not target:
            error_console.print(
                "[red]Both --source and --target connection strings are required[/red]"
            )
            raise typer.Exit(code=1)

        from querysense.upgrade import UpgradeConfig, UpgradeValidator

        config = UpgradeConfig(source_dsn=source, target_dsn=target, top_queries=top_queries)

        console.print("[bold]QuerySense Upgrade Validation[/bold]")
        console.print(f"[dim]Comparing top {top_queries} queries...[/dim]\n")

        try:
            validator = UpgradeValidator(config)
            report = validator.validate()
        except SystemExit:
            raise
        except Exception as e:
            error_console.print(f"[red]Upgrade validation failed:[/red] {e}")
            raise typer.Exit(code=1)

        if output_format == "json":
            output_text = json.dumps(report.to_dict(), indent=2)
        else:
            output_text = report.render_summary()

        _write_output(output_text, output_file, output_format)

        if report.safe_to_upgrade:
            console.print(
                f"\n[green bold]SAFE TO UPGRADE[/green bold]: "
                f"{report.total_queries} queries compared, "
                f"{report.regressions} regression(s), 0 critical"
            )
        else:
            console.print(
                f"\n[red bold]UPGRADE RISK DETECTED[/red bold]: "
                f"{report.critical_regressions} critical regression(s) found"
            )
            raise typer.Exit(code=1)

    @upgrade_app.command("knowledge")
    def upgrade_knowledge(
        from_version: Annotated[
            int,
            typer.Option("--from", help="Source PostgreSQL major version"),
        ] = 15,
        to_version: Annotated[
            int,
            typer.Option("--to", help="Target PostgreSQL major version"),
        ] = 16,
    ) -> None:
        """
        Show known optimizer changes between PostgreSQL versions.

        Examples:

            $ querysense upgrade knowledge --from 15 --to 16
        """
        from querysense.upgrade import get_version_changes

        changes = get_version_changes(from_version, to_version)

        if not changes:
            console.print(
                f"[yellow]No known optimizer changes between "
                f"PG{from_version} and PG{to_version}[/yellow]"
            )
            return

        console.print(
            f"[bold]Known Optimizer Changes: PG{from_version} -> PG{to_version}[/bold]\n"
        )

        table = Table()
        table.add_column("Change", style="cyan")
        table.add_column("Risk")
        table.add_column("Description")
        table.add_column("Affected Nodes")

        risk_style = {"improvement": "green", "neutral": "yellow", "risk": "red"}

        for c in changes:
            style = risk_style.get(c.risk_level, "white")
            table.add_row(
                c.title,
                f"[{style}]{c.risk_level.upper()}[/{style}]",
                c.description[:80],
                ", ".join(c.affected_node_types[:3]) or "-",
            )

        console.print(table)
        console.print(f"\n[dim]{len(changes)} known change(s)[/dim]")


def _write_output(text: str, output_file: str | None, output_format: str) -> None:
    """Write output to file or stdout."""
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_text(text, encoding="utf-8")
        Console(stderr=True).print(f"[dim]Report written to {output_file}[/dim]")
    elif output_format in ("markdown", "json"):
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
    else:
        console.print(text)
