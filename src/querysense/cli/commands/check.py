"""
Check command: the git-diff for query performance.

Compare a baseline plan against a current plan and exit non-zero on regression.
Designed to be the simplest possible CI integration:

    querysense check --baseline main.json --current pr.json

This is the "secret weapon" — deterministic regression detection in one command.
"""

from __future__ import annotations

import json
import sys
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
    """Register the check command on the given Typer app."""

    @app.command()
    def check(
        baseline: Annotated[
            Path,
            typer.Option(
                "--baseline", "-b",
                help="Path to baseline EXPLAIN JSON (e.g. main branch plan)",
                exists=True,
                readable=True,
            ),
        ],
        current: Annotated[
            Path,
            typer.Option(
                "--current", "-c",
                help="Path to current EXPLAIN JSON (e.g. PR branch plan)",
                exists=True,
                readable=True,
            ),
        ],
        baseline_sql: Annotated[
            Optional[Path],
            typer.Option(
                "--baseline-sql",
                help="Optional SQL file for baseline plan",
                exists=True,
                readable=True,
            ),
        ] = None,
        current_sql: Annotated[
            Optional[Path],
            typer.Option(
                "--current-sql",
                help="Optional SQL file for current plan",
                exists=True,
                readable=True,
            ),
        ] = None,
        fail_on: Annotated[
            str,
            typer.Option(
                "--fail-on",
                help="Exit non-zero on: regression, new-critical, new-warning, any-new, never",
            ),
        ] = "regression",
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output as JSON for CI parsing"),
        ] = False,
        output_file: Annotated[
            Optional[Path],
            typer.Option("--output", "-o", help="Write comparison result to file"),
        ] = None,
        allow_plain: Annotated[
            bool,
            typer.Option("--allow-plain", help="Allow EXPLAIN without ANALYZE data"),
        ] = False,
    ) -> None:
        """
        Compare two EXPLAIN plans — the git diff for query performance.

        Compares a baseline plan (e.g. from main branch) against a current plan
        (e.g. from a PR) and reports regressions, improvements, and new issues.
        Exits non-zero if regressions are detected.

        \\b
        Quick start:
            $ querysense check --baseline main.json --current pr.json

        \\b
        In CI (GitHub Actions):
            - run: querysense check -b plans/main.json -c plans/pr.json --json -o result.json

        \\b
        Strict mode (fail on any new issue):
            $ querysense check -b main.json -c pr.json --fail-on any-new

        \\b
        Exit codes:
            0 = No regressions (pass)
            1 = Regressions detected (fail)
            2 = Parse/input error
        """
        from querysense.analyzer.comparator import compare_analyses, compare_plans
        from querysense.parser.parser import validate_has_analyze

        # ── Parse both plans ─────────────────────────────────────────
        try:
            baseline_explain = parse_explain(baseline)
            if not allow_plain:
                validate_has_analyze(baseline_explain)
        except ParseError as e:
            error_console.print(f"[red]Baseline parse error:[/red] {e.message}")
            raise typer.Exit(code=2)
        except Exception as e:
            error_console.print(f"[red]Baseline error:[/red] {e}")
            raise typer.Exit(code=2)

        try:
            current_explain = parse_explain(current)
            if not allow_plain:
                validate_has_analyze(current_explain)
        except ParseError as e:
            error_console.print(f"[red]Current parse error:[/red] {e.message}")
            raise typer.Exit(code=2)
        except Exception as e:
            error_console.print(f"[red]Current error:[/red] {e}")
            raise typer.Exit(code=2)

        # ── Analyze both plans ───────────────────────────────────────
        service = AnalysisService()

        b_sql = baseline_sql.read_text(encoding="utf-8") if baseline_sql else None
        c_sql = current_sql.read_text(encoding="utf-8") if current_sql else None

        baseline_result = service.analyze(baseline_explain, sql=b_sql)
        current_result = service.analyze(current_explain, sql=c_sql)

        # ── Compare ──────────────────────────────────────────────────
        analysis_diff = compare_analyses(baseline_result, current_result)
        plan_diff = compare_plans(baseline_explain, current_explain)

        # ── Cost delta from raw plans ────────────────────────────────
        b_cost = baseline_explain.plan.get("Total Cost", 0)
        c_cost = current_explain.plan.get("Total Cost", 0)
        cost_delta = c_cost - b_cost
        cost_pct = (cost_delta / b_cost * 100) if b_cost > 0 else 0

        b_time = baseline_explain.plan.get("Actual Total Time")
        c_time = current_explain.plan.get("Actual Total Time")
        time_delta = None
        time_pct = None
        if b_time is not None and c_time is not None:
            time_delta = c_time - b_time
            time_pct = (time_delta / b_time * 100) if b_time > 0 else 0

        # ── Build result ─────────────────────────────────────────────
        result = {
            "status": "pass",
            "baseline_file": str(baseline),
            "current_file": str(current),
            "summary": {
                "fixed_count": len(analysis_diff.fixed_issues),
                "new_count": len(analysis_diff.new_issues),
                "unchanged_count": len(analysis_diff.unchanged_issues),
                "net_improvement": analysis_diff.net_improvement,
                "is_regression": analysis_diff.is_regression,
                "is_improvement": analysis_diff.is_improvement,
                "cost_delta": round(cost_delta, 2),
                "cost_delta_pct": round(cost_pct, 1),
            },
            "new_issues": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "suggestion": f.suggestion,
                }
                for f in analysis_diff.new_issues
            ],
            "fixed_issues": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                }
                for f in analysis_diff.fixed_issues
            ],
            "node_changes": len([d for d in plan_diff.node_diffs if d.status == "changed"]),
        }

        if time_delta is not None:
            result["summary"]["time_delta_ms"] = round(time_delta, 2)
            result["summary"]["time_delta_pct"] = round(time_pct, 1)

        # ── Determine verdict ────────────────────────────────────────
        is_fail = False
        if fail_on == "regression":
            is_fail = analysis_diff.is_regression or cost_pct > 20
        elif fail_on == "new-critical":
            is_fail = any(f.severity.value == "critical" for f in analysis_diff.new_issues)
        elif fail_on == "new-warning":
            is_fail = any(
                f.severity.value in ("critical", "warning")
                for f in analysis_diff.new_issues
            )
        elif fail_on == "any-new":
            is_fail = len(analysis_diff.new_issues) > 0
        elif fail_on == "never":
            is_fail = False

        result["status"] = "fail" if is_fail else "pass"

        # ── JSON output ──────────────────────────────────────────────
        if json_output or output_file:
            json_text = json.dumps(result, indent=2)
            if output_file:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(json_text, encoding="utf-8")
                error_console.print(f"[dim]Results written to {output_file}[/dim]")
            if json_output:
                sys.stdout.buffer.write(json_text.encode("utf-8"))
                sys.stdout.buffer.write(b"\n")
                sys.stdout.buffer.flush()
                raise typer.Exit(code=1 if is_fail else 0)

        # ── Rich terminal output ─────────────────────────────────────
        _render_check_output(
            analysis_diff=analysis_diff,
            plan_diff=plan_diff,
            baseline_explain=baseline_explain,
            current_explain=current_explain,
            cost_delta=cost_delta,
            cost_pct=cost_pct,
            time_delta=time_delta,
            time_pct=time_pct,
            baseline_path=str(baseline),
            current_path=str(current),
            is_fail=is_fail,
        )

        raise typer.Exit(code=1 if is_fail else 0)


def _render_check_output(
    *,
    analysis_diff,
    plan_diff,
    baseline_explain,
    current_explain,
    cost_delta: float,
    cost_pct: float,
    time_delta: float | None,
    time_pct: float | None,
    baseline_path: str,
    current_path: str,
    is_fail: bool,
) -> None:
    """Render rich terminal output for the check command."""
    # Header
    if is_fail:
        verdict_style = "red bold"
        verdict_text = "REGRESSION DETECTED"
        verdict_icon = "✗"
    elif analysis_diff.is_improvement:
        verdict_style = "green bold"
        verdict_text = "IMPROVED"
        verdict_icon = "✓"
    else:
        verdict_style = "green bold"
        verdict_text = "NO REGRESSION"
        verdict_icon = "✓"

    console.print()
    console.print(Panel(
        f"[{verdict_style}]{verdict_icon} {verdict_text}[/{verdict_style}]",
        title="QuerySense Check",
        subtitle=f"{baseline_path} → {current_path}",
        border_style="red" if is_fail else "green",
    ))

    # Summary table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Baseline", justify="right")
    table.add_column("Current", justify="right")
    table.add_column("Delta", justify="right")

    # Cost
    b_findings = len(analysis_diff.before.findings)
    c_findings = len(analysis_diff.after.findings)
    delta_str = f"{analysis_diff.net_improvement:+d}"
    delta_style = "green" if analysis_diff.net_improvement >= 0 else "red"
    table.add_row(
        "Total findings",
        str(b_findings),
        str(c_findings),
        f"[{delta_style}]{delta_str}[/{delta_style}]",
    )

    # Cost row — show baseline/current costs and delta percentage
    cost_sign = "+" if cost_delta > 0 else ""
    cost_style = "red" if cost_delta > 0 else "green"
    b_cost_display = f"{baseline_explain.plan.get('Total Cost', 0):.0f}"
    c_cost_display = f"{current_explain.plan.get('Total Cost', 0):.0f}"
    table.add_row(
        "Plan cost",
        b_cost_display,
        c_cost_display,
        f"[{cost_style}]{cost_sign}{cost_pct:.1f}%[/{cost_style}]",
    )

    if time_delta is not None:
        time_sign = "+" if time_delta > 0 else ""
        time_style = "red" if time_delta > 0 else "green"
        table.add_row(
            "Execution time",
            "—",
            "—",
            f"[{time_style}]{time_sign}{time_pct:.1f}% ({time_sign}{time_delta:.1f}ms)[/{time_style}]",
        )

    # Critical / Warning counts
    from querysense.analyzer.models import Severity

    for sev in Severity:
        b_count = len(analysis_diff.before.findings_by_severity(sev))
        c_count = len(analysis_diff.after.findings_by_severity(sev))
        d = c_count - b_count
        if b_count > 0 or c_count > 0:
            d_str = f"{d:+d}" if d != 0 else "="
            d_style = "red" if d > 0 else ("green" if d < 0 else "dim")
            sev_icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(sev.value, "")
            table.add_row(
                f"{sev_icon} {sev.value.capitalize()}",
                str(b_count),
                str(c_count),
                f"[{d_style}]{d_str}[/{d_style}]",
            )

    console.print(table)

    # Node changes
    changed_nodes = [d for d in plan_diff.node_diffs if d.status == "changed"]
    if changed_nodes:
        console.print(f"\n[bold]Node changes:[/bold] {len(changed_nodes)}")
        for nd in changed_nodes[:5]:
            if nd.scan_type_changed:
                console.print(
                    f"  {nd.path}: {nd.before_type} → {nd.after_type}"
                    + (" [green]✓ index scan[/green]" if nd.became_index_scan else "")
                )

    # Fixed issues
    if analysis_diff.fixed_issues:
        console.print(f"\n[green bold]Fixed ({len(analysis_diff.fixed_issues)}):[/green bold]")
        for f in analysis_diff.fixed_issues:
            console.print(f"  [green]✓[/green] {f.title} [dim]({f.rule_id})[/dim]")

    # New issues
    if analysis_diff.new_issues:
        console.print(f"\n[red bold]New issues ({len(analysis_diff.new_issues)}):[/red bold]")
        for f in analysis_diff.new_issues:
            sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(f.severity.value, "white")
            console.print(
                f"  [{sev_color}]✗[/{sev_color}] {f.title} [dim]({f.rule_id})[/dim]"
            )
            if f.suggestion:
                console.print(f"    [dim]Fix: {f.suggestion[:120]}[/dim]")

    console.print()
