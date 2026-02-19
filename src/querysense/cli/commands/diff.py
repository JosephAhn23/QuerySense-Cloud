"""
Diff command: compare two EXPLAIN plans side-by-side.

This is the top-level `querysense diff` command that developers actually want:
take a before.json and after.json, show what changed structurally and whether
performance improved or regressed.

Addresses pain point #8: "I can't compare before/after plans easily."

Usage:
    querysense diff before.json after.json
    querysense diff before.json after.json --json
    querysense diff before.json after.json --markdown -o report.md
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from querysense.engine import AnalysisService
from querysense.parser import ParseError, parse_explain
from querysense.plan_diff import diff_plan_nodes

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register the diff command on the given Typer app."""

    @app.command()
    def diff(
        before_file: Annotated[
            Path,
            typer.Argument(
                help="Path to the BEFORE EXPLAIN JSON (baseline/old plan)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        after_file: Annotated[
            Path,
            typer.Argument(
                help="Path to the AFTER EXPLAIN JSON (current/new plan)",
                exists=True,
                readable=True,
                resolve_path=True,
            ),
        ],
        json_output: Annotated[
            bool,
            typer.Option("--json", "-j", help="Output diff as JSON"),
        ] = False,
        markdown_output: Annotated[
            bool,
            typer.Option("--markdown", "-m", help="Output diff as Markdown"),
        ] = False,
        output_file: Annotated[
            Optional[str],
            typer.Option("--output", "-o", help="Write output to file"),
        ] = None,
    ) -> None:
        """
        Compare two EXPLAIN plans and show what changed.

        Takes a before and after EXPLAIN JSON file and produces a structured
        diff showing structural changes, cost changes, node additions/removals,
        and whether performance improved or regressed.

        \b
        Examples:
            # Quick before/after comparison
            $ querysense diff before.json after.json

            # After applying a fix, verify improvement
            $ psql -c "EXPLAIN (ANALYZE, FORMAT JSON) ..." > after.json
            $ querysense diff before.json after.json

            # Generate markdown report
            $ querysense diff before.json after.json --markdown -o diff_report.md

            # JSON output for programmatic use
            $ querysense diff before.json after.json --json
        """
        try:
            before_explain = parse_explain(before_file)
            after_explain = parse_explain(after_file)
        except ParseError as e:
            error_console.print(f"[red]Error:[/red] {e.message}")
            if e.detail:
                error_console.print(f"\n[dim]{e.detail}[/dim]")
            raise typer.Exit(code=1)

        # Normalize both plans for structural comparison
        from querysense.baseline import _normalize_plan_tree, _compute_structure_hash

        before_normalized = _normalize_plan_tree(before_explain.plan)
        after_normalized = _normalize_plan_tree(after_explain.plan)

        before_hash = _compute_structure_hash(before_normalized)
        after_hash = _compute_structure_hash(after_normalized)

        before_by_path = {n["path"]: n for n in before_normalized}
        after_by_path = {n["path"]: n for n in after_normalized}

        node_type_changes, nodes_added, nodes_removed = diff_plan_nodes(
            before_by_path, after_by_path
        )

        # Compute metrics
        cost_before = before_explain.plan.total_cost
        cost_after = after_explain.plan.total_cost
        cost_change_pct = (
            ((cost_after - cost_before) / cost_before * 100)
            if cost_before > 0 else 0.0
        )

        rows_before = before_explain.plan.plan_rows
        rows_after = after_explain.plan.plan_rows

        time_before = before_explain.execution_time
        time_after = after_explain.execution_time

        nodes_before = len(before_explain.all_nodes)
        nodes_after = len(after_explain.all_nodes)

        is_structural_change = before_hash != after_hash
        is_improvement = cost_after < cost_before
        is_regression = cost_after > cost_before * 1.1  # >10% cost increase

        # Run analysis on both plans
        service = AnalysisService()
        before_result = service.analyze(before_explain)
        after_result = service.analyze(after_explain)

        findings_before = len(before_result.findings)
        findings_after = len(after_result.findings)

        # Build diff data
        diff_data: dict[str, Any] = {
            "structural_change": is_structural_change,
            "structure_hash_before": before_hash,
            "structure_hash_after": after_hash,
            "cost_before": cost_before,
            "cost_after": cost_after,
            "cost_change_percent": round(cost_change_pct, 2),
            "rows_before": rows_before,
            "rows_after": rows_after,
            "execution_time_before_ms": time_before,
            "execution_time_after_ms": time_after,
            "nodes_before": nodes_before,
            "nodes_after": nodes_after,
            "findings_before": findings_before,
            "findings_after": findings_after,
            "is_improvement": is_improvement,
            "is_regression": is_regression,
            "node_type_changes": node_type_changes,
            "nodes_added": nodes_added,
            "nodes_removed": nodes_removed,
        }

        # Output
        if json_output:
            output_text = json.dumps(diff_data, indent=2, default=str)
        elif markdown_output:
            output_text = _render_diff_markdown(
                diff_data, str(before_file.name), str(after_file.name)
            )
        else:
            _render_diff_rich(
                diff_data, str(before_file.name), str(after_file.name)
            )
            # If no file output requested, we're done (rendered to console)
            if not output_file:
                return
            # For file output, fall back to markdown
            output_text = _render_diff_markdown(
                diff_data, str(before_file.name), str(after_file.name)
            )

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            Path(output_file).write_text(output_text, encoding="utf-8")
            error_console.print(f"[dim]Diff written to {output_file}[/dim]")
        else:
            console.print(output_text)


def _render_diff_rich(
    diff_data: dict[str, Any],
    before_name: str,
    after_name: str,
) -> None:
    """Render diff with Rich formatting to the console."""
    is_improvement = diff_data["is_improvement"]
    is_regression = diff_data["is_regression"]
    structural = diff_data["structural_change"]

    # Header
    if is_improvement:
        status = "[green bold]IMPROVED[/green bold]"
        border = "green"
    elif is_regression:
        status = "[red bold]REGRESSED[/red bold]"
        border = "red"
    elif structural:
        status = "[yellow bold]CHANGED[/yellow bold]"
        border = "yellow"
    else:
        status = "[green bold]UNCHANGED[/green bold]"
        border = "green"

    console.print(Panel(
        f"Plan comparison: {status}",
        title=f"QuerySense Diff: {before_name} → {after_name}",
        border_style=border,
    ))

    # Metrics table
    table = Table(title="Plan Metrics", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Before", justify="right")
    table.add_column("After", justify="right")
    table.add_column("Change", justify="right")

    # Cost
    cost_change = diff_data["cost_change_percent"]
    cost_style = "green" if cost_change < 0 else ("red" if cost_change > 10 else "yellow")
    table.add_row(
        "Total Cost",
        f"{diff_data['cost_before']:,.0f}",
        f"{diff_data['cost_after']:,.0f}",
        f"[{cost_style}]{cost_change:+.1f}%[/{cost_style}]",
    )

    # Execution time
    time_before = diff_data["execution_time_before_ms"]
    time_after = diff_data["execution_time_after_ms"]
    if time_before is not None and time_after is not None:
        time_change = ((time_after - time_before) / time_before * 100) if time_before > 0 else 0
        time_style = "green" if time_change < 0 else ("red" if time_change > 10 else "yellow")
        table.add_row(
            "Execution Time",
            f"{time_before:.2f}ms",
            f"{time_after:.2f}ms",
            f"[{time_style}]{time_change:+.1f}%[/{time_style}]",
        )

    # Rows
    table.add_row(
        "Estimated Rows",
        f"{diff_data['rows_before']:,}",
        f"{diff_data['rows_after']:,}",
        "",
    )

    # Nodes
    table.add_row(
        "Plan Nodes",
        str(diff_data["nodes_before"]),
        str(diff_data["nodes_after"]),
        "",
    )

    # Findings
    fb = diff_data["findings_before"]
    fa = diff_data["findings_after"]
    findings_style = "green" if fa < fb else ("red" if fa > fb else "dim")
    table.add_row(
        "Issues Found",
        str(fb),
        str(fa),
        f"[{findings_style}]{fa - fb:+d}[/{findings_style}]" if fa != fb else "[dim]—[/dim]",
    )

    console.print(table)

    # Structural changes
    changes = diff_data["node_type_changes"]
    added = diff_data["nodes_added"]
    removed = diff_data["nodes_removed"]

    if changes or added or removed:
        console.print("\n[bold]Structural Changes:[/bold]")

        for change in changes:
            from querysense.baseline import _compute_transition_danger
            danger = _compute_transition_danger(change["before"], change["after"])
            relation = f" on {change.get('relation', '')}" if change.get("relation") else ""

            if danger >= 60:
                style = "red bold"
            elif danger >= 30:
                style = "yellow"
            else:
                style = "dim"

            console.print(
                f"  [{style}]{change['path']}:[/{style}] "
                f"[red]{change['before']}[/red] → [green]{change['after']}[/green]"
                f"{relation} [dim](danger: {danger})[/dim]"
            )

        for node in added:
            console.print(f"  [green]+ {node}[/green]")

        for node in removed:
            console.print(f"  [red]- {node}[/red]")
    else:
        console.print("\n[dim]No structural changes — plan shape is identical.[/dim]")

    # Summary
    console.print()
    if is_improvement:
        speedup = diff_data["cost_before"] / diff_data["cost_after"] if diff_data["cost_after"] > 0 else 0
        console.print(f"[green bold]Performance improved — {speedup:.1f}x faster by cost estimate[/green bold]")
    elif is_regression:
        console.print(f"[red bold]Performance regressed — cost increased {diff_data['cost_change_percent']:+.1f}%[/red bold]")
    console.print()


def _render_diff_markdown(
    diff_data: dict[str, Any],
    before_name: str,
    after_name: str,
) -> str:
    """Render diff as Markdown."""
    lines: list[str] = []

    is_improvement = diff_data["is_improvement"]
    is_regression = diff_data["is_regression"]
    structural = diff_data["structural_change"]

    if is_improvement:
        lines.append(f"## ✅ Plan Improved: `{before_name}` → `{after_name}`")
    elif is_regression:
        lines.append(f"## 🔴 Plan Regressed: `{before_name}` → `{after_name}`")
    elif structural:
        lines.append(f"## 🟡 Plan Changed: `{before_name}` → `{after_name}`")
    else:
        lines.append(f"## ✅ Plan Unchanged: `{before_name}` → `{after_name}`")

    lines.append("")

    # Metrics table
    lines.append("| Metric | Before | After | Change |")
    lines.append("|--------|-------:|------:|-------:|")

    cost_change = diff_data["cost_change_percent"]
    lines.append(
        f"| Total Cost | {diff_data['cost_before']:,.0f} | "
        f"{diff_data['cost_after']:,.0f} | {cost_change:+.1f}% |"
    )

    time_before = diff_data["execution_time_before_ms"]
    time_after = diff_data["execution_time_after_ms"]
    if time_before is not None and time_after is not None:
        time_change = ((time_after - time_before) / time_before * 100) if time_before > 0 else 0
        lines.append(
            f"| Execution Time | {time_before:.2f}ms | "
            f"{time_after:.2f}ms | {time_change:+.1f}% |"
        )

    lines.append(
        f"| Estimated Rows | {diff_data['rows_before']:,} | "
        f"{diff_data['rows_after']:,} | |"
    )

    fb = diff_data["findings_before"]
    fa = diff_data["findings_after"]
    lines.append(f"| Issues Found | {fb} | {fa} | {fa - fb:+d} |")

    lines.append("")

    # Structural changes
    changes = diff_data["node_type_changes"]
    added = diff_data["nodes_added"]
    removed = diff_data["nodes_removed"]

    if changes or added or removed:
        lines.append("### Structural Changes")
        lines.append("")

        for change in changes:
            relation = f" on `{change.get('relation', '')}`" if change.get("relation") else ""
            lines.append(
                f"- `{change['path']}`: **{change['before']}** → **{change['after']}**{relation}"
            )

        for node in added:
            lines.append(f"- ➕ {node}")

        for node in removed:
            lines.append(f"- ➖ {node}")

        lines.append("")

    # Summary
    if is_improvement:
        speedup = diff_data["cost_before"] / diff_data["cost_after"] if diff_data["cost_after"] > 0 else 0
        lines.append(f"**Result:** Performance improved — **{speedup:.1f}x** faster by cost estimate")
    elif is_regression:
        lines.append(f"**Result:** Performance regressed — cost increased **{cost_change:+.1f}%**")
    else:
        lines.append("**Result:** No significant performance change")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by [QuerySense](https://github.com/JosephAhn23/Query-Sense)*")

    return "\n".join(lines)
