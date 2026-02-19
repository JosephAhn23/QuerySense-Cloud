"""
CLI commands for Universal IR and Causal Analysis.

Provides:
- ``querysense ir translate``: Translate a plan to the universal IR
- ``querysense ir causal``: Run causal root-cause analysis
- ``querysense ir drift``: Detect plan drift/regressions over time
- ``querysense ir compare``: Compare two plans using the IR
- ``querysense ir verify``: Verify a fix recommendation
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
from rich.tree import Tree

console = Console()


def register(app: typer.Typer) -> None:
    """Register IR commands with the Typer app."""

    ir_app = typer.Typer(
        name="ir",
        help="Universal IR and causal plan analysis",
        no_args_is_help=True,
    )
    app.add_typer(ir_app, name="ir")

    @ir_app.command("translate")
    def translate(
        plan_file: Annotated[Path, typer.Argument(help="Path to EXPLAIN JSON/XML file")],
        engine: Annotated[
            Optional[str],
            typer.Option("--engine", "-e", help="Engine: postgres, mysql, sqlserver, oracle"),
        ] = None,
        output: Annotated[
            Optional[Path],
            typer.Option("--output", "-o", help="Output file (default: stdout)"),
        ] = None,
        compact: Annotated[bool, typer.Option("--compact", help="Compact JSON output")] = False,
    ) -> None:
        """Translate a plan to the universal IR format."""
        raw = _load_plan(plan_file)
        from querysense.ir.unified import UnifiedAnalyzer

        analyzer = UnifiedAnalyzer(store_snapshots=False)
        try:
            ir_plan = analyzer._translate(raw, engine, sql=None)
        except Exception as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1)

        ir_json = ir_plan.to_json(indent=None if compact else 2)

        if output:
            output.write_text(ir_json)
            console.print(f"[green]IR plan written to {output}[/green]")
        else:
            console.print_json(ir_json)

        # Summary
        fp = ir_plan.full_fingerprint()
        console.print(
            Panel(
                f"Engine: {ir_plan.engine}\n"
                f"Nodes: {ir_plan.node_count}\n"
                f"Structure Hash: {fp['structure']}\n"
                f"Capabilities: {len(ir_plan.capabilities)}",
                title="IR Translation Summary",
                border_style="blue",
            )
        )

    @ir_app.command("causal")
    def causal(
        plan_file: Annotated[Path, typer.Argument(help="Path to EXPLAIN JSON/XML file")],
        engine: Annotated[
            Optional[str],
            typer.Option("--engine", "-e", help="Engine hint"),
        ] = None,
        sql: Annotated[
            Optional[str],
            typer.Option("--sql", help="SQL query text"),
        ] = None,
        top: Annotated[int, typer.Option("--top", "-n", help="Show top N causes")] = 5,
        json_output: Annotated[
            bool, typer.Option("--json", help="JSON output")
        ] = False,
    ) -> None:
        """Run causal root-cause analysis on a query plan."""
        raw = _load_plan(plan_file)
        from querysense.ir.unified import UnifiedAnalyzer

        analyzer = UnifiedAnalyzer(store_snapshots=False)
        report = analyzer.analyze_raw(raw, engine=engine, sql=sql)

        if json_output:
            data = {
                "engine": report.ir_plan.engine,
                "nodes": report.ir_plan.node_count,
                "capabilities": report.capabilities,
                "hypotheses": [
                    {
                        "rank": rh.rank,
                        "id": rh.hypothesis.id.value,
                        "title": rh.hypothesis.title,
                        "confidence": round(rh.confidence, 3),
                        "category": rh.hypothesis.category,
                        "evidence_count": rh.evidence_count,
                        "explanation": rh.explanation,
                        "remediation": rh.result.remediation,
                        "affected_nodes": rh.result.affected_nodes,
                    }
                    for rh in report.causal_report.ranked[:top]
                ],
                "skipped": [
                    {"name": name, "missing": missing}
                    for name, missing in report.causal_report.skipped
                ],
            }
            console.print_json(json.dumps(data, indent=2))
            return

        # Rich output
        console.print(
            Panel(
                f"Engine: [bold]{report.ir_plan.engine}[/bold]  |  "
                f"Nodes: [bold]{report.ir_plan.node_count}[/bold]  |  "
                f"Capabilities: [bold]{len(report.capabilities)}[/bold]",
                title="Causal Root-Cause Analysis",
                border_style="cyan",
            )
        )

        if not report.causal_report.has_findings:
            console.print("[green]No root-cause hypotheses matched the evidence.[/green]")
            return

        table = Table(
            title=f"Top {min(top, len(report.causal_report.ranked))} Root Causes",
            show_lines=True,
        )
        table.add_column("#", style="bold", width=3)
        table.add_column("Confidence", justify="center", width=12)
        table.add_column("Hypothesis", style="bold cyan", min_width=20)
        table.add_column("Category", width=12)
        table.add_column("Explanation", min_width=30)
        table.add_column("Nodes", width=8)

        for rh in report.causal_report.ranked[:top]:
            conf = rh.confidence
            if conf >= 0.7:
                conf_style = "bold red"
            elif conf >= 0.4:
                conf_style = "bold yellow"
            else:
                conf_style = "dim"

            table.add_row(
                str(rh.rank),
                f"[{conf_style}]{conf:.0%}[/{conf_style}]",
                rh.hypothesis.title,
                rh.hypothesis.category,
                rh.explanation[:80] + ("..." if len(rh.explanation) > 80 else ""),
                str(len(rh.result.affected_nodes)),
            )

        console.print(table)

        # Show remediation for top cause
        top_cause = report.causal_report.top_cause
        if top_cause and top_cause.result.remediation:
            console.print(
                Panel(
                    top_cause.result.remediation,
                    title=f"Recommended Fix: {top_cause.hypothesis.title}",
                    border_style="green",
                )
            )

        if report.causal_report.skipped:
            console.print(
                f"\n[dim]{len(report.causal_report.skipped)} hypotheses skipped "
                f"(insufficient evidence)[/dim]"
            )

    @ir_app.command("compare")
    def compare(
        before_file: Annotated[Path, typer.Argument(help="Path to 'before' EXPLAIN JSON")],
        after_file: Annotated[Path, typer.Argument(help="Path to 'after' EXPLAIN JSON")],
        engine: Annotated[
            Optional[str],
            typer.Option("--engine", "-e", help="Engine hint"),
        ] = None,
    ) -> None:
        """Compare two plans using the universal IR."""
        before_raw = _load_plan(before_file)
        after_raw = _load_plan(after_file)

        from querysense.ir.unified import UnifiedAnalyzer
        from querysense.verification.comparator import compare_ir_plans

        analyzer = UnifiedAnalyzer(store_snapshots=False)
        before_ir = analyzer._translate(before_raw, engine, sql=None)
        after_ir = analyzer._translate(after_raw, engine, sql=None)

        comparison = compare_ir_plans(before_ir, after_ir)

        # Header
        status = "[green]IMPROVED[/green]" if comparison.has_improvements else (
            "[red]REGRESSED[/red]" if comparison.has_regressions else "[yellow]UNCHANGED[/yellow]"
        )
        console.print(
            Panel(
                f"Status: {status}\n"
                f"Structure Changed: {'Yes' if comparison.structure_changed else 'No'}\n"
                f"Cost: {comparison.total_cost_before:.1f} -> {comparison.total_cost_after:.1f} "
                f"({comparison.cost_improvement_pct:+.1f}%)\n"
                f"Scan Improvements: {comparison.scan_improvements}  |  "
                f"Scan Regressions: {comparison.scan_regressions}\n"
                f"New Nodes: {comparison.new_count}  |  Removed: {comparison.removed_count}",
                title="IR Plan Comparison",
                border_style="cyan",
            )
        )

        # Changed nodes detail
        changed = [d for d in comparison.node_diffs if d.operator_changed]
        if changed:
            table = Table(title="Operator Changes")
            table.add_column("Node", width=8)
            table.add_column("Before", width=20)
            table.add_column("After", width=20)
            table.add_column("Cost Delta", justify="right", width=12)
            table.add_column("Table", width=15)
            table.add_column("Type")

            for d in changed:
                change_type = (
                    "[green]upgrade[/green]" if d.scan_upgrade
                    else "[red]downgrade[/red]" if d.scan_downgrade
                    else "changed"
                )
                table.add_row(
                    d.node_id,
                    d.before_op.value,
                    d.after_op.value if d.after_op else "removed",
                    f"{d.cost_delta:+.1f}",
                    d.relation or "",
                    change_type,
                )

            console.print(table)

    @ir_app.command("tree")
    def tree_view(
        plan_file: Annotated[Path, typer.Argument(help="Path to EXPLAIN JSON/XML file")],
        engine: Annotated[
            Optional[str],
            typer.Option("--engine", "-e", help="Engine hint"),
        ] = None,
    ) -> None:
        """Display the IR plan as an interactive tree."""
        raw = _load_plan(plan_file)
        from querysense.ir.unified import UnifiedAnalyzer

        analyzer = UnifiedAnalyzer(store_snapshots=False)
        ir_plan = analyzer._translate(raw, engine, sql=None)

        tree = Tree(
            f"[bold cyan]{ir_plan.engine}[/bold cyan] plan "
            f"({ir_plan.node_count} nodes)",
        )
        _build_tree(tree, ir_plan.root)
        console.print(tree)

    @ir_app.command("capabilities")
    def capabilities(
        plan_file: Annotated[Path, typer.Argument(help="Path to EXPLAIN JSON/XML file")],
        engine: Annotated[
            Optional[str],
            typer.Option("--engine", "-e", help="Engine hint"),
        ] = None,
    ) -> None:
        """Show capabilities derived from a plan."""
        raw = _load_plan(plan_file)
        from querysense.ir.unified import UnifiedAnalyzer

        analyzer = UnifiedAnalyzer(store_snapshots=False)
        ir_plan = analyzer._translate(raw, engine, sql=None)

        table = Table(title="Derived Capabilities")
        table.add_column("Capability", style="cyan")
        table.add_column("Available", justify="center")

        from querysense.ir.annotations import IRCapability
        for cap in sorted(IRCapability, key=lambda c: c.value):
            available = cap in ir_plan.capabilities
            style = "green" if available else "dim"
            table.add_row(
                cap.value,
                f"[{style}]{'Yes' if available else 'No'}[/{style}]",
            )

        console.print(table)
        console.print(
            f"\n[bold]{sum(1 for c in IRCapability if c in ir_plan.capabilities)}"
            f"/{len(IRCapability)}[/bold] capabilities available"
        )


def _load_plan(path: Path) -> dict | str | list:
    """Load a plan file (JSON or XML)."""
    content = path.read_text(encoding="utf-8")
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Might be XML (SQL Server)
        if content.strip().startswith("<"):
            return content
        raise


def _build_tree(parent: Tree, node: "UniversalIRNode") -> None:
    """Recursively build a Rich tree from IR nodes."""
    # Node label
    parts = [f"[bold]{node.operator.value}[/bold]"]
    if node.algorithm and node.algorithm != node.operator.value:
        parts.append(f"[dim]({node.algorithm})[/dim]")
    if node.properties.relation_name:
        parts.append(f"[yellow]{node.properties.relation_name}[/yellow]")
    if node.properties.index_name:
        parts.append(f"[green]via {node.properties.index_name}[/green]")

    c = node.properties.cardinality
    if c.actual_rows is not None:
        parts.append(f"rows={c.actual_rows:.0f}")
    elif c.estimated_rows is not None:
        parts.append(f"est={c.estimated_rows:.0f}")

    cost = node.properties.cost
    if cost.total_cost is not None:
        parts.append(f"cost={cost.total_cost:.1f}")

    t = node.properties.time
    if t.self_time_ms is not None:
        parts.append(f"self={t.self_time_ms:.1f}ms")

    if node.properties.memory.is_spilling:
        parts.append("[red]SPILL[/red]")

    label = "  ".join(parts)
    child_tree = parent.add(label)

    for child in node.children:
        _build_tree(child_tree, child)


# Type hint for tree building
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from querysense.ir.plan import IRNode as UniversalIRNode
