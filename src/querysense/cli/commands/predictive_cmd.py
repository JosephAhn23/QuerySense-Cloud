"""
CLI commands for next-level analysis:
- querysense predict -- predictive workload optimization
- querysense holistic -- coordinated multi-dimension tuning
- querysense geqo -- genetic optimizer analysis
- querysense profile-nodes -- deep per-node execution profiling
- querysense calibrate -- cost model calibration
- querysense stability -- plan stability analysis
- querysense translate -- cross-DB semantic translation
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

console = Console()


def _load_plans(paths: list[Path]) -> list[dict]:
    """Load EXPLAIN JSON plans from file paths."""
    plans = []
    for p in paths:
        if not p.exists():
            console.print(f"[yellow]Skipping missing file: {p}[/yellow]")
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            plans.append(data)
        except json.JSONDecodeError:
            console.print(f"[yellow]Skipping invalid JSON: {p}[/yellow]")
    return plans


def register(app: typer.Typer) -> None:

    @app.command("predict")
    def predict(
        plans_dir: Annotated[
            Path,
            typer.Argument(help="Directory of EXPLAIN JSON plans (or single file)"),
        ],
        top_k: Annotated[
            int,
            typer.Option("--top", "-k", help="Number of recommendations"),
        ] = 10,
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Predictive workload optimization -- identify critical queries and predict improvements."""
        from querysense.predictive import PredictiveOptimizer

        if plans_dir.is_dir():
            plan_files = sorted(plans_dir.glob("*.json"))
        else:
            plan_files = [plans_dir]

        plans = _load_plans(plan_files)
        if not plans:
            console.print("[red]No valid EXPLAIN JSON plans found.[/red]")
            raise typer.Exit(1)

        optimizer = PredictiveOptimizer()
        result = optimizer.optimize(plans, top_k=top_k)

        if output_json:
            console.print(result.to_json())
        else:
            console.print(result.format_text())

    @app.command("holistic")
    def holistic(
        plans_dir: Annotated[
            Path,
            typer.Argument(help="Directory of EXPLAIN JSON plans (or single file)"),
        ],
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Holistic tuning -- coordinate index, knob, and query hint optimization."""
        from querysense.holistic_tuner import HolisticTuner

        if plans_dir.is_dir():
            plan_files = sorted(plans_dir.glob("*.json"))
        else:
            plan_files = [plans_dir]

        plans = _load_plans(plan_files)
        if not plans:
            console.print("[red]No valid EXPLAIN JSON plans found.[/red]")
            raise typer.Exit(1)

        tuner = HolisticTuner()
        result = tuner.tune(plans)

        if output_json:
            console.print(result.to_json())
        else:
            console.print(result.format_text())

    @app.command("geqo")
    def geqo(
        plan_file: Annotated[
            Path,
            typer.Argument(help="EXPLAIN JSON plan file"),
        ],
        threshold: Annotated[
            int,
            typer.Option("--threshold", help="GEQO activation threshold (default: 12)"),
        ] = 12,
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Analyze genetic optimizer behavior for complex joins."""
        from querysense.geqo_analyzer import GEQOAnalyzer

        if not plan_file.exists():
            console.print(f"[red]File not found: {plan_file}[/red]")
            raise typer.Exit(1)

        plan = json.loads(plan_file.read_text(encoding="utf-8"))
        analyzer = GEQOAnalyzer(geqo_threshold=threshold)
        result = analyzer.analyze(plan)

        if output_json:
            console.print(result.to_json())
        else:
            console.print(result.format_text())

    @app.command("profile-nodes")
    def profile_nodes(
        plan_file: Annotated[
            Path,
            typer.Argument(help="EXPLAIN ANALYZE JSON plan file"),
        ],
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Deep per-node execution profiling -- find the exact bottleneck."""
        from querysense.node_profiler import NodeProfiler

        if not plan_file.exists():
            console.print(f"[red]File not found: {plan_file}[/red]")
            raise typer.Exit(1)

        plan = json.loads(plan_file.read_text(encoding="utf-8"))
        profiler = NodeProfiler()
        result = profiler.profile(plan)

        if output_json:
            console.print(result.to_json())
        else:
            console.print(result.format_text())

    @app.command("calibrate")
    def calibrate(
        plans_dir: Annotated[
            Path,
            typer.Argument(help="Directory of EXPLAIN ANALYZE JSON plans"),
        ],
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Calibrate PostgreSQL cost model -- compare estimated vs actual costs."""
        from querysense.cost_calibrator import CostCalibrator

        if plans_dir.is_dir():
            plan_files = sorted(plans_dir.glob("*.json"))
        else:
            plan_files = [plans_dir]

        plans = _load_plans(plan_files)
        if not plans:
            console.print("[red]No valid EXPLAIN ANALYZE JSON plans found.[/red]")
            raise typer.Exit(1)

        calibrator = CostCalibrator()
        result = calibrator.calibrate(plans)

        if output_json:
            console.print(result.to_json())
        else:
            console.print(result.format_text())

    @app.command("stability")
    def stability(
        plans_dir: Annotated[
            Path,
            typer.Argument(help="Directory of EXPLAIN JSON plans for the SAME query"),
        ],
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Plan stability analysis -- detect parameter sniffing and plan flips."""
        from querysense.cost_calibrator import PlanStabilityAnalyzer

        if plans_dir.is_dir():
            plan_files = sorted(plans_dir.glob("*.json"))
        else:
            plan_files = [plans_dir]

        plans = _load_plans(plan_files)
        if len(plans) < 2:
            console.print("[yellow]Need at least 2 plans to analyze stability.[/yellow]")
            raise typer.Exit(1)

        analyzer = PlanStabilityAnalyzer()
        result = analyzer.analyze(plans)

        if output_json:
            console.print(result.to_json())
        else:
            console.print(result.format_text())

        if not result.is_stable:
            raise typer.Exit(1)

    @app.command("translate")
    def translate(
        sql: Annotated[
            str,
            typer.Argument(help="SQL recommendation to translate"),
        ] = "",
        file: Annotated[
            str,
            typer.Option("--file", "-f", help="File with SQL recommendations (one per line)"),
        ] = "",
        target: Annotated[
            str,
            typer.Option("--target", "-t", help="Target database: mysql, sqlserver, oracle"),
        ] = "mysql",
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Translate PostgreSQL optimizations to other databases."""
        from querysense.semantic_translator import SemanticTranslator

        translator = SemanticTranslator()

        if file:
            p = Path(file)
            if not p.exists():
                console.print(f"[red]File not found: {file}[/red]")
                raise typer.Exit(1)
            sqls = [line.strip() for line in p.read_text(encoding="utf-8").split("\n") if line.strip()]
            result = translator.translate_batch(sqls, target=target)

            if output_json:
                console.print(result.to_json())
            else:
                console.print(result.format_text())
        elif sql:
            result = translator.translate(sql, target=target)
            if output_json:
                console.print(json.dumps(result.to_dict(), indent=2))
            else:
                console.print(f"\n  PG:     {result.original_sql}")
                console.print(f"  {target.upper()}: {result.translated_sql}")
                if result.notes:
                    for n in result.notes:
                        console.print(f"  Note: {n}")
                console.print(f"  Confidence: {result.confidence:.0%}")
        else:
            console.print("[red]Provide SQL as argument or use --file[/red]")
            raise typer.Exit(1)
