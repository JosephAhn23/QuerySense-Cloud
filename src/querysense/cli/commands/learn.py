"""
CLI command: querysense learn

Generate personalized learning paths from analysis findings.

Usage:
    querysense learn plan.json --level beginner
    querysense learn plan.json --level intermediate --json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register(app: typer.Typer) -> None:
    @app.command("learn")
    def learn(
        plan_file: Annotated[
            Path,
            typer.Argument(help="EXPLAIN JSON plan file to analyze"),
        ],
        level: Annotated[
            str,
            typer.Option("--level", "-l", help="User level: beginner, intermediate, advanced"),
        ] = "beginner",
        output_json: Annotated[
            bool,
            typer.Option("--json", help="Output as JSON"),
        ] = False,
    ) -> None:
        """Generate a personalized learning path from analysis findings."""
        from querysense import AnalysisService
        from querysense.learning import generate_learning_path

        if not plan_file.exists():
            console.print(f"[red]File not found: {plan_file}[/red]")
            raise typer.Exit(1)

        plan_data = json.loads(plan_file.read_text(encoding="utf-8"))

        # Run analysis to get findings
        service = AnalysisService()
        result = service.analyze(plan_data)

        # Generate learning path
        path = generate_learning_path(result.findings, user_level=level)

        if output_json:
            console.print(json.dumps(path.to_dict(), indent=2))
            return

        # Rich output
        console.print(Panel(
            f"[bold cyan]QUERYSENSE LEARNING PATH[/bold cyan]\n"
            f"Level: {path.user_level} | Lessons: {path.total_lessons} | "
            f"Est. time: {path.estimated_time_minutes} min",
            border_style="cyan",
        ))

        for i, lesson in enumerate(path.lessons, 1):
            table = Table(title=f"Lesson {i}: {lesson.title}", show_header=False)
            table.add_column("Field", style="bold")
            table.add_column("Value")

            table.add_row("Category", lesson.category)
            table.add_row("Level", lesson.level)
            if lesson.concepts:
                table.add_row("Concepts", ", ".join(lesson.concepts))
            if lesson.explanation:
                table.add_row("Explanation", lesson.explanation[:200])
            if lesson.practice_sql:
                table.add_row("Practice SQL", lesson.practice_sql[:200])
            if lesson.quizzes:
                table.add_row("Quiz", lesson.quizzes[0].question)

            console.print(table)
            console.print()
