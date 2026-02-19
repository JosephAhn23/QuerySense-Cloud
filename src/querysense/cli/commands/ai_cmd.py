"""
AI/LLM CLI commands — natural language query explanations.

Commands:
    querysense ai explain <sql> [--plan plan.json]
    querysense ai explain-file <plan.json>
    querysense ai models
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()


def register(parent: typer.Typer) -> None:
    """Register AI/LLM commands."""

    @parent.command(name="explain")
    def ai_explain(
        sql: Annotated[str, typer.Argument(help="SQL query to explain")],
        plan_file: Annotated[Path | None, typer.Option(
            "--plan", help="EXPLAIN plan JSON file"
        )] = None,
        llm: Annotated[str, typer.Option(
            "--llm", help="LLM provider: ollama, openai, claude (empty = deterministic only)"
        )] = "",
        model: Annotated[str, typer.Option(
            "--model", help="Model name (e.g., llama3, gpt-4o-mini)"
        )] = "",
        api_key: Annotated[str, typer.Option(
            "--api-key", help="API key for cloud LLMs (or set OPENAI_API_KEY env var)"
        )] = "",
    ) -> None:
        """
        Explain why a query is slow in plain English.

        Works offline by default (no LLM needed). Add --llm for AI-enhanced explanations.

        Examples:
            querysense ai explain "SELECT * FROM orders WHERE status = 'pending'"
            querysense ai explain "SELECT * FROM orders" --plan explain.json
            querysense ai explain "SELECT * FROM orders" --llm ollama --model llama3
            querysense ai explain "SELECT * FROM orders" --llm openai --api-key sk-...
        """
        import os
        from querysense.explainer.nlq import NLQueryExplainer

        plan_data = None
        if plan_file and plan_file.exists():
            plan_data = json.loads(plan_file.read_text())

        # Resolve API key from env if not provided
        if not api_key and llm == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key and llm == "claude":
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        explainer = NLQueryExplainer(
            llm=llm, model=model, api_key=api_key,
        )

        if llm:
            result = asyncio.run(explainer.explain_query_async(sql, plan_data))
        else:
            result = explainer.explain_query(sql, plan_data)

        # Display
        console.print(Panel(
            result.to_plain_english(),
            title=f"Query Explanation ({result.query_type}, "
                  f"complexity {result.complexity_score}/10)"
                  + (f" — enhanced by {llm}" if llm else " — deterministic"),
        ))

        if result.index_suggestions:
            console.print("\n[bold cyan]Suggested indexes:[/]")
            for s in result.index_suggestions:
                console.print(f"  [green]{s}[/]")

    @parent.command(name="explain-file")
    def ai_explain_file(
        file: Annotated[Path, typer.Argument(help="EXPLAIN plan JSON file")],
        llm: Annotated[str, typer.Option("--llm", help="LLM provider")] = "",
        model: Annotated[str, typer.Option("--model", help="Model name")] = "",
        api_key: Annotated[str, typer.Option("--api-key", help="API key")] = "",
    ) -> None:
        """Explain a query plan file in plain English."""
        import os
        from querysense.explainer.nlq import NLQueryExplainer

        plan_data = json.loads(file.read_text())

        # Try to extract SQL from plan
        sql = ""
        if isinstance(plan_data, list) and plan_data:
            sql = plan_data[0].get("Query Text", plan_data[0].get("query", ""))
        elif isinstance(plan_data, dict):
            sql = plan_data.get("Query Text", plan_data.get("query", ""))

        if not api_key and llm == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key and llm == "claude":
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        explainer = NLQueryExplainer(llm=llm, model=model, api_key=api_key)

        if llm:
            result = asyncio.run(explainer.explain_query_async(sql, plan_data))
        else:
            result = explainer.explain_query(sql, plan_data)

        console.print(Panel(
            result.to_plain_english(),
            title=f"Plan Explanation ({result.query_type})"
                  + (f" — {llm}" if llm else ""),
        ))

    @parent.command(name="models")
    def ai_models(
        ollama_url: Annotated[str, typer.Option(
            "--ollama-url", help="Ollama server URL"
        )] = "http://localhost:11434",
    ) -> None:
        """List available local Ollama models."""
        from querysense.explainer.ollama_explainer import check_ollama

        result = asyncio.run(check_ollama(ollama_url))

        if not result["available"]:
            console.print(
                f"[yellow]Ollama not available at {ollama_url}[/]\n"
                f"Error: {result.get('error', 'unknown')}\n\n"
                f"Install Ollama: https://ollama.ai\n"
                f"Then: ollama serve && ollama pull llama3"
            )
            return

        models = result.get("models", [])
        if not models:
            console.print(
                "[yellow]Ollama is running but no models installed.[/]\n"
                "Pull a model: ollama pull llama3"
            )
            return

        table = Table(title="Available Ollama Models (Local, Private)")
        table.add_column("Model", style="cyan")
        table.add_column("Use With", style="green")

        for m in models:
            table.add_row(m, f'querysense ai explain "..." --llm ollama --model {m}')

        console.print(table)
        console.print(
            "\n[dim]All processing happens locally — your queries never leave your machine.[/]"
        )
