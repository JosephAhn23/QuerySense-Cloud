"""Compliance enforcement commands: check, init, detect-pii."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

console = Console()
error_console = Console(stderr=True)


def register(compliance_app: typer.Typer) -> None:
    """Register compliance commands on the given Typer sub-app."""

    @compliance_app.command("check")
    def compliance_check(
        sql_file: Annotated[
            Optional[str],
            typer.Argument(help="Path to SQL file to check"),
        ] = None,
        sql: Annotated[
            Optional[str],
            typer.Option("--sql", help="Inline SQL to check"),
        ] = None,
        tables_config: Annotated[
            str,
            typer.Option("--tables", help="Path to table classifications file"),
        ] = ".querysense/tables.yml",
        regulations: Annotated[
            Optional[str],
            typer.Option(
                "--regulations",
                help="Comma-separated list of regulations (PCI-DSS,HIPAA,SOC2,GDPR,SOX)",
            ),
        ] = None,
        output_format: Annotated[
            str,
            typer.Option("--format", "-f", help="Output format: text, json, sarif"),
        ] = "text",
    ) -> None:
        """
        Check SQL queries against compliance rules.

        Examples:

            $ querysense compliance check query.sql --tables .querysense/tables.yml
            $ querysense compliance check --sql "SELECT * FROM payments"
        """
        from querysense.compliance import ComplianceEngine, load_table_classifications

        sql_text = ""
        if sql_file:
            sql_text = Path(sql_file).read_text(encoding="utf-8")
        elif sql:
            sql_text = sql
        else:
            error_console.print("[red]Provide a SQL file or --sql option[/red]")
            raise typer.Exit(code=1)

        tables = load_table_classifications(tables_config)
        if not tables:
            error_console.print(
                f"[yellow]No table classifications found at {tables_config}[/yellow]"
            )
            error_console.print(
                "[dim]Run 'querysense compliance init' to create one[/dim]"
            )

        reg_list = None
        if regulations:
            reg_list = [r.strip() for r in regulations.split(",")]

        engine = ComplianceEngine(tables=tables, regulations=reg_list)
        violations = engine.check_query(sql_text)

        if output_format == "sarif":
            sarif = engine.generate_sarif_report(violations)
            console.print_json(json.dumps(sarif, indent=2))
        elif output_format == "json":
            output_data = [v.to_dict() for v in violations]
            console.print_json(json.dumps(output_data, indent=2))
        else:
            if not violations:
                console.print("[green]No compliance violations found.[/green]")
                return

            console.print(f"[bold]{len(violations)} compliance violation(s):[/bold]\n")
            for v in violations:
                sev_style = {
                    "critical": "red bold",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                }
                style = sev_style.get(v.severity, "white")
                console.print(
                    f"[{style}][{v.severity.upper()}][/{style}] "
                    f"[{v.regulation}] {v.message}"
                )
                if v.rule_reference:
                    console.print(f"  [dim]Reference: {v.rule_reference}[/dim]")
                if v.remediation:
                    console.print(f"  [green]Fix: {v.remediation}[/green]")
                console.print()

        if violations:
            raise typer.Exit(code=1)

    @compliance_app.command("init")
    def compliance_init(
        output_path: Annotated[
            str,
            typer.Option("--output", "-o", help="Path for table classifications file"),
        ] = ".querysense/tables.yml",
    ) -> None:
        """
        Initialize a table classifications file.

        Examples:

            $ querysense compliance init
        """
        from querysense.compliance import generate_default_tables_config

        output = Path(output_path)
        if output.exists():
            error_console.print(
                f"[yellow]File already exists: {output_path}[/yellow]"
            )
            raise typer.Exit(code=0)

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(generate_default_tables_config(), encoding="utf-8")
        console.print(f"[green]Created {output_path}[/green]")
        console.print(
            "[dim]Edit the file to classify your tables and enable compliance rules.[/dim]"
        )

    @compliance_app.command("detect-pii")
    def compliance_detect_pii(
        dsn: Annotated[
            str,
            typer.Option("--dsn", help="PostgreSQL connection string", envvar="QUERYSENSE_DSN"),
        ] = "",
        schema_name: Annotated[
            str,
            typer.Option("--schema", help="Schema to scan"),
        ] = "public",
    ) -> None:
        """
        Auto-detect potential PII columns by name pattern matching.

        Examples:

            $ querysense compliance detect-pii --dsn postgresql://localhost/mydb
        """
        from querysense.compliance import detect_pii_columns

        if not dsn:
            error_console.print("[red]--dsn is required[/red]")
            raise typer.Exit(code=1)

        try:
            import psycopg

            with psycopg.connect(dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT table_name, column_name
                        FROM information_schema.columns
                        WHERE table_schema = %s
                        ORDER BY table_name, ordinal_position
                        """,
                        [schema_name],
                    )
                    rows = cur.fetchall()

            table_columns: dict[str, list[str]] = {}
            for table_name, col_name in rows:
                table_columns.setdefault(table_name, []).append(col_name)

            console.print(
                f"[bold]PII Detection Scan — schema '{schema_name}'[/bold]\n"
            )

            total_detected = 0
            for table_name, columns in sorted(table_columns.items()):
                detections = detect_pii_columns(columns)
                if detections:
                    console.print(f"[cyan]{table_name}[/cyan]:")
                    for col, pii_type in detections.items():
                        console.print(
                            f"  [yellow]{col}[/yellow] -> {pii_type.value}"
                        )
                        total_detected += 1
                    console.print()

            if total_detected == 0:
                console.print("[green]No potential PII columns detected.[/green]")
            else:
                console.print(
                    f"[dim]{total_detected} potential PII column(s) detected[/dim]"
                )
                console.print(
                    "[dim]Review detections and add to .querysense/tables.yml[/dim]"
                )

        except ImportError:
            error_console.print(
                "[red]psycopg not installed. Install with: "
                "pip install 'querysense[db]'[/red]"
            )
            raise typer.Exit(code=1)
