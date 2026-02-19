"""
Init command: zero-config onboarding.

querysense init — detects your setup and configures everything.

This is the anti-Harness: no enterprise setup wizard, no dedicated DevOps
team required. One command, done.

Detects:
- Git repository (generates .querysense-ci.yml + GitHub/GitLab workflow)
- Migration framework (Flyway, Alembic, Django, Prisma)
- SQL files (creates a plans/ directory for EXPLAIN exports)
- PostgreSQL connection (offers to run initial analysis)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()
error_console = Console(stderr=True)


def register(app: typer.Typer) -> None:
    """Register the init command on the given Typer app."""

    @app.command()
    def init(
        force: Annotated[
            bool,
            typer.Option("--force", help="Overwrite existing configuration"),
        ] = False,
        skip_ci: Annotated[
            bool,
            typer.Option("--skip-ci", help="Skip CI/CD workflow generation"),
        ] = False,
        skip_detect: Annotated[
            bool,
            typer.Option("--skip-detect", help="Skip auto-detection"),
        ] = False,
    ) -> None:
        """
        Set up QuerySense in your project — zero configuration required.

        Automatically detects your environment and generates:
        - .querysense-ci.yml (CI/CD configuration)
        - GitHub Actions / GitLab CI workflow
        - plans/ directory for EXPLAIN exports
        - .querysense/ directory for baselines and state

        \\b
        Quick start:
            $ cd my-project
            $ querysense init

        \\b
        That's it. Push and your PRs are gated.
        """
        console.print(Panel(
            "[bold]QuerySense Init[/bold] — setting up your project",
            border_style="brand",
        ))

        created_files: list[str] = []
        detected: list[str] = []

        # ── Detect environment ────────────────────────────────────
        if not skip_detect:
            console.print("\n[bold]Detecting environment...[/bold]")

            # Git
            is_git = Path(".git").exists()
            if is_git:
                detected.append("Git repository")
                console.print("  [green]✓[/green] Git repository detected")

            # GitHub Actions
            is_github = Path(".github").exists()
            if is_github:
                detected.append("GitHub repository")
                console.print("  [green]✓[/green] GitHub repository detected")

            # GitLab CI
            is_gitlab = Path(".gitlab-ci.yml").exists()
            if is_gitlab:
                detected.append("GitLab CI")
                console.print("  [green]✓[/green] GitLab CI detected")

            # Migration frameworks
            if Path("flyway.conf").exists() or any(Path(".").glob("**/V*__*.sql")):
                detected.append("Flyway migrations")
                console.print("  [green]✓[/green] Flyway migrations detected")
            if Path("alembic.ini").exists() or Path("alembic").is_dir():
                detected.append("Alembic migrations")
                console.print("  [green]✓[/green] Alembic migrations detected")
            if any(Path(".").glob("**/migrations/*.py")):
                detected.append("Django migrations")
                console.print("  [green]✓[/green] Django-style migrations detected")
            if Path("prisma/schema.prisma").exists():
                detected.append("Prisma schema")
                console.print("  [green]✓[/green] Prisma schema detected")

            # Existing SQL files
            sql_files = list(Path(".").glob("**/*.sql"))[:100]
            if sql_files:
                detected.append(f"{len(sql_files)} SQL file(s)")
                console.print(f"  [green]✓[/green] {len(sql_files)} SQL file(s) found")

            # Existing EXPLAIN files
            json_files = [f for f in Path(".").glob("plans/**/*.json") if "node_modules" not in str(f)]
            if json_files:
                detected.append(f"{len(json_files)} EXPLAIN plan(s)")
                console.print(f"  [green]✓[/green] {len(json_files)} EXPLAIN plan file(s) in plans/")

            if not detected:
                console.print("  [dim]No specific frameworks detected — using defaults[/dim]")

        # ── Create directory structure ────────────────────────────
        console.print("\n[bold]Creating project structure...[/bold]")

        # .querysense/ directory
        qs_dir = Path(".querysense")
        if not qs_dir.exists():
            qs_dir.mkdir(parents=True, exist_ok=True)
            console.print(f"  [green]✓[/green] Created {qs_dir}/")
            created_files.append(str(qs_dir))

        # plans/ directory
        plans_dir = Path("plans")
        if not plans_dir.exists():
            plans_dir.mkdir(parents=True, exist_ok=True)
            console.print(f"  [green]✓[/green] Created {plans_dir}/")
            created_files.append(str(plans_dir))

            # Add .gitkeep
            gitkeep = plans_dir / ".gitkeep"
            gitkeep.write_text("", encoding="utf-8")

        # ── Generate CI config ────────────────────────────────────
        ci_config_path = Path(".querysense-ci.yml")
        if ci_config_path.exists() and not force:
            console.print(f"  [dim]Skipping {ci_config_path} (exists, use --force)[/dim]")
        else:
            ci_config_path.write_text(_CI_CONFIG_TEMPLATE, encoding="utf-8")
            console.print(f"  [green]✓[/green] Created {ci_config_path}")
            created_files.append(str(ci_config_path))

        # ── Generate CI workflow ──────────────────────────────────
        if not skip_ci:
            # GitHub Actions
            if Path(".git").exists():
                gh_dir = Path(".github/workflows")
                gh_path = gh_dir / "querysense.yml"
                if gh_path.exists() and not force:
                    console.print(f"  [dim]Skipping {gh_path} (exists)[/dim]")
                else:
                    gh_dir.mkdir(parents=True, exist_ok=True)
                    gh_path.write_text(_GITHUB_WORKFLOW, encoding="utf-8")
                    console.print(f"  [green]✓[/green] Created {gh_path}")
                    created_files.append(str(gh_path))

            # GitLab CI
            if Path(".gitlab-ci.yml").exists():
                gl_path = Path(".gitlab-querysense.yml")
                if not gl_path.exists() or force:
                    gl_path.write_text(_GITLAB_CI, encoding="utf-8")
                    console.print(f"  [green]✓[/green] Created {gl_path}")
                    created_files.append(str(gl_path))

        # ── Generate .gitignore additions ─────────────────────────
        gitignore = Path(".gitignore")
        qs_ignore_lines = [
            "\n# QuerySense",
            ".querysense/watch_state.json",
            ".querysense/*.cache",
        ]
        if gitignore.exists():
            content = gitignore.read_text(encoding="utf-8")
            if "QuerySense" not in content:
                with open(gitignore, "a", encoding="utf-8") as f:
                    f.write("\n".join(qs_ignore_lines) + "\n")
                console.print(f"  [green]✓[/green] Updated .gitignore")
        else:
            gitignore.write_text("\n".join(qs_ignore_lines) + "\n", encoding="utf-8")
            console.print(f"  [green]✓[/green] Created .gitignore")

        # ── Summary ───────────────────────────────────────────────
        console.print()
        if created_files:
            console.print(Panel(
                f"[green bold]Setup complete![/green bold]\n\n"
                f"Created {len(created_files)} file(s).\n\n"
                "[bold]Next steps:[/bold]\n"
                "  1. Export an EXPLAIN plan:  [cyan]psql -c 'EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT ...' > plans/query.json[/cyan]\n"
                "  2. Analyze it:              [cyan]querysense analyze plans/query.json[/cyan]\n"
                "  3. Commit and push:         [cyan]git add . && git commit -m 'Add QuerySense' && git push[/cyan]\n"
                "  4. Your PRs are now gated automatically.\n\n"
                "[dim]Tip: Run 'querysense ci gate' locally to test before pushing[/dim]",
                border_style="green",
            ))
        else:
            console.print("[dim]Nothing to create — QuerySense is already set up.[/dim]")


# ── Templates ─────────────────────────────────────────────────────────


_CI_CONFIG_TEMPLATE = """\
# QuerySense CI/CD Configuration
# Docs: https://github.com/JosephAhn23/Query-Sense#ci-cd
#
# This file controls how QuerySense gates your pull requests.
# Generated by `querysense init`.

plans:
  - "plans/**/*.json"

# Severity threshold to fail CI: critical, warning, info, none
fail_on: warning

# Require EXPLAIN (ANALYZE) data (not just EXPLAIN)
require_analyze: false

# Rules to ignore (by rule_id)
ignore_rules: []

# GitHub-specific settings
github:
  annotations: true
  step_summary: true

# Baseline file for regression detection
baseline: .querysense/baselines.json

# Policy file for custom enforcement (optional)
# policy: .querysense/policy.yml
"""


_GITHUB_WORKFLOW = """\
# QuerySense — SQL performance linting in CI
# Generated by `querysense init`
#
# Runs QuerySense on every PR to catch slow queries before production.

name: QuerySense

on:
  pull_request:
    paths:
      - "plans/**"
      - "migrations/**"
      - ".querysense-ci.yml"

concurrency:
  group: querysense-${{ github.head_ref }}
  cancel-in-progress: true

jobs:
  lint-queries:
    name: Lint SQL Performance
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install QuerySense
        run: pip install querysense

      - name: Run QuerySense gate
        id: querysense
        run: querysense ci gate
"""


_GITLAB_CI = """\
# QuerySense — SQL performance linting in GitLab CI
# Generated by `querysense init`
# Include this in your .gitlab-ci.yml: include: .gitlab-querysense.yml

querysense:
  stage: test
  image: python:3.12-slim
  rules:
    - changes:
        - plans/**
        - migrations/**
        - .querysense-ci.yml
  script:
    - pip install querysense
    - querysense ci gate
  allow_failure: false
"""
