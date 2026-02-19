"""
Migration auto-discovery for CI/CD query analysis.

Automatically discovers SQL migration files across popular frameworks:
- Tier 1 (zero deps): Flyway, Prisma, raw SQL, dbmate, goose
- Tier 2 (framework CLI): Django sqlmigrate, Alembic, Rails
- Tier 3 (AST parsing): Ruby/Python/JS migration DSLs

Usage:
    from querysense.migrations import discover_migrations, MigrationFile

    migrations = discover_migrations(".")
    for m in migrations:
        print(f"{m.path} ({m.framework}): {len(m.sql_statements)} statements")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Models ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MigrationFile:
    """A discovered migration file with its SQL content."""

    path: str
    framework: str  # "flyway", "prisma", "django", "alembic", "rails", "raw_sql", "dbmate", "goose"
    version: str = ""
    description: str = ""
    sql_content: str = ""
    sql_statements: tuple[str, ...] = ()

    @property
    def has_ddl(self) -> bool:
        """Check if migration contains DDL statements."""
        ddl_patterns = [
            r"\bCREATE\s+(TABLE|INDEX|VIEW|FUNCTION|TRIGGER|SEQUENCE)",
            r"\bALTER\s+(TABLE|INDEX|COLUMN)",
            r"\bDROP\s+(TABLE|INDEX|VIEW|FUNCTION|TRIGGER|SEQUENCE)",
            r"\bADD\s+CONSTRAINT",
            r"\bADD\s+COLUMN",
            r"\bDROP\s+COLUMN",
        ]
        text = self.sql_content.upper()
        return any(re.search(pat, text, re.IGNORECASE) for pat in ddl_patterns)

    @property
    def has_dml(self) -> bool:
        """Check if migration contains DML statements."""
        dml_patterns = [
            r"\bINSERT\s+INTO",
            r"\bUPDATE\s+\w+\s+SET",
            r"\bDELETE\s+FROM",
            r"\bSELECT\b",
        ]
        text = self.sql_content.upper()
        return any(re.search(pat, text, re.IGNORECASE) for pat in dml_patterns)


@dataclass
class DiscoveryConfig:
    """Configuration for migration discovery."""

    root_dir: str = "."
    auto_detect: bool = True
    custom_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    include_frameworks: list[str] = field(default_factory=list)  # empty = all


# ── Framework Patterns ─────────────────────────────────────────────────


FRAMEWORK_PATTERNS: dict[str, list[str]] = {
    "flyway": [
        "sql/V*.sql",
        "db/migration/V*.sql",
        "src/main/resources/db/migration/V*.sql",
        "migrations/V*.sql",
    ],
    "prisma": [
        "prisma/migrations/*/migration.sql",
    ],
    "dbmate": [
        "db/migrations/*.sql",
    ],
    "goose": [
        "migrations/*.sql",
        "db/migrations/*.sql",
    ],
    "raw_sql": [
        "migrations/*.sql",
        "sql/migrations/*.sql",
        "db/migrate/*.sql",
        "database/migrations/*.sql",
        "schema/*.sql",
    ],
    "alembic": [
        "alembic/versions/*.py",
        "migrations/versions/*.py",
    ],
    "django": [
        "*/migrations/*.py",
    ],
    "rails": [
        "db/migrate/*.rb",
    ],
}


# ── SQL Extraction ─────────────────────────────────────────────────────


def _extract_sql_from_file(path: Path) -> str:
    """Read SQL content from a file."""
    try:
        content = path.read_text(encoding="utf-8")
        return content
    except (OSError, UnicodeDecodeError) as e:
        logger.warning("Cannot read %s: %s", path, e)
        return ""


def _extract_sql_from_alembic(path: Path) -> str:
    """Extract SQL statements from Alembic migration Python files."""
    try:
        content = path.read_text(encoding="utf-8")

        # Look for op.execute("SQL") patterns
        sql_parts: list[str] = []
        execute_pattern = re.compile(
            r'op\.execute\(\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|"(.*?)"|\'(.*?)\')\s*\)',
            re.DOTALL,
        )
        for match in execute_pattern.finditer(content):
            sql = match.group(1) or match.group(2) or match.group(3) or match.group(4)
            if sql:
                sql_parts.append(sql.strip())

        # Look for op.create_table, op.add_column, etc.
        create_table_pattern = re.compile(
            r'op\.create_table\(\s*["\'](\w+)["\']', re.DOTALL
        )
        for match in create_table_pattern.finditer(content):
            sql_parts.append(f"-- CREATE TABLE {match.group(1)} (extracted from Alembic)")

        add_column_pattern = re.compile(
            r'op\.add_column\(\s*["\'](\w+)["\']', re.DOTALL
        )
        for match in add_column_pattern.finditer(content):
            sql_parts.append(f"-- ALTER TABLE {match.group(1)} ADD COLUMN (extracted from Alembic)")

        create_index_pattern = re.compile(
            r'op\.create_index\(\s*["\'](\w+)["\']', re.DOTALL
        )
        for match in create_index_pattern.finditer(content):
            sql_parts.append(f"-- CREATE INDEX {match.group(1)} (extracted from Alembic)")

        return "\n".join(sql_parts)
    except Exception as e:
        logger.warning("Cannot parse Alembic migration %s: %s", path, e)
        return ""


def _extract_sql_from_django(path: Path) -> str:
    """Extract SQL hints from Django migration Python files."""
    try:
        content = path.read_text(encoding="utf-8")

        sql_parts: list[str] = []

        # Look for migrations.RunSQL
        runsql_pattern = re.compile(
            r'migrations\.RunSQL\(\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|"(.*?)"|\'(.*?)\')',
            re.DOTALL,
        )
        for match in runsql_pattern.finditer(content):
            sql = match.group(1) or match.group(2) or match.group(3) or match.group(4)
            if sql:
                sql_parts.append(sql.strip())

        # Look for model changes
        create_model_pattern = re.compile(
            r'migrations\.CreateModel\(\s*name=["\'](\w+)["\']', re.DOTALL
        )
        for match in create_model_pattern.finditer(content):
            sql_parts.append(f"-- CREATE TABLE {match.group(1).lower()} (from Django migration)")

        add_field_pattern = re.compile(
            r'migrations\.AddField\(\s*model_name=["\'](\w+)["\']', re.DOTALL
        )
        for match in add_field_pattern.finditer(content):
            sql_parts.append(
                f"-- ALTER TABLE {match.group(1).lower()} ADD COLUMN (from Django migration)"
            )

        return "\n".join(sql_parts)
    except Exception as e:
        logger.warning("Cannot parse Django migration %s: %s", path, e)
        return ""


def _split_sql_statements(sql: str) -> tuple[str, ...]:
    """Split SQL content into individual statements."""
    if not sql.strip():
        return ()

    # Simple statement splitting on semicolons
    # (respects strings and comments at a basic level)
    statements: list[str] = []
    current: list[str] = []

    for line in sql.split("\n"):
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("--"):
            continue

        current.append(line)

        if stripped.endswith(";"):
            stmt = "\n".join(current).strip().rstrip(";").strip()
            if stmt:
                statements.append(stmt)
            current = []

    # Any remaining content
    if current:
        stmt = "\n".join(current).strip().rstrip(";").strip()
        if stmt:
            statements.append(stmt)

    return tuple(statements)


# ── Discovery Engine ───────────────────────────────────────────────────


def discover_migrations(
    root_dir: str = ".",
    config: DiscoveryConfig | None = None,
) -> list[MigrationFile]:
    """
    Discover migration files in a project directory.

    Args:
        root_dir: Root directory to scan
        config: Optional discovery configuration

    Returns:
        List of discovered MigrationFile objects, sorted by path
    """
    if config is None:
        config = DiscoveryConfig(root_dir=root_dir)

    root = Path(config.root_dir if config.root_dir != "." else root_dir)
    if not root.exists():
        logger.warning("Root directory not found: %s", root)
        return []

    migrations: list[MigrationFile] = []
    seen_paths: set[str] = set()

    # Apply framework patterns
    frameworks = config.include_frameworks or list(FRAMEWORK_PATTERNS.keys())

    for framework in frameworks:
        patterns = FRAMEWORK_PATTERNS.get(framework, [])
        for pattern in patterns:
            for path in root.glob(pattern):
                if not path.is_file():
                    continue

                rel_path = str(path.relative_to(root))
                if rel_path in seen_paths:
                    continue

                # Check exclude patterns
                if any(
                    re.search(excl, rel_path) for excl in config.exclude_patterns
                ):
                    continue

                seen_paths.add(rel_path)

                # Extract SQL based on framework
                if framework == "alembic" and path.suffix == ".py":
                    sql = _extract_sql_from_alembic(path)
                elif framework == "django" and path.suffix == ".py":
                    sql = _extract_sql_from_django(path)
                elif path.suffix == ".sql":
                    sql = _extract_sql_from_file(path)
                else:
                    continue  # Skip non-SQL, non-Python files for now

                if not sql.strip():
                    continue

                statements = _split_sql_statements(sql)

                # Extract version from filename
                version = _extract_version(path.name, framework)

                migrations.append(
                    MigrationFile(
                        path=rel_path,
                        framework=framework,
                        version=version,
                        description=_extract_description(path.name, framework),
                        sql_content=sql,
                        sql_statements=statements,
                    )
                )

    # Apply custom patterns
    for pattern in config.custom_patterns:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            rel_path = str(path.relative_to(root))
            if rel_path in seen_paths:
                continue
            seen_paths.add(rel_path)

            sql = _extract_sql_from_file(path)
            if sql.strip():
                statements = _split_sql_statements(sql)
                migrations.append(
                    MigrationFile(
                        path=rel_path,
                        framework="custom",
                        sql_content=sql,
                        sql_statements=statements,
                    )
                )

    migrations.sort(key=lambda m: m.path)
    logger.info("Discovered %d migration(s) in %s", len(migrations), root)
    return migrations


def _extract_version(filename: str, framework: str) -> str:
    """Extract version number from migration filename."""
    if framework == "flyway":
        # V1__description.sql -> 1
        match = re.match(r"V(\d+(?:\.\d+)*)", filename)
        return match.group(1) if match else ""

    if framework == "prisma":
        # 20210101000000_init/migration.sql -> 20210101000000
        match = re.match(r"(\d{14})", filename)
        return match.group(1) if match else ""

    if framework == "rails":
        # 20210101000000_create_users.rb -> 20210101000000
        match = re.match(r"(\d{14})", filename)
        return match.group(1) if match else ""

    # Generic numeric prefix
    match = re.match(r"(\d+)", filename)
    return match.group(1) if match else ""


def _extract_description(filename: str, framework: str) -> str:
    """Extract description from migration filename."""
    if framework == "flyway":
        # V1__description.sql -> description
        match = re.match(r"V\d+(?:\.\d+)*__(.+)\.sql", filename)
        return match.group(1).replace("_", " ") if match else filename

    # Generic: strip extension and leading numbers
    name = Path(filename).stem
    name = re.sub(r"^\d+[_-]?", "", name)
    return name.replace("_", " ") or filename


# ── PR Changed Files Detection ─────────────────────────────────────────


def detect_changed_migrations(
    changed_files: list[str],
    root_dir: str = ".",
) -> list[MigrationFile]:
    """
    From a list of changed files (e.g., from a PR), detect which are migrations.

    Args:
        changed_files: List of file paths relative to repo root
        root_dir: Repository root

    Returns:
        MigrationFile objects for files that match migration patterns
    """
    root = Path(root_dir)
    migrations: list[MigrationFile] = []

    for file_path in changed_files:
        path = root / file_path
        if not path.exists() or not path.is_file():
            continue

        framework = _detect_framework_for_file(file_path)
        if framework is None:
            continue

        if path.suffix == ".py" and framework == "alembic":
            sql = _extract_sql_from_alembic(path)
        elif path.suffix == ".py" and framework == "django":
            sql = _extract_sql_from_django(path)
        elif path.suffix == ".sql":
            sql = _extract_sql_from_file(path)
        else:
            continue

        if not sql.strip():
            continue

        statements = _split_sql_statements(sql)
        migrations.append(
            MigrationFile(
                path=file_path,
                framework=framework,
                version=_extract_version(path.name, framework),
                description=_extract_description(path.name, framework),
                sql_content=sql,
                sql_statements=statements,
            )
        )

    return migrations


def _detect_framework_for_file(file_path: str) -> str | None:
    """Detect which framework a file belongs to based on its path."""
    path_lower = file_path.lower().replace("\\", "/")

    if "prisma/migrations/" in path_lower and path_lower.endswith(".sql"):
        return "prisma"
    if re.match(r".*V\d+.*\.sql$", file_path, re.IGNORECASE):
        return "flyway"
    if "alembic/versions/" in path_lower and path_lower.endswith(".py"):
        return "alembic"
    if "/migrations/" in path_lower and path_lower.endswith(".py"):
        return "django"
    if "db/migrate/" in path_lower and path_lower.endswith(".rb"):
        return "rails"
    if path_lower.endswith(".sql") and "migrat" in path_lower:
        return "raw_sql"

    return None
