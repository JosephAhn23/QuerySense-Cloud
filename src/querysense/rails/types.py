"""
Custom PostgreSQL Type Detector — find columns that should be enums, composites, or domains.

Connects to a live PostgreSQL database and analyzes column data to detect:
1. Enum candidates: columns with few distinct string values
2. Composite type candidates: groups of related columns (address_*, shipping_*)
3. Domain candidates: columns with check constraints that could be domains

Generates CREATE TYPE SQL + Rails migrations + model integration code.

Based on pganalyze "Advanced Database Programming with Rails" (p.7-8).

Usage:
    from querysense.rails.types import TypeDetector

    detector = TypeDetector()
    report = await detector.detect(dsn, schema="public")
    for enum in report.enums:
        print(enum.create_type_sql)
"""

from __future__ import annotations

import re
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnumCandidate:
    """A column that should be a PostgreSQL enum type."""

    table: str
    column: str
    current_type: str
    distinct_values: list[str] = field(default_factory=list)
    row_count: int = 0
    null_count: int = 0
    type_name: str = ""

    def __post_init__(self) -> None:
        if not self.type_name:
            self.type_name = f"{self.table}_{self.column}"

    @property
    def create_type_sql(self) -> str:
        vals = ", ".join(f"'{v}'" for v in self.distinct_values)
        return f"CREATE TYPE {self.type_name} AS ENUM ({vals});"

    @property
    def alter_column_sql(self) -> str:
        return (
            f"ALTER TABLE {self.table} "
            f"ALTER COLUMN {self.column} TYPE {self.type_name} "
            f"USING {self.column}::{self.type_name};"
        )

    @property
    def migration_rb(self) -> str:
        return textwrap.dedent(f"""\
            class Add{self.type_name.title().replace('_', '')}Enum < ActiveRecord::Migration[7.1]
              def up
                execute <<~SQL
                  {self.create_type_sql}
                  {self.alter_column_sql}
                SQL
              end

              def down
                execute <<~SQL
                  ALTER TABLE {self.table} ALTER COLUMN {self.column} TYPE varchar USING {self.column}::varchar;
                  DROP TYPE IF EXISTS {self.type_name};
                SQL
              end
            end
        """)

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "column": self.column,
            "current_type": self.current_type,
            "distinct_values": self.distinct_values,
            "type_name": self.type_name,
            "create_type_sql": self.create_type_sql,
            "alter_column_sql": self.alter_column_sql,
        }


@dataclass
class CompositeCandidate:
    """A group of columns that could be a composite type."""

    table: str
    columns: list[str] = field(default_factory=list)
    column_types: dict[str, str] = field(default_factory=dict)
    prefix: str = ""
    type_name: str = ""

    def __post_init__(self) -> None:
        if not self.type_name and self.prefix:
            self.type_name = self.prefix

    @property
    def create_type_sql(self) -> str:
        fields = []
        for col in self.columns:
            pg_type = self.column_types.get(col, "TEXT")
            short_name = col
            if self.prefix and col.startswith(self.prefix + "_"):
                short_name = col[len(self.prefix) + 1:]
            fields.append(f"    {short_name} {pg_type}")
        return f"CREATE TYPE {self.type_name} AS (\n{','.join(chr(10) + f for f in fields)}\n);"

    @property
    def migration_rb(self) -> str:
        return textwrap.dedent(f"""\
            class Create{self.type_name.title().replace('_', '')}Type < ActiveRecord::Migration[7.1]
              def up
                execute <<~SQL
                  {self.create_type_sql}
                SQL
                # Then replace columns with the composite type:
                # ALTER TABLE {self.table} ADD COLUMN {self.type_name} {self.type_name};
                # Migrate data, then drop old columns.
              end

              def down
                execute "DROP TYPE IF EXISTS {self.type_name} CASCADE;"
              end
            end
        """)

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "columns": self.columns,
            "column_types": self.column_types,
            "prefix": self.prefix,
            "type_name": self.type_name,
            "create_type_sql": self.create_type_sql,
        }


@dataclass
class TypeDetectionReport:
    """Full type detection report."""

    tables_analyzed: int = 0
    enums: list[EnumCandidate] = field(default_factory=list)
    composites: list[CompositeCandidate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tables_analyzed": self.tables_analyzed,
            "enums": [e.to_dict() for e in self.enums],
            "composites": [c.to_dict() for c in self.composites],
            "total_candidates": len(self.enums) + len(self.composites),
        }


_ENUM_MAX_DISTINCT = 20
_COMPOSITE_PREFIXES = [
    "shipping", "billing", "mailing", "home", "work", "primary",
    "secondary", "contact", "address", "phone", "emergency",
]


class TypeDetector:
    """
    Detect columns that should use custom PostgreSQL types.

    Connects to a live database and analyzes column statistics
    to find enum and composite type candidates.
    """

    def __init__(
        self,
        max_enum_values: int = _ENUM_MAX_DISTINCT,
        min_rows: int = 100,
    ) -> None:
        self.max_enum_values = max_enum_values
        self.min_rows = min_rows

    async def detect(
        self,
        dsn: str,
        schema: str = "public",
    ) -> TypeDetectionReport:
        """Run full type detection against a live database."""
        import asyncpg

        conn = await asyncpg.connect(dsn)
        try:
            report = TypeDetectionReport()

            tables = await conn.fetch(
                "SELECT tablename FROM pg_tables WHERE schemaname = $1",
                schema,
            )
            report.tables_analyzed = len(tables)

            for table_row in tables:
                table = table_row["tablename"]

                row_count = await conn.fetchval(
                    "SELECT reltuples::bigint FROM pg_class WHERE relname = $1",
                    table,
                )
                if (row_count or 0) < self.min_rows:
                    continue

                enums = await self._detect_enums(conn, schema, table)
                report.enums.extend(enums)

                composites = await self._detect_composites(conn, schema, table)
                report.composites.extend(composites)

            return report
        finally:
            await conn.close()

    async def detect_table(
        self,
        dsn: str,
        table: str,
        schema: str = "public",
    ) -> TypeDetectionReport:
        """Detect types for a single table."""
        import asyncpg

        conn = await asyncpg.connect(dsn)
        try:
            report = TypeDetectionReport(tables_analyzed=1)
            report.enums = await self._detect_enums(conn, schema, table)
            report.composites = await self._detect_composites(conn, schema, table)
            return report
        finally:
            await conn.close()

    async def _detect_enums(
        self,
        conn: Any,
        schema: str,
        table: str,
    ) -> list[EnumCandidate]:
        """Find columns with few distinct string values."""
        candidates: list[EnumCandidate] = []

        columns = await conn.fetch("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2
              AND data_type IN ('character varying', 'text', 'character')
        """, schema, table)

        for col_row in columns:
            col = col_row["column_name"]

            try:
                stats = await conn.fetchrow(f"""
                    SELECT
                        COUNT(DISTINCT "{col}") AS n_distinct,
                        COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE "{col}" IS NULL) AS null_count
                    FROM "{schema}"."{table}"
                """)

                n_distinct = stats["n_distinct"] or 0
                total = stats["total"] or 0

                if 2 <= n_distinct <= self.max_enum_values and total >= self.min_rows:
                    values = await conn.fetch(f"""
                        SELECT DISTINCT "{col}" AS val
                        FROM "{schema}"."{table}"
                        WHERE "{col}" IS NOT NULL
                        ORDER BY "{col}"
                    """)

                    candidates.append(EnumCandidate(
                        table=table,
                        column=col,
                        current_type=col_row["data_type"],
                        distinct_values=[str(r["val"]) for r in values],
                        row_count=total,
                        null_count=stats["null_count"] or 0,
                    ))
            except Exception:
                pass

        return candidates

    async def _detect_composites(
        self,
        conn: Any,
        schema: str,
        table: str,
    ) -> list[CompositeCandidate]:
        """Find groups of columns with common prefixes."""
        candidates: list[CompositeCandidate] = []

        columns = await conn.fetch("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2
            ORDER BY ordinal_position
        """, schema, table)

        col_names = [r["column_name"] for r in columns]
        col_types = {r["column_name"]: r["data_type"] for r in columns}

        prefix_groups: dict[str, list[str]] = defaultdict(list)

        for col in col_names:
            for prefix in _COMPOSITE_PREFIXES:
                if col.startswith(prefix + "_"):
                    prefix_groups[prefix].append(col)
                    break
            else:
                parts = col.split("_")
                if len(parts) >= 2:
                    prefix = parts[0]
                    matching = [c for c in col_names if c.startswith(prefix + "_")]
                    if len(matching) >= 3:
                        prefix_groups[prefix] = matching

        for prefix, cols in prefix_groups.items():
            if len(cols) >= 3:
                candidates.append(CompositeCandidate(
                    table=table,
                    columns=cols,
                    column_types={c: col_types.get(c, "TEXT") for c in cols},
                    prefix=prefix,
                    type_name=prefix,
                ))

        return candidates
