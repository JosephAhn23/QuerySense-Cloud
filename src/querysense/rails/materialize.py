"""
Materialized View Generator — SQL + Rails model + migration + refresh schedule.

Generates everything needed to add a materialized view to a Rails app:
1. CREATE MATERIALIZED VIEW SQL
2. Rails model file (read-only ApplicationRecord subclass)
3. Rails migration file
4. Refresh rake task or Sidekiq worker
5. Scenic integration (if using the scenic gem)

Based on pganalyze "Advanced Database Programming with Rails" (p.5-6).

Usage:
    from querysense.rails.materialize import MaterializedViewGenerator

    gen = MaterializedViewGenerator()
    spec = gen.from_sql("customer_order_summaries", sql)
    print(spec.migration_rb)
    print(spec.model_rb)
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class MaterializedViewSpec:
    """Full specification for a materialized view in a Rails app."""

    name: str
    sql: str
    columns: list[str] = field(default_factory=list)
    source_tables: list[str] = field(default_factory=list)
    has_aggregation: bool = False
    unique_index_columns: list[str] = field(default_factory=list)
    refresh_interval: str = "1 hour"

    @property
    def class_name(self) -> str:
        """Rails model class name (CamelCase singular)."""
        parts = self.name.split("_")
        return "".join(p.capitalize() for p in parts)

    @property
    def create_sql(self) -> str:
        lines = [f"CREATE MATERIALIZED VIEW {self.name} AS"]
        lines.append(self.sql.rstrip(";"))
        lines.append("WITH DATA;")
        if self.unique_index_columns:
            cols = ", ".join(self.unique_index_columns)
            lines.append("")
            lines.append(
                f"CREATE UNIQUE INDEX idx_{self.name}_unique "
                f"ON {self.name} ({cols});"
            )
        return "\n".join(lines)

    @property
    def drop_sql(self) -> str:
        return f"DROP MATERIALIZED VIEW IF EXISTS {self.name} CASCADE;"

    @property
    def refresh_sql(self) -> str:
        if self.unique_index_columns:
            return f"REFRESH MATERIALIZED VIEW CONCURRENTLY {self.name};"
        return f"REFRESH MATERIALIZED VIEW {self.name};"

    @property
    def migration_rb(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return textwrap.dedent(f"""\
            class Create{self.class_name} < ActiveRecord::Migration[7.1]
              def up
                execute <<~SQL
                  {self.create_sql}
                SQL
              end

              def down
                execute <<~SQL
                  {self.drop_sql}
                SQL
              end
            end
        """)

    @property
    def model_rb(self) -> str:
        return textwrap.dedent(f"""\
            # app/models/{self._snake_singular}.rb
            #
            # Materialized view — read-only model for pre-computed data.
            # Refresh with: {self.class_name}.refresh!
            #
            class {self.class_name} < ApplicationRecord
              self.table_name = '{self.name}'

              # Materialized views are read-only
              def readonly?
                true
              end

              def self.refresh!(concurrently: {'true' if self.unique_index_columns else 'false'})
                connection.execute(
                  "REFRESH MATERIALIZED VIEW{' CONCURRENTLY' if self.unique_index_columns else ''} {self.name};"
                )
              end
            end
        """)

    @property
    def rake_task_rb(self) -> str:
        ns = self.name
        return textwrap.dedent(f"""\
            # lib/tasks/{ns}.rake
            namespace :{ns} do
              desc "Refresh the {self.name} materialized view"
              task refresh: :environment do
                puts "Refreshing {self.name}..."
                {self.class_name}.refresh!
                puts "Done."
              end
            end
        """)

    @property
    def sidekiq_worker_rb(self) -> str:
        return textwrap.dedent(f"""\
            # app/workers/refresh_{self._snake_singular}_worker.rb
            class Refresh{self.class_name}Worker
              include Sidekiq::Worker
              sidekiq_options queue: :low, retry: 1

              def perform
                {self.class_name}.refresh!
              end
            end

            # In config/sidekiq_cron.yml:
            # refresh_{self.name}:
            #   cron: "0 * * * *"  # every hour
            #   class: Refresh{self.class_name}Worker
        """)

    @property
    def scenic_migration_rb(self) -> str:
        """Migration using the Scenic gem (simpler matview management)."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return textwrap.dedent(f"""\
            # Using Scenic gem (recommended for matview management)
            # 1. Add to Gemfile: gem 'scenic'
            # 2. Create db/views/{self.name}_v01.sql with the SELECT query
            # 3. Run this migration:

            class Create{self.class_name} < ActiveRecord::Migration[7.1]
              def change
                create_view :{self.name}, materialized: true
                {"add_index :" + self.name + ", " + ", ".join(":" + c for c in self.unique_index_columns) + ", unique: true" if self.unique_index_columns else ""}
              end
            end
        """)

    @property
    def _snake_singular(self) -> str:
        name = self.name
        if name.endswith("ies"):
            name = name[:-3] + "y"
        elif name.endswith("s") and not name.endswith("ss"):
            name = name[:-1]
        return name

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sql": self.sql,
            "class_name": self.class_name,
            "columns": self.columns,
            "source_tables": self.source_tables,
            "has_aggregation": self.has_aggregation,
            "unique_index_columns": self.unique_index_columns,
            "refresh_interval": self.refresh_interval,
            "create_sql": self.create_sql,
            "refresh_sql": self.refresh_sql,
            "migration_rb": self.migration_rb,
            "model_rb": self.model_rb,
            "rake_task_rb": self.rake_task_rb,
        }


_TABLE_RE = re.compile(r"\bFROM\s+(\w+)", re.IGNORECASE)
_JOIN_RE = re.compile(r"\bJOIN\s+(\w+)", re.IGNORECASE)
_AGG_RE = re.compile(r"\b(COUNT|SUM|AVG|MIN|MAX)\s*\(", re.IGNORECASE)
_GROUP_RE = re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE)
_SELECT_COL_RE = re.compile(
    r"SELECT\s+(.+?)\s+FROM", re.IGNORECASE | re.DOTALL
)


class MaterializedViewGenerator:
    """Generate materialized view specs from SQL or Rails-style descriptions."""

    def from_sql(
        self,
        name: str,
        sql: str,
        unique_on: list[str] | None = None,
        refresh_interval: str = "1 hour",
    ) -> MaterializedViewSpec:
        """Generate a full matview spec from a SELECT query."""
        tables = _TABLE_RE.findall(sql) + _JOIN_RE.findall(sql)
        has_agg = bool(_AGG_RE.search(sql))

        columns: list[str] = []
        col_match = _SELECT_COL_RE.search(sql)
        if col_match:
            raw_cols = col_match.group(1)
            for part in raw_cols.split(","):
                part = part.strip()
                as_match = re.search(r"\bAS\s+(\w+)", part, re.IGNORECASE)
                if as_match:
                    columns.append(as_match.group(1))
                elif "." in part:
                    columns.append(part.split(".")[-1].strip('"'))
                elif part != "*":
                    columns.append(part.strip('"'))

        unique_cols = unique_on or []
        if not unique_cols and columns:
            for col in columns:
                if col.lower() in ("id", "pk"):
                    unique_cols = [col]
                    break

        return MaterializedViewSpec(
            name=name,
            sql=sql,
            columns=columns,
            source_tables=list(dict.fromkeys(tables)),
            has_aggregation=has_agg,
            unique_index_columns=unique_cols,
            refresh_interval=refresh_interval,
        )

    async def from_expensive_queries(
        self,
        dsn: str,
        min_calls: int = 100,
        min_total_ms: float = 10000,
    ) -> list[MaterializedViewSpec]:
        """
        Detect queries that would benefit from materialization.

        Connects to pg_stat_statements and finds high-cost, high-frequency
        read queries with aggregations.
        """
        import asyncpg

        conn = await asyncpg.connect(dsn)
        try:
            rows = await conn.fetch("""
                SELECT query, calls, total_exec_time, mean_exec_time
                FROM pg_stat_statements
                WHERE calls >= $1
                  AND total_exec_time >= $2
                  AND query ~* '\\b(SELECT|WITH)\\b'
                  AND query ~* '\\b(COUNT|SUM|AVG|GROUP BY)\\b'
                  AND query !~* '\\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\\b'
                ORDER BY total_exec_time DESC
                LIMIT 20
            """, min_calls, min_total_ms)

            specs: list[MaterializedViewSpec] = []
            for i, row in enumerate(rows):
                sql = row["query"]
                name = f"mv_auto_{i + 1}"
                spec = self.from_sql(name, sql)
                specs.append(spec)

            return specs
        finally:
            await conn.close()
