"""
MySQL EXPLAIN (FORMAT=JSON) parser — production-ready.

Handles MySQL 5.7+, 8.0+, and MariaDB EXPLAIN FORMAT=JSON output.
Converts to engine-agnostic models that flow through the same IR pipeline
as PostgreSQL plans.

MySQL EXPLAIN JSON structure:
    {
      "query_block": {
        "select_id": 1,
        "cost_info": { "query_cost": "1.00" },
        "table": {
          "table_name": "orders",
          "access_type": "ALL",
          "rows_examined_per_scan": 1000,
          ...
        }
      }
    }

Usage:
    from querysense.parser.mysql_parser import parse_mysql_explain

    output = parse_mysql_explain("mysql_explain.json")
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from querysense.parser.parser import ParseError

logger = logging.getLogger(__name__)


# ── MySQL-specific models ──────────────────────────────────────────────────


class MySQLCostInfo(BaseModel):
    """MySQL cost information."""
    model_config = ConfigDict(extra="allow")

    query_cost: str = "0.00"
    read_cost: str | None = None
    eval_cost: str | None = None
    prefix_cost: str | None = None
    data_read_per_join: str | None = None

    @property
    def total_cost(self) -> float:
        try:
            return float(self.query_cost)
        except (ValueError, TypeError):
            return 0.0


class MySQLTableAccess(BaseModel):
    """A single table access in a MySQL EXPLAIN plan."""
    model_config = ConfigDict(extra="allow")

    table_name: str = Field(default="", alias="table_name")
    access_type: str = Field(default="ALL", alias="access_type")
    possible_keys: list[str] | None = None
    key: str | None = None
    key_length: str | None = None
    ref: list[str] | None = None
    rows_examined_per_scan: int = Field(default=0, alias="rows_examined_per_scan")
    rows_produced_per_join: int = Field(default=0, alias="rows_produced_per_join")
    filtered: str | float = "100.00"
    cost_info: MySQLCostInfo | None = None
    used_columns: list[str] | None = None
    attached_condition: str | None = None
    using_index: bool = False
    using_filesort: bool = False
    using_temporary_table: bool = False
    using_index_condition: str | None = None
    materialized_from_subquery: dict[str, Any] | None = None


class MySQLNestedLoop(BaseModel):
    """MySQL nested loop join representation."""
    model_config = ConfigDict(extra="allow")

    table: MySQLTableAccess | None = None


class MySQLOrderingOperation(BaseModel):
    """MySQL ORDER BY operation."""
    model_config = ConfigDict(extra="allow")

    using_filesort: bool = False
    using_temporary_table: bool = False
    cost_info: MySQLCostInfo | None = None
    nested_loop: list[MySQLNestedLoop] | None = None
    table: MySQLTableAccess | None = None


class MySQLGroupingOperation(BaseModel):
    """MySQL GROUP BY operation."""
    model_config = ConfigDict(extra="allow")

    using_filesort: bool = False
    using_temporary_table: bool = False
    cost_info: MySQLCostInfo | None = None
    nested_loop: list[MySQLNestedLoop] | None = None
    table: MySQLTableAccess | None = None
    ordering_operation: MySQLOrderingOperation | None = None


class MySQLDuplicatesRemoval(BaseModel):
    """MySQL DISTINCT operation."""
    model_config = ConfigDict(extra="allow")

    using_filesort: bool = False
    using_temporary_table: bool = False
    cost_info: MySQLCostInfo | None = None
    nested_loop: list[MySQLNestedLoop] | None = None


class MySQLQueryBlock(BaseModel):
    """Top-level MySQL query block."""
    model_config = ConfigDict(extra="allow")

    select_id: int = 1
    cost_info: MySQLCostInfo | None = None
    table: MySQLTableAccess | None = None
    nested_loop: list[MySQLNestedLoop] | None = None
    ordering_operation: MySQLOrderingOperation | None = None
    grouping_operation: MySQLGroupingOperation | None = None
    duplicates_removal: MySQLDuplicatesRemoval | None = None
    having_subqueries: list[dict[str, Any]] | None = None
    optimized_away: bool = False
    message: str | None = None


class MySQLExplainOutput(BaseModel):
    """Top-level MySQL EXPLAIN FORMAT=JSON output."""
    model_config = ConfigDict(extra="allow")

    query_block: MySQLQueryBlock

    # Computed properties for compatibility with PostgreSQL ExplainOutput
    @property
    def engine(self) -> str:
        return "mysql"

    @property
    def total_cost(self) -> float:
        if self.query_block.cost_info:
            return self.query_block.cost_info.total_cost
        return 0.0

    @property
    def tables_accessed(self) -> list[str]:
        """Collect all table names from the plan."""
        tables: list[str] = []
        self._collect_tables(tables)
        return tables

    def _collect_tables(self, tables: list[str]) -> None:
        """Recursively collect table names."""
        qb = self.query_block
        if qb.table and qb.table.table_name:
            tables.append(qb.table.table_name)
        if qb.nested_loop:
            for nl in qb.nested_loop:
                if nl.table and nl.table.table_name:
                    tables.append(nl.table.table_name)
        if qb.ordering_operation:
            if qb.ordering_operation.table and qb.ordering_operation.table.table_name:
                tables.append(qb.ordering_operation.table.table_name)
            if qb.ordering_operation.nested_loop:
                for nl in qb.ordering_operation.nested_loop:
                    if nl.table and nl.table.table_name:
                        tables.append(nl.table.table_name)
        if qb.grouping_operation:
            if qb.grouping_operation.nested_loop:
                for nl in qb.grouping_operation.nested_loop:
                    if nl.table and nl.table.table_name:
                        tables.append(nl.table.table_name)

    @property
    def all_table_accesses(self) -> list[MySQLTableAccess]:
        """Collect all table access objects for analysis."""
        accesses: list[MySQLTableAccess] = []
        self._collect_accesses(accesses)
        return accesses

    def _collect_accesses(self, accesses: list[MySQLTableAccess]) -> None:
        qb = self.query_block
        if qb.table:
            accesses.append(qb.table)
        if qb.nested_loop:
            for nl in qb.nested_loop:
                if nl.table:
                    accesses.append(nl.table)

        # Ordering operation tables
        if qb.ordering_operation:
            op = qb.ordering_operation
            if op.table:
                accesses.append(op.table)
            if op.nested_loop:
                for nl in op.nested_loop:
                    if nl.table:
                        accesses.append(nl.table)

        # Grouping operation tables
        if qb.grouping_operation:
            gp = qb.grouping_operation
            if gp.nested_loop:
                for nl in gp.nested_loop:
                    if nl.table:
                        accesses.append(nl.table)
            if gp.ordering_operation:
                oo = gp.ordering_operation
                if oo.table:
                    accesses.append(oo.table)
                if oo.nested_loop:
                    for nl in oo.nested_loop:
                        if nl.table:
                            accesses.append(nl.table)

    @property
    def has_filesort(self) -> bool:
        """Check if any table uses filesort."""
        if self.query_block.ordering_operation:
            return self.query_block.ordering_operation.using_filesort
        return any(t.using_filesort for t in self.all_table_accesses)

    @property
    def has_temporary_table(self) -> bool:
        """Check if any operation uses temporary tables."""
        if self.query_block.ordering_operation:
            if self.query_block.ordering_operation.using_temporary_table:
                return True
        if self.query_block.grouping_operation:
            if self.query_block.grouping_operation.using_temporary_table:
                return True
        return any(t.using_temporary_table for t in self.all_table_accesses)


# ── MySQL access type mapping ──────────────────────────────────────────────

MYSQL_ACCESS_SEVERITY = {
    "ALL": "critical",         # Full table scan
    "index": "warning",        # Full index scan
    "range": "info",           # Range scan
    "index_subquery": "info",
    "unique_subquery": "ok",
    "index_merge": "info",
    "ref_or_null": "info",
    "fulltext": "ok",
    "ref": "ok",
    "eq_ref": "ok",
    "const": "ok",
    "system": "ok",
    "NULL": "ok",
}


# ── Detection and parsing ──────────────────────────────────────────────────


def is_mysql_explain(data: dict[str, Any]) -> bool:
    """Detect whether JSON data is MySQL EXPLAIN FORMAT=JSON output."""
    if "query_block" in data:
        return True
    # Tabular format wrapped in array
    if isinstance(data, list) and data and "select_type" in data[0]:
        return True
    return False


def parse_mysql_explain(
    source: str | Path | dict[str, Any],
) -> MySQLExplainOutput:
    """
    Parse MySQL EXPLAIN (FORMAT=JSON) output.

    Args:
        source: File path, JSON string, or already-parsed dict

    Returns:
        MySQLExplainOutput with typed access to plan data

    Raises:
        ParseError: If input cannot be parsed or validated
    """
    data = _load_mysql_source(source)

    if "query_block" not in data:
        raise ParseError(
            "Missing 'query_block' — this doesn't look like MySQL EXPLAIN FORMAT=JSON",
            detail=(
                "MySQL EXPLAIN FORMAT=JSON output must contain a 'query_block' object.\n"
                "Run: EXPLAIN FORMAT=JSON <your query>"
            ),
            source="mysql_validation",
        )

    try:
        return MySQLExplainOutput.model_validate(data)
    except Exception as e:
        raise ParseError(
            "MySQL EXPLAIN output validation failed",
            detail=str(e),
            source="mysql_validation",
        ) from e


def _load_mysql_source(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load MySQL EXPLAIN source into a dict."""
    if isinstance(source, dict):
        return source

    if isinstance(source, Path):
        source = str(source)

    if isinstance(source, str):
        stripped = source.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                if not isinstance(data, dict):
                    raise ParseError(
                        f"Expected JSON object, got {type(data).__name__}",
                        source="mysql_json_decode",
                    )
                return data
            except json.JSONDecodeError as e:
                raise ParseError(
                    "Invalid JSON format",
                    detail=f"Line {e.lineno}, column {e.colno}: {e.msg}",
                    source="mysql_json_decode",
                ) from e

        # File path
        path = Path(stripped)
        if not path.exists():
            raise ParseError(f"File not found: {path}", source="mysql_file_read")

        try:
            content = path.read_text(encoding="utf-8")
            return _load_mysql_source(content)
        except OSError as e:
            raise ParseError(
                f"Cannot read file: {path}",
                detail=str(e),
                source="mysql_file_read",
            ) from e

    raise ParseError(
        f"Unsupported source type: {type(source).__name__}",
        source="mysql_type_check",
    )
