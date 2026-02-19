"""
Schema drift detection for QuerySense.

Extracts the current database schema (tables, columns, indexes, constraints),
stores a baseline, and detects unauthorized or unexpected changes.

Competes with Liquibase Pro's drift detection but works offline and
doesn't require a migration framework.

Usage:
    from querysense.schema import SchemaSnapshot, SchemaDrift, detect_drift

    # Capture current schema
    snapshot = await capture_schema(conn)
    snapshot.save("~/.querysense/schema_baseline.json")

    # Later, detect drift
    baseline = SchemaSnapshot.load("~/.querysense/schema_baseline.json")
    current = await capture_schema(conn)
    drift = detect_drift(baseline, current)
    if drift.has_changes:
        for change in drift.changes:
            print(change)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass
class ColumnInfo:
    """Schema information for a table column."""

    name: str
    data_type: str
    is_nullable: bool = True
    column_default: str | None = None
    ordinal_position: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "data_type": self.data_type,
            "is_nullable": self.is_nullable,
            "column_default": self.column_default,
            "ordinal_position": self.ordinal_position,
        }


@dataclass
class IndexInfo:
    """Schema information for an index."""

    name: str
    columns: tuple[str, ...]
    is_unique: bool = False
    is_primary: bool = False
    index_type: str = "btree"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "columns": list(self.columns),
            "is_unique": self.is_unique,
            "is_primary": self.is_primary,
            "index_type": self.index_type,
        }


@dataclass
class ConstraintInfo:
    """Schema information for a constraint."""

    name: str
    constraint_type: str  # PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK
    columns: tuple[str, ...] = ()
    foreign_table: str | None = None
    foreign_columns: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "constraint_type": self.constraint_type,
            "columns": list(self.columns),
        }
        if self.foreign_table:
            d["foreign_table"] = self.foreign_table
            d["foreign_columns"] = list(self.foreign_columns)
        return d


@dataclass
class TableSchema:
    """Complete schema for a single table."""

    name: str
    schema_name: str = "public"
    columns: list[ColumnInfo] = field(default_factory=list)
    indexes: list[IndexInfo] = field(default_factory=list)
    constraints: list[ConstraintInfo] = field(default_factory=list)
    row_estimate: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "schema": self.schema_name,
            "columns": [c.to_dict() for c in self.columns],
            "indexes": [i.to_dict() for i in self.indexes],
            "constraints": [c.to_dict() for c in self.constraints],
            "row_estimate": self.row_estimate,
        }


@dataclass
class SchemaSnapshot:
    """Complete database schema snapshot."""

    tables: dict[str, TableSchema] = field(default_factory=dict)
    captured_at: str = ""
    pg_version: str = ""
    database_name: str = ""
    label: str = ""

    def save(self, path: str | Path) -> None:
        """Save snapshot to JSON file."""
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "captured_at": self.captured_at,
            "pg_version": self.pg_version,
            "database_name": self.database_name,
            "label": self.label,
            "tables": {name: t.to_dict() for name, t in self.tables.items()},
        }
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def format_json(self) -> dict[str, Any]:
        """Serialize snapshot to a JSON-compatible dict."""
        return {
            "captured_at": self.captured_at,
            "pg_version": self.pg_version,
            "database_name": self.database_name,
            "label": self.label,
            "table_count": len(self.tables),
            "tables": {name: t.to_dict() for name, t in self.tables.items()},
        }

    @classmethod
    def load(cls, path: str | Path) -> SchemaSnapshot:
        """Load snapshot from JSON file."""
        p = Path(path).expanduser()
        data = json.loads(p.read_text(encoding="utf-8"))
        snapshot = cls(
            captured_at=data.get("captured_at", ""),
            pg_version=data.get("pg_version", ""),
            database_name=data.get("database_name", ""),
            label=data.get("label", ""),
        )
        for name, tdata in data.get("tables", {}).items():
            snapshot.tables[name] = TableSchema(
                name=tdata["name"],
                schema_name=tdata.get("schema", "public"),
                columns=[
                    ColumnInfo(**c) for c in tdata.get("columns", [])
                ],
                indexes=[
                    IndexInfo(
                        name=i["name"],
                        columns=tuple(i["columns"]),
                        is_unique=i.get("is_unique", False),
                        is_primary=i.get("is_primary", False),
                        index_type=i.get("index_type", "btree"),
                    )
                    for i in tdata.get("indexes", [])
                ],
                constraints=[
                    ConstraintInfo(
                        name=c["name"],
                        constraint_type=c["constraint_type"],
                        columns=tuple(c.get("columns", [])),
                        foreign_table=c.get("foreign_table"),
                        foreign_columns=tuple(c.get("foreign_columns", [])),
                    )
                    for c in tdata.get("constraints", [])
                ],
                row_estimate=tdata.get("row_estimate", 0),
            )
        return snapshot


# ── Drift Detection ──────────────────────────────────────────────────


@dataclass
class SchemaChange:
    """A single schema change detected between snapshots."""

    change_type: str  # "table_added", "table_removed", "column_added", etc.
    table: str
    detail: str
    severity: str = "info"  # "critical", "warning", "info"

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.change_type}: {self.table} - {self.detail}"


@dataclass
class SchemaDrift:
    """Result of comparing two schema snapshots."""

    baseline_at: str
    current_at: str
    changes: list[SchemaChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return len(self.changes) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.changes if c.severity == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.changes if c.severity == "warning")

    def summary(self) -> str:
        if not self.has_changes:
            return "No schema drift detected."
        return (
            f"{len(self.changes)} change(s): "
            f"{self.critical_count} critical, "
            f"{self.warning_count} warning, "
            f"{len(self.changes) - self.critical_count - self.warning_count} info"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_at": self.baseline_at,
            "current_at": self.current_at,
            "has_changes": self.has_changes,
            "summary": self.summary(),
            "changes": [
                {
                    "change_type": c.change_type,
                    "table": c.table,
                    "detail": c.detail,
                    "severity": c.severity,
                }
                for c in self.changes
            ],
        }


def detect_drift(baseline: SchemaSnapshot, current: SchemaSnapshot) -> SchemaDrift:
    """
    Compare two schema snapshots and identify all changes.

    Detects:
    - Tables added or removed
    - Columns added, removed, or type-changed
    - Indexes added or removed
    - Constraints added or removed
    """
    drift = SchemaDrift(
        baseline_at=baseline.captured_at,
        current_at=current.captured_at,
    )

    baseline_tables = set(baseline.tables.keys())
    current_tables = set(current.tables.keys())

    # Tables added
    for table in current_tables - baseline_tables:
        drift.changes.append(SchemaChange(
            change_type="table_added",
            table=table,
            detail=f"New table '{table}' not in baseline",
            severity="warning",
        ))

    # Tables removed
    for table in baseline_tables - current_tables:
        drift.changes.append(SchemaChange(
            change_type="table_removed",
            table=table,
            detail=f"Table '{table}' was removed",
            severity="critical",
        ))

    # Compare shared tables
    for table in baseline_tables & current_tables:
        _compare_table(baseline.tables[table], current.tables[table], drift)

    return drift


def _compare_table(baseline: TableSchema, current: TableSchema, drift: SchemaDrift) -> None:
    """Compare two versions of the same table."""
    table = baseline.name

    # Compare columns
    baseline_cols = {c.name: c for c in baseline.columns}
    current_cols = {c.name: c for c in current.columns}

    for col_name in set(current_cols) - set(baseline_cols):
        drift.changes.append(SchemaChange(
            change_type="column_added",
            table=table,
            detail=f"Column '{col_name}' added ({current_cols[col_name].data_type})",
            severity="info",
        ))

    for col_name in set(baseline_cols) - set(current_cols):
        drift.changes.append(SchemaChange(
            change_type="column_removed",
            table=table,
            detail=f"Column '{col_name}' was removed",
            severity="critical",
        ))

    for col_name in set(baseline_cols) & set(current_cols):
        b_col = baseline_cols[col_name]
        c_col = current_cols[col_name]
        if b_col.data_type != c_col.data_type:
            drift.changes.append(SchemaChange(
                change_type="column_type_changed",
                table=table,
                detail=f"Column '{col_name}' type: {b_col.data_type} -> {c_col.data_type}",
                severity="warning",
            ))
        if b_col.is_nullable != c_col.is_nullable:
            null_change = "nullable" if c_col.is_nullable else "NOT NULL"
            drift.changes.append(SchemaChange(
                change_type="column_nullable_changed",
                table=table,
                detail=f"Column '{col_name}' now {null_change}",
                severity="warning",
            ))

    # Compare indexes
    baseline_idx = {i.name: i for i in baseline.indexes}
    current_idx = {i.name: i for i in current.indexes}

    for idx_name in set(current_idx) - set(baseline_idx):
        idx = current_idx[idx_name]
        drift.changes.append(SchemaChange(
            change_type="index_added",
            table=table,
            detail=f"Index '{idx_name}' added on ({', '.join(idx.columns)})",
            severity="info",
        ))

    for idx_name in set(baseline_idx) - set(current_idx):
        drift.changes.append(SchemaChange(
            change_type="index_removed",
            table=table,
            detail=f"Index '{idx_name}' was removed",
            severity="warning",
        ))

    # Compare constraints
    baseline_con = {c.name: c for c in baseline.constraints}
    current_con = {c.name: c for c in current.constraints}

    for con_name in set(current_con) - set(baseline_con):
        con = current_con[con_name]
        drift.changes.append(SchemaChange(
            change_type="constraint_added",
            table=table,
            detail=f"Constraint '{con_name}' ({con.constraint_type}) added",
            severity="info",
        ))

    for con_name in set(baseline_con) - set(current_con):
        con = baseline_con[con_name]
        drift.changes.append(SchemaChange(
            change_type="constraint_removed",
            table=table,
            detail=f"Constraint '{con_name}' ({con.constraint_type}) removed",
            severity="critical",
        ))


async def capture_schema(
    conn_or_dsn: "AsyncDBConnection | str",
    schema_name: str = "public",
) -> SchemaSnapshot:
    """
    Capture the current database schema.

    Reads tables, columns, indexes, and constraints from information_schema
    and pg_catalog.
    """
    # Support DSN string as convenience
    own_conn = False
    if isinstance(conn_or_dsn, str):
        try:
            import asyncpg
            conn = await asyncpg.connect(conn_or_dsn)
            own_conn = True
        except ImportError:
            raise RuntimeError("asyncpg is required: pip install asyncpg")
    else:
        conn = conn_or_dsn

    snapshot = SchemaSnapshot(
        captured_at=datetime.now(timezone.utc).isoformat(),
    )

    try:
        snapshot.pg_version = await conn.fetchval("SHOW server_version") or ""
        snapshot.database_name = await conn.fetchval("SELECT current_database()") or ""
    except Exception:
        pass

    # Get tables
    try:
        tables = await conn.fetch(
            """SELECT c.relname AS table_name,
                      c.reltuples::bigint AS row_estimate
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = $1
                 AND c.relkind = 'r'
               ORDER BY c.relname""",
            schema_name,
        )
    except Exception:
        return snapshot

    for trow in tables:
        table_name = trow["table_name"]
        table = TableSchema(
            name=table_name,
            schema_name=schema_name,
            row_estimate=trow["row_estimate"] or 0,
        )

        # Columns
        try:
            cols = await conn.fetch(
                """SELECT column_name, data_type, is_nullable, column_default,
                          ordinal_position
                   FROM information_schema.columns
                   WHERE table_schema = $1 AND table_name = $2
                   ORDER BY ordinal_position""",
                schema_name, table_name,
            )
            table.columns = [
                ColumnInfo(
                    name=c["column_name"],
                    data_type=c["data_type"],
                    is_nullable=c["is_nullable"] == "YES",
                    column_default=c["column_default"],
                    ordinal_position=c["ordinal_position"],
                )
                for c in cols
            ]
        except Exception:
            pass

        # Indexes
        try:
            idxs = await conn.fetch(
                """SELECT i.relname AS index_name,
                          array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns,
                          ix.indisunique, ix.indisprimary, am.amname
                   FROM pg_index ix
                   JOIN pg_class i ON i.oid = ix.indexrelid
                   JOIN pg_class t ON t.oid = ix.indrelid
                   JOIN pg_namespace n ON n.oid = t.relnamespace
                   JOIN pg_am am ON am.oid = i.relam
                   JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
                   WHERE t.relname = $1 AND n.nspname = $2
                   GROUP BY i.relname, ix.indisunique, ix.indisprimary, am.amname""",
                table_name, schema_name,
            )
            table.indexes = [
                IndexInfo(
                    name=idx["index_name"],
                    columns=tuple(idx["columns"]),
                    is_unique=idx["indisunique"],
                    is_primary=idx["indisprimary"],
                    index_type=idx["amname"],
                )
                for idx in idxs
            ]
        except Exception:
            pass

        # Constraints
        try:
            cons = await conn.fetch(
                """SELECT tc.constraint_name, tc.constraint_type,
                          array_agg(kcu.column_name ORDER BY kcu.ordinal_position) AS columns,
                          ccu.table_name AS foreign_table
                   FROM information_schema.table_constraints tc
                   JOIN information_schema.key_column_usage kcu
                        ON tc.constraint_name = kcu.constraint_name
                        AND tc.table_schema = kcu.table_schema
                   LEFT JOIN information_schema.constraint_column_usage ccu
                        ON tc.constraint_name = ccu.constraint_name
                        AND tc.constraint_type = 'FOREIGN KEY'
                   WHERE tc.table_name = $1 AND tc.table_schema = $2
                   GROUP BY tc.constraint_name, tc.constraint_type, ccu.table_name""",
                table_name, schema_name,
            )
            table.constraints = [
                ConstraintInfo(
                    name=c["constraint_name"],
                    constraint_type=c["constraint_type"],
                    columns=tuple(c["columns"]),
                    foreign_table=c["foreign_table"],
                )
                for c in cons
            ]
        except Exception:
            pass

        snapshot.tables[table_name] = table

    if own_conn:
        await conn.close()  # type: ignore[union-attr]

    return snapshot


# ── Schema Comparison (for schema_cmd.py) ────────────────────────────

@dataclass
class SchemaDifference:
    """A single difference between two schema snapshots (for compare command)."""

    table: str
    category: str  # "column", "index", "constraint", "table"
    change_type: str  # "added", "removed", "modified"
    object_name: str
    source_value: str = ""
    target_value: str = ""
    severity: str = "info"


@dataclass
class SchemaDiff:
    """Result of comparing two schema snapshots (full comparison report)."""

    source_label: str = ""
    target_label: str = ""
    differences: list[SchemaDifference] = field(default_factory=list)

    @property
    def has_differences(self) -> bool:
        return len(self.differences) > 0

    def format_json(self) -> dict[str, Any]:
        return {
            "source_label": self.source_label,
            "target_label": self.target_label,
            "has_differences": self.has_differences,
            "difference_count": len(self.differences),
            "differences": [
                {
                    "table": d.table,
                    "category": d.category,
                    "change_type": d.change_type,
                    "object_name": d.object_name,
                    "source_value": d.source_value,
                    "target_value": d.target_value,
                    "severity": d.severity,
                }
                for d in self.differences
            ],
        }

    def generate_sync_sql(self) -> list[str]:
        """Generate SQL to sync target to match source."""
        sqls: list[str] = []
        for d in self.differences:
            if d.category == "table" and d.change_type == "added":
                sqls.append(f"-- CREATE TABLE {d.object_name} (manual definition required)")
            elif d.category == "table" and d.change_type == "removed":
                sqls.append(f"DROP TABLE IF EXISTS {d.object_name};")
            elif d.category == "column" and d.change_type == "added":
                sqls.append(
                    f"ALTER TABLE {d.table} ADD COLUMN {d.object_name} {d.source_value};"
                )
            elif d.category == "column" and d.change_type == "removed":
                sqls.append(
                    f"ALTER TABLE {d.table} DROP COLUMN IF EXISTS {d.object_name};"
                )
            elif d.category == "column" and d.change_type == "modified":
                sqls.append(
                    f"ALTER TABLE {d.table} ALTER COLUMN {d.object_name} "
                    f"TYPE {d.source_value};"
                )
            elif d.category == "index" and d.change_type == "removed":
                sqls.append(f"DROP INDEX IF EXISTS {d.object_name};")
            elif d.category == "constraint" and d.change_type == "removed":
                sqls.append(
                    f"ALTER TABLE {d.table} DROP CONSTRAINT IF EXISTS {d.object_name};"
                )
        return sqls


def compare_schemas(source: SchemaSnapshot, target: SchemaSnapshot) -> SchemaDiff:
    """
    Compare two schema snapshots and return a SchemaDiff.

    Used by the `querysense schema compare` command.
    Source is the "truth"; differences are relative to target.
    """
    diff = SchemaDiff(
        source_label=source.label or source.database_name or source.captured_at,
        target_label=target.label or target.database_name or target.captured_at,
    )

    source_tables = set(source.tables.keys())
    target_tables = set(target.tables.keys())

    # Tables in source but not target (target needs them)
    for table in source_tables - target_tables:
        diff.differences.append(SchemaDifference(
            table=table,
            category="table",
            change_type="added",
            object_name=table,
            source_value=f"{len(source.tables[table].columns)} columns",
            severity="warning",
        ))

    # Tables in target but not source (target has extra)
    for table in target_tables - source_tables:
        diff.differences.append(SchemaDifference(
            table=table,
            category="table",
            change_type="removed",
            object_name=table,
            target_value=f"{len(target.tables[table].columns)} columns",
            severity="critical",
        ))

    # Compare shared tables
    for table in source_tables & target_tables:
        src_t = source.tables[table]
        tgt_t = target.tables[table]
        _compare_table_diff(table, src_t, tgt_t, diff)

    return diff


def _compare_table_diff(
    table: str, source: TableSchema, target: TableSchema, diff: SchemaDiff,
) -> None:
    """Compare two table schemas for the compare command."""
    src_cols = {c.name: c for c in source.columns}
    tgt_cols = {c.name: c for c in target.columns}

    for col in set(src_cols) - set(tgt_cols):
        diff.differences.append(SchemaDifference(
            table=table,
            category="column",
            change_type="added",
            object_name=col,
            source_value=src_cols[col].data_type,
            severity="warning",
        ))

    for col in set(tgt_cols) - set(src_cols):
        diff.differences.append(SchemaDifference(
            table=table,
            category="column",
            change_type="removed",
            object_name=col,
            target_value=tgt_cols[col].data_type,
            severity="critical",
        ))

    for col in set(src_cols) & set(tgt_cols):
        if src_cols[col].data_type != tgt_cols[col].data_type:
            diff.differences.append(SchemaDifference(
                table=table,
                category="column",
                change_type="modified",
                object_name=col,
                source_value=src_cols[col].data_type,
                target_value=tgt_cols[col].data_type,
                severity="warning",
            ))

    # Indexes
    src_idx = {i.name: i for i in source.indexes}
    tgt_idx = {i.name: i for i in target.indexes}

    for idx in set(src_idx) - set(tgt_idx):
        diff.differences.append(SchemaDifference(
            table=table,
            category="index",
            change_type="added",
            object_name=idx,
            source_value=f"({', '.join(src_idx[idx].columns)})",
            severity="info",
        ))

    for idx in set(tgt_idx) - set(src_idx):
        diff.differences.append(SchemaDifference(
            table=table,
            category="index",
            change_type="removed",
            object_name=idx,
            target_value=f"({', '.join(tgt_idx[idx].columns)})",
            severity="warning",
        ))

    # Constraints
    src_con = {c.name: c for c in source.constraints}
    tgt_con = {c.name: c for c in target.constraints}

    for con in set(src_con) - set(tgt_con):
        diff.differences.append(SchemaDifference(
            table=table,
            category="constraint",
            change_type="added",
            object_name=con,
            source_value=src_con[con].constraint_type,
            severity="info",
        ))

    for con in set(tgt_con) - set(src_con):
        diff.differences.append(SchemaDifference(
            table=table,
            category="constraint",
            change_type="removed",
            object_name=con,
            target_value=tgt_con[con].constraint_type,
            severity="critical",
        ))
