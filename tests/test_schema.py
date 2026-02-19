"""Tests for Schema Drift Detection."""

import json
from pathlib import Path

import pytest

from querysense.schema import (
    ColumnInfo,
    ConstraintInfo,
    IndexInfo,
    SchemaDiff,
    SchemaDifference,
    SchemaSnapshot,
    TableSchema,
    compare_schemas,
    detect_drift,
)


def _make_snapshot(
    tables: dict[str, dict] | None = None,
    label: str = "test",
) -> SchemaSnapshot:
    """Create a SchemaSnapshot from a simple dict spec."""
    snapshot = SchemaSnapshot(label=label)
    if tables:
        for name, spec in tables.items():
            table = TableSchema(name=name)
            for col_spec in spec.get("columns", []):
                if isinstance(col_spec, str):
                    table.columns.append(ColumnInfo(name=col_spec, data_type="text"))
                elif isinstance(col_spec, dict):
                    table.columns.append(ColumnInfo(
                        name=col_spec["name"],
                        data_type=col_spec.get("type", "text"),
                        is_nullable=col_spec.get("nullable", True),
                        column_default=col_spec.get("default"),
                    ))
            for idx_spec in spec.get("indexes", []):
                table.indexes.append(IndexInfo(
                    name=idx_spec["name"],
                    columns=tuple(idx_spec.get("columns", [])),
                    is_unique=idx_spec.get("unique", False),
                ))
            for con_spec in spec.get("constraints", []):
                table.constraints.append(ConstraintInfo(
                    name=con_spec["name"],
                    constraint_type=con_spec.get("type", "CHECK"),
                ))
            snapshot.tables[name] = table
    return snapshot


class TestSchemaSnapshotIO:
    """Tests for save/load."""

    def test_save_and_load(self, tmp_path):
        original = _make_snapshot({
            "users": {
                "columns": [
                    {"name": "id", "type": "integer", "nullable": False},
                    {"name": "email", "type": "text"},
                ],
                "indexes": [
                    {"name": "idx_users_email", "columns": ["email"]},
                ],
            }
        }, label="prod")

        path = tmp_path / "schema.json"
        original.save(path)

        loaded = SchemaSnapshot.load(path)
        assert loaded.label == "prod"
        assert "users" in loaded.tables
        assert len(loaded.tables["users"].columns) == 2
        assert len(loaded.tables["users"].indexes) == 1

    def test_save_creates_valid_json(self, tmp_path):
        snap = _make_snapshot({"t": {"columns": ["a"]}})
        path = tmp_path / "test.json"
        snap.save(path)

        data = json.loads(path.read_text())
        assert "tables" in data
        assert "t" in data["tables"]


class TestCompareSchemas:
    """Tests for schema comparison."""

    def test_identical_schemas(self):
        snap1 = _make_snapshot({"users": {"columns": ["id", "name"]}})
        snap2 = _make_snapshot({"users": {"columns": ["id", "name"]}})
        diff = compare_schemas(snap1, snap2)
        assert not diff.has_differences

    def test_missing_table_in_target(self):
        """Table in source but missing from target."""
        source = _make_snapshot({
            "users": {"columns": ["id"]},
            "orders": {"columns": ["id"]},
        })
        target = _make_snapshot({
            "users": {"columns": ["id"]},
        })
        diff = compare_schemas(source, target)
        assert diff.has_differences
        # source has "orders" but target doesn't => "added" (source wants to add)
        added = [d for d in diff.differences if d.category == "table" and d.change_type == "added"]
        assert len(added) == 1
        assert added[0].table == "orders"

    def test_extra_table_in_target(self):
        """Table in target but not in source."""
        source = _make_snapshot({"users": {"columns": ["id"]}})
        target = _make_snapshot({
            "users": {"columns": ["id"]},
            "temp_data": {"columns": ["x"]},
        })
        diff = compare_schemas(source, target)
        removed = [d for d in diff.differences if d.category == "table" and d.change_type == "removed"]
        assert len(removed) == 1
        assert removed[0].table == "temp_data"

    def test_missing_column_in_target(self):
        source = _make_snapshot({
            "users": {"columns": [
                {"name": "id", "type": "integer"},
                {"name": "email", "type": "text"},
            ]}
        })
        target = _make_snapshot({
            "users": {"columns": [
                {"name": "id", "type": "integer"},
            ]}
        })
        diff = compare_schemas(source, target)
        added = [d for d in diff.differences if d.category == "column" and d.change_type == "added"]
        assert len(added) == 1
        assert added[0].object_name == "email"

    def test_extra_column_in_target(self):
        source = _make_snapshot({"users": {"columns": ["id"]}})
        target = _make_snapshot({
            "users": {"columns": ["id", "temp_col"]}
        })
        diff = compare_schemas(source, target)
        removed = [d for d in diff.differences if d.category == "column" and d.change_type == "removed"]
        assert len(removed) == 1
        assert removed[0].object_name == "temp_col"

    def test_column_type_change(self):
        source = _make_snapshot({
            "users": {"columns": [{"name": "age", "type": "integer"}]}
        })
        target = _make_snapshot({
            "users": {"columns": [{"name": "age", "type": "text"}]}
        })
        diff = compare_schemas(source, target)
        modified = [d for d in diff.differences if d.change_type == "modified"]
        assert len(modified) == 1
        assert modified[0].object_name == "age"

    def test_missing_index(self):
        source = _make_snapshot({
            "orders": {
                "columns": ["id"],
                "indexes": [{"name": "idx_orders_status", "columns": ["status"]}],
            }
        })
        target = _make_snapshot({
            "orders": {"columns": ["id"]}
        })
        diff = compare_schemas(source, target)
        # Source has index, target doesn't => "added"
        idx_diffs = [d for d in diff.differences if d.category == "index"]
        assert len(idx_diffs) == 1
        assert "idx_orders_status" in idx_diffs[0].object_name

    def test_missing_constraint(self):
        source = _make_snapshot({
            "payments": {
                "columns": ["id"],
                "constraints": [{"name": "chk_amount", "type": "CHECK"}],
            }
        })
        target = _make_snapshot({
            "payments": {"columns": ["id"]}
        })
        diff = compare_schemas(source, target)
        con_diffs = [d for d in diff.differences if d.category == "constraint"]
        assert len(con_diffs) == 1
        assert con_diffs[0].object_name == "chk_amount"


class TestDetectDrift:
    """Tests for the detect_drift function."""

    def test_no_drift(self):
        snap = _make_snapshot({"users": {"columns": ["id"]}})
        drift = detect_drift(snap, snap)
        assert not drift.has_changes

    def test_detects_table_added(self):
        baseline = _make_snapshot({"users": {"columns": ["id"]}})
        current = _make_snapshot({
            "users": {"columns": ["id"]},
            "orders": {"columns": ["id"]},
        })
        drift = detect_drift(baseline, current)
        assert drift.has_changes
        assert any("table_added" in c.change_type for c in drift.changes)

    def test_detects_table_removed(self):
        baseline = _make_snapshot({
            "users": {"columns": ["id"]},
            "orders": {"columns": ["id"]},
        })
        current = _make_snapshot({"users": {"columns": ["id"]}})
        drift = detect_drift(baseline, current)
        assert drift.has_changes
        assert any("table_removed" in c.change_type for c in drift.changes)

    def test_detects_column_added(self):
        baseline = _make_snapshot({"users": {"columns": ["id"]}})
        current = _make_snapshot({"users": {"columns": ["id", "email"]}})
        drift = detect_drift(baseline, current)
        assert drift.has_changes
        assert any("column_added" in c.change_type for c in drift.changes)

    def test_detects_column_removed(self):
        baseline = _make_snapshot({"users": {"columns": ["id", "email"]}})
        current = _make_snapshot({"users": {"columns": ["id"]}})
        drift = detect_drift(baseline, current)
        assert drift.has_changes
        assert any("column_removed" in c.change_type for c in drift.changes)

    def test_summary(self):
        baseline = _make_snapshot({"users": {"columns": ["id"]}})
        current = _make_snapshot({
            "users": {"columns": ["id"]},
            "orders": {"columns": ["id"]},
        })
        drift = detect_drift(baseline, current)
        summary = drift.summary()
        assert "change" in summary


class TestSchemaDiffOutput:
    """Tests for diff formatting."""

    def test_format_json(self):
        diff = SchemaDiff(
            source_label="a",
            target_label="b",
            differences=[
                SchemaDifference(
                    category="table",
                    change_type="removed",
                    table="test",
                    object_name="test",
                ),
            ],
        )
        data = diff.format_json()
        assert data["difference_count"] == 1
        assert data["differences"][0]["table"] == "test"

    def test_generate_sync_sql(self):
        diff = SchemaDiff(
            source_label="a",
            target_label="b",
            differences=[
                SchemaDifference(
                    category="column",
                    change_type="added",
                    table="users",
                    object_name="email",
                    source_value="text",
                ),
            ],
        )
        sqls = diff.generate_sync_sql()
        assert len(sqls) == 1
        assert "ALTER TABLE" in sqls[0]
        assert "ADD COLUMN" in sqls[0]


class TestComplexSchemaComparison:
    """Integration tests with realistic schemas."""

    def test_realistic_diff(self):
        source = _make_snapshot({
            "users": {
                "columns": [
                    {"name": "id", "type": "integer", "nullable": False},
                    {"name": "email", "type": "text", "nullable": False},
                    {"name": "name", "type": "text"},
                ],
                "indexes": [
                    {"name": "idx_users_email", "columns": ["email"], "unique": True},
                ],
                "constraints": [
                    {"name": "users_pkey", "type": "PRIMARY KEY"},
                ],
            },
            "orders": {
                "columns": [
                    {"name": "id", "type": "integer"},
                    {"name": "user_id", "type": "integer"},
                    {"name": "status", "type": "text"},
                ],
                "indexes": [
                    {"name": "idx_orders_user", "columns": ["user_id"]},
                    {"name": "idx_orders_status", "columns": ["status"]},
                ],
            },
        }, label="production")

        target = _make_snapshot({
            "users": {
                "columns": [
                    {"name": "id", "type": "integer", "nullable": False},
                    {"name": "email", "type": "text", "nullable": False},
                    {"name": "name", "type": "text"},
                    {"name": "temp_data", "type": "text"},  # Extra column
                ],
                "indexes": [
                    {"name": "idx_users_email", "columns": ["email"], "unique": True},
                ],
                "constraints": [
                    {"name": "users_pkey", "type": "PRIMARY KEY"},
                ],
            },
            "orders": {
                "columns": [
                    {"name": "id", "type": "integer"},
                    {"name": "user_id", "type": "integer"},
                    {"name": "status", "type": "text"},
                ],
                "indexes": [
                    {"name": "idx_orders_user", "columns": ["user_id"]},
                    # Missing idx_orders_status
                ],
            },
        }, label="staging")

        diff = compare_schemas(source, target)

        assert diff.has_differences
        # Extra column in staging target
        assert any(
            d.category == "column" and d.change_type == "removed"
            and d.object_name == "temp_data"
            for d in diff.differences
        )
        # Missing index in staging target
        assert any(
            d.category == "index"
            and "idx_orders_status" in d.object_name
            for d in diff.differences
        )
