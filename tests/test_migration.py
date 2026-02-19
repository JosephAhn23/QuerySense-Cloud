"""Tests for the Migration Safety Analyzer."""

import pytest

from querysense.migration import (
    DataImpact,
    LockAnalysis,
    LockLevel,
    MigrationAnalyzer,
    MigrationReport,
    PerformanceImpact,
    RiskLevel,
    SafeMigrationStep,
)


class TestLockLevel:
    """Tests for LockLevel enum."""

    def test_severity_ordering(self):
        assert LockLevel.ACCESS_SHARE.severity < LockLevel.ACCESS_EXCLUSIVE.severity
        assert LockLevel.ROW_EXCLUSIVE.severity < LockLevel.SHARE.severity

    def test_blocks_reads(self):
        assert LockLevel.ACCESS_EXCLUSIVE.blocks_reads
        assert not LockLevel.SHARE.blocks_reads
        assert not LockLevel.ROW_EXCLUSIVE.blocks_reads

    def test_blocks_writes(self):
        assert LockLevel.SHARE.blocks_writes
        assert LockLevel.ACCESS_EXCLUSIVE.blocks_writes
        assert not LockLevel.ROW_EXCLUSIVE.blocks_writes


class TestMigrationAnalyzerAddColumn:
    """Tests for ALTER TABLE ADD COLUMN analysis."""

    def test_add_nullable_column(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze("ALTER TABLE orders ADD COLUMN status TEXT;")

        assert len(report.statements) == 1
        assert len(report.lock_analyses) == 1
        assert report.lock_analyses[0].lock_level == LockLevel.ACCESS_EXCLUSIVE
        assert report.lock_analyses[0].estimated_duration_ms == 10.0  # Metadata only
        assert report.overall_risk == RiskLevel.MEDIUM  # Blocks writes

    def test_add_not_null_without_default(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders ADD COLUMN user_id INT NOT NULL;"
        )

        assert report.overall_risk == RiskLevel.HIGH
        assert any(la.blocks_reads for la in report.lock_analyses)
        assert any("NOT NULL" in w for w in report.warnings)
        assert len(report.rollback_sql) >= 1
        assert "DROP COLUMN" in report.rollback_sql[0]

    def test_add_not_null_with_default(self):
        """PG11+ can do this without rewrite."""
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';"
        )

        # Should NOT require table rewrite (PG11+)
        assert report.lock_analyses[0].estimated_duration_ms == 10.0

    def test_add_column_with_volatile_default(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders ADD COLUMN created_at TIMESTAMPTZ DEFAULT now();"
        )

        # Volatile default (now()) always requires rewrite
        assert any(la.blocks_reads for la in report.lock_analyses)

    def test_add_column_with_table_sizes(self):
        """Refined estimates with known table sizes."""
        analyzer = MigrationAnalyzer(table_sizes={"orders": 5_000_000})
        report = analyzer.analyze(
            "ALTER TABLE orders ADD COLUMN user_id INT NOT NULL;"
        )

        # Duration should reflect table size
        assert report.lock_analyses[0].estimated_duration_ms is not None
        assert report.lock_analyses[0].estimated_duration_ms > 100

    def test_generates_rollback(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders ADD COLUMN user_id INT;"
        )
        assert any("DROP COLUMN" in r for r in report.rollback_sql)


class TestMigrationAnalyzerDropColumn:
    """Tests for ALTER TABLE DROP COLUMN."""

    def test_drop_column_data_loss(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders DROP COLUMN status;"
        )

        assert any(di.data_loss_risk for di in report.data_impacts)
        assert report.overall_risk == RiskLevel.CRITICAL

    def test_drop_column_performance_impact(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders DROP COLUMN status;"
        )

        assert any(pi.category == "column_drop" for pi in report.performance_impacts)


class TestMigrationAnalyzerAlterType:
    """Tests for ALTER COLUMN TYPE."""

    def test_type_change_requires_rewrite(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders ALTER COLUMN amount TYPE NUMERIC(10,2);"
        )

        assert any(di.requires_rewrite for di in report.data_impacts)
        assert any(la.blocks_reads for la in report.lock_analyses)
        assert report.overall_risk == RiskLevel.HIGH


class TestMigrationAnalyzerCreateIndex:
    """Tests for CREATE INDEX."""

    def test_concurrent_index_safe(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "CREATE INDEX CONCURRENTLY idx_orders_user ON orders(user_id);"
        )

        assert report.lock_analyses[0].lock_level == LockLevel.SHARE_UPDATE_EXCLUSIVE
        assert not report.lock_analyses[0].blocks_writes
        assert report.overall_risk == RiskLevel.LOW

    def test_non_concurrent_warns(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "CREATE INDEX idx_orders_user ON orders(user_id);"
        )

        assert report.lock_analyses[0].lock_level == LockLevel.SHARE
        assert report.lock_analyses[0].blocks_writes
        assert any("CONCURRENTLY" in w for w in report.warnings)

    def test_generates_drop_rollback(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "CREATE INDEX idx_orders_user ON orders(user_id);"
        )
        assert any("DROP INDEX" in r for r in report.rollback_sql)


class TestMigrationAnalyzerDropIndex:
    """Tests for DROP INDEX."""

    def test_drop_index_performance_impact(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze("DROP INDEX idx_orders_user;")

        assert any(pi.category == "index_drop" for pi in report.performance_impacts)

    def test_drop_heavily_used_index(self):
        analyzer = MigrationAnalyzer(heavy_indexes={"idx_orders_user"})
        report = analyzer.analyze("DROP INDEX idx_orders_user;")

        assert any(
            pi.severity == RiskLevel.HIGH for pi in report.performance_impacts
        )


class TestMigrationAnalyzerDropTable:
    """Tests for DROP TABLE."""

    def test_drop_table_critical(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze("DROP TABLE orders;")

        assert report.overall_risk == RiskLevel.CRITICAL
        assert any(di.data_loss_risk for di in report.data_impacts)

    def test_drop_table_cascade_warning(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze("DROP TABLE orders CASCADE;")

        assert any("CASCADE" in w for w in report.warnings)


class TestMigrationAnalyzerConstraints:
    """Tests for constraint operations."""

    def test_add_constraint_not_valid(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders ADD CONSTRAINT chk_positive "
            "CHECK (amount > 0) NOT VALID;"
        )

        assert report.lock_analyses[0].lock_level == LockLevel.SHARE_UPDATE_EXCLUSIVE
        assert not report.lock_analyses[0].blocks_writes

    def test_add_constraint_without_not_valid(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders ADD CONSTRAINT chk_positive CHECK (amount > 0);"
        )

        assert report.lock_analyses[0].lock_level == LockLevel.ACCESS_EXCLUSIVE
        assert "NOT VALID" in report.lock_analyses[0].recommendation


class TestMigrationAnalyzerDML:
    """Tests for INSERT/UPDATE/DELETE in migrations."""

    def test_update_without_where(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze("UPDATE orders SET status = 'migrated';")

        assert any("without WHERE" in w for w in report.warnings)

    def test_delete_without_where(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze("DELETE FROM temp_data;")

        assert any("without WHERE" in w for w in report.warnings)


class TestMigrationAnalyzerTruncate:
    """Tests for TRUNCATE."""

    def test_truncate_data_loss(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze("TRUNCATE orders;")

        assert any(di.data_loss_risk for di in report.data_impacts)
        assert report.overall_risk == RiskLevel.CRITICAL


class TestSafeMigrationPlan:
    """Tests for safe migration plan generation."""

    def test_not_null_split_into_phases(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "ALTER TABLE orders ADD COLUMN user_id INT NOT NULL;"
        )

        assert len(report.safe_plan) >= 3
        # Phase 1: Add nullable
        assert "nullable" in report.safe_plan[0].description.lower()
        # Phase 2: Backfill
        assert "backfill" in report.safe_plan[1].description.lower()
        # Phase 3: NOT NULL constraint
        assert "not null" in report.safe_plan[2].description.lower()

    def test_index_adds_concurrently(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "CREATE INDEX idx_test ON orders(status);"
        )

        assert any("CONCURRENTLY" in s.sql for s in report.safe_plan)

    def test_safe_plan_for_create_table(self):
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(
            "CREATE TABLE new_table (id SERIAL PRIMARY KEY, name TEXT);"
        )

        assert len(report.safe_plan) >= 1


class TestMigrationAnalyzerMultiStatement:
    """Tests for multi-statement migrations."""

    def test_parses_multiple_statements(self):
        sql = """
        ALTER TABLE orders ADD COLUMN user_id INT;
        CREATE INDEX CONCURRENTLY idx_orders_user ON orders(user_id);
        """
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(sql)

        assert len(report.statements) == 2
        assert len(report.lock_analyses) == 2

    def test_overall_risk_is_max(self):
        sql = """
        ALTER TABLE orders ADD COLUMN status TEXT;
        DROP TABLE old_orders;
        """
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(sql)

        assert report.overall_risk == RiskLevel.CRITICAL  # DROP TABLE


class TestMigrationReport:
    """Tests for MigrationReport formatting."""

    def test_format_text(self):
        report = MigrationReport(
            original_sql="ALTER TABLE test ADD COLUMN x INT;",
            statements=["ALTER TABLE test ADD COLUMN x INT"],
            lock_analyses=[
                LockAnalysis(
                    lock_level=LockLevel.ACCESS_EXCLUSIVE,
                    affected_table="test",
                    estimated_duration_ms=10.0,
                )
            ],
            overall_risk=RiskLevel.MEDIUM,
        )
        text = report.format()
        assert "MIGRATION IMPACT PREDICTION" in text
        assert "MEDIUM" in text

    def test_format_json(self):
        report = MigrationReport(
            original_sql="SELECT 1",
            statements=["SELECT 1"],
            overall_risk=RiskLevel.LOW,
        )
        data = report.format_json()
        assert data["overall_risk"] == "low"
        assert isinstance(data["statements"], list)

    def test_format_pr_comment(self):
        report = MigrationReport(
            original_sql="ALTER TABLE t ADD COLUMN x INT;",
            statements=["ALTER TABLE t ADD COLUMN x INT"],
            overall_risk=RiskLevel.MEDIUM,
            warnings=["Test warning"],
            rollback_sql=["ALTER TABLE t DROP COLUMN x;"],
        )
        md = report.format_pr_comment()
        assert "Migration Analysis" in md
        assert "MEDIUM" in md
        assert "Rollback" in md
        assert "Test warning" in md
