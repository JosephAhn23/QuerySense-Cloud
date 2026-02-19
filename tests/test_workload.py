"""Tests for the workload-wide index advisor."""

import pytest

from querysense.parser.models import ExplainOutput, PlanNode
from querysense.workload import (
    IndexCandidate,
    IndexScore,
    RedundantIndex,
    WorkloadAdvisor,
    WorkloadPlan,
    WorkloadReport,
)


def _make_explain(
    node_type: str = "Seq Scan",
    relation_name: str | None = "orders",
    actual_rows: int | None = 100_000,
    plan_rows: int = 100_000,
    filter_cond: str | None = "(status = 'active')",
    children: list[PlanNode] | None = None,
) -> ExplainOutput:
    """Create a minimal ExplainOutput for testing."""
    root = PlanNode(
        node_type=node_type,
        total_cost=5000.0,
        startup_cost=0.0,
        plan_rows=plan_rows,
        plan_width=64,
        actual_rows=actual_rows,
        actual_loops=1,
        actual_startup_time=0.5,
        actual_total_time=250.0,
        relation_name=relation_name,
        filter=filter_cond,
        rows_removed_by_filter=90_000 if filter_cond else None,
        plans=children or [],
    )
    return ExplainOutput(
        plan=root,
        planning_time=0.5,
        execution_time=250.0,
    )


class TestIndexCandidate:
    """Tests for IndexCandidate model."""

    def test_key_generation(self):
        c = IndexCandidate(table="orders", columns=("status", "created_at"))
        assert "orders" in c.key
        assert "status" in c.key

    def test_index_name(self):
        c = IndexCandidate(table="orders", columns=("status",))
        assert c.index_name == "idx_orders_status"

    def test_partial_index_name(self):
        c = IndexCandidate(
            table="orders",
            columns=("status",),
            is_partial=True,
            partial_predicate="active = true",
        )
        assert "partial" in c.index_name

    def test_create_sql_simple(self):
        c = IndexCandidate(table="orders", columns=("status",))
        sql = c.create_sql
        assert "CREATE INDEX CONCURRENTLY" in sql
        assert "ON orders" in sql
        assert "(status)" in sql

    def test_create_sql_gin(self):
        c = IndexCandidate(
            table="documents", columns=("content",), index_type="gin"
        )
        assert "USING gin" in c.create_sql

    def test_create_sql_with_include(self):
        c = IndexCandidate(
            table="orders",
            columns=("user_id",),
            include_columns=("total", "status"),
        )
        assert "INCLUDE (total, status)" in c.create_sql

    def test_create_sql_partial(self):
        c = IndexCandidate(
            table="orders",
            columns=("status",),
            is_partial=True,
            partial_predicate="active = true",
        )
        assert "WHERE active = true" in c.create_sql


class TestWorkloadAdvisor:
    """Tests for the WorkloadAdvisor engine."""

    def test_empty_workload(self):
        advisor = WorkloadAdvisor()
        report = advisor.analyze()
        assert report.plans_analyzed == 0
        assert report.total_findings == 0
        assert report.recommended_indexes == []

    def test_single_plan(self):
        advisor = WorkloadAdvisor()
        explain = _make_explain()
        advisor.add_plan(explain, label="q1", frequency=100)
        report = advisor.analyze()
        assert report.plans_analyzed == 1
        assert report.total_findings >= 0

    def test_multiple_plans_same_table(self):
        advisor = WorkloadAdvisor()

        # Two queries on the same table with different filters
        advisor.add_plan(
            _make_explain(filter_cond="(status = 'active')"),
            label="q1",
            frequency=500,
        )
        advisor.add_plan(
            _make_explain(filter_cond="(user_id = 42)"),
            label="q2",
            frequency=200,
        )

        report = advisor.analyze()
        assert report.plans_analyzed == 2
        # Should detect the hot table
        assert "orders" in report.table_hotspots

    def test_table_hotspots_counted(self):
        advisor = WorkloadAdvisor()
        for i in range(5):
            advisor.add_plan(
                _make_explain(relation_name="users"),
                label=f"q{i}",
            )
        report = advisor.analyze()
        assert "users" in report.table_hotspots
        assert report.table_hotspots["users"] >= 5

    def test_storage_budget(self):
        advisor = WorkloadAdvisor(storage_budget_mb=10.0)
        for i in range(10):
            advisor.add_plan(
                _make_explain(relation_name=f"table_{i}"),
                label=f"q{i}",
            )
        report = advisor.analyze()
        # With a tight budget, should limit recommendations
        total_size = sum(
            idx.estimated_size_mb for idx in report.recommended_indexes
        )
        assert total_size <= 10.0


class TestRedundantIndexDetection:
    """Tests for redundant index detection."""

    def test_prefix_detected(self):
        advisor = WorkloadAdvisor()
        # These should be detected via internal consolidation
        scored = [
            IndexScore(
                candidate=IndexCandidate(
                    table="orders", columns=("user_id",)
                ),
                queries_benefited=2,
            ),
            IndexScore(
                candidate=IndexCandidate(
                    table="orders", columns=("user_id", "status")
                ),
                queries_benefited=3,
            ),
        ]
        redundant = advisor._detect_redundant(scored)
        assert len(redundant) == 1
        assert "prefix" in redundant[0].reason.lower()

    def test_no_redundant_different_tables(self):
        advisor = WorkloadAdvisor()
        scored = [
            IndexScore(
                candidate=IndexCandidate(
                    table="orders", columns=("user_id",)
                ),
            ),
            IndexScore(
                candidate=IndexCandidate(
                    table="users", columns=("user_id", "status")
                ),
            ),
        ]
        redundant = advisor._detect_redundant(scored)
        assert len(redundant) == 0


class TestWorkloadReport:
    """Tests for WorkloadReport formatting."""

    def test_format_text(self):
        report = WorkloadReport(
            plans_analyzed=5,
            total_findings=12,
            recommended_indexes=[
                IndexScore(
                    candidate=IndexCandidate(
                        table="orders", columns=("status",)
                    ),
                    queries_benefited=3,
                    total_frequency_benefited=500,
                    roi_score=45.0,
                )
            ],
            redundant_indexes=[],
            table_hotspots={"orders": 8, "users": 4},
        )
        text = report.format()
        assert "Workload Analysis" in text
        assert "orders" in text
        assert "Plans analyzed: 5" in text

    def test_format_json(self):
        report = WorkloadReport(
            plans_analyzed=1,
            total_findings=0,
            recommended_indexes=[],
            redundant_indexes=[],
            table_hotspots={},
        )
        data = report.format_json()
        assert data["plans_analyzed"] == 1
        assert isinstance(data["recommended_indexes"], list)
        assert isinstance(data["redundant_indexes"], list)

    def test_format_with_redundant(self):
        report = WorkloadReport(
            plans_analyzed=2,
            total_findings=4,
            recommended_indexes=[],
            redundant_indexes=[
                RedundantIndex(
                    redundant="idx_orders_status",
                    covered_by="idx_orders_status_created_at",
                    reason="Prefix match",
                    drop_sql="DROP INDEX idx_orders_status;",
                )
            ],
            table_hotspots={},
        )
        text = report.format()
        assert "Redundant" in text
        assert "DROP" in text
