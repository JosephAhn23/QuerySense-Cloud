"""Tests for new rules: FK index, stale stats, table bloat."""

import pytest

from querysense.analyzer.models import Severity
from querysense.analyzer.rules.foreign_key_index import ForeignKeyWithoutIndex
from querysense.analyzer.rules.stale_statistics import StaleStatistics
from querysense.analyzer.rules.table_bloat import TableBloat
from querysense.parser.models import ExplainOutput, PlanNode


def make_explain(nodes: list[dict]) -> ExplainOutput:
    """Create minimal ExplainOutput from node dicts."""
    plan_nodes = []
    for node_data in nodes:
        plan_nodes.append(PlanNode(
            node_type=node_data.get("node_type", "Seq Scan"),
            total_cost=node_data.get("total_cost", 1000.0),
            startup_cost=node_data.get("startup_cost", 0.0),
            plan_rows=node_data.get("plan_rows", 100),
            plan_width=node_data.get("plan_width", 64),
            actual_rows=node_data.get("actual_rows"),
            actual_loops=node_data.get("actual_loops", 1),
            actual_startup_time=node_data.get("actual_startup_time"),
            actual_total_time=node_data.get("actual_total_time"),
            relation_name=node_data.get("relation_name"),
            filter=node_data.get("filter"),
            rows_removed_by_filter=node_data.get("rows_removed_by_filter"),
        ))
    
    root_node = plan_nodes[0] if plan_nodes else PlanNode(
        node_type="Result",
        total_cost=0,
        startup_cost=0,
        plan_rows=0,
        plan_width=0,
    )
    
    return ExplainOutput(
        plan=root_node,
        planning_time=0.5,
        execution_time=100.0,
    )


class TestForeignKeyWithoutIndex:
    """Tests for FK index detection."""
    
    def test_detects_fk_column_in_filter(self):
        """Should detect seq scan with FK-like column in filter."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "orders",
            "actual_rows": 50_000,
            "plan_rows": 50_000,
            "filter": "(user_id = 123)",
        }])
        
        rule = ForeignKeyWithoutIndex()
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].rule_id == "FOREIGN_KEY_WITHOUT_INDEX"
        assert "user_id" in findings[0].title
        assert "CREATE INDEX" in findings[0].suggestion
    
    def test_ignores_small_tables(self):
        """Should not flag small tables."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "settings",
            "actual_rows": 50,
            "plan_rows": 50,
            "filter": "(user_id = 123)",
        }])
        
        rule = ForeignKeyWithoutIndex()
        findings = rule.analyze(explain)
        
        assert len(findings) == 0
    
    def test_ignores_non_fk_columns(self):
        """Should not flag filters on non-FK columns."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "users",
            "actual_rows": 50_000,
            "plan_rows": 50_000,
            "filter": "(name = 'John')",
        }])
        
        rule = ForeignKeyWithoutIndex()
        findings = rule.analyze(explain)
        
        assert len(findings) == 0
    
    def test_critical_severity_for_large_table(self):
        """Should escalate to CRITICAL for very large tables."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "events",
            "actual_rows": 500_000,
            "plan_rows": 500_000,
            "filter": "(account_id = 456)",
        }])
        
        rule = ForeignKeyWithoutIndex()
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestStaleStatistics:
    """Tests for stale statistics detection."""
    
    def test_detects_underestimate(self):
        """Should detect when actual >> planned rows."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "orders",
            "actual_rows": 100_000,
            "plan_rows": 1_000,  # 100x underestimate
        }])
        
        rule = StaleStatistics()
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].rule_id == "STALE_STATISTICS"
        assert "100x" in findings[0].title or "100" in findings[0].title
        assert "ANALYZE" in findings[0].suggestion
    
    def test_detects_overestimate(self):
        """Should detect when planned >> actual rows."""
        explain = make_explain([{
            "node_type": "Index Scan",
            "relation_name": "users",
            "actual_rows": 1_000,
            "plan_rows": 100_000,  # 100x overestimate
        }])
        
        rule = StaleStatistics()
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert "overestimated" in findings[0].title
    
    def test_ignores_accurate_estimates(self):
        """Should not flag accurate estimates."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "products",
            "actual_rows": 1_000,
            "plan_rows": 950,  # Close enough
        }])
        
        rule = StaleStatistics()
        findings = rule.analyze(explain)
        
        assert len(findings) == 0
    
    def test_critical_for_extreme_errors(self):
        """Should be CRITICAL for 100x+ errors."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "logs",
            "actual_rows": 1_000_000,
            "plan_rows": 100,  # 10000x underestimate
        }])
        
        rule = StaleStatistics()
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestTableBloat:
    """Tests for table bloat detection."""
    
    def test_detects_high_removal_ratio(self):
        """Should detect when many rows removed by filter."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "events",
            "actual_rows": 100,
            "plan_rows": 50_000,
            "rows_removed_by_filter": 50_000,  # 500x more removed than returned
        }])
        
        rule = TableBloat()
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].rule_id == "TABLE_BLOAT"
        assert "VACUUM" in findings[0].suggestion
    
    def test_ignores_low_removal_ratio(self):
        """Should not flag low removal ratios."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "users",
            "actual_rows": 1_000,
            "plan_rows": 1_000,
            "rows_removed_by_filter": 500,  # Only 0.5x
        }])
        
        rule = TableBloat()
        findings = rule.analyze(explain)
        
        assert len(findings) == 0
    
    def test_critical_for_severe_bloat(self):
        """Should be CRITICAL for severe bloat indicators."""
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "old_data",
            "actual_rows": 10,
            "plan_rows": 200_000,
            "rows_removed_by_filter": 200_000,  # 20000x
        }])
        
        rule = TableBloat()
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestFixCommand:
    """Integration tests for the fix command output."""
    
    def test_fix_outputs_sql(self):
        """Verify fix command would produce SQL."""
        # This is more of a smoke test - the actual CLI test
        # would be in integration tests
        explain = make_explain([{
            "node_type": "Seq Scan",
            "relation_name": "orders",
            "actual_rows": 250_000,
            "plan_rows": 250_000,
            "filter": "(customer_id = 999)",
        }])
        
        rule = ForeignKeyWithoutIndex()
        findings = rule.analyze(explain)
        
        assert len(findings) > 0
        assert findings[0].suggestion is not None
        assert "CREATE INDEX" in findings[0].suggestion
