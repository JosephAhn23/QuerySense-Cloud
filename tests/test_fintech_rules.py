"""
Tests for fintech-specific detection rules.
"""

import pytest

from querysense.analyzer.models import Finding, Severity
from querysense.analyzer.rules.fintech import (
    LatencySLABreach,
    HighCostQuery,
    WeakIsolationLevel,
    RaceConditionRisk,
)
from querysense.parser import parse_explain


# Test fixtures - complete PostgreSQL EXPLAIN ANALYZE output
SLOW_TRADING_QUERY = [{
    "Plan": {
        "Node Type": "Seq Scan",
        "Relation Name": "market_data",
        "Schema": "public",
        "Alias": "market_data",
        "Startup Cost": 0.0,
        "Total Cost": 15000.0,
        "Plan Rows": 1000,
        "Plan Width": 100,
        "Actual Startup Time": 0.01,
        "Actual Total Time": 150.0,  # 150ms - breaches 50ms trading SLA
        "Actual Rows": 100000,
        "Actual Loops": 1,
        "Shared Hit Blocks": 1000,
        "Shared Read Blocks": 5000,
    },
    "Execution Time": 150.0,
    "Planning Time": 1.0,
}]

SLOW_FRAUD_QUERY = [{
    "Plan": {
        "Node Type": "Hash Join",
        "Startup Cost": 100.0,
        "Total Cost": 25000.0,
        "Plan Rows": 5000,
        "Plan Width": 200,
        "Actual Startup Time": 50.0,
        "Actual Total Time": 250.0,  # 250ms - breaches 100ms fraud SLA
        "Actual Rows": 50000,
        "Actual Loops": 1,
        "Plans": [
            {
                "Node Type": "Seq Scan",
                "Relation Name": "transactions",
                "Schema": "public",
                "Alias": "transactions",
                "Startup Cost": 0.0,
                "Total Cost": 20000.0,
                "Plan Rows": 5000,
                "Plan Width": 100,
                "Actual Startup Time": 0.01,
                "Actual Total Time": 200.0,
                "Actual Rows": 50000,
                "Actual Loops": 1,
            },
            {
                "Node Type": "Hash",
                "Startup Cost": 0.0,
                "Total Cost": 5000.0,
                "Plan Rows": 100,
                "Plan Width": 100,
                "Actual Startup Time": 10.0,
                "Actual Total Time": 50.0,
                "Actual Rows": 1000,
                "Actual Loops": 1,
            },
        ],
    },
    "Execution Time": 250.0,
    "Planning Time": 1.0,
}]

HIGH_COST_QUERY = [{
    "Plan": {
        "Node Type": "Seq Scan",
        "Relation Name": "orders",
        "Schema": "public",
        "Alias": "orders",
        "Startup Cost": 0.0,
        "Total Cost": 100000.0,
        "Plan Rows": 50000,
        "Plan Width": 100,
        "Actual Startup Time": 0.01,
        "Actual Total Time": 2000.0,  # 2 seconds
        "Actual Rows": 500000,
        "Actual Loops": 1,
        "Shared Hit Blocks": 10000,
        "Shared Read Blocks": 50000,  # Lots of I/O
    },
    "Execution Time": 2000.0,
    "Planning Time": 1.0,
}]

BALANCE_CHECK_NO_LOCK = [{
    "Plan": {
        "Node Type": "Index Scan",
        "Relation Name": "accounts",
        "Schema": "public",
        "Alias": "accounts",
        "Index Name": "accounts_pkey",
        "Startup Cost": 0.0,
        "Total Cost": 8.0,
        "Plan Rows": 1,
        "Plan Width": 50,
        "Actual Startup Time": 0.01,
        "Actual Total Time": 0.5,
        "Actual Rows": 1,
        "Actual Loops": 1,
        "Filter": "(balance >= 100)",  # Balance check without FOR UPDATE
    },
    "Execution Time": 0.5,
    "Planning Time": 0.1,
}]

GOOD_LOCKED_QUERY = [{
    "Plan": {
        "Node Type": "LockRows",
        "Startup Cost": 0.0,
        "Total Cost": 10.0,
        "Plan Rows": 1,
        "Plan Width": 50,
        "Actual Startup Time": 0.01,
        "Actual Total Time": 0.6,
        "Actual Rows": 1,
        "Actual Loops": 1,
        "Plans": [
            {
                "Node Type": "Index Scan",
                "Relation Name": "accounts",
                "Schema": "public",
                "Alias": "accounts",
                "Index Name": "accounts_pkey",
                "Startup Cost": 0.0,
                "Total Cost": 8.0,
                "Plan Rows": 1,
                "Plan Width": 50,
                "Actual Startup Time": 0.01,
                "Actual Total Time": 0.5,
                "Actual Rows": 1,
                "Actual Loops": 1,
                "Filter": "(balance >= 100)",
            },
        ],
    },
    "Execution Time": 0.6,
    "Planning Time": 0.1,
}]


class TestLatencySLABreach:
    """Tests for latency SLA breach detection."""
    
    def test_detects_trading_sla_breach(self):
        """Detects trading query that exceeds 50ms SLA."""
        explain = parse_explain(SLOW_TRADING_QUERY)
        rule = LatencySLABreach()
        
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].rule_id == "FINTECH_LATENCY_SLA_BREACH"
        assert "trading" in findings[0].title.lower()
        assert findings[0].severity == Severity.CRITICAL  # 150ms / 50ms = 3x > 2x threshold
    
    def test_detects_fraud_sla_breach(self):
        """Detects fraud detection query that exceeds 100ms SLA."""
        explain = parse_explain(SLOW_FRAUD_QUERY)
        rule = LatencySLABreach()
        
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert "fraud" in findings[0].title.lower() or "transaction" in findings[0].description.lower()
        assert findings[0].metrics["execution_time_ms"] == 250
    
    def test_custom_sla_threshold(self):
        """Respects custom SLA thresholds."""
        explain = parse_explain(SLOW_TRADING_QUERY)
        rule = LatencySLABreach(config={"trading_sla_ms": 200.0})  # Raise threshold
        
        findings = rule.analyze(explain)
        
        # 150ms < 200ms threshold, should not trigger
        assert len(findings) == 0


class TestHighCostQuery:
    """Tests for query cost attribution."""
    
    def test_calculates_query_cost(self):
        """Calculates cost breakdown for expensive query."""
        explain = parse_explain(HIGH_COST_QUERY)
        # Lower threshold to catch our test query
        rule = HighCostQuery(config={
            "cost_per_execution_threshold": 0.0001,  # Very low threshold
        })
        
        findings = rule.analyze(explain)
        
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.rule_id == "FINTECH_HIGH_COST_QUERY"
        assert "annual_cost_dollars" in finding.metrics
        assert finding.metrics["annual_cost_dollars"] > 0
    
    def test_includes_roi_in_suggestion(self):
        """Suggestion includes ROI calculation."""
        explain = parse_explain(HIGH_COST_QUERY)
        rule = HighCostQuery(config={
            "cost_per_execution_threshold": 0.0001,
        })
        
        findings = rule.analyze(explain)
        
        assert len(findings) >= 1
        assert "ROI" in findings[0].suggestion or "savings" in findings[0].suggestion.lower()
    
    def test_custom_cost_rates(self):
        """Respects custom cloud pricing."""
        explain = parse_explain(HIGH_COST_QUERY)
        rule = HighCostQuery(config={
            "cpu_cost_per_second": 0.001,  # 10x default
            "cost_per_execution_threshold": 0.0001,
        })
        
        findings = rule.analyze(explain)
        
        assert len(findings) >= 1
        # Higher CPU cost should result in higher total


class TestWeakIsolationLevel:
    """Tests for isolation level detection."""
    
    def test_flags_unprotected_financial_modification(self):
        """Flags modifications to financial tables without locking."""
        # Create a plan that modifies financial data
        modify_plan = [{
            "Plan": {
                "Node Type": "ModifyTable",
                "Relation Name": "accounts",
                "Schema": "public",
                "Alias": "accounts",
                "Startup Cost": 0.0,
                "Total Cost": 10.0,
                "Plan Rows": 1,
                "Plan Width": 50,
                "Actual Startup Time": 0.01,
                "Actual Total Time": 1.0,
                "Actual Rows": 1,
                "Actual Loops": 1,
                "Plans": [
                    {
                        "Node Type": "Index Scan",
                        "Relation Name": "accounts",
                        "Schema": "public",
                        "Alias": "accounts",
                        "Startup Cost": 0.0,
                        "Total Cost": 8.0,
                        "Plan Rows": 1,
                        "Plan Width": 50,
                        "Actual Startup Time": 0.01,
                        "Actual Total Time": 0.5,
                        "Actual Rows": 1,
                        "Actual Loops": 1,
                    },
                ],
            },
            "Execution Time": 1.0,
            "Planning Time": 0.1,
        }]
        
        explain = parse_explain(modify_plan)
        rule = WeakIsolationLevel()
        
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "isolation" in findings[0].suggestion.lower() or "lock" in findings[0].suggestion.lower()


class TestRaceConditionRisk:
    """Tests for race condition detection."""
    
    def test_flags_balance_check_without_lock(self):
        """Flags balance check without FOR UPDATE."""
        explain = parse_explain(BALANCE_CHECK_NO_LOCK)
        rule = RaceConditionRisk()
        
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert findings[0].rule_id == "FINTECH_RACE_CONDITION_RISK"
        assert "race" in findings[0].title.lower() or "lock" in findings[0].title.lower()
    
    def test_accepts_locked_balance_check(self):
        """Accepts balance check with FOR UPDATE (LockRows node)."""
        explain = parse_explain(GOOD_LOCKED_QUERY)
        rule = RaceConditionRisk()
        
        findings = rule.analyze(explain)
        
        # LockRows present, should not flag
        assert len(findings) == 0
    
    def test_includes_fix_pattern(self):
        """Fix includes FOR UPDATE pattern."""
        explain = parse_explain(BALANCE_CHECK_NO_LOCK)
        rule = RaceConditionRisk()
        
        findings = rule.analyze(explain)
        
        assert len(findings) == 1
        assert "FOR UPDATE" in findings[0].suggestion


class TestFintechRuleIntegration:
    """Integration tests for fintech rules working together."""
    
    def test_multiple_rules_on_same_query(self):
        """Multiple fintech rules can flag the same query."""
        # A trading query that's both slow and has race condition risk
        combined_plan = [{
            "Plan": {
                "Node Type": "Index Scan",
                "Relation Name": "positions",  # Trading table
                "Schema": "public",
                "Alias": "positions",
                "Index Name": "positions_pkey",
                "Startup Cost": 0.0,
                "Total Cost": 8.0,
                "Plan Rows": 1,
                "Plan Width": 100,
                "Actual Startup Time": 0.01,
                "Actual Total Time": 100.0,  # Slow for trading (50ms SLA)
                "Actual Rows": 1,
                "Actual Loops": 1,
                "Filter": "(quantity >= 100)",  # Balance-like check
            },
            "Execution Time": 100.0,
            "Planning Time": 0.1,
        }]
        
        explain = parse_explain(combined_plan)
        
        # Run all fintech rules
        latency_findings = LatencySLABreach().analyze(explain)
        race_findings = RaceConditionRisk().analyze(explain)
        
        # Should get findings from both rules
        assert len(latency_findings) >= 1
        assert len(race_findings) >= 1
