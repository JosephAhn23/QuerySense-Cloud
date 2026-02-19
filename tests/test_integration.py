"""
Integration tests for the QuerySense pipeline.

These tests verify the full flow from parsing to analysis works together.
Unlike unit tests, these catch issues in module boundaries and data flow.

Test categories:
- test_parse_*: Parser with resource limits
- test_analyze_*: Parser → Analyzer flow
- test_full_*: Full pipeline (stubbed explainer)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from querysense.analyzer import (
    Analyzer,
    AnalysisResult,
    ExecutionMetadata,
    Finding,
    NodeContext,
    NodePath,
    RuleError,
    RulePhase,
    RuleRegistry,
    Severity,
    get_registry,
    reset_registry,
)
from querysense.analyzer.rules import SeqScanLargeTable
from querysense.parser import parse_explain, ParseError, ParserConfig


def make_finding(
    rule_id: str = "TEST_RULE",
    severity: Severity = Severity.WARNING,
    title: str = "Test finding",
    description: str = "Test description",
    node_type: str = "Seq Scan",
    relation_name: str | None = "test_table",
    **metrics: int | float,
) -> Finding:
    """Helper to create findings with NodeContext for tests."""
    context = NodeContext(
        path=NodePath.root(),
        node_type=node_type,
        relation_name=relation_name,
    )
    return Finding(
        rule_id=rule_id,
        severity=severity,
        context=context,
        title=title,
        description=description,
        metrics=dict(metrics) if metrics else {},
    )


FIXTURES_DIR = Path(__file__).parent / "fixtures"


# =============================================================================
# Parser Resource Limit Tests
# =============================================================================

class TestParserResourceLimits:
    """Test that resource limits prevent pathological inputs."""
    
    def test_rejects_oversized_file(self, tmp_path: Path) -> None:
        """Files exceeding max_file_size_mb are rejected before loading."""
        # Create a file that exceeds the limit
        large_file = tmp_path / "large.json"
        
        # 1KB of content, but we'll set limit to 0.0001MB (100 bytes)
        content = json.dumps([{"Plan": {"Node Type": "Result"}}] + [" "] * 1000)
        large_file.write_text(content)
        
        config = ParserConfig(max_file_size_mb=0.0001)
        
        with pytest.raises(ParseError) as exc_info:
            parse_explain(large_file, config=config)
        
        assert exc_info.value.source == "resource_limit"
        assert "too large" in exc_info.value.message.lower()
    
    def test_rejects_deeply_nested_plan(self) -> None:
        """Plans exceeding max_depth are rejected."""
        # Build a deeply nested plan
        def make_nested(depth: int) -> dict:
            if depth == 0:
                return {
                    "Node Type": "Result",
                    "Startup Cost": 0.0,
                    "Total Cost": 0.01,
                    "Plan Rows": 1,
                    "Plan Width": 0,
                }
            return {
                "Node Type": "Append",
                "Startup Cost": 0.0,
                "Total Cost": float(depth),
                "Plan Rows": 1,
                "Plan Width": 0,
                "Plans": [make_nested(depth - 1)],
            }
        
        deep_plan = [{"Plan": make_nested(50), "Planning Time": 0.1}]
        
        config = ParserConfig(max_depth=10)
        
        with pytest.raises(ParseError) as exc_info:
            parse_explain(deep_plan, config=config)
        
        assert exc_info.value.source == "resource_limit"
        assert "deeply nested" in exc_info.value.message.lower()
    
    def test_rejects_too_many_nodes(self) -> None:
        """Plans exceeding max_nodes are rejected."""
        # Build a wide plan with many siblings
        plan = {
            "Node Type": "Append",
            "Startup Cost": 0.0,
            "Total Cost": 100.0,
            "Plan Rows": 100,
            "Plan Width": 10,
            "Plans": [
                {
                    "Node Type": "Result",
                    "Startup Cost": 0.0,
                    "Total Cost": 0.01,
                    "Plan Rows": 1,
                    "Plan Width": 0,
                }
                for _ in range(50)  # 51 total nodes (1 parent + 50 children)
            ],
        }
        
        data = [{"Plan": plan, "Planning Time": 0.1}]
        
        config = ParserConfig(max_nodes=10)
        
        with pytest.raises(ParseError) as exc_info:
            parse_explain(data, config=config)
        
        assert exc_info.value.source == "resource_limit"
        assert "too large" in exc_info.value.message.lower()
    
    def test_accepts_within_limits(self) -> None:
        """Plans within all limits parse successfully."""
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        
        # Very generous limits
        config = ParserConfig(
            max_file_size_mb=100,
            max_nodes=50_000,
            max_depth=100,
        )
        
        output = parse_explain(fixture_path, config=config)
        assert output.plan.node_type == "Index Scan"


# =============================================================================
# Analyzer Integration Tests
# =============================================================================

class TestAnalyzerIntegration:
    """Test parser → analyzer flow."""
    
    def test_seq_scan_rule_finds_large_scan(self) -> None:
        """SeqScanLargeTable detects the fixture's sequential scan."""
        fixture_path = FIXTURES_DIR / "sequential_scan_large_table.json"
        
        # Parse the fixture
        output = parse_explain(fixture_path)
        
        # Run the rule
        rule = SeqScanLargeTable(threshold_rows=1000)
        findings = rule.analyze(output)
        
        # Should find exactly one issue
        assert len(findings) == 1
        finding = findings[0]
        
        # Verify finding structure
        assert finding.rule_id == "SEQ_SCAN_LARGE_TABLE"
        assert finding.severity == Severity.WARNING
        assert "orders" in finding.title.lower()
        assert finding.metrics["rows_scanned"] > 1000
    
    def test_seq_scan_rule_ignores_small_tables(self) -> None:
        """SeqScanLargeTable doesn't fire on small scans."""
        # Index scan fixture has no seq scans
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        
        output = parse_explain(fixture_path)
        rule = SeqScanLargeTable(threshold_rows=1000)
        findings = rule.analyze(output)
        
        assert len(findings) == 0
    
    def test_findings_are_sortable(self) -> None:
        """Findings can be sorted deterministically."""
        f1 = make_finding(rule_id="RULE_A", severity=Severity.WARNING, title="Warning A")
        f2 = make_finding(rule_id="RULE_B", severity=Severity.CRITICAL, title="Critical B")
        f3 = make_finding(rule_id="RULE_A", severity=Severity.INFO, title="Info A")
        
        sorted_findings = sorted([f1, f2, f3])
        
        # CRITICAL first, then WARNING, then INFO
        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[1].severity == Severity.WARNING
        assert sorted_findings[2].severity == Severity.INFO
    
    def test_findings_are_hashable(self) -> None:
        """Findings can be used in sets for deduplication."""
        f1 = make_finding(rule_id="RULE_A", title="Title", rows=100)
        f2 = make_finding(rule_id="RULE_A", title="Title", rows=100)  # Same content
        f3 = make_finding(rule_id="RULE_B", title="Title", rows=100)  # Different rule
        
        unique = {f1, f2, f3}
        assert len(unique) == 2  # f1 and f2 are duplicates
    
    def test_finding_cache_key_deterministic(self) -> None:
        """Cache keys are stable across runs."""
        f1 = make_finding(rule_id="RULE_A", title="Title", a=1, b=2)
        f2 = make_finding(rule_id="RULE_A", title="Title", b=2, a=1)  # Same metrics, different order
        
        key1 = f1.cache_key("claude-3", "1.0.0")
        key2 = f2.cache_key("claude-3", "1.0.0")
        
        # Same content = same key
        assert key1 == key2
        
        # Different model = different key
        key3 = f1.cache_key("gpt-4", "1.0.0")
        assert key1 != key3
    
    def test_node_path_navigation(self) -> None:
        """NodePath provides correct tree navigation."""
        root = NodePath.root()
        assert str(root) == "Plan"
        assert root.is_root
        assert root.depth == 0
        
        child = root.child(0)
        assert str(child) == "Plan → Plans[0]"
        assert not child.is_root
        assert child.depth == 1
        
        grandchild = child.child(2)
        assert str(grandchild) == "Plan → Plans[0] → Plans[2]"
        assert grandchild.depth == 2
        
        # Parent navigation
        assert grandchild.parent() == child
        assert child.parent() == root
        assert root.parent() is None


# =============================================================================
# Full Pipeline Tests (Stubbed Explainer)
# =============================================================================

class TestFullPipeline:
    """
    Test the complete pipeline from input to output.
    
    These tests use the Analyzer orchestrator and a stubbed explainer
    since we don't want to call the real LLM API in tests.
    """
    
    def test_analyze_complex_plan(self) -> None:
        """Analyze a plan with multiple issues using Analyzer orchestrator."""
        fixture_path = FIXTURES_DIR / "bad_estimate.json"
        
        # Parse
        output = parse_explain(fixture_path)
        
        # Use the Analyzer orchestrator
        analyzer = Analyzer(rules=[SeqScanLargeTable(threshold_rows=100)])
        result = analyzer.analyze(output)
        
        # Verify structure
        assert result.node_count > 0
        assert len(result.findings) >= 1  # Should find the seq scans
        assert result.rules_run == 1
        assert result.rules_failed == 0
        
        # Verify serialization works
        result_dict = result.model_dump()
        assert "findings" in result_dict
        assert "metadata" in result_dict
        assert "node_count" in result_dict["metadata"]
        assert "rules_run" in result_dict["metadata"]
    
    def test_empty_findings_for_optimized_query(self) -> None:
        """Well-optimized queries produce no findings."""
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        
        output = parse_explain(fixture_path)
        
        # Use the Analyzer orchestrator
        analyzer = Analyzer(rules=[SeqScanLargeTable(threshold_rows=100)])
        result = analyzer.analyze(output)
        
        assert len(result.findings) == 0
        assert not result.has_critical
        assert not result.has_warnings
        assert not result.has_errors
    
    def test_analyzer_handles_rule_errors_gracefully(self) -> None:
        """Analyzer continues when a rule fails."""
        from querysense.analyzer.rules.base import Rule
        
        class BrokenRule(Rule):
            rule_id = "BROKEN_RULE"
            version = "1.0.0"
            severity = Severity.WARNING
            description = "A rule that always crashes"
            
            def analyze(self, explain, prior_findings=None):
                raise ValueError("Intentional test failure")
        
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        output = parse_explain(fixture_path)
        
        # Analyzer with broken rule + working rule
        analyzer = Analyzer(
            rules=[BrokenRule(), SeqScanLargeTable()],
            fail_fast=False,
        )
        result = analyzer.analyze(output)
        
        # Should have one error, but continue
        assert result.rules_failed == 1
        assert result.has_errors
        assert len(result.errors) == 1
        
        # Errors are strings now (simplified)
        error = result.errors[0]
        assert "Intentional test failure" in error
    
    def test_analyzer_fail_fast_mode(self) -> None:
        """Analyzer stops on first error when fail_fast=True."""
        from querysense.analyzer.rules.base import Rule
        
        class BrokenRule(Rule):
            rule_id = "BROKEN_RULE"
            version = "1.0.0"
            severity = Severity.WARNING
            description = "A rule that always crashes"
            
            def analyze(self, explain, prior_findings=None):
                raise ValueError("Intentional test failure")
        
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        output = parse_explain(fixture_path)
        
        analyzer = Analyzer(rules=[BrokenRule()], fail_fast=True)
        
        with pytest.raises(RuleError) as exc_info:
            analyzer.analyze(output)
        
        assert exc_info.value.rule_id == "BROKEN_RULE"
    
    def test_analyzer_summary(self) -> None:
        """AnalysisResult provides useful summary."""
        fixture_path = FIXTURES_DIR / "sequential_scan_large_table.json"
        output = parse_explain(fixture_path)
        
        analyzer = Analyzer(rules=[SeqScanLargeTable(threshold_rows=100)])
        result = analyzer.analyze(output)
        
        summary = result.summary()
        assert "critical" in summary
        assert "warning" in summary
        assert "info" in summary
        assert "errors" in summary
        assert "total" in summary
        assert "success_rate" in summary
        assert summary["errors"] == 0
        assert summary["success_rate"] == 1.0
    
    def test_execution_metadata_separation(self) -> None:
        """ExecutionMetadata is properly separated from findings."""
        fixture_path = FIXTURES_DIR / "sequential_scan_large_table.json"
        output = parse_explain(fixture_path)
        
        analyzer = Analyzer(rules=[SeqScanLargeTable(threshold_rows=100)])
        result = analyzer.analyze(output)
        
        # Metadata is accessible
        assert isinstance(result.metadata, ExecutionMetadata)
        assert result.metadata.node_count > 0
        assert result.metadata.rules_run == 1
        assert result.metadata.rules_failed == 0
        assert result.metadata.success_rate == 1.0
        
        # Convenience properties still work
        assert result.node_count == result.metadata.node_count
        assert result.rules_run == result.metadata.rules_run


# =============================================================================
# Contract Tests for Rules
# =============================================================================

class TestRuleContract:
    """Verify all rules follow the expected contract."""
    
    def test_seq_scan_rule_has_required_attributes(self) -> None:
        """Rules have all required class attributes."""
        rule = SeqScanLargeTable()
        
        assert hasattr(rule, "rule_id")
        assert hasattr(rule, "version")
        assert hasattr(rule, "severity")
        assert hasattr(rule, "description")
        assert hasattr(rule, "analyze")
        
        # Verify attribute types
        assert isinstance(rule.rule_id, str)
        assert isinstance(rule.version, str)
        assert isinstance(rule.severity, Severity)
        assert isinstance(rule.description, str)
    
    def test_rule_id_is_upper_snake_case(self) -> None:
        """Rule IDs follow naming convention."""
        rule = SeqScanLargeTable()
        
        assert rule.rule_id.isupper() or "_" in rule.rule_id
        assert " " not in rule.rule_id
    
    def test_analyze_returns_list_of_findings(self) -> None:
        """analyze() always returns a list of Finding objects."""
        fixture_path = FIXTURES_DIR / "sequential_scan_large_table.json"
        output = parse_explain(fixture_path)
        
        rule = SeqScanLargeTable(threshold_rows=100)  # Low threshold (minimum allowed)
        result = rule.analyze(output)
        
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, Finding)
    
    def test_analyze_returns_empty_list_not_none(self) -> None:
        """analyze() returns empty list, never None."""
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        output = parse_explain(fixture_path)
        
        rule = SeqScanLargeTable()
        result = rule.analyze(output)
        
        assert result is not None
        assert isinstance(result, list)
        assert len(result) == 0


# =============================================================================
# Rule Registry Tests
# =============================================================================

class TestRuleRegistry:
    """Test the rule registry system."""
    
    def test_seq_scan_is_registered(self) -> None:
        """SeqScanLargeTable is registered in global registry."""
        registry = get_registry()
        
        assert "SEQ_SCAN_LARGE_TABLE" in registry
        assert registry.get("SEQ_SCAN_LARGE_TABLE") is SeqScanLargeTable
    
    def test_registry_filter_include(self) -> None:
        """Registry can filter to include only specific rules."""
        registry = get_registry()
        
        filtered = registry.filter(include={"SEQ_SCAN_LARGE_TABLE"})
        assert len(filtered) == 1
        assert filtered[0].rule_id == "SEQ_SCAN_LARGE_TABLE"
        
        # Include non-existent rule returns empty
        filtered = registry.filter(include={"NONEXISTENT"})
        assert len(filtered) == 0
    
    def test_registry_filter_exclude(self) -> None:
        """Registry can exclude specific rules."""
        registry = get_registry()
        
        all_rules = registry.all()
        filtered = registry.filter(exclude={"SEQ_SCAN_LARGE_TABLE"})
        
        assert len(filtered) == len(all_rules) - 1
        assert not any(r.rule_id == "SEQ_SCAN_LARGE_TABLE" for r in filtered)
    
    def test_analyzer_uses_registry(self) -> None:
        """Analyzer uses registry when no rules are provided."""
        # Don't provide rules - should use registry
        analyzer = Analyzer()
        
        assert len(analyzer.rules) >= 1
        assert any(r.rule_id == "SEQ_SCAN_LARGE_TABLE" for r in analyzer.rules)
    
    def test_analyzer_include_rules(self) -> None:
        """Analyzer respects include_rules filter."""
        analyzer = Analyzer(include_rules={"SEQ_SCAN_LARGE_TABLE"})
        
        assert len(analyzer.rules) == 1
        assert analyzer.rules[0].rule_id == "SEQ_SCAN_LARGE_TABLE"
    
    def test_analyzer_exclude_rules(self) -> None:
        """Analyzer respects exclude_rules filter."""
        analyzer = Analyzer(exclude_rules={"SEQ_SCAN_LARGE_TABLE"})
        
        assert not any(r.rule_id == "SEQ_SCAN_LARGE_TABLE" for r in analyzer.rules)
    
    def test_fresh_registry_for_testing(self) -> None:
        """Can create fresh registry for isolated testing."""
        from querysense.analyzer.rules.base import Rule
        
        # Create isolated registry
        test_registry = RuleRegistry()
        
        class TestRule(Rule):
            rule_id = "TEST_RULE"
            version = "1.0.0"
            severity = Severity.INFO
            description = "Test rule"
            
            def analyze(self, explain, prior_findings=None):
                return []
        
        test_registry.register(TestRule)
        
        assert "TEST_RULE" in test_registry
        assert len(test_registry) == 1
        
        # Global registry is unaffected
        global_registry = get_registry()
        assert "TEST_RULE" not in global_registry
    
    def test_duplicate_registration_fails(self) -> None:
        """Cannot register two rules with same ID."""
        from querysense.analyzer.rules.base import Rule
        
        test_registry = RuleRegistry()
        
        class RuleA(Rule):
            rule_id = "DUPLICATE"
            version = "1.0.0"
            severity = Severity.INFO
            description = "First"
            def analyze(self, explain, prior_findings=None): return []
        
        class RuleB(Rule):
            rule_id = "DUPLICATE"
            version = "1.0.0"
            severity = Severity.INFO
            description = "Second"
            def analyze(self, explain, prior_findings=None): return []
        
        test_registry.register(RuleA)
        
        with pytest.raises(ValueError) as exc_info:
            test_registry.register(RuleB)
        
        assert "already registered" in str(exc_info.value)


# =============================================================================
# Parallel Execution Tests
# =============================================================================

class TestParallelExecution:
    """Test parallel rule execution."""
    
    def test_parallel_produces_same_results_as_sequential(self) -> None:
        """Parallel and sequential execution produce identical findings."""
        fixture_path = FIXTURES_DIR / "bad_estimate.json"
        output = parse_explain(fixture_path)
        
        # Run with parallel=True
        analyzer_parallel = Analyzer(
            rules=[SeqScanLargeTable(threshold_rows=100)],
            parallel=True,
        )
        result_parallel = analyzer_parallel.analyze(output)
        
        # Run with parallel=False
        analyzer_sequential = Analyzer(
            rules=[SeqScanLargeTable(threshold_rows=100)],
            parallel=False,
        )
        result_sequential = analyzer_sequential.analyze(output)
        
        # Results should be identical
        assert len(result_parallel.findings) == len(result_sequential.findings)
        assert result_parallel.metadata.rules_run == result_sequential.metadata.rules_run
        
        # Findings should match (sorted, so order is deterministic)
        for p, s in zip(result_parallel.findings, result_sequential.findings):
            assert p.rule_id == s.rule_id
            assert p.severity == s.severity
            assert p.context.path == s.context.path
    
    def test_parallel_handles_multiple_rules(self) -> None:
        """Parallel execution works with multiple rules."""
        from querysense.analyzer.rules.base import Rule
        
        class SlowRule(Rule):
            rule_id = "SLOW_RULE"
            version = "1.0.0"
            severity = Severity.INFO
            description = "A rule that takes some time"
            
            def analyze(self, explain, prior_findings=None):
                import time
                time.sleep(0.05)  # 50ms
                return [make_finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="Slow finding",
                    description="From slow rule",
                )]
        
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        output = parse_explain(fixture_path)
        
        # Create 3 copies of the slow rule with different IDs
        rules = []
        for i in range(3):
            class TempRule(SlowRule):
                rule_id = f"SLOW_RULE_{i}"
            rules.append(TempRule())
        
        analyzer = Analyzer(rules=rules, parallel=True, max_workers=3)
        result = analyzer.analyze(output)
        
        # All rules should complete
        assert result.metadata.rules_run == 3
        assert result.metadata.rules_failed == 0
        assert len(result.findings) == 3
    
    def test_parallel_handles_errors_gracefully(self) -> None:
        """Parallel execution handles rule errors without crashing."""
        from querysense.analyzer.rules.base import Rule
        
        class GoodRule(Rule):
            rule_id = "GOOD_RULE"
            version = "1.0.0"
            severity = Severity.INFO
            description = "Works fine"
            def analyze(self, explain, prior_findings=None):
                return [make_finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="Good finding",
                    description="All good",
                )]
        
        class BadRule(Rule):
            rule_id = "BAD_RULE"
            version = "1.0.0"
            severity = Severity.WARNING
            description = "Always crashes"
            def analyze(self, explain, prior_findings=None):
                raise RuntimeError("Intentional failure")
        
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        output = parse_explain(fixture_path)
        
        analyzer = Analyzer(
            rules=[GoodRule(), BadRule()],
            parallel=True,
            fail_fast=False,
        )
        result = analyzer.analyze(output)
        
        # Good rule succeeded
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "GOOD_RULE"
        
        # Bad rule error captured (errors are strings now)
        assert len(result.errors) == 1
        assert "Intentional failure" in result.errors[0]
        
        # Metadata reflects the failure
        assert result.metadata.rules_failed == 1
    
    def test_sequential_fallback_for_single_rule(self) -> None:
        """With only one rule, sequential is used even if parallel=True."""
        fixture_path = FIXTURES_DIR / "index_scan_good.json"
        output = parse_explain(fixture_path)
        
        # Even with parallel=True, one rule doesn't need threads
        analyzer = Analyzer(
            rules=[SeqScanLargeTable()],
            parallel=True,
        )
        result = analyzer.analyze(output)
        
        # Should still work
        assert result.metadata.rules_run == 1


# =============================================================================
# Rule Configuration Tests
# =============================================================================

class TestRuleConfiguration:
    """Test the rule configuration system."""
    
    def test_seq_scan_config_validation(self) -> None:
        """SeqScanConfig validates thresholds."""
        from querysense.analyzer.rules.seq_scan_large_table import SeqScanConfig
        
        # Valid config
        config = SeqScanConfig(threshold_rows=5000, critical_threshold_rows=50000)
        assert config.threshold_rows == 5000
        assert config.critical_threshold_rows == 50000
    
    def test_seq_scan_config_rejects_invalid_threshold(self) -> None:
        """SeqScanConfig rejects threshold below minimum."""
        from querysense.analyzer.rules.seq_scan_large_table import SeqScanConfig
        from pydantic import ValidationError
        
        with pytest.raises(ValidationError) as exc_info:
            SeqScanConfig(threshold_rows=50)  # Below minimum of 100
        
        assert "greater than or equal to 100" in str(exc_info.value)
    
    def test_seq_scan_config_rejects_inverted_thresholds(self) -> None:
        """SeqScanConfig rejects critical < warning threshold."""
        from querysense.analyzer.rules.seq_scan_large_table import SeqScanConfig
        from pydantic import ValidationError
        
        with pytest.raises(ValidationError) as exc_info:
            SeqScanConfig(threshold_rows=10000, critical_threshold_rows=5000)
        
        assert "must be greater than" in str(exc_info.value)
    
    def test_rule_uses_config(self) -> None:
        """Rule respects configured thresholds."""
        fixture_path = FIXTURES_DIR / "bad_estimate.json"
        output = parse_explain(fixture_path)
        
        # Low threshold should trigger
        rule_low = SeqScanLargeTable(threshold_rows=100)
        findings_low = rule_low.analyze(output)
        
        # High threshold should not trigger
        rule_high = SeqScanLargeTable(
            threshold_rows=10_000_000,
            critical_threshold=100_000_000,  # Must be > threshold_rows
        )
        findings_high = rule_high.analyze(output)
        
        # Verify thresholds are respected
        assert len(findings_low) >= len(findings_high)
    
    def test_rule_config_via_dict(self) -> None:
        """Rule can be configured via dict."""
        rule = SeqScanLargeTable(config={"threshold_rows": 500})
        
        # Access config through rule
        assert rule.config.threshold_rows == 500


# Note: Observability tests removed - module stripped for simplicity
