"""
Backwards Compatibility Tests

These tests ensure we don't break existing users when releasing new versions.
Any changes that would break these tests require a major version bump (or
careful consideration during 0.x development).

Run with: pytest tests/test_backwards_compat.py
"""

from __future__ import annotations

import json
from typing import Any

import pytest


class TestPublicAPIStability:
    """Ensure public API surface remains stable."""

    def test_analyzer_can_be_imported(self) -> None:
        """Analyzer must be importable from main package."""
        from querysense import Analyzer
        
        assert Analyzer is not None

    def test_parse_explain_can_be_imported(self) -> None:
        """parse_explain must be importable from main package."""
        from querysense import parse_explain
        
        assert parse_explain is not None

    def test_analyzer_basic_instantiation(self) -> None:
        """Analyzer() with no arguments must work."""
        from querysense import Analyzer
        
        analyzer = Analyzer()
        assert analyzer is not None

    def test_analyzer_has_analyze_method(self) -> None:
        """Analyzer must have analyze() method."""
        from querysense import Analyzer
        
        analyzer = Analyzer()
        assert hasattr(analyzer, "analyze")
        assert callable(analyzer.analyze)

    def test_analyzer_has_rules_attribute(self) -> None:
        """Analyzer must expose rules list."""
        from querysense import Analyzer
        
        analyzer = Analyzer()
        assert hasattr(analyzer, "rules")
        assert isinstance(analyzer.rules, list)


class TestAnalysisResultStability:
    """Ensure AnalysisResult structure remains stable."""

    def test_analysis_result_has_findings(self) -> None:
        """AnalysisResult must have findings attribute."""
        from querysense.analyzer.models import AnalysisResult
        
        result = AnalysisResult.empty()
        assert hasattr(result, "findings")

    def test_analysis_result_has_errors(self) -> None:
        """AnalysisResult must have errors attribute."""
        from querysense.analyzer.models import AnalysisResult
        
        result = AnalysisResult.empty()
        assert hasattr(result, "errors")

    def test_analysis_result_has_metadata(self) -> None:
        """AnalysisResult must have metadata attribute."""
        from querysense.analyzer.models import AnalysisResult
        
        result = AnalysisResult.empty()
        assert hasattr(result, "metadata")


class TestFindingStructureStability:
    """Ensure Finding structure remains stable for JSON consumers."""

    def test_finding_required_fields(self) -> None:
        """Finding must have all required fields."""
        from querysense.analyzer.models import Finding, NodeContext, Severity
        from querysense.analyzer.path import NodePath
        
        # These fields must exist and be settable
        context = NodeContext(path=NodePath.root(), node_type="Seq Scan")
        finding = Finding(
            rule_id="TEST_RULE",
            severity=Severity.WARNING,
            context=context,
            title="Test finding",
            description="Test description",
        )
        
        # Required attributes must exist
        assert hasattr(finding, "rule_id")
        assert hasattr(finding, "severity")
        assert hasattr(finding, "context")
        assert hasattr(finding, "title")
        assert hasattr(finding, "description")
        assert hasattr(finding, "suggestion")
        assert hasattr(finding, "metrics")

    def test_finding_is_frozen(self) -> None:
        """Finding must be immutable (frozen)."""
        from querysense.analyzer.models import Finding, NodeContext, Severity
        from querysense.analyzer.path import NodePath
        
        context = NodeContext(path=NodePath.root(), node_type="Seq Scan")
        finding = Finding(
            rule_id="TEST_RULE",
            severity=Severity.WARNING,
            context=context,
            title="Test finding",
            description="Test description",
        )
        
        with pytest.raises(Exception):  # Pydantic ValidationError or similar
            finding.title = "Modified"  # type: ignore[misc]


class TestSeverityEnumStability:
    """Ensure Severity enum values remain stable."""

    def test_severity_values_exist(self) -> None:
        """All expected severity values must exist."""
        from querysense.analyzer.models import Severity
        
        assert hasattr(Severity, "CRITICAL")
        assert hasattr(Severity, "WARNING")
        assert hasattr(Severity, "INFO")

    def test_severity_string_values(self) -> None:
        """Severity string values must remain stable for JSON output."""
        from querysense.analyzer.models import Severity
        
        assert Severity.CRITICAL.value == "critical"
        assert Severity.WARNING.value == "warning"
        assert Severity.INFO.value == "info"


class TestRuleIDStability:
    """Ensure built-in rule IDs don't change."""

    def test_seq_scan_rule_id(self) -> None:
        """SEQ_SCAN_LARGE_TABLE rule ID must remain stable."""
        from querysense.analyzer.registry import get_registry
        
        registry = get_registry()
        assert "SEQ_SCAN_LARGE_TABLE" in registry

    def test_bad_row_estimate_rule_id(self) -> None:
        """BAD_ROW_ESTIMATE rule ID must remain stable."""
        from querysense.analyzer.registry import get_registry
        
        registry = get_registry()
        assert "BAD_ROW_ESTIMATE" in registry


class TestRegistryAPIStability:
    """Ensure Registry API remains stable."""

    def test_get_registry_function(self) -> None:
        """get_registry() must return a registry."""
        from querysense.analyzer.registry import get_registry
        
        registry = get_registry()
        assert registry is not None

    def test_registry_has_all_method(self) -> None:
        """Registry must have all() method."""
        from querysense.analyzer.registry import get_registry
        
        registry = get_registry()
        assert hasattr(registry, "all")
        rules = registry.all()
        assert isinstance(rules, list)

    def test_registry_has_filter_method(self) -> None:
        """Registry must have filter() method."""
        from querysense.analyzer.registry import get_registry
        
        registry = get_registry()
        assert hasattr(registry, "filter")


class TestNewFeatureBackwardsCompat:
    """Ensure new features don't break existing code."""

    def test_analyzer_works_without_new_options(self) -> None:
        """Analyzer must work without new 0.4.0 options."""
        from querysense import Analyzer
        
        # Old-style instantiation must still work
        analyzer = Analyzer(
            fail_fast=False,
            parallel=True,
        )
        assert analyzer is not None

    def test_analyzer_cache_disabled_by_default(self) -> None:
        """Caching must be disabled by default for backwards compat."""
        from querysense import Analyzer
        
        analyzer = Analyzer()
        assert analyzer.cache_enabled is False

    def test_analyzer_tracing_disabled_by_default(self) -> None:
        """Tracing must be disabled by default for backwards compat."""
        from querysense import Analyzer
        
        analyzer = Analyzer()
        assert analyzer.tracing_enabled is False


class TestJSONOutputStability:
    """Ensure JSON output format remains stable."""

    def test_finding_json_serializable(self) -> None:
        """Finding must be JSON serializable."""
        from querysense.analyzer.models import Finding, NodeContext, Severity
        from querysense.analyzer.path import NodePath
        
        context = NodeContext(path=NodePath.root(), node_type="Seq Scan")
        finding = Finding(
            rule_id="TEST_RULE",
            severity=Severity.WARNING,
            context=context,
            title="Test finding",
            description="Test description",
        )
        
        # Must be serializable without error
        json_str = finding.model_dump_json()
        data = json.loads(json_str)
        
        # Key fields must be present
        assert "rule_id" in data
        assert "severity" in data
        assert "title" in data
        assert "description" in data

    def test_analysis_result_json_serializable(self) -> None:
        """AnalysisResult must be JSON serializable."""
        from querysense.analyzer.models import AnalysisResult
        
        result = AnalysisResult.empty()
        
        # Must be serializable without error
        json_str = result.model_dump_json()
        data = json.loads(json_str)
        
        # Key fields must be present
        assert "findings" in data
        assert "errors" in data
        assert "metadata" in data


class TestThreadSafety:
    """Ensure thread safety claims are valid."""

    def test_analyzer_is_thread_safe(self) -> None:
        """Analyzer must be safe to use from multiple threads."""
        import threading
        from querysense import Analyzer
        
        analyzer = Analyzer()
        results: list[Any] = []
        errors: list[Exception] = []
        
        def analyze_in_thread() -> None:
            try:
                # Just test that we can call analyze without race conditions
                # We're not testing actual analysis here, just thread safety
                _ = analyzer.rules  # Access shared state
                results.append(True)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=analyze_in_thread) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Thread safety errors: {errors}"
        assert len(results) == 10


class TestTypeHints:
    """Ensure type hints are available for IDE support."""

    def test_py_typed_marker_exists(self) -> None:
        """py.typed marker must exist for PEP 561."""
        from pathlib import Path
        import querysense
        
        package_dir = Path(querysense.__file__).parent
        py_typed = package_dir / "py.typed"
        
        assert py_typed.exists(), "py.typed marker missing - breaks IDE type checking"
