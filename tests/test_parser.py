"""
Tests for the EXPLAIN JSON parser.

Test philosophy:
- Test the happy path (valid EXPLAIN outputs parse correctly)
- Test edge cases (missing fields, unusual structures)
- Test error cases (invalid JSON, malformed EXPLAIN)
- Validate computed properties work correctly

Each fixture represents a real-world query pattern we want to detect.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from querysense.parser import parse_explain, ParseError, ExplainOutput, PlanNode
from querysense.parser.parser import validate_has_analyze


# =============================================================================
# Fixtures
# =============================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    path = FIXTURES_DIR / f"{name}.json"
    return json.loads(path.read_text())


@pytest.fixture
def sequential_scan_fixture() -> dict:
    """Large table sequential scan - classic performance problem."""
    return load_fixture("sequential_scan_large_table")


@pytest.fixture
def index_scan_fixture() -> dict:
    """Well-optimized index scan - the happy path."""
    return load_fixture("index_scan_good")


@pytest.fixture
def nested_loop_fixture() -> dict:
    """Nested loop with high loop count - potential N+1 smell."""
    return load_fixture("nested_loop_high_loops")


@pytest.fixture
def bad_estimate_fixture() -> dict:
    """Query with severely wrong row estimates."""
    return load_fixture("bad_estimate")


@pytest.fixture
def sort_without_index_fixture() -> dict:
    """Sort spilling to disk - missing index on sort column."""
    return load_fixture("sort_without_index")


# =============================================================================
# Happy Path Tests
# =============================================================================

class TestParseValidExplain:
    """Test parsing of valid EXPLAIN ANALYZE output."""
    
    def test_parse_sequential_scan(self, sequential_scan_fixture: dict) -> None:
        """Parse a simple sequential scan."""
        output = parse_explain(sequential_scan_fixture)
        
        assert isinstance(output, ExplainOutput)
        assert output.plan.node_type == "Seq Scan"
        assert output.plan.relation_name == "orders"
        assert output.has_analyze_data
        
    def test_parse_index_scan(self, index_scan_fixture: dict) -> None:
        """Parse an index scan with all expected fields."""
        output = parse_explain(index_scan_fixture)
        
        assert output.plan.node_type == "Index Scan"
        assert output.plan.index_name == "users_email_idx"
        assert output.plan.scan_direction == "Forward"
        
    def test_parse_nested_plan(self, nested_loop_fixture: dict) -> None:
        """Parse a query with nested child plans."""
        output = parse_explain(nested_loop_fixture)
        
        assert output.plan.node_type == "Nested Loop"
        assert len(output.plan.plans) == 2
        
        # Check child nodes
        outer = output.plan.plans[0]
        inner = output.plan.plans[1]
        
        assert outer.node_type == "Seq Scan"
        assert inner.node_type == "Index Scan"
        assert inner.actual_loops == 10234  # High loop count
        
    def test_parse_from_file(self) -> None:
        """Parse directly from a file path."""
        path = FIXTURES_DIR / "index_scan_good.json"
        output = parse_explain(path)
        
        assert output.plan.node_type == "Index Scan"
        
    def test_parse_from_string(self, index_scan_fixture: dict) -> None:
        """Parse from a JSON string."""
        json_string = json.dumps(index_scan_fixture)
        output = parse_explain(json_string)
        
        assert output.plan.node_type == "Index Scan"
        
    def test_parse_unwrapped_dict(self, index_scan_fixture: dict) -> None:
        """Parse from already-unwrapped dict (without outer array)."""
        inner = index_scan_fixture[0]  # Remove the outer array
        output = parse_explain(inner)
        
        assert output.plan.node_type == "Index Scan"


# =============================================================================
# Computed Properties Tests
# =============================================================================

class TestPlanNodeProperties:
    """Test computed properties on PlanNode."""
    
    def test_is_scan_node(self, sequential_scan_fixture: dict) -> None:
        """Seq Scan is correctly identified as scan node."""
        output = parse_explain(sequential_scan_fixture)
        assert output.plan.is_scan_node
        
    def test_is_join_node(self, nested_loop_fixture: dict) -> None:
        """Nested Loop is correctly identified as join node."""
        output = parse_explain(nested_loop_fixture)
        assert output.plan.is_join_node
        assert not output.plan.is_scan_node
        
    def test_has_analyze_data(self, sequential_scan_fixture: dict) -> None:
        """Detect presence of ANALYZE data."""
        output = parse_explain(sequential_scan_fixture)
        assert output.plan.has_analyze_data
        assert output.has_analyze_data
        
    def test_row_estimate_ratio_accurate(self, index_scan_fixture: dict) -> None:
        """Row estimate ratio near 1.0 for accurate estimate."""
        output = parse_explain(index_scan_fixture)
        ratio = output.plan.row_estimate_ratio
        
        assert ratio is not None
        assert ratio == 1.0  # Estimated 1, got 1
        
    def test_row_estimate_ratio_underestimate(self, bad_estimate_fixture: dict) -> None:
        """Detect severe underestimates in row count."""
        output = parse_explain(bad_estimate_fixture)
        
        # Find the orders seq scan which has bad estimate
        orders_scan = None
        for node in output.all_nodes:
            if node.node_type == "Seq Scan" and node.relation_name == "orders":
                orders_scan = node
                break
        
        assert orders_scan is not None
        ratio = orders_scan.row_estimate_ratio
        
        assert ratio is not None
        assert ratio > 1000  # Estimated 50, got 250000
        
    def test_total_actual_time(self, nested_loop_fixture: dict) -> None:
        """Total time accounts for loop iterations."""
        output = parse_explain(nested_loop_fixture)
        inner_scan = output.plan.plans[1]  # The index scan
        
        # actual_total_time is per-loop, multiply by loops for true total
        assert inner_scan.actual_loops == 10234
        assert inner_scan.actual_total_time == 0.421
        
        total = inner_scan.total_actual_time
        assert total is not None
        assert abs(total - (0.421 * 10234)) < 0.01
        
    def test_iter_nodes_flattens_tree(self, nested_loop_fixture: dict) -> None:
        """iter_nodes returns all nodes in the tree."""
        output = parse_explain(nested_loop_fixture)
        all_nodes = output.plan.iter_nodes()
        
        # Should have: Nested Loop, Seq Scan, Index Scan
        assert len(all_nodes) == 3
        
        node_types = {n.node_type for n in all_nodes}
        assert node_types == {"Nested Loop", "Seq Scan", "Index Scan"}


class TestExplainOutputProperties:
    """Test computed properties on ExplainOutput."""
    
    def test_all_nodes(self, nested_loop_fixture: dict) -> None:
        """all_nodes property returns flat list."""
        output = parse_explain(nested_loop_fixture)
        assert len(output.all_nodes) == 3
        
    def test_find_nodes_by_type(self, bad_estimate_fixture: dict) -> None:
        """Find specific node types in complex plans."""
        output = parse_explain(bad_estimate_fixture)
        
        seq_scans = output.find_nodes_by_type("Seq Scan")
        assert len(seq_scans) == 2  # orders and users tables
        
        hash_nodes = output.find_nodes_by_type("Hash")
        assert len(hash_nodes) == 1
        
    def test_find_slow_nodes(self, sequential_scan_fixture: dict) -> None:
        """Find nodes exceeding time threshold."""
        output = parse_explain(sequential_scan_fixture)
        
        slow = output.find_slow_nodes(threshold_ms=100.0)
        assert len(slow) == 1
        assert slow[0].node_type == "Seq Scan"
        
        # Nothing slow with high threshold
        very_slow = output.find_slow_nodes(threshold_ms=10000.0)
        assert len(very_slow) == 0


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestParseErrors:
    """Test error handling for invalid inputs."""
    
    def test_invalid_json(self) -> None:
        """Reject malformed JSON."""
        with pytest.raises(ParseError) as exc_info:
            parse_explain("{not valid json}")
        
        assert exc_info.value.source == "json_decode"
        assert "Invalid JSON" in exc_info.value.message
        
    def test_empty_array(self) -> None:
        """Reject empty array."""
        with pytest.raises(ParseError) as exc_info:
            parse_explain([])
        
        assert "Empty array" in exc_info.value.message
        
    def test_multiple_plans(self) -> None:
        """Reject multiple EXPLAIN outputs concatenated."""
        with pytest.raises(ParseError) as exc_info:
            parse_explain([{"Plan": {}}, {"Plan": {}}])
        
        assert "single EXPLAIN output" in exc_info.value.message
        
    def test_missing_plan_field(self) -> None:
        """Reject objects without Plan field."""
        with pytest.raises(ParseError) as exc_info:
            parse_explain({"NotAPlan": {}})
        
        assert "Missing 'Plan'" in exc_info.value.message
        
    def test_file_not_found(self) -> None:
        """Clear error for missing files."""
        with pytest.raises(ParseError) as exc_info:
            parse_explain("/nonexistent/path.json")
        
        assert exc_info.value.source == "file_read"
        assert "not found" in exc_info.value.message
        
    def test_validation_error_readable(self) -> None:
        """Pydantic validation errors are human-readable."""
        invalid = [{
            "Plan": {
                "Node Type": "Seq Scan",
                # Missing required fields
            }
        }]
        
        with pytest.raises(ParseError) as exc_info:
            parse_explain(invalid)
        
        assert exc_info.value.source == "validation"
        # Should mention the missing field
        assert "Startup Cost" in str(exc_info.value.detail) or "required" in str(exc_info.value.detail).lower()


class TestValidateHasAnalyze:
    """Test validation of ANALYZE data presence."""
    
    def test_accepts_analyze_output(self, sequential_scan_fixture: dict) -> None:
        """No error for output with ANALYZE data."""
        output = parse_explain(sequential_scan_fixture)
        validate_has_analyze(output)  # Should not raise
        
    def test_rejects_plain_explain(self) -> None:
        """Error for output without ANALYZE data."""
        plain_explain = [{
            "Plan": {
                "Node Type": "Seq Scan",
                "Relation Name": "users",
                "Startup Cost": 0.0,
                "Total Cost": 100.0,
                "Plan Rows": 1000,
                "Plan Width": 100,
                # No Actual* fields = no ANALYZE
            },
            "Planning Time": 0.1,
            # No Execution Time = no ANALYZE
        }]
        
        output = parse_explain(plain_explain)
        
        with pytest.raises(ParseError) as exc_info:
            validate_has_analyze(output)
        
        assert "EXPLAIN ANALYZE" in exc_info.value.message


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Test unusual but valid inputs."""
    
    def test_zero_plan_rows(self) -> None:
        """Handle plan_rows = 0 without division error."""
        data = [{
            "Plan": {
                "Node Type": "Result",
                "Startup Cost": 0.0,
                "Total Cost": 0.01,
                "Plan Rows": 0,  # Edge case
                "Plan Width": 0,
                "Actual Rows": 0,
                "Actual Loops": 1,
                "Actual Startup Time": 0.001,
                "Actual Total Time": 0.001,
            },
            "Planning Time": 0.05,
            "Execution Time": 0.01,
        }]
        
        output = parse_explain(data)
        ratio = output.plan.row_estimate_ratio
        
        # 0 estimated, 0 actual = ratio of 1.0 (both correct)
        assert ratio == 1.0
        
    def test_zero_plan_rows_nonzero_actual(self) -> None:
        """Handle division by zero when estimate is 0 but actual > 0."""
        data = [{
            "Plan": {
                "Node Type": "Result",
                "Startup Cost": 0.0,
                "Total Cost": 0.01,
                "Plan Rows": 0,  # Estimated nothing
                "Plan Width": 0,
                "Actual Rows": 100,  # Got 100
                "Actual Loops": 1,
                "Actual Startup Time": 0.001,
                "Actual Total Time": 0.001,
            },
            "Planning Time": 0.05,
            "Execution Time": 0.01,
        }]
        
        output = parse_explain(data)
        ratio = output.plan.row_estimate_ratio
        
        # Infinite ratio (underestimate of infinity)
        assert ratio == float('inf')
        
    def test_deeply_nested_plan(self) -> None:
        """Handle deeply nested plan structures."""
        # Build a 5-level deep plan
        def make_node(depth: int) -> dict:
            node = {
                "Node Type": "Result" if depth == 0 else "Append",
                "Startup Cost": 0.0,
                "Total Cost": float(depth),
                "Plan Rows": 1,
                "Plan Width": 10,
            }
            if depth > 0:
                node["Plans"] = [make_node(depth - 1)]
            return node
        
        data = [{"Plan": make_node(5), "Planning Time": 0.1}]
        output = parse_explain(data)
        
        # Should have 6 nodes total
        assert len(output.all_nodes) == 6
        
    def test_unknown_node_type(self) -> None:
        """Accept unknown node types (future Postgres versions)."""
        data = [{
            "Plan": {
                "Node Type": "FuturisticScan",  # Doesn't exist (yet)
                "Startup Cost": 0.0,
                "Total Cost": 1.0,
                "Plan Rows": 100,
                "Plan Width": 50,
            },
            "Planning Time": 0.1,
        }]
        
        output = parse_explain(data)
        assert output.plan.node_type == "FuturisticScan"
        
    def test_extra_fields_captured(self) -> None:
        """Unknown fields are captured, not rejected."""
        data = [{
            "Plan": {
                "Node Type": "Seq Scan",
                "Relation Name": "test",
                "Startup Cost": 0.0,
                "Total Cost": 1.0,
                "Plan Rows": 100,
                "Plan Width": 50,
                "Some Future Field": "preserved",  # Unknown field
            },
            "Planning Time": 0.1,
            "Some Top Level Field": 42,  # Unknown top-level field
        }]
        
        output = parse_explain(data)
        
        # Extra fields accessible via model_extra
        assert output.plan.model_extra.get("Some Future Field") == "preserved"
        assert output.model_extra.get("Some Top Level Field") == 42

