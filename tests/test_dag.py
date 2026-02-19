"""
Tests for the Rule DAG execution engine.

These tests verify:
- Topological sorting
- Cycle detection
- Capability checking
- SKIP enforcement
- Deterministic execution

Design principle: The DAG is the truth
"""

from __future__ import annotations

import pytest

from querysense.analyzer.capabilities import (
    Capability,
    FactKey,
    FactStore,
    check_requirements,
    capabilities_from_strings,
)
from querysense.analyzer.dag import (
    CycleDetectedError,
    DAGValidationError,
    ExecutionPlan,
    RuleDAG,
    RuleNode,
)
from querysense.analyzer.models import (
    EvidenceLevel,
    Finding,
    NodeContext,
    RulePhase,
    RuleRun,
    RuleRunStatus,
    Severity,
    compute_evidence_level,
)
from querysense.analyzer.path import NodePath
from querysense.analyzer.rules.base import Rule


# =============================================================================
# Mock Rules for Testing
# =============================================================================


class MockRule(Rule):
    """Base mock rule for testing."""

    rule_id = "MOCK_RULE"
    version = "1.0.0"
    severity = Severity.WARNING
    phase = RulePhase.PER_NODE
    requires: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()

    def __init__(self, **kwargs: object) -> None:
        # Preserve class-level attributes: only override if explicitly passed
        for key, value in kwargs.items():
            setattr(self, key, value)
        super().__init__()

    def analyze(self, explain, prior_findings=None):  # type: ignore[override]
        return []


class RuleA(MockRule):
    """Rule A: No requirements, provides seq_scan_findings."""

    rule_id = "RULE_A"
    version = "1.0.0"
    severity = Severity.WARNING
    phase = RulePhase.PER_NODE
    requires: tuple[str, ...] = ()
    provides: tuple[str, ...] = ("seq_scan_findings",)


class RuleB(MockRule):
    """Rule B: Requires seq_scan_findings, provides join_findings."""

    rule_id = "RULE_B"
    version = "1.0.0"
    severity = Severity.WARNING
    phase = RulePhase.PER_NODE
    requires: tuple[str, ...] = ("seq_scan_findings",)
    provides: tuple[str, ...] = ("join_findings",)


class RuleC(MockRule):
    """Rule C: Requires join_findings."""

    rule_id = "RULE_C"
    version = "1.0.0"
    severity = Severity.WARNING
    phase = RulePhase.PER_NODE
    requires: tuple[str, ...] = ("join_findings",)
    provides: tuple[str, ...] = ()


class RuleCycle1(MockRule):
    """Cycle rule 1: Creates a cycle with RuleCycle2."""

    rule_id = "RULE_CYCLE_1"
    version = "1.0.0"
    severity = Severity.WARNING
    phase = RulePhase.PER_NODE
    requires: tuple[str, ...] = ("validated_indexes",)
    provides: tuple[str, ...] = ("index_recommendations",)


class RuleCycle2(MockRule):
    """Cycle rule 2: Creates a cycle with RuleCycle1."""

    rule_id = "RULE_CYCLE_2"
    version = "1.0.0"
    severity = Severity.WARNING
    phase = RulePhase.PER_NODE
    requires: tuple[str, ...] = ("index_recommendations",)
    provides: tuple[str, ...] = ("validated_indexes",)


class RuleSqlRequired(MockRule):
    """Rule that requires SQL AST."""
    
    rule_id = "RULE_SQL_REQUIRED"
    version = "1.0.0"
    severity = Severity.WARNING
    phase = RulePhase.PER_NODE
    requires: tuple[str, ...] = ("sql_ast",)
    provides: tuple[str, ...] = ()


class RuleDbRequired(MockRule):
    """Rule that requires DB probe."""
    
    rule_id = "RULE_DB_REQUIRED"
    version = "1.0.0"
    severity = Severity.WARNING
    phase = RulePhase.PER_NODE
    requires: tuple[str, ...] = ("db_connected",)
    provides: tuple[str, ...] = ()


# =============================================================================
# Tests: Capabilities
# =============================================================================


class TestCapability:
    """Tests for the Capability enum."""
    
    def test_capability_values(self):
        """Capabilities should have string values."""
        assert Capability.SQL_AST.value == "sql_ast"
        assert Capability.DB_CONNECTED.value == "db_connected"
        assert Capability.EXPLAIN_PLAN.value == "explain_plan"
    
    def test_capability_string_conversion(self):
        """Capabilities should convert to strings."""
        assert str(Capability.SQL_AST) == "sql_ast"
    
    def test_capabilities_from_strings(self):
        """Should convert string tuples to Capability sets."""
        strings = ("sql_ast", "db_connected", "unknown_cap")
        caps = capabilities_from_strings(strings)
        
        assert Capability.SQL_AST in caps
        assert Capability.DB_CONNECTED in caps
        assert len(caps) == 2  # Unknown cap is ignored


class TestFactStore:
    """Tests for the FactStore."""
    
    def test_set_and_get_fact(self):
        """Should store and retrieve facts."""
        store = FactStore()
        store.set(FactKey.SQL_HASH, "abc123", source_rule="test")
        
        assert store.has(FactKey.SQL_HASH)
        assert store.get(FactKey.SQL_HASH) == "abc123"
    
    def test_get_missing_fact(self):
        """Should return default for missing facts."""
        store = FactStore()
        
        assert store.get(FactKey.SQL_HASH) is None
        assert store.get(FactKey.SQL_HASH, "default") == "default"
    
    def test_get_required_missing(self):
        """Should raise for missing required facts."""
        store = FactStore()
        
        with pytest.raises(KeyError):
            store.get_required(FactKey.SQL_HASH)
    
    def test_capability_tracking(self):
        """Should track capabilities."""
        store = FactStore()
        store.add_capability(Capability.SQL_AST)
        store.add_capability(Capability.DB_CONNECTED)
        
        assert store.has_capability(Capability.SQL_AST)
        assert store.has_capability(Capability.DB_CONNECTED)
        assert not store.has_capability(Capability.DB_STATS)
    
    def test_missing_capabilities(self):
        """Should report missing capabilities."""
        store = FactStore()
        store.add_capability(Capability.SQL_AST)
        
        required = {Capability.SQL_AST, Capability.DB_CONNECTED}
        missing = store.missing_capabilities(required)
        
        assert missing == {Capability.DB_CONNECTED}


class TestCheckRequirements:
    """Tests for check_requirements function."""
    
    def test_no_requirements(self):
        """Rules with no requirements should always pass."""
        rule = RuleA()
        can_run, missing = check_requirements(rule, set())
        
        assert can_run is True
        assert missing == []
    
    def test_requirements_met(self):
        """Should pass when all requirements are met."""
        rule = RuleSqlRequired()
        caps = {Capability.SQL_AST, Capability.DB_CONNECTED}
        can_run, missing = check_requirements(rule, caps)
        
        assert can_run is True
        assert missing == []
    
    def test_requirements_not_met(self):
        """Should fail when requirements are not met."""
        rule = RuleSqlRequired()
        caps = {Capability.DB_CONNECTED}
        can_run, missing = check_requirements(rule, caps)
        
        assert can_run is False
        assert "sql_ast" in missing


# =============================================================================
# Tests: Rule DAG
# =============================================================================


class TestRuleDAG:
    """Tests for the RuleDAG class."""
    
    def test_simple_dag(self):
        """Should build DAG with simple dependency chain."""
        rules = [RuleA(), RuleB(), RuleC()]
        dag = RuleDAG(rules, strict=False)
        
        assert "RULE_A" in dag.rule_ids
        assert "RULE_B" in dag.rule_ids
        assert "RULE_C" in dag.rule_ids
    
    def test_topological_order(self):
        """Topological order should respect dependencies."""
        rules = [RuleC(), RuleB(), RuleA()]  # Wrong order
        dag = RuleDAG(rules, strict=False)
        plan = dag.get_execution_plan()
        
        # A must come before B, B must come before C
        a_idx = plan.phase1_order.index("RULE_A")
        b_idx = plan.phase1_order.index("RULE_B")
        c_idx = plan.phase1_order.index("RULE_C")
        
        assert a_idx < b_idx < c_idx
    
    def test_cycle_detection(self):
        """Should detect cycles and raise error."""
        rules = [RuleCycle1(), RuleCycle2()]
        
        with pytest.raises(CycleDetectedError):
            RuleDAG(rules, strict=False)
    
    def test_deterministic_order(self):
        """Execution order should be deterministic."""
        rules = [RuleA(), RuleB(), RuleC()]
        
        dag1 = RuleDAG(rules, strict=False)
        dag2 = RuleDAG(rules, strict=False)
        
        plan1 = dag1.get_execution_plan()
        plan2 = dag2.get_execution_plan()
        
        assert plan1.phase1_order == plan2.phase1_order


class TestExecutionPlan:
    """Tests for the ExecutionPlan class."""
    
    def test_phase_separation(self):
        """Rules should be separated by phase."""

        class RulePerNode(MockRule):
            rule_id = "PER_NODE"
            phase = RulePhase.PER_NODE

        class RuleAggregate(MockRule):
            rule_id = "AGGREGATE"
            phase = RulePhase.AGGREGATE

        rule_per_node = RulePerNode()
        rule_aggregate = RuleAggregate()
        
        dag = RuleDAG([rule_per_node, rule_aggregate], strict=False)
        plan = dag.get_execution_plan()
        
        assert "PER_NODE" in plan.phase1_order
        assert "AGGREGATE" in plan.phase2_order
        assert "PER_NODE" not in plan.phase2_order
        assert "AGGREGATE" not in plan.phase1_order


# =============================================================================
# Tests: Evidence Level Computation
# =============================================================================


class TestEvidenceLevel:
    """Tests for evidence level computation."""
    
    def test_plan_only(self):
        """Should return PLAN when only plan is available."""
        from querysense.analyzer.models import SQLConfidence
        
        level = compute_evidence_level(
            has_plan=True,
            has_sql=False,
            sql_confidence=SQLConfidence.NONE,
            has_db_probe=False,
        )
        
        assert level == EvidenceLevel.PLAN
    
    def test_plan_sql(self):
        """Should return PLAN_SQL when SQL is available."""
        from querysense.analyzer.models import SQLConfidence
        
        level = compute_evidence_level(
            has_plan=True,
            has_sql=True,
            sql_confidence=SQLConfidence.HIGH,
            has_db_probe=False,
        )
        
        assert level == EvidenceLevel.PLAN_SQL
    
    def test_plan_sql_db(self):
        """Should return PLAN_SQL_DB when DB probe succeeds."""
        from querysense.analyzer.models import SQLConfidence
        
        level = compute_evidence_level(
            has_plan=True,
            has_sql=True,
            sql_confidence=SQLConfidence.HIGH,
            has_db_probe=True,
            db_probe_succeeded=True,
        )
        
        assert level == EvidenceLevel.PLAN_SQL_DB
    
    def test_low_sql_confidence(self):
        """Should return PLAN when SQL confidence is LOW."""
        from querysense.analyzer.models import SQLConfidence
        
        level = compute_evidence_level(
            has_plan=True,
            has_sql=True,
            sql_confidence=SQLConfidence.LOW,
            has_db_probe=False,
        )
        
        assert level == EvidenceLevel.PLAN


# =============================================================================
# Property Tests (Invariant Checks)
# =============================================================================


class TestDagInvariants:
    """Property-based tests for DAG invariants."""
    
    def test_no_cycles_invariant(self):
        """DAG should never contain cycles (property test)."""
        # Test with various rule configurations
        configs = [
            [RuleA()],
            [RuleA(), RuleB()],
            [RuleA(), RuleB(), RuleC()],
        ]
        
        for rules in configs:
            dag = RuleDAG(rules, strict=False)
            plan = dag.get_execution_plan()
            
            # Verify order respects dependencies
            for rule_id in plan.phase1_order:
                node = dag.get_node(rule_id)
                rule_idx = plan.phase1_order.index(rule_id)
                
                for dep_id in node.depends_on:
                    if dep_id in plan.phase1_order:
                        dep_idx = plan.phase1_order.index(dep_id)
                        assert dep_idx < rule_idx, \
                            f"Dependency {dep_id} should come before {rule_id}"
    
    def test_missing_capability_skip_invariant(self):
        """Rules with missing capabilities should be SKIPPED, not FAIL."""
        # This is a critical invariant for the analyzer
        rule = RuleSqlRequired()
        caps: set[Capability] = set()  # No capabilities
        
        can_run, missing = check_requirements(rule, caps)
        
        assert can_run is False
        assert len(missing) > 0
        # The rule should be SKIPPED, not crash


# =============================================================================
# Golden Tests
# =============================================================================


class TestGoldenResults:
    """Golden tests for deterministic output."""
    
    def test_rule_run_fields(self):
        """RuleRun should have all required fields."""
        run = RuleRun(
            rule_id="TEST_RULE",
            version="1.0.0",
            status=RuleRunStatus.PASS,
            runtime_ms=10.5,
            findings_count=2,
        )
        
        assert run.rule_id == "TEST_RULE"
        assert run.version == "1.0.0"
        assert run.status == RuleRunStatus.PASS
        assert run.runtime_ms == 10.5
        assert run.findings_count == 2
        assert run.error_summary is None
        assert run.skip_reason is None
    
    def test_skip_rule_run(self):
        """SKIP RuleRun should have skip_reason."""
        run = RuleRun(
            rule_id="TEST_RULE",
            version="1.0.0",
            status=RuleRunStatus.SKIP,
            runtime_ms=0.0,
            findings_count=0,
            skip_reason="Missing capabilities: sql_ast",
        )
        
        assert run.status == RuleRunStatus.SKIP
        assert run.skip_reason is not None
        assert "sql_ast" in run.skip_reason
    
    def test_finding_fields(self):
        """Finding should have all required fields."""
        context = NodeContext(
            path=NodePath.root(),
            node_type="Seq Scan",
            relation_name="orders",
            actual_rows=1000000,
        )
        
        finding = Finding(
            rule_id="SEQ_SCAN_LARGE_TABLE",
            severity=Severity.WARNING,
            context=context,
            title="Sequential scan on orders",
            description="Large table scan detected",
            suggestion="Consider adding an index",
            assumptions=("Table has no indexes on filter columns",),
            verification_steps=("Run EXPLAIN ANALYZE after adding index",),
        )
        
        assert finding.rule_id == "SEQ_SCAN_LARGE_TABLE"
        assert finding.severity == Severity.WARNING
        assert finding.context.relation_name == "orders"
        assert len(finding.assumptions) == 1
        assert len(finding.verification_steps) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
