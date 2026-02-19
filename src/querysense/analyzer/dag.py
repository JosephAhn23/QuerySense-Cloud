"""
Rule DAG (Directed Acyclic Graph) - the single authoritative module for
rule dependency management.

Implements deterministic rule execution with:
- Topological sorting based on requires/provides
- Cycle detection at startup (fail fast)
- SKIP as a first-class outcome
- Typed capability checking

This module provides two levels of abstraction:
1. build_rule_dag(): Simple convenience function for topological sorting.
   Used by the Analyzer for basic rule ordering.
2. RuleDAG + DAGExecutor: Full framework for validated, phase-aware
   execution with capability checking. Used for advanced scenarios.

Design principles:
- The DAG is the truth: execution order is determined by dependencies
- Fail fast: cycles and unknown capabilities are hard errors at startup
- Explicit SKIP: every rule has a RuleRun, even if it didn't execute
- Deterministic: same inputs always produce same execution order

Usage:
    # Simple: just sort rules
    from querysense.analyzer.dag import build_rule_dag
    sorted_rules = build_rule_dag(rules)

    # Advanced: full DAG validation and execution
    from querysense.analyzer.dag import RuleDAG, DAGExecutor
    dag = RuleDAG(rules)
    dag.validate()
    executor = DAGExecutor(dag, fact_store, config)
    results = executor.execute(explain)
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from querysense.analyzer.capabilities import (
    Capability,
    FactKey,
    FactStore,
    capabilities_from_strings,
)
from querysense.analyzer.models import (
    Finding,
    RulePhase,
    RuleRun,
    RuleRunStatus,
)

if TYPE_CHECKING:
    from querysense.analyzer.rules.base import Rule, RuleContext
    from querysense.analyzer.sql_ast import QueryInfo
    from querysense.config import Config
    from querysense.db.probe import DBProbe
    from querysense.parser.models import ExplainOutput

logger = logging.getLogger(__name__)


class DAGValidationError(Exception):
    """Raised when DAG validation fails."""
    pass


class CycleDetectedError(DAGValidationError):
    """Raised when a cycle is detected in the rule DAG."""

    def __init__(self, cycle: list[str]) -> None:
        self.cycle = cycle
        super().__init__(f"Cycle detected in rule DAG: {' -> '.join(cycle)}")


class UnknownCapabilityError(DAGValidationError):
    """Raised when a rule requires an unknown capability."""
    
    def __init__(self, rule_id: str, capability: str) -> None:
        self.rule_id = rule_id
        self.capability = capability
        super().__init__(
            f"Rule {rule_id} requires unknown capability: {capability}. "
            f"Use optional_requires for soft dependencies."
        )


@dataclass
class RuleNode:
    """
    A node in the rule DAG.
    
    Contains the rule and its dependency information.
    """
    
    rule: "Rule"
    requires: set[Capability] = field(default_factory=set)
    optional_requires: set[Capability] = field(default_factory=set)
    provides: set[Capability] = field(default_factory=set)
    
    # Computed during DAG construction
    depends_on: set[str] = field(default_factory=set)  # Rule IDs this depends on
    dependents: set[str] = field(default_factory=set)  # Rule IDs that depend on this
    
    @property
    def rule_id(self) -> str:
        return self.rule.rule_id
    
    @property
    def phase(self) -> RulePhase:
        return self.rule.phase


@dataclass
class ExecutionPlan:
    """
    The execution plan for rules.
    
    Contains rules in topological order, grouped by phase.
    """
    
    phase1_order: list[str] = field(default_factory=list)  # PER_NODE rules
    phase2_order: list[str] = field(default_factory=list)  # AGGREGATE rules
    all_capabilities: set[Capability] = field(default_factory=set)  # All providable capabilities
    
    def __repr__(self) -> str:
        return (
            f"ExecutionPlan(phase1={len(self.phase1_order)} rules, "
            f"phase2={len(self.phase2_order)} rules)"
        )


class RuleDAG:
    """
    Directed Acyclic Graph of rules based on requires/provides.
    
    Validates at construction time:
    - No cycles
    - All required capabilities are provided (or optional)
    
    Usage:
        dag = RuleDAG(rules)
        dag.validate()  # Optional - constructor also validates
        
        plan = dag.get_execution_plan()
        for rule_id in plan.phase1_order:
            rule = dag.get_rule(rule_id)
            ...
    """
    
    def __init__(
        self,
        rules: list["Rule"],
        strict: bool = True,
    ) -> None:
        """
        Build the rule DAG.
        
        Args:
            rules: List of Rule instances
            strict: If True, raise on unknown capabilities. If False, log warning.
        """
        self._nodes: dict[str, RuleNode] = {}
        self._capability_providers: dict[Capability, set[str]] = defaultdict(set)
        self._strict = strict
        
        # Build nodes
        for rule in rules:
            self._add_rule(rule)
        
        # Build edges based on capabilities
        self._build_edges()
        
        # Validate (cycles, unknown capabilities)
        self.validate()
    
    def _add_rule(self, rule: "Rule") -> None:
        """Add a rule to the DAG."""
        # Convert string capabilities to typed Capability enum
        requires = capabilities_from_strings(rule.requires)
        provides = capabilities_from_strings(rule.provides)
        
        # Handle optional_requires if the rule defines it
        optional_requires: set[Capability] = set()
        if hasattr(rule, 'optional_requires'):
            optional_requires = capabilities_from_strings(rule.optional_requires)
        
        node = RuleNode(
            rule=rule,
            requires=requires,
            optional_requires=optional_requires,
            provides=provides,
        )
        
        self._nodes[rule.rule_id] = node
        
        # Track capability providers
        for cap in provides:
            self._capability_providers[cap].add(rule.rule_id)
    
    def _build_edges(self) -> None:
        """Build dependency edges based on requires/provides."""
        for node in self._nodes.values():
            for cap in node.requires:
                # Find rules that provide this capability
                providers = self._capability_providers.get(cap, set())
                for provider_id in providers:
                    if provider_id != node.rule_id:
                        node.depends_on.add(provider_id)
                        self._nodes[provider_id].dependents.add(node.rule_id)
    
    def validate(self) -> None:
        """
        Validate the DAG.
        
        Raises:
            CycleDetectedError: If a cycle is detected
            UnknownCapabilityError: If a required capability has no provider (strict mode)
        """
        # Check for cycles
        cycle = self._detect_cycle()
        if cycle:
            raise CycleDetectedError(cycle)
        
        # Check for unknown capabilities (not provided by any rule)
        # Note: Some capabilities are system-provided (SQL_AST, DB_*, etc.)
        system_capabilities = {
            Capability.SQL_AST,
            Capability.SQL_AST_HIGH,
            Capability.SQL_NORMALIZED,
            Capability.SQL_TABLES,
            Capability.SQL_COLUMNS,
            Capability.DB_CONNECTED,
            Capability.DB_SCHEMA,
            Capability.DB_STATS,
            Capability.DB_INDEXES,
            Capability.DB_SETTINGS,
            Capability.EXPLAIN_PLAN,
            Capability.EXPLAIN_ANALYZE,
            Capability.EXPLAIN_BUFFERS,
            Capability.PRIOR_FINDINGS,
        }
        
        all_providable = set(self._capability_providers.keys()) | system_capabilities
        
        for node in self._nodes.values():
            for cap in node.requires:
                if cap not in all_providable and cap not in node.optional_requires:
                    if self._strict:
                        raise UnknownCapabilityError(node.rule_id, cap.value)
                    else:
                        logger.warning(
                            "Rule %s requires unknown capability %s",
                            node.rule_id, cap.value
                        )
    
    def _detect_cycle(self) -> list[str] | None:
        """
        Detect cycles using DFS.
        
        Returns the cycle path if found, None otherwise.
        """
        WHITE, GRAY, BLACK = 0, 1, 2
        colors: dict[str, int] = {rule_id: WHITE for rule_id in self._nodes}
        path: list[str] = []
        
        def dfs(rule_id: str) -> list[str] | None:
            colors[rule_id] = GRAY
            path.append(rule_id)
            
            for dep_id in self._nodes[rule_id].depends_on:
                if dep_id not in colors:
                    continue  # Unknown rule, skip
                    
                if colors[dep_id] == GRAY:
                    # Found cycle - return path from dep_id to current
                    cycle_start = path.index(dep_id)
                    return path[cycle_start:] + [dep_id]
                
                if colors[dep_id] == WHITE:
                    result = dfs(dep_id)
                    if result:
                        return result
            
            colors[rule_id] = BLACK
            path.pop()
            return None
        
        for rule_id in self._nodes:
            if colors[rule_id] == WHITE:
                cycle = dfs(rule_id)
                if cycle:
                    return cycle
        
        return None
    
    def get_execution_plan(self) -> ExecutionPlan:
        """
        Get the execution plan with rules in topological order.
        
        Rules are grouped by phase:
        - Phase 1: PER_NODE rules in topological order
        - Phase 2: AGGREGATE rules in topological order
        """
        phase1_nodes = [n for n in self._nodes.values() if n.phase == RulePhase.PER_NODE]
        phase2_nodes = [n for n in self._nodes.values() if n.phase == RulePhase.AGGREGATE]
        
        phase1_order = self._topological_sort(phase1_nodes)
        phase2_order = self._topological_sort(phase2_nodes)
        
        all_capabilities = set(self._capability_providers.keys())
        
        return ExecutionPlan(
            phase1_order=phase1_order,
            phase2_order=phase2_order,
            all_capabilities=all_capabilities,
        )
    
    def _topological_sort(self, nodes: list[RuleNode]) -> list[str]:
        """
        Topologically sort a set of nodes.
        
        Uses Kahn's algorithm for stable, deterministic ordering.
        """
        if not nodes:
            return []
        
        node_ids = {n.rule_id for n in nodes}
        
        # Build in-degree map (only considering nodes in this set)
        in_degree: dict[str, int] = {}
        for node in nodes:
            in_degree[node.rule_id] = 0
        
        for node in nodes:
            for dep_id in node.depends_on:
                if dep_id in node_ids:
                    in_degree[node.rule_id] = in_degree.get(node.rule_id, 0) + 1
        
        # Start with nodes that have no dependencies
        # Sort by rule_id for deterministic ordering
        queue: deque[str] = deque(sorted(
            node.rule_id for node in nodes
            if in_degree.get(node.rule_id, 0) == 0
        ))
        
        result: list[str] = []
        
        while queue:
            rule_id = queue.popleft()
            result.append(rule_id)
            
            # Collect newly-ready dependents and insert in sorted order
            ready: list[str] = []
            for dependent_id in self._nodes[rule_id].dependents:
                if dependent_id in node_ids:
                    in_degree[dependent_id] -= 1
                    if in_degree[dependent_id] == 0:
                        ready.append(dependent_id)
            
            # Merge ready list into queue in sorted order for determinism
            if ready:
                merged: deque[str] = deque()
                ready_sorted = sorted(ready)
                ri = 0
                for q_id in queue:
                    while ri < len(ready_sorted) and ready_sorted[ri] < q_id:
                        merged.append(ready_sorted[ri])
                        ri += 1
                    merged.append(q_id)
                while ri < len(ready_sorted):
                    merged.append(ready_sorted[ri])
                    ri += 1
                queue = merged
        
        return result
    
    def get_rule(self, rule_id: str) -> "Rule":
        """Get a rule by ID."""
        return self._nodes[rule_id].rule
    
    def get_node(self, rule_id: str) -> RuleNode:
        """Get a node by rule ID."""
        return self._nodes[rule_id]
    
    @property
    def rules(self) -> list["Rule"]:
        """Get all rules."""
        return [node.rule for node in self._nodes.values()]
    
    @property
    def rule_ids(self) -> set[str]:
        """Get all rule IDs."""
        return set(self._nodes.keys())


@dataclass
class ExecutionResult:
    """Result of executing the rule DAG."""
    
    findings: list[Finding] = field(default_factory=list)
    rule_runs: list[RuleRun] = field(default_factory=list)
    capabilities_provided: set[Capability] = field(default_factory=set)
    duration_ms: float = 0.0


class DAGExecutor:
    """
    Executes rules according to the DAG execution plan.
    
    Handles:
    - Capability checking before each rule
    - SKIP for rules with unmet requirements
    - Error handling with FAIL status
    - Capability updates as rules provide new capabilities
    
    Usage:
        executor = DAGExecutor(
            dag=dag,
            fact_store=fact_store,
            config=config,
            max_findings_per_rule=100,
        )
        result = executor.execute(explain, prior_findings=[])
    """
    
    def __init__(
        self,
        dag: RuleDAG,
        fact_store: FactStore,
        config: "Config | None" = None,
        max_findings_per_rule: int = 100,
        fail_fast: bool = False,
    ) -> None:
        self.dag = dag
        self.fact_store = fact_store
        self.config = config
        self.max_findings_per_rule = max_findings_per_rule
        self.fail_fast = fail_fast
        
        self._plan = dag.get_execution_plan()
    
    def execute(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
        query_info: "QueryInfo | None" = None,
        db_probe: "DBProbe | None" = None,
    ) -> ExecutionResult:
        """
        Execute all rules according to the DAG.
        
        Returns:
            ExecutionResult with findings, rule_runs, and capabilities
        """
        start_time = time.perf_counter()
        prior_findings = prior_findings or []
        
        result = ExecutionResult()
        
        # Phase 1: PER_NODE rules
        phase1_findings, phase1_runs = self._execute_phase(
            rule_ids=self._plan.phase1_order,
            explain=explain,
            prior_findings=[],
            query_info=query_info,
            db_probe=db_probe,
        )
        result.findings.extend(phase1_findings)
        result.rule_runs.extend(phase1_runs)
        
        # Add PRIOR_FINDINGS capability for phase 2
        self.fact_store.add_capability(Capability.PRIOR_FINDINGS)
        
        # Phase 2: AGGREGATE rules
        phase2_findings, phase2_runs = self._execute_phase(
            rule_ids=self._plan.phase2_order,
            explain=explain,
            prior_findings=phase1_findings,
            query_info=query_info,
            db_probe=db_probe,
        )
        result.findings.extend(phase2_findings)
        result.rule_runs.extend(phase2_runs)
        
        result.capabilities_provided = self.fact_store.capabilities
        result.duration_ms = (time.perf_counter() - start_time) * 1000
        
        return result
    
    def _execute_phase(
        self,
        rule_ids: list[str],
        explain: "ExplainOutput",
        prior_findings: list[Finding],
        query_info: "QueryInfo | None",
        db_probe: "DBProbe | None",
    ) -> tuple[list[Finding], list[RuleRun]]:
        """Execute a phase of rules."""
        findings: list[Finding] = []
        rule_runs: list[RuleRun] = []
        
        for rule_id in rule_ids:
            node = self.dag.get_node(rule_id)
            rule = node.rule
            
            # Check if rule is enabled in config
            if self.config is not None and not self.config.is_rule_enabled(rule_id):
                rule_runs.append(RuleRun(
                    rule_id=rule_id,
                    version=rule.version,
                    status=RuleRunStatus.SKIP,
                    runtime_ms=0.0,
                    findings_count=0,
                    skip_reason="Disabled in configuration",
                ))
                continue
            
            # Check required capabilities
            missing = self.fact_store.missing_capabilities(node.requires)
            if missing:
                skip_reason = f"Missing capabilities: {', '.join(sorted(c.value for c in missing))}"
                rule_runs.append(RuleRun(
                    rule_id=rule_id,
                    version=rule.version,
                    status=RuleRunStatus.SKIP,
                    runtime_ms=0.0,
                    findings_count=0,
                    skip_reason=skip_reason,
                ))
                logger.debug("Rule %s skipped: %s", rule_id, skip_reason)
                continue
            
            # Execute the rule
            rule_start = time.perf_counter()
            try:
                rule_findings = self._run_rule(
                    rule=rule,
                    explain=explain,
                    prior_findings=prior_findings,
                    query_info=query_info,
                    db_probe=db_probe,
                )
                
                # Limit findings per rule
                rule_findings = rule_findings[:self.max_findings_per_rule]
                findings.extend(rule_findings)
                
                runtime_ms = (time.perf_counter() - rule_start) * 1000
                
                rule_runs.append(RuleRun(
                    rule_id=rule_id,
                    version=rule.version,
                    status=RuleRunStatus.PASS,
                    runtime_ms=runtime_ms,
                    findings_count=len(rule_findings),
                ))
                
                # Add capabilities this rule provides
                self.fact_store.add_capabilities(node.provides)
                
            except Exception as e:
                runtime_ms = (time.perf_counter() - rule_start) * 1000
                
                if self.fail_fast:
                    raise
                
                rule_runs.append(RuleRun(
                    rule_id=rule_id,
                    version=rule.version,
                    status=RuleRunStatus.FAIL,
                    runtime_ms=runtime_ms,
                    findings_count=0,
                    error_summary=str(e),
                ))
                logger.warning("Rule %s failed: %s", rule_id, e)
        
        return findings, rule_runs
    
    def _run_rule(
        self,
        rule: "Rule",
        explain: "ExplainOutput",
        prior_findings: list[Finding],
        query_info: "QueryInfo | None",
        db_probe: "DBProbe | None",
    ) -> list[Finding]:
        """Run a single rule."""
        from querysense.analyzer.rules.base import RuleContext

        # Check if rule uses context-aware execution
        if rule.uses_context:
            ctx = RuleContext(
                explain=explain,
                prior_findings=prior_findings,
                query_info=query_info,
                db_probe=db_probe,
                capabilities={c.value for c in self.fact_store.capabilities},
            )
            return rule.analyze_with_context(ctx)
        else:
            return rule.analyze(explain, prior_findings)


# =============================================================================
# Convenience function: simple topological sort without full DAG framework
# =============================================================================


def build_rule_dag(rules: list["Rule"]) -> list["Rule"]:
    """
    Build and validate the rule dependency DAG, returning rules in
    topological order (dependencies before dependents).

    This is the simple convenience function for rule ordering. For
    full DAG validation and execution, use RuleDAG + DAGExecutor.

    Algorithm: Kahn's algorithm for topological sorting.

    Args:
        rules: List of Rule objects to sort

    Returns:
        Rules in topological order

    Raises:
        CycleDetectedError: If dependencies form a cycle
    """
    if not rules:
        return []

    # Build adjacency list and in-degree count
    rule_map = {r.rule_id: r for r in rules}
    provides_map: dict[str, set[str]] = {}  # capability -> rules that provide it

    # First pass: build provides_map
    for rule in rules:
        for cap in rule.provides:
            cap_str = cap.value if isinstance(cap, Capability) else str(cap)
            if cap_str not in provides_map:
                provides_map[cap_str] = set()
            provides_map[cap_str].add(rule.rule_id)

    # Build edges: for each rule, find rules that provide what it requires
    edges: dict[str, set[str]] = {r.rule_id: set() for r in rules}
    in_degree: dict[str, int] = {r.rule_id: 0 for r in rules}

    for rule in rules:
        for cap in rule.requires:
            cap_str = cap.value if isinstance(cap, Capability) else str(cap)

            # Find rules that provide this capability
            providers = provides_map.get(cap_str, set())
            for provider_id in providers:
                if provider_id != rule.rule_id:
                    # Edge: provider -> rule (provider must run first)
                    if rule.rule_id not in edges[provider_id]:
                        edges[provider_id].add(rule.rule_id)
                        in_degree[rule.rule_id] += 1

    # Kahn's algorithm
    queue: deque[str] = deque(
        rule_id for rule_id, degree in in_degree.items() if degree == 0
    )
    sorted_ids: list[str] = []

    while queue:
        rule_id = queue.popleft()
        sorted_ids.append(rule_id)

        for dependent_id in edges[rule_id]:
            in_degree[dependent_id] -= 1
            if in_degree[dependent_id] == 0:
                queue.append(dependent_id)

    # Check for cycle
    if len(sorted_ids) != len(rules):
        # Find the cycle for error message
        remaining = set(rule_map.keys()) - set(sorted_ids)
        cycle = _find_cycle(remaining, edges)
        raise CycleDetectedError(cycle)

    return [rule_map[rule_id] for rule_id in sorted_ids]


def _find_cycle(remaining: set[str], edges: dict[str, set[str]]) -> list[str]:
    """Find a cycle in the remaining nodes for error reporting."""
    for start in remaining:
        visited: set[str] = set()
        path: list[str] = []

        if _dfs_find_cycle(start, remaining, edges, visited, path):
            return path

    return list(remaining)[:5] + ["..."]


def _dfs_find_cycle(
    node: str,
    remaining: set[str],
    edges: dict[str, set[str]],
    visited: set[str],
    path: list[str],
) -> bool:
    """DFS helper to find cycle."""
    if node in visited:
        cycle_start = path.index(node) if node in path else 0
        path[:] = path[cycle_start:] + [node]
        return True

    if node not in remaining:
        return False

    visited.add(node)
    path.append(node)

    for neighbor in edges.get(node, set()):
        if neighbor in remaining:
            if _dfs_find_cycle(neighbor, remaining, edges, visited, path):
                return True

    path.pop()
    return False
