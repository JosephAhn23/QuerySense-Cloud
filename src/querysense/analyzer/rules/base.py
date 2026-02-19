"""
Base class for analyzer rules.

All rules must inherit from Rule and implement the analyze() method.
This ensures consistent behavior and enables contract testing.

Rules support two analysis signatures:
1. analyze(explain, prior_findings) - Simple, for basic rules
2. analyze_with_context(ctx) - Advanced, for rules needing schema/history

If a rule implements analyze_with_context(), it will be called with the full
RuleContext. Otherwise, analyze() is called with just explain and prior_findings.

SQL Enhancement Protocol:
Rules can optionally implement enhance_with_sql() to provide better suggestions
when SQL query is available. This decouples rules from the analyzer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Iterator, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.path import NodePath, traverse_with_path

if TYPE_CHECKING:
    from querysense.analyzer.sql_ast import QueryInfo
    from querysense.db.probe import DBProbe
    from querysense.parser.models import ExplainOutput, PlanNode


@runtime_checkable
class SQLEnhanceable(Protocol):
    """
    Protocol for rules that can enhance findings with SQL information.
    
    Rules implementing this protocol can provide better suggestions
    when the original SQL query is available.
    
    Example:
        class SeqScanLargeTable(Rule, SQLEnhanceable):
            def enhance_with_sql(
                self,
                finding: Finding,
                query_info: QueryInfo,
            ) -> Finding:
                # Get recommended columns from SQL analysis
                table = finding.context.relation_name
                if table:
                    columns = query_info.suggest_composite_index(table)
                    if columns:
                        return finding.model_copy(update={
                            "suggestion": f"CREATE INDEX ON {table}({', '.join(columns)})"
                        })
                return finding
    """
    
    def enhance_with_sql(
        self,
        finding: "Finding",
        query_info: "QueryInfo",
    ) -> "Finding":
        """
        Enhance a finding with SQL-based recommendations.
        
        Args:
            finding: The original finding from this rule
            query_info: Parsed information about the SQL query
            
        Returns:
            Enhanced finding with better suggestions, or original if no enhancement
        """
        ...


class RuleConfig(BaseModel):
    """
    Base configuration for all rules.
    
    Rules can define their own config schema by subclassing this.
    All configs support 'enabled' to allow disabling rules.
    
    Example:
        class MyRuleConfig(RuleConfig):
            threshold: int = 1000
            check_filters: bool = True
    """
    
    model_config = ConfigDict(frozen=True, extra="forbid")
    
    enabled: bool = True


class RuleContext:
    """
    Full context for rule execution.
    
    Provides access to:
    - EXPLAIN output
    - Prior findings from earlier phases
    - SQL query info (if available)
    - Database probe (if available)
    - Available capabilities
    
    Rules that override analyze_with_context() receive this.
    """
    
    def __init__(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
        query_info: "QueryInfo | None" = None,
        db_probe: "DBProbe | None" = None,
        capabilities: set[str] | None = None,
    ) -> None:
        self.explain = explain
        self.prior_findings = prior_findings or []
        self.query_info: "QueryInfo | None" = query_info
        self.db_probe: "DBProbe | None" = db_probe
        self.capabilities = capabilities or set()
    
    def has_capability(self, capability: str) -> bool:
        """Check if a capability is available."""
        return capability in self.capabilities
    
    def get_table_info(self, table: str) -> Any | None:
        """
        Get table information from DB probe (if available).
        
        Returns None if DB probe is not available or data not pre-fetched.
        Note: DB probe operations are async; table info should be
        pre-fetched into the FactStore before rule execution.
        """
        if self.db_probe is None:
            return None
        return None


class Rule(ABC):
    """
    Abstract base class for analyzer rules.
    
    Each rule detects a specific class of performance issues in query plans.
    Rules should be:
    - Deterministic: Same input always produces same output
    - Fast: O(n) in the number of plan nodes
    - Focused: One rule, one concern
    
    Attributes:
        rule_id: Unique identifier, UPPER_SNAKE_CASE (e.g., "SEQ_SCAN_LARGE_TABLE")
        version: Semver string, bump when detection logic changes
        severity: Default severity for findings from this rule
        description: One-line description for documentation
        config_schema: Pydantic model for rule configuration (default: RuleConfig)
        phase: When to run this rule (PER_NODE or AGGREGATE)
        requires: Capabilities this rule requires (e.g., ["sql_ast", "db_probe"])
        provides: Capabilities this rule provides for downstream rules
    
    Phases:
        PER_NODE (default): Rule analyzes individual nodes. Runs first.
        AGGREGATE: Rule analyzes patterns across the entire query.
            Receives findings from PER_NODE phase. Runs second.
    
    Dependencies:
        Rules can declare dependencies via `requires` and `provides`.
        The analyzer topologically sorts rules and SKIPS those with unmet requirements.
        
        Built-in capabilities:
        - "sql_ast": SQL AST is available (parsed with pglast or sqlparse)
        - "sql_ast_high": SQL AST with HIGH confidence (pglast)
        - "db_probe": Database probe is available for validation
        - "prior_findings": Findings from PER_NODE phase (automatic for AGGREGATE)
    
    Example:
        class SeqScanConfig(RuleConfig):
            threshold_rows: int = 10_000
        
        class SeqScanLargeTable(Rule):
            rule_id = "SEQ_SCAN_LARGE_TABLE"
            version = "1.0.0"
            severity = Severity.WARNING
            phase = RulePhase.PER_NODE
            config_schema = SeqScanConfig
            
            # Only run if we have SQL AST for better recommendations
            requires: tuple[str, ...] = ()  # No requirements (runs always)
            provides: tuple[str, ...] = ("seq_scan_findings",)
            
            def analyze(self, explain, prior_findings=[]) -> list[Finding]:
                if node.actual_rows > self.config.threshold_rows:
                    # ... detection logic ...
        
        class IndexValidator(Rule):
            rule_id = "INDEX_VALIDATOR"
            phase = RulePhase.AGGREGATE
            
            # Requires DB probe to validate index recommendations
            requires: tuple[str, ...] = ("db_probe", "seq_scan_findings")
            provides: tuple[str, ...] = ("validated_indexes",)
    """
    
    # Subclasses must define these
    rule_id: str
    version: str = "1.0.0"
    severity: Severity
    description: str = ""
    
    # Configuration schema (subclasses can override)
    config_schema: type[RuleConfig] = RuleConfig
    
    # Execution phase (subclasses can override)
    phase: RulePhase = RulePhase.PER_NODE
    
    # Dependency DAG: what this rule requires and provides
    requires: tuple[str, ...] = ()  # Capabilities this rule needs
    provides: tuple[str, ...] = ()  # Capabilities this rule provides
    
    def __init__(self, config: RuleConfig | dict[str, Any] | None = None) -> None:
        """
        Initialize the rule with configuration.
        
        Args:
            config: Configuration as RuleConfig instance, dict, or None for defaults.
                    If dict, it's validated against config_schema.
        """
        if config is None:
            self.config = self.config_schema()
        elif isinstance(config, dict):
            self.config = self.config_schema(**config)
        else:
            self.config = config
    
    @abstractmethod
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Analyze an EXPLAIN output and return findings.
        
        This is the simple interface for basic rules. Override this
        for rules that only need the explain plan and prior findings.
        
        Args:
            explain: Parsed EXPLAIN output to analyze
            prior_findings: Findings from earlier phases (for AGGREGATE rules).
                Empty list for PER_NODE rules.
            
        Returns:
            List of findings, or empty list if no issues detected.
            Findings should use self.severity unless there's a reason
            to override (e.g., escalate to CRITICAL for extreme cases).
        """
        pass
    
    def analyze_with_context(
        self,
        ctx: RuleContext,
    ) -> list[Finding]:
        """
        Analyze with full context (advanced rules).
        
        Override this for rules that need schema information, historical
        data, or other context beyond the explain plan.
        
        By default, delegates to analyze() for backward compatibility.
        
        Args:
            ctx: Full rule context including explain, schema, history, etc.
            
        Returns:
            List of findings, or empty list if no issues detected.
            
        Example:
            def analyze_with_context(self, ctx: RuleContext) -> list[Finding]:
                findings = []
                
                for path, node, parent in self.iter_nodes_with_parent(ctx.explain):
                    if node.node_type == "Seq Scan" and node.relation_name:
                        # Check if indexes exist
                        table_info = ctx.get_table_info(node.relation_name)
                        if table_info and table_info.indexes:
                            findings.append(Finding(
                                rule_id="UNUSED_INDEX",
                                title=f"Seq scan despite existing indexes",
                                ...
                            ))
                
                return findings
        """
        # Default: delegate to simple analyze() for backward compatibility
        return self.analyze(ctx.explain, ctx.prior_findings)
    
    @property
    def uses_context(self) -> bool:
        """
        Check if this rule overrides analyze_with_context.
        
        Used by the analyzer to determine whether to pass full context.
        """
        # Check if analyze_with_context is overridden
        return type(self).analyze_with_context is not Rule.analyze_with_context
    
    def iter_nodes(
        self, explain: "ExplainOutput"
    ) -> Iterator[tuple[NodePath, "PlanNode"]]:
        """
        Iterate over all nodes with their paths.
        
        This is the recommended way to traverse the plan tree.
        It's O(n) and provides the path without reconstruction.
        
        Args:
            explain: The EXPLAIN output to traverse
            
        Yields:
            (NodePath, PlanNode) tuples in depth-first order
            
        Example:
            for path, node in self.iter_nodes(explain):
                if node.node_type == "Seq Scan":
                    findings.append(Finding(context=NodeContext.from_node(node, path), ...))
        """
        yield from traverse_with_path(explain.plan)
    
    def iter_nodes_with_parent(
        self, explain: "ExplainOutput"
    ) -> Iterator[tuple[NodePath, "PlanNode", "PlanNode | None"]]:
        """
        Iterate over all nodes with their paths and parent nodes.
        
        Useful for creating NodeContext with parent information.
        
        Args:
            explain: The EXPLAIN output to traverse
            
        Yields:
            (NodePath, PlanNode, parent_PlanNode_or_None) tuples in depth-first order
        """
        
        def _traverse(
            node: "PlanNode",
            path: NodePath,
            parent: "PlanNode | None",
        ) -> Iterator[tuple[NodePath, "PlanNode", "PlanNode | None"]]:
            yield path, node, parent
            
            if node.plans:
                for i, child in enumerate(node.plans):
                    child_path = path.child(i)
                    yield from _traverse(child, child_path, node)
        
        yield from _traverse(explain.plan, NodePath.root(), None)
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(rule_id={self.rule_id!r}, version={self.version!r}, phase={self.phase.name})"


def discover_rules() -> list[Any]:
    """
    Discover all Rule subclasses in the rules module.
    
    Used for dynamically loading rules without hardcoding imports.
    
    Returns:
        List of Rule subclasses (not instances). Return type is Any
        to work around mypy's strict handling of abstract classes.
    """
    # Import all rule modules to register subclasses
    # Add imports here as new rules are created:
    # from querysense.analyzer.rules import seq_scan_large_table
    
    # Return all concrete subclasses
    return [cls for cls in Rule.__subclasses__() if not cls.__name__.startswith("_")]
