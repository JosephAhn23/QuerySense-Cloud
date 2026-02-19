"""
Rule: Correlated Subquery (Inefficient SubPlan)

Detects correlated subqueries that execute once per outer row,
causing O(n*m) performance when a JOIN would be O(n+m).

Why it matters:
- SubPlan nodes with loops = outer row count execute the subquery repeatedly
- A 10K row outer table with a subquery = 10K subquery executions
- JOINs, CTEs, or LATERAL can often achieve the same result more efficiently

When it's okay:
- Very small outer result sets (< 100 rows)
- Subquery is extremely cheap (index lookup returning 1 row)
- EXISTS/NOT EXISTS with proper indexing (can be optimized)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput, PlanNode


class CorrelatedSubqueryConfig(RuleConfig):
    """
    Configuration for correlated subquery detection.
    
    Attributes:
        min_loops: Minimum loop count to flag (default 100)
        critical_loops: Loop count to escalate to CRITICAL (default 10,000)
    """
    
    min_loops: int = Field(
        default=100,
        ge=10,
        le=100_000,
        description="Minimum loop count to trigger warning",
    )
    
    critical_loops: int = Field(
        default=10_000,
        ge=100,
        description="Loop count to escalate to CRITICAL",
    )


@register_rule
class CorrelatedSubquery(Rule):
    """
    Detect correlated subqueries executed many times.
    
    Looks for SubPlan nodes (scalar subqueries in WHERE/SELECT) that
    have high loop counts, indicating they're executed once per outer row.
    """
    
    rule_id = "CORRELATED_SUBQUERY"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects correlated subqueries executed once per outer row"
    config_schema = CorrelatedSubqueryConfig
    phase = RulePhase.PER_NODE
    
    # Node types that indicate subquery execution
    SUBPLAN_TYPES = {"SubPlan", "InitPlan", "Subquery Scan"}
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Find subqueries with high loop counts.
        
        Args:
            explain: Parsed EXPLAIN output
            prior_findings: Not used (PER_NODE rule)
            
        Returns:
            List of findings for problematic subqueries
        """
        config: CorrelatedSubqueryConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []
        
        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Check for SubPlan pattern
            # In EXPLAIN, SubPlans appear as child nodes with high loop counts
            # Also check for "SubPlan" in node extras or parent relationship
            
            if not self._is_subplan_like(node, parent):
                continue
            
            # Need ANALYZE data
            if node.actual_loops is None:
                continue
            
            loops = node.actual_loops
            
            # Skip low loop counts
            if loops < config.min_loops:
                continue
            
            # Calculate total work
            rows_per_loop = node.actual_rows or 0
            total_rows = rows_per_loop * loops
            
            # Determine severity
            if loops >= config.critical_loops:
                severity = Severity.CRITICAL
            else:
                severity = self.severity
            
            context = NodeContext.from_node(node, path, parent)
            
            finding = Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Subquery executed {loops:,} times ({total_rows:,} total rows)",
                description=self._build_description(node, loops, total_rows),
                suggestion=self._build_suggestion(node, parent),
                metrics={
                    "loops": loops,
                    "rows_per_loop": rows_per_loop,
                    "total_rows": total_rows,
                },
            )
            findings.append(finding)
        
        return findings
    
    def _is_subplan_like(self, node: "PlanNode", parent: "PlanNode | None") -> bool:
        """Check if node represents a subplan/subquery pattern."""
        # Direct SubPlan types
        if node.node_type in self.SUBPLAN_TYPES:
            return True
        
        # Check for SubPlan name in extras
        if node.model_extra:
            subplan_name = node.model_extra.get("Subplan Name")
            if subplan_name:
                return True
            # Also check Parent Relationship
            parent_rel = node.model_extra.get("Parent Relationship")
            if parent_rel in ("SubPlan", "InitPlan"):
                return True
        
        return False
    
    def _build_description(
        self,
        node: "PlanNode",
        loops: int,
        total_rows: int,
    ) -> str:
        """Build description of the subquery problem."""
        parts = [
            f"This subquery was executed {loops:,} times, "
            f"processing {total_rows:,} total rows."
        ]
        
        if loops >= 1000:
            parts.append(
                "Correlated subqueries in WHERE or SELECT clauses run once per outer row. "
                "This creates O(n*m) complexity instead of O(n+m) for equivalent JOINs."
            )
        
        if node.node_type == "Seq Scan":
            parts.append(
                "The subquery uses a sequential scan, making each execution expensive."
            )
        
        return " ".join(parts)
    
    def _build_suggestion(
        self,
        node: "PlanNode",
        parent: "PlanNode | None",
    ) -> str:
        """Build suggestion for rewriting the subquery."""
        lines = [
            "-- Rewrite as JOIN (usually fastest):",
            "-- Before: SELECT * FROM orders WHERE customer_id IN (SELECT id FROM customers WHERE active)",
            "-- After:  SELECT o.* FROM orders o JOIN customers c ON o.customer_id = c.id WHERE c.active",
            "",
            "-- Or use a CTE for complex subqueries:",
            "-- WITH active_customers AS (",
            "--     SELECT id FROM customers WHERE active",
            "-- )",
            "-- SELECT * FROM orders WHERE customer_id IN (SELECT id FROM active_customers)",
            "",
            "-- For EXISTS patterns, ensure the subquery has an index:",
            "-- CREATE INDEX idx_customers_active ON customers(active) WHERE active = true;",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/queries-table-expressions.html#QUERIES-LATERAL",
        ]
        
        return "\n".join(lines)
