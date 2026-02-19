"""
Rule: Nested Loop Join on Large Tables

Detects nested loop joins where the inner relation is scanned many times
with a large number of rows, indicating O(n*m) performance problems.

Why it matters:
- Nested loops execute inner child once per outer row
- With 10K outer rows and 10K inner rows = 100M comparisons
- Hash or Merge joins are O(n+m) and much faster for large tables

When it's okay:
- Small inner tables (< 1000 rows)
- When inner is an index scan with high selectivity
- When outer table has very few rows
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import Field

from querysense.analyzer.index_advisor import IndexRecommender
from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput, PlanNode


class NestedLoopConfig(RuleConfig):
    """
    Configuration for nested loop detection.
    
    Attributes:
        min_inner_rows: Minimum inner rows to trigger (default 1,000)
        min_outer_loops: Minimum outer loop iterations (default 100)
        critical_product_threshold: Row product for CRITICAL severity (default 10M)
    """
    
    min_inner_rows: int = Field(
        default=1_000,
        ge=10,
        le=1_000_000,
        description="Minimum inner rows per loop to trigger warning",
    )
    
    min_outer_loops: int = Field(
        default=100,
        ge=1,
        le=100_000,
        description="Minimum outer loop count to trigger warning",
    )
    
    critical_product_threshold: int = Field(
        default=10_000_000,
        ge=100_000,
        description="Total row product (inner * outer) to escalate to CRITICAL",
    )


@register_rule
class NestedLoopLargeTable(Rule):
    """
    Detect nested loop joins scanning large tables repeatedly.
    
    Nested loops are efficient for small tables or when the inner side
    uses an efficient index. They become problematic when:
    - The inner side is a sequential scan on a large table
    - The outer side produces many rows, causing many iterations
    """
    
    rule_id = "NESTED_LOOP_LARGE_TABLE"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects nested loop joins on large tables (O(n*m) problem)"
    config_schema = NestedLoopConfig
    phase = RulePhase.PER_NODE
    
    def __init__(
        self,
        config: RuleConfig | dict[str, Any] | None = None,
    ) -> None:
        """Initialize the rule with configuration."""
        super().__init__(config)
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Find nested loops with large inner scans.
        
        Args:
            explain: Parsed EXPLAIN output
            prior_findings: Not used (PER_NODE rule)
            
        Returns:
            List of findings for problematic nested loops
        """
        config: NestedLoopConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []
        
        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Only check Nested Loop nodes
            if node.node_type != "Nested Loop":
                continue
            
            # Need ANALYZE data
            if node.actual_loops is None:
                continue
            
            # Get the inner child (second child in the plans list)
            # In PostgreSQL, nested loop children are: [outer, inner]
            if len(node.plans) < 2:
                continue
            
            inner_child = node.plans[1]
            
            # Need inner child ANALYZE data
            if inner_child.actual_rows is None or inner_child.actual_loops is None:
                continue
            
            inner_rows = inner_child.actual_rows
            outer_loops = inner_child.actual_loops  # Inner executes once per outer row
            
            # Check thresholds
            if inner_rows < config.min_inner_rows:
                continue
            if outer_loops < config.min_outer_loops:
                continue
            
            # Calculate total row product
            total_rows = inner_rows * outer_loops
            
            # Determine severity
            if total_rows >= config.critical_product_threshold:
                severity = Severity.CRITICAL
            else:
                severity = self.severity
            
            # Get table info
            inner_table = self._get_inner_table_name(inner_child)
            
            # Build context
            context = NodeContext.from_node(node, path, parent)
            
            finding = Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Nested loop scans {inner_table} {outer_loops:,}x ({total_rows:,} total rows)",
                description=self._build_description(inner_child, inner_rows, outer_loops, total_rows),
                suggestion=self._build_suggestion(node, inner_child),
                metrics={
                    "inner_rows_per_loop": inner_rows,
                    "outer_loops": outer_loops,
                    "total_rows_scanned": total_rows,
                    "inner_node_type": inner_child.node_type,
                },
            )
            findings.append(finding)
        
        return findings
    
    def _get_inner_table_name(self, inner_child: "PlanNode") -> str:
        """Extract table name from inner child, traversing down if needed."""
        if inner_child.relation_name:
            return inner_child.relation_name
        
        # Check children (e.g., for Materialize -> Seq Scan)
        for child in inner_child.plans:
            if child.relation_name:
                return child.relation_name
        
        return "inner table"
    
    def _build_description(
        self,
        inner_child: "PlanNode",
        inner_rows: int,
        outer_loops: int,
        total_rows: int,
    ) -> str:
        """Build detailed description of the problem."""
        parts = [
            f"Nested loop join executes {outer_loops:,} iterations, "
            f"scanning {inner_rows:,} rows each time for {total_rows:,} total row accesses."
        ]
        
        if inner_child.node_type == "Seq Scan":
            parts.append(
                "The inner side is a sequential scan, which is very expensive "
                "when executed many times."
            )
        elif inner_child.node_type == "Materialize":
            parts.append(
                "PostgreSQL materialized the inner result to avoid re-scanning, "
                "but this still uses significant memory."
            )
        
        if total_rows > 1_000_000:
            parts.append(
                "Consider converting to a Hash Join or Merge Join, "
                "which are O(n+m) instead of O(n*m)."
            )
        
        return " ".join(parts)
    
    def _build_suggestion(
        self,
        node: "PlanNode",
        inner_child: "PlanNode",
    ) -> str:
        """Build actionable suggestion with smart index recommendation."""
        # Use IndexRecommender for smart analysis
        recommender = IndexRecommender()
        recommendations = recommender._analyze_nested_loop(node)
        
        if recommendations:
            return recommendations.format_full()
        
        # Fallback if no specific recommendation
        lines: list[str] = []
        inner_table = self._get_inner_table_name(inner_child)
        
        if inner_child.node_type == "Seq Scan":
            if node.model_extra:
                join_filter = node.model_extra.get("Join Filter")
                if join_filter:
                    lines.append(f"-- Join condition: {join_filter}")
            
            lines.append(f"-- Add an index on {inner_table} for the join column:")
            lines.append(f"CREATE INDEX idx_{inner_table}_<join_column> ON {inner_table}(<join_column>);")
        else:
            lines.append("-- Consider restructuring the query to enable Hash Join:")
            lines.append("SET enable_nestloop = off;  -- Test if Hash Join is faster")
        
        lines.append("")
        lines.append("-- Or increase work_mem to favor hash-based joins:")
        lines.append("SET work_mem = '256MB';")
        lines.append("")
        lines.append("-- Docs: https://www.postgresql.org/docs/current/planner-optimizer.html")
        
        return "\n".join(lines)
