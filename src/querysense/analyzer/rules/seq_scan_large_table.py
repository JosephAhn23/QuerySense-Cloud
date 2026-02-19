"""
Rule: Sequential Scan on Large Table

Detects sequential scans that read a large number of rows, which often
indicates a missing index. This is one of the most common performance
issues in PostgreSQL queries.

Why it matters:
- Sequential scans read every row in the table
- O(n) performance degrades as table grows
- Index scans are O(log n) and much faster for selective queries

When it's okay:
- Small tables (< 10K rows) where index overhead isn't worth it
- Queries that need most of the table anyway
- Tables that are mostly in cache

SQL Enhancement:
This rule implements the SQLEnhanceable protocol to provide better
index recommendations when the original SQL query is available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import Field, model_validator

from querysense.analyzer.index_advisor import (
    CostEstimator,
    IndexRecommendation,
    IndexRecommender,
    IndexType,
)
from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig, SQLEnhanceable

if TYPE_CHECKING:
    from querysense.analyzer.sql_ast import QueryInfo
    from querysense.parser.models import ExplainOutput, PlanNode


class SeqScanConfig(RuleConfig):
    """
    Configuration for sequential scan detection.
    
    Attributes:
        threshold_rows: Minimum rows to trigger WARNING (default 10,000)
        critical_threshold_rows: Minimum rows to escalate to CRITICAL (default 1,000,000)
    """
    
    threshold_rows: int = Field(
        default=10_000,
        ge=100,
        le=10_000_000,
        description="Minimum rows to trigger a warning",
    )
    
    critical_threshold_rows: int = Field(
        default=1_000_000,
        ge=1_000,
        le=100_000_000,
        description="Minimum rows to escalate to CRITICAL severity",
    )
    
    @model_validator(mode="after")
    def validate_thresholds(self) -> "SeqScanConfig":
        """Ensure critical threshold is greater than warning threshold."""
        if self.critical_threshold_rows <= self.threshold_rows:
            raise ValueError(
                f"critical_threshold_rows ({self.critical_threshold_rows}) "
                f"must be greater than threshold_rows ({self.threshold_rows})"
            )
        return self


@register_rule
class SeqScanLargeTable(Rule, SQLEnhanceable):
    """
    Detect sequential scans on tables exceeding a row threshold.
    
    Uses SeqScanConfig for user-configurable thresholds.
    
    Implements SQLEnhanceable to provide enhanced index recommendations
    when the original SQL query is available.
    """
    
    rule_id = "SEQ_SCAN_LARGE_TABLE"
    version = "2.1.0"  # Bumped for SQLEnhanceable
    severity = Severity.WARNING
    description = "Detects sequential scans on tables over a configurable threshold"
    config_schema = SeqScanConfig
    phase = RulePhase.PER_NODE  # Analyze individual nodes
    
    # Keep backward compatibility with direct threshold arguments
    def __init__(
        self,
        config: RuleConfig | dict[str, Any] | None = None,
        *,
        threshold_rows: int | None = None,
        critical_threshold: int | None = None,
    ) -> None:
        """
        Initialize the rule with configuration.
        
        Args:
            config: Configuration object or dict. Preferred method.
            threshold_rows: Legacy parameter, use config instead.
            critical_threshold: Legacy parameter, use config instead.
        """
        # Handle legacy parameters
        if config is None and (threshold_rows is not None or critical_threshold is not None):
            config_dict: dict[str, Any] = {}
            if threshold_rows is not None:
                config_dict["threshold_rows"] = threshold_rows
            if critical_threshold is not None:
                config_dict["critical_threshold_rows"] = critical_threshold
            super().__init__(config_dict)
        else:
            super().__init__(config)
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Find sequential scans exceeding the row threshold.
        
        Args:
            explain: Parsed EXPLAIN output
            prior_findings: Not used (PER_NODE rule)
            
        Returns:
            List of findings for each problematic sequential scan
        """
        # Type-safe config access
        config: SeqScanConfig = self.config  # type: ignore[assignment]
        
        findings: list[Finding] = []
        
        # Use iter_nodes_with_parent to get parent context
        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Only check Seq Scan nodes
            if node.node_type != "Seq Scan":
                continue
            
            # Need ANALYZE data to know actual rows
            actual_rows = node.actual_rows
            if actual_rows is None:
                continue
            
            # Check threshold
            if actual_rows < config.threshold_rows:
                continue
            
            # Determine severity based on configured thresholds
            severity = (
                Severity.CRITICAL
                if actual_rows >= config.critical_threshold_rows
                else self.severity
            )
            
            # Get table name (might be None for subqueries)
            table_name = node.relation_name or "unknown table"
            
            # Build NodeContext with full information
            context = NodeContext.from_node(node, path, parent)
            
            # Calculate selectivity and improvement estimate
            rows_removed = node.rows_removed_by_filter or 0
            total_before = actual_rows + rows_removed
            selectivity = actual_rows / total_before if total_before > 0 else 1.0
            
            estimated_improvement = 1.0
            if selectivity < 0.5 and total_before > 0:
                estimated_improvement = CostEstimator.estimate_improvement(
                    total_before, actual_rows, node.total_cost
                )
            
            # Build the finding with full context
            finding = Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Seq Scan on {table_name} (cost={node.total_cost:,.0f}, {actual_rows:,} rows)",
                description=self._build_description(node, actual_rows),
                suggestion=self._build_suggestion(node),
                metrics={
                    "rows_scanned": actual_rows,
                    "rows_removed_by_filter": rows_removed,
                    "total_cost": node.total_cost,
                    "startup_cost": node.startup_cost,
                    "selectivity": round(selectivity, 4),
                    "estimated_improvement": round(estimated_improvement, 2),
                },
            )
            findings.append(finding)
        
        return findings
    
    def _build_description(self, node: "PlanNode", actual_rows: int) -> str:
        """Build a detailed description with cost analysis."""
        table = node.relation_name or "unknown"
        parts = [
            f"Sequential scan on '{table}' "
            f"(cost={node.total_cost:,.2f}, {actual_rows:,} rows)"
        ]
        
        if node.filter:
            parts.append(f"\nFilter: {node.filter}")
            
        if node.rows_removed_by_filter:
            total_before = actual_rows + node.rows_removed_by_filter
            selectivity = actual_rows / total_before if total_before > 0 else 1.0
            
            parts.append(
                f"\nSelectivity: {selectivity:.2%} "
                f"({actual_rows:,} matching / {total_before:,} scanned)"
            )
            
            if selectivity < 0.1:
                # Very selective - index would help a lot
                # Estimate improvement
                estimated_improvement = CostEstimator.estimate_improvement(
                    total_before, actual_rows, node.total_cost
                )
                parts.append(
                    f"\nEstimated index improvement: {estimated_improvement:.1f}x faster"
                )
            elif selectivity < 0.5:
                parts.append("\nModerate selectivity - index may help.")
            else:
                parts.append(
                    "\nLow selectivity - index may not help (too many rows match)."
                )
        
        return "".join(parts)
    
    def _build_suggestion(self, node: "PlanNode") -> str | None:
        """Build an actionable suggestion with cost analysis."""
        if not node.relation_name:
            return None
        
        # Use the smart IndexRecommender for detailed analysis
        recommender = IndexRecommender()
        recommendations = recommender.analyze_node(node)
        
        if recommendations:
            # Use the best recommendation
            rec = recommendations[0]
            return rec.format_full()
        
        # Fallback if no filter to analyze
        table = node.relation_name
        docs_url = "https://www.postgresql.org/docs/current/indexes-types.html"
        
        if node.filter:
            return (
                f"-- Add an index on {table} for the filtered column(s)\n"
                f"-- Filter: {node.filter}\n"
                f"-- Docs: {docs_url}"
            )
        
        return (
            f"-- Consider whether all rows from {table} are needed.\n"
            f"-- If filtering is possible, add a WHERE clause and corresponding index.\n"
            f"-- Docs: {docs_url}"
        )
    
    def enhance_with_sql(
        self,
        finding: Finding,
        query_info: "QueryInfo",
    ) -> Finding:
        """
        Enhance finding with SQL-based index recommendations.
        
        When the original SQL query is available, we can provide much more
        specific index recommendations including:
        - Composite indexes covering multiple columns
        - Correct column ordering (equality first, then range, then sort)
        - Better column names (not just parsed from filter strings)
        
        Args:
            finding: The original finding from this rule
            query_info: Parsed information about the SQL query
            
        Returns:
            Enhanced finding with better index suggestion
        """
        table = finding.context.relation_name
        if not table:
            return finding
        
        # Get recommended columns from SQL analysis
        columns = query_info.suggest_composite_index(table)
        
        if not columns:
            return finding
        
        # Build enhanced recommendation
        rec = IndexRecommendation(
            table=table,
            columns=columns,
            index_type=IndexType.BTREE,
            estimated_improvement=finding.metrics.get("estimated_improvement", 1.0),
            reasoning=self._build_sql_reasoning(query_info, table, columns),
        )
        
        # Return new finding with enhanced suggestion
        return finding.model_copy(update={
            "suggestion": rec.format_full(),
        })
    
    def _build_sql_reasoning(
        self,
        query_info: "QueryInfo",
        table: str,
        columns: list[str],
    ) -> str:
        """Build reasoning based on SQL analysis."""
        parts: list[str] = ["Based on SQL query analysis:"]
        
        filter_cols = [
            c for c in query_info.filter_columns
            if c.table == table or c.table is None
        ]
        join_cols = [
            c for c in query_info.join_columns
            if c.table == table or c.table is None
        ]
        order_cols = [
            c for c in query_info.order_by_columns
            if c.table == table or c.table is None
        ]
        
        if filter_cols:
            equality = [c.column for c in filter_cols if c.is_equality]
            ranges = [c.column for c in filter_cols if c.is_range]
            if equality:
                parts.append(f"- Equality filters on: {', '.join(equality)}")
            if ranges:
                parts.append(f"- Range filters on: {', '.join(ranges)}")
        
        if join_cols:
            parts.append(f"- Join columns: {', '.join(c.column for c in join_cols)}")
        
        if order_cols:
            parts.append(f"- Sort columns: {', '.join(c.column for c in order_cols)}")
        
        parts.append("")
        parts.append(f"Recommended column order: {', '.join(columns)}")
        parts.append("(Equality columns first, then range, then sort)")
        
        return "\n".join(parts)