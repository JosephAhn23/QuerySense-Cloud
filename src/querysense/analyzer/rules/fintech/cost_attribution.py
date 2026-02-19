"""
Query Cost Attribution for Fintech.

Calculates actual $ cost per query execution, making performance
optimization ROI visible to finance teams.

Cost factors:
- CPU time × cloud instance cost per second
- I/O operations × storage IOPS cost
- Memory usage × RAM cost
- Execution frequency × total daily cost
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.path import NodePath
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class CostAttributionConfig(RuleConfig):
    """Configuration for cost calculation."""
    
    # Cloud pricing (AWS defaults, adjust per provider)
    cpu_cost_per_second: float = Field(
        default=0.0001,
        ge=0.0,
        description="$ cost per CPU-second (m5.xlarge = $0.192/hr ≈ $0.0000533/s)"
    )
    io_cost_per_block: float = Field(
        default=0.000001,
        ge=0.0,
        description="$ cost per 8KB block read (gp3 IOPS cost)"
    )
    memory_cost_per_mb_second: float = Field(
        default=0.00000001,
        ge=0.0,
        description="$ cost per MB-second of memory"
    )
    
    # Execution frequency assumptions
    default_daily_executions: int = Field(
        default=1000,
        ge=1,
        description="Assumed daily executions if not provided"
    )
    
    # Thresholds for alerts
    cost_per_execution_threshold: float = Field(
        default=0.01,
        ge=0.0,
        description="$ threshold per execution to trigger warning"
    )
    daily_cost_threshold: float = Field(
        default=100.0,
        ge=0.0,
        description="$ daily threshold to trigger critical"
    )


class HighCostQuery(Rule):
    """
    Calculate and flag high-cost queries.
    
    Makes performance optimization ROI visible:
    - Shows $ cost per query execution
    - Projects daily/monthly/annual costs
    - Estimates savings from optimization
    
    Example output:
    {
        "cost_per_execution": "$0.023",
        "daily_cost": "$230",
        "annual_cost": "$83,950",
        "optimization_savings": "$71,357/year (85% reduction)"
    }
    """
    
    rule_id = "FINTECH_HIGH_COST_QUERY"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Query has high execution cost with optimization potential"
    config_schema = CostAttributionConfig
    phase = RulePhase.AGGREGATE
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Calculate query cost and flag if above threshold."""
        findings: list[Finding] = []
        config: CostAttributionConfig = self.config  # type: ignore
        
        root = explain.plan
        if not root.has_analyze_data:
            return []  # Need EXPLAIN ANALYZE for accurate costing
        
        # Calculate cost components
        cost_breakdown = self._calculate_cost(explain, config)
        cost_per_execution = cost_breakdown["total"]
        
        # Check thresholds
        daily_executions = config.default_daily_executions
        daily_cost = cost_per_execution * daily_executions
        annual_cost = daily_cost * 365
        
        if cost_per_execution >= config.cost_per_execution_threshold:
            severity = Severity.CRITICAL if daily_cost >= config.daily_cost_threshold else Severity.WARNING
            
            # Estimate optimization potential
            optimization_potential = self._estimate_optimization_savings(
                explain, cost_per_execution, prior_findings or []
            )
            
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=NodeContext(
                    path=NodePath.root(),
                    node_type=root.node_type,
                    relation_name=root.relation_name,
                    actual_rows=root.actual_rows,
                    plan_rows=root.plan_rows,
                    total_cost=root.total_cost,
                    depth=0,
                ),
                title=f"High-cost query: ${cost_per_execution:.4f}/execution (${annual_cost:,.0f}/year)",
                description=(
                    f"Cost breakdown: "
                    f"CPU ${cost_breakdown['cpu']:.4f}, "
                    f"I/O ${cost_breakdown['io']:.4f}, "
                    f"Memory ${cost_breakdown['memory']:.4f}. "
                    f"At {daily_executions:,} executions/day, this costs ${daily_cost:.2f}/day. "
                    f"Optimization could save {optimization_potential['savings_percent']:.0f}% "
                    f"(${optimization_potential['annual_savings']:,.0f}/year)."
                ),
                suggestion=self._generate_cost_optimization(explain, cost_breakdown),
                metrics={
                    "cost_per_execution_cents": int(cost_per_execution * 100),
                    "daily_cost_dollars": int(daily_cost),
                    "annual_cost_dollars": int(annual_cost),
                    "potential_savings_percent": int(optimization_potential['savings_percent']),
                },
            ))
        
        return findings
    
    def _calculate_cost(
        self,
        explain: "ExplainOutput",
        config: CostAttributionConfig
    ) -> dict[str, float]:
        """Calculate cost breakdown for a query."""
        root = explain.plan
        
        # CPU cost: based on execution time
        execution_time_s = (root.total_actual_time or 0.0) / 1000.0
        cpu_cost = execution_time_s * config.cpu_cost_per_second
        
        # I/O cost: based on buffer reads
        total_blocks = 0
        for node in explain.all_nodes:
            # Shared buffers read from disk
            shared_read = getattr(node, 'shared_blks_read', 0) or 0
            # Temp buffers (spilling to disk)
            temp_read = getattr(node, 'temp_blks_read', 0) or 0
            temp_written = getattr(node, 'temp_blks_written', 0) or 0
            total_blocks += shared_read + temp_read + temp_written
        
        io_cost = total_blocks * config.io_cost_per_block
        
        # Memory cost: based on work_mem usage (estimated from sort/hash sizes)
        memory_mb = 0.0
        for node in explain.all_nodes:
            # Peak memory from sorts/hashes
            if hasattr(node, 'peak_memory_usage'):
                memory_mb += (getattr(node, 'peak_memory_usage', 0) or 0) / 1024
            # Estimate from row counts for hash operations
            if 'Hash' in node.node_type and node.actual_rows:
                memory_mb += node.actual_rows * 0.0001  # ~100 bytes per row estimate
        
        memory_cost = memory_mb * execution_time_s * config.memory_cost_per_mb_second
        
        return {
            "cpu": cpu_cost,
            "io": io_cost,
            "memory": memory_cost,
            "total": cpu_cost + io_cost + memory_cost,
        }
    
    def _estimate_optimization_savings(
        self,
        explain: "ExplainOutput",
        current_cost: float,
        prior_findings: list[Finding]
    ) -> dict[str, float]:
        """Estimate potential savings from optimization."""
        # Base savings estimate on detected issues
        savings_percent = 0.0
        
        # Check for common optimizable patterns
        for node in explain.all_nodes:
            if node.node_type == "Seq Scan" and (node.actual_rows or 0) > 10000:
                savings_percent += 70.0  # Index can reduce 70%+
            if "Sort" in node.node_type:
                sort_method = getattr(node, 'sort_method', '')
                if 'external' in str(sort_method).lower():
                    savings_percent += 30.0  # work_mem increase
        
        # Check prior findings for optimization opportunities
        for finding in prior_findings:
            if "SEQ_SCAN" in finding.rule_id:
                savings_percent += 50.0
            if "SPILLING" in finding.rule_id:
                savings_percent += 20.0
        
        # Cap at 90%
        savings_percent = min(savings_percent, 90.0)
        
        config: CostAttributionConfig = self.config  # type: ignore
        daily_executions = config.default_daily_executions
        annual_cost = current_cost * daily_executions * 365
        annual_savings = annual_cost * (savings_percent / 100.0)
        
        return {
            "savings_percent": savings_percent,
            "annual_savings": annual_savings,
        }
    
    def _generate_cost_optimization(
        self,
        explain: "ExplainOutput",
        cost_breakdown: dict[str, float]
    ) -> str:
        """Generate cost-focused optimization suggestions."""
        suggestions = ["-- Query Cost Optimization Plan"]
        
        # Prioritize by cost component
        if cost_breakdown["io"] > cost_breakdown["cpu"]:
            suggestions.append("-- PRIMARY: Reduce I/O (largest cost driver)")
            suggestions.append("-- Add covering indexes to eliminate table lookups")
            suggestions.append("-- Consider partitioning for large tables")
        else:
            suggestions.append("-- PRIMARY: Reduce CPU time")
            suggestions.append("-- Add indexes on filter/join columns")
            suggestions.append("-- Simplify complex expressions")
        
        # Specific fixes based on plan
        for node in explain.all_nodes:
            if node.node_type == "Seq Scan" and node.relation_name:
                suggestions.append(
                    f"CREATE INDEX idx_{node.relation_name}_cost "
                    f"ON {node.relation_name}(<filter_columns>);  -- Est. 70% cost reduction"
                )
                break
        
        suggestions.append("")
        suggestions.append("-- ROI: Optimization time (4 hours) × developer rate ($100/hr) = $400")
        suggestions.append(f"-- Annual savings: ${cost_breakdown['total'] * 1000 * 365 * 0.7:,.0f}")
        suggestions.append("-- Payback period: < 1 day")
        
        return "\n".join(suggestions)
