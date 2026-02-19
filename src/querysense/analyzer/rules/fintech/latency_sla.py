"""
Latency SLA Breach Detection for Fintech.

Detects queries that exceed latency thresholds critical to financial operations:
- Trading queries: 50ms (missed trades cost money)
- Fraud detection: 100ms (false negatives = losses)
- Payment authorization: 200ms (customer abandonment)
- Reporting: 5000ms (compliance deadlines)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.path import NodePath
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class LatencySLAConfig(RuleConfig):
    """Configuration for latency SLA thresholds."""
    
    # SLA thresholds in milliseconds by query type
    trading_sla_ms: float = Field(default=50.0, ge=1.0, description="Trading query SLA")
    fraud_sla_ms: float = Field(default=100.0, ge=1.0, description="Fraud detection SLA")
    payment_sla_ms: float = Field(default=200.0, ge=1.0, description="Payment auth SLA")
    reporting_sla_ms: float = Field(default=5000.0, ge=1.0, description="Reporting SLA")
    default_sla_ms: float = Field(default=500.0, ge=1.0, description="Default SLA")
    
    # Financial impact estimation
    cost_per_ms_delay: float = Field(
        default=0.10,
        ge=0.0,
        description="Estimated $ cost per millisecond of delay"
    )
    
    # Query type detection keywords
    trading_keywords: list[str] = Field(
        default=["market_data", "quotes", "prices", "orders", "trades", "positions"],
        description="Table names indicating trading queries"
    )
    fraud_keywords: list[str] = Field(
        default=["transactions", "fraud", "risk_score", "alerts", "suspicious"],
        description="Table names indicating fraud detection"
    )
    payment_keywords: list[str] = Field(
        default=["payments", "authorization", "settlements", "transfers"],
        description="Table names indicating payment processing"
    )


class LatencySLABreach(Rule):
    """
    Detect queries that breach fintech latency SLAs.
    
    In fintech, latency isn't just UX - it's money:
    - Trading: 50ms delay = missed arbitrage opportunity
    - Fraud: 100ms delay = transaction approved before fraud flagged
    - Payments: 200ms delay = 7% increase in cart abandonment
    
    This rule:
    1. Detects query type from table names
    2. Applies appropriate SLA threshold
    3. Calculates financial impact of breach
    4. Suggests specific optimization
    """
    
    rule_id = "FINTECH_LATENCY_SLA_BREACH"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Query execution time exceeds fintech SLA threshold"
    config_schema = LatencySLAConfig
    phase = RulePhase.AGGREGATE  # Needs full plan context
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Analyze query for SLA breaches."""
        findings: list[Finding] = []
        config: LatencySLAConfig = self.config  # type: ignore
        
        # Get execution time from plan
        root = explain.plan
        if not root.has_analyze_data:
            return []  # Need EXPLAIN ANALYZE for timing
        
        # Total execution time in ms
        execution_time_ms = root.total_actual_time or 0.0
        
        # Detect query type from tables accessed
        query_type = self._detect_query_type(explain, config)
        sla_threshold = self._get_sla_threshold(query_type, config)
        
        if execution_time_ms > sla_threshold:
            breach_factor = execution_time_ms / sla_threshold
            severity = Severity.CRITICAL if breach_factor >= 2.0 else Severity.WARNING
            
            # Calculate financial impact
            delay_ms = execution_time_ms - sla_threshold
            cost_per_hour = self._estimate_hourly_cost(delay_ms, config)
            
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
                title=f"Latency SLA breach: {query_type} query ({execution_time_ms:.0f}ms > {sla_threshold:.0f}ms)",
                description=(
                    f"This {query_type} query took {execution_time_ms:.1f}ms, "
                    f"exceeding the {sla_threshold:.0f}ms SLA by {breach_factor:.1f}x. "
                    f"Estimated cost: ${cost_per_hour:.0f}/hour in delayed operations."
                ),
                suggestion=self._generate_fix(explain, query_type, execution_time_ms),
                metrics={
                    "execution_time_ms": int(execution_time_ms),
                    "sla_threshold_ms": int(sla_threshold),
                    "breach_factor": int(breach_factor * 100) / 100,
                    "estimated_cost_per_hour": int(cost_per_hour),
                },
            ))
        
        return findings
    
    def _detect_query_type(
        self,
        explain: "ExplainOutput",
        config: LatencySLAConfig
    ) -> str:
        """Detect query type from table names in the plan."""
        # Collect all table names from the plan
        tables: set[str] = set()
        for node in explain.all_nodes:
            if node.relation_name:
                tables.add(node.relation_name.lower())
        
        # Check for query type keywords
        tables_str = " ".join(tables)
        
        for keyword in config.trading_keywords:
            if keyword in tables_str:
                return "trading"
        
        for keyword in config.fraud_keywords:
            if keyword in tables_str:
                return "fraud_detection"
        
        for keyword in config.payment_keywords:
            if keyword in tables_str:
                return "payment"
        
        return "general"
    
    def _get_sla_threshold(self, query_type: str, config: LatencySLAConfig) -> float:
        """Get SLA threshold for query type."""
        thresholds = {
            "trading": config.trading_sla_ms,
            "fraud_detection": config.fraud_sla_ms,
            "payment": config.payment_sla_ms,
            "reporting": config.reporting_sla_ms,
            "general": config.default_sla_ms,
        }
        return thresholds.get(query_type, config.default_sla_ms)
    
    def _estimate_hourly_cost(self, delay_ms: float, config: LatencySLAConfig) -> float:
        """Estimate hourly cost of latency breach."""
        # Assume 1000 queries/hour for estimation
        queries_per_hour = 1000
        cost = delay_ms * config.cost_per_ms_delay * queries_per_hour
        return cost
    
    def _generate_fix(
        self,
        explain: "ExplainOutput",
        query_type: str,
        current_latency: float
    ) -> str:
        """Generate fix suggestion based on query type and plan."""
        # Find the slowest node
        slowest_node = None
        max_time = 0.0
        for node in explain.all_nodes:
            if node.actual_total_time and node.actual_total_time > max_time:
                max_time = node.actual_total_time
                slowest_node = node
        
        fix_parts = [f"-- Target: reduce latency from {current_latency:.0f}ms to SLA"]
        
        if slowest_node:
            if slowest_node.node_type == "Seq Scan" and slowest_node.relation_name:
                fix_parts.append(
                    f"CREATE INDEX idx_{slowest_node.relation_name}_perf "
                    f"ON {slowest_node.relation_name}(<filter_columns>);"
                )
            elif "Sort" in slowest_node.node_type:
                fix_parts.append("SET work_mem = '256MB';  -- Avoid disk sort")
            elif "Hash" in slowest_node.node_type:
                fix_parts.append("SET work_mem = '256MB';  -- Larger hash table")
        
        if query_type == "trading":
            fix_parts.append("-- Consider: Materialized view for hot market data")
            fix_parts.append("-- Consider: Connection pooling to reduce overhead")
        elif query_type == "fraud_detection":
            fix_parts.append("-- Consider: Pre-computed risk scores table")
            fix_parts.append("-- Consider: Async processing for non-blocking")
        
        return "\n".join(fix_parts)
