"""
Stale Statistics Detection.

When PostgreSQL's planner statistics are outdated, it makes bad decisions:
- Chooses Seq Scan when Index Scan would be 100x faster
- Wrong JOIN order causing nested loops on large tables
- Hash joins that spill to disk unexpectedly

Detection: Large discrepancy between plan_rows and actual_rows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.path import NodePath
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class StaleStatisticsConfig(RuleConfig):
    """Configuration for stale statistics detection."""
    
    # Minimum discrepancy ratio to flag
    min_ratio: float = Field(
        default=10.0,
        ge=2.0,
        description="Minimum actual/estimated ratio to flag"
    )
    
    # Minimum rows to care about
    min_rows: int = Field(
        default=100,
        ge=1,
        description="Minimum actual rows to flag"
    )


@register_rule
class StaleStatistics(Rule):
    """
    Detect stale table statistics from row estimation errors.
    
    When actual rows >> planned rows (or vice versa), the planner
    has stale statistics. Common after:
    - Bulk imports
    - Major DELETEs
    - Schema changes
    - PostgreSQL upgrades
    
    Fix: ANALYZE tablename;
    """
    
    rule_id = "STALE_STATISTICS"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Table statistics may be stale (large row estimation error)"
    config_schema = StaleStatisticsConfig
    phase = RulePhase.PER_NODE
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Detect nodes with large estimation errors indicating stale stats."""
        findings: list[Finding] = []
        config: StaleStatisticsConfig = self.config  # type: ignore
        seen_tables: set[str] = set()
        
        for node in explain.all_nodes:
            if not node.has_analyze_data:
                continue
            
            actual = node.actual_rows or 0
            planned = node.plan_rows or 1
            
            if actual < config.min_rows:
                continue
            
            # Calculate ratio (handle both over and under estimates)
            if actual > planned:
                ratio = actual / max(planned, 1)
                direction = "underestimated"
            else:
                ratio = planned / max(actual, 1)
                direction = "overestimated"
            
            if ratio < config.min_ratio:
                continue
            
            # Only flag each table once
            table = node.relation_name or "unknown"
            if table in seen_tables:
                continue
            seen_tables.add(table)
            
            severity = Severity.CRITICAL if ratio > 100 else Severity.WARNING
            
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=NodeContext(
                    path=NodePath.root(),
                    node_type=node.node_type,
                    relation_name=node.relation_name,
                    actual_rows=node.actual_rows,
                    plan_rows=node.plan_rows,
                    total_cost=node.total_cost,
                    depth=0,
                ),
                title=f"Stale statistics on {table} ({ratio:.0f}x {direction})",
                description=(
                    f"Planner estimated {planned:,} rows but actually got {actual:,} rows "
                    f"({ratio:.0f}x {direction}). This causes the planner to choose wrong "
                    f"execution strategies. Table statistics are likely stale."
                ),
                suggestion=(
                    f"-- Update statistics for this table\n"
                    f"ANALYZE {table};\n\n"
                    f"-- Or analyze entire database after bulk operations\n"
                    f"ANALYZE;\n\n"
                    f"-- Check when table was last analyzed\n"
                    f"SELECT schemaname, relname, last_analyze, last_autoanalyze\n"
                    f"FROM pg_stat_user_tables\n"
                    f"WHERE relname = '{table}';\n\n"
                    f"-- Consider increasing autovacuum frequency\n"
                    f"ALTER TABLE {table} SET (autovacuum_analyze_scale_factor = 0.05);"
                ),
                metrics={
                    "actual_rows": actual,
                    "planned_rows": planned,
                    "ratio": int(ratio),
                },
            ))
        
        return findings
