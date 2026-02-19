"""
Table Bloat Detection (from EXPLAIN patterns).

PostgreSQL tables accumulate dead tuples that cause:
- Larger table size (more I/O)
- Slower sequential scans
- Slower index scans (index bloat)
- Wasted disk space

Detection from EXPLAIN:
- High "Rows Removed by Filter" relative to returned rows
- Large gap between estimated and actual rows
- Heap Fetches much higher than expected
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


class TableBloatConfig(RuleConfig):
    """Configuration for bloat detection."""
    
    # Ratio of removed rows to returned rows that suggests bloat
    filter_removal_ratio: float = Field(
        default=10.0,
        ge=2.0,
        description="Rows Removed / Rows Returned ratio to flag"
    )
    
    # Minimum rows to care about
    min_rows: int = Field(
        default=1000,
        ge=1,
        description="Minimum rows examined to flag"
    )


@register_rule
class TableBloat(Rule):
    """
    Detect potential table bloat from EXPLAIN patterns.
    
    Signs of bloat in EXPLAIN output:
    1. "Rows Removed by Filter" is very high compared to actual rows
    2. Sequential scans taking longer than expected
    3. Index scans with many heap fetches
    
    Note: This is heuristic-based. For accurate bloat detection,
    use pg_stat_user_tables or pgstattuple extension.
    
    Fix: VACUUM ANALYZE tablename; or VACUUM FULL tablename;
    """
    
    rule_id = "TABLE_BLOAT"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Table may have significant bloat"
    config_schema = TableBloatConfig
    phase = RulePhase.PER_NODE
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Detect potential table bloat from filter removal patterns."""
        findings: list[Finding] = []
        config: TableBloatConfig = self.config  # type: ignore
        seen_tables: set[str] = set()
        
        for node in explain.all_nodes:
            if not node.relation_name:
                continue
            
            # Already flagged this table
            if node.relation_name in seen_tables:
                continue
            
            # Check for high "Rows Removed by Filter"
            rows_removed = getattr(node, 'rows_removed_by_filter', 0) or 0
            actual_rows = node.actual_rows or 0
            
            if rows_removed < config.min_rows:
                continue
            
            if actual_rows == 0:
                # All rows removed - extreme bloat or missing index
                ratio = rows_removed
            else:
                ratio = rows_removed / actual_rows
            
            if ratio < config.filter_removal_ratio:
                continue
            
            seen_tables.add(node.relation_name)
            
            # Calculate bloat severity
            if ratio > 100:
                severity = Severity.CRITICAL
                bloat_desc = "severe"
            elif ratio > 50:
                severity = Severity.WARNING
                bloat_desc = "significant"
            else:
                severity = Severity.INFO
                bloat_desc = "moderate"
            
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
                    filter=node.filter,
                    depth=0,
                ),
                title=f"Potential {bloat_desc} bloat on {node.relation_name}",
                description=(
                    f"Query removed {rows_removed:,} rows by filter but only returned "
                    f"{actual_rows:,} rows ({ratio:.0f}x more removed than returned). "
                    f"This pattern often indicates table bloat from dead tuples, "
                    f"or a missing partial index."
                ),
                suggestion=(
                    f"-- Check table bloat\n"
                    f"SELECT relname,\n"
                    f"       n_dead_tup,\n"
                    f"       n_live_tup,\n"
                    f"       round(n_dead_tup * 100.0 / nullif(n_live_tup, 0), 1) as dead_pct,\n"
                    f"       last_vacuum,\n"
                    f"       last_autovacuum\n"
                    f"FROM pg_stat_user_tables\n"
                    f"WHERE relname = '{node.relation_name}';\n\n"
                    f"-- If bloat confirmed, run vacuum\n"
                    f"VACUUM ANALYZE {node.relation_name};\n\n"
                    f"-- For severe bloat (>40%), consider VACUUM FULL (locks table!)\n"
                    f"-- VACUUM FULL {node.relation_name};\n\n"
                    f"-- Or consider a partial index if filtering on specific values\n"
                    f"-- CREATE INDEX idx_{node.relation_name}_active\n"
                    f"--     ON {node.relation_name}(id) WHERE {node.filter or 'condition'};"
                ),
                metrics={
                    "rows_removed": rows_removed,
                    "rows_returned": actual_rows,
                    "removal_ratio": int(ratio),
                },
            ))
        
        return findings
