"""
Foreign Key Without Index Detection.

The #1 cause of cascading delete slowness and JOIN performance issues.

When a foreign key references a parent table, PostgreSQL doesn't 
automatically create an index on the FK column. This causes:
- Slow cascading DELETEs (full table scan to find child rows)
- Slow JOINs when joining on FK column
- Lock contention during parent row updates
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.path import NodePath
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class ForeignKeyIndexConfig(RuleConfig):
    """Configuration for FK index detection."""
    
    # Minimum rows to consider the FK index worth flagging
    min_rows: int = 1000


@register_rule
class ForeignKeyWithoutIndex(Rule):
    """
    Detect sequential scans that could be FK lookups without indexes.
    
    Common pattern:
    - JOIN on user_id, order_id, etc. (typical FK columns)
    - Seq Scan instead of Index Scan
    - Filter on FK column
    
    This is the #1 missed optimization in production databases.
    
    Fix: CREATE INDEX idx_tablename_fk_column ON tablename(fk_column);
    """
    
    rule_id = "FOREIGN_KEY_WITHOUT_INDEX"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Foreign key column likely missing index"
    config_schema = ForeignKeyIndexConfig
    phase = RulePhase.PER_NODE
    
    # Common FK column patterns
    FK_PATTERNS = [
        "_id", "Id", "_fk", "_ref", 
        "user_id", "order_id", "customer_id", "product_id",
        "account_id", "parent_id", "company_id", "team_id",
        "category_id", "author_id", "owner_id", "creator_id",
    ]
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Detect FK columns without indexes."""
        findings: list[Finding] = []
        config: ForeignKeyIndexConfig = self.config  # type: ignore
        
        for node in explain.all_nodes:
            # Only check Seq Scans with filters
            if node.node_type != "Seq Scan":
                continue
            
            if not node.filter:
                continue
            
            rows = node.actual_rows or node.plan_rows or 0
            if rows < config.min_rows:
                continue
            
            # Check if filter contains FK-like column
            fk_column = self._extract_fk_column(node.filter)
            if not fk_column:
                continue
            
            # This is likely a missing FK index
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=Severity.CRITICAL if rows > 100_000 else Severity.WARNING,
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
                title=f"Missing index on FK column: {node.relation_name}.{fk_column}",
                description=(
                    f"Sequential scan on '{node.relation_name}' filtering by '{fk_column}' "
                    f"({rows:,} rows). This pattern typically indicates a foreign key column "
                    f"without an index. Cascading deletes and JOINs will be slow."
                ),
                suggestion=(
                    f"-- Add index on foreign key column\n"
                    f"CREATE INDEX CONCURRENTLY idx_{node.relation_name}_{fk_column}\n"
                    f"    ON {node.relation_name}({fk_column});\n\n"
                    f"-- Verify FK constraint exists\n"
                    f"SELECT conname, conrelid::regclass, confrelid::regclass\n"
                    f"FROM pg_constraint\n"
                    f"WHERE contype = 'f' AND conrelid = '{node.relation_name}'::regclass;"
                ),
                metrics={
                    "rows": rows,
                },
            ))
        
        return findings
    
    def _extract_fk_column(self, filter_str: str) -> str | None:
        """Extract FK-like column name from filter condition."""
        filter_lower = filter_str.lower()
        
        # Check each FK pattern
        for pattern in self.FK_PATTERNS:
            if pattern.lower() in filter_lower:
                # Try to extract the actual column name
                # Common patterns: (user_id = 123), (t.user_id = 123)
                import re
                # Match: column_name = or column_name IN or column_name IS
                match = re.search(
                    rf'\b(\w*{re.escape(pattern.lower())}\w*)\s*[=<>]',
                    filter_lower
                )
                if match:
                    return match.group(1)
                # Also check for pattern at word boundary
                match = re.search(rf'\b(\w*{re.escape(pattern.lower())})\b', filter_lower)
                if match:
                    return match.group(1)
        
        return None
