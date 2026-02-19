"""
Rule: Excessive Sequential Scans (AGGREGATE)

Detects queries with too many sequential scans, indicating structural
problems or missing indexes that compound into severe performance issues.

This is an AGGREGATE rule - it runs after PER_NODE rules and can see
their findings to detect patterns across the entire query.

Why it matters:
- Multiple sequential scans multiply performance problems
- Often indicates a query that should be restructured
- May suggest missing composite indexes or CTEs
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


class ExcessiveSeqScansConfig(RuleConfig):
    """Configuration for excessive sequential scans detection."""
    
    min_scans: int = Field(
        default=3,
        ge=2,
        le=20,
        description="Minimum number of sequential scans to trigger",
    )
    
    min_total_rows: int = Field(
        default=100_000,
        ge=1_000,
        description="Minimum total rows across all seq scans",
    )


@register_rule
class ExcessiveSeqScans(Rule):
    """
    Detect queries with too many sequential scans.
    
    This AGGREGATE rule looks at findings from PER_NODE phase and
    identifies when multiple sequential scans indicate a systemic problem.
    """
    
    rule_id = "EXCESSIVE_SEQ_SCANS"
    version = "1.0.0"
    severity = Severity.CRITICAL
    description = "Detects queries with excessive sequential scans"
    config_schema = ExcessiveSeqScansConfig
    phase = RulePhase.AGGREGATE  # ← Runs after PER_NODE rules
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Analyze patterns across prior findings.
        
        Args:
            explain: The EXPLAIN output
            prior_findings: Findings from PER_NODE phase
            
        Returns:
            List of aggregate findings
        """
        config: ExcessiveSeqScansConfig = self.config  # type: ignore[assignment]
        
        if not prior_findings:
            return []
        
        # Find all sequential scan findings from phase 1
        seq_scan_findings = [
            f for f in prior_findings
            if f.rule_id == "SEQ_SCAN_LARGE_TABLE"
        ]
        
        if len(seq_scan_findings) < config.min_scans:
            return []
        
        # Calculate aggregate metrics
        total_rows = sum(
            f.metrics.get("rows_scanned", 0)
            for f in seq_scan_findings
        )
        
        if total_rows < config.min_total_rows:
            return []
        
        # Get unique tables
        tables = {
            f.context.relation_name
            for f in seq_scan_findings
            if f.context.relation_name
        }
        
        # Check for same table scanned multiple times
        table_scan_counts: dict[str, int] = {}
        for f in seq_scan_findings:
            table = f.context.relation_name or "unknown"
            table_scan_counts[table] = table_scan_counts.get(table, 0) + 1
        
        duplicate_tables = {
            table: count
            for table, count in table_scan_counts.items()
            if count > 1
        }
        
        # Build description
        desc_parts = [
            f"Query performs {len(seq_scan_findings)} sequential scans "
            f"reading {total_rows:,} total rows.",
        ]
        
        if duplicate_tables:
            dup_list = ", ".join(
                f"{table} ({count}x)"
                for table, count in duplicate_tables.items()
            )
            desc_parts.append(f"Tables scanned multiple times: {dup_list}")
        
        # Build suggestion
        suggestions = []
        if duplicate_tables:
            suggestions.append(
                "Consider using CTEs or subqueries to avoid scanning the same table multiple times."
            )
        suggestions.append(
            f"Add indexes for tables: {', '.join(tables)}."
        )
        suggestions.append(
            "Review query structure - multiple sequential scans often indicate a design issue."
        )
        
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                context=NodeContext.root("Query"),
                title=f"Query has {len(seq_scan_findings)} sequential scans ({total_rows:,} total rows)",
                description=" ".join(desc_parts),
                suggestion=" ".join(suggestions),
                metrics={
                    "seq_scan_count": len(seq_scan_findings),
                    "total_rows_scanned": total_rows,
                    "unique_tables": len(tables),
                    "duplicate_table_scans": len(duplicate_tables),
                },
            )
        ]
