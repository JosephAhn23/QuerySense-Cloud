"""
Rule: Missing BUFFERS Option

Detects when EXPLAIN ANALYZE was run without BUFFERS, limiting diagnostic ability.

Why it matters:
- Without BUFFERS, you can't see I/O patterns
- Can't distinguish cached vs disk reads
- Can't identify which nodes cause the most I/O
- Makes performance diagnosis incomplete

Simple fix:
- Run EXPLAIN (ANALYZE, BUFFERS) instead of just EXPLAIN ANALYZE
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


@register_rule
class MissingBuffers(Rule):
    """
    Detect when EXPLAIN ANALYZE was run without BUFFERS option.
    
    This is an aggregate rule that checks once per query, not per node.
    """
    
    rule_id = "MISSING_BUFFERS"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Suggests using EXPLAIN (ANALYZE, BUFFERS) for better diagnostics"
    phase = RulePhase.AGGREGATE  # Only check once per query
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Check if BUFFERS data is present in the plan.
        
        Args:
            explain: Parsed EXPLAIN output
            prior_findings: Findings from PER_NODE phase (not used)
            
        Returns:
            Single finding if BUFFERS is missing, empty list otherwise
        """
        # Must have ANALYZE data first
        if not explain.has_analyze_data:
            # Without ANALYZE, we'd suggest running ANALYZE first
            # Don't double up on advice
            return []
        
        # Check if any node has buffer statistics
        has_buffers = self._has_buffer_stats(explain)
        
        if has_buffers:
            return []
        
        # No buffer stats found - suggest adding BUFFERS
        context = NodeContext.root("Query")
        
        return [Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            context=context,
            title="EXPLAIN run without BUFFERS option",
            description=self._build_description(prior_findings),
            suggestion=self._build_suggestion(),
            metrics={
                "has_analyze": True,
                "has_buffers": False,
            },
        )]
    
    def _has_buffer_stats(self, explain: "ExplainOutput") -> bool:
        """Check if any node has buffer statistics."""
        for node in explain.all_nodes:
            # Check for any buffer-related field
            if node.shared_hit_blocks is not None:
                return True
            if node.shared_read_blocks is not None:
                return True
            if node.shared_dirtied_blocks is not None:
                return True
            if node.shared_written_blocks is not None:
                return True
            # Also check for I/O timing
            if node.io_read_time is not None:
                return True
            if node.io_write_time is not None:
                return True
        
        return False
    
    def _build_description(self, prior_findings: list[Finding] | None) -> str:
        """Build description explaining why BUFFERS matters."""
        parts = [
            "This EXPLAIN ANALYZE output doesn't include buffer statistics. "
            "Without BUFFERS, you can't see:"
        ]
        
        parts.append(
            "\n- How many blocks were read from cache vs disk"
            "\n- Which nodes cause the most I/O"
            "\n- Whether your query is I/O or CPU bound"
        )
        
        # If we found other issues, emphasize that BUFFERS would help
        if prior_findings and len(prior_findings) > 0:
            parts.append(
                f"\n\nWe found {len(prior_findings)} issue(s) in this query. "
                "BUFFERS data would help diagnose whether they're causing I/O problems."
            )
        
        return "".join(parts)
    
    def _build_suggestion(self) -> str:
        """Build suggestion for using BUFFERS."""
        lines = [
            "-- Run with BUFFERS to see I/O statistics:",
            "EXPLAIN (ANALYZE, BUFFERS) SELECT ...;",
            "",
            "-- For maximum detail, also add TIMING and FORMAT JSON:",
            "EXPLAIN (ANALYZE, BUFFERS, TIMING, FORMAT JSON) SELECT ...;",
            "",
            "-- Buffer stats show:",
            "--   Shared Hit Blocks: reads satisfied from cache",
            "--   Shared Read Blocks: reads from disk (slow!)",
            "--   Shared Written Blocks: blocks written",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/sql-explain.html",
        ]
        
        return "\n".join(lines)
