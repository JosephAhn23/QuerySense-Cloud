"""
Rule: Parallel Query Not Used

Detects large sequential scans that could benefit from parallel execution
but are not using it.

Why it matters:
- PostgreSQL can parallelize Seq Scans, Aggregates, and Joins
- On multi-core systems, parallel queries can be 2-8x faster
- Many systems have parallelism disabled or misconfigured

When parallel is used:
- Table must be above min_parallel_table_scan_size (8MB default)
- Query cost must exceed parallel_tuple_cost thresholds
- No functions marked PARALLEL UNSAFE
- Not in a transaction with serializable isolation
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput, PlanNode


class ParallelQueryConfig(RuleConfig):
    """
    Configuration for parallel query detection.
    
    Attributes:
        min_rows_for_parallel: Minimum rows to suggest parallelism (default 100,000)
        min_cost_for_parallel: Minimum cost to suggest parallelism (default 1,000)
    """
    
    min_rows_for_parallel: int = Field(
        default=100_000,
        ge=1_000,
        le=100_000_000,
        description="Minimum rows scanned to suggest parallelism",
    )
    
    min_cost_for_parallel: float = Field(
        default=1_000.0,
        ge=100.0,
        description="Minimum total_cost to suggest parallelism",
    )


@register_rule
class ParallelQueryNotUsed(Rule):
    """
    Detect queries that could benefit from parallelism but don't use it.
    
    Looks for:
    - Large sequential scans (> 100K rows) with parallel_aware = False
    - Gather nodes with workers_launched < workers_planned
    - High-cost operations without any parallel nodes
    """
    
    rule_id = "PARALLEL_QUERY_NOT_USED"
    version = "1.0.0"
    severity = Severity.INFO
    description = "Detects queries that could benefit from parallel execution"
    config_schema = ParallelQueryConfig
    phase = RulePhase.PER_NODE
    
    # Scan nodes that can be parallelized
    PARALLELIZABLE_SCANS = {"Seq Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan"}
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """
        Find operations that could benefit from parallelism.
        
        Args:
            explain: Parsed EXPLAIN output
            prior_findings: Not used (PER_NODE rule)
            
        Returns:
            List of findings for parallelism opportunities
        """
        config: ParallelQueryConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []
        
        # First, check if the query uses any parallel workers
        has_parallel = self._query_uses_parallel(explain)
        
        for path, node, parent in self.iter_nodes_with_parent(explain):
            finding = None
            
            # Check for large non-parallel scans
            if node.node_type in self.PARALLELIZABLE_SCANS:
                finding = self._check_non_parallel_scan(
                    node, path, parent, config, has_parallel
                )
            
            # Check for Gather nodes that didn't launch all workers
            elif node.node_type in {"Gather", "Gather Merge"}:
                finding = self._check_gather_workers(node, path, parent)
            
            if finding:
                findings.append(finding)
        
        return findings
    
    def _query_uses_parallel(self, explain: "ExplainOutput") -> bool:
        """Check if the query plan uses any parallel workers."""
        for node in explain.all_nodes:
            if node.node_type in {"Gather", "Gather Merge"}:
                return True
            if node.workers_planned and node.workers_planned > 0:
                return True
        return False
    
    def _check_non_parallel_scan(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
        config: ParallelQueryConfig,
        query_has_parallel: bool,
    ) -> Finding | None:
        """Check if a scan could benefit from parallelism."""
        # Need ANALYZE data
        if node.actual_rows is None:
            return None
        
        # Skip if already parallel-aware
        if node.parallel_aware:
            return None
        
        # Skip small scans
        if node.actual_rows < config.min_rows_for_parallel:
            return None
        
        # Skip low-cost operations
        if node.total_cost < config.min_cost_for_parallel:
            return None
        
        # If query already uses parallel elsewhere, this might be intentional
        # Still flag but at lower severity
        severity = Severity.INFO if query_has_parallel else Severity.WARNING
        
        # Escalate for very large scans
        if node.actual_rows >= 1_000_000:
            severity = Severity.WARNING
        
        table_name = node.relation_name or "table"
        context = NodeContext.from_node(node, path, parent)
        
        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=f"{node.node_type} on {table_name} not using parallel workers ({node.actual_rows:,} rows)",
            description=self._build_scan_description(node),
            suggestion=self._build_scan_suggestion(node),
            metrics={
                "actual_rows": node.actual_rows,
                "total_cost": node.total_cost,
                "parallel_aware": node.parallel_aware or False,
            },
        )
    
    def _check_gather_workers(
        self,
        node: "PlanNode",
        path,
        parent: "PlanNode | None",
    ) -> Finding | None:
        """Check if Gather node launched fewer workers than planned."""
        if node.workers_planned is None or node.workers_launched is None:
            return None
        
        planned = node.workers_planned
        launched = node.workers_launched
        
        # All workers launched - no issue
        if launched >= planned:
            return None
        
        # No workers launched at all
        if launched == 0:
            severity = Severity.WARNING
            title = f"Gather planned {planned} workers but launched none"
        else:
            severity = Severity.INFO
            title = f"Gather launched only {launched}/{planned} workers"
        
        context = NodeContext.from_node(node, path, parent)
        
        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=context,
            title=title,
            description=self._build_gather_description(node, planned, launched),
            suggestion=self._build_gather_suggestion(planned, launched),
            metrics={
                "workers_planned": planned,
                "workers_launched": launched,
                "workers_missing": planned - launched,
            },
        )
    
    def _build_scan_description(self, node: "PlanNode") -> str:
        """Build description for non-parallel scan."""
        parts = [
            f"This {node.node_type} processed {node.actual_rows:,} rows without parallel workers."
        ]
        
        if node.actual_rows >= 1_000_000:
            parts.append(
                "With over 1 million rows, parallel execution could provide "
                "significant speedup on multi-core systems."
            )
        
        parts.append(
            "PostgreSQL can parallelize sequential scans, index scans, and "
            "some joins/aggregates when tables are large enough."
        )
        
        return " ".join(parts)
    
    def _build_gather_description(
        self,
        node: "PlanNode",
        planned: int,
        launched: int,
    ) -> str:
        """Build description for under-utilized Gather."""
        parts = []
        
        if launched == 0:
            parts.append(
                f"Query planned to use {planned} parallel workers but none were launched. "
                "This usually means workers were all busy or max_parallel_workers was reached."
            )
        else:
            parts.append(
                f"Query planned {planned} parallel workers but only {launched} were available. "
                "System was under parallel worker contention."
            )
        
        parts.append(
            "When parallel workers aren't available, queries run single-threaded "
            "and may be significantly slower than expected."
        )
        
        return " ".join(parts)
    
    def _build_scan_suggestion(self, node: "PlanNode") -> str:
        """Build suggestion for enabling parallelism."""
        lines = [
            "-- Check current parallel settings:",
            "SHOW max_parallel_workers_per_gather;  -- Default: 2",
            "SHOW max_parallel_workers;             -- Default: 8",
            "SHOW min_parallel_table_scan_size;     -- Default: 8MB",
            "",
            "-- Enable more parallel workers:",
            "SET max_parallel_workers_per_gather = 4;",
            "",
            "-- Force parallel scan for testing:",
            "SET parallel_tuple_cost = 0;",
            "SET parallel_setup_cost = 0;",
            "",
            "-- Note: Some functions disable parallelism. Check for PARALLEL UNSAFE functions.",
            "-- Docs: https://www.postgresql.org/docs/current/parallel-query.html",
        ]
        
        return "\n".join(lines)
    
    def _build_gather_suggestion(self, planned: int, launched: int) -> str:
        """Build suggestion for worker contention."""
        lines = [
            "-- Increase system-wide parallel worker limit:",
            f"ALTER SYSTEM SET max_parallel_workers = {max(8, planned * 2)};",
            "SELECT pg_reload_conf();",
            "",
            "-- Or reduce concurrent queries competing for workers",
            "",
            "-- Check current worker usage:",
            "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'parallel worker';",
            "",
            "-- Docs: https://www.postgresql.org/docs/current/runtime-config-resource.html#GUC-MAX-PARALLEL-WORKERS",
        ]
        
        return "\n".join(lines)
