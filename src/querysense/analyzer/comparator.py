"""
Query plan comparison and diff analysis.

Enables before/after comparison of query optimizations:
- Which issues were fixed?
- What new issues appeared?
- How did metrics change?
- Node-level diffs (scan type changed, rows/loops changed, buffers changed)
- Findings diff (new warnings, resolved warnings)

Design principle: Point-in-time tools become products when they track change.

Because EXPLAIN ANALYZE provides actual times/rows, comparing these
across changes is meaningful and actionable.

Usage:
    from querysense.analyzer.comparator import compare_analyses, compare_plans
    
    # Compare analysis results
    comparison = compare_analyses(before_result, after_result)
    print(f"Fixed: {len(comparison.fixed_issues)}, New: {len(comparison.new_issues)}")
    
    # Compare raw plans (node-level diff)
    plan_diff = compare_plans(before_explain, after_explain)
    for node_diff in plan_diff.node_diffs:
        if node_diff.scan_type_changed:
            print(f"{node_diff.path}: {node_diff.before_type} -> {node_diff.after_type}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding
    from querysense.parser.models import ExplainOutput, PlanNode


@dataclass(frozen=True)
class FindingDelta:
    """
    Change in a finding between two analyses.
    
    Tracks how a finding changed:
    - new: Finding appeared in after, not in before
    - fixed: Finding was in before, not in after
    - changed: Finding exists in both but metrics changed
    - unchanged: Finding is identical in both
    """
    
    finding: "Finding"
    status: Literal["new", "fixed", "changed", "unchanged"]
    before_metrics: dict[str, int | float] | None = None
    after_metrics: dict[str, int | float] | None = None
    
    @property
    def is_improvement(self) -> bool:
        """True if this delta represents an improvement."""
        if self.status == "fixed":
            return True
        if self.status == "changed" and self.before_metrics and self.after_metrics:
            # Check if key metrics improved (lower is better for most)
            before_rows = self.before_metrics.get("rows_scanned", 0)
            after_rows = self.after_metrics.get("rows_scanned", 0)
            return after_rows < before_rows
        return False
    
    @property
    def is_regression(self) -> bool:
        """True if this delta represents a regression."""
        if self.status == "new":
            return True
        if self.status == "changed" and self.before_metrics and self.after_metrics:
            before_rows = self.before_metrics.get("rows_scanned", 0)
            after_rows = self.after_metrics.get("rows_scanned", 0)
            return after_rows > before_rows
        return False
    
    def metric_delta(self, metric_name: str) -> float | None:
        """
        Get the change in a specific metric.
        
        Args:
            metric_name: Name of the metric to compare
            
        Returns:
            after - before value, or None if metric missing
        """
        if not self.before_metrics or not self.after_metrics:
            return None
        
        before = self.before_metrics.get(metric_name)
        after = self.after_metrics.get(metric_name)
        
        if before is None or after is None:
            return None
        
        return after - before


@dataclass
class AnalysisComparison:
    """
    Comparison of two analysis results (before vs after optimization).
    
    Provides a complete picture of what changed between two query plans,
    enabling users to verify their optimization efforts.
    
    Example:
        before = analyzer.analyze(explain_before)
        after = analyzer.analyze(explain_after)
        
        comparison = compare_analyses(before, after)
        
        print(f"Fixed: {len(comparison.fixed_issues)}")
        print(f"New: {len(comparison.new_issues)}")
        print(f"Net improvement: {comparison.net_improvement:+d}")
    """
    
    before: "AnalysisResult"
    after: "AnalysisResult"
    
    fixed_issues: list["Finding"] = field(default_factory=list)
    new_issues: list["Finding"] = field(default_factory=list)
    unchanged_issues: list["Finding"] = field(default_factory=list)
    changed_issues: list[FindingDelta] = field(default_factory=list)
    
    @property
    def net_improvement(self) -> int:
        """
        Net change in issue count.
        
        Positive = fewer issues (better)
        Negative = more issues (worse)
        """
        return len(self.fixed_issues) - len(self.new_issues)
    
    @property
    def is_improvement(self) -> bool:
        """True if overall the query improved."""
        return self.net_improvement > 0
    
    @property
    def is_regression(self) -> bool:
        """True if overall the query got worse."""
        return self.net_improvement < 0
    
    @property
    def total_cost_delta(self) -> float:
        """
        Change in total cost across all findings.
        
        Negative = lower cost (better)
        Positive = higher cost (worse)
        """
        before_cost = sum(
            f.metrics.get("total_cost", 0) for f in self.before.findings
        )
        after_cost = sum(
            f.metrics.get("total_cost", 0) for f in self.after.findings
        )
        return after_cost - before_cost
    
    @property
    def total_rows_delta(self) -> int:
        """
        Change in total rows scanned across all findings.
        
        Negative = fewer rows (better)
        Positive = more rows (worse)
        """
        before_rows = sum(
            int(f.metrics.get("rows_scanned", 0)) for f in self.before.findings
        )
        after_rows = sum(
            int(f.metrics.get("rows_scanned", 0)) for f in self.after.findings
        )
        return after_rows - before_rows
    
    @property
    def severity_improvement(self) -> dict[str, int]:
        """
        Change in issue count by severity.
        
        Returns:
            Dict with severity -> delta (negative = fewer issues)
        """
        from querysense.analyzer.models import Severity
        
        before_counts = {s: 0 for s in Severity}
        after_counts = {s: 0 for s in Severity}
        
        for f in self.before.findings:
            before_counts[f.severity] += 1
        for f in self.after.findings:
            after_counts[f.severity] += 1
        
        return {
            s.value: after_counts[s] - before_counts[s]
            for s in Severity
        }
    
    def summary(self) -> dict[str, int | float | bool]:
        """
        Get a summary of the comparison.
        
        Returns:
            Dict with key metrics about the comparison
        """
        return {
            "fixed_count": len(self.fixed_issues),
            "new_count": len(self.new_issues),
            "unchanged_count": len(self.unchanged_issues),
            "changed_count": len(self.changed_issues),
            "net_improvement": self.net_improvement,
            "is_improvement": self.is_improvement,
            "total_cost_delta": self.total_cost_delta,
            "total_rows_delta": self.total_rows_delta,
        }
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": self.summary(),
            "fixed_issues": [f.model_dump(mode="json") for f in self.fixed_issues],
            "new_issues": [f.model_dump(mode="json") for f in self.new_issues],
            "unchanged_count": len(self.unchanged_issues),
            "changed_issues": [
                {
                    "finding": d.finding.model_dump(mode="json"),
                    "status": d.status,
                    "before_metrics": d.before_metrics,
                    "after_metrics": d.after_metrics,
                }
                for d in self.changed_issues
            ],
            "severity_changes": self.severity_improvement,
        }


def _finding_key(finding: "Finding") -> str:
    """
    Generate a key for matching findings across analyses.
    
    Uses rule_id + node path + relation name for stable matching
    even when metrics change.
    """
    return f"{finding.rule_id}:{finding.context.path}:{finding.context.relation_name}"


def compare_analyses(
    before: "AnalysisResult",
    after: "AnalysisResult",
) -> AnalysisComparison:
    """
    Compare two analysis results to identify what changed.
    
    Matches findings by rule_id and node path, then categorizes
    them as fixed, new, changed, or unchanged.
    
    Args:
        before: Analysis result before optimization
        after: Analysis result after optimization
        
    Returns:
        AnalysisComparison with categorized findings
        
    Example:
        comparison = compare_analyses(before_result, after_result)
        
        if comparison.is_improvement:
            print(f"Great! Fixed {len(comparison.fixed_issues)} issues")
        else:
            print(f"Warning: {len(comparison.new_issues)} new issues")
    """
    # Build lookup maps by key
    before_map = {_finding_key(f): f for f in before.findings}
    after_map = {_finding_key(f): f for f in after.findings}
    
    # Find fixed issues (in before, not in after)
    fixed_issues = [
        f for key, f in before_map.items()
        if key not in after_map
    ]
    
    # Find new issues (in after, not in before)
    new_issues = [
        f for key, f in after_map.items()
        if key not in before_map
    ]
    
    # Find unchanged and changed issues
    unchanged_issues: list["Finding"] = []
    changed_issues: list[FindingDelta] = []
    
    common_keys = set(before_map.keys()) & set(after_map.keys())
    
    for key in common_keys:
        before_finding = before_map[key]
        after_finding = after_map[key]
        
        if before_finding.metrics == after_finding.metrics:
            unchanged_issues.append(after_finding)
        else:
            changed_issues.append(FindingDelta(
                finding=after_finding,
                status="changed",
                before_metrics=dict(before_finding.metrics),
                after_metrics=dict(after_finding.metrics),
            ))
    
    return AnalysisComparison(
        before=before,
        after=after,
        fixed_issues=fixed_issues,
        new_issues=new_issues,
        unchanged_issues=unchanged_issues,
        changed_issues=changed_issues,
    )


def compare_explains(
    before_explain: "ExplainOutput",
    after_explain: "ExplainOutput",
    analyzer: "Analyzer",
) -> AnalysisComparison:
    """
    Convenience function to compare two EXPLAIN outputs.
    
    Runs analysis on both and returns the comparison.
    
    Args:
        before_explain: EXPLAIN output before optimization
        after_explain: EXPLAIN output after optimization
        analyzer: Analyzer instance to use
        
    Returns:
        AnalysisComparison with categorized findings
    """
    # Import here to avoid circular import
    from querysense.parser.models import ExplainOutput
    
    before_result = analyzer.analyze(before_explain)
    after_result = analyzer.analyze(after_explain)
    
    return compare_analyses(before_result, after_result)


# =============================================================================
# Plan Node-Level Comparison
# =============================================================================

@dataclass(frozen=True)
class NodeDiff:
    """
    Diff of a single plan node between two plans.
    
    Tracks changes at the node level:
    - Scan type changes (Seq Scan -> Index Scan)
    - Row estimate changes
    - Actual row changes
    - Buffer changes
    - Cost changes
    """
    
    path: str
    before_type: str | None
    after_type: str | None
    
    # Existence
    status: Literal["added", "removed", "changed", "unchanged"]
    
    # Row changes
    before_plan_rows: int | None = None
    after_plan_rows: int | None = None
    before_actual_rows: int | None = None
    after_actual_rows: int | None = None
    
    # Cost changes
    before_total_cost: float | None = None
    after_total_cost: float | None = None
    before_startup_cost: float | None = None
    after_startup_cost: float | None = None
    
    # Buffer changes (from EXPLAIN BUFFERS)
    before_shared_hit: int | None = None
    after_shared_hit: int | None = None
    before_shared_read: int | None = None
    after_shared_read: int | None = None
    
    # Loop changes
    before_loops: int | None = None
    after_loops: int | None = None
    
    # Table/Index info
    relation_name: str | None = None
    index_name_before: str | None = None
    index_name_after: str | None = None
    
    @property
    def scan_type_changed(self) -> bool:
        """True if the scan type changed."""
        return (
            self.before_type is not None
            and self.after_type is not None
            and self.before_type != self.after_type
        )
    
    @property
    def became_index_scan(self) -> bool:
        """True if changed from Seq Scan to Index Scan."""
        if not self.scan_type_changed:
            return False
        before = self.before_type or ""
        after = self.after_type or ""
        return "Seq Scan" in before and "Index" in after
    
    @property
    def row_estimate_delta(self) -> float | None:
        """Change in row estimate (plan_rows)."""
        if self.before_plan_rows is None or self.after_plan_rows is None:
            return None
        return self.after_plan_rows - self.before_plan_rows
    
    @property
    def actual_rows_delta(self) -> int | None:
        """Change in actual rows processed."""
        if self.before_actual_rows is None or self.after_actual_rows is None:
            return None
        return self.after_actual_rows - self.before_actual_rows
    
    @property
    def cost_delta(self) -> float | None:
        """Change in total cost."""
        if self.before_total_cost is None or self.after_total_cost is None:
            return None
        return self.after_total_cost - self.before_total_cost
    
    @property
    def buffer_delta(self) -> int | None:
        """Change in total buffer hits + reads."""
        before_total = (self.before_shared_hit or 0) + (self.before_shared_read or 0)
        after_total = (self.after_shared_hit or 0) + (self.after_shared_read or 0)
        if before_total == 0 and after_total == 0:
            return None
        return after_total - before_total
    
    @property
    def is_improvement(self) -> bool:
        """True if this node improved."""
        if self.status == "removed":
            return True
        if self.became_index_scan:
            return True
        cost_delta = self.cost_delta
        if cost_delta is not None and cost_delta < 0:
            return True
        return False
    
    @property
    def is_regression(self) -> bool:
        """True if this node regressed."""
        if self.status == "added":
            # Could be a regression, depends on context
            return False
        cost_delta = self.cost_delta
        if cost_delta is not None and cost_delta > 0:
            return True
        return False


@dataclass
class PlanComparison:
    """
    Comparison of two query plans at the node level.
    
    Provides detailed node-by-node diff for understanding
    exactly what changed in the query plan.
    """
    
    before_explain: "ExplainOutput"
    after_explain: "ExplainOutput"
    
    node_diffs: list[NodeDiff] = field(default_factory=list)
    
    @property
    def total_cost_before(self) -> float:
        """Total cost of before plan."""
        return self.before_explain.plan.total_cost
    
    @property
    def total_cost_after(self) -> float:
        """Total cost of after plan."""
        return self.after_explain.plan.total_cost
    
    @property
    def cost_reduction_percent(self) -> float:
        """Percent reduction in total cost."""
        before = self.total_cost_before
        if before == 0:
            return 0.0
        return ((before - self.total_cost_after) / before) * 100
    
    @property
    def execution_time_before_ms(self) -> float | None:
        """Execution time from before plan (if ANALYZE)."""
        return self.before_explain.execution_time_ms
    
    @property
    def execution_time_after_ms(self) -> float | None:
        """Execution time from after plan (if ANALYZE)."""
        return self.after_explain.execution_time_ms
    
    @property
    def time_reduction_percent(self) -> float | None:
        """Percent reduction in execution time."""
        before = self.execution_time_before_ms
        after = self.execution_time_after_ms
        if before is None or after is None or before == 0:
            return None
        return ((before - after) / before) * 100
    
    @property
    def scan_type_changes(self) -> list[NodeDiff]:
        """Nodes where scan type changed."""
        return [d for d in self.node_diffs if d.scan_type_changed]
    
    @property
    def improvements(self) -> list[NodeDiff]:
        """Nodes that improved."""
        return [d for d in self.node_diffs if d.is_improvement]
    
    @property
    def regressions(self) -> list[NodeDiff]:
        """Nodes that regressed."""
        return [d for d in self.node_diffs if d.is_regression]
    
    def summary(self) -> dict[str, Any]:
        """Get summary of plan comparison."""
        return {
            "total_nodes_before": len(self.before_explain.all_nodes),
            "total_nodes_after": len(self.after_explain.all_nodes),
            "nodes_added": len([d for d in self.node_diffs if d.status == "added"]),
            "nodes_removed": len([d for d in self.node_diffs if d.status == "removed"]),
            "nodes_changed": len([d for d in self.node_diffs if d.status == "changed"]),
            "scan_type_changes": len(self.scan_type_changes),
            "cost_reduction_percent": self.cost_reduction_percent,
            "time_reduction_percent": self.time_reduction_percent,
            "improvements": len(self.improvements),
            "regressions": len(self.regressions),
        }


def _node_path_key(node: "PlanNode", path: str) -> str:
    """Generate key for matching nodes across plans."""
    # Use path + relation name for stable matching
    relation = node.relation_name or ""
    return f"{path}:{node.node_type}:{relation}"


def _collect_nodes(
    node: "PlanNode",
    path: str = "0",
) -> dict[str, tuple[str, "PlanNode"]]:
    """Collect all nodes with their paths."""
    result: dict[str, tuple[str, "PlanNode"]] = {}
    
    key = _node_path_key(node, path)
    result[key] = (path, node)
    
    if node.plans:
        for i, child in enumerate(node.plans):
            child_path = f"{path}.{i}"
            result.update(_collect_nodes(child, child_path))
    
    return result


def compare_plans(
    before_explain: "ExplainOutput",
    after_explain: "ExplainOutput",
) -> PlanComparison:
    """
    Compare two query plans at the node level.
    
    Provides detailed node-by-node diff for understanding
    exactly what changed in the query plan structure and metrics.
    
    Args:
        before_explain: EXPLAIN output before changes
        after_explain: EXPLAIN output after changes
        
    Returns:
        PlanComparison with node-level diffs
        
    Example:
        diff = compare_plans(before, after)
        
        for node in diff.scan_type_changes:
            print(f"{node.path}: {node.before_type} -> {node.after_type}")
        
        print(f"Cost reduction: {diff.cost_reduction_percent:.1f}%")
    """
    # Collect nodes from both plans
    before_nodes = _collect_nodes(before_explain.plan)
    after_nodes = _collect_nodes(after_explain.plan)
    
    node_diffs: list[NodeDiff] = []
    
    # Find all unique keys
    all_keys = set(before_nodes.keys()) | set(after_nodes.keys())
    
    for key in all_keys:
        before_info = before_nodes.get(key)
        after_info = after_nodes.get(key)
        
        if before_info and after_info:
            # Node exists in both - compare
            before_path, before_node = before_info
            after_path, after_node = after_info
            
            # Determine if changed or unchanged
            if (
                before_node.node_type == after_node.node_type
                and before_node.total_cost == after_node.total_cost
                and before_node.plan_rows == after_node.plan_rows
            ):
                status: Literal["added", "removed", "changed", "unchanged"] = "unchanged"
            else:
                status = "changed"
            
            node_diffs.append(NodeDiff(
                path=before_path,
                before_type=before_node.node_type,
                after_type=after_node.node_type,
                status=status,
                before_plan_rows=before_node.plan_rows,
                after_plan_rows=after_node.plan_rows,
                before_actual_rows=before_node.actual_rows,
                after_actual_rows=after_node.actual_rows,
                before_total_cost=before_node.total_cost,
                after_total_cost=after_node.total_cost,
                before_startup_cost=before_node.startup_cost,
                after_startup_cost=after_node.startup_cost,
                before_shared_hit=before_node.shared_hit_blocks,
                after_shared_hit=after_node.shared_hit_blocks,
                before_shared_read=before_node.shared_read_blocks,
                after_shared_read=after_node.shared_read_blocks,
                before_loops=before_node.actual_loops,
                after_loops=after_node.actual_loops,
                relation_name=before_node.relation_name or after_node.relation_name,
                index_name_before=before_node.index_name,
                index_name_after=after_node.index_name,
            ))
        
        elif before_info:
            # Node removed
            before_path, before_node = before_info
            node_diffs.append(NodeDiff(
                path=before_path,
                before_type=before_node.node_type,
                after_type=None,
                status="removed",
                before_plan_rows=before_node.plan_rows,
                before_actual_rows=before_node.actual_rows,
                before_total_cost=before_node.total_cost,
                before_startup_cost=before_node.startup_cost,
                relation_name=before_node.relation_name,
                index_name_before=before_node.index_name,
            ))
        
        else:
            # Node added
            after_path, after_node = after_info  # type: ignore[misc]
            node_diffs.append(NodeDiff(
                path=after_path,
                before_type=None,
                after_type=after_node.node_type,
                status="added",
                after_plan_rows=after_node.plan_rows,
                after_actual_rows=after_node.actual_rows,
                after_total_cost=after_node.total_cost,
                after_startup_cost=after_node.startup_cost,
                relation_name=after_node.relation_name,
                index_name_after=after_node.index_name,
            ))
    
    # Sort by path for consistent output
    node_diffs.sort(key=lambda d: d.path)
    
    return PlanComparison(
        before_explain=before_explain,
        after_explain=after_explain,
        node_diffs=node_diffs,
    )
