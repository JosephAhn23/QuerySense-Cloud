"""Rule: LATERAL Join Composite Index — detects missing indexes on LATERAL subqueries.

LATERAL subqueries with ORDER BY + LIMIT patterns need composite indexes
to avoid full table scans per parent row. Without (parent_id, sort_col) index,
PostgreSQL scans the entire child table for EACH parent row.

Source evidence:
- php.cn Forums: "LATERAL JOIN indexes fail silently — no warning" (1000+ views/month)
- Schönig 2020: Composite index detection for workload-aware recommendations
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


@register_rule
class LateralJoinIndex(Rule):
    """Detect LATERAL subqueries missing composite indexes."""

    rule_id = "LATERAL_JOIN_INDEX"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "LATERAL subquery with ORDER BY + LIMIT needs composite index"
    phase = RulePhase.AGGREGATE

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Look for Nested Loop nodes that are likely LATERAL joins
            if node.node_type != "Nested Loop":
                continue

            children = node.raw.get("Plans", [])
            if len(children) < 2:
                continue

            inner = children[1]
            inner_type = inner.get("Node Type", "")

            # LATERAL pattern: inner side has Sort + Limit or SubqueryScan
            # Check for Sort node in inner subtree
            has_sort = False
            has_limit = False
            sort_keys: list[str] = []
            scan_relation = ""
            scan_type = ""

            def _walk_inner(n: dict) -> None:
                nonlocal has_sort, has_limit, sort_keys, scan_relation, scan_type
                nt = n.get("Node Type", "")
                if nt == "Sort":
                    has_sort = True
                    sort_keys = n.get("Sort Key", [])
                if nt == "Limit":
                    has_limit = True
                if nt in ("Seq Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan"):
                    if not scan_relation:
                        scan_relation = n.get("Relation Name", "")
                        scan_type = nt
                for child in n.get("Plans", []):
                    _walk_inner(child)

            _walk_inner(inner)

            # Must have both Sort + Limit in inner subtree (LATERAL ORDER BY ... LIMIT pattern)
            if not (has_sort and has_limit):
                continue

            # Check loop count — LATERAL runs once per parent row
            actual_loops = inner.get("Actual Loops", node.raw.get("Actual Loops", 1))
            if actual_loops < 5:
                continue

            # Check if inner uses Seq Scan (missing index) or Sort (could use index ordering)
            inner_uses_seq_scan = scan_type == "Seq Scan"
            inner_sort_cost = 0
            for _, child_node, _ in self.iter_nodes_with_parent(explain):
                if child_node.node_type == "Sort" and child_node.raw.get("Sort Key") == sort_keys:
                    inner_sort_cost = child_node.raw.get("Actual Total Time", 0) or 0
                    break

            if not inner_uses_seq_scan and actual_loops < 20:
                # Only flag if using seq scan or high loop count
                continue

            # Build index recommendation
            if sort_keys:
                # Extract column names from sort keys
                col_parts = []
                for key in sort_keys:
                    key_str = str(key)
                    # Handle "column DESC", "column ASC", etc.
                    col_name = key_str.split()[0].strip('"').split(".")[-1]
                    direction = "DESC" if "DESC" in key_str.upper() else ""
                    col_parts.append(f"{col_name}{' DESC' if direction else ''}")

                index_cols = ", ".join(col_parts)
                suggestion = (
                    f"-- Create composite index for LATERAL subquery pattern\n"
                    f"CREATE INDEX CONCURRENTLY ON {scan_relation} "
                    f"(parent_join_column, {index_cols});\n\n"
                    f"-- Replace 'parent_join_column' with the actual join column\n"
                    f"-- (the column matching the WHERE clause in the LATERAL subquery)"
                )
            else:
                suggestion = (
                    f"-- Add composite index on {scan_relation}\n"
                    f"-- Include the join column + ORDER BY column(s)\n"
                    f"CREATE INDEX CONCURRENTLY ON {scan_relation} (join_col, sort_col);"
                )

            impact = ImpactBand.HIGH if actual_loops >= 50 else ImpactBand.MEDIUM
            impact_score = min(9.5, 6.0 + (actual_loops / 50) * 3)

            context = NodeContext.from_node(node, path, parent)
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity if actual_loops < 100 else Severity.CRITICAL,
                context=context,
                title=f"LATERAL subquery on {scan_relation or 'table'} missing composite index",
                description=(
                    f"This LATERAL subquery with ORDER BY + LIMIT runs {actual_loops:,} times "
                    f"(once per parent row). The inner side uses {scan_type} on '{scan_relation}', "
                    f"meaning PostgreSQL {'scans the full table' if inner_uses_seq_scan else 'sorts data'} "
                    f"for EACH parent row. A composite index on (join_column, {', '.join(str(k) for k in sort_keys)}) "
                    f"would allow index-ordered retrieval, potentially 100x faster for large parent sets."
                ),
                suggestion=suggestion,
                impact_score=impact_score,
                impact_band=impact,
                metrics={
                    "lateral_loops": actual_loops,
                    "inner_scan_type": scan_type,
                    "scan_relation": scan_relation,
                    "sort_keys": ", ".join(str(k) for k in sort_keys),
                    "estimated_speedup": f"{min(actual_loops, 100)}x",
                },
                assumptions=[
                    "High loop count with Sort+Limit indicates LATERAL pattern",
                    "Composite index would eliminate per-loop sort operation",
                ],
                verification_steps=[
                    "Verify the LATERAL subquery uses ORDER BY ... LIMIT",
                    f"Create the composite index and re-run EXPLAIN to confirm improvement",
                    "Check that the index covers the join predicate and sort order",
                ],
            ))

        return findings
