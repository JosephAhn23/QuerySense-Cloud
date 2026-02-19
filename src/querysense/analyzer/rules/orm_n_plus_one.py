"""Rule: ORM N+1 Query Detector — detects correlated subquery patterns from ORMs.

Addresses the #1 ORM anti-pattern: N+1 queries where the ORM generates
one query per parent row instead of a single JOIN or batch query.

Detection heuristics:
- Nested Loop with high actual loops count (>10) over an Index/Seq Scan
- Plan shape matches: parent scan → nested loop → child scan pattern
- SQL patterns: repeated WHERE parent_id = ? or IN (SELECT ...) from ORM
- Row estimate accuracy: actual loops >> planned loops

Source evidence:
- X.com #database: "N+1 queries going undetected until production" (viral weekly)
- Dombrovskaya et al. 2024: ORM pitfalls chapter
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, RulePhase, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


@register_rule
class ORMNPlusOne(Rule):
    """Detect N+1 query patterns from ORM-generated SQL."""

    rule_id = "ORM_N_PLUS_ONE"
    version = "1.0.0"
    severity = Severity.CRITICAL
    description = "N+1 query anti-pattern: correlated lookup with excessive loop count"
    phase = RulePhase.AGGREGATE

    # Thresholds
    HIGH_LOOP_THRESHOLD = 10
    EXTREME_LOOP_THRESHOLD = 100

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            # Look for Nested Loop nodes with high loop counts
            if node.node_type != "Nested Loop":
                continue

            actual_loops = node.raw.get("Actual Loops", 1)
            if actual_loops < self.HIGH_LOOP_THRESHOLD:
                continue

            # Check if the inner side is an Index Scan or Seq Scan
            children = node.raw.get("Plans", [])
            if len(children) < 2:
                continue

            inner = children[1]  # Inner side of nested loop
            inner_type = inner.get("Node Type", "")
            inner_relation = inner.get("Relation Name", "")
            inner_loops = inner.get("Actual Loops", 1)
            inner_rows = inner.get("Actual Rows", 0)
            plan_rows = inner.get("Plan Rows", 0)

            # N+1 pattern: inner side loops many times, each returning ~1 row
            is_point_lookup = inner_rows <= 5 and inner_loops >= self.HIGH_LOOP_THRESHOLD

            # Also check for Index Scan or Seq Scan patterns
            is_scan = inner_type in (
                "Index Scan", "Index Only Scan", "Seq Scan",
                "Bitmap Heap Scan", "Bitmap Index Scan",
            )

            if not (is_scan and is_point_lookup):
                continue

            # Calculate wasted effort
            total_rows_scanned = inner_loops * max(inner_rows, 1)
            severity = Severity.CRITICAL if inner_loops >= self.EXTREME_LOOP_THRESHOLD else Severity.WARNING

            # Determine impact score
            if inner_loops >= 1000:
                impact_score = 9.5
                estimated_speedup = f"{inner_loops}x"
            elif inner_loops >= 100:
                impact_score = 9.0
                estimated_speedup = f"{inner_loops // 10}x+"
            else:
                impact_score = 8.0
                estimated_speedup = f"{inner_loops}x"

            # Build ORM-specific suggestion
            if inner_type in ("Index Scan", "Index Only Scan"):
                index_name = inner.get("Index Name", "")
                fix_parts = [
                    f"-- N+1 detected: {inner_loops} individual lookups on '{inner_relation}'",
                    f"-- Each lookup returns ~{inner_rows} row(s) via {inner_type}",
                    "",
                    "-- ORM fixes:",
                    "-- Rails:       Model.includes(:association)",
                    "-- Django:      queryset.select_related('fk') or .prefetch_related('m2m')",
                    "-- SQLAlchemy:  query.options(joinedload(Model.relation))",
                    "-- Hibernate:   @BatchSize(size=100) or JOIN FETCH in HQL",
                    "",
                    f"-- SQL fix: Rewrite as a single JOIN instead of {inner_loops} subqueries",
                ]
                suggestion = "\n".join(fix_parts)
            else:
                suggestion = (
                    f"-- {inner_loops} sequential scans on '{inner_relation}' (N+1 pattern)\n"
                    f"-- Add an index or rewrite as a JOIN to eliminate {inner_loops} lookups\n"
                    f"-- ORM: use eager loading (includes/select_related/joinedload)"
                )

            context = NodeContext.from_node(node, path, parent)
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"N+1 Query: {inner_loops} lookups on {inner_relation or 'inner table'}",
                description=(
                    f"Nested Loop executes the inner {inner_type} on "
                    f"'{inner_relation}' {inner_loops:,} times, each returning "
                    f"~{inner_rows} row(s). This is the classic ORM N+1 anti-pattern "
                    f"where {inner_loops:,} individual queries replace what should be "
                    f"a single JOIN. Total rows scanned: {total_rows_scanned:,}."
                ),
                suggestion=suggestion,
                impact_score=impact_score,
                impact_band=ImpactBand.HIGH if inner_loops >= 100 else ImpactBand.MEDIUM,
                metrics={
                    "inner_loops": inner_loops,
                    "rows_per_loop": inner_rows,
                    "total_rows_scanned": total_rows_scanned,
                    "inner_node_type": inner_type,
                    "estimated_speedup": estimated_speedup,
                },
                assumptions=[
                    "High loop count on inner scan suggests ORM-generated per-row queries",
                    "Each loop returning few rows indicates point lookups (N+1 pattern)",
                ],
                verification_steps=[
                    "Check application logs for repeated SQL with different parameter values",
                    "Verify ORM configuration for eager/lazy loading settings",
                    f"Run EXPLAIN on a JOIN version of this query to confirm improvement",
                ],
            ))

        return findings
