"""
GEQO (Genetic Query Optimizer) Analyzer.

PostgreSQL uses the Genetic Query Optimizer for complex joins (>12 tables
by default). GEQO treats join ordering as a "traveling salesman problem"
and uses evolutionary algorithms to find good plans.

This module surfaces GEQO behavior:
- Detects when GEQO is active (join count > geqo_threshold)
- Analyzes plan stability across GEQO seeds
- Identifies suboptimal join orders
- Suggests join_collapse_limit tuning
- Recommends explicit join order hints

Usage:
    from querysense.geqo_analyzer import GEQOAnalyzer

    analyzer = GEQOAnalyzer()
    result = analyzer.analyze(plan_json)
    for finding in result.findings:
        print(f"{finding.severity}: {finding.description}")
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any


@dataclass
class JoinNode:
    """A join operation in the plan tree."""
    join_type: str          # Nested Loop, Hash Join, Merge Join
    inner_table: str = ""
    outer_table: str = ""
    join_condition: str = ""
    estimated_cost: float = 0.0
    actual_cost: float = 0.0
    estimated_rows: int = 0
    actual_rows: int = 0
    depth: int = 0

    @property
    def cost_error_ratio(self) -> float:
        if self.estimated_cost <= 0:
            return 0.0
        return abs(self.actual_cost - self.estimated_cost) / self.estimated_cost


@dataclass
class GEQOFinding:
    """A finding from GEQO analysis."""
    severity: str           # critical, warning, info
    title: str
    description: str
    impact_score: float = 0.0
    recommendation: str = ""
    sql_hint: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "impact_score": round(self.impact_score, 2),
            "recommendation": self.recommendation,
            "sql_hint": self.sql_hint,
            "metrics": self.metrics,
        }


@dataclass
class GEQOAnalysisResult:
    """Result of GEQO analysis."""
    join_count: int = 0
    geqo_active: bool = False
    geqo_threshold: int = 12  # Default PostgreSQL setting
    join_nodes: list[JoinNode] = field(default_factory=list)
    findings: list[GEQOFinding] = field(default_factory=list)
    join_order_quality: float = 0.0  # 0-1, estimated quality of current join order
    tables_involved: list[str] = field(default_factory=list)
    total_join_cost: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "join_count": self.join_count,
            "geqo_active": self.geqo_active,
            "geqo_threshold": self.geqo_threshold,
            "join_order_quality": round(self.join_order_quality, 2),
            "tables_involved": self.tables_involved,
            "total_join_cost": round(self.total_join_cost, 2),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  GEQO (Genetic Query Optimizer) ANALYSIS")
        lines.append("  " + "=" * 60)
        lines.append(f"  Join count: {self.join_count} (GEQO threshold: {self.geqo_threshold})")
        lines.append(f"  GEQO active: {'YES' if self.geqo_active else 'No'}")
        lines.append(f"  Tables: {', '.join(self.tables_involved)}")
        lines.append(f"  Join order quality: {self.join_order_quality:.0%}")
        lines.append(f"  Total join cost: {self.total_join_cost:,.0f}")
        lines.append("")

        if self.join_nodes:
            lines.append("  Join Tree:")
            for jn in self.join_nodes:
                indent = "    " + "  " * jn.depth
                err = f" [ERROR: {jn.cost_error_ratio:.1f}x]" if jn.cost_error_ratio > 2 else ""
                lines.append(
                    f"{indent}{jn.join_type}: "
                    f"{jn.outer_table} x {jn.inner_table} "
                    f"(cost: {jn.estimated_cost:,.0f}{err})"
                )
            lines.append("")

        for finding in self.findings:
            severity_mark = {"critical": "[!!]", "warning": "[! ]", "info": "[  ]"}.get(finding.severity, "[  ]")
            lines.append(f"  {severity_mark} {finding.title}")
            lines.append(f"       {finding.description}")
            if finding.recommendation:
                lines.append(f"       Fix: {finding.recommendation}")
            if finding.sql_hint:
                lines.append(f"       SQL: {finding.sql_hint}")
            lines.append("")

        return "\n".join(lines)


class GEQOAnalyzer:
    """Analyze GEQO behavior and join ordering quality."""

    def __init__(self, geqo_threshold: int = 12):
        self.geqo_threshold = geqo_threshold

    def analyze(self, plan_data: dict[str, Any] | list) -> GEQOAnalysisResult:
        """Analyze a plan for GEQO-related issues."""
        plan = self._extract_plan(plan_data)
        if not plan:
            return GEQOAnalysisResult()

        # Extract join tree
        join_nodes: list[JoinNode] = []
        tables: set[str] = set()
        self._extract_joins(plan, join_nodes, tables, depth=0)

        join_count = len(join_nodes)
        geqo_active = join_count >= self.geqo_threshold

        # Analyze join quality
        quality = self._assess_join_quality(join_nodes)
        total_cost = sum(jn.estimated_cost for jn in join_nodes)

        # Generate findings
        findings = self._generate_findings(join_nodes, join_count, geqo_active, quality, list(tables))

        return GEQOAnalysisResult(
            join_count=join_count,
            geqo_active=geqo_active,
            geqo_threshold=self.geqo_threshold,
            join_nodes=join_nodes,
            findings=findings,
            join_order_quality=quality,
            tables_involved=sorted(tables),
            total_join_cost=total_cost,
        )

    def _extract_joins(
        self,
        node: dict[str, Any],
        joins: list[JoinNode],
        tables: set[str],
        depth: int,
    ) -> None:
        """Walk plan tree and extract join nodes."""
        nt = node.get("Node Type", "")

        # Collect table names
        rel = node.get("Relation Name")
        if rel:
            tables.add(rel)

        # Detect join nodes
        if "Join" in nt or nt == "Nested Loop":
            children = node.get("Plans", [])
            outer_table = self._find_table(children[0]) if children else ""
            inner_table = self._find_table(children[1]) if len(children) > 1 else ""

            join_cond = (
                node.get("Hash Cond", "")
                or node.get("Merge Cond", "")
                or node.get("Join Filter", "")
            )

            joins.append(JoinNode(
                join_type=nt,
                inner_table=inner_table,
                outer_table=outer_table,
                join_condition=join_cond,
                estimated_cost=node.get("Total Cost", 0.0),
                actual_cost=node.get("Actual Total Time") or 0.0,
                estimated_rows=node.get("Plan Rows", 0),
                actual_rows=node.get("Actual Rows") or 0,
                depth=depth,
            ))

        for child in node.get("Plans", []):
            self._extract_joins(child, joins, tables, depth + 1)

    def _find_table(self, node: dict[str, Any]) -> str:
        """Find the primary table accessed by a subtree."""
        if node.get("Relation Name"):
            return node["Relation Name"]
        for child in node.get("Plans", []):
            result = self._find_table(child)
            if result:
                return result
        return node.get("Node Type", "")

    def _assess_join_quality(self, joins: list[JoinNode]) -> float:
        """Estimate quality of the current join order (0-1)."""
        if not joins:
            return 1.0

        # Heuristics for good join ordering:
        # 1. Small tables should be on the inner side of nested loops
        # 2. Large tables should use hash/merge joins
        # 3. Cost estimation errors indicate suboptimal choices
        quality = 1.0

        for jn in joins:
            # Nested loop on large result sets is usually suboptimal
            if jn.join_type == "Nested Loop" and jn.actual_rows > 50000:
                quality -= 0.15

            # Large estimation errors suggest wrong join order
            if jn.cost_error_ratio > 5:
                quality -= 0.10
            elif jn.cost_error_ratio > 2:
                quality -= 0.05

        return max(0.0, min(1.0, quality))

    def _generate_findings(
        self,
        joins: list[JoinNode],
        join_count: int,
        geqo_active: bool,
        quality: float,
        tables: list[str],
    ) -> list[GEQOFinding]:
        """Generate findings from GEQO analysis."""
        findings: list[GEQOFinding] = []

        # GEQO activation
        if geqo_active:
            findings.append(GEQOFinding(
                severity="info",
                title="Genetic Query Optimizer Active",
                description=(
                    f"Query joins {join_count} tables (threshold: {self.geqo_threshold}). "
                    f"PostgreSQL is using the Genetic Query Optimizer (GEQO) which uses "
                    f"evolutionary algorithms to find a good join order. The result may not be "
                    f"optimal -- it depends on the random seed (geqo_seed)."
                ),
                impact_score=3.0 + (join_count - self.geqo_threshold) * 0.5,
                recommendation=(
                    "Test plan stability: run EXPLAIN 5 times with different geqo_seed values. "
                    "If plans vary significantly, consider explicit join order."
                ),
                sql_hint=(
                    f"-- Test plan stability:\n"
                    f"SET geqo_seed = 0.1; EXPLAIN (ANALYZE) <query>;\n"
                    f"SET geqo_seed = 0.5; EXPLAIN (ANALYZE) <query>;\n"
                    f"SET geqo_seed = 0.9; EXPLAIN (ANALYZE) <query>;"
                ),
                metrics={"join_count": join_count, "table_count": len(tables)},
            ))

        # Near GEQO threshold
        elif join_count >= self.geqo_threshold - 2:
            findings.append(GEQOFinding(
                severity="info",
                title="Near GEQO Threshold",
                description=(
                    f"Query joins {join_count} tables, just below GEQO threshold ({self.geqo_threshold}). "
                    f"Adding one more JOIN could trigger the genetic optimizer."
                ),
                impact_score=2.0,
                recommendation=(
                    "Consider increasing join_collapse_limit to allow exhaustive search: "
                    f"SET join_collapse_limit = {join_count + 4};"
                ),
                sql_hint=f"SET join_collapse_limit = {join_count + 4};",
            ))

        # Nested loop on large tables
        bad_nested_loops = [j for j in joins if j.join_type == "Nested Loop" and j.actual_rows > 50000]
        if bad_nested_loops:
            for jn in bad_nested_loops:
                findings.append(GEQOFinding(
                    severity="warning",
                    title=f"Nested Loop on Large Result ({jn.actual_rows:,} rows)",
                    description=(
                        f"Nested Loop join between {jn.outer_table} and {jn.inner_table} "
                        f"producing {jn.actual_rows:,} rows. Hash Join or Merge Join would "
                        f"likely be faster for this data volume."
                    ),
                    impact_score=min(9.0, 4.0 + math.log10(max(jn.actual_rows, 1))),
                    recommendation="Force hash join or improve statistics so planner chooses it",
                    sql_hint="SET LOCAL enable_nestloop = off; -- then run query",
                    metrics={
                        "join_type": jn.join_type,
                        "actual_rows": jn.actual_rows,
                        "estimated_rows": jn.estimated_rows,
                    },
                ))

        # Join cost estimation errors
        bad_estimates = [j for j in joins if j.cost_error_ratio > 5]
        if bad_estimates:
            worst = max(bad_estimates, key=lambda j: j.cost_error_ratio)
            findings.append(GEQOFinding(
                severity="warning",
                title=f"Join Cost Estimation Error ({worst.cost_error_ratio:.0f}x off)",
                description=(
                    f"Join between {worst.outer_table} and {worst.inner_table} has a "
                    f"{worst.cost_error_ratio:.0f}x cost estimation error. The planner may have "
                    f"chosen this join order based on incorrect cost assumptions."
                ),
                impact_score=min(8.0, 3.0 + worst.cost_error_ratio * 0.5),
                recommendation=(
                    "Run ANALYZE on involved tables. If errors persist, check for "
                    "correlated columns (consider CREATE STATISTICS for multi-column stats)."
                ),
                sql_hint=(
                    f"ANALYZE {worst.outer_table};\n"
                    f"ANALYZE {worst.inner_table};\n"
                    f"-- For correlated columns:\n"
                    f"CREATE STATISTICS st_{worst.outer_table} ON col1, col2 FROM {worst.outer_table};"
                ),
            ))

        # Low join quality
        if quality < 0.5 and join_count >= 4:
            findings.append(GEQOFinding(
                severity="critical",
                title=f"Suboptimal Join Order (quality: {quality:.0%})",
                description=(
                    f"The join order quality is estimated at {quality:.0%}. Multiple signals "
                    f"indicate the planner chose a suboptimal execution strategy: nested loops "
                    f"on large tables, significant cost estimation errors, and/or deep join trees."
                ),
                impact_score=8.0,
                recommendation=(
                    "Consider: (1) explicit join order with join_collapse_limit=1, "
                    "(2) better statistics with ANALYZE, (3) increasing geqo_generations "
                    "for more thorough genetic search."
                ),
                sql_hint=(
                    "-- Force explicit join order:\n"
                    "SET LOCAL join_collapse_limit = 1;\n"
                    f"-- Or increase GEQO thoroughness:\n"
                    f"SET geqo_generations = {join_count * 2};\n"
                    f"SET geqo_pool_size = {join_count * 3};"
                ),
            ))

        return findings

    def _extract_plan(self, data: Any) -> dict[str, Any] | None:
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            return data.get("Plan", data if "Node Type" in data else None)
        return None
