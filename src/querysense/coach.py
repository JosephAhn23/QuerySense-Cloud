"""
QuerySense Coach — step-by-step optimization wizard.

Based on the "Ultimate Optimization Algorithm" from "PostgreSQL Query
Optimization" (Dombrovskaya et al. 2024, final chapter).

Guides developers through a systematic optimization process:
Step 1: Check statistics freshness
Step 2: Classify query type (OLTP vs OLAP)
Step 3: Examine sequential scans
Step 4: Review join order and types
Step 5: Check index usage
Step 6: Analyze sorts and aggregations
Step 7: Evaluate memory settings
Step 8: Consider parallelism
Step 9: Test improvements
Step 10: Generate implementation plan

Each step produces findings, educational context, and specific actions.

Usage:
    from querysense.coach import Coach, CoachSession

    coach = Coach()
    session = coach.start(explain_output, sql="SELECT ...")
    for step in session.steps:
        print(f"Step {step.number}: {step.title}")
        print(f"  Status: {step.status}")
        print(f"  Findings: {step.findings}")
        print(f"  Actions: {step.actions}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class StepStatus(str, Enum):
    PASS = "pass"
    WARN = "warning"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class CoachAction:
    """A specific action to take."""
    description: str
    sql: str = ""
    priority: int = 1  # 1=highest
    category: str = ""


@dataclass
class CoachStep:
    """A single step in the optimization walkthrough."""
    number: int
    title: str
    status: StepStatus
    explanation: str  # Educational context — the "why"
    findings: list[str] = field(default_factory=list)
    actions: list[CoachAction] = field(default_factory=list)
    reference: str = ""  # Textbook reference

    @property
    def has_issues(self) -> bool:
        return self.status in (StepStatus.WARN, StepStatus.FAIL)


@dataclass
class CoachSession:
    """A complete coaching session."""
    steps: list[CoachStep] = field(default_factory=list)
    summary: str = ""
    overall_status: StepStatus = StepStatus.PASS
    priority_actions: list[CoachAction] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for s in self.steps if s.status == StepStatus.PASS)

    @property
    def issue_count(self) -> int:
        return sum(1 for s in self.steps if s.has_issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "overall_status": self.overall_status.value,
            "steps": [
                {
                    "number": s.number,
                    "title": s.title,
                    "status": s.status.value,
                    "explanation": s.explanation,
                    "findings": s.findings,
                    "actions": [
                        {"description": a.description, "sql": a.sql, "priority": a.priority}
                        for a in s.actions
                    ],
                }
                for s in self.steps
            ],
            "priority_actions": [
                {"description": a.description, "sql": a.sql, "priority": a.priority}
                for a in self.priority_actions
            ],
        }


class Coach:
    """
    The QuerySense Coach — implements the Ultimate Optimization Algorithm.

    Takes an EXPLAIN plan (and optional SQL), walks through each step
    of the systematic optimization process, and produces an educational
    session with specific actions.
    """

    def start(
        self,
        plan_data: Any,
        sql: str = "",
        analysis_result: Any = None,
    ) -> CoachSession:
        """
        Start a coaching session.

        Args:
            plan_data: ExplainOutput or raw EXPLAIN dict
            sql: Optional SQL text
            analysis_result: Optional AnalysisResult from querysense.engine

        Returns:
            CoachSession with all steps and prioritized actions
        """
        session = CoachSession()

        # Extract nodes and metadata
        nodes = self._get_nodes(plan_data)
        findings = []
        if analysis_result:
            findings = list(getattr(analysis_result, "findings", []))

        # Run each step
        session.steps.append(self._step1_statistics(nodes, findings))
        session.steps.append(self._step2_classify(plan_data, sql))
        session.steps.append(self._step3_seq_scans(nodes, findings))
        session.steps.append(self._step4_joins(nodes, findings))
        session.steps.append(self._step5_indexes(nodes, findings))
        session.steps.append(self._step6_sorts(nodes, findings))
        session.steps.append(self._step7_memory(nodes, findings))
        session.steps.append(self._step8_parallelism(nodes, findings))
        session.steps.append(self._step9_test(plan_data))
        session.steps.append(self._step10_plan(session))

        # Overall status
        if any(s.status == StepStatus.FAIL for s in session.steps):
            session.overall_status = StepStatus.FAIL
        elif any(s.status == StepStatus.WARN for s in session.steps):
            session.overall_status = StepStatus.WARN
        else:
            session.overall_status = StepStatus.PASS

        # Collect priority actions
        all_actions: list[CoachAction] = []
        for step in session.steps:
            all_actions.extend(step.actions)
        session.priority_actions = sorted(all_actions, key=lambda a: a.priority)[:10]

        # Summary
        session.summary = (
            f"Analyzed {len(nodes)} plan nodes across 10 optimization steps. "
            f"{session.pass_count} passed, {session.issue_count} need attention. "
            f"{len(session.priority_actions)} priority actions identified."
        )

        return session

    def _get_nodes(self, plan_data: Any) -> list[Any]:
        """Extract all plan nodes."""
        if hasattr(plan_data, "all_nodes"):
            return list(plan_data.all_nodes)
        if isinstance(plan_data, dict):
            return self._collect_nodes_dict(plan_data.get("Plan", plan_data))
        return []

    def _collect_nodes_dict(self, plan: dict) -> list[dict]:
        nodes = [plan]
        for child in plan.get("Plans", []):
            nodes.extend(self._collect_nodes_dict(child))
        return nodes

    def _node_type(self, node: Any) -> str:
        if isinstance(node, dict):
            return node.get("Node Type", "")
        return getattr(node, "node_type", "")

    def _node_rows(self, node: Any) -> int:
        if isinstance(node, dict):
            return node.get("Actual Rows", node.get("Plan Rows", 0))
        return getattr(node, "actual_rows", 0) or getattr(node, "plan_rows", 0) or 0

    def _step1_statistics(self, nodes: list, findings: list) -> CoachStep:
        """Step 1: Check statistics freshness."""
        stale = [f for f in findings if "stale" in getattr(f, "rule_id", "").lower() or
                 "statistic" in getattr(f, "title", "").lower()]
        bad_estimates = [f for f in findings if "estimation" in getattr(f, "title", "").lower() or
                        "row_estimate" in getattr(f, "rule_id", "").lower().replace("_", "")]

        status = StepStatus.PASS
        step_findings = []
        actions = []

        if stale:
            status = StepStatus.FAIL
            step_findings.append(f"Found {len(stale)} stale statistics warning(s)")
            for f in stale:
                table = getattr(f, "context", {})
                actions.append(CoachAction(
                    description=f"Update statistics: {getattr(f, 'title', '')}",
                    sql=getattr(f, "suggestion", "ANALYZE;"),
                    priority=1,
                    category="statistics",
                ))

        if bad_estimates:
            status = StepStatus.FAIL if not stale else status
            step_findings.append(f"Found {len(bad_estimates)} row estimation error(s)")
            actions.append(CoachAction(
                description="Run ANALYZE on affected tables to update statistics",
                sql="ANALYZE;",
                priority=1,
                category="statistics",
            ))

        if not stale and not bad_estimates:
            step_findings.append("Statistics appear up-to-date")

        return CoachStep(
            number=1,
            title="Check Statistics Freshness",
            status=status,
            explanation=(
                "PostgreSQL's query planner relies on table statistics (row counts, "
                "value distributions) to choose the best execution plan. Stale stats "
                "cause the planner to make wrong estimates, leading to bad plans. "
                "ANALYZE updates these statistics. Run it after bulk loads, schema "
                "changes, or when you see row estimation errors."
            ),
            findings=step_findings,
            actions=actions,
            reference="PostgreSQL Query Optimization (Dombrovskaya 2024), Ch. 4",
        )

    def _step2_classify(self, plan_data: Any, sql: str) -> CoachStep:
        """Step 2: Classify query type."""
        from querysense.query_classifier import QueryClassifier

        classifier = QueryClassifier()
        if sql:
            classification = classifier.classify_sql(sql)
        else:
            classification = classifier.classify(plan_data)

        step_findings = [
            f"Query type: {classification.query_type.value.upper()} "
            f"(confidence: {classification.confidence:.0%})",
            f"Complexity: {classification.complexity.value}",
        ]

        actions = [
            CoachAction(
                description=rec,
                priority=3,
                category="classification",
            )
            for rec in classification.recommendations[:3]
        ]

        return CoachStep(
            number=2,
            title="Classify Query Type (OLTP vs OLAP)",
            status=StepStatus.PASS,
            explanation=(
                "OLTP queries (short, indexed lookups) and OLAP queries (analytical, "
                "aggregation-heavy) need completely different optimization strategies. "
                "OLTP: minimize latency with index-only scans. "
                "OLAP: maximize throughput with parallelism and higher work_mem."
            ),
            findings=step_findings,
            actions=actions,
            reference="PostgreSQL Query Optimization (Dombrovskaya 2024), Ch. 2",
        )

    def _step3_seq_scans(self, nodes: list, findings: list) -> CoachStep:
        """Step 3: Examine sequential scans."""
        seq_scans = [n for n in nodes if "Seq Scan" in self._node_type(n)]
        large_seq = [n for n in seq_scans if self._node_rows(n) > 10000]

        status = StepStatus.PASS
        step_findings = []
        actions = []

        if large_seq:
            status = StepStatus.FAIL
            step_findings.append(f"{len(large_seq)} large sequential scan(s) detected")
            for n in large_seq[:3]:
                rows = self._node_rows(n)
                step_findings.append(f"  Seq Scan: {rows:,} rows")
        elif seq_scans:
            status = StepStatus.WARN
            step_findings.append(f"{len(seq_scans)} sequential scan(s), but on small tables")
        else:
            step_findings.append("No sequential scans — good index usage")

        # Pull fixes from analysis findings
        for f in findings:
            if "seq" in getattr(f, "rule_id", "").lower() and getattr(f, "suggestion", ""):
                actions.append(CoachAction(
                    description=getattr(f, "title", "Add index"),
                    sql=getattr(f, "suggestion", ""),
                    priority=1,
                    category="index",
                ))

        return CoachStep(
            number=3,
            title="Examine Sequential Scans",
            status=status,
            explanation=(
                "Sequential scans read every row in a table — O(n) complexity. "
                "For small tables (<10k rows), this is fine. For large tables, "
                "an index scan is typically 10-1000x faster. Create an index on "
                "the columns used in WHERE, JOIN, and ORDER BY clauses."
            ),
            findings=step_findings,
            actions=actions,
            reference="PostgreSQL Query Optimization (Dombrovskaya 2024), Ch. 6",
        )

    def _step4_joins(self, nodes: list, findings: list) -> CoachStep:
        """Step 4: Review join order and types."""
        joins = [n for n in nodes if "Join" in self._node_type(n) or "Nested Loop" in self._node_type(n)]
        nested_loops = [n for n in joins if "Nested Loop" in self._node_type(n)]

        status = StepStatus.PASS
        step_findings = []
        actions = []

        if not joins:
            step_findings.append("No joins in this query")
            return CoachStep(
                number=4, title="Review Join Order & Types", status=StepStatus.SKIP,
                explanation="This query has no joins.", findings=step_findings, actions=actions,
            )

        step_findings.append(f"{len(joins)} join(s) detected")

        for n in nested_loops:
            loops = 0
            if isinstance(n, dict):
                loops = n.get("Actual Loops", 0)
            else:
                loops = getattr(n, "actual_loops", 0) or 0
            if loops > 100:
                status = StepStatus.WARN
                step_findings.append(
                    f"Nested Loop with {loops:,} iterations — consider index on inner table"
                )

        join_findings = [f for f in findings if "join" in getattr(f, "rule_id", "").lower() or
                        "nested" in getattr(f, "rule_id", "").lower()]
        for f in join_findings:
            if getattr(f, "suggestion", ""):
                actions.append(CoachAction(
                    description=getattr(f, "title", ""),
                    sql=getattr(f, "suggestion", ""),
                    priority=2,
                    category="join",
                ))

        return CoachStep(
            number=4,
            title="Review Join Order & Types",
            status=status,
            explanation=(
                "PostgreSQL has three join strategies: Nested Loop (good for small inners), "
                "Hash Join (good for large equi-joins), and Merge Join (good for sorted data). "
                "A Nested Loop with many iterations suggests the inner table needs an index. "
                "The planner chooses join order — if it's wrong, check statistics and consider "
                "increasing join_collapse_limit."
            ),
            findings=step_findings,
            actions=actions,
            reference="PostgreSQL Query Optimization (Dombrovskaya 2024), Ch. 8",
        )

    def _step5_indexes(self, nodes: list, findings: list) -> CoachStep:
        """Step 5: Check index usage."""
        idx_scans = [n for n in nodes if "Index" in self._node_type(n)]

        step_findings = [f"{len(idx_scans)} index scan(s) in plan"]
        actions = []

        # Check for index-related findings
        idx_findings = [f for f in findings if "index" in getattr(f, "rule_id", "").lower()]
        if idx_findings:
            step_findings.append(f"{len(idx_findings)} index optimization(s) suggested")
            for f in idx_findings[:3]:
                if getattr(f, "suggestion", ""):
                    actions.append(CoachAction(
                        description=getattr(f, "title", ""),
                        sql=getattr(f, "suggestion", ""),
                        priority=2,
                        category="index",
                    ))

        return CoachStep(
            number=5,
            title="Check Index Usage & Opportunities",
            status=StepStatus.WARN if idx_findings else StepStatus.PASS,
            explanation=(
                "Beyond basic B-tree indexes, consider: partial indexes (WHERE clause "
                "reduces size), expression indexes (for functions in WHERE), covering "
                "indexes (INCLUDE avoids heap fetches), and multi-column indexes "
                "(leftmost prefix rule applies)."
            ),
            findings=step_findings,
            actions=actions,
            reference="Mastering PostgreSQL 13 (Schönig 2020), Ch. 7",
        )

    def _step6_sorts(self, nodes: list, findings: list) -> CoachStep:
        """Step 6: Analyze sorts and aggregations."""
        sorts = [n for n in nodes if "Sort" in self._node_type(n)]
        aggs = [n for n in nodes if "Aggregate" in self._node_type(n) or "Group" in self._node_type(n)]

        step_findings = []
        actions = []
        status = StepStatus.PASS

        if sorts:
            step_findings.append(f"{len(sorts)} sort operation(s)")
        if aggs:
            step_findings.append(f"{len(aggs)} aggregation operation(s)")

        sort_findings = [f for f in findings if "sort" in getattr(f, "rule_id", "").lower() or
                        "spill" in getattr(f, "rule_id", "").lower() or
                        "work_mem" in getattr(f, "rule_id", "").lower()]
        if sort_findings:
            status = StepStatus.WARN
            for f in sort_findings:
                step_findings.append(getattr(f, "title", ""))
                if getattr(f, "suggestion", ""):
                    actions.append(CoachAction(
                        description=getattr(f, "title", ""),
                        sql=getattr(f, "suggestion", ""),
                        priority=2,
                        category="memory",
                    ))

        if not sorts and not aggs:
            step_findings.append("No sorts or aggregations in this query")

        return CoachStep(
            number=6,
            title="Analyze Sorts & Aggregations",
            status=status,
            explanation=(
                "Sorts that exceed work_mem spill to disk, which is 10-100x slower. "
                "If a sort is spilling, increase work_mem for the session. "
                "Alternatively, create an index that provides pre-sorted data."
            ),
            findings=step_findings,
            actions=actions,
            reference="PostgreSQL Query Optimization (Dombrovskaya 2024), Ch. 10",
        )

    def _step7_memory(self, nodes: list, findings: list) -> CoachStep:
        """Step 7: Evaluate memory settings."""
        mem_findings = [f for f in findings if "work_mem" in getattr(f, "rule_id", "").lower() or
                       "memory" in getattr(f, "title", "").lower() or
                       "spill" in getattr(f, "title", "").lower()]

        status = StepStatus.WARN if mem_findings else StepStatus.PASS
        step_findings = []
        actions = []

        if mem_findings:
            step_findings.append(f"{len(mem_findings)} memory-related finding(s)")
            for f in mem_findings:
                if getattr(f, "suggestion", ""):
                    actions.append(CoachAction(
                        description=getattr(f, "title", ""),
                        sql=getattr(f, "suggestion", ""),
                        priority=2,
                        category="memory",
                    ))
        else:
            step_findings.append("Memory usage appears adequate")

        return CoachStep(
            number=7,
            title="Evaluate Memory Settings",
            status=status,
            explanation=(
                "work_mem controls how much memory sorts and hash operations can use "
                "before spilling to disk. The default (4MB) is conservative. For OLAP "
                "queries, SET work_mem = '128MB' at session level. For OLTP, keep it "
                "low to leave RAM for connections."
            ),
            findings=step_findings,
            actions=actions,
            reference="PostgreSQL Mistakes (Angelakos 2025), Ch. 3",
        )

    def _step8_parallelism(self, nodes: list, findings: list) -> CoachStep:
        """Step 8: Consider parallelism."""
        gather = [n for n in nodes if "Gather" in self._node_type(n)]
        parallel_findings = [f for f in findings if "parallel" in getattr(f, "rule_id", "").lower() or
                           "worker" in getattr(f, "rule_id", "").lower()]

        status = StepStatus.PASS
        step_findings = []
        actions = []

        if gather:
            step_findings.append(f"Query uses {len(gather)} parallel gather node(s) — good")
        elif parallel_findings:
            status = StepStatus.WARN
            step_findings.append("Parallel query not being used despite potential benefit")
            actions.append(CoachAction(
                description="Enable parallel query workers",
                sql="SET max_parallel_workers_per_gather = 4;",
                priority=3,
                category="parallelism",
            ))
        else:
            step_findings.append("Parallelism not applicable for this query size")

        return CoachStep(
            number=8,
            title="Consider Parallelism",
            status=status,
            explanation=(
                "PostgreSQL can parallelize sequential scans, aggregations, and joins "
                "across multiple CPU cores. This benefits OLAP queries on large tables. "
                "Set max_parallel_workers_per_gather > 0 to enable."
            ),
            findings=step_findings,
            actions=actions,
            reference="PostgreSQL Query Optimization (Dombrovskaya 2024), Ch. 11",
        )

    def _step9_test(self, plan_data: Any) -> CoachStep:
        """Step 9: Provide testing guidance."""
        return CoachStep(
            number=9,
            title="Test Improvements",
            status=StepStatus.PASS,
            explanation=(
                "After applying fixes, re-run EXPLAIN ANALYZE to verify improvement. "
                "Use 'querysense diff before.json after.json' to compare plans. "
                "Test with production-like data volumes — plans change with row counts."
            ),
            findings=["Re-run EXPLAIN ANALYZE after each change"],
            actions=[
                CoachAction(
                    description="Export current plan as baseline, then compare after fixes",
                    sql="-- Before: EXPLAIN (ANALYZE, FORMAT JSON) <query> > before.json\n"
                        "-- Apply fix\n"
                        "-- After:  EXPLAIN (ANALYZE, FORMAT JSON) <query> > after.json\n"
                        "-- Compare: querysense diff before.json after.json",
                    priority=5,
                    category="testing",
                ),
            ],
            reference="PostgreSQL Query Optimization (Dombrovskaya 2024), Ch. 12",
        )

    def _step10_plan(self, session: CoachSession) -> CoachStep:
        """Step 10: Generate implementation plan."""
        total_actions = sum(len(s.actions) for s in session.steps)
        priority_actions = sorted(
            [a for s in session.steps for a in s.actions],
            key=lambda a: a.priority,
        )[:5]

        return CoachStep(
            number=10,
            title="Implementation Plan",
            status=StepStatus.PASS,
            explanation=(
                "Apply changes in priority order. Test after each change. "
                "Statistics updates (ANALYZE) should always come first, as "
                "they may resolve other issues automatically."
            ),
            findings=[
                f"{total_actions} total action(s) identified",
                f"Top {len(priority_actions)} priority action(s):",
            ] + [f"  {i+1}. {a.description}" for i, a in enumerate(priority_actions)],
            actions=priority_actions,
            reference="All textbooks agree: systematic, step-by-step optimization beats guessing",
        )
