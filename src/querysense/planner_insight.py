"""
Planner Behavior Engine — explains WHY PostgreSQL chose each plan decision.

Codifies the textbook logic from:
- Peng & Peng Ch. 5: Query Compilation and Cost Estimation
- Dombrovskaya Ch. 4-5: Understanding Execution Plans and Index Selection
- Rogov "PostgreSQL Internals" (2023): Cost model internals

Instead of just saying "Seq Scan detected," this module explains:
  "PostgreSQL chose Seq Scan because:
   1. No index exists on the filter column 'status'
   2. Even with an index, random_page_cost=4.0 makes index scans 4x more
      expensive per page than sequential reads
   3. The table has 1.2M rows and the WHERE clause filters ~30%, which
      exceeds the planner's ~5% threshold for index scan preference"

This closes the gap with pganalyze's "purpose-built logic based on
Postgres planner behavior" while being fully transparent about the reasoning.

Usage:
    from querysense.planner_insight import PlannerInsight, explain_plan_choices

    insights = explain_plan_choices(plan_json)
    for insight in insights:
        print(f"{insight.node_type}: {insight.explanation}")
        for factor in insight.decision_factors:
            print(f"  - {factor}")
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Data Classes ───────────────────────────────────────────────────────


@dataclass
class DecisionFactor:
    """A single factor that influenced the planner's decision."""

    factor: str          # What the factor is
    value: str           # Current value
    influence: str       # How it influenced the decision
    adjustable: bool     # Whether the user can change this
    fix_hint: str = ""   # How to change it

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor": self.factor,
            "value": self.value,
            "influence": self.influence,
            "adjustable": self.adjustable,
            "fix_hint": self.fix_hint,
        }


@dataclass
class PlannerInsight:
    """Explains why the planner chose a specific operator for a node."""

    node_id: str
    node_type: str
    relation: str
    explanation: str              # Human-readable explanation
    decision_factors: list[DecisionFactor] = field(default_factory=list)
    alternative_paths: list[str] = field(default_factory=list)  # What the planner rejected
    planner_rule: str = ""        # The planner heuristic that applied
    cost_model_detail: str = ""   # Cost formula explanation
    textbook_ref: str = ""        # Source reference

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "relation": self.relation,
            "explanation": self.explanation,
            "decision_factors": [f.to_dict() for f in self.decision_factors],
            "alternative_paths": self.alternative_paths,
            "planner_rule": self.planner_rule,
            "cost_model_detail": self.cost_model_detail,
            "textbook_ref": self.textbook_ref,
        }


# ── Planner Cost Model Constants (PostgreSQL defaults) ────────────────


PG_DEFAULTS = {
    "seq_page_cost": 1.0,
    "random_page_cost": 4.0,
    "cpu_tuple_cost": 0.01,
    "cpu_index_tuple_cost": 0.005,
    "cpu_operator_cost": 0.0025,
    "parallel_tuple_cost": 0.1,
    "parallel_setup_cost": 1000.0,
    "effective_cache_size": 4 * 1024 * 1024,  # 4GB in 8kB pages
}


# ── Insight Generators ─────────────────────────────────────────────────


def explain_plan_choices(
    plan_json: str | dict,
    settings: dict[str, Any] | None = None,
) -> list[PlannerInsight]:
    """
    Analyze a PostgreSQL EXPLAIN plan and explain every planner decision.

    Args:
        plan_json: EXPLAIN (FORMAT JSON) output
        settings: Optional dict of current PostgreSQL settings
            (random_page_cost, work_mem, etc.)

    Returns:
        List of PlannerInsight objects explaining each node
    """
    if isinstance(plan_json, str):
        try:
            data = json.loads(plan_json)
        except json.JSONDecodeError:
            return []
    else:
        data = plan_json

    if isinstance(data, list):
        data = data[0]

    plan = data.get("Plan", data)
    config = {**PG_DEFAULTS, **(settings or {})}

    insights: list[PlannerInsight] = []
    _analyze_node(plan, insights, config, path="0", parent=None)

    return insights


def _analyze_node(
    node: dict,
    insights: list[PlannerInsight],
    config: dict[str, Any],
    path: str,
    parent: dict | None,
) -> None:
    """Recursively analyze each node's planner decision."""
    node_type = node.get("Node Type", "Unknown")
    relation = node.get("Relation Name", "")
    index_name = node.get("Index Name", "")

    insight = None

    if "Scan" in node_type:
        insight = _explain_scan_choice(node, config, path, parent)
    elif "Join" in node_type or node_type == "Nested Loop":
        insight = _explain_join_choice(node, config, path, parent)
    elif "Sort" in node_type:
        insight = _explain_sort_choice(node, config, path, parent)
    elif "Aggregate" in node_type or node_type == "HashAggregate" or node_type == "GroupAggregate":
        insight = _explain_aggregate_choice(node, config, path)
    elif node_type == "Gather" or node_type == "Gather Merge":
        insight = _explain_parallel_choice(node, config, path)
    elif node_type == "Materialize":
        insight = _explain_materialize_choice(node, config, path)

    if insight:
        insights.append(insight)

    # Recurse into children
    for i, child in enumerate(node.get("Plans", [])):
        _analyze_node(child, insights, config, f"{path}.{i}", parent=node)


def _explain_scan_choice(
    node: dict, config: dict, path: str, parent: dict | None,
) -> PlannerInsight:
    """Explain why the planner chose this scan type."""
    node_type = node.get("Node Type", "")
    relation = node.get("Relation Name", "")
    index_name = node.get("Index Name", "")
    rows = node.get("Plan Rows", 0)
    total_cost = node.get("Total Cost", 0)
    filter_cond = node.get("Filter", "")
    index_cond = node.get("Index Cond", "")

    factors: list[DecisionFactor] = []
    alternatives: list[str] = []
    explanation = ""
    cost_detail = ""
    planner_rule = ""

    rpc = config.get("random_page_cost", 4.0)
    spc = config.get("seq_page_cost", 1.0)

    if node_type == "Seq Scan":
        explanation = f"PostgreSQL chose Sequential Scan on '{relation}'"

        # Factor 1: No index
        if not index_name and filter_cond:
            factors.append(DecisionFactor(
                factor="No index on filter column",
                value=f"Filter: {filter_cond}",
                influence="Without an index, Seq Scan is the only option for filtering",
                adjustable=True,
                fix_hint=f"CREATE INDEX ON {relation} (/* filter columns */)",
            ))
        elif not filter_cond:
            factors.append(DecisionFactor(
                factor="Full table access (no WHERE clause)",
                value="All rows needed",
                influence="Without filtering, sequential scan is optimal (reads every page once)",
                adjustable=False,
            ))

        # Factor 2: Selectivity
        actual_rows = node.get("Actual Rows")
        removed = node.get("Rows Removed by Filter", 0)
        if actual_rows is not None and removed > 0:
            selectivity = actual_rows / max(actual_rows + removed, 1)
            if selectivity > 0.05:
                factors.append(DecisionFactor(
                    factor="Low selectivity (too many rows match)",
                    value=f"{selectivity:.1%} of rows match ({actual_rows:,} / {actual_rows + removed:,})",
                    influence=(
                        f"Planner prefers Seq Scan when >~5% of rows match because "
                        f"random I/O from index scan costs {rpc:.1f}x per page "
                        f"vs {spc:.1f}x for sequential reads"
                    ),
                    adjustable=True,
                    fix_hint="Partial index or more selective WHERE clause",
                ))
            else:
                factors.append(DecisionFactor(
                    factor="Selectivity suggests index scan should be faster",
                    value=f"Only {selectivity:.2%} of rows match",
                    influence="Index scan rejected — likely no suitable index exists",
                    adjustable=True,
                    fix_hint=f"CREATE INDEX ON {relation} (/* filter column */) — should switch to Index Scan",
                ))

        # Factor 3: random_page_cost
        if rpc > 1.5:
            factors.append(DecisionFactor(
                factor="random_page_cost penalizes index scans",
                value=f"random_page_cost = {rpc}",
                influence=f"Each random page read costs {rpc}x vs {spc}x for sequential. On SSDs this should be ~1.1",
                adjustable=True,
                fix_hint=f"ALTER SYSTEM SET random_page_cost = 1.1;  -- if using SSDs",
            ))

        alternatives = ["Index Scan (if index existed)", "Index Only Scan (if covering index existed)"]
        cost_detail = f"Seq Scan cost ≈ (pages × seq_page_cost) + (rows × cpu_tuple_cost) = {total_cost:.1f}"
        planner_rule = "Sequential scan is chosen when no index provides a cheaper path"

    elif "Index Scan" in node_type or "Index Only Scan" in node_type:
        explanation = f"PostgreSQL chose {node_type} on '{relation}' using index '{index_name}'"

        factors.append(DecisionFactor(
            factor=f"Index '{index_name}' provides efficient access",
            value=f"Condition: {index_cond or 'N/A'}",
            influence="Index enables point/range lookups at O(log N) cost",
            adjustable=False,
        ))

        if "Only" in node_type:
            factors.append(DecisionFactor(
                factor="Index covers all needed columns (index-only scan)",
                value="No heap access needed",
                influence="Eliminates random I/O to heap — fastest possible access",
                adjustable=False,
            ))

            heap_fetches = node.get("Heap Fetches", 0)
            if heap_fetches and heap_fetches > 0:
                factors.append(DecisionFactor(
                    factor="Heap fetches degrading index-only scan",
                    value=f"{heap_fetches:,} heap fetches (not all-visible pages)",
                    influence="Pages modified since last VACUUM require heap access for visibility check",
                    adjustable=True,
                    fix_hint=f"VACUUM {relation}; -- marks pages as all-visible",
                ))

        alternatives = ["Seq Scan (rejected — index path is cheaper)"]
        planner_rule = "Index scan chosen when selectivity makes random I/O cheaper than full scan"

    elif node_type == "Bitmap Heap Scan":
        explanation = f"PostgreSQL chose Bitmap Scan on '{relation}'"
        factors.append(DecisionFactor(
            factor="Intermediate selectivity: too many rows for Index Scan, too few for Seq Scan",
            value=f"~{rows:,} rows estimated",
            influence=(
                "Bitmap Scan: (1) build bitmap from index, (2) sort by physical location, "
                "(3) read heap pages sequentially. Combines index precision with sequential I/O."
            ),
            adjustable=False,
        ))
        alternatives = ["Index Scan (rejected — too many random reads)", "Seq Scan (rejected — too many wasted reads)"]
        planner_rule = "Bitmap scan chosen when selectivity is between Index Scan and Seq Scan thresholds"

    else:
        explanation = f"Scan type: {node_type} on '{relation}'"

    textbook_ref = "Dombrovskaya Ch. 4-5; Peng & Peng Ch. 5.5: Cost Estimation"

    return PlannerInsight(
        node_id=path,
        node_type=node_type,
        relation=relation,
        explanation=explanation,
        decision_factors=factors,
        alternative_paths=alternatives,
        planner_rule=planner_rule,
        cost_model_detail=cost_detail,
        textbook_ref=textbook_ref,
    )


def _explain_join_choice(
    node: dict, config: dict, path: str, parent: dict | None,
) -> PlannerInsight:
    """Explain why the planner chose this join strategy."""
    node_type = node.get("Node Type", "")
    join_type = node.get("Join Type", "Inner")
    rows = node.get("Plan Rows", 0)
    total_cost = node.get("Total Cost", 0)
    hash_cond = node.get("Hash Cond", "")
    join_filter = node.get("Join Filter", "")

    children = node.get("Plans", [])
    outer = children[0] if children else {}
    inner = children[1] if len(children) > 1 else {}
    outer_rows = outer.get("Plan Rows", 0)
    inner_rows = inner.get("Plan Rows", 0)

    factors: list[DecisionFactor] = []
    alternatives: list[str] = []
    explanation = ""

    if node_type == "Hash Join":
        explanation = f"PostgreSQL chose Hash Join ({join_type})"
        factors.append(DecisionFactor(
            factor="Hash Join: build hash table from inner, probe with outer",
            value=f"Inner: {inner_rows:,} rows → hash table, Outer: {outer_rows:,} rows probe",
            influence=(
                f"Hash Join is O(N + M) — builds hash table from smaller side ({inner_rows:,} rows), "
                f"then probes once per outer row ({outer_rows:,}). Requires work_mem to fit hash table."
            ),
            adjustable=False,
        ))

        hash_batches = node.get("Hash Batches", 1)
        if hash_batches > 1:
            factors.append(DecisionFactor(
                factor="Hash spills to multiple batches (work_mem too small)",
                value=f"{hash_batches} batches (only 1 is in-memory)",
                influence=f"Each additional batch doubles I/O. With {hash_batches} batches, data is read {hash_batches}x",
                adjustable=True,
                fix_hint=f"SET work_mem = '{max(64, hash_batches * 16)}MB';  -- session-level",
            ))

        alternatives = [
            f"Merge Join (requires sorted input — may need explicit Sort)",
            f"Nested Loop (O(N*M) = {outer_rows * inner_rows:,} — rejected as too expensive)",
        ]

    elif node_type == "Merge Join":
        explanation = f"PostgreSQL chose Merge Join ({join_type})"
        factors.append(DecisionFactor(
            factor="Both sides are pre-sorted (from index or Sort)",
            value=f"Outer: {outer_rows:,} rows, Inner: {inner_rows:,} rows",
            influence="Merge Join is O(N + M) with sorted input — no hash table memory needed",
            adjustable=False,
        ))
        alternatives = ["Hash Join (needs hash table in work_mem)", "Nested Loop (O(N*M))"]

    elif node_type == "Nested Loop":
        explanation = f"PostgreSQL chose Nested Loop ({join_type})"

        actual_loops = inner.get("Actual Loops", 1)
        inner_type = inner.get("Node Type", "")

        if outer_rows < 100:
            factors.append(DecisionFactor(
                factor="Small outer side makes Nested Loop efficient",
                value=f"Outer: {outer_rows:,} rows → {actual_loops} inner executions",
                influence=(
                    "With few outer rows, Nested Loop has low startup cost and can "
                    "use index lookups on the inner side for O(N * log M) total"
                ),
                adjustable=False,
            ))
        else:
            factors.append(DecisionFactor(
                factor="Large outer side makes Nested Loop expensive",
                value=f"Outer: {outer_rows:,} rows → {actual_loops} inner executions",
                influence=(
                    f"Nested Loop executes inner side {actual_loops} times. "
                    f"This is O(N*M) unless inner side has index. "
                    f"Hash Join would be O(N+M) — may be faster."
                ),
                adjustable=True,
                fix_hint="SET enable_nestloop = off;  -- force Hash/Merge Join",
            ))

        if "Index" in inner_type:
            factors.append(DecisionFactor(
                factor="Inner side uses index lookup",
                value=f"Inner: {inner_type}",
                influence="Each outer row triggers an O(log N) index lookup — efficient for small outer sets",
                adjustable=False,
            ))

        alternatives = [
            f"Hash Join — O({outer_rows} + {inner_rows})",
            f"Merge Join — O({outer_rows} + {inner_rows}) with sorted input",
        ]

    textbook_ref = "Dombrovskaya Ch. 6: Long Queries; Peng & Peng Ch. 6: Query Execution"

    return PlannerInsight(
        node_id=path,
        node_type=node_type,
        relation=f"{join_type} Join",
        explanation=explanation,
        decision_factors=factors,
        alternative_paths=alternatives,
        planner_rule=f"{node_type} selected based on estimated costs of all join strategies",
        textbook_ref=textbook_ref,
    )


def _explain_sort_choice(
    node: dict, config: dict, path: str, parent: dict | None,
) -> PlannerInsight:
    """Explain why the planner chose this sort method."""
    sort_key = node.get("Sort Key", [])
    sort_method = node.get("Sort Method", "")
    sort_space = node.get("Sort Space Used", 0)
    sort_type = node.get("Sort Space Type", "")
    rows = node.get("Plan Rows", 0)

    factors: list[DecisionFactor] = []

    explanation = f"PostgreSQL needs to sort {rows:,} rows by {', '.join(sort_key) if sort_key else '?'}"

    if "quicksort" in sort_method.lower():
        factors.append(DecisionFactor(
            factor="In-memory quicksort (fits in work_mem)",
            value=f"Method: {sort_method}, Space: {sort_space}kB ({sort_type})",
            influence="Data fits in work_mem — fastest sort method",
            adjustable=False,
        ))
    elif "external" in sort_method.lower() or sort_type == "Disk":
        factors.append(DecisionFactor(
            factor="External sort — spilling to disk",
            value=f"Method: {sort_method}, Space: {sort_space}kB on disk",
            influence=(
                f"Data exceeds work_mem — PostgreSQL uses external merge sort with disk I/O. "
                f"This is 10-100x slower than in-memory sort."
            ),
            adjustable=True,
            fix_hint=f"SET work_mem = '{max(64, sort_space * 2 // 1024)}MB';",
        ))
    elif "top-N" in sort_method.lower():
        factors.append(DecisionFactor(
            factor="Top-N heapsort (only keeping N smallest/largest)",
            value=f"Method: {sort_method}",
            influence="Only tracking top N rows — much less memory than full sort",
            adjustable=False,
        ))

    # Why not avoid the sort entirely?
    factors.append(DecisionFactor(
        factor="No index provides pre-sorted data",
        value=f"Sort Key: {', '.join(sort_key) if sort_key else 'unknown'}",
        influence="An index on the sort key columns would eliminate this Sort node entirely",
        adjustable=True,
        fix_hint=f"CREATE INDEX ON table ({', '.join(sort_key) if sort_key else '...'});",
    ))

    return PlannerInsight(
        node_id=path,
        node_type=node.get("Node Type", "Sort"),
        relation="",
        explanation=explanation,
        decision_factors=factors,
        alternative_paths=["Index providing pre-sorted output (eliminates Sort node)"],
        planner_rule="Sort is added when no index provides the required ordering",
        textbook_ref="Dombrovskaya Ch. 5: Indexes eliminate sorts",
    )


def _explain_aggregate_choice(
    node: dict, config: dict, path: str,
) -> PlannerInsight:
    """Explain the aggregation strategy choice."""
    node_type = node.get("Node Type", "")
    rows = node.get("Plan Rows", 0)
    group_key = node.get("Group Key", [])

    factors: list[DecisionFactor] = []

    if node_type == "HashAggregate":
        explanation = "PostgreSQL chose Hash Aggregate for grouping"
        factors.append(DecisionFactor(
            factor="Hash-based grouping (builds hash table of groups)",
            value=f"~{rows:,} groups by {', '.join(group_key) if group_key else '?'}",
            influence=(
                "Hash Aggregate is O(N) — one hash lookup per input row. "
                "Chosen when groups fit in work_mem and input is unsorted."
            ),
            adjustable=False,
        ))
    elif node_type == "GroupAggregate":
        explanation = "PostgreSQL chose Group Aggregate (sorted input)"
        factors.append(DecisionFactor(
            factor="Stream-based grouping (input already sorted)",
            value=f"~{rows:,} groups by {', '.join(group_key) if group_key else '?'}",
            influence="Group Aggregate scans sorted input once — no hash table needed",
            adjustable=False,
        ))
    else:
        explanation = f"Aggregation: {node_type}"

    return PlannerInsight(
        node_id=path,
        node_type=node_type,
        relation="",
        explanation=explanation,
        decision_factors=factors,
        alternative_paths=["HashAggregate (hash-based)", "GroupAggregate (sort-based)"],
        planner_rule="Hash vs Sort aggregate depends on work_mem, group count, and input order",
        textbook_ref="Peng & Peng Ch. 6; Dombrovskaya Ch. 6",
    )


def _explain_parallel_choice(
    node: dict, config: dict, path: str,
) -> PlannerInsight:
    """Explain parallel query decision."""
    workers_planned = node.get("Workers Planned", 0)
    workers_launched = node.get("Workers Launched")

    factors: list[DecisionFactor] = []
    explanation = f"PostgreSQL parallelized this query with {workers_planned} workers"

    factors.append(DecisionFactor(
        factor="Query cost exceeded parallel_tuple_cost threshold",
        value=f"{workers_planned} workers planned",
        influence=(
            "Parallel query splits scan work across multiple processes. "
            f"Each worker handles ~1/{workers_planned + 1} of the data."
        ),
        adjustable=True,
        fix_hint="SET max_parallel_workers_per_gather = N;  -- adjust worker count",
    ))

    if workers_launched is not None and workers_launched < workers_planned:
        factors.append(DecisionFactor(
            factor="Not all planned workers were launched",
            value=f"{workers_launched} of {workers_planned} launched",
            influence="Other queries may be consuming the worker pool. Check max_parallel_workers.",
            adjustable=True,
            fix_hint="ALTER SYSTEM SET max_parallel_workers = N;  -- increase pool",
        ))

    return PlannerInsight(
        node_id=path,
        node_type=node.get("Node Type", "Gather"),
        relation="",
        explanation=explanation,
        decision_factors=factors,
        alternative_paths=["Non-parallel plan (if cost below threshold)"],
        planner_rule="Parallel query used when estimated cost exceeds threshold and workers available",
        textbook_ref="PostgreSQL Query Optimization (Dombrovskaya 2024)",
    )


def _explain_materialize_choice(
    node: dict, config: dict, path: str,
) -> PlannerInsight:
    """Explain Materialize node."""
    rows = node.get("Plan Rows", 0)

    return PlannerInsight(
        node_id=path,
        node_type="Materialize",
        relation="",
        explanation=f"PostgreSQL materializes {rows:,} rows to avoid re-computing them",
        decision_factors=[DecisionFactor(
            factor="Inner side of join needs multiple scans",
            value=f"{rows:,} rows cached in memory/disk",
            influence=(
                "Materialize caches results of a subplan so it can be re-scanned "
                "without re-executing. Used inside Nested Loops when inner side "
                "is a non-seekable scan."
            ),
            adjustable=False,
        )],
        alternative_paths=["Hash Join (avoids re-scanning entirely)"],
        planner_rule="Materialize added when subplan must be re-scanned multiple times",
        textbook_ref="Peng & Peng Ch. 6: Query Execution",
    )
