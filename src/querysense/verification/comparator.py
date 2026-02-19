"""
IR-level plan comparison for before/after verification.

Compares two IR plans and produces a structured diff showing:
- Which operators changed
- Cost/cardinality deltas per node
- Scan method upgrades/downgrades
- Overall improvement assessment
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from querysense.ir.operators import IROperator, is_scan, scan_danger_rank
from querysense.ir.plan import IRNode, IRPlan


@dataclass(frozen=True)
class IRNodeDiff:
    """
    Diff between two corresponding IR nodes.

    Attributes:
        node_id: Node ID in the "before" plan.
        before_op: Operator in the before plan.
        after_op: Operator in the after plan (or None if removed).
        operator_changed: Whether the operator type changed.
        cost_delta: Change in total cost.
        cost_improvement_pct: Percentage improvement (positive = better).
        row_delta: Change in estimated rows.
        scan_upgrade: True if scan method improved (e.g. seq -> index).
        scan_downgrade: True if scan method worsened.
        relation: Table name (if applicable).
        details: Additional diff details.
    """

    node_id: str
    before_op: IROperator
    after_op: IROperator | None = None
    operator_changed: bool = False
    cost_delta: float = 0.0
    cost_improvement_pct: float = 0.0
    row_delta: float = 0.0
    scan_upgrade: bool = False
    scan_downgrade: bool = False
    relation: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class IRPlanComparison:
    """
    Complete comparison between two IR plans.

    Attributes:
        before_hash: Structure hash of the before plan.
        after_hash: Structure hash of the after plan.
        structure_changed: Whether the plan structure differs.
        node_diffs: Per-node diffs.
        total_cost_before: Total cost of the before plan.
        total_cost_after: Total cost of the after plan.
        cost_delta: Change in total cost.
        cost_improvement_pct: Percentage improvement (positive = better).
        new_nodes: Nodes present only in the after plan.
        removed_nodes: Nodes present only in the before plan.
    """

    before_hash: str = ""
    after_hash: str = ""
    structure_changed: bool = False
    node_diffs: list[IRNodeDiff] = field(default_factory=list)
    total_cost_before: float = 0.0
    total_cost_after: float = 0.0
    cost_delta: float = 0.0
    cost_improvement_pct: float = 0.0
    new_nodes: list[str] = field(default_factory=list)
    removed_nodes: list[str] = field(default_factory=list)

    @property
    def changed_count(self) -> int:
        return sum(1 for d in self.node_diffs if d.operator_changed)

    @property
    def new_count(self) -> int:
        return len(self.new_nodes)

    @property
    def removed_count(self) -> int:
        return len(self.removed_nodes)

    @property
    def scan_improvements(self) -> int:
        return sum(1 for d in self.node_diffs if d.scan_upgrade)

    @property
    def scan_regressions(self) -> int:
        return sum(1 for d in self.node_diffs if d.scan_downgrade)

    @property
    def has_improvements(self) -> bool:
        return self.cost_delta < 0 or self.scan_improvements > 0

    @property
    def has_regressions(self) -> bool:
        return self.cost_delta > 0 or self.scan_regressions > 0


def compare_ir_plans(before: IRPlan, after: IRPlan) -> IRPlanComparison:
    """
    Compare two IR plans and produce a structured diff.

    Matching is done by position in depth-first traversal order.
    For more precise matching, use the structure hash to detect
    identical subtrees.
    """
    before_hash = before.structure_hash()
    after_hash = after.structure_hash()

    before_nodes = list(before.all_nodes())
    after_nodes = list(after.all_nodes())

    before_cost = before.root.properties.cost.total_cost or 0.0
    after_cost = after.root.properties.cost.total_cost or 0.0
    cost_delta = after_cost - before_cost
    cost_pct = (cost_delta / before_cost * 100) if before_cost > 0 else 0

    # Match nodes by position
    node_diffs: list[IRNodeDiff] = []
    matched = min(len(before_nodes), len(after_nodes))

    for i in range(matched):
        b = before_nodes[i]
        a = after_nodes[i]

        b_cost = b.properties.cost.total_cost or 0.0
        a_cost = a.properties.cost.total_cost or 0.0
        nd_cost_delta = a_cost - b_cost
        nd_cost_pct = (nd_cost_delta / b_cost * 100) if b_cost > 0 else 0

        b_rows = b.properties.cardinality.estimated_rows or 0
        a_rows = a.properties.cardinality.estimated_rows or 0

        op_changed = b.operator != a.operator

        # Detect scan upgrades/downgrades
        scan_up = False
        scan_down = False
        if op_changed and is_scan(b.operator) and is_scan(a.operator):
            b_rank = scan_danger_rank(b.operator)
            a_rank = scan_danger_rank(a.operator)
            if a_rank < b_rank:
                scan_up = True  # Better scan method
            elif a_rank > b_rank:
                scan_down = True  # Worse scan method

        node_diffs.append(IRNodeDiff(
            node_id=b.id,
            before_op=b.operator,
            after_op=a.operator,
            operator_changed=op_changed,
            cost_delta=nd_cost_delta,
            cost_improvement_pct=-nd_cost_pct,
            row_delta=a_rows - b_rows,
            scan_upgrade=scan_up,
            scan_downgrade=scan_down,
            relation=b.properties.relation_name or a.properties.relation_name,
        ))

    # Nodes only in before (removed)
    removed = [n.id for n in before_nodes[matched:]]

    # Nodes only in after (new)
    new = [n.id for n in after_nodes[matched:]]

    return IRPlanComparison(
        before_hash=before_hash,
        after_hash=after_hash,
        structure_changed=before_hash != after_hash,
        node_diffs=node_diffs,
        total_cost_before=before_cost,
        total_cost_after=after_cost,
        cost_delta=cost_delta,
        cost_improvement_pct=-cost_pct,
        new_nodes=new,
        removed_nodes=removed,
    )
