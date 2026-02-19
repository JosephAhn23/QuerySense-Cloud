"""
Holistic Tuner -- solve the coordination problem.

Inspired by CMU research on joint optimization: tuning indexes in isolation,
then queries in isolation, often misses global optima. This module reasons
across ALL dimensions simultaneously:

1. System knobs (work_mem, shared_buffers, effective_cache_size, etc.)
2. Physical design (indexes, partitioning, clustering)
3. Query hints (join order, scan methods, parallelism)

The key insight: a suboptimal intermediate step (e.g., a "worse" index) can
enable a much better query plan when combined with the right knob setting.

Usage:
    from querysense.holistic_tuner import HolisticTuner

    tuner = HolisticTuner()
    result = tuner.tune(plans, sqls)
    print(result.format_text())
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TuningDimension(str, Enum):
    KNOB = "knob"
    INDEX = "index"
    QUERY_HINT = "query_hint"
    PARTITIONING = "partitioning"
    CLUSTERING = "clustering"


@dataclass
class TuningAction:
    """A single action in the tuning plan."""
    dimension: TuningDimension
    name: str
    sql: str
    predicted_improvement_pct: float = 0.0
    confidence: float = 0.5
    interactions: list[str] = field(default_factory=list)  # Other actions it synergizes with
    conflicts: list[str] = field(default_factory=list)     # Other actions it conflicts with
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension.value,
            "name": self.name,
            "sql": self.sql,
            "predicted_improvement_pct": round(self.predicted_improvement_pct, 2),
            "confidence": round(self.confidence, 2),
            "interactions": self.interactions,
            "conflicts": self.conflicts,
            "reasoning": self.reasoning,
        }


@dataclass
class InteractionEffect:
    """Synergy or conflict between two tuning actions."""
    action_a: str
    action_b: str
    combined_improvement_pct: float  # Together
    individual_sum_pct: float        # A alone + B alone
    synergy: float = 0.0            # positive = synergy, negative = conflict

    @property
    def is_synergy(self) -> bool:
        return self.synergy > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_a": self.action_a,
            "action_b": self.action_b,
            "combined_pct": round(self.combined_improvement_pct, 2),
            "individual_sum_pct": round(self.individual_sum_pct, 2),
            "synergy": round(self.synergy, 2),
            "type": "synergy" if self.is_synergy else "conflict",
        }


@dataclass
class HolisticTuningResult:
    """Result of holistic tuning analysis."""
    actions: list[TuningAction] = field(default_factory=list)
    interactions: list[InteractionEffect] = field(default_factory=list)
    execution_order: list[str] = field(default_factory=list)
    total_predicted_improvement_pct: float = 0.0
    sequential_improvement_pct: float = 0.0  # If done in isolation
    holistic_bonus_pct: float = 0.0          # Extra from coordination

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_predicted_improvement_pct": round(self.total_predicted_improvement_pct, 2),
            "sequential_improvement_pct": round(self.sequential_improvement_pct, 2),
            "holistic_bonus_pct": round(self.holistic_bonus_pct, 2),
            "execution_order": self.execution_order,
            "action_count": len(self.actions),
            "synergies": sum(1 for i in self.interactions if i.is_synergy),
            "conflicts": sum(1 for i in self.interactions if not i.is_synergy),
            "actions": [a.to_dict() for a in self.actions],
            "interactions": [i.to_dict() for i in self.interactions],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  HOLISTIC TUNING PLAN")
        lines.append("  " + "=" * 60)
        lines.append(f"  Sequential tuning: {self.sequential_improvement_pct:.1f}% improvement")
        lines.append(f"  Holistic tuning:   {self.total_predicted_improvement_pct:.1f}% improvement")
        lines.append(f"  Coordination bonus: +{self.holistic_bonus_pct:.1f}%")
        lines.append("")

        lines.append("  Execution Order:")
        for i, name in enumerate(self.execution_order, 1):
            action = next((a for a in self.actions if a.name == name), None)
            if action:
                lines.append(
                    f"    {i}. [{action.dimension.value:>10}] {action.name} "
                    f"(+{action.predicted_improvement_pct:.1f}%)"
                )
        lines.append("")

        synergies = [i for i in self.interactions if i.is_synergy]
        if synergies:
            lines.append("  Synergies Detected:")
            for s in synergies:
                lines.append(
                    f"    + {s.action_a} + {s.action_b} = "
                    f"+{s.synergy:.1f}% bonus"
                )
            lines.append("")

        conflicts = [i for i in self.interactions if not i.is_synergy]
        if conflicts:
            lines.append("  Conflicts Detected:")
            for c in conflicts:
                lines.append(
                    f"    - {c.action_a} vs {c.action_b}: "
                    f"{c.synergy:.1f}% interference"
                )
            lines.append("")

        for action in self.actions:
            lines.append(f"  {action.name}:")
            lines.append(f"    SQL: {action.sql[:120]}")
            if action.reasoning:
                lines.append(f"    Why: {action.reasoning[:120]}")
            lines.append("")

        return "\n".join(lines)


class HolisticTuner:
    """
    Coordinate optimization across indexes, knobs, and query hints.

    Unlike sequential tuning (index -> knob -> hint), this explores
    the joint space and detects synergies / conflicts between actions.
    """

    def tune(
        self,
        plans: list[dict[str, Any]],
        sqls: list[str] | None = None,
    ) -> HolisticTuningResult:
        """Run holistic tuning analysis."""
        # Generate candidates per dimension
        knob_actions = self._generate_knob_actions(plans)
        index_actions = self._generate_index_actions(plans)
        hint_actions = self._generate_hint_actions(plans)

        all_actions = knob_actions + index_actions + hint_actions

        # Detect interactions between all pairs
        interactions = self._detect_interactions(all_actions, plans)

        # Determine optimal execution order (topological sort by dependency)
        order = self._optimize_order(all_actions, interactions)

        # Calculate improvements
        sequential = sum(a.predicted_improvement_pct for a in all_actions)
        holistic = sequential
        for inter in interactions:
            holistic += inter.synergy

        return HolisticTuningResult(
            actions=all_actions,
            interactions=interactions,
            execution_order=order,
            total_predicted_improvement_pct=min(holistic, 95.0),
            sequential_improvement_pct=min(sequential, 80.0),
            holistic_bonus_pct=max(0, holistic - sequential),
        )

    def _generate_knob_actions(self, plans: list[dict[str, Any]]) -> list[TuningAction]:
        actions: list[TuningAction] = []

        has_spill = False
        has_low_cache = False
        has_bad_estimates = False
        total_cost = 0.0

        for plan_data in plans:
            plan = self._get_plan(plan_data)
            if not plan:
                continue
            total_cost += plan.get("Total Cost", 0)
            for node in self._walk(plan):
                if node.get("Sort Space Type") == "Disk" or (node.get("Hash Batches", 0) or 0) > 1:
                    has_spill = True
                est = node.get("Plan Rows", 0)
                act = node.get("Actual Rows") or 0
                if est > 0 and act > 0 and abs(act - est) / max(est, 1) > 10:
                    has_bad_estimates = True
                shared_read = node.get("Shared Read Blocks") or 0
                shared_hit = node.get("Shared Hit Blocks") or 0
                if shared_read > 0 and shared_hit > 0:
                    hit_ratio = shared_hit / (shared_hit + shared_read)
                    if hit_ratio < 0.95:
                        has_low_cache = True

        if has_spill:
            actions.append(TuningAction(
                dimension=TuningDimension.KNOB,
                name="increase_work_mem",
                sql="ALTER SYSTEM SET work_mem = '128MB';",
                predicted_improvement_pct=15.0,
                confidence=0.70,
                interactions=["create_covering_index"],
                reasoning="Disk spill detected -- in-memory sort/hash is 5-50x faster",
            ))

        if has_low_cache:
            actions.append(TuningAction(
                dimension=TuningDimension.KNOB,
                name="increase_shared_buffers",
                sql="ALTER SYSTEM SET shared_buffers = '2GB';",
                predicted_improvement_pct=10.0,
                confidence=0.60,
                reasoning="Cache hit ratio below 95% -- more buffer cache reduces disk I/O",
            ))

        if has_bad_estimates:
            actions.append(TuningAction(
                dimension=TuningDimension.KNOB,
                name="improve_statistics",
                sql="ALTER SYSTEM SET default_statistics_target = 500;\nANALYZE;",
                predicted_improvement_pct=20.0,
                confidence=0.75,
                interactions=["create_index"],
                reasoning="Row estimation errors >10x -- better stats enable better plan selection",
            ))

        return actions

    def _generate_index_actions(self, plans: list[dict[str, Any]]) -> list[TuningAction]:
        actions: list[TuningAction] = []
        seen_indexes: set[str] = set()

        for plan_data in plans:
            plan = self._get_plan(plan_data)
            if not plan:
                continue
            for node in self._walk(plan):
                if node.get("Node Type") == "Seq Scan":
                    table = node.get("Relation Name", "")
                    rows = node.get("Actual Rows") or node.get("Plan Rows", 0)
                    filt = node.get("Filter", "")

                    if table and rows > 10000 and filt:
                        key = f"{table}_{filt[:20]}"
                        if key in seen_indexes:
                            continue
                        seen_indexes.add(key)

                        # Extract likely column from filter
                        import re
                        col_match = re.search(r'(\w+)\s*(?:=|<|>)', filt)
                        col = col_match.group(1) if col_match else "column"

                        actions.append(TuningAction(
                            dimension=TuningDimension.INDEX,
                            name=f"create_index_{table}_{col}",
                            sql=f"CREATE INDEX CONCURRENTLY idx_{table}_{col} ON {table}({col});",
                            predicted_improvement_pct=min(40.0, math.log10(rows) * 8),
                            confidence=0.80,
                            interactions=["improve_statistics"],
                            reasoning=f"Seq scan on {table} ({rows:,} rows) with filter on {col}",
                        ))

        return actions

    def _generate_hint_actions(self, plans: list[dict[str, Any]]) -> list[TuningAction]:
        actions: list[TuningAction] = []

        join_count = 0
        has_nested_loop_large = False

        for plan_data in plans:
            plan = self._get_plan(plan_data)
            if not plan:
                continue
            for node in self._walk(plan):
                nt = node.get("Node Type", "")
                if "Join" in nt or "Nested Loop" in nt:
                    join_count += 1
                if nt == "Nested Loop":
                    rows = node.get("Actual Rows") or node.get("Plan Rows", 0)
                    if rows > 50000:
                        has_nested_loop_large = True

        if join_count > 8:
            actions.append(TuningAction(
                dimension=TuningDimension.QUERY_HINT,
                name="tune_join_collapse_limit",
                sql=f"SET join_collapse_limit = {max(8, join_count + 2)};",
                predicted_improvement_pct=10.0,
                confidence=0.55,
                reasoning=f"Query has {join_count} joins -- increasing join_collapse_limit may find better join order",
                conflicts=["enable_geqo"],
            ))

        if has_nested_loop_large:
            actions.append(TuningAction(
                dimension=TuningDimension.QUERY_HINT,
                name="prefer_hash_join",
                sql="SET LOCAL enable_nestloop = off;",
                predicted_improvement_pct=25.0,
                confidence=0.60,
                interactions=["increase_work_mem"],
                reasoning="Nested loop on large dataset -- hash join with enough work_mem is typically faster",
            ))

        return actions

    def _detect_interactions(
        self, actions: list[TuningAction], plans: list[dict[str, Any]],
    ) -> list[InteractionEffect]:
        """Detect synergies and conflicts between actions."""
        interactions: list[InteractionEffect] = []

        for i, a in enumerate(actions):
            for j, b in enumerate(actions):
                if j <= i:
                    continue

                # Check declared interactions
                if b.name in a.interactions or a.name in b.interactions:
                    bonus = (a.predicted_improvement_pct + b.predicted_improvement_pct) * 0.15
                    interactions.append(InteractionEffect(
                        action_a=a.name,
                        action_b=b.name,
                        combined_improvement_pct=a.predicted_improvement_pct + b.predicted_improvement_pct + bonus,
                        individual_sum_pct=a.predicted_improvement_pct + b.predicted_improvement_pct,
                        synergy=bonus,
                    ))

                # Check declared conflicts
                if b.name in a.conflicts or a.name in b.conflicts:
                    penalty = min(a.predicted_improvement_pct, b.predicted_improvement_pct) * 0.5
                    interactions.append(InteractionEffect(
                        action_a=a.name,
                        action_b=b.name,
                        combined_improvement_pct=a.predicted_improvement_pct + b.predicted_improvement_pct - penalty,
                        individual_sum_pct=a.predicted_improvement_pct + b.predicted_improvement_pct,
                        synergy=-penalty,
                    ))

                # Cross-dimension synergies
                if a.dimension == TuningDimension.INDEX and b.dimension == TuningDimension.KNOB:
                    if "work_mem" in b.sql and "covering" in a.name:
                        bonus = 8.0
                        interactions.append(InteractionEffect(
                            action_a=a.name,
                            action_b=b.name,
                            combined_improvement_pct=a.predicted_improvement_pct + b.predicted_improvement_pct + bonus,
                            individual_sum_pct=a.predicted_improvement_pct + b.predicted_improvement_pct,
                            synergy=bonus,
                        ))

        return interactions

    def _optimize_order(
        self, actions: list[TuningAction], interactions: list[InteractionEffect],
    ) -> list[str]:
        """Determine optimal execution order."""
        # Priority: knobs first (low risk, enable other optimizations),
        # then indexes, then query hints
        priority = {
            TuningDimension.KNOB: 0,
            TuningDimension.INDEX: 1,
            TuningDimension.CLUSTERING: 2,
            TuningDimension.PARTITIONING: 3,
            TuningDimension.QUERY_HINT: 4,
        }
        sorted_actions = sorted(actions, key=lambda a: (priority.get(a.dimension, 5), -a.predicted_improvement_pct))
        return [a.name for a in sorted_actions]

    def _get_plan(self, data: dict[str, Any]) -> dict[str, Any] | None:
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            return data.get("Plan", data if "Node Type" in data else None)
        return None

    def _walk(self, node: dict[str, Any]):
        yield node
        for child in node.get("Plans", []):
            yield from self._walk(child)
