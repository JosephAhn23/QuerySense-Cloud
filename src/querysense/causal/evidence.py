"""
Evidence evaluation functions for causal hypotheses.

Each hypothesis has a set of evidence predicates.  Each predicate emits
``(weight, explanation, provenance)`` when its conditions are met.

Evidence functions consume IR nodes/properties and optional DB probe data.
They are designed to be engine-portable where possible, with engine-specific
variants for deeper analysis.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from querysense.ir.annotations import IRCapability
from querysense.ir.operators import IROperator, is_join, is_scan
from querysense.ir.plan import IRNode, IRPlan


class EvidenceStrength(str, Enum):
    """How strongly a piece of evidence supports a hypothesis."""
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    COUNTER = "counter"  # Evidence against the hypothesis


@dataclass(frozen=True)
class Evidence:
    """A single piece of evidence for/against a hypothesis."""
    weight: float  # positive = supporting, negative = counter-evidence
    strength: EvidenceStrength
    explanation: str
    provenance: str  # where this evidence came from (node id, metric, etc.)
    node_id: str | None = None  # IR node this evidence applies to


@dataclass
class EvidenceResult:
    """Aggregated evidence for one hypothesis."""
    hypothesis_id: str
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    raw_score: float = 0.0
    affected_nodes: list[str] = field(default_factory=list)
    remediation: str = ""

    @property
    def top_explanation(self) -> str:
        if not self.evidence:
            return ""
        strongest = max(self.evidence, key=lambda e: abs(e.weight))
        return strongest.explanation


# ── Evidence functions (portable) ─────────────────────────────────────

def evaluate_missing_access_path(plan: IRPlan, db_facts: dict[str, Any] | None = None) -> EvidenceResult:
    """
    H1: Missing access path.

    Look for sequential scans on tables that could benefit from an index.
    """
    result = EvidenceResult(hypothesis_id="H1_missing_access_path")

    for node in plan.all_nodes():
        if node.operator not in (IROperator.SCAN_SEQ,):
            continue

        table = node.properties.relation_name
        filter_cond = node.properties.predicates.filter_condition
        est_rows = node.properties.cardinality.estimated_rows

        if not filter_cond:
            continue  # No filter -> seq scan may be optimal

        weight = 0.5
        strength = EvidenceStrength.MODERATE

        # Higher confidence if table has many estimated rows
        if est_rows and est_rows > 10000:
            weight = 0.8
            strength = EvidenceStrength.STRONG

        # Check if DB facts show existing indexes on this table
        if db_facts and table:
            indexes = db_facts.get(f"indexes_{table}", [])
            if indexes:
                # Has indexes but still seq scanning -> weaker evidence
                weight *= 0.7

        result.evidence.append(Evidence(
            weight=weight,
            strength=strength,
            explanation=(
                f"Sequential scan on '{table}' with filter '{filter_cond}' "
                f"(~{est_rows} rows estimated). An index may eliminate this scan."
            ),
            provenance=f"node={node.id}, op=SCAN_SEQ, filter present",
            node_id=node.id,
        ))
        result.affected_nodes.append(node.id)

    _compute_confidence(result)
    return result


def evaluate_bad_cardinality(plan: IRPlan, **_: Any) -> EvidenceResult:
    """
    H2: Bad cardinality estimate.

    Check for nodes where actual rows diverge strongly from estimated rows.
    Uses log-ratio: |log(actual/estimated)| > threshold.
    """
    result = EvidenceResult(hypothesis_id="H2_bad_cardinality_estimate")

    THRESHOLD_MODERATE = 1.5  # ~4.5x off
    THRESHOLD_STRONG = 3.0   # ~20x off

    for node in plan.all_nodes():
        c = node.properties.cardinality
        if not c.has_actuals or c.estimated_rows is None:
            continue
        if c.estimated_rows <= 0 or c.actual_rows is None:
            continue

        actual = max(c.actual_rows, 1)
        estimated = max(c.estimated_rows, 1)
        log_ratio = abs(math.log(actual / estimated))

        if log_ratio < THRESHOLD_MODERATE:
            continue

        if log_ratio >= THRESHOLD_STRONG:
            weight = 0.95
            strength = EvidenceStrength.STRONG
        else:
            weight = 0.6
            strength = EvidenceStrength.MODERATE

        error_factor = c.estimate_error_factor
        direction = "under" if actual > estimated else "over"

        result.evidence.append(Evidence(
            weight=weight,
            strength=strength,
            explanation=(
                f"Cardinality {direction}-estimate at node '{node.id}' "
                f"({node.algorithm}): estimated {estimated:.0f} rows, "
                f"actual {actual:.0f} rows "
                f"(error factor {error_factor:.1f}x)."
            ),
            provenance=(
                f"node={node.id}, est={estimated}, act={actual}, "
                f"log_ratio={log_ratio:.2f}"
            ),
            node_id=node.id,
        ))
        result.affected_nodes.append(node.id)

    _compute_confidence(result)
    return result


def evaluate_stale_statistics(
    plan: IRPlan, db_facts: dict[str, Any] | None = None, **_: Any,
) -> EvidenceResult:
    """
    H3: Stale statistics.

    Check if last_analyze / last_autoanalyze is far in the past for
    tables involved in the plan.
    """
    result = EvidenceResult(hypothesis_id="H3_stale_statistics")

    if not db_facts:
        return result

    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)

    for node in plan.all_nodes():
        table = node.properties.relation_name
        if not table:
            continue

        stats = db_facts.get(f"table_stats_{table}")
        if not stats:
            continue

        last_analyze = stats.get("last_analyze") or stats.get("last_autoanalyze")
        if not last_analyze:
            result.evidence.append(Evidence(
                weight=0.7,
                strength=EvidenceStrength.MODERATE,
                explanation=(
                    f"Table '{table}' has never been analyzed. "
                    f"Statistics may be absent or based on defaults."
                ),
                provenance=f"table={table}, last_analyze=never",
                node_id=node.id,
            ))
            result.affected_nodes.append(node.id)
            continue

        if isinstance(last_analyze, str):
            try:
                last_analyze = datetime.datetime.fromisoformat(last_analyze)
            except ValueError:
                continue

        age = now - last_analyze
        if age.days > 7:
            weight = min(0.9, 0.3 + age.days * 0.02)
            result.evidence.append(Evidence(
                weight=weight,
                strength=(
                    EvidenceStrength.STRONG if age.days > 30
                    else EvidenceStrength.MODERATE
                ),
                explanation=(
                    f"Table '{table}' was last analyzed {age.days} days ago. "
                    f"Statistics may not reflect current data distribution."
                ),
                provenance=f"table={table}, last_analyze={last_analyze.isoformat()}",
                node_id=node.id,
            ))
            result.affected_nodes.append(node.id)

    _compute_confidence(result)
    return result


def evaluate_insufficient_stats(plan: IRPlan, **_: Any) -> EvidenceResult:
    """
    H4: Insufficient statistics for skew/correlation.

    Detect symptoms suggesting the default statistics target is too low:
    - Large cardinality errors on filtered scans
    - Errors that persist even after ANALYZE
    """
    result = EvidenceResult(hypothesis_id="H4_insufficient_stats_skew")

    for node in plan.all_nodes():
        c = node.properties.cardinality
        if not c.has_actuals or c.estimated_rows is None:
            continue
        if c.estimated_rows <= 0 or c.actual_rows is None:
            continue

        actual = max(c.actual_rows, 1)
        estimated = max(c.estimated_rows, 1)
        error_factor = max(actual / estimated, estimated / actual)

        # Only flag if moderate error AND the node has a filter (suggesting
        # selectivity estimation is the issue, not join ordering)
        has_filter = bool(node.properties.predicates.filter_condition)
        has_index_cond = bool(node.properties.predicates.index_condition)

        if error_factor < 5 or not (has_filter or has_index_cond):
            continue

        # Check for join nodes where error propagates
        if is_join(node.operator) and error_factor > 10:
            weight = 0.7
            strength = EvidenceStrength.MODERATE
        elif is_scan(node.operator) and has_filter:
            weight = 0.6
            strength = EvidenceStrength.MODERATE
        else:
            continue

        result.evidence.append(Evidence(
            weight=weight,
            strength=strength,
            explanation=(
                f"Cardinality error of {error_factor:.0f}x at '{node.id}' "
                f"({node.algorithm}) with filter predicate, suggesting "
                f"insufficient histogram resolution or correlated columns."
            ),
            provenance=f"node={node.id}, error_factor={error_factor:.1f}",
            node_id=node.id,
        ))
        result.affected_nodes.append(node.id)

    _compute_confidence(result)
    return result


def evaluate_cost_misconfiguration(
    plan: IRPlan, db_facts: dict[str, Any] | None = None, **_: Any,
) -> EvidenceResult:
    """
    H5: Misconfigured planner cost constants.

    Check if storage is SSD/managed but random_page_cost is high.
    """
    result = EvidenceResult(hypothesis_id="H5_cost_misconfiguration")

    if not db_facts:
        return result

    settings = db_facts.get("db_settings", {})
    random_page_cost = settings.get("random_page_cost")
    seq_page_cost = settings.get("seq_page_cost")
    effective_cache_size = settings.get("effective_cache_size")

    if random_page_cost is not None:
        rpc = float(random_page_cost)
        if rpc >= 3.0:
            # High random_page_cost suggests HDD assumptions
            weight = 0.4  # low-to-medium confidence without knowing storage
            result.evidence.append(Evidence(
                weight=weight,
                strength=EvidenceStrength.WEAK,
                explanation=(
                    f"random_page_cost={rpc} (default 4.0). If storage is "
                    f"SSD or managed (cloud), this is likely too high and "
                    f"discourages index usage. Recommended: 1.1 for SSD."
                ),
                provenance=f"db_setting=random_page_cost, value={rpc}",
            ))

            # Stronger if we see seq scans on indexed tables
            for node in plan.all_nodes():
                if (
                    node.operator == IROperator.SCAN_SEQ
                    and node.properties.predicates.filter_condition
                    and node.properties.cardinality.estimated_rows
                    and node.properties.cardinality.estimated_rows > 1000
                ):
                    result.evidence.append(Evidence(
                        weight=0.6,
                        strength=EvidenceStrength.MODERATE,
                        explanation=(
                            f"Seq scan on '{node.properties.relation_name}' "
                            f"with filter while random_page_cost={rpc}. "
                            f"The high cost constant may be discouraging "
                            f"index usage."
                        ),
                        provenance=(
                            f"node={node.id}, random_page_cost={rpc}, "
                            f"seq_scan+filter"
                        ),
                        node_id=node.id,
                    ))
                    result.affected_nodes.append(node.id)

    _compute_confidence(result)
    return result


def evaluate_memory_pressure(plan: IRPlan, **_: Any) -> EvidenceResult:
    """
    H6: Memory pressure / spill to disk.

    Look for sort/hash nodes that are spilling to disk.
    """
    result = EvidenceResult(hypothesis_id="H6_memory_pressure_spill")

    for node in plan.all_nodes():
        mem = node.properties.memory
        if not mem.is_spilling:
            continue

        weight = 0.85
        strength = EvidenceStrength.STRONG

        detail_parts = []
        if mem.sort_space_used_kb:
            detail_parts.append(f"sort_space={mem.sort_space_used_kb}KB")
        if mem.sort_space_type:
            detail_parts.append(f"type={mem.sort_space_type}")
        if mem.hash_batches:
            detail_parts.append(f"hash_batches={mem.hash_batches}")
        if mem.temp_written_blocks:
            detail_parts.append(f"temp_blocks_written={mem.temp_written_blocks}")

        detail = ", ".join(detail_parts) or "spill detected"

        result.evidence.append(Evidence(
            weight=weight,
            strength=strength,
            explanation=(
                f"Node '{node.id}' ({node.algorithm}) is spilling to disk: "
                f"{detail}. Consider increasing work_mem."
            ),
            provenance=f"node={node.id}, {detail}",
            node_id=node.id,
        ))
        result.affected_nodes.append(node.id)

    _compute_confidence(result)
    return result


def evaluate_join_mismatch(plan: IRPlan, **_: Any) -> EvidenceResult:
    """
    H7: Join strategy mismatch.

    Detect nested loop joins on large row sets where hash/merge
    would likely be better.
    """
    result = EvidenceResult(hypothesis_id="H7_join_strategy_mismatch")

    for node in plan.all_nodes():
        if node.operator != IROperator.JOIN_NESTED_LOOP:
            continue

        # Check inner side cardinality
        if len(node.children) < 2:
            continue

        inner = node.children[1]
        inner_rows = (
            inner.properties.cardinality.actual_rows
            or inner.properties.cardinality.estimated_rows
        )
        outer = node.children[0]
        outer_rows = (
            outer.properties.cardinality.actual_rows
            or outer.properties.cardinality.estimated_rows
        )

        loops = node.properties.cardinality.actual_loops or 1

        if inner_rows is None or outer_rows is None:
            continue

        # Flag if both sides have many rows and NL is used
        total_inner_rows = inner_rows * (outer_rows if loops == 1 else loops)
        if total_inner_rows > 50000 and outer_rows > 100:
            weight = 0.65
            strength = EvidenceStrength.MODERATE

            # Check if inner side is a seq scan (worse)
            if inner.operator == IROperator.SCAN_SEQ:
                weight = 0.85
                strength = EvidenceStrength.STRONG

            result.evidence.append(Evidence(
                weight=weight,
                strength=strength,
                explanation=(
                    f"Nested loop join at '{node.id}' with outer={outer_rows:.0f} "
                    f"rows, inner={inner_rows:.0f} rows (total inner visits: "
                    f"~{total_inner_rows:.0f}). Hash or merge join may be "
                    f"more efficient."
                ),
                provenance=(
                    f"node={node.id}, outer_rows={outer_rows}, "
                    f"inner_rows={inner_rows}, inner_op={inner.operator.value}"
                ),
                node_id=node.id,
            ))
            result.affected_nodes.append(node.id)

    _compute_confidence(result)
    return result


def evaluate_suboptimal_parallelism(plan: IRPlan, **_: Any) -> EvidenceResult:
    """
    H10: Suboptimal parallelism.

    Check if planned workers > launched workers.
    """
    result = EvidenceResult(hypothesis_id="H10_suboptimal_parallelism")

    for node in plan.all_nodes():
        p = node.properties.parallelism
        if not p.is_parallel:
            continue

        if (
            p.planned_workers
            and p.launched_workers is not None
            and p.launched_workers < p.planned_workers
        ):
            ratio = p.launched_workers / p.planned_workers
            weight = 0.5 + (1 - ratio) * 0.4
            result.evidence.append(Evidence(
                weight=weight,
                strength=(
                    EvidenceStrength.STRONG if ratio < 0.5
                    else EvidenceStrength.MODERATE
                ),
                explanation=(
                    f"Node '{node.id}' planned {p.planned_workers} parallel "
                    f"workers but only {p.launched_workers} were launched "
                    f"({ratio:.0%} utilization)."
                ),
                provenance=(
                    f"node={node.id}, planned={p.planned_workers}, "
                    f"launched={p.launched_workers}"
                ),
                node_id=node.id,
            ))
            result.affected_nodes.append(node.id)

    _compute_confidence(result)
    return result


# ── Confidence computation ────────────────────────────────────────────

def _compute_confidence(result: EvidenceResult) -> None:
    """
    Compute confidence from accumulated evidence.

    Uses a bounded function of total weight with penalties for counter-evidence.
    """
    if not result.evidence:
        result.confidence = 0.0
        result.raw_score = 0.0
        return

    positive = sum(e.weight for e in result.evidence if e.weight > 0)
    negative = sum(abs(e.weight) for e in result.evidence if e.weight < 0)

    # Diminishing returns: sigmoid-like scaling
    raw = positive - negative * 1.5  # counter-evidence penalized 1.5x
    result.raw_score = raw

    # Map to 0-1 using a bounded function
    # confidence = 1 - exp(-k * raw) for raw > 0
    if raw <= 0:
        result.confidence = 0.0
    else:
        result.confidence = min(0.99, 1.0 - math.exp(-0.8 * raw))


# ── Registry of evidence functions ────────────────────────────────────

EVIDENCE_FUNCTIONS: dict[str, Callable[..., EvidenceResult]] = {
    "H1_missing_access_path": evaluate_missing_access_path,
    "H2_bad_cardinality_estimate": evaluate_bad_cardinality,
    "H3_stale_statistics": evaluate_stale_statistics,
    "H4_insufficient_stats_skew": evaluate_insufficient_stats,
    "H5_cost_misconfiguration": evaluate_cost_misconfiguration,
    "H6_memory_pressure_spill": evaluate_memory_pressure,
    "H7_join_strategy_mismatch": evaluate_join_mismatch,
    "H10_suboptimal_parallelism": evaluate_suboptimal_parallelism,
}
