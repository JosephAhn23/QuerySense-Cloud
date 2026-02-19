"""
Causal Analysis Engine: orchestrates hypothesis evaluation and ranking.

The engine:
1. Filters hypotheses by available capabilities
2. Evaluates evidence functions against the IR plan
3. Ranks results by confidence
4. Produces a CausalReport with explanations and remediation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from querysense.causal.evidence import (
    EVIDENCE_FUNCTIONS,
    EvidenceResult,
)
from querysense.causal.hypotheses import (
    HYPOTHESIS_CATALOG,
    CausalHypothesis,
    HypothesisID,
)
from querysense.ir.annotations import IRCapability
from querysense.ir.plan import IRPlan


@dataclass(frozen=True)
class RankedHypothesis:
    """A hypothesis with its evaluated confidence and evidence."""

    hypothesis: CausalHypothesis
    result: EvidenceResult
    rank: int = 0

    @property
    def confidence(self) -> float:
        return self.result.confidence

    @property
    def explanation(self) -> str:
        return self.result.top_explanation

    @property
    def evidence_count(self) -> int:
        return len(self.result.evidence)


@dataclass
class CausalReport:
    """
    Complete causal analysis report.

    Contains ranked hypotheses, skipped hypotheses (unmet capabilities),
    and a summary.
    """

    ranked: list[RankedHypothesis] = field(default_factory=list)
    skipped: list[tuple[str, list[str]]] = field(default_factory=list)
    engine: str = ""
    node_count: int = 0
    capabilities_available: frozenset[IRCapability] = frozenset()

    @property
    def top_cause(self) -> RankedHypothesis | None:
        return self.ranked[0] if self.ranked else None

    @property
    def high_confidence(self) -> list[RankedHypothesis]:
        """Hypotheses with confidence >= 0.6."""
        return [h for h in self.ranked if h.confidence >= 0.6]

    @property
    def has_findings(self) -> bool:
        return bool(self.ranked)

    def summary(self) -> str:
        """Human-readable summary of causal analysis."""
        if not self.ranked:
            return "No root-cause hypotheses matched the available evidence."

        lines = [f"Causal Analysis ({self.engine}, {self.node_count} nodes):"]
        for rh in self.ranked[:5]:
            lines.append(
                f"  #{rh.rank} [{rh.confidence:.0%}] {rh.hypothesis.title}: "
                f"{rh.explanation}"
            )
        if self.skipped:
            lines.append(
                f"  ({len(self.skipped)} hypotheses skipped due to "
                f"insufficient evidence)"
            )
        return "\n".join(lines)


class CausalEngine:
    """
    Orchestrates causal analysis on an IR plan.

    Usage::

        engine = CausalEngine()
        report = engine.analyze(ir_plan, db_facts={"table_stats_orders": {...}})
        print(report.summary())
    """

    def __init__(
        self,
        hypotheses: dict[HypothesisID, CausalHypothesis] | None = None,
        min_confidence: float = 0.1,
    ):
        self.hypotheses = hypotheses or HYPOTHESIS_CATALOG
        self.min_confidence = min_confidence

    def analyze(
        self,
        plan: IRPlan,
        db_facts: dict[str, Any] | None = None,
    ) -> CausalReport:
        """
        Run causal analysis on an IR plan.

        Args:
            plan: The IR plan to analyze.
            db_facts: Optional database facts (table stats, settings, indexes).

        Returns:
            A CausalReport with ranked hypotheses.
        """
        capabilities = plan.capabilities
        cap_values = {c.value for c in capabilities}

        report = CausalReport(
            engine=plan.engine,
            node_count=plan.node_count,
            capabilities_available=capabilities,
        )

        results: list[tuple[CausalHypothesis, EvidenceResult]] = []

        for hyp_id, hypothesis in self.hypotheses.items():
            # Check required capabilities
            missing = [
                cap for cap in hypothesis.required_capabilities
                if cap not in cap_values
            ]
            if missing:
                report.skipped.append((hypothesis.title, missing))
                continue

            # Evaluate evidence
            eval_fn = EVIDENCE_FUNCTIONS.get(hyp_id.value)
            if eval_fn is None:
                continue

            try:
                result = eval_fn(plan, db_facts=db_facts)
            except Exception as exc:
                # Don't let one hypothesis crash the whole analysis
                result = EvidenceResult(hypothesis_id=hyp_id.value)

            if result.confidence >= self.min_confidence:
                # Generate remediation from template
                result.remediation = self._render_remediation(
                    hypothesis, result, plan
                )
                results.append((hypothesis, result))

        # Rank by weighted confidence (hypothesis weight * evidence confidence)
        results.sort(
            key=lambda pair: pair[0].weight * pair[1].confidence,
            reverse=True,
        )

        for rank, (hypothesis, result) in enumerate(results, 1):
            report.ranked.append(
                RankedHypothesis(
                    hypothesis=hypothesis,
                    result=result,
                    rank=rank,
                )
            )

        return report

    def _render_remediation(
        self,
        hypothesis: CausalHypothesis,
        result: EvidenceResult,
        plan: IRPlan,
    ) -> str:
        """Render remediation template with evidence data."""
        template = hypothesis.remediation_template
        if not template:
            return ""

        # Collect substitution values from evidence
        subs: dict[str, str] = {}
        for node in plan.all_nodes():
            if node.id in result.affected_nodes:
                if node.properties.relation_name:
                    subs.setdefault("table", node.properties.relation_name)
                if node.properties.index_name:
                    subs.setdefault("index", node.properties.index_name)
                if node.properties.predicates.filter_condition:
                    subs.setdefault(
                        "columns",
                        _extract_columns(
                            node.properties.predicates.filter_condition
                        ),
                    )
                mem = node.properties.memory
                if mem.sort_space_used_kb:
                    subs["current_kb"] = str(mem.sort_space_used_kb)
                    subs["spill_type"] = mem.sort_space_type or "unknown"
                    subs["mem"] = str(max(64, mem.sort_space_used_kb // 512))
                par = node.properties.parallelism
                if par.planned_workers:
                    subs["planned"] = str(par.planned_workers)
                    subs["launched"] = str(par.launched_workers or 0)

        try:
            return template.format_map(
                _SafeDict(subs)
            )
        except Exception:
            return template


class _SafeDict(dict):  # type: ignore[type-arg]
    """Dict that returns '{key}' for missing keys in format_map."""
    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"


def _extract_columns(filter_expr: str) -> str:
    """Extract column-like identifiers from a filter expression."""
    import re
    # Simple heuristic: extract words that look like column names
    candidates = re.findall(r'\b([a-z_][a-z0-9_]*)\b', filter_expr.lower())
    # Remove common SQL keywords
    keywords = {
        "and", "or", "not", "in", "is", "null", "true", "false",
        "between", "like", "any", "all", "exists", "case", "when",
        "then", "else", "end",
    }
    columns = [c for c in candidates if c not in keywords]
    return ", ".join(dict.fromkeys(columns))  # dedupe preserving order
