"""
Domain Leverage Scorecard for QuerySense problem selection.

Operationalizes the "Problem Selection & Domain Leverage" discipline
as a repeatable scoring framework. Each candidate problem is evaluated
against six dimensions that predict disproportionate returns:

1. Trigger frequency — how often the problem recurs in normal operations
2. Concentration of risk — blast radius of the worst-case outcome
3. Workflow embed points — natural gates where the tool becomes required
4. Switching costs — training/process/tooling integration that creates retention
5. Observability primitives — standard system hooks that reduce build effort
6. Determinism & explainability — ability to produce stable, reviewable outputs

This module is used both as an internal planning tool and as a data model
that can be exposed to users evaluating which QuerySense capabilities
to prioritize for their environment.

Usage:
    from querysense.scorecard import LeverageScorecard, score_problem

    # Score a candidate problem
    scorecard = score_problem(
        name="Plan regression prevention",
        trigger_frequency=9,
        risk_concentration=9,
        workflow_embed=8,
        switching_costs=8,
        observability=9,
        determinism=8,
    )
    print(f"Weighted score: {scorecard.weighted_score}/100")
    print(scorecard.format_report())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DimensionScore:
    """Score for a single leverage dimension (1-10 scale)."""

    name: str
    score: int  # 1-10
    weight: float  # 0.0-1.0 (relative importance)
    rationale: str = ""
    evidence: tuple[str, ...] = ()

    @property
    def weighted(self) -> float:
        """Weighted contribution to the composite score."""
        return self.score * self.weight

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "score": self.score,
            "weight": self.weight,
            "weighted": round(self.weighted, 2),
            "rationale": self.rationale,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class LeverageScorecard:
    """
    Composite domain leverage scorecard for a candidate problem.

    Combines six dimension scores into a weighted composite that
    predicts the problem's potential for disproportionate returns.
    """

    name: str
    description: str = ""
    dimensions: tuple[DimensionScore, ...] = ()

    @property
    def weighted_score(self) -> float:
        """
        Composite weighted score normalized to 0-100 scale.

        Higher scores indicate stronger domain leverage and
        greater potential for disproportionate returns.
        """
        if not self.dimensions:
            return 0.0
        total_weight = sum(d.weight for d in self.dimensions)
        if total_weight == 0:
            return 0.0
        raw = sum(d.weighted for d in self.dimensions) / total_weight
        return round(raw * 10, 1)  # Scale from 1-10 to 10-100

    @property
    def top_strengths(self) -> tuple[DimensionScore, ...]:
        """Dimensions scoring 8 or above (strong leverage points)."""
        return tuple(d for d in self.dimensions if d.score >= 8)

    @property
    def improvement_areas(self) -> tuple[DimensionScore, ...]:
        """Dimensions scoring below 5 (potential weaknesses)."""
        return tuple(d for d in self.dimensions if d.score < 5)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "weighted_score": self.weighted_score,
            "dimensions": [d.to_dict() for d in self.dimensions],
        }

    def format_report(self) -> str:
        """Human-readable scorecard report."""
        lines: list[str] = []
        lines.append(f"Leverage Scorecard: {self.name}")
        lines.append(f"Composite Score: {self.weighted_score}/100")
        lines.append("")

        if self.description:
            lines.append(f"  {self.description}")
            lines.append("")

        lines.append("  Dimension Scores:")
        for d in sorted(self.dimensions, key=lambda x: x.weighted, reverse=True):
            bar = "#" * d.score + "." * (10 - d.score)
            lines.append(
                f"    [{bar}] {d.score}/10  {d.name} "
                f"(weight: {d.weight:.1f})"
            )
            if d.rationale:
                lines.append(f"      {d.rationale}")

        if self.top_strengths:
            lines.append("")
            lines.append("  Top Strengths:")
            for d in self.top_strengths:
                lines.append(f"    + {d.name} ({d.score}/10)")

        if self.improvement_areas:
            lines.append("")
            lines.append("  Improvement Areas:")
            for d in self.improvement_areas:
                lines.append(f"    - {d.name} ({d.score}/10)")

        return "\n".join(lines)


def score_problem(
    name: str,
    *,
    trigger_frequency: int,
    risk_concentration: int,
    workflow_embed: int,
    switching_costs: int,
    observability: int,
    determinism: int,
    description: str = "",
    rationales: dict[str, str] | None = None,
) -> LeverageScorecard:
    """
    Score a candidate problem using the domain leverage framework.

    Each dimension is scored 1-10. Weights reflect the relative
    importance of each dimension for sustainable product leverage.

    Args:
        name: Problem name
        trigger_frequency: How often the problem recurs (1=rare, 10=daily)
        risk_concentration: Blast radius of worst case (1=minor, 10=incident)
        workflow_embed: Natural gates for enforcement (1=none, 10=required CI check)
        switching_costs: Integration depth that creates retention (1=easy to replace, 10=embedded)
        observability: Standard system hooks available (1=custom build, 10=standard APIs)
        determinism: Ability to produce stable, reviewable outputs (1=noisy, 10=deterministic)
        description: Optional description of the problem
        rationales: Optional per-dimension rationale strings

    Returns:
        LeverageScorecard with composite scoring and analysis
    """
    rats = rationales or {}

    dimensions = (
        DimensionScore(
            name="Trigger Frequency",
            score=min(max(trigger_frequency, 1), 10),
            weight=0.20,
            rationale=rats.get("trigger_frequency", ""),
        ),
        DimensionScore(
            name="Risk Concentration",
            score=min(max(risk_concentration, 1), 10),
            weight=0.20,
            rationale=rats.get("risk_concentration", ""),
        ),
        DimensionScore(
            name="Workflow Embed Points",
            score=min(max(workflow_embed, 1), 10),
            weight=0.20,
            rationale=rats.get("workflow_embed", ""),
        ),
        DimensionScore(
            name="Switching Costs",
            score=min(max(switching_costs, 1), 10),
            weight=0.15,
            rationale=rats.get("switching_costs", ""),
        ),
        DimensionScore(
            name="Observability Primitives",
            score=min(max(observability, 1), 10),
            weight=0.15,
            rationale=rats.get("observability", ""),
        ),
        DimensionScore(
            name="Determinism & Explainability",
            score=min(max(determinism, 1), 10),
            weight=0.10,
            rationale=rats.get("determinism", ""),
        ),
    )

    return LeverageScorecard(
        name=name,
        description=description,
        dimensions=dimensions,
    )


# Pre-scored problems from the strategic analysis document.
# These serve as reference points for the domain leverage framework.
QUERYSENSE_PROBLEM_SCORES: dict[str, LeverageScorecard] = {
    "plan_regression_prevention": score_problem(
        name="Plan Regression Prevention",
        description=(
            "Detect and prevent query plan regressions caused by statistics drift, "
            "schema changes, version upgrades, and parameter sensitivity. "
            "Multiple database vendors (Aurora, Oracle, SQL Server) build dedicated "
            "plan management features for this problem."
        ),
        trigger_frequency=9,
        risk_concentration=9,
        workflow_embed=8,
        switching_costs=8,
        observability=9,
        determinism=8,
        rationales={
            "trigger_frequency": (
                "Continuously re-perturbed by ANALYZE cycles, deploys, "
                "data changes, and parameter distributions"
            ),
            "risk_concentration": (
                "Plan regressions cause production incidents; "
                "vendors build dedicated features (Aurora QPM, SQL Server Query Store)"
            ),
            "workflow_embed": (
                "Natural fit as required CI status check and merge gate; "
                "GitHub branch protection provides enforcement primitive"
            ),
            "switching_costs": (
                "Once baselines, policies, and CI integration are configured, "
                "removing the tool recreates risk and process toil"
            ),
            "observability": (
                "pg_stat_statements and auto_explain provide standard hooks; "
                "EXPLAIN output is a stable, documented API"
            ),
            "determinism": (
                "Structural plan comparison is deterministic; "
                "pattern-based detection outperforms cost-only comparison"
            ),
        },
    ),
    "ci_cd_query_gating": score_problem(
        name="CI/CD Query Gating",
        description=(
            "Enforce query performance standards as required merge checks. "
            "Converts QuerySense from advisory tool to required infrastructure."
        ),
        trigger_frequency=8,
        risk_concentration=7,
        workflow_embed=10,
        switching_costs=9,
        observability=7,
        determinism=9,
        rationales={
            "workflow_embed": (
                "GitHub required status checks make the tool a mandatory "
                "part of the merge workflow"
            ),
            "switching_costs": (
                "Process integration, team training, and policy configuration "
                "create high switching costs per Porter's framework"
            ),
        },
    ),
    "post_upgrade_validation": score_problem(
        name="Post-Upgrade Plan Validation",
        description=(
            "Validate query plans after PostgreSQL version upgrades to catch "
            "planner regressions before they reach production."
        ),
        trigger_frequency=3,
        risk_concentration=10,
        workflow_embed=6,
        switching_costs=5,
        observability=8,
        determinism=8,
        rationales={
            "trigger_frequency": "Episodic (annual-ish), not continuous",
            "risk_concentration": (
                "Upgrades concentrate risk: many queries may regress simultaneously"
            ),
        },
    ),
    "compliance_policy_enforcement": score_problem(
        name="Compliance & Policy Enforcement",
        description=(
            "Enforce declarative performance policies as code, producing "
            "auditable evidence for compliance requirements."
        ),
        trigger_frequency=7,
        risk_concentration=6,
        workflow_embed=8,
        switching_costs=7,
        observability=6,
        determinism=9,
        rationales={
            "determinism": (
                "Policy-as-code produces reproducible, auditable results "
                "suitable for compliance evidence"
            ),
        },
    ),
    "query_optimization_education": score_problem(
        name="Query Optimization Education",
        description=(
            "Help developers understand and improve query performance. "
            "Structurally lower leverage due to substitutability."
        ),
        trigger_frequency=6,
        risk_concentration=3,
        workflow_embed=3,
        switching_costs=2,
        observability=5,
        determinism=6,
        rationales={
            "switching_costs": (
                "Education helps users become less dependent on the tool; "
                "many substitutes exist (docs, blogs, consultants)"
            ),
        },
    ),
}
