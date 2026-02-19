"""
What-if analysis framework for fix verification.

Provides a structured workflow for verifying that a recommended fix
actually improves the query plan.  Supports:
- Before/after EXPLAIN comparison
- Hypothetical index testing (via HypoPG on Postgres)
- Invisible index testing (MySQL)
- Automated verification pipelines
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from querysense.ir.plan import IRPlan


class VerificationStep(str, Enum):
    """Steps in a verification workflow."""
    CAPTURE_BEFORE = "capture_before"
    APPLY_FIX = "apply_fix"
    CAPTURE_AFTER = "capture_after"
    COMPARE = "compare"
    REPORT = "report"
    ROLLBACK = "rollback"


@dataclass
class VerificationResult:
    """
    Result of a fix verification.

    Attributes:
        fix_description: What fix was tested.
        improved: Whether the fix improved performance.
        before_plan: IR plan before the fix.
        after_plan: IR plan after the fix (if available).
        cost_delta: Change in total cost (negative = improvement).
        cost_improvement_pct: Percentage improvement in cost.
        structure_changed: Whether the plan structure changed.
        before_hash: Plan structure hash before.
        after_hash: Plan structure hash after.
        details: Additional details about the comparison.
        errors: Any errors encountered during verification.
    """

    fix_description: str
    improved: bool = False
    before_plan: IRPlan | None = None
    after_plan: IRPlan | None = None
    cost_delta: float | None = None
    cost_improvement_pct: float | None = None
    structure_changed: bool = False
    before_hash: str = ""
    after_hash: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        status = "IMPROVED" if self.improved else "NO IMPROVEMENT"
        parts = [f"[{status}] {self.fix_description}"]

        if self.cost_improvement_pct is not None:
            parts.append(f"Cost change: {self.cost_improvement_pct:+.1f}%")

        if self.structure_changed:
            parts.append(
                f"Plan changed: {self.before_hash[:8]}.. -> "
                f"{self.after_hash[:8]}.."
            )
        else:
            parts.append("Plan structure unchanged")

        if self.errors:
            parts.append(f"Errors: {', '.join(self.errors)}")

        return " | ".join(parts)


@dataclass(frozen=True)
class VerificationWorkflow:
    """
    A complete verification workflow definition.

    Defines what fix to test and how to verify it.
    """

    fix_description: str
    fix_sql: str  # SQL to apply the fix (CREATE INDEX, SET param, etc.)
    rollback_sql: str = ""  # SQL to undo the fix
    query_sql: str = ""  # The query to test
    hypothesis_id: str = ""  # Which causal hypothesis this addresses
    steps: tuple[VerificationStep, ...] = (
        VerificationStep.CAPTURE_BEFORE,
        VerificationStep.APPLY_FIX,
        VerificationStep.CAPTURE_AFTER,
        VerificationStep.COMPARE,
        VerificationStep.ROLLBACK,
        VerificationStep.REPORT,
    )


class WhatIfVerifier(ABC):
    """
    Abstract base for what-if verification backends.

    Subclasses implement engine-specific verification (HypoPG, invisible
    indexes, plan forcing, etc.).
    """

    @abstractmethod
    async def verify(
        self,
        workflow: VerificationWorkflow,
    ) -> VerificationResult:
        """Execute a verification workflow."""
        ...

    @abstractmethod
    async def explain_query(self, sql: str) -> IRPlan:
        """Get the IR plan for a query."""
        ...

    def compare_plans(
        self,
        before: IRPlan,
        after: IRPlan,
        fix_description: str,
    ) -> VerificationResult:
        """Compare before and after IR plans."""
        from querysense.verification.comparator import compare_ir_plans

        comparison = compare_ir_plans(before, after)

        before_cost = before.root.properties.cost.total_cost or 0
        after_cost = after.root.properties.cost.total_cost or 0
        cost_delta = after_cost - before_cost
        cost_pct = (
            (cost_delta / before_cost * 100) if before_cost > 0 else 0
        )

        before_hash = before.structure_hash()
        after_hash = after.structure_hash()

        return VerificationResult(
            fix_description=fix_description,
            improved=cost_delta < 0 or comparison.has_improvements,
            before_plan=before,
            after_plan=after,
            cost_delta=cost_delta,
            cost_improvement_pct=-cost_pct,  # positive = improvement
            structure_changed=before_hash != after_hash,
            before_hash=before_hash,
            after_hash=after_hash,
            details={
                "node_changes": comparison.changed_count,
                "new_nodes": comparison.new_count,
                "removed_nodes": comparison.removed_count,
                "scan_improvements": comparison.scan_improvements,
            },
        )
