"""
Explainer protocol (optional LLM integration).

The analyzer works without any explainer.
Only use this for ambiguous cases where deterministic suggestions aren't enough.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.analyzer.models import Finding


@dataclass
class ExplanationResult:
    """Result from explaining a finding."""
    
    finding_id: str
    explanation: str | None
    error: str | None = None
    from_cache: bool = False
    latency_ms: float = 0.0


class Explainer(ABC):
    """
    Abstract base for LLM explainers.
    
    Implement this to add LLM-generated explanations.
    But consider: do you actually need LLM for this?
    
    Good uses for LLM:
    - "Explain this complex join strategy to a junior developer"
    - "Why might the planner have chosen this approach?"
    
    Bad uses for LLM (use deterministic rules instead):
    - "What index should I add?" (deterministic)
    - "Is this query slow?" (yes, you already detected it)
    """
    
    @abstractmethod
    async def explain_one(self, finding: "Finding") -> ExplanationResult:
        """Explain a single finding."""
        ...
    
    async def explain_batch(
        self,
        findings: list["Finding"],
    ) -> list[ExplanationResult]:
        """Explain multiple findings. Default: sequential calls."""
        results = []
        for finding in findings:
            result = await self.explain_one(finding)
            results.append(result)
        return results