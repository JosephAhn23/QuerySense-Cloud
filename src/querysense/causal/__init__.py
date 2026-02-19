"""
Causal Plan Analysis Engine.

Transforms multiple symptoms into ranked root-cause hypotheses with
confidence scores and justifications.

The causal engine does not attempt to predict the optimizer; instead it:
1. Maintains a fixed catalog of root-cause hypotheses
2. Evaluates per-hypothesis evidence functions against IR facts
3. Produces a ranked list of likely causes with explanations
"""

from querysense.causal.hypotheses import (
    CausalHypothesis,
    HypothesisID,
    HYPOTHESIS_CATALOG,
)
from querysense.causal.evidence import (
    Evidence,
    EvidenceStrength,
    EvidenceResult,
)
from querysense.causal.engine import CausalEngine, CausalReport

__all__ = [
    "CausalHypothesis",
    "HypothesisID",
    "HYPOTHESIS_CATALOG",
    "Evidence",
    "EvidenceStrength",
    "EvidenceResult",
    "CausalEngine",
    "CausalReport",
]
