"""
LLM explanation module (OPTIONAL).

The analyzer works perfectly without this module.
Only use LLM explanations when deterministic suggestions aren't enough.
"""

from querysense.explainer.protocol import (
    ExplanationResult,
    Explainer,
)

# Optional Claude implementation
try:
    from querysense.explainer.claude import ClaudeExplainer
    _HAS_CLAUDE = True
except ImportError:
    _HAS_CLAUDE = False
    ClaudeExplainer = None  # type: ignore

__all__ = [
    "Explainer",
    "ExplanationResult",
    "ClaudeExplainer",
]
