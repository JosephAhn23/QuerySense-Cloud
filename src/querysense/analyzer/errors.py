"""
Error types for the analyzer module.

These are re-exported from the package-level exception hierarchy
(querysense.exceptions) for backward compatibility.

All new code should import from querysense.exceptions directly.
"""

from __future__ import annotations

# Re-export from the canonical package-level hierarchy
from querysense.exceptions import (  # noqa: F401
    AnalyzerError,
    ConfigurationError,
    RuleError,
)

__all__ = [
    "AnalyzerError",
    "ConfigurationError",
    "RuleError",
]
