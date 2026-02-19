"""
Fix Verification: what-if analysis and before/after plan comparison.

Provides:
- HypoPG integration for hypothetical index verification (Postgres)
- Invisible index verification (MySQL)
- Before/after plan comparison using the IR
- Verification workflows for automated fix validation
"""

from querysense.verification.whatif import (
    VerificationResult,
    VerificationStep,
    VerificationWorkflow,
    WhatIfVerifier,
)
from querysense.verification.hypopg import HypoPGVerifier
from querysense.verification.index_simulator import (
    IndexSimulator,
    SimulationResult,
    format_simulation_results,
)
from querysense.verification.comparator import (
    IRPlanComparison,
    IRNodeDiff,
    compare_ir_plans,
)

__all__ = [
    "VerificationResult",
    "VerificationStep",
    "VerificationWorkflow",
    "WhatIfVerifier",
    "HypoPGVerifier",
    "IndexSimulator",
    "SimulationResult",
    "format_simulation_results",
    "IRPlanComparison",
    "IRNodeDiff",
    "compare_ir_plans",
]
