"""
Unified Advisor Framework — Percona PMM-grade advisory engine.

Provides a shared architecture for all QuerySense advisors:
    - Base class with standard interface (check, severity, category)
    - Registry for discovering and running advisors
    - Configurable intervals (Rare/Standard/Frequent)
    - Category-based organization (Security, Configuration, Performance, Query)
    - Offline-first: all results stay local, nothing leaves your infrastructure

Usage:
    from querysense.advisor import AdvisorRegistry, run_all

    registry = AdvisorRegistry()
    results = await registry.run_all(dsn="postgresql://localhost/mydb")
    for r in results:
        print(f"[{r.severity}] {r.check_name}: {r.summary}")
"""

from querysense.advisor.base import (
    AdvisorCategory,
    AdvisorCheck,
    CheckInterval,
    CheckResult,
    CheckSeverity,
    Finding,
)
from querysense.advisor.registry import AdvisorRegistry

__all__ = [
    "AdvisorCategory",
    "AdvisorCheck",
    "AdvisorRegistry",
    "CheckInterval",
    "CheckResult",
    "CheckSeverity",
    "Finding",
]
