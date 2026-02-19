"""
Fintech-specific detection rules for QuerySense.

These rules detect performance issues that have direct financial impact:
- Latency SLA breaches (trading, fraud, payments)
- Query cost attribution ($ per execution)
- Transaction safety (race conditions, isolation)
- Compliance violations (audit trails, data retention)

Install: pip install querysense[fintech]
"""

from querysense.analyzer.rules.fintech.latency_sla import LatencySLABreach
from querysense.analyzer.rules.fintech.cost_attribution import HighCostQuery
from querysense.analyzer.rules.fintech.transaction_safety import (
    WeakIsolationLevel,
    RaceConditionRisk,
)

__all__ = [
    "LatencySLABreach",
    "HighCostQuery",
    "WeakIsolationLevel",
    "RaceConditionRisk",
]

# Fintech rule IDs for filtering
FINTECH_RULE_IDS = [
    "FINTECH_LATENCY_SLA_BREACH",
    "FINTECH_HIGH_COST_QUERY",
    "FINTECH_WEAK_ISOLATION",
    "FINTECH_RACE_CONDITION_RISK",
]
