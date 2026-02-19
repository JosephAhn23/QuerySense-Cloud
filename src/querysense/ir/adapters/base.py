"""
Base adapter interface for engine-specific plan translation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from querysense.ir.plan import IRPlan


class PlanAdapter(ABC):
    """
    Abstract base for engine adapters.

    Each adapter translates a raw plan (JSON dict, XML string, etc.)
    into an ``IRPlan`` with capabilities derived.
    """

    engine: str = "unknown"

    @abstractmethod
    def translate(self, raw_plan: Any, **kwargs: Any) -> IRPlan:
        """
        Translate a raw engine plan into an IR plan.

        Args:
            raw_plan: The engine-specific plan data (dict for JSON, str for XML).
            **kwargs: Optional extras (sql text, engine version, etc.).

        Returns:
            A fully populated ``IRPlan`` with capabilities derived.
        """
        ...

    @abstractmethod
    def can_handle(self, raw_plan: Any) -> bool:
        """
        Return True if this adapter can handle the given raw plan format.

        Used for auto-detection when the engine is not specified.
        """
        ...


def auto_detect_adapter(raw_plan: Any) -> PlanAdapter:
    """
    Auto-detect the appropriate adapter for a raw plan.

    Tries each adapter's ``can_handle`` method in order.
    """
    from querysense.ir.adapters.mysql import MySQLAdapter
    from querysense.ir.adapters.oracle import OracleAdapter
    from querysense.ir.adapters.postgres import PostgresAdapter
    from querysense.ir.adapters.sqlserver import SQLServerAdapter

    for adapter_cls in [PostgresAdapter, MySQLAdapter, SQLServerAdapter, OracleAdapter]:
        adapter = adapter_cls()
        if adapter.can_handle(raw_plan):
            return adapter

    raise ValueError(
        "Cannot auto-detect engine from plan format. "
        "Pass engine explicitly or use a specific adapter."
    )
