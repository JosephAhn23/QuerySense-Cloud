"""
Engine adapters: translate engine-specific EXPLAIN output into the IR.

Two generations of adapters exist:

**Legacy (backward-compatible)**:
- ``PostgreSQLAdapter`` (from ``postgresql.py``) -- used by the existing
  analyzer pipeline; maps EXPLAIN JSON to ``node.IRNode``/``node.IRPlan``.

**Universal IR (new)**:
- ``PostgresAdapter`` (from ``postgres.py``) -- maps EXPLAIN JSON to
  ``plan.IRNode``/``plan.IRPlan`` with three-layer properties.
- ``MySQLAdapter`` (from ``mysql.py``) -- maps MySQL EXPLAIN JSON.
- ``SQLServerAdapter`` (from ``sqlserver.py``) -- maps Showplan XML.
- ``OracleAdapter`` (from ``oracle.py``) -- maps V$SQL_PLAN JSON.

Each new adapter implements ``translate(raw_plan) -> IRPlan`` and
``can_handle(raw_plan) -> bool`` for auto-detection.
"""

from querysense.ir.adapters.base import PlanAdapter, auto_detect_adapter

# Legacy adapter
from querysense.ir.adapters.postgresql import PostgreSQLAdapter

# Universal IR adapters
from querysense.ir.adapters.postgres import PostgresAdapter
from querysense.ir.adapters.mysql import MySQLAdapter
from querysense.ir.adapters.sqlserver import SQLServerAdapter
from querysense.ir.adapters.oracle import OracleAdapter

__all__ = [
    "PlanAdapter",
    "auto_detect_adapter",
    "PostgreSQLAdapter",
    "PostgresAdapter",
    "MySQLAdapter",
    "SQLServerAdapter",
    "OracleAdapter",
]
