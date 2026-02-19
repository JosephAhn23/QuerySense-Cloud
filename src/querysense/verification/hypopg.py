"""
HypoPG integration for hypothetical index verification.

HypoPG is a PostgreSQL extension that creates virtual indexes that don't
physically exist but are visible to the planner.  This allows testing
"would this index help?" without the cost of actually building it.

Usage requires the ``hypopg`` extension to be installed in the target
PostgreSQL database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from querysense.ir.adapters.postgres import PostgresAdapter
from querysense.ir.plan import IRPlan
from querysense.verification.whatif import (
    VerificationResult,
    VerificationStep,
    VerificationWorkflow,
    WhatIfVerifier,
)


class AsyncDBConnection(Protocol):
    """Protocol for async database connections."""

    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...
    async def execute(self, query: str, *args: Any) -> str: ...


@dataclass
class HypotheticalIndex:
    """A hypothetical index created via HypoPG."""

    oid: int
    index_name: str
    table_name: str
    columns: tuple[str, ...]
    create_sql: str
    size_bytes: int = 0


class HypoPGVerifier(WhatIfVerifier):
    """
    Verify index recommendations using HypoPG hypothetical indexes.

    Example::

        verifier = HypoPGVerifier(conn)
        workflow = VerificationWorkflow(
            fix_description="Add index on orders(customer_id)",
            fix_sql="CREATE INDEX ON orders(customer_id)",
            query_sql="SELECT * FROM orders WHERE customer_id = 42",
        )
        result = await verifier.verify(workflow)
        if result.improved:
            print(f"Index would improve by {result.cost_improvement_pct:.1f}%")
    """

    def __init__(self, conn: AsyncDBConnection):
        self.conn = conn
        self.adapter = PostgresAdapter()
        self._hypo_indexes: list[HypotheticalIndex] = []

    async def verify(
        self,
        workflow: VerificationWorkflow,
    ) -> VerificationResult:
        """Execute a HypoPG-based verification workflow."""
        errors: list[str] = []

        # Check HypoPG availability
        if not await self._check_hypopg():
            return VerificationResult(
                fix_description=workflow.fix_description,
                errors=["HypoPG extension is not installed. "
                        "Install with: CREATE EXTENSION hypopg;"],
            )

        try:
            # Step 1: Capture before plan
            before_plan = await self.explain_query(workflow.query_sql)

            # Step 2: Create hypothetical index
            hypo_idx = await self._create_hypothetical_index(workflow.fix_sql)
            if hypo_idx is None:
                return VerificationResult(
                    fix_description=workflow.fix_description,
                    before_plan=before_plan,
                    errors=["Failed to create hypothetical index"],
                )

            # Step 3: Capture after plan (with hypo index visible)
            after_plan = await self.explain_query(workflow.query_sql)

            # Step 4: Compare
            result = self.compare_plans(
                before_plan, after_plan, workflow.fix_description
            )
            result.details["hypothetical_index"] = {
                "name": hypo_idx.index_name,
                "table": hypo_idx.table_name,
                "columns": hypo_idx.columns,
                "estimated_size_bytes": hypo_idx.size_bytes,
            }

            return result

        except Exception as exc:
            errors.append(f"Verification failed: {exc}")
            return VerificationResult(
                fix_description=workflow.fix_description,
                errors=errors,
            )

        finally:
            # Step 5: Clean up hypothetical indexes
            await self._cleanup_hypothetical_indexes()

    async def explain_query(self, sql: str) -> IRPlan:
        """Get EXPLAIN JSON for a query and convert to IR."""
        import json

        explain_sql = f"EXPLAIN (FORMAT JSON, COSTS) {sql}"
        result = await self.conn.fetchval(explain_sql)

        if isinstance(result, str):
            raw_plan = json.loads(result)
        else:
            raw_plan = result

        return self.adapter.translate(raw_plan, sql=sql)

    async def _check_hypopg(self) -> bool:
        """Check if HypoPG extension is available."""
        try:
            result = await self.conn.fetchval(
                "SELECT EXISTS("
                "  SELECT 1 FROM pg_extension WHERE extname = 'hypopg'"
                ")"
            )
            return bool(result)
        except Exception:
            return False

    async def _create_hypothetical_index(
        self, create_index_sql: str,
    ) -> HypotheticalIndex | None:
        """Create a hypothetical index using HypoPG."""
        try:
            # HypoPG wraps CREATE INDEX statements
            result = await self.conn.fetch(
                f"SELECT * FROM hypopg_create_index($1)",
                create_index_sql,
            )

            if not result:
                return None

            row = result[0]
            oid = row[0] if isinstance(row, (list, tuple)) else getattr(row, "indexrelid", 0)
            name = row[1] if isinstance(row, (list, tuple)) else getattr(row, "indexname", "")

            # Get estimated size
            try:
                size = await self.conn.fetchval(
                    "SELECT hypopg_relation_size($1)", oid
                )
            except Exception:
                size = 0

            hypo = HypotheticalIndex(
                oid=oid,
                index_name=name,
                table_name="",
                columns=(),
                create_sql=create_index_sql,
                size_bytes=size or 0,
            )
            self._hypo_indexes.append(hypo)
            return hypo

        except Exception:
            return None

    async def _cleanup_hypothetical_indexes(self) -> None:
        """Remove all hypothetical indexes."""
        try:
            await self.conn.execute("SELECT hypopg_reset()")
        except Exception:
            pass
        self._hypo_indexes.clear()

    async def bulk_verify(
        self,
        workflows: list[VerificationWorkflow],
    ) -> list[VerificationResult]:
        """Verify multiple index recommendations."""
        results = []
        for wf in workflows:
            result = await self.verify(wf)
            results.append(result)
        return results
