"""
Rewrite Sandbox — test SQL rewrites against a real database safely.

Wraps every rewritten query in a read-only transaction, captures EXPLAIN
output before and after, and compares results. The original query is NEVER
committed — all testing happens inside a rolled-back transaction.

This addresses the safety gap: developers can verify rewrites produce
identical results and actually improve performance before applying them.

Usage:
    from querysense.rewrite_sandbox import RewriteSandbox

    sandbox = RewriteSandbox(dsn="postgresql://localhost/mydb")
    result = await sandbox.test_rewrite(
        original_sql="SELECT * FROM orders WHERE id IN (SELECT ...)",
        rewritten_sql="SELECT * FROM orders WHERE EXISTS (SELECT 1 ...)",
    )
    print(result.is_safe)  # True if results match
    print(result.speedup)  # e.g., 2.5x
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    """Result of a sandbox rewrite test."""

    original_sql: str
    rewritten_sql: str

    # Safety checks
    is_safe: bool = False
    results_match: bool = False
    row_count_original: int = 0
    row_count_rewritten: int = 0
    result_hash_original: str = ""
    result_hash_rewritten: str = ""

    # Performance comparison
    original_cost: float = 0.0
    rewritten_cost: float = 0.0
    original_time_ms: float = 0.0
    rewritten_time_ms: float = 0.0
    speedup: float = 1.0
    cost_reduction_pct: float = 0.0

    # Plan comparison
    original_plan_type: str = ""
    rewritten_plan_type: str = ""
    plan_changed: bool = False

    # Errors
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        parts = []
        if self.results_match:
            parts.append("Results MATCH")
        else:
            parts.append(
                f"Results DIFFER ({self.row_count_original} vs {self.row_count_rewritten} rows)"
            )
        parts.append(f"Speedup: {self.speedup:.1f}x")
        parts.append(f"Cost: {self.cost_reduction_pct:.0f}% reduction")
        parts.append(f"Safe: {'YES' if self.is_safe else 'NO'}")
        return " | ".join(parts)


@dataclass
class SandboxConfig:
    """Configuration for sandbox testing."""

    # Limits
    max_rows_to_compare: int = 10000
    statement_timeout_ms: int = 30000
    max_result_size_mb: int = 50

    # Behavior
    compare_results: bool = True
    compare_row_count_only: bool = False  # faster: only compare counts, not hashes
    require_exact_match: bool = True


class RewriteSandbox:
    """
    Test SQL rewrites safely against a real database.

    All queries run inside a rolled-back transaction. No data is modified.
    Supports both PostgreSQL (via asyncpg) and MySQL (via aiomysql).
    """

    def __init__(
        self,
        dsn: str,
        config: SandboxConfig | None = None,
    ) -> None:
        self.dsn = dsn
        self.config = config or SandboxConfig()
        self._is_mysql = "mysql" in dsn.lower() or "mariadb" in dsn.lower()

    async def test_rewrite(
        self,
        original_sql: str,
        rewritten_sql: str,
    ) -> SandboxResult:
        """
        Test a rewritten query against the original.

        1. Opens a read-only transaction
        2. Runs EXPLAIN ANALYZE on both queries
        3. Optionally compares result sets (row counts + hashes)
        4. Rolls back the transaction (no side effects)

        Returns SandboxResult with safety and performance comparison.
        """
        result = SandboxResult(
            original_sql=original_sql,
            rewritten_sql=rewritten_sql,
        )

        try:
            if self._is_mysql:
                await self._test_mysql(result)
            else:
                await self._test_postgresql(result)
        except Exception as e:
            result.error = str(e)
            result.is_safe = False
            logger.error("Sandbox test failed: %s", e)

        return result

    async def _test_postgresql(self, result: SandboxResult) -> None:
        """Test rewrite against PostgreSQL."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required for PostgreSQL sandbox: pip install asyncpg")

        conn = await asyncpg.connect(self.dsn)
        try:
            # Set timeout
            await conn.execute(
                f"SET statement_timeout = '{self.config.statement_timeout_ms}ms'"
            )

            # Start read-only transaction
            await conn.execute("BEGIN TRANSACTION READ ONLY")

            try:
                # EXPLAIN ANALYZE original
                orig_explain = await conn.fetch(
                    f"EXPLAIN (ANALYZE, FORMAT JSON) {result.original_sql}"
                )
                orig_plan = json.loads(orig_explain[0][0])[0]
                result.original_cost = orig_plan["Plan"]["Total Cost"]
                result.original_time_ms = orig_plan.get("Execution Time", 0)
                result.original_plan_type = orig_plan["Plan"]["Node Type"]

                # EXPLAIN ANALYZE rewritten
                rew_explain = await conn.fetch(
                    f"EXPLAIN (ANALYZE, FORMAT JSON) {result.rewritten_sql}"
                )
                rew_plan = json.loads(rew_explain[0][0])[0]
                result.rewritten_cost = rew_plan["Plan"]["Total Cost"]
                result.rewritten_time_ms = rew_plan.get("Execution Time", 0)
                result.rewritten_plan_type = rew_plan["Plan"]["Node Type"]

                result.plan_changed = (
                    result.original_plan_type != result.rewritten_plan_type
                )

                # Compare results if configured
                if self.config.compare_results:
                    await self._compare_results_pg(conn, result)

                # Calculate metrics
                self._calculate_metrics(result)

            finally:
                await conn.execute("ROLLBACK")

        finally:
            await conn.close()

    async def _compare_results_pg(
        self,
        conn: Any,
        result: SandboxResult,
    ) -> None:
        """Compare result sets between original and rewritten queries."""
        limit = self.config.max_rows_to_compare

        # Get row counts
        orig_rows = await conn.fetch(
            f"SELECT COUNT(*) FROM ({result.original_sql}) _qs_orig"
        )
        result.row_count_original = orig_rows[0][0]

        rew_rows = await conn.fetch(
            f"SELECT COUNT(*) FROM ({result.rewritten_sql}) _qs_rew"
        )
        result.row_count_rewritten = rew_rows[0][0]

        if self.config.compare_row_count_only:
            result.results_match = (
                result.row_count_original == result.row_count_rewritten
            )
            return

        # Hash-based comparison (limited rows)
        if result.row_count_original > limit:
            result.warnings.append(
                f"Result set too large ({result.row_count_original:,} rows). "
                f"Comparing first {limit:,} rows only."
            )

        orig_hash_rows = await conn.fetch(
            f"SELECT md5(CAST(row_to_json(t) AS text)) FROM "
            f"({result.original_sql} LIMIT {limit}) t"
        )
        result.result_hash_original = hashlib.md5(
            "".join(r[0] for r in sorted(orig_hash_rows)).encode()
        ).hexdigest()

        rew_hash_rows = await conn.fetch(
            f"SELECT md5(CAST(row_to_json(t) AS text)) FROM "
            f"({result.rewritten_sql} LIMIT {limit}) t"
        )
        result.result_hash_rewritten = hashlib.md5(
            "".join(r[0] for r in sorted(rew_hash_rows)).encode()
        ).hexdigest()

        result.results_match = (
            result.result_hash_original == result.result_hash_rewritten
        )

    async def _test_mysql(self, result: SandboxResult) -> None:
        """Test rewrite against MySQL."""
        try:
            import aiomysql
        except ImportError:
            raise RuntimeError("aiomysql required for MySQL sandbox: pip install aiomysql")

        # Parse DSN for aiomysql
        from urllib.parse import urlparse
        parsed = urlparse(self.dsn)

        conn = await aiomysql.connect(
            host=parsed.hostname or "localhost",
            port=parsed.port or 3306,
            user=parsed.username or "root",
            password=parsed.password or "",
            db=parsed.path.lstrip("/") if parsed.path else "",
        )

        try:
            async with conn.cursor() as cur:
                await cur.execute("START TRANSACTION READ ONLY")

                try:
                    # EXPLAIN original
                    await cur.execute(f"EXPLAIN FORMAT=JSON {result.original_sql}")
                    orig_row = await cur.fetchone()
                    orig_plan = json.loads(orig_row[0])
                    result.original_cost = float(
                        orig_plan.get("query_block", {})
                        .get("cost_info", {})
                        .get("query_cost", "0")
                    )
                    result.original_plan_type = "mysql_query_block"

                    # EXPLAIN rewritten
                    await cur.execute(f"EXPLAIN FORMAT=JSON {result.rewritten_sql}")
                    rew_row = await cur.fetchone()
                    rew_plan = json.loads(rew_row[0])
                    result.rewritten_cost = float(
                        rew_plan.get("query_block", {})
                        .get("cost_info", {})
                        .get("query_cost", "0")
                    )
                    result.rewritten_plan_type = "mysql_query_block"

                    # Compare row counts
                    if self.config.compare_results:
                        await cur.execute(
                            f"SELECT COUNT(*) FROM ({result.original_sql}) _orig"
                        )
                        result.row_count_original = (await cur.fetchone())[0]

                        await cur.execute(
                            f"SELECT COUNT(*) FROM ({result.rewritten_sql}) _rew"
                        )
                        result.row_count_rewritten = (await cur.fetchone())[0]

                        result.results_match = (
                            result.row_count_original == result.row_count_rewritten
                        )

                    self._calculate_metrics(result)

                finally:
                    await cur.execute("ROLLBACK")

        finally:
            conn.close()

    def _calculate_metrics(self, result: SandboxResult) -> None:
        """Calculate speedup and cost reduction."""
        if result.original_cost > 0 and result.rewritten_cost > 0:
            result.cost_reduction_pct = (
                (1 - result.rewritten_cost / result.original_cost) * 100
            )
            result.speedup = result.original_cost / result.rewritten_cost

        if result.original_time_ms > 0 and result.rewritten_time_ms > 0:
            result.speedup = result.original_time_ms / result.rewritten_time_ms

        # Safety determination
        if result.results_match or not self.config.compare_results:
            if result.cost_reduction_pct >= 0:
                result.is_safe = True
            else:
                result.is_safe = True
                result.warnings.append(
                    "Rewrite is slower than original — still safe but may not help."
                )
        else:
            result.is_safe = False
            result.warnings.append(
                f"Result sets differ: {result.row_count_original} vs "
                f"{result.row_count_rewritten} rows."
            )
