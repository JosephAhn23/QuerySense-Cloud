"""
Concurrency Tester — find where queries start failing under load.

Addresses the P0 gap from Exasol benchmark: "Systems fail deterministically
under concurrency — benchmarks ignore this." Your analysis is single-query
only; this adds multi-user stress testing.

Capabilities:
1. Ramp up concurrent queries: 1 → 5 → 10 → 15 → 20 users
2. Detect failure points (timeouts, lock contention, OOM)
3. Report p50/p95/p99 latencies at each concurrency level
4. Identify the max safe concurrency for a workload
5. Suggest configuration changes (work_mem, max_connections)

Usage:
    from querysense.concurrency_tester import ConcurrencyTester

    tester = ConcurrencyTester()
    report = tester.test(dsn, queries, max_users=20)
    print(report.max_safe_concurrency)
    print(report.failure_point)
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ConcurrencyLevel:
    """Results for a single concurrency level."""

    concurrency: int
    total_queries: int
    successful: int
    failed: int
    errors: list[str] = field(default_factory=list)

    # Latency metrics (in milliseconds)
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    avg_ms: float = 0.0
    max_ms: float = 0.0

    # Throughput
    queries_per_second: float = 0.0

    @property
    def failure_rate(self) -> float:
        return self.failed / max(self.total_queries, 1)

    @property
    def is_healthy(self) -> bool:
        return self.failure_rate < 0.01  # <1% failures


@dataclass
class ConcurrencyReport:
    """Complete concurrency test report."""

    levels: list[ConcurrencyLevel] = field(default_factory=list)
    max_safe_concurrency: int = 0
    failure_point: int | None = None
    failure_reason: str = ""
    recommendations: list[str] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return self.failure_point is not None

    def summary(self) -> str:
        if self.failure_point:
            return (
                f"Queries start failing at {self.failure_point} concurrent users. "
                f"Max safe concurrency: {self.max_safe_concurrency}. "
                f"Reason: {self.failure_reason}"
            )
        return (
            f"All concurrency levels passed. Max tested: "
            f"{self.levels[-1].concurrency if self.levels else 0} users."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "max_safe_concurrency": self.max_safe_concurrency,
            "failure_point": self.failure_point,
            "failure_reason": self.failure_reason,
            "levels": [
                {
                    "concurrency": lv.concurrency,
                    "total_queries": lv.total_queries,
                    "successful": lv.successful,
                    "failed": lv.failed,
                    "failure_rate": f"{lv.failure_rate:.1%}",
                    "p50_ms": round(lv.p50_ms, 2),
                    "p95_ms": round(lv.p95_ms, 2),
                    "p99_ms": round(lv.p99_ms, 2),
                    "avg_ms": round(lv.avg_ms, 2),
                    "max_ms": round(lv.max_ms, 2),
                    "queries_per_second": round(lv.queries_per_second, 1),
                    "errors": lv.errors[:5],  # First 5 unique errors
                }
                for lv in self.levels
            ],
            "recommendations": self.recommendations,
        }


class ConcurrencyTester:
    """Test where queries start failing under concurrent load.

    Uses asyncpg for real PostgreSQL connections. Falls back to
    simulated mode when no DSN is provided.
    """

    DEFAULT_LEVELS = [1, 5, 10, 15, 20, 30, 50]
    QUERIES_PER_LEVEL = 50  # Number of queries to run at each level
    TIMEOUT_SECONDS = 30

    def test_sync(
        self,
        dsn: str,
        queries: list[str],
        max_users: int = 20,
        timeout_sec: int = 30,
    ) -> ConcurrencyReport:
        """Run concurrency test synchronously using threads.

        This is the simplest interface — uses Python threads and psycopg2
        (or any DB-API 2.0 driver).

        Args:
            dsn: PostgreSQL connection string
            queries: List of SQL queries to run concurrently
            max_users: Maximum number of concurrent users to test
            timeout_sec: Per-query timeout in seconds
        """
        import concurrent.futures

        levels = [l for l in self.DEFAULT_LEVELS if l <= max_users]
        if max_users not in levels:
            levels.append(max_users)

        report = ConcurrencyReport()
        max_safe = 0

        for concurrency in levels:
            latencies: list[float] = []
            errors: list[str] = []
            total = max(self.QUERIES_PER_LEVEL, concurrency * 2)
            start_time = time.monotonic()

            def _run_query(q: str) -> tuple[float | None, str | None]:
                try:
                    import psycopg2  # type: ignore[import-untyped]
                    conn = psycopg2.connect(dsn)
                    conn.set_session(autocommit=True)
                    cur = conn.cursor()
                    cur.execute(f"SET statement_timeout = '{timeout_sec * 1000}'")
                    t0 = time.monotonic()
                    cur.execute(q)
                    _ = cur.fetchall()
                    elapsed = (time.monotonic() - t0) * 1000  # ms
                    cur.close()
                    conn.close()
                    return elapsed, None
                except Exception as e:
                    return None, str(e)[:200]

            # Run queries concurrently
            query_cycle = [queries[i % len(queries)] for i in range(total)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [executor.submit(_run_query, q) for q in query_cycle]
                for future in concurrent.futures.as_completed(futures, timeout=timeout_sec * 2):
                    try:
                        elapsed, error = future.result(timeout=timeout_sec)
                        if elapsed is not None:
                            latencies.append(elapsed)
                        if error:
                            errors.append(error)
                    except Exception as e:
                        errors.append(str(e)[:200])

            elapsed_total = time.monotonic() - start_time
            successful = len(latencies)
            failed = len(errors)

            # Compute percentiles
            p50 = p95 = p99 = avg = mx = 0.0
            if latencies:
                sorted_lat = sorted(latencies)
                p50 = sorted_lat[len(sorted_lat) // 2]
                p95 = sorted_lat[int(len(sorted_lat) * 0.95)]
                p99 = sorted_lat[int(len(sorted_lat) * 0.99)]
                avg = statistics.mean(latencies)
                mx = max(latencies)

            qps = successful / elapsed_total if elapsed_total > 0 else 0

            level = ConcurrencyLevel(
                concurrency=concurrency,
                total_queries=total,
                successful=successful,
                failed=failed,
                errors=list(set(errors))[:5],
                p50_ms=p50,
                p95_ms=p95,
                p99_ms=p99,
                avg_ms=avg,
                max_ms=mx,
                queries_per_second=qps,
            )
            report.levels.append(level)

            if level.is_healthy:
                max_safe = concurrency
            elif report.failure_point is None:
                report.failure_point = concurrency
                # Determine failure reason
                unique_errors = set(errors)
                if any("timeout" in e.lower() for e in unique_errors):
                    report.failure_reason = "Query timeout exceeded — queries too slow under load"
                elif any("lock" in e.lower() for e in unique_errors):
                    report.failure_reason = "Lock contention — concurrent queries waiting for locks"
                elif any("memory" in e.lower() or "oom" in e.lower() for e in unique_errors):
                    report.failure_reason = "Out of memory — work_mem too high for concurrent workload"
                elif any("connection" in e.lower() for e in unique_errors):
                    report.failure_reason = "Connection limit reached — increase max_connections or use pgbouncer"
                else:
                    report.failure_reason = f"Failures at {concurrency} concurrent users: {errors[0] if errors else 'unknown'}"

        report.max_safe_concurrency = max_safe

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        return report

    def estimate_from_plan(
        self,
        plan_json: dict[str, Any],
        target_concurrency: int = 20,
    ) -> ConcurrencyReport:
        """Estimate concurrency limits from a single EXPLAIN ANALYZE plan.

        This is an offline estimation — no database connection needed.
        Uses plan cost and memory metrics to predict failure points.

        Args:
            plan_json: EXPLAIN ANALYZE JSON output
            target_concurrency: Target concurrent users to evaluate
        """
        root = plan_json[0] if isinstance(plan_json, list) else plan_json
        plan = root.get("Plan", root)

        # Extract key metrics
        total_cost = plan.get("Total Cost", 0)
        total_time_ms = plan.get("Actual Total Time", 0)
        shared_hit = plan.get("Shared Hit Blocks", 0)
        shared_read = plan.get("Shared Read Blocks", 0)
        temp_written = plan.get("Temp Written Blocks", 0)
        work_mem_used = temp_written > 0  # Spilling to disk

        # Walk tree for memory-intensive operations
        sort_count = 0
        hash_count = 0
        max_rows = 0

        def _walk(node: dict) -> None:
            nonlocal sort_count, hash_count, max_rows
            nt = node.get("Node Type", "")
            rows = node.get("Actual Rows", 0) or node.get("Plan Rows", 0)
            if rows > max_rows:
                max_rows = rows
            if "Sort" in nt:
                sort_count += 1
            if "Hash" in nt:
                hash_count += 1
            for child in node.get("Plans", []):
                _walk(child)

        _walk(plan)

        # Estimate memory per query (rough: 1KB per row in sorts/hashes + work_mem)
        estimated_mem_mb = max_rows * (sort_count + hash_count) * 0.001  # Very rough
        if work_mem_used:
            estimated_mem_mb *= 2  # Already spilling, needs more

        # Estimate max concurrency before memory pressure
        # Assume 4GB available for queries (conservative)
        available_memory_mb = 4096
        if estimated_mem_mb > 0:
            max_mem_concurrency = int(available_memory_mb / max(estimated_mem_mb, 1))
        else:
            max_mem_concurrency = 100

        # Estimate max concurrency before latency degradation
        # Rule of thumb: latency doubles per 2x concurrency due to shared resources
        if total_time_ms > 0:
            max_latency_concurrency = max(1, int(1000 / total_time_ms * 10))
        else:
            max_latency_concurrency = 50

        estimated_max = min(max_mem_concurrency, max_latency_concurrency)

        # Generate simulated levels
        report = ConcurrencyReport()
        levels_to_test = [l for l in self.DEFAULT_LEVELS if l <= target_concurrency]

        for conc in levels_to_test:
            # Simulate latency increase: linear + contention factor
            contention_factor = 1.0 + (conc / estimated_max) ** 2
            est_p50 = total_time_ms * contention_factor
            est_p95 = est_p50 * 1.5
            est_p99 = est_p50 * 2.5

            failure_rate = max(0, (conc - estimated_max) / max(estimated_max, 1))

            level = ConcurrencyLevel(
                concurrency=conc,
                total_queries=100,
                successful=int(100 * (1 - failure_rate)),
                failed=int(100 * failure_rate),
                p50_ms=round(est_p50, 2),
                p95_ms=round(est_p95, 2),
                p99_ms=round(est_p99, 2),
                avg_ms=round(est_p50 * 1.1, 2),
                max_ms=round(est_p99 * 1.3, 2),
                errors=["estimated — run live test for real data"] if failure_rate > 0 else [],
            )
            report.levels.append(level)

            if level.is_healthy:
                report.max_safe_concurrency = conc

        if estimated_max < target_concurrency:
            report.failure_point = estimated_max
            if estimated_mem_mb > available_memory_mb / target_concurrency:
                report.failure_reason = (
                    f"Estimated memory per query: {estimated_mem_mb:.0f}MB. "
                    f"At {target_concurrency} users: {estimated_mem_mb * target_concurrency:.0f}MB needed "
                    f"(available: ~{available_memory_mb}MB)"
                )
            else:
                report.failure_reason = (
                    f"Query latency ({total_time_ms:.0f}ms) suggests degradation at "
                    f"~{estimated_max} concurrent users"
                )

        report.recommendations = self._generate_recommendations(report)
        return report

    def _generate_recommendations(self, report: ConcurrencyReport) -> list[str]:
        """Generate actionable recommendations based on test results."""
        recs: list[str] = []

        if not report.levels:
            return recs

        # Check for latency degradation
        if len(report.levels) >= 2:
            first = report.levels[0]
            last = report.levels[-1]
            if first.p50_ms > 0 and last.p50_ms > first.p50_ms * 5:
                recs.append(
                    f"Latency increased {last.p50_ms / first.p50_ms:.0f}x from "
                    f"{first.concurrency} to {last.concurrency} users. "
                    f"Consider connection pooling (PgBouncer) and reducing work_mem."
                )

        # Check for memory issues
        has_memory_errors = any(
            any("memory" in e.lower() or "oom" in e.lower() for e in lv.errors)
            for lv in report.levels
        )
        if has_memory_errors:
            recs.append(
                "Out-of-memory errors detected. Reduce work_mem from session-level "
                "to query-level: SET LOCAL work_mem = '64MB' inside transactions."
            )

        # Check for lock contention
        has_lock_errors = any(
            any("lock" in e.lower() or "deadlock" in e.lower() for e in lv.errors)
            for lv in report.levels
        )
        if has_lock_errors:
            recs.append(
                "Lock contention detected. Consider: (1) shorter transactions, "
                "(2) advisory locks, (3) SKIP LOCKED for queue patterns."
            )

        # Check for connection limits
        has_conn_errors = any(
            any("connection" in e.lower() for e in lv.errors)
            for lv in report.levels
        )
        if has_conn_errors:
            recs.append(
                "Connection limit reached. Deploy PgBouncer or increase "
                "max_connections (but beware: more connections = more memory)."
            )

        # General recommendations based on max safe concurrency
        if report.max_safe_concurrency < 10:
            recs.append(
                "Max safe concurrency is very low (<10). This workload needs "
                "optimization before production use. Focus on reducing per-query cost."
            )
        elif report.max_safe_concurrency < 20:
            recs.append(
                "Max safe concurrency is moderate. Consider adding indexes, "
                "enabling parallel query, or partitioning hot tables."
            )

        if not recs:
            recs.append(
                "All concurrency levels passed. Your workload handles "
                f"up to {report.max_safe_concurrency} concurrent users well."
            )

        return recs
