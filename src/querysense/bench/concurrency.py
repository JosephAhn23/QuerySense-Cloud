"""
Concurrency Tester — find the breaking point of your database.

Runs queries at increasing concurrency levels (1, 5, 10, 20, 50...)
measuring latency, throughput, and failure rates. Identifies the
maximum safe concurrency and recommends fixes for bottlenecks.

Inspired by Exasol benchmarking methodology.

Usage (offline, no DB required):
    from querysense.bench import ConcurrencyTester

    # Simulation mode (no real DB needed)
    tester = ConcurrencyTester()
    report = tester.simulate_workload(
        queries=["SELECT * FROM orders WHERE id = $1", "SELECT count(*) FROM orders"],
        concurrency_levels=[1, 5, 10, 20, 50],
    )
    print(report.format_text())

Usage (live DB):
    tester = ConcurrencyTester(dsn="postgresql://...")
    report = await tester.test_workload(
        queries=["SELECT * FROM orders WHERE id = $1"],
        concurrency_levels=[1, 5, 10, 20],
        duration_seconds=30,
    )
"""

from __future__ import annotations

import asyncio
import json
import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConcurrencyResult:
    """Results from a single concurrency level test."""
    concurrency_level: int
    total_queries: int = 0
    success_count: int = 0
    failure_count: int = 0
    success_rate: float = 1.0
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    throughput_qps: float = 0.0  # queries per second
    failures: list[dict[str, Any]] = field(default_factory=list)
    failing_queries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "concurrency_level": self.concurrency_level,
            "total_queries": self.total_queries,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": round(self.success_rate, 4),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "p50_latency_ms": round(self.p50_latency_ms, 2),
            "p95_latency_ms": round(self.p95_latency_ms, 2),
            "p99_latency_ms": round(self.p99_latency_ms, 2),
            "min_latency_ms": round(self.min_latency_ms, 2),
            "max_latency_ms": round(self.max_latency_ms, 2),
            "throughput_qps": round(self.throughput_qps, 2),
            "failure_count_detail": len(self.failures),
            "failing_queries": self.failing_queries,
        }


@dataclass
class BenchmarkReport:
    """Full benchmark report across all concurrency levels."""
    results: list[ConcurrencyResult] = field(default_factory=list)
    max_safe_concurrency: int = 0
    breaking_point: int = 0
    recommendations: list[str] = field(default_factory=list)
    query_count: int = 0
    duration_seconds: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_safe_concurrency": self.max_safe_concurrency,
            "breaking_point": self.breaking_point,
            "query_count": self.query_count,
            "duration_seconds": self.duration_seconds,
            "recommendations": self.recommendations,
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  QUERYSENSE CONCURRENCY BENCHMARK")
        lines.append("  " + "=" * 60)
        lines.append("")

        # Results table
        lines.append(
            f"  {'Conc':>6} | {'QPS':>8} | {'Avg(ms)':>8} | {'P95(ms)':>8} | "
            f"{'P99(ms)':>8} | {'Success':>8} | {'Status'}"
        )
        lines.append("  " + "-" * 72)

        for r in self.results:
            status = "OK" if r.success_rate >= 0.99 else (
                "WARN" if r.success_rate >= 0.95 else "FAIL"
            )
            marker = {
                "OK": " [OK]",
                "WARN": " [!!]",
                "FAIL": " [XX]",
            }[status]

            lines.append(
                f"  {r.concurrency_level:>6} | {r.throughput_qps:>8.1f} | "
                f"{r.avg_latency_ms:>8.1f} | {r.p95_latency_ms:>8.1f} | "
                f"{r.p99_latency_ms:>8.1f} | {r.success_rate:>7.1%} | {marker}"
            )

        lines.append("")
        lines.append(f"  Max safe concurrency: {self.max_safe_concurrency}")
        if self.breaking_point:
            lines.append(f"  Breaking point: {self.breaking_point} concurrent queries")
        lines.append("")

        if self.recommendations:
            lines.append("  Recommendations:")
            for rec in self.recommendations:
                lines.append(f"    * {rec}")
            lines.append("")

        return "\n".join(lines)


class ConcurrencyTester:
    """
    Benchmark database performance under concurrent load.

    Supports two modes:
    1. Live mode: Actually runs queries against a database (requires asyncpg)
    2. Simulation mode: Models concurrency using queueing theory (no DB needed)
    """

    def __init__(self, dsn: str = ""):
        self.dsn = dsn

    # ── Live mode (requires asyncpg) ─────────────────────────────────

    async def test_workload(
        self,
        queries: list[str],
        concurrency_levels: list[int] | None = None,
        duration_seconds: int = 30,
    ) -> BenchmarkReport:
        """
        Run queries at increasing concurrency against a real database.

        Requires: asyncpg (pip install asyncpg)
        """
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "asyncpg is required for live benchmarking. "
                "Install it with: pip install asyncpg"
            )

        if not self.dsn:
            raise ValueError("DSN is required for live benchmarking")

        levels = concurrency_levels or [1, 5, 10, 20, 50]
        results: list[ConcurrencyResult] = []

        for level in levels:
            result = await self._run_level(queries, level, duration_seconds)
            results.append(result)

            # Stop early if failure rate is too high
            if result.success_rate < 0.90:
                break

        return self._build_report(results, len(queries), duration_seconds)

    async def _run_level(
        self,
        queries: list[str],
        concurrency: int,
        duration: int,
    ) -> ConcurrencyResult:
        """Run a single concurrency level test."""
        import asyncpg  # type: ignore[import-untyped]

        all_latencies: list[float] = []
        all_failures: list[dict[str, Any]] = []

        async def worker(worker_id: int) -> tuple[list[float], list[dict[str, Any]]]:
            latencies: list[float] = []
            failures: list[dict[str, Any]] = []

            conn = await asyncpg.connect(self.dsn)
            try:
                start_time = time.monotonic()
                while time.monotonic() - start_time < duration:
                    for query in queries:
                        try:
                            q_start = time.monotonic()
                            await conn.execute(query)
                            latency = (time.monotonic() - q_start) * 1000
                            latencies.append(latency)
                        except Exception as e:
                            failures.append({
                                "worker": worker_id,
                                "query": query[:100],
                                "error": str(e),
                                "timestamp": time.time(),
                            })
            finally:
                await conn.close()

            return latencies, failures

        tasks = [worker(i) for i in range(concurrency)]
        worker_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in worker_results:
            if isinstance(r, Exception):
                all_failures.append({"error": str(r), "type": "worker_crash"})
                continue
            lats, fails = r
            all_latencies.extend(lats)
            all_failures.extend(fails)

        return self._compile_result(concurrency, all_latencies, all_failures, duration)

    # ── Simulation mode (no DB required) ─────────────────────────────

    def simulate_workload(
        self,
        queries: list[str] | None = None,
        concurrency_levels: list[int] | None = None,
        base_latency_ms: float = 5.0,
        max_connections: int = 100,
        duration_seconds: int = 30,
    ) -> BenchmarkReport:
        """
        Simulate concurrency behavior using M/M/c queueing theory.

        Models:
        - Latency increases as sqrt(concurrency) due to contention
        - Connection pool exhaustion at max_connections
        - Lock contention adds exponential tail latency
        - Failure rate increases past 80% capacity

        Args:
            queries: List of SQL queries (used for count, not executed)
            concurrency_levels: Concurrency levels to test
            base_latency_ms: Baseline latency at concurrency=1
            max_connections: Simulated max_connections limit
            duration_seconds: Simulated test duration
        """
        levels = concurrency_levels or [1, 5, 10, 20, 50, 100]
        query_count = len(queries) if queries else 3
        results: list[ConcurrencyResult] = []

        for level in levels:
            result = self._simulate_level(
                level, base_latency_ms, max_connections, query_count, duration_seconds
            )
            results.append(result)

            if result.success_rate < 0.90:
                break

        return self._build_report(results, query_count, duration_seconds)

    def _simulate_level(
        self,
        concurrency: int,
        base_latency_ms: float,
        max_connections: int,
        query_count: int,
        duration: int,
    ) -> ConcurrencyResult:
        """Simulate results for a single concurrency level."""
        # Contention factor: latency grows with sqrt(concurrency)
        contention = math.sqrt(concurrency)

        # Utilization ratio
        utilization = concurrency / max_connections

        # Average latency model: base * sqrt(C) * (1 + utilization^2)
        avg_latency = base_latency_ms * contention * (1 + utilization ** 2)

        # Tail latency model
        p50_latency = avg_latency * 0.85
        p95_latency = avg_latency * 2.5 * (1 + utilization)
        p99_latency = avg_latency * 5.0 * (1 + utilization ** 2)

        # Throughput model (Amdahl's law approximation)
        serial_fraction = 0.05  # 5% of work is serial (locks, etc.)
        speedup = 1 / (serial_fraction + (1 - serial_fraction) / concurrency)
        base_qps = 1000 / base_latency_ms
        throughput = base_qps * speedup * (1 - max(0, utilization - 0.8) * 2)
        throughput = max(0, throughput)

        # Failure model
        if utilization > 1.0:
            failure_rate = 0.5 + 0.5 * (utilization - 1.0)
        elif utilization > 0.8:
            failure_rate = 0.01 * ((utilization - 0.8) / 0.2) ** 2
        else:
            failure_rate = 0.0

        total_queries = int(throughput * duration * query_count)
        success_count = int(total_queries * (1 - failure_rate))
        failure_count = total_queries - success_count

        failures: list[dict[str, Any]] = []
        if utilization > 1.0:
            failures.append({
                "type": "connection_pool_exhaustion",
                "error": "too many clients already",
                "count": failure_count,
            })
        elif utilization > 0.9:
            failures.append({
                "type": "timeout",
                "error": "query timeout after 30s",
                "count": failure_count,
            })

        return ConcurrencyResult(
            concurrency_level=concurrency,
            total_queries=total_queries,
            success_count=success_count,
            failure_count=failure_count,
            success_rate=1 - failure_rate,
            avg_latency_ms=avg_latency,
            p50_latency_ms=p50_latency,
            p95_latency_ms=p95_latency,
            p99_latency_ms=p99_latency,
            min_latency_ms=base_latency_ms,
            max_latency_ms=p99_latency * 1.5,
            throughput_qps=throughput,
            failures=failures,
            failing_queries=[],
        )

    # ── Shared analysis ──────────────────────────────────────────────

    def _compile_result(
        self,
        concurrency: int,
        latencies: list[float],
        failures: list[dict[str, Any]],
        duration: int,
    ) -> ConcurrencyResult:
        """Compile latencies and failures into a result."""
        if not latencies:
            return ConcurrencyResult(
                concurrency_level=concurrency,
                total_queries=len(failures),
                failure_count=len(failures),
                success_rate=0.0,
                failures=failures,
                failing_queries=list({f.get("query", "") for f in failures}),
            )

        latencies.sort()
        total = len(latencies) + len(failures)

        return ConcurrencyResult(
            concurrency_level=concurrency,
            total_queries=total,
            success_count=len(latencies),
            failure_count=len(failures),
            success_rate=len(latencies) / total if total else 1.0,
            avg_latency_ms=statistics.mean(latencies),
            p50_latency_ms=latencies[len(latencies) // 2],
            p95_latency_ms=latencies[int(len(latencies) * 0.95)],
            p99_latency_ms=latencies[int(len(latencies) * 0.99)],
            min_latency_ms=latencies[0],
            max_latency_ms=latencies[-1],
            throughput_qps=len(latencies) / duration if duration else 0,
            failures=failures,
            failing_queries=list({f.get("query", "") for f in failures}),
        )

    def _build_report(
        self,
        results: list[ConcurrencyResult],
        query_count: int,
        duration: int,
    ) -> BenchmarkReport:
        """Build the final benchmark report with recommendations."""
        max_safe = 0
        breaking_point = 0

        for i, r in enumerate(results):
            if r.success_rate >= 0.99:
                max_safe = r.concurrency_level
            elif not breaking_point:
                breaking_point = r.concurrency_level

        recommendations = self._generate_recommendations(results)

        return BenchmarkReport(
            results=results,
            max_safe_concurrency=max_safe,
            breaking_point=breaking_point,
            recommendations=recommendations,
            query_count=query_count,
            duration_seconds=duration,
        )

    def _generate_recommendations(self, results: list[ConcurrencyResult]) -> list[str]:
        """Generate specific fix recommendations based on failure patterns."""
        recs: list[str] = []

        all_failures = [f for r in results for f in r.failures]

        # Connection pool exhaustion
        if any("too many clients" in str(f) for f in all_failures):
            recs.append(
                "Connection pool exhausted. Use PgBouncer or increase "
                "max_connections: ALTER SYSTEM SET max_connections = 200;"
            )

        # Timeout failures
        if any("timeout" in str(f) for f in all_failures):
            recs.append(
                "Query timeouts detected. Review slow queries with: "
                "querysense analyze plan.json"
            )

        # Memory issues
        if any("out of memory" in str(f).lower() for f in all_failures):
            recs.append(
                "OOM under load. Reduce work_mem or add more RAM: "
                "ALTER SYSTEM SET work_mem = '64MB';"
            )

        # Deadlocks
        if any("deadlock" in str(f).lower() for f in all_failures):
            recs.append(
                "Deadlocks detected. Review transaction order or use "
                "advisory locks: SELECT pg_advisory_lock(...);"
            )

        # Latency degradation
        if len(results) >= 2:
            first = results[0]
            last = results[-1]
            if last.avg_latency_ms > first.avg_latency_ms * 10:
                recs.append(
                    f"Latency increased {last.avg_latency_ms / first.avg_latency_ms:.0f}x "
                    f"from {first.concurrency_level} to {last.concurrency_level} concurrent "
                    f"queries. Likely lock contention — check pg_stat_activity for waits."
                )

        # P99 tail latency
        for r in results:
            if r.p99_latency_ms > r.avg_latency_ms * 20:
                recs.append(
                    f"Extreme tail latency at concurrency {r.concurrency_level}: "
                    f"P99={r.p99_latency_ms:.0f}ms vs avg={r.avg_latency_ms:.0f}ms. "
                    f"Check for table-level locks or autovacuum running."
                )
                break

        if not recs and results:
            max_c = results[-1].concurrency_level
            recs.append(
                f"Database handles {max_c} concurrent queries well. "
                f"Consider testing higher levels."
            )

        return recs
