"""
Performance Advisor Checks — Runtime performance health.

Checks that require looking at live database activity:
    1. Cache hit ratio (should be >99%)
    2. Index usage ratio (index vs sequential scans)
    3. Lock contention detection
    4. Temp file usage (sorts spilling to disk)
    5. Table scan detection on large tables
    6. Long-running queries

These checks run on the FREQUENT interval since they reflect
current workload conditions.
"""

from __future__ import annotations

from querysense.advisor.base import (
    AdvisorCategory,
    AdvisorCheck,
    AsyncDBConnection,
    CheckInterval,
    CheckResult,
    CheckSeverity,
    Finding,
)


class CacheHitRatioCheck(AdvisorCheck):
    """Check buffer cache hit ratio."""

    name = "postgres_cache_hit_ratio"
    title = "Buffer Cache Hit Ratio"
    description = "Verify cache hit ratio is above 99%"
    category = AdvisorCategory.PERFORMANCE
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT "
                "  sum(heap_blks_read) AS heap_read, "
                "  sum(heap_blks_hit) AS heap_hit, "
                "  sum(idx_blks_read) AS idx_read, "
                "  sum(idx_blks_hit) AS idx_hit "
                "FROM pg_statio_user_tables"
            )
        except Exception:
            return result

        if rows:
            r = rows[0]
            if isinstance(r, (list, tuple)):
                heap_read, heap_hit, idx_read, idx_hit = r[:4]
            else:
                heap_read = getattr(r, "heap_read", 0)
                heap_hit = getattr(r, "heap_hit", 0)
                idx_read = getattr(r, "idx_read", 0)
                idx_hit = getattr(r, "idx_hit", 0)

            total_read = int(heap_read or 0) + int(idx_read or 0)
            total_hit = int(heap_hit or 0) + int(idx_hit or 0)
            total = total_read + total_hit

            if total > 0:
                ratio = total_hit / total
                if ratio < 0.95:
                    sev = CheckSeverity.CRITICAL if ratio < 0.90 else CheckSeverity.WARNING
                    result.findings.append(Finding(
                        severity=sev,
                        title=f"Cache hit ratio is {ratio:.1%} (target: >99%)",
                        description=(
                            f"Buffer cache is serving only {ratio:.1%} of requests from memory. "
                            f"Disk reads: {total_read:,}. Cache hits: {total_hit:,}."
                        ),
                        recommendation="Increase shared_buffers or reduce working set size.",
                        fix_sql="ALTER SYSTEM SET shared_buffers = '4GB';\n-- Adjust based on RAM",
                        evidence={"hit_ratio": round(ratio, 4), "disk_reads": total_read, "cache_hits": total_hit},
                        tags=["cache", "memory", "performance"],
                    ))
                    result.passed = False

        return result


class IndexUsageRatioCheck(AdvisorCheck):
    """Check overall index vs sequential scan ratio."""

    name = "postgres_index_usage_ratio"
    title = "Index Usage Ratio"
    description = "Verify indexes are being used effectively"
    category = AdvisorCategory.PERFORMANCE
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT "
                "  sum(seq_scan) AS seq_scans, "
                "  sum(idx_scan) AS idx_scans, "
                "  sum(seq_tup_read) AS seq_tuples, "
                "  sum(idx_tup_fetch) AS idx_tuples "
                "FROM pg_stat_user_tables"
            )
        except Exception:
            return result

        if rows:
            r = rows[0]
            if isinstance(r, (list, tuple)):
                seq_scans, idx_scans, seq_tuples, idx_tuples = r[:4]
            else:
                seq_scans = getattr(r, "seq_scans", 0)
                idx_scans = getattr(r, "idx_scans", 0)
                seq_tuples = getattr(r, "seq_tuples", 0)
                idx_tuples = getattr(r, "idx_tuples", 0)

            total_scans = int(seq_scans or 0) + int(idx_scans or 0)
            if total_scans > 100:
                idx_ratio = int(idx_scans or 0) / total_scans
                if idx_ratio < 0.80:
                    result.findings.append(Finding(
                        severity=CheckSeverity.WARNING,
                        title=f"Low index usage: {idx_ratio:.0%} of scans use indexes",
                        description=(
                            f"Sequential scans: {int(seq_scans or 0):,}. "
                            f"Index scans: {int(idx_scans or 0):,}. "
                            "High sequential scan ratio suggests missing indexes."
                        ),
                        recommendation="Run `querysense index check` to identify missing indexes.",
                        evidence={"idx_scan_ratio": round(idx_ratio, 3)},
                        tags=["indexes", "sequential-scans"],
                    ))
                    result.passed = False

        return result


class TempFileUsageCheck(AdvisorCheck):
    """Check for queries spilling to temporary files."""

    name = "postgres_temp_file_usage"
    title = "Temporary File Usage"
    description = "Detect sorts and hashes spilling to disk"
    category = AdvisorCategory.PERFORMANCE
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT datname, temp_files, temp_bytes, "
                "  pg_size_pretty(temp_bytes) AS temp_size "
                "FROM pg_stat_database "
                "WHERE datname = current_database() AND temp_bytes > 0"
            )
        except Exception:
            return result

        for r in rows:
            if isinstance(r, (list, tuple)):
                db, files, bytes_val, size_pretty = r[:4]
            else:
                db = getattr(r, "datname", "")
                files = getattr(r, "temp_files", 0)
                bytes_val = getattr(r, "temp_bytes", 0)
                size_pretty = getattr(r, "temp_size", "")

            files_i = int(files or 0)
            bytes_i = int(bytes_val or 0)

            if bytes_i > 1024 * 1024 * 1024:  # > 1GB
                sev = CheckSeverity.WARNING
            elif files_i > 1000:
                sev = CheckSeverity.NOTICE
            else:
                continue

            result.findings.append(Finding(
                severity=sev,
                title=f"Database '{db}': {files_i:,} temp files ({size_pretty} total)",
                description="Sorts and hash operations are spilling to disk, causing slow queries.",
                recommendation="Increase work_mem to reduce disk spills.",
                fix_sql="ALTER SYSTEM SET work_mem = '64MB';",
                evidence={"temp_files": files_i, "temp_bytes": bytes_i},
                tags=["temp-files", "work_mem", "performance"],
            ))
            result.passed = False

        return result


class LockContentionCheck(AdvisorCheck):
    """Detect current lock contention."""

    name = "postgres_lock_contention"
    title = "Lock Contention Detection"
    description = "Find blocked queries waiting on locks"
    category = AdvisorCategory.PERFORMANCE
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT blocked.pid AS blocked_pid, "
                "  blocked.query AS blocked_query, "
                "  blocking.pid AS blocking_pid, "
                "  blocking.query AS blocking_query, "
                "  EXTRACT(EPOCH FROM (now() - blocked.query_start))::int AS wait_seconds "
                "FROM pg_stat_activity blocked "
                "JOIN pg_locks bl ON bl.pid = blocked.pid AND NOT bl.granted "
                "JOIN pg_locks gl ON gl.locktype = bl.locktype "
                "  AND gl.database IS NOT DISTINCT FROM bl.database "
                "  AND gl.relation IS NOT DISTINCT FROM bl.relation "
                "  AND gl.page IS NOT DISTINCT FROM bl.page "
                "  AND gl.tuple IS NOT DISTINCT FROM bl.tuple "
                "  AND gl.pid != bl.pid AND gl.granted "
                "JOIN pg_stat_activity blocking ON blocking.pid = gl.pid "
                "WHERE EXTRACT(EPOCH FROM (now() - blocked.query_start)) > 5 "
                "ORDER BY wait_seconds DESC LIMIT 5"
            )
        except Exception:
            return result

        for r in rows:
            if isinstance(r, (list, tuple)):
                b_pid, b_query, g_pid, g_query, wait = r[:5]
            else:
                b_pid = getattr(r, "blocked_pid", 0)
                b_query = getattr(r, "blocked_query", "")
                g_pid = getattr(r, "blocking_pid", 0)
                g_query = getattr(r, "blocking_query", "")
                wait = getattr(r, "wait_seconds", 0)

            wait_s = int(wait or 0)
            sev = CheckSeverity.CRITICAL if wait_s > 60 else CheckSeverity.WARNING

            result.findings.append(Finding(
                severity=sev,
                title=f"PID {b_pid} blocked for {wait_s}s by PID {g_pid}",
                description=(
                    f"Blocked query: {str(b_query)[:100]}...\n"
                    f"Blocking query: {str(g_query)[:100]}..."
                ),
                recommendation=f"Consider terminating blocker: SELECT pg_terminate_backend({g_pid});",
                evidence={
                    "blocked_pid": int(b_pid or 0),
                    "blocking_pid": int(g_pid or 0),
                    "wait_seconds": wait_s,
                },
                tags=["locks", "contention", "blocking"],
            ))
            result.passed = False

        return result


class LargeTableSeqScanCheck(AdvisorCheck):
    """Find large tables with excessive sequential scans."""

    name = "postgres_large_table_seq_scans"
    title = "Large Table Sequential Scans"
    description = "Detect large tables being sequentially scanned"
    category = AdvisorCategory.PERFORMANCE
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT relname, seq_scan, seq_tup_read, idx_scan, "
                "  n_live_tup, pg_size_pretty(pg_relation_size(relid)) AS size, "
                "  pg_relation_size(relid) AS size_bytes "
                "FROM pg_stat_user_tables "
                "WHERE seq_scan > 100 "
                "  AND pg_relation_size(relid) > 100 * 1024 * 1024 "  # > 100MB
                "  AND (idx_scan = 0 OR seq_scan > idx_scan * 5) "
                "ORDER BY seq_tup_read DESC LIMIT 5"
            )
        except Exception:
            return result

        for r in rows:
            if isinstance(r, (list, tuple)):
                table, seq, seq_tup, idx, live, size, size_b = r[:7]
            else:
                table = getattr(r, "relname", "")
                seq = getattr(r, "seq_scan", 0)
                seq_tup = getattr(r, "seq_tup_read", 0)
                idx = getattr(r, "idx_scan", 0)
                live = getattr(r, "n_live_tup", 0)
                size = getattr(r, "size", "")
                size_b = getattr(r, "size_bytes", 0)

            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"'{table}' ({size}): {int(seq or 0):,} seq scans vs {int(idx or 0):,} idx scans",
                description=(
                    f"Large table '{table}' with {int(live or 0):,} rows is being "
                    f"sequentially scanned {int(seq or 0):,} times. "
                    f"Total tuples read by seq scan: {int(seq_tup or 0):,}."
                ),
                recommendation=f"Run `querysense index check` to identify missing indexes for '{table}'.",
                evidence={
                    "seq_scans": int(seq or 0),
                    "idx_scans": int(idx or 0),
                    "size_bytes": int(size_b or 0),
                },
                tags=["sequential-scans", "missing-indexes", "performance"],
            ))
            result.passed = False

        return result


class LongRunningQueriesCheck(AdvisorCheck):
    """Detect currently long-running queries."""

    name = "postgres_long_running_queries"
    title = "Long-Running Queries"
    description = "Find queries running for extended periods"
    category = AdvisorCategory.PERFORMANCE
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT pid, usename, state, "
                "  EXTRACT(EPOCH FROM (now() - query_start))::int AS runtime_seconds, "
                "  left(query, 200) AS query_text "
                "FROM pg_stat_activity "
                "WHERE state = 'active' "
                "  AND query NOT LIKE '%pg_stat_activity%' "
                "  AND backend_type = 'client backend' "
                "  AND EXTRACT(EPOCH FROM (now() - query_start)) > 300 "
                "ORDER BY query_start LIMIT 5"
            )
        except Exception:
            return result

        for r in rows:
            if isinstance(r, (list, tuple)):
                pid, user, state, runtime, query = r[:5]
            else:
                pid = getattr(r, "pid", 0)
                user = getattr(r, "usename", "")
                state = getattr(r, "state", "")
                runtime = getattr(r, "runtime_seconds", 0)
                query = getattr(r, "query_text", "")

            rt = int(runtime or 0)
            sev = CheckSeverity.CRITICAL if rt > 3600 else CheckSeverity.WARNING

            result.findings.append(Finding(
                severity=sev,
                title=f"Query running for {rt // 60}m by user '{user}' (PID {pid})",
                description=f"Query: {str(query)[:150]}...",
                recommendation=f"Investigate or terminate: SELECT pg_terminate_backend({pid});",
                evidence={"pid": int(pid or 0), "runtime_seconds": rt, "user": str(user)},
                tags=["long-running", "queries"],
            ))
            result.passed = False

        return result


def get_performance_checks() -> list[AdvisorCheck]:
    """Return all performance advisor checks."""
    return [
        CacheHitRatioCheck(),
        IndexUsageRatioCheck(),
        TempFileUsageCheck(),
        LockContentionCheck(),
        LargeTableSeqScanCheck(),
        LongRunningQueriesCheck(),
    ]
