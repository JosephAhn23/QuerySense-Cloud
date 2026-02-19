#!/usr/bin/env python3
"""
QuerySense Automated Health Check Script

Standalone script that runs a comprehensive PostgreSQL health check
using QuerySense monitoring queries.  Designed for cron, CI pipelines,
or manual invocation.

Usage:
    # Basic check (prints report to stdout)
    python scripts/health_check.py --dsn postgresql://user:pass@localhost/mydb

    # CI mode (exit code 1 if critical issues found)
    python scripts/health_check.py --dsn $DATABASE_URL --fail-on-critical

    # JSON output for automation
    python scripts/health_check.py --dsn $DATABASE_URL --format json

    # With specific checks only
    python scripts/health_check.py --dsn $DATABASE_URL --checks queries,vacuum,locks

Environment variables:
    DATABASE_URL  — Default connection string if --dsn not provided
    PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE — Standard libpq vars
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


@dataclass
class CheckResult:
    """Result of a single health check."""
    name: str
    status: str  # "ok", "warning", "critical", "error"
    message: str
    details: list = field(default_factory=list)
    row_count: int = 0


@dataclass
class HealthReport:
    """Complete health check report."""
    timestamp: str
    dsn_host: str
    checks: list = field(default_factory=list)
    overall_status: str = "ok"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "host": self.dsn_host,
            "overall_status": self.overall_status,
            "checks": [asdict(c) for c in self.checks],
        }


def _safe_dsn_host(dsn):
    """Extract host from DSN without exposing password."""
    if "@" in dsn:
        return dsn.split("@", 1)[1].split("/")[0].split("?")[0]
    return "localhost"


def _run_query(conn, sql):
    """Execute query and return results as list of dicts."""
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        if cursor.description is None:
            return []
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]
    finally:
        cursor.close()


def check_long_queries(conn, threshold_min=5):
    """Check for long-running queries."""
    sql = f"""\
SELECT pid, usename, application_name, state,
       LEFT(query, 200) AS query,
       age(now(), query_start) AS duration
FROM pg_stat_activity
WHERE state = 'active'
  AND (now() - query_start) > interval '{threshold_min} minutes'
  AND pid != pg_backend_pid()
ORDER BY query_start ASC;"""

    rows = _run_query(conn, sql)
    if not rows:
        return CheckResult("long_queries", "ok", "No long-running queries")

    status = "critical" if len(rows) > 5 else "warning"
    return CheckResult(
        "long_queries", status,
        f"{len(rows)} queries running > {threshold_min} min",
        details=rows, row_count=len(rows),
    )


def check_replication_lag(conn, max_lag_mb=100):
    """Check replication lag."""
    sql = """\
SELECT application_name, state, sync_state,
       pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes
FROM pg_stat_replication;"""

    try:
        rows = _run_query(conn, sql)
    except Exception:
        return CheckResult("replication_lag", "ok", "Not a primary or no replicas")

    if not rows:
        return CheckResult("replication_lag", "ok", "No replicas connected")

    max_lag = max(r.get("lag_bytes", 0) or 0 for r in rows)
    max_lag_actual_mb = max_lag / (1024 * 1024)

    if max_lag_actual_mb > max_lag_mb:
        status = "critical"
    elif max_lag_actual_mb > max_lag_mb / 2:
        status = "warning"
    else:
        status = "ok"

    return CheckResult(
        "replication_lag", status,
        f"Max lag: {max_lag_actual_mb:.1f} MB ({len(rows)} replicas)",
        details=rows, row_count=len(rows),
    )


def check_connections(conn, max_pct=80):
    """Check connection utilisation."""
    sql = """\
SELECT count(*) AS used,
       current_setting('max_connections')::int AS max_conn
FROM pg_stat_activity;"""

    rows = _run_query(conn, sql)
    if not rows:
        return CheckResult("connections", "ok", "Unable to check")

    used = rows[0]["used"]
    max_conn = rows[0]["max_conn"]
    pct = (used / max_conn) * 100

    if pct > max_pct:
        status = "critical"
    elif pct > max_pct * 0.75:
        status = "warning"
    else:
        status = "ok"

    return CheckResult(
        "connections", status,
        f"{used}/{max_conn} connections ({pct:.0f}%)",
        details=rows, row_count=1,
    )


def check_vacuum(conn, dead_pct_threshold=20.0):
    """Check for tables needing vacuum."""
    sql = """\
SELECT schemaname, tablename, n_dead_tup, n_live_tup,
       CASE WHEN n_live_tup > 0
            THEN round(n_dead_tup::numeric / n_live_tup * 100, 2)
            ELSE 0
       END AS dead_pct,
       last_autovacuum
FROM pg_stat_user_tables
WHERE n_dead_tup > 10000
ORDER BY n_dead_tup DESC
LIMIT 20;"""

    rows = _run_query(conn, sql)
    if not rows:
        return CheckResult("vacuum", "ok", "All tables healthy")

    critical_tables = [
        r for r in rows
        if (r.get("dead_pct") or 0) > dead_pct_threshold
    ]

    if critical_tables:
        status = "critical"
        msg = f"{len(critical_tables)} tables have >{dead_pct_threshold}% dead tuples"
    else:
        status = "warning"
        msg = f"{len(rows)} tables have >10k dead tuples"

    serializable = []
    for r in rows:
        clean = {}
        for k, v in r.items():
            if isinstance(v, datetime):
                clean[k] = v.isoformat()
            else:
                clean[k] = v
        serializable.append(clean)

    return CheckResult(
        "vacuum", status, msg,
        details=serializable, row_count=len(rows),
    )


def check_locks(conn):
    """Check for lock contention."""
    sql = """\
SELECT count(*) AS waiting
FROM pg_stat_activity
WHERE wait_event_type = 'Lock'
  AND state = 'active';"""

    rows = _run_query(conn, sql)
    waiting = rows[0]["waiting"] if rows else 0

    if waiting > 10:
        status = "critical"
    elif waiting > 3:
        status = "warning"
    else:
        status = "ok"

    return CheckResult(
        "locks", status,
        f"{waiting} processes waiting on locks",
        row_count=waiting,
    )


def check_cache_hit_ratio(conn, min_ratio=0.95):
    """Check buffer cache hit ratio."""
    sql = """\
SELECT
    sum(heap_blks_hit) AS hits,
    sum(heap_blks_read) AS reads
FROM pg_statio_user_tables;"""

    rows = _run_query(conn, sql)
    if not rows or (rows[0]["hits"] or 0) + (rows[0]["reads"] or 0) == 0:
        return CheckResult("cache_hit_ratio", "ok", "No data yet")

    hits = rows[0]["hits"] or 0
    reads = rows[0]["reads"] or 0
    ratio = hits / (hits + reads)

    if ratio < min_ratio:
        status = "warning" if ratio > 0.90 else "critical"
    else:
        status = "ok"

    return CheckResult(
        "cache_hit_ratio", status,
        f"Table cache hit ratio: {ratio:.2%}",
        details=[{"hit_ratio": float(round(ratio, 4))}],
        row_count=1,
    )


def check_disk_space(conn):
    """Check database sizes."""
    sql = """\
SELECT datname,
       pg_database_size(datname) / 1024 / 1024 AS size_mb
FROM pg_database
WHERE datistemplate = false
ORDER BY size_mb DESC;"""

    rows = _run_query(conn, sql)
    if not rows:
        return CheckResult("disk_space", "ok", "No databases")

    total_mb = sum(r["size_mb"] for r in rows)
    return CheckResult(
        "disk_space", "ok",
        f"Total: {total_mb:,.0f} MB across {len(rows)} databases",
        details=rows, row_count=len(rows),
    )


ALL_CHECKS = {
    "queries": check_long_queries,
    "replication": check_replication_lag,
    "connections": check_connections,
    "vacuum": check_vacuum,
    "locks": check_locks,
    "cache": check_cache_hit_ratio,
    "disk": check_disk_space,
}


def run_health_check(dsn, *, checks=None):
    """Run health checks and return a structured report."""
    try:
        import psycopg2
        conn = psycopg2.connect(dsn)
        conn.autocommit = True
    except ImportError:
        try:
            import psycopg
            conn = psycopg.connect(dsn, autocommit=True)
        except ImportError:
            print(
                "ERROR: psycopg2 or psycopg required. "
                "Install with: pip install psycopg2-binary",
                file=sys.stderr,
            )
            sys.exit(2)

    report = HealthReport(
        timestamp=datetime.utcnow().isoformat() + "Z",
        dsn_host=_safe_dsn_host(dsn),
    )

    selected = checks or list(ALL_CHECKS.keys())

    for name in selected:
        check_fn = ALL_CHECKS.get(name)
        if check_fn is None:
            report.checks.append(
                CheckResult(name, "error", f"Unknown check: {name}")
            )
            continue

        try:
            result = check_fn(conn)
        except Exception as e:
            result = CheckResult(name, "error", str(e))

        report.checks.append(result)

    conn.close()

    statuses = [c.status for c in report.checks]
    if "critical" in statuses:
        report.overall_status = "critical"
    elif "warning" in statuses:
        report.overall_status = "warning"
    elif "error" in statuses:
        report.overall_status = "error"
    else:
        report.overall_status = "ok"

    return report


def format_text_report(report):
    """Format health report as human-readable text."""
    lines = [
        "=" * 60,
        "  QuerySense Health Check Report",
        f"  Host: {report.dsn_host}",
        f"  Time: {report.timestamp}",
        "=" * 60,
        "",
    ]

    status_icons = {
        "ok": "[OK]",
        "warning": "[WARN]",
        "critical": "[CRIT]",
        "error": "[ERR]",
    }

    for check in report.checks:
        icon = status_icons.get(check.status, "[??]")
        lines.append(f"  {icon:8s} {check.name:20s} {check.message}")

    lines.append("")
    lines.append(f"  Overall: {report.overall_status.upper()}")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="QuerySense PostgreSQL Health Check",
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get("DATABASE_URL", ""),
        help="PostgreSQL connection string (default: $DATABASE_URL)",
    )
    parser.add_argument(
        "--checks",
        default="",
        help=f"Comma-separated checks to run (default: all). "
        f"Available: {', '.join(ALL_CHECKS.keys())}",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with code 1 if any critical issue found",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Exit with code 1 if any warning or critical found",
    )

    args = parser.parse_args()

    if not args.dsn:
        parser.error(
            "Database connection required. Use --dsn or set DATABASE_URL."
        )

    checks = [c.strip() for c in args.checks.split(",") if c.strip()] or None
    report = run_health_check(args.dsn, checks=checks)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print(format_text_report(report))

    if args.fail_on_critical and report.overall_status == "critical":
        sys.exit(1)
    if args.fail_on_warning and report.overall_status in ("warning", "critical"):
        sys.exit(1)


if __name__ == "__main__":
    main()
