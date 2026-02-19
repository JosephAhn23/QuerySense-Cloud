"""
Consolidated Monitoring Queries

Provides a single-entrypoint module that generates all key PostgreSQL
monitoring queries: top queries, index usage, missing indexes, vacuum
status, lock monitoring, session overview, wait events, and cache hit
ratios.

Each function returns the SQL query string so it can be used with any
database driver (psycopg2, asyncpg, SQLAlchemy, etc.).  When a live
connection is available, helper functions execute and parse the results.

Usage:
    from querysense.monitoring import MonitoringQueries

    mq = MonitoringQueries()

    # Get raw SQL for any monitoring query
    print(mq.top_queries_sql(limit=20))

    # Or execute all and get a structured report
    report = await mq.collect_all(conn)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MonitoringQuery:
    """A named monitoring query with its SQL and description."""
    name: str
    description: str
    sql: str
    category: str = "general"
    requires_extension: str | None = None
    min_pg_version: int = 12


class MonitoringQueries:
    """
    Collection of production monitoring queries for PostgreSQL.

    All queries are read-only and safe to run on production databases.
    They use standard system views and pg_stat_statements.
    """

    @staticmethod
    def top_queries_sql(
        *,
        limit: int = 20,
        sort_by: str = "total_exec_time",
    ) -> MonitoringQuery:
        valid_sorts = {
            "total_exec_time", "mean_exec_time", "calls",
            "shared_blks_read", "rows",
        }
        if sort_by not in valid_sorts:
            sort_by = "total_exec_time"

        return MonitoringQuery(
            name="top_queries",
            description="Top queries by execution time from pg_stat_statements",
            category="queries",
            requires_extension="pg_stat_statements",
            sql=f"""\
SELECT
    queryid,
    LEFT(query, 200) AS query_preview,
    calls,
    round(total_exec_time::numeric, 2) AS total_exec_time_ms,
    round(mean_exec_time::numeric, 2) AS mean_exec_time_ms,
    round(stddev_exec_time::numeric, 2) AS stddev_exec_time_ms,
    rows,
    shared_blks_hit,
    shared_blks_read,
    CASE WHEN shared_blks_hit + shared_blks_read > 0
         THEN round(shared_blks_hit::numeric /
              (shared_blks_hit + shared_blks_read), 4)
         ELSE 1.0
    END AS cache_hit_ratio
FROM pg_stat_statements
WHERE query NOT LIKE '%pg_stat_statements%'
  AND queryid IS NOT NULL
ORDER BY {sort_by} DESC
LIMIT {limit};""",
        )

    @staticmethod
    def index_usage_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="index_usage",
            description="Index usage statistics — low idx_scan indicates unused indexes",
            category="indexes",
            sql="""\
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
ORDER BY idx_scan ASC NULLS FIRST;""",
        )

    @staticmethod
    def missing_indexes_sql(min_seq_scans: int = 1000) -> MonitoringQuery:
        return MonitoringQuery(
            name="missing_indexes",
            description="Tables with high sequential scans and no index usage",
            category="indexes",
            sql=f"""\
SELECT
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    n_live_tup,
    pg_size_pretty(pg_table_size(relid)) AS table_size
FROM pg_stat_user_tables
WHERE seq_scan > {min_seq_scans}
  AND (idx_scan = 0 OR idx_scan IS NULL)
  AND n_live_tup > 1000
ORDER BY seq_scan DESC;""",
        )

    @staticmethod
    def vacuum_status_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="vacuum_status",
            description="Tables needing vacuum — dead tuples and vacuum history",
            category="vacuum",
            sql="""\
SELECT
    schemaname,
    tablename,
    n_dead_tup,
    n_live_tup,
    CASE WHEN n_live_tup > 0
         THEN round(n_dead_tup::numeric / n_live_tup * 100, 2)
         ELSE 0
    END AS dead_pct,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze,
    n_mod_since_analyze
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC;""",
        )

    @staticmethod
    def lock_monitoring_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="lock_monitoring",
            description="Active queries waiting on locks",
            category="locks",
            sql="""\
SELECT
    pid,
    usename,
    application_name,
    state,
    LEFT(query, 200) AS query_preview,
    wait_event_type,
    wait_event,
    age(now(), query_start) AS query_age,
    age(now(), state_change) AS state_age
FROM pg_stat_activity
WHERE wait_event IS NOT NULL
  AND state = 'active'
ORDER BY query_start ASC;""",
        )

    @staticmethod
    def blocking_chains_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="blocking_chains",
            description="Blocking lock chains — who is blocking whom",
            category="locks",
            min_pg_version=14,
            sql="""\
SELECT
    blocked.pid AS blocked_pid,
    blocked.usename AS blocked_user,
    LEFT(blocked.query, 150) AS blocked_query,
    blocking.pid AS blocking_pid,
    blocking.usename AS blocking_user,
    LEFT(blocking.query, 150) AS blocking_query,
    age(now(), blocked.query_start) AS blocked_duration
FROM pg_stat_activity blocked
JOIN pg_locks bl ON bl.pid = blocked.pid AND NOT bl.granted
JOIN pg_locks gl ON gl.locktype = bl.locktype
    AND gl.database IS NOT DISTINCT FROM bl.database
    AND gl.relation IS NOT DISTINCT FROM bl.relation
    AND gl.page IS NOT DISTINCT FROM bl.page
    AND gl.tuple IS NOT DISTINCT FROM bl.tuple
    AND gl.pid != bl.pid
    AND gl.granted
JOIN pg_stat_activity blocking ON blocking.pid = gl.pid
ORDER BY blocked_duration DESC;""",
        )

    @staticmethod
    def session_overview_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="session_overview",
            description="Active session summary by state",
            category="sessions",
            sql="""\
SELECT
    state,
    count(*) AS connection_count,
    round(avg(EXTRACT(EPOCH FROM age(now(), state_change)))::numeric, 2)
        AS avg_state_age_seconds
FROM pg_stat_activity
WHERE pid != pg_backend_pid()
GROUP BY state
ORDER BY connection_count DESC;""",
        )

    @staticmethod
    def wait_events_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="wait_events",
            description="Wait event distribution across active processes",
            category="sessions",
            sql="""\
SELECT
    wait_event_type,
    wait_event,
    count(*) AS waiting_processes
FROM pg_stat_activity
WHERE wait_event_type IS NOT NULL
  AND pid != pg_backend_pid()
GROUP BY wait_event_type, wait_event
ORDER BY count(*) DESC;""",
        )

    @staticmethod
    def cache_hit_ratio_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="cache_hit_ratio",
            description="Buffer cache hit ratio for indexes and tables",
            category="performance",
            sql="""\
SELECT 'index hit' AS type,
       CASE WHEN sum(idx_blks_hit) + sum(idx_blks_read) > 0
            THEN round(sum(idx_blks_hit)::numeric /
                 (sum(idx_blks_hit) + sum(idx_blks_read)), 4)
            ELSE 1.0
       END AS hit_ratio
FROM pg_statio_user_indexes
UNION ALL
SELECT 'table hit' AS type,
       CASE WHEN sum(heap_blks_hit) + sum(heap_blks_read) > 0
            THEN round(sum(heap_blks_hit)::numeric /
                 (sum(heap_blks_hit) + sum(heap_blks_read)), 4)
            ELSE 1.0
       END AS hit_ratio
FROM pg_statio_user_tables;""",
        )

    @staticmethod
    def replication_lag_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="replication_lag",
            description="Replication lag for streaming replicas",
            category="replication",
            sql="""\
SELECT
    application_name,
    client_addr,
    state,
    sync_state,
    pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn))
        AS lag_pretty,
    pg_wal_lsn_diff(pg_current_wal_lsn(), sent_lsn) AS send_lag_bytes,
    pg_wal_lsn_diff(sent_lsn, flush_lsn) AS flush_lag_bytes,
    pg_wal_lsn_diff(flush_lsn, replay_lsn) AS replay_lag_bytes
FROM pg_stat_replication;""",
        )

    @staticmethod
    def long_running_queries_sql(
        threshold_minutes: int = 5,
    ) -> MonitoringQuery:
        return MonitoringQuery(
            name="long_running_queries",
            description=f"Queries running longer than {threshold_minutes} minutes",
            category="queries",
            sql=f"""\
SELECT
    pid,
    usename,
    application_name,
    state,
    LEFT(query, 200) AS query_preview,
    age(now(), query_start) AS duration,
    wait_event_type,
    wait_event
FROM pg_stat_activity
WHERE state = 'active'
  AND (now() - query_start) > interval '{threshold_minutes} minutes'
  AND pid != pg_backend_pid()
ORDER BY query_start ASC;""",
        )

    @staticmethod
    def database_sizes_sql() -> MonitoringQuery:
        return MonitoringQuery(
            name="database_sizes",
            description="Database sizes and connection counts",
            category="general",
            sql="""\
SELECT
    d.datname AS database_name,
    pg_size_pretty(pg_database_size(d.datname)) AS size,
    pg_database_size(d.datname) AS size_bytes,
    s.numbackends AS active_connections,
    s.xact_commit AS commits,
    s.xact_rollback AS rollbacks,
    CASE WHEN s.xact_commit + s.xact_rollback > 0
         THEN round(s.xact_rollback::numeric /
              (s.xact_commit + s.xact_rollback) * 100, 2)
         ELSE 0
    END AS rollback_pct
FROM pg_database d
LEFT JOIN pg_stat_database s ON d.datname = s.datname
WHERE d.datistemplate = false
ORDER BY pg_database_size(d.datname) DESC;""",
        )

    def all_queries(self) -> list[MonitoringQuery]:
        """Return all monitoring queries as a list."""
        return [
            self.top_queries_sql(),
            self.index_usage_sql(),
            self.missing_indexes_sql(),
            self.vacuum_status_sql(),
            self.lock_monitoring_sql(),
            self.blocking_chains_sql(),
            self.session_overview_sql(),
            self.wait_events_sql(),
            self.cache_hit_ratio_sql(),
            self.replication_lag_sql(),
            self.long_running_queries_sql(),
            self.database_sizes_sql(),
        ]

    def queries_by_category(self) -> dict[str, list[MonitoringQuery]]:
        """Group all monitoring queries by category."""
        result: dict[str, list[MonitoringQuery]] = {}
        for q in self.all_queries():
            result.setdefault(q.category, []).append(q)
        return result

    def format_all_sql(self) -> str:
        """Format all queries into a single runnable SQL script."""
        lines = [
            "-- " + "=" * 68,
            "-- QuerySense: PostgreSQL Monitoring Queries",
            "-- Run these against your production database for a full health check",
            "-- " + "=" * 68,
            "",
        ]

        for category, queries in self.queries_by_category().items():
            lines.append(f"-- {'=' * 30} {category.upper()} {'=' * 30}")
            lines.append("")
            for q in queries:
                lines.append(f"-- [{q.name}] {q.description}")
                if q.requires_extension:
                    lines.append(f"-- Requires: {q.requires_extension}")
                lines.append(q.sql)
                lines.append("")

        return "\n".join(lines)
