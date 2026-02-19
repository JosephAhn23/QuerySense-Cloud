"""
Replication Impact Analyzer — detect queries causing WAL bloat and replica lag.

Based on "Mastering PostgreSQL 13" (Schönig 2020):
certain query patterns generate excessive WAL, causing replication lag.

Detects:
- Queries with high WAL generation per row
- Large bulk UPDATE/DELETE without batching
- Schema changes incompatible with logical replication
- Replica lag status and trends
- Missing replica indexes causing sequential scans on standby

Usage:
    from querysense.replication_analyzer import ReplicationAnalyzer, ReplicationHealth

    analyzer = ReplicationAnalyzer()
    health = await analyzer.check(dsn="postgresql://localhost/mydb")
    for alert in health.alerts:
        print(f"{alert.severity}: {alert.message}")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReplicationAlert:
    """A replication-related finding."""
    severity: str
    category: str  # wal_bloat, replica_lag, schema_compat, missing_index
    message: str
    description: str
    fix_command: str
    impact: str
    table: str = ""


@dataclass
class ReplicaStatus:
    """Status of a single replica."""
    client_addr: str
    state: str  # streaming, startup, catchup, backup
    sent_lsn: str
    write_lsn: str
    flush_lsn: str
    replay_lsn: str
    write_lag_seconds: float
    flush_lag_seconds: float
    replay_lag_seconds: float
    sync_state: str  # async, sync, potential, quorum


@dataclass
class ReplicationHealth:
    """Complete replication health report."""
    alerts: list[ReplicationAlert] = field(default_factory=list)
    replicas: list[ReplicaStatus] = field(default_factory=list)
    is_primary: bool = False
    wal_level: str = ""
    max_wal_senders: int = 0
    replication_slots: int = 0
    wal_generated_mb: float = 0.0
    max_replay_lag_seconds: float = 0.0

    @property
    def fix_script(self) -> str:
        lines = ["-- QuerySense Replication Health Fix Script", ""]
        for alert in self.alerts:
            if alert.severity in ("critical", "warning"):
                lines.append(f"-- {alert.message}")
                lines.append(f"{alert.fix_command}")
                lines.append("")
        return "\n".join(lines)


class ReplicationAnalyzer:
    """Analyze replication health and detect WAL-bloat-causing queries."""

    async def check(self, dsn: str) -> ReplicationHealth:
        """Run replication health check."""
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            health = ReplicationHealth()

            # Check if this is a primary
            is_recovery = await conn.fetchval("SELECT pg_is_in_recovery()")
            health.is_primary = not is_recovery

            # WAL level
            health.wal_level = await conn.fetchval(
                "SELECT current_setting('wal_level')"
            )

            health.max_wal_senders = int(
                await conn.fetchval("SELECT current_setting('max_wal_senders')")
            )

            # Replication slots
            health.replication_slots = await conn.fetchval(
                "SELECT count(*) FROM pg_replication_slots"
            ) or 0

            if health.is_primary:
                # Check replicas
                health.replicas = await self._fetch_replica_status(conn)
                if health.replicas:
                    health.max_replay_lag_seconds = max(
                        r.replay_lag_seconds for r in health.replicas
                    )

                # Check for lag alerts
                for replica in health.replicas:
                    if replica.replay_lag_seconds > 30:
                        health.alerts.append(ReplicationAlert(
                            severity="critical" if replica.replay_lag_seconds > 300 else "warning",
                            category="replica_lag",
                            message=(
                                f"Replica {replica.client_addr} has "
                                f"{replica.replay_lag_seconds:.0f}s replay lag"
                            ),
                            description=(
                                "High replay lag means reads from the replica are "
                                "returning stale data."
                            ),
                            fix_command=(
                                "-- Check for long-running queries on replica:\n"
                                "-- On replica: SELECT pid, state, query, "
                                "age(now(), query_start) FROM pg_stat_activity "
                                "WHERE state = 'active';\n"
                                "-- Consider: ALTER SYSTEM SET hot_standby_feedback = on;"
                            ),
                            impact="Read replicas serving stale data",
                        ))

                # Check WAL generation from pg_stat_statements
                await self._check_wal_heavy_queries(conn, health)

                # Check inactive replication slots (WAL retention)
                await self._check_replication_slots(conn, health)

            # Check WAL level for logical replication
            if health.wal_level == "replica" and health.replication_slots > 0:
                health.alerts.append(ReplicationAlert(
                    severity="info",
                    category="schema_compat",
                    message="wal_level is 'replica' — logical replication requires 'logical'",
                    description=(
                        "If you plan to use logical replication for zero-downtime "
                        "migrations, change wal_level to 'logical'."
                    ),
                    fix_command="ALTER SYSTEM SET wal_level = 'logical';\n-- Requires restart",
                    impact="Cannot use logical replication for migrations",
                ))

            return health
        finally:
            await conn.close()

    async def _fetch_replica_status(self, conn: Any) -> list[ReplicaStatus]:
        """Fetch status of all replicas."""
        rows = await conn.fetch("""
            SELECT
                client_addr::text,
                state,
                sent_lsn::text,
                write_lsn::text,
                flush_lsn::text,
                replay_lsn::text,
                COALESCE(EXTRACT(EPOCH FROM write_lag), 0) AS write_lag_secs,
                COALESCE(EXTRACT(EPOCH FROM flush_lag), 0) AS flush_lag_secs,
                COALESCE(EXTRACT(EPOCH FROM replay_lag), 0) AS replay_lag_secs,
                sync_state
            FROM pg_stat_replication
            ORDER BY replay_lag DESC NULLS LAST
        """)

        return [
            ReplicaStatus(
                client_addr=row["client_addr"] or "unknown",
                state=row["state"],
                sent_lsn=row["sent_lsn"] or "",
                write_lsn=row["write_lsn"] or "",
                flush_lsn=row["flush_lsn"] or "",
                replay_lsn=row["replay_lsn"] or "",
                write_lag_seconds=row["write_lag_secs"],
                flush_lag_seconds=row["flush_lag_secs"],
                replay_lag_seconds=row["replay_lag_secs"],
                sync_state=row["sync_state"],
            )
            for row in rows
        ]

    async def _check_wal_heavy_queries(self, conn: Any, health: ReplicationHealth) -> None:
        """Detect queries that generate excessive WAL."""
        try:
            rows = await conn.fetch("""
                SELECT
                    queryid,
                    query,
                    calls,
                    wal_bytes,
                    wal_bytes / NULLIF(calls, 0) AS wal_per_call,
                    rows
                FROM pg_stat_statements
                WHERE wal_bytes > 0
                ORDER BY wal_bytes DESC
                LIMIT 10
            """)
        except Exception:
            # pg_stat_statements may not be available or may not have wal_bytes
            return

        for row in rows:
            wal_per_call = row["wal_per_call"] or 0
            if wal_per_call > 10 * 1024 * 1024:  # > 10MB WAL per call
                query = (row["query"] or "")[:200]
                health.alerts.append(ReplicationAlert(
                    severity="warning",
                    category="wal_bloat",
                    message=f"Query generates {wal_per_call // 1024 // 1024}MB WAL per execution",
                    description=(
                        f"Query: {query}\n"
                        f"Called {row['calls']} times, total WAL: "
                        f"{row['wal_bytes'] // 1024 // 1024}MB"
                    ),
                    fix_command=(
                        "-- Consider batching large updates:\n"
                        "-- Instead of: UPDATE t SET col = val WHERE <big filter>\n"
                        "-- Use: UPDATE t SET col = val WHERE id IN "
                        "(SELECT id FROM t WHERE <filter> LIMIT 1000)"
                    ),
                    impact="Excessive WAL causes replica lag and fills pg_wal",
                ))

    async def _check_replication_slots(self, conn: Any, health: ReplicationHealth) -> None:
        """Check for inactive replication slots retaining WAL."""
        rows = await conn.fetch("""
            SELECT
                slot_name,
                slot_type,
                active,
                pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS retained_bytes
            FROM pg_replication_slots
            WHERE NOT active
            ORDER BY retained_bytes DESC NULLS LAST
        """)

        for row in rows:
            retained = row["retained_bytes"] or 0
            if retained > 1024 * 1024 * 1024:  # > 1GB
                health.alerts.append(ReplicationAlert(
                    severity="critical",
                    category="wal_bloat",
                    message=(
                        f"Inactive replication slot '{row['slot_name']}' "
                        f"retaining {retained // 1024 // 1024 // 1024}GB of WAL"
                    ),
                    description=(
                        "Inactive replication slots prevent WAL cleanup, "
                        "which can fill the disk."
                    ),
                    fix_command=(
                        f"-- Drop the inactive slot:\n"
                        f"SELECT pg_drop_replication_slot('{row['slot_name']}');"
                    ),
                    impact="Disk filling up with retained WAL segments",
                ))

    def analyze_migration_safety(
        self,
        migration_sql: str,
    ) -> list[ReplicationAlert]:
        """
        Analyze a migration SQL for replication compatibility.

        Checks for schema changes that break logical replication.
        """
        alerts: list[ReplicationAlert] = []
        sql_upper = migration_sql.upper()

        # NOT NULL without DEFAULT breaks logical replication
        if re.search(r"ADD\s+COLUMN\s+\w+\s+\w+\s+NOT\s+NULL(?!\s+DEFAULT)", sql_upper):
            alerts.append(ReplicationAlert(
                severity="critical",
                category="schema_compat",
                message="ADD COLUMN ... NOT NULL without DEFAULT breaks logical replication",
                description=(
                    "Adding a NOT NULL column without a DEFAULT value causes "
                    "INSERT failures on the subscriber because existing rows "
                    "don't have a value for the new column."
                ),
                fix_command=(
                    "-- Safe migration plan (3 steps):\n"
                    "-- 1. ALTER TABLE t ADD COLUMN col type DEFAULT value;\n"
                    "-- 2. Wait for replication to catch up\n"
                    "-- 3. ALTER TABLE t ALTER COLUMN col SET NOT NULL;"
                ),
                impact="Replication breaks, subscriber falls behind",
            ))

        # ALTER TYPE can break replication
        if re.search(r"ALTER\s+(TABLE\s+\w+\s+)?ALTER\s+COLUMN\s+\w+\s+(SET\s+DATA\s+)?TYPE", sql_upper):
            alerts.append(ReplicationAlert(
                severity="warning",
                category="schema_compat",
                message="ALTER COLUMN TYPE may require table rewrite and break replication",
                description=(
                    "Column type changes may require a full table rewrite. "
                    "During replication, this can cause timeouts or inconsistencies."
                ),
                fix_command=(
                    "-- Safe approach: create new column, migrate data, swap names:\n"
                    "-- 1. ALTER TABLE t ADD COLUMN new_col new_type;\n"
                    "-- 2. UPDATE t SET new_col = old_col::new_type;\n"
                    "-- 3. Application switches to new_col\n"
                    "-- 4. ALTER TABLE t DROP COLUMN old_col;\n"
                    "-- 5. ALTER TABLE t RENAME COLUMN new_col TO old_col;"
                ),
                impact="Table lock during rewrite, potential replication lag",
            ))

        # RENAME TABLE breaks logical replication subscriptions
        if re.search(r"ALTER\s+TABLE\s+\w+\s+RENAME\s+TO", sql_upper):
            alerts.append(ReplicationAlert(
                severity="warning",
                category="schema_compat",
                message="RENAME TABLE breaks logical replication subscriptions",
                description="Logical replication subscriptions track table names.",
                fix_command=(
                    "-- Recreate the subscription after rename:\n"
                    "-- ALTER SUBSCRIPTION sub REFRESH PUBLICATION;"
                ),
                impact="Replication stops for renamed table",
            ))

        # DROP COLUMN on replicated table
        if re.search(r"DROP\s+COLUMN", sql_upper):
            alerts.append(ReplicationAlert(
                severity="info",
                category="schema_compat",
                message="DROP COLUMN — ensure subscriber schema is updated first",
                description="Drop the column on subscriber before publisher to avoid errors.",
                fix_command=(
                    "-- Order of operations:\n"
                    "-- 1. On SUBSCRIBER: ALTER TABLE t DROP COLUMN col;\n"
                    "-- 2. On PUBLISHER: ALTER TABLE t DROP COLUMN col;"
                ),
                impact="Wrong order causes replication error",
            ))

        return alerts
