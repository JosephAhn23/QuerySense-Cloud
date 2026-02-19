"""
Replication Advisor Checks — Monitor replication health and WAL.

Implements Percona's replication monitoring pattern:
    1. Replication lag detection
    2. Stale replication slot detection
    3. WAL retention and archiver health
    4. Primary-replica topology awareness

Bridges to querysense.replication_analyzer for deeper analysis.
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


class ReplicationLagCheck(AdvisorCheck):
    """Check for excessive replication lag on replicas."""

    name = "postgres_replication_lag"
    title = "Replication Lag"
    description = "Detect replicas with excessive replay lag"
    category = AdvisorCategory.REPLICATION
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        # Check if this is a primary with replicas
        try:
            rows = await conn.fetch(
                "SELECT client_addr, state, sync_state, "
                "  EXTRACT(EPOCH FROM write_lag)::float AS write_lag_s, "
                "  EXTRACT(EPOCH FROM flush_lag)::float AS flush_lag_s, "
                "  EXTRACT(EPOCH FROM replay_lag)::float AS replay_lag_s "
                "FROM pg_stat_replication "
                "ORDER BY replay_lag DESC NULLS LAST"
            )
        except Exception:
            return result

        for row in rows:
            if isinstance(row, (list, tuple)):
                addr, state, sync, write_lag, flush_lag, replay_lag = row[:6]
            else:
                addr = getattr(row, "client_addr", "")
                state = getattr(row, "state", "")
                sync = getattr(row, "sync_state", "")
                write_lag = getattr(row, "write_lag_s", 0)
                flush_lag = getattr(row, "flush_lag_s", 0)
                replay_lag = getattr(row, "replay_lag_s", 0)

            replay_s = float(replay_lag or 0)

            if replay_s > 600:  # 10 minutes
                sev = CheckSeverity.CRITICAL
            elif replay_s > 60:  # 1 minute
                sev = CheckSeverity.WARNING
            elif replay_s > 10:
                sev = CheckSeverity.NOTICE
            else:
                continue

            result.findings.append(Finding(
                severity=sev,
                title=f"Replica {addr}: {replay_s:.0f}s replay lag",
                description=(
                    f"Replica at {addr} (state: {state}, sync: {sync}) "
                    f"has {replay_s:.1f}s replay lag. "
                    f"Write lag: {float(write_lag or 0):.1f}s, "
                    f"Flush lag: {float(flush_lag or 0):.1f}s."
                ),
                recommendation="Check replica I/O performance and network connectivity.",
                evidence={
                    "address": str(addr),
                    "replay_lag_seconds": round(replay_s, 1),
                    "state": str(state),
                },
                tags=["replication", "lag", "replica"],
            ))
            result.passed = False

        return result


class StaleReplicationSlotCheck(AdvisorCheck):
    """Detect stale (inactive) replication slots consuming WAL."""

    name = "postgres_stale_replication_slots"
    title = "Stale Replication Slots"
    description = "Find inactive replication slots preventing WAL cleanup"
    category = AdvisorCategory.REPLICATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            rows = await conn.fetch(
                "SELECT slot_name, slot_type, database, active, "
                "  pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal "
                "FROM pg_replication_slots "
                "WHERE NOT active "
                "ORDER BY pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) DESC"
            )
        except Exception:
            return result

        for row in rows:
            if isinstance(row, (list, tuple)):
                name, slot_type, db, active, retained = row[:5]
            else:
                name = getattr(row, "slot_name", "")
                slot_type = getattr(row, "slot_type", "")
                db = getattr(row, "database", "")
                active = getattr(row, "active", False)
                retained = getattr(row, "retained_wal", "")

            result.findings.append(Finding(
                severity=CheckSeverity.WARNING,
                title=f"Stale replication slot: '{name}' retaining {retained} of WAL",
                description=(
                    f"Slot '{name}' (type: {slot_type}, db: {db}) is inactive. "
                    f"It prevents {retained} of WAL from being cleaned up, "
                    f"which can fill the disk."
                ),
                recommendation=(
                    f"If the consumer is permanently gone, drop it: "
                    f"SELECT pg_drop_replication_slot('{name}');"
                ),
                fix_sql=f"SELECT pg_drop_replication_slot('{name}');",
                rationale=(
                    "Inactive replication slots hold back WAL indefinitely. "
                    "This is a common cause of disk space exhaustion."
                ),
                evidence={"slot_name": str(name), "slot_type": str(slot_type), "retained_wal": str(retained)},
                tags=["replication", "wal", "disk-space"],
            ))
            result.passed = False

        return result


class WALArchiverCheck(AdvisorCheck):
    """Check WAL archiver status."""

    name = "postgres_wal_archiver"
    title = "WAL Archiver Health"
    description = "Verify WAL archiving is functioning correctly"
    category = AdvisorCategory.REPLICATION
    interval = CheckInterval.STANDARD

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        archive_mode = await conn.fetchval("SHOW archive_mode")
        if str(archive_mode).lower() != "on":
            return result  # Archiving not enabled, skip

        try:
            rows = await conn.fetch(
                "SELECT archived_count, failed_count, last_archived_wal, "
                "  last_archived_time, last_failed_wal, last_failed_time "
                "FROM pg_stat_archiver"
            )
        except Exception:
            return result

        if rows:
            r = rows[0]
            if isinstance(r, (list, tuple)):
                archived, failed, last_wal, last_time, fail_wal, fail_time = r[:6]
            else:
                archived = getattr(r, "archived_count", 0)
                failed = getattr(r, "failed_count", 0)
                last_wal = getattr(r, "last_archived_wal", "")
                last_time = getattr(r, "last_archived_time", None)
                fail_wal = getattr(r, "last_failed_wal", "")
                fail_time = getattr(r, "last_failed_time", None)

            failed_count = int(failed or 0)
            if failed_count > 0:
                result.findings.append(Finding(
                    severity=CheckSeverity.CRITICAL,
                    title=f"WAL archiver has {failed_count} failures",
                    description=(
                        f"Last failed WAL: {fail_wal} at {fail_time}. "
                        f"Total archived: {archived}, failed: {failed_count}. "
                        "Failed archiving means you cannot do point-in-time recovery."
                    ),
                    recommendation="Check archive_command, disk space, and permissions.",
                    evidence={
                        "archived_count": int(archived or 0),
                        "failed_count": failed_count,
                        "last_failed_wal": str(fail_wal),
                    },
                    tags=["wal", "archiver", "backup", "pitr"],
                ))
                result.passed = False

        return result


class WALSizeCheck(AdvisorCheck):
    """Monitor WAL directory size."""

    name = "postgres_wal_size"
    title = "WAL Directory Size"
    description = "Check if WAL is consuming excessive disk space"
    category = AdvisorCategory.REPLICATION
    interval = CheckInterval.FREQUENT

    async def run(self, conn: AsyncDBConnection) -> CheckResult:
        result = CheckResult(check_name=self.name, category=self.category)

        try:
            wal_bytes = await conn.fetchval(
                "SELECT sum(size) FROM pg_ls_waldir()"
            )
        except Exception:
            return result

        if wal_bytes:
            wal_gb = float(wal_bytes) / (1024 ** 3)
            max_wal = await conn.fetchval("SHOW max_wal_size")

            if wal_gb > 10:
                sev = CheckSeverity.WARNING if wal_gb < 50 else CheckSeverity.CRITICAL
                result.findings.append(Finding(
                    severity=sev,
                    title=f"WAL directory is {wal_gb:.1f}GB",
                    description=(
                        f"WAL is consuming {wal_gb:.1f}GB of disk. "
                        f"max_wal_size = {max_wal}. "
                        "Excessive WAL is often caused by stale replication slots."
                    ),
                    recommendation="Check for stale replication slots: SELECT * FROM pg_replication_slots;",
                    evidence={"wal_size_gb": round(wal_gb, 1), "max_wal_size": str(max_wal)},
                    tags=["wal", "disk-space"],
                ))
                result.passed = False

        return result


def get_replication_checks() -> list[AdvisorCheck]:
    """Return all replication advisor checks."""
    return [
        ReplicationLagCheck(),
        StaleReplicationSlotCheck(),
        WALArchiverCheck(),
        WALSizeCheck(),
    ]
