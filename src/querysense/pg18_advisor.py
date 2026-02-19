"""
PostgreSQL 18 Advisor — detect PG18 features and recommend upgrades.

PostgreSQL 18 introduced fundamental changes that affect performance:

1. Asynchronous I/O (AIO) — changes how Postgres interacts with disk
2. B-tree Skip Scan — efficient multi-value index scans
3. UUIDv7 — time-sortable UUIDs for better index locality
4. autovacuum_vacuum_max_threshold — cap on vacuum scale factor
5. Planner improvements — OR-to-array, self-join removal, DISTINCT opt
6. EXPLAIN enhancements — richer output, SERIALIZE option
7. pg_stat_plans — plan-level metrics via PlannedStmt.PlanID

This module:
- Detects the current PostgreSQL version
- Identifies which PG18 features apply to the current workload
- Recommends configuration changes for PG18
- Advises on migration from UUIDv4 to UUIDv7
- Detects queries that benefit from Skip Scan or OR-to-array transforms

Usage:
    from querysense.pg18_advisor import PG18Advisor
    advisor = PG18Advisor()
    report = await advisor.analyze(dsn)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PG18Finding:
    """A finding related to PostgreSQL 18 features."""
    category: str  # aio, skip_scan, uuidv7, vacuum, planner, monitoring
    title: str
    description: str
    recommendation: str
    sql_command: str = ""
    severity: str = "info"  # critical, warning, notice, info
    pg18_required: bool = True
    impact: str = ""


@dataclass
class PG18Report:
    """Complete PostgreSQL 18 readiness report."""
    current_version: str = ""
    major_version: int = 0
    is_pg18_or_later: bool = False
    findings: list[PG18Finding] = field(default_factory=list)
    uuid_tables: list[dict[str, Any]] = field(default_factory=list)
    skip_scan_candidates: list[dict[str, Any]] = field(default_factory=list)
    aio_status: dict[str, Any] = field(default_factory=dict)
    total_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_version": self.current_version,
            "major_version": self.major_version,
            "is_pg18_or_later": self.is_pg18_or_later,
            "total_findings": len(self.findings),
            "findings": [
                {"category": f.category, "title": f.title,
                 "severity": f.severity, "recommendation": f.recommendation}
                for f in self.findings
            ],
            "uuid_tables": len(self.uuid_tables),
            "skip_scan_candidates": len(self.skip_scan_candidates),
        }


class PG18Advisor:
    """
    Analyze a PostgreSQL instance for PG18 readiness and optimization.

    Works on PG14+ — recommends upgrade paths and identifies workloads
    that would benefit most from PG18 features.
    """

    async def analyze(
        self,
        dsn: str,
        check_uuid: bool = True,
        check_aio: bool = True,
        check_skip_scan: bool = True,
        check_vacuum: bool = True,
        check_planner: bool = True,
    ) -> PG18Report:
        """Run full PG18 readiness analysis."""
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        report = PG18Report()
        conn = await asyncpg.connect(dsn)

        try:
            # Detect version
            version_str = await conn.fetchval("SELECT version()")
            report.current_version = version_str
            report.major_version = self._parse_major_version(version_str)
            report.is_pg18_or_later = report.major_version >= 18

            # Run checks
            if check_aio:
                await self._check_async_io(conn, report)

            if check_skip_scan:
                await self._check_skip_scan_candidates(conn, report)

            if check_uuid:
                await self._check_uuid_columns(conn, report)

            if check_vacuum:
                await self._check_vacuum_enhancements(conn, report)

            if check_planner:
                await self._check_planner_improvements(conn, report)

            self._check_monitoring_upgrades(report)

            report.total_findings = len(report.findings)

        finally:
            await conn.close()

        return report

    def _parse_major_version(self, version_str: str) -> int:
        """Extract major version number."""
        m = re.search(r'PostgreSQL (\d+)', version_str)
        return int(m.group(1)) if m else 0

    # ── Async I/O ────────────────────────────────────────────────────

    async def _check_async_io(
        self, conn: Any, report: PG18Report,
    ) -> None:
        """Check async I/O readiness and configuration."""
        if report.is_pg18_or_later:
            # Check if AIO is enabled
            try:
                io_method = await conn.fetchval(
                    "SELECT setting FROM pg_settings WHERE name = 'io_method'"
                )
                io_combine_limit = await conn.fetchval(
                    "SELECT setting FROM pg_settings WHERE name = 'io_combine_limit'"
                )

                report.aio_status = {
                    "io_method": io_method,
                    "io_combine_limit": io_combine_limit,
                }

                if io_method == "sync":
                    report.findings.append(PG18Finding(
                        category="aio",
                        title="Async I/O is available but not enabled",
                        description=(
                            "PostgreSQL 18 supports asynchronous I/O which can "
                            "significantly improve performance, especially in cloud "
                            "environments where latency is the bottleneck."
                        ),
                        recommendation="Enable async I/O for better cloud performance",
                        sql_command=(
                            "ALTER SYSTEM SET io_method = 'worker';\n"
                            "SELECT pg_reload_conf();"
                        ),
                        severity="warning",
                        impact="10-50% I/O improvement in cloud environments",
                    ))

                if io_combine_limit and int(io_combine_limit) < 128:
                    report.findings.append(PG18Finding(
                        category="aio",
                        title=f"io_combine_limit is low ({io_combine_limit}KB)",
                        description=(
                            "The io_combine_limit controls how many pages can be "
                            "combined in a single I/O request. Higher values improve "
                            "sequential scan performance."
                        ),
                        recommendation="Increase io_combine_limit for sequential scans",
                        sql_command=(
                            "ALTER SYSTEM SET io_combine_limit = '128kB';\n"
                            "SELECT pg_reload_conf();"
                        ),
                        severity="notice",
                    ))
            except Exception:
                pass  # Settings don't exist pre-PG18
        else:
            report.findings.append(PG18Finding(
                category="aio",
                title="Async I/O not available (requires PostgreSQL 18+)",
                description=(
                    f"Current version: PG{report.major_version}. "
                    "PostgreSQL 18 introduces asynchronous I/O that fundamentally "
                    "changes how Postgres interacts with the disk. Cloud environments "
                    "(RDS, Aurora, GCP) benefit significantly from reduced I/O latency."
                ),
                recommendation=f"Upgrade from PG{report.major_version} to PG18 for async I/O",
                severity="info",
                pg18_required=True,
                impact="10-50% I/O improvement, especially in cloud",
            ))

    # ── B-tree Skip Scan ─────────────────────────────────────────────

    async def _check_skip_scan_candidates(
        self, conn: Any, report: PG18Report,
    ) -> None:
        """Find indexes that would benefit from B-tree Skip Scan."""
        # Skip Scan benefits multi-column indexes where the leading column
        # has low cardinality but queries filter on non-leading columns
        rows = await conn.fetch("""
            SELECT
                schemaname, tablename, indexname, indexdef,
                pg_relation_size(indexrelid) AS index_size
            FROM pg_stat_user_indexes sui
            JOIN pg_indexes pi ON sui.indexrelname = pi.indexname
                AND sui.schemaname = pi.schemaname
            WHERE idx_scan > 0
            ORDER BY pg_relation_size(indexrelid) DESC
            LIMIT 50
        """)

        for row in rows:
            indexdef = row["indexdef"]
            # Find multi-column indexes
            col_match = re.search(r'\(([^)]+)\)', indexdef)
            if not col_match:
                continue
            cols = [c.strip().split()[0] for c in col_match.group(1).split(",")]
            if len(cols) < 2:
                continue

            # Check leading column cardinality
            table = row["tablename"]
            schema = row["schemaname"]
            lead_col = cols[0]

            try:
                ndistinct = await conn.fetchval(f"""
                    SELECT n_distinct FROM pg_stats
                    WHERE schemaname = $1 AND tablename = $2 AND attname = $3
                """, schema, table, lead_col)

                if ndistinct is not None and 0 < ndistinct < 100:
                    report.skip_scan_candidates.append({
                        "schema": schema,
                        "table": table,
                        "index": row["indexname"],
                        "columns": cols,
                        "leading_col_distinct": ndistinct,
                        "index_size": row["index_size"],
                    })
            except Exception:
                continue

        if report.skip_scan_candidates:
            desc = "skip scan" if report.is_pg18_or_later else "skip scan (requires PG18)"
            report.findings.append(PG18Finding(
                category="skip_scan",
                title=f"{len(report.skip_scan_candidates)} indexes would benefit from B-tree Skip Scan",
                description=(
                    "B-tree Skip Scan in PG18 efficiently handles queries that filter on "
                    "non-leading columns of a multi-column index. Previously these required "
                    "separate indexes or full index scans."
                ),
                recommendation=(
                    f"These multi-column indexes have low-cardinality leading columns "
                    f"({desc}): "
                    + ", ".join(c["index"] for c in report.skip_scan_candidates[:5])
                ),
                severity="notice" if report.is_pg18_or_later else "info",
                pg18_required=True,
                impact="Eliminates need for redundant single-column indexes",
            ))

    # ── UUID Columns ─────────────────────────────────────────────────

    async def _check_uuid_columns(
        self, conn: Any, report: PG18Report,
    ) -> None:
        """Find UUIDv4 primary keys that should migrate to UUIDv7."""
        rows = await conn.fetch("""
            SELECT
                c.table_schema, c.table_name, c.column_name,
                tc.constraint_type,
                pg_relation_size(quote_ident(c.table_schema) || '.' ||
                    quote_ident(c.table_name)) AS table_size
            FROM information_schema.columns c
            LEFT JOIN information_schema.constraint_column_usage ccu
                ON c.table_schema = ccu.table_schema
                AND c.table_name = ccu.table_name
                AND c.column_name = ccu.column_name
            LEFT JOIN information_schema.table_constraints tc
                ON ccu.constraint_name = tc.constraint_name
                AND tc.constraint_type = 'PRIMARY KEY'
            WHERE c.data_type = 'uuid'
                AND c.table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY pg_relation_size(quote_ident(c.table_schema) || '.' ||
                quote_ident(c.table_name)) DESC
        """)

        uuid_pks: list[dict] = []
        for row in rows:
            if row["constraint_type"] == "PRIMARY KEY":
                uuid_pks.append({
                    "schema": row["table_schema"],
                    "table": row["table_name"],
                    "column": row["column_name"],
                    "table_size": row["table_size"],
                })

        report.uuid_tables = uuid_pks

        if uuid_pks:
            total_size_mb = sum(t["table_size"] for t in uuid_pks) // (1024 * 1024)
            report.findings.append(PG18Finding(
                category="uuidv7",
                title=f"{len(uuid_pks)} tables use UUID primary keys ({total_size_mb}MB total)",
                description=(
                    "UUID primary keys (likely UUIDv4) cause random B-tree insertions, "
                    "leading to index bloat and poor cache locality. PostgreSQL 18 adds "
                    "built-in uuidv7() which generates time-sorted UUIDs for sequential "
                    "index insertions."
                ),
                recommendation=(
                    "Migrate from gen_random_uuid() (v4) to uuidv7() (PG18) for "
                    "better index locality. For new tables: DEFAULT uuidv7(). "
                    "For existing data, consider a phased migration."
                ),
                sql_command=(
                    "-- PG18: Set new default for future inserts\n"
                    "ALTER TABLE {table} ALTER COLUMN {col} SET DEFAULT uuidv7();\n\n"
                    "-- If still on PG16/17 with pg_uuidv7 extension:\n"
                    "CREATE EXTENSION IF NOT EXISTS pg_uuidv7;\n"
                    "ALTER TABLE {table} ALTER COLUMN {col} SET DEFAULT uuid_generate_v7();"
                ),
                severity="notice" if total_size_mb > 1000 else "info",
                impact=(
                    f"Better index locality for {len(uuid_pks)} tables, "
                    "reduced page splits, improved sequential insert performance"
                ),
            ))

    # ── VACUUM Enhancements ──────────────────────────────────────────

    async def _check_vacuum_enhancements(
        self, conn: Any, report: PG18Report,
    ) -> None:
        """Check for PG18 VACUUM improvements."""
        # autovacuum_vacuum_max_threshold (PG18)
        large_tables = await conn.fetch("""
            SELECT
                schemaname, relname,
                n_live_tup, n_dead_tup,
                pg_relation_size(relid) AS table_size
            FROM pg_stat_user_tables
            WHERE n_live_tup > 10000000
            ORDER BY n_live_tup DESC
            LIMIT 20
        """)

        if large_tables:
            table_names = [f"{r['schemaname']}.{r['relname']}" for r in large_tables[:5]]
            report.findings.append(PG18Finding(
                category="vacuum",
                title=f"{len(large_tables)} large tables benefit from autovacuum_vacuum_max_threshold",
                description=(
                    "PG18 adds autovacuum_vacuum_max_threshold which caps the number of "
                    "dead tuples before vacuum triggers, regardless of scale factor. "
                    "This prevents autovacuum from waiting too long on very large tables "
                    f"where the default 20% scale factor means millions of dead tuples. "
                    f"Affected tables: {', '.join(table_names)}"
                ),
                recommendation=(
                    "Set autovacuum_vacuum_max_threshold per-table for large tables "
                    "to trigger vacuum before dead tuples accumulate."
                ),
                sql_command=(
                    "-- PG18: Set max dead tuple threshold\n"
                    "ALTER SYSTEM SET autovacuum_vacuum_max_threshold = 1000000;\n\n"
                    "-- Per-table override for very large tables:\n"
                    + "\n".join(
                        f"ALTER TABLE {r['schemaname']}.{r['relname']} "
                        f"SET (autovacuum_vacuum_scale_factor = 0.01);"
                        for r in large_tables[:3]
                    )
                ),
                severity="warning" if len(large_tables) > 5 else "notice",
                impact=f"Faster VACUUM on {len(large_tables)} tables with 10M+ rows",
            ))

        # Multi-index-phase VACUUM resource usage
        multi_idx_tables = await conn.fetch("""
            SELECT
                t.schemaname, t.relname,
                t.n_dead_tup,
                (SELECT count(*) FROM pg_index i
                 WHERE i.indrelid = t.relid) AS idx_count
            FROM pg_stat_user_tables t
            WHERE t.n_dead_tup > 100000
            ORDER BY t.n_dead_tup DESC
            LIMIT 20
        """)

        high_idx = [r for r in multi_idx_tables if r["idx_count"] > 5]
        if high_idx:
            report.findings.append(PG18Finding(
                category="vacuum",
                title=f"{len(high_idx)} tables with many indexes have heavy VACUUM overhead",
                description=(
                    "Tables with many indexes require VACUUM to process each index "
                    "in separate phases. With limited autovacuum_work_mem, VACUUM may "
                    "need multiple passes, consuming significant resources."
                ),
                recommendation=(
                    "Increase autovacuum_work_mem to hold all dead tuple TIDs in one "
                    "pass, reducing multi-index-phase overhead."
                ),
                sql_command=(
                    "-- Avoid multi-pass VACUUM on tables with many indexes\n"
                    "ALTER SYSTEM SET autovacuum_work_mem = '1GB';\n"
                    "SELECT pg_reload_conf();"
                ),
                severity="notice",
            ))

    # ── Planner Improvements ─────────────────────────────────────────

    async def _check_planner_improvements(
        self, conn: Any, report: PG18Report,
    ) -> None:
        """Detect queries that benefit from PG18 planner improvements."""
        # Check for queries with OR clauses that PG18 transforms to array scans
        try:
            or_queries = await conn.fetch("""
                SELECT query, calls, mean_exec_time
                FROM pg_stat_statements
                WHERE query ~* '\\bOR\\b.*\\bOR\\b'
                    AND calls > 10
                ORDER BY mean_exec_time * calls DESC
                LIMIT 10
            """)

            if or_queries:
                report.findings.append(PG18Finding(
                    category="planner",
                    title=f"{len(or_queries)} queries with multiple OR clauses",
                    description=(
                        "PG18 can automatically transform OR clauses into array scans, "
                        "allowing the planner to use index scans instead of sequential "
                        "scans or bitmap ORs."
                    ),
                    recommendation=(
                        "On PG18, these queries may automatically use more efficient "
                        "array-based index scans. On older versions, manually rewrite "
                        "OR to ANY(ARRAY[...])"
                    ),
                    severity="notice",
                    impact=f"Potential speedup for {len(or_queries)} frequently-run queries",
                ))
        except Exception:
            pass

        # Check for self-joins that PG18 eliminates
        try:
            self_joins = await conn.fetch("""
                SELECT query, calls, mean_exec_time
                FROM pg_stat_statements
                WHERE query ~* 'JOIN\\s+\\w+\\s+\\w+\\s+ON\\s+\\w+\\.\\w+\\s*=\\s*\\w+\\.\\w+'
                    AND calls > 10
                ORDER BY mean_exec_time DESC
                LIMIT 10
            """)
            # Heuristic: check if any queries join a table to itself
            self_join_count = 0
            for row in self_joins:
                tables = re.findall(r'\bFROM\s+(\w+)', row["query"], re.IGNORECASE)
                joins = re.findall(r'\bJOIN\s+(\w+)', row["query"], re.IGNORECASE)
                all_tables = tables + joins
                if len(all_tables) != len(set(all_tables)):
                    self_join_count += 1

            if self_join_count > 0:
                report.findings.append(PG18Finding(
                    category="planner",
                    title=f"{self_join_count} queries with unnecessary self-joins",
                    description=(
                        "PG18 can automatically remove unnecessary self-joins "
                        "where a table is joined to itself redundantly."
                    ),
                    recommendation=(
                        "These queries may run faster on PG18 due to automatic "
                        "self-join removal."
                    ),
                    severity="info",
                ))
        except Exception:
            pass

    # ── Monitoring Upgrades ──────────────────────────────────────────

    def _check_monitoring_upgrades(self, report: PG18Report) -> None:
        """Note PG18 monitoring improvements."""
        if not report.is_pg18_or_later:
            report.findings.append(PG18Finding(
                category="monitoring",
                title="PG18 monitoring improvements not available",
                description=(
                    "PostgreSQL 18 adds: richer EXPLAIN output (SERIALIZE option, "
                    "memory accounting), extended pg_stat_* views (WAL activity, "
                    "NUMA interactions with shared buffers), and the pg_stat_plans "
                    "extension for plan-level metrics via PlannedStmt.PlanID."
                ),
                recommendation=(
                    "After upgrading to PG18, install pg_stat_plans for plan-level "
                    "metrics tracking: CREATE EXTENSION pg_stat_plans;"
                ),
                severity="info",
                pg18_required=True,
            ))
        else:
            report.findings.append(PG18Finding(
                category="monitoring",
                title="Enable PG18 monitoring extensions",
                description=(
                    "PG18 supports pg_stat_plans which adds PlannedStmt.PlanID to "
                    "track plan-level metrics alongside pg_stat_statements."
                ),
                recommendation=(
                    "Install pg_stat_plans for plan change detection and "
                    "per-plan performance tracking."
                ),
                sql_command=(
                    "CREATE EXTENSION IF NOT EXISTS pg_stat_plans;\n"
                    "-- Then query: SELECT * FROM pg_stat_plans ORDER BY total_exec_time DESC;"
                ),
                severity="notice",
            ))
