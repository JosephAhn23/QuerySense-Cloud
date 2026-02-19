"""
Cluster-Aware Index Advisor — the full pganalyze Feb 2026 parity.

This is the key insight from pganalyze's Feb 4, 2026 announcement:
instead of analyzing each server independently and merging *results*,
we merge the *input data* (scans) across the cluster before running
the CP-SAT solver. This produces a single, globally optimal index set
for the entire cluster.

Key behaviors:
1. Scans from all servers (primary + replicas) are merged per table
2. Scan frequency is the sum across all servers in the cluster
3. The CP-SAT model receives the combined scan set
4. IWO is calculated from the primary's write rates (replicas don't write)
5. HypoPG verification runs on the primary (where indexes are created)
6. Unused indexes are only flagged if unused on ALL servers

Architecture:
    ┌─────────┐  ┌──────────┐  ┌──────────┐
    │ Primary │  │ Replica1 │  │ Replica2 │
    │  scans  │  │  scans   │  │  scans   │
    └────┬────┘  └────┬─────┘  └────┬─────┘
         │            │              │
         └──────┬─────┴──────────────┘
                │
    ┌───────────▼───────────┐
    │ Scan Merger (per table)│   ← The critical step
    │ Dedup + sum frequency  │
    └───────────┬───────────┘
                │
    ┌───────────▼──────────┐
    │ IWO from primary only │
    └───────────┬──────────┘
                │
    ┌───────────▼──────────┐
    │ CP-SAT Optimization  │
    └───────────┬──────────┘
                │
    ┌───────────▼──────────────────┐
    │ Cluster-wide recommendation  │
    │ (applied on primary)         │
    └──────────────────────────────┘

Usage:
    from querysense.cluster import ClusterDetector
    from querysense.index.cluster_advisor import ClusterIndexAdvisor

    detector = ClusterDetector()
    cluster = await detector.detect(dsns=[primary, replica1, replica2])

    advisor = ClusterIndexAdvisor()
    result = await advisor.advise_cluster(cluster)
    print(result.fix_script)  # CREATE INDEX on primary
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ServerScanContribution:
    """Tracks which server contributed which scans."""
    server_label: str
    server_dsn: str
    is_primary: bool
    scans_extracted: int = 0
    tables: set[str] = field(default_factory=set)


@dataclass
class ClusterAdvisorResult:
    """Result from the cluster-aware index advisor."""
    # Recommendations (applied on primary)
    recommended_indexes: list[Any] = field(default_factory=list)  # CandidateIndex
    dropped_indexes: list[str] = field(default_factory=list)

    # Cluster info
    cluster_id: str = ""
    server_count: int = 0
    is_cluster_aware: bool = False  # True if >1 server contributed

    # Per-server scan contributions
    server_contributions: list[ServerScanContribution] = field(default_factory=list)

    # Merged stats
    total_scans_before_merge: int = 0
    total_scans_after_merge: int = 0
    scans_unique_to_replicas: int = 0  # Scans that only exist on replicas
    tables_analyzed: int = 0
    candidates_generated: int = 0
    solver_time_ms: float = 0
    total_time_ms: float = 0

    # Impact
    total_cost_reduction_pct: float = 0
    total_iwo: float = 0

    # Unused index analysis
    indexes_unused_cluster_wide: list[str] = field(default_factory=list)
    indexes_saved_by_replicas: list[dict[str, Any]] = field(default_factory=list)

    @property
    def fix_script(self) -> str:
        lines = [
            "-- QuerySense Cluster-Aware Index Advisor",
            f"-- Cluster: {self.cluster_id} ({self.server_count} servers)",
            f"-- Scans merged from {self.server_count} servers "
            f"({self.total_scans_before_merge} → {self.total_scans_after_merge} unique)",
            "",
        ]

        if self.dropped_indexes:
            lines.append("-- Step 1: Remove indexes unused across entire cluster")
            for idx in self.dropped_indexes:
                lines.append(f"DROP INDEX CONCURRENTLY IF EXISTS {idx};")
            lines.append("")

        if self.indexes_saved_by_replicas:
            lines.append("-- NOTE: The following indexes appear unused on primary")
            lines.append("-- but ARE used on replicas — do NOT drop:")
            for saved in self.indexes_saved_by_replicas:
                lines.append(f"--   {saved['index_name']} (used on {saved['used_on']})")
            lines.append("")

        lines.append("-- Step 2: Create optimized indexes (covers primary + all replicas)")
        for idx in self.recommended_indexes:
            servers = "primary + replicas" if self.is_cluster_aware else "standalone"
            lines.append(
                f"-- Covers {idx.scans_covered} scans across {servers}, "
                f"{idx.total_frequency:,} total calls"
            )
            lines.append(idx.create_sql)
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "server_count": self.server_count,
            "is_cluster_aware": self.is_cluster_aware,
            "total_scans_before_merge": self.total_scans_before_merge,
            "total_scans_after_merge": self.total_scans_after_merge,
            "scans_unique_to_replicas": self.scans_unique_to_replicas,
            "tables_analyzed": self.tables_analyzed,
            "solver_time_ms": self.solver_time_ms,
            "total_time_ms": self.total_time_ms,
            "total_cost_reduction_pct": self.total_cost_reduction_pct,
            "recommended_indexes": [
                {
                    "table": idx.table,
                    "columns": idx.columns,
                    "create_sql": idx.create_sql,
                    "scans_covered": idx.scans_covered,
                    "total_frequency": idx.total_frequency,
                    "improvement_ratio": idx.improvement_ratio,
                    "iwo_score": idx.iwo_score,
                }
                for idx in self.recommended_indexes
            ],
            "dropped_indexes": self.dropped_indexes,
            "indexes_unused_cluster_wide": self.indexes_unused_cluster_wide,
            "indexes_saved_by_replicas": self.indexes_saved_by_replicas,
            "server_contributions": [
                {
                    "server": c.server_label,
                    "is_primary": c.is_primary,
                    "scans": c.scans_extracted,
                    "tables": len(c.tables),
                }
                for c in self.server_contributions
            ],
        }


class ClusterIndexAdvisor:
    """
    Cluster-aware Index Advisor implementing pganalyze's Feb 2026 design.

    Instead of running the advisor on each server independently and merging
    results, this merges the *input scans* across the cluster and feeds
    the combined data to a single CP-SAT optimization pass.
    """

    def __init__(
        self,
        max_indexes_per_table: int = 8,
        max_iwo: float = 50.0,
        use_hypopg: bool = True,
        top_queries: int = 100,
    ) -> None:
        self.max_indexes_per_table = max_indexes_per_table
        self.max_iwo = max_iwo
        self.use_hypopg = use_hypopg
        self.top_queries = top_queries

    async def advise_cluster(
        self,
        cluster: Any,  # ClusterTopology
        schema: str = "public",
        tables: list[str] | None = None,
    ) -> ClusterAdvisorResult:
        """
        Run cluster-aware index advisor.

        1. Extract scans from every server in the cluster
        2. Merge scans by (database, schema, table) — combining frequencies
        3. Run IWO scoring on primary
        4. Run CP-SAT with combined scan set
        5. Determine unused indexes across the entire cluster
        """
        start = time.monotonic()
        result = ClusterAdvisorResult(
            cluster_id=cluster.cluster_id,
            server_count=cluster.server_count,
            is_cluster_aware=not cluster.is_standalone,
        )

        from querysense.scan_extractor import ScanExtractor, WorkloadScans

        # ── Stage 1: Extract scans from every server ──────────────────────
        logger.info(
            "Stage 1: Extracting scans from %d servers...",
            cluster.server_count,
        )
        per_server_scans: dict[str, WorkloadScans] = {}

        for server in cluster.all_servers:
            if not server.dsn:
                logger.debug("Skipping server %s (no DSN)", server.label)
                continue

            try:
                extractor = ScanExtractor()
                workload = await extractor.extract_from_database(
                    server.dsn, top_n=self.top_queries,
                )
                per_server_scans[server.dsn] = workload

                contribution = ServerScanContribution(
                    server_label=server.label,
                    server_dsn=server.dsn,
                    is_primary=server.is_primary,
                    scans_extracted=len(workload.scans),
                    tables=workload.tables,
                )
                result.server_contributions.append(contribution)
                result.total_scans_before_merge += len(workload.scans)

                logger.info(
                    "  %s: %d scans across %d tables",
                    server.label,
                    len(workload.scans),
                    len(workload.tables),
                )
            except Exception as e:
                logger.warning("Failed to extract scans from %s: %s", server.label, e)

        if not per_server_scans:
            result.total_time_ms = (time.monotonic() - start) * 1000
            return result

        # ── Stage 2: Merge scans across cluster ───────────────────────────
        logger.info("Stage 2: Merging scans across cluster...")
        merged = self._merge_scans(per_server_scans)
        result.total_scans_after_merge = len(merged.scans)
        result.tables_analyzed = len(merged.tables)

        # Count scans unique to replicas
        primary_dsn = cluster.primary_dsn
        if primary_dsn and primary_dsn in per_server_scans:
            primary_scan_ids = {s.scan_id for s in per_server_scans[primary_dsn].scans}
            replica_only = sum(
                1 for s in merged.scans if s.scan_id not in primary_scan_ids
            )
            result.scans_unique_to_replicas = replica_only

        if tables:
            target_tables = tables
        else:
            target_tables = merged.hot_tables[:20]

        # ── Stage 3-5: Run advisor pipeline on primary with merged scans ──
        logger.info("Stage 3-5: Running CP-SAT on primary with merged scans...")
        from querysense.index.advisor_pipeline import IndexAdvisorPipeline

        pipeline = IndexAdvisorPipeline(
            max_indexes_per_table=self.max_indexes_per_table,
            max_iwo=self.max_iwo,
            use_hypopg=self.use_hypopg,
            top_queries=self.top_queries,
        )

        # Use primary for IWO and HypoPG, but merged scans for input
        if primary_dsn:
            try:
                import asyncpg
                conn = await asyncpg.connect(primary_dsn)
                try:
                    for table in target_tables:
                        table_scans = merged.scans_for_table(table)
                        if not table_scans:
                            continue

                        # Generate candidates from MERGED scans
                        candidates = pipeline._generate_candidates(table, table_scans)
                        result.candidates_generated += len(candidates)

                        # IWO from PRIMARY (where writes happen)
                        candidates = await pipeline._score_iwo(conn, candidates, table, schema)
                        candidates = [c for c in candidates if c.iwo_score <= self.max_iwo]

                        if not candidates:
                            continue

                        # HypoPG on PRIMARY
                        if self.use_hypopg:
                            candidates = await pipeline._cost_with_hypopg(
                                conn, candidates, table_scans,
                            )

                        # CP-SAT with MERGED scan data
                        try:
                            selected = pipeline._run_cp_sat(candidates, table_scans, table)
                        except Exception as e:
                            logger.debug("CP-SAT failed (%s), greedy fallback", e)
                            selected = pipeline._greedy_select(candidates)

                        result.recommended_indexes.extend(selected)

                    # ── Stage 6: Cluster-wide unused index detection ──────────
                    logger.info("Stage 6: Detecting cluster-wide unused indexes...")
                    unused = await self._detect_unused_cluster_wide(
                        cluster, per_server_scans, schema,
                    )
                    result.indexes_unused_cluster_wide = unused["truly_unused"]
                    result.indexes_saved_by_replicas = unused["saved_by_replicas"]
                    result.dropped_indexes = unused["truly_unused"]

                finally:
                    await conn.close()
            except Exception as e:
                logger.error("Failed to run advisor on primary: %s", e)

        # Compute aggregate stats
        if result.recommended_indexes:
            total_seq = sum(i.sequential_cost for i in result.recommended_indexes if i.sequential_cost)
            total_idx = sum(i.index_cost for i in result.recommended_indexes if i.index_cost)
            if total_seq > 0:
                result.total_cost_reduction_pct = (total_seq - total_idx) / total_seq * 100
            result.total_iwo = sum(i.iwo_score for i in result.recommended_indexes)

        result.total_time_ms = (time.monotonic() - start) * 1000
        return result

    def _merge_scans(
        self,
        per_server: dict[str, Any],
    ) -> Any:
        """
        Merge scans from multiple servers into a single WorkloadScans.

        This is the critical pganalyze insight: don't merge recommendations,
        merge the *input data*. Scans with the same filter structure on the
        same table are deduplicated, with frequencies summed.

        Example from pganalyze blog:
            Primary scan: (column1 = $1) at 0.36 scans/min
            Replica scan: (column1 = $1, column2 = $1) at 20.9 scans/min
            → Merged: both scans present, CP-SAT sees the full picture
            → Result: CREATE INDEX ON t (column1, column2) covers both
        """
        from querysense.scan_extractor import WorkloadScans

        merged = WorkloadScans()
        # Key: (table, schema, frozenset of filter columns) → aggregated scan
        scan_map: dict[str, Any] = {}  # scan_id → ExtractedScan (first seen)
        freq_map: dict[str, int] = {}  # scan_id → total frequency

        for dsn, workload in per_server.items():
            merged.total_queries += workload.total_queries
            merged.tables.update(workload.tables)

            for scan in workload.scans:
                # Dedup key: table + sorted filter columns + sorted join columns
                # This ensures the same scan structure maps to one entry
                filter_key = tuple(sorted(
                    (c.column, c.operator) for c in scan.filter_columns
                ))
                join_key = tuple(sorted(c.column for c in scan.join_columns))
                dedup_key = f"{scan.table}:{scan.schema}:{filter_key}:{join_key}"

                if dedup_key not in scan_map:
                    scan_map[dedup_key] = scan
                    freq_map[dedup_key] = scan.frequency
                else:
                    # Same scan structure — sum the frequency
                    freq_map[dedup_key] += scan.frequency
                    # Keep the higher cost estimate (conservative)
                    existing = scan_map[dedup_key]
                    if scan.sequential_cost > existing.sequential_cost:
                        scan_map[dedup_key] = scan

        # Build merged scans with summed frequencies
        from querysense.scan_extractor import ExtractedScan

        for dedup_key, scan in scan_map.items():
            # Create a copy with merged frequency
            merged_scan = ExtractedScan(
                scan_id=scan.scan_id,
                table=scan.table,
                schema=scan.schema,
                scan_type=scan.scan_type,
                filter_columns=scan.filter_columns,
                join_columns=scan.join_columns,
                order_columns=scan.order_columns,
                group_columns=scan.group_columns,
                output_columns=scan.output_columns,
                sequential_cost=scan.sequential_cost,
                actual_cost=scan.actual_cost,
                rows_estimated=scan.rows_estimated,
                rows_actual=scan.rows_actual,
                frequency=freq_map[dedup_key],  # Summed across cluster
                query_hash=scan.query_hash,
                sql_snippet=scan.sql_snippet,
            )
            merged.scans.append(merged_scan)

        return merged

    async def _detect_unused_cluster_wide(
        self,
        cluster: Any,  # ClusterTopology
        per_server_scans: dict[str, Any],
        schema: str,
    ) -> dict[str, list]:
        """
        Detect truly unused indexes across the entire cluster.

        Key pganalyze rule: an index is only "unused" if it's unused on
        ALL servers. An index that's unused on the primary but used on a
        replica should NOT be dropped.
        """
        try:
            import asyncpg
        except ImportError:
            return {"truly_unused": [], "saved_by_replicas": []}

        # Collect index usage stats from every server
        # Key: index_name → dict(server_label → scan_count)
        index_usage: dict[str, dict[str, int]] = defaultdict(dict)
        index_meta: dict[str, dict] = {}  # index_name → metadata

        for server in cluster.all_servers:
            if not server.dsn:
                continue
            try:
                conn = await asyncpg.connect(server.dsn, timeout=10)
                try:
                    rows = await conn.fetch("""
                        SELECT
                            i.indexrelid::regclass::text AS index_name,
                            ix.indisprimary,
                            ix.indisunique,
                            COALESCE(s.idx_scan, 0) AS scan_count,
                            pg_relation_size(i.oid) AS index_size
                        FROM pg_index ix
                        JOIN pg_class i ON i.oid = ix.indexrelid
                        JOIN pg_class t ON t.oid = ix.indrelid
                        JOIN pg_namespace n ON n.oid = t.relnamespace
                        LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = i.oid
                        WHERE n.nspname = $1
                          AND NOT ix.indisprimary
                          AND NOT ix.indisunique
                    """, schema)

                    for row in rows:
                        idx_name = row["index_name"]
                        index_usage[idx_name][server.label] = row["scan_count"]
                        if idx_name not in index_meta:
                            index_meta[idx_name] = {
                                "index_name": idx_name,
                                "size_bytes": row["index_size"] or 0,
                            }
                finally:
                    await conn.close()
            except Exception as e:
                logger.debug("Could not fetch index stats from %s: %s", server.label, e)

        truly_unused: list[str] = []
        saved_by_replicas: list[dict[str, Any]] = []

        for idx_name, usage_by_server in index_usage.items():
            total_scans = sum(usage_by_server.values())
            primary_scans = 0
            replica_scans = 0
            used_on_servers: list[str] = []

            for server_label, count in usage_by_server.items():
                if count > 0:
                    used_on_servers.append(server_label)
                # Determine if this is primary or replica
                for server in cluster.all_servers:
                    if server.label == server_label:
                        if server.is_primary:
                            primary_scans = count
                        else:
                            replica_scans += count
                        break

            if total_scans == 0:
                # Unused on ALL servers → safe to drop
                truly_unused.append(idx_name)
            elif primary_scans == 0 and replica_scans > 0:
                # Unused on primary but USED on replicas → DO NOT DROP
                saved_by_replicas.append({
                    "index_name": idx_name,
                    "primary_scans": primary_scans,
                    "replica_scans": replica_scans,
                    "used_on": ", ".join(used_on_servers),
                    "size_bytes": index_meta.get(idx_name, {}).get("size_bytes", 0),
                })

        return {
            "truly_unused": truly_unused,
            "saved_by_replicas": saved_by_replicas,
        }
