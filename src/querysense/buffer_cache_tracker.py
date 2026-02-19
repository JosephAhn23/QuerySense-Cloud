"""
PostgreSQL Buffer Cache Tracker.

Continuous monitoring of pg_buffercache contents: which tables and indexes
occupy shared_buffers, how cache residency changes over time, and where
cache thrashing or outlier patterns emerge.

Based on pganalyze blog: Buffer Cache Statistics & System Memory dashboard.

Note: pg_buffercache scans all shared buffers and holds a lightweight lock.
On very large shared_buffers (>200 GB) this can take noticeable time;
the sampling_interval should be increased accordingly.

Usage:
    from querysense.buffer_cache_tracker import BufferCacheTracker
    tracker = BufferCacheTracker()
    snapshot = await tracker.take_snapshot(dsn)
    dashboard = tracker.get_dashboard()
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RelationCacheEntry:
    """Cache usage for a single relation (table or index)."""
    schema: str
    name: str
    kind: str  # 'table', 'index', 'toast', 'sequence'
    buffers: int
    size_mb: float = 0

    @property
    def full_name(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass
class BufferCacheSnapshot:
    """Point-in-time snapshot of buffer cache contents."""
    timestamp: datetime
    total_buffers: int
    buffers_used: int
    cache_hit_ratio: float
    relations: list[RelationCacheEntry] = field(default_factory=list)

    @property
    def utilization_pct(self) -> float:
        if self.total_buffers == 0:
            return 0
        return self.buffers_used / self.total_buffers * 100

    @property
    def top_tables(self) -> list[RelationCacheEntry]:
        return sorted(
            [r for r in self.relations if r.kind == "table"],
            key=lambda r: r.buffers, reverse=True,
        )[:15]

    @property
    def top_indexes(self) -> list[RelationCacheEntry]:
        return sorted(
            [r for r in self.relations if r.kind == "index"],
            key=lambda r: r.buffers, reverse=True,
        )[:15]


@dataclass
class TableCacheStats:
    """Aggregated cache statistics for a relation over time."""
    full_name: str
    avg_buffers: float
    peak_buffers: int
    min_buffers: int
    current_buffers: int
    in_cache_pct: float
    volatility: float  # stddev / mean — higher = more unstable


@dataclass
class CacheDashboard:
    """Dashboard data for buffer cache monitoring."""
    current: BufferCacheSnapshot | None = None
    snapshots_count: int = 0
    utilization_pct: float = 0
    hit_ratio_pct: float = 0
    top_tables: list[dict[str, Any]] = field(default_factory=list)
    top_indexes: list[dict[str, Any]] = field(default_factory=list)
    outliers: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    hit_ratio_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "utilization_pct": round(self.utilization_pct, 1),
            "hit_ratio_pct": round(self.hit_ratio_pct, 2),
            "snapshots": self.snapshots_count,
            "top_tables": self.top_tables[:10],
            "top_indexes": self.top_indexes[:10],
            "outliers": self.outliers[:5],
            "recommendations": self.recommendations,
        }


class BufferCacheTracker:
    """
    Track PostgreSQL buffer cache contents over time.

    Each call to take_snapshot() queries pg_buffercache and records
    per-relation buffer counts. Over multiple snapshots the tracker
    computes volatility, outliers, and cache recommendations.
    """

    BLOCK_SIZE = 8192  # PG default block size

    def __init__(self, max_snapshots: int = 288) -> None:
        # 288 snapshots = 24h at 5-min intervals
        self.max_snapshots = max_snapshots
        self.snapshots: list[BufferCacheSnapshot] = []

    async def take_snapshot(self, dsn: str) -> BufferCacheSnapshot:
        """Take a point-in-time snapshot of buffer cache."""
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            # Verify extension
            has_ext = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM pg_extension WHERE extname = 'pg_buffercache'
                )
            """)
            if not has_ext:
                raise RuntimeError(
                    "pg_buffercache extension not installed. "
                    "Run: CREATE EXTENSION pg_buffercache;"
                )

            total_buffers = await self._get_total_buffers(conn)

            # Per-relation cache usage
            rows = await conn.fetch("""
                SELECT
                    n.nspname AS schema_name,
                    c.relname AS relation_name,
                    c.relkind,
                    count(*) AS buffers,
                    pg_relation_size(c.oid) AS rel_size
                FROM pg_buffercache b
                JOIN pg_class c ON b.relfilenode = pg_relation_filenode(c.oid)
                    AND b.reldatabase IN (
                        0,
                        (SELECT oid FROM pg_database WHERE datname = current_database())
                    )
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname NOT LIKE 'pg_%'
                GROUP BY n.nspname, c.relname, c.relkind, c.oid
                ORDER BY buffers DESC
            """)

            kind_map = {"r": "table", "i": "index", "t": "toast", "S": "sequence"}
            relations: list[RelationCacheEntry] = []
            for r in rows:
                relations.append(RelationCacheEntry(
                    schema=r["schema_name"],
                    name=r["relation_name"],
                    kind=kind_map.get(r["relkind"], "other"),
                    buffers=r["buffers"],
                    size_mb=(r["rel_size"] or 0) / (1024 * 1024),
                ))

            hit_ratio = await self._get_hit_ratio(conn)

            snapshot = BufferCacheSnapshot(
                timestamp=datetime.now(),
                total_buffers=total_buffers,
                buffers_used=sum(r.buffers for r in relations),
                cache_hit_ratio=hit_ratio,
                relations=relations,
            )

            self.snapshots.append(snapshot)
            if len(self.snapshots) > self.max_snapshots:
                self.snapshots = self.snapshots[-self.max_snapshots:]

            return snapshot

        finally:
            await conn.close()

    def get_table_stats(self, full_name: str) -> TableCacheStats | None:
        """Get historical cache stats for a specific relation."""
        if not self.snapshots:
            return None

        values: list[int] = []
        for snap in self.snapshots:
            buffers = 0
            for rel in snap.relations:
                if rel.full_name == full_name:
                    buffers = rel.buffers
                    break
            values.append(buffers)

        if not values or max(values) == 0:
            return None

        avg = sum(values) / len(values)
        variance = sum((v - avg) ** 2 for v in values) / len(values)
        stddev = math.sqrt(variance)
        volatility = stddev / avg if avg > 0 else 0

        latest = self.snapshots[-1]
        current = 0
        for rel in latest.relations:
            if rel.full_name == full_name:
                current = rel.buffers
                break

        return TableCacheStats(
            full_name=full_name,
            avg_buffers=round(avg, 1),
            peak_buffers=max(values),
            min_buffers=min(values),
            current_buffers=current,
            in_cache_pct=round(current / latest.total_buffers * 100, 2)
                if latest.total_buffers > 0 else 0,
            volatility=round(volatility, 3),
        )

    def get_dashboard(self) -> CacheDashboard:
        """Generate dashboard data from collected snapshots."""
        dashboard = CacheDashboard(snapshots_count=len(self.snapshots))

        if not self.snapshots:
            return dashboard

        latest = self.snapshots[-1]
        dashboard.current = latest
        dashboard.utilization_pct = latest.utilization_pct
        dashboard.hit_ratio_pct = latest.cache_hit_ratio * 100

        # Top tables
        for rel in latest.top_tables[:10]:
            dashboard.top_tables.append({
                "name": rel.full_name,
                "buffers": rel.buffers,
                "size_mb": round(rel.size_mb, 1),
            })

        # Top indexes
        for rel in latest.top_indexes[:10]:
            dashboard.top_indexes.append({
                "name": rel.full_name,
                "buffers": rel.buffers,
                "size_mb": round(rel.size_mb, 1),
            })

        # Hit ratio history
        for snap in self.snapshots[-48:]:
            dashboard.hit_ratio_history.append({
                "ts": snap.timestamp.isoformat(),
                "ratio": round(snap.cache_hit_ratio * 100, 2),
            })

        # Outliers: high current usage but low historical presence
        dashboard.outliers = self._find_outliers()

        # Recommendations
        dashboard.recommendations = self._generate_recommendations()

        return dashboard

    # ── Internal ─────────────────────────────────────────────────────

    async def _get_total_buffers(self, conn: Any) -> int:
        raw = await conn.fetchval("SHOW shared_buffers")
        return self._parse_mem(raw) // self.BLOCK_SIZE

    async def _get_hit_ratio(self, conn: Any) -> float:
        row = await conn.fetchrow("""
            SELECT
                sum(heap_blks_hit) AS hits,
                sum(heap_blks_read) AS reads
            FROM pg_statio_user_tables
        """)
        if not row:
            return 0
        hits = row["hits"] or 0
        reads = row["reads"] or 0
        total = hits + reads
        return hits / total if total > 0 else 1.0

    @staticmethod
    def _parse_mem(setting: str) -> int:
        m = re.match(r"(\d+)\s*([kKmMgGtT]?[bB]?)", setting.strip())
        if not m:
            return 0
        val = int(m.group(1))
        unit = m.group(2).lower()
        if "g" in unit:
            return val * 1024 * 1024 * 1024
        if "m" in unit:
            return val * 1024 * 1024
        if "k" in unit:
            return val * 1024
        # PG SHOW returns in 8kB units when no suffix
        return val * 8192

    def _find_outliers(self) -> list[dict[str, Any]]:
        """Relations with high current cache usage but low historical presence."""
        if len(self.snapshots) < 3:
            return []

        latest = self.snapshots[-1]
        recent = self.snapshots[-10:]
        outliers: list[dict[str, Any]] = []

        for rel in latest.relations:
            if rel.buffers < 500:
                continue
            presence = sum(
                1 for snap in recent
                if any(r.full_name == rel.full_name for r in snap.relations)
            ) / len(recent)

            if presence < 0.4:
                outliers.append({
                    "name": rel.full_name,
                    "buffers": rel.buffers,
                    "presence_ratio": round(presence, 2),
                    "note": "High cache usage but intermittent presence — possible cache thrashing",
                })

        return sorted(outliers, key=lambda o: o["buffers"], reverse=True)[:5]

    def _generate_recommendations(self) -> list[dict[str, Any]]:
        if len(self.snapshots) < 5:
            return []

        recs: list[dict[str, Any]] = []
        latest = self.snapshots[-1]

        # Low hit ratio
        if latest.cache_hit_ratio < 0.95:
            recs.append({
                "severity": "WARNING",
                "message": (
                    f"Cache hit ratio is {latest.cache_hit_ratio:.1%} — "
                    "below 95% target. Consider increasing shared_buffers."
                ),
            })

        # High utilization
        if latest.utilization_pct > 95:
            recs.append({
                "severity": "WARNING",
                "message": (
                    f"Buffer cache is {latest.utilization_pct:.0f}% full. "
                    "Working set may exceed shared_buffers."
                ),
            })

        # Check for volatile tables
        for rel in latest.top_tables[:5]:
            stats = self.get_table_stats(rel.full_name)
            if stats and stats.volatility > 0.5:
                recs.append({
                    "severity": "INFO",
                    "message": (
                        f"{rel.full_name}: high cache volatility "
                        f"({stats.volatility:.2f}) — competing workloads "
                        "or large sequential scans evicting data."
                    ),
                })

        return recs
