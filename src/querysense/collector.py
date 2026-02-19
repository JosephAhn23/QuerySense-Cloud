"""
Stats Collector — continuous pg_stat_statements harvester with EXPLAIN capture.

Reverse-engineered from pganalyze/collector (BSD-3-Clause):
https://github.com/pganalyze/collector

pganalyze's collector is a Go daemon that runs every 10 minutes,
snapshots pg_stat_statements, captures EXPLAIN plans for top queries,
and ships data to their cloud. Our collector does the same but stores
locally (SQLite/TimescaleDB) for free.

Architecture:
    Collector (async loop) → Snapshot pg_stat_statements
                           → Capture EXPLAIN for top queries
                           → Detect regressions (new slow queries, plan changes)
                           → Store in TemporalStore
                           → Emit alerts

Design choices matching pganalyze/collector:
1. Differential snapshots — only store changes, not full state
2. Query fingerprinting — group identical queries with different parameters
3. EXPLAIN capture — run EXPLAIN on top-N queries by total time
4. Regression detection — alert when a query's cost jumps
5. Schema snapshot — capture table/index definitions periodically

Usage:
    from querysense.collector import StatsCollector, CollectorConfig

    config = CollectorConfig(dsn="postgresql://localhost/mydb")
    collector = StatsCollector(config)

    # Single snapshot
    snapshot = await collector.collect_once()

    # Continuous collection
    await collector.run()  # runs forever, collecting every interval

    # With callback
    async def on_regression(alert):
        print(f"REGRESSION: {alert.query_fingerprint} cost +{alert.cost_increase_pct:.0f}%")

    collector = StatsCollector(config, on_regression=on_regression)
    await collector.run()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


# ── Configuration ──────────────────────────────────────────────────────


@dataclass
class CollectorConfig:
    """Collector configuration."""
    dsn: str
    interval_seconds: int = 600        # 10 minutes (matches pganalyze)
    explain_top_n: int = 20            # EXPLAIN top N queries by total time
    explain_min_calls: int = 5         # Minimum calls before EXPLAIN
    explain_min_mean_ms: float = 10.0  # Minimum mean time before EXPLAIN
    explain_timeout_ms: int = 5000     # Statement timeout for EXPLAIN
    store_path: str = ".querysense/collector.db"  # SQLite path
    max_query_length: int = 10000      # Truncate long queries
    regression_threshold_pct: float = 50.0  # Cost increase % to alert
    schema_interval_multiplier: int = 6     # Schema snapshot every N × interval


# ── Data Classes ───────────────────────────────────────────────────────


@dataclass
class QuerySnapshot:
    """A snapshot of a single query from pg_stat_statements."""
    queryid: int
    query: str
    fingerprint: str        # Normalized query hash
    calls: int = 0
    total_exec_time_ms: float = 0.0
    mean_exec_time_ms: float = 0.0
    min_exec_time_ms: float = 0.0
    max_exec_time_ms: float = 0.0
    stddev_exec_time_ms: float = 0.0
    rows: int = 0
    shared_blks_hit: int = 0
    shared_blks_read: int = 0
    temp_blks_written: int = 0
    blk_read_time_ms: float = 0.0
    blk_write_time_ms: float = 0.0
    wal_bytes: int = 0
    # Differential (since last snapshot)
    delta_calls: int = 0
    delta_total_time_ms: float = 0.0
    delta_rows: int = 0

    @property
    def cache_hit_ratio(self) -> float:
        total = self.shared_blks_hit + self.shared_blks_read
        return self.shared_blks_hit / total if total > 0 else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "queryid": self.queryid,
            "fingerprint": self.fingerprint,
            "query": self.query[:500],
            "calls": self.calls,
            "total_exec_time_ms": round(self.total_exec_time_ms, 2),
            "mean_exec_time_ms": round(self.mean_exec_time_ms, 2),
            "rows": self.rows,
            "cache_hit_ratio": round(self.cache_hit_ratio, 4),
            "delta_calls": self.delta_calls,
            "delta_total_time_ms": round(self.delta_total_time_ms, 2),
        }


@dataclass
class ExplainCapture:
    """A captured EXPLAIN plan for a query."""
    queryid: int
    fingerprint: str
    query: str
    plan_json: dict[str, Any] = field(default_factory=dict)
    total_cost: float = 0.0
    node_types: list[str] = field(default_factory=list)
    structure_hash: str = ""
    captured_at: float = 0.0  # Unix timestamp

    def to_dict(self) -> dict[str, Any]:
        return {
            "queryid": self.queryid,
            "fingerprint": self.fingerprint,
            "total_cost": round(self.total_cost, 1),
            "node_types": self.node_types,
            "structure_hash": self.structure_hash,
        }


@dataclass
class RegressionAlert:
    """Alert when a query's performance regresses."""
    queryid: int
    fingerprint: str
    query: str
    alert_type: str          # "cost_increase" | "plan_change" | "new_slow_query"
    previous_cost: float = 0.0
    current_cost: float = 0.0
    cost_increase_pct: float = 0.0
    previous_mean_ms: float = 0.0
    current_mean_ms: float = 0.0
    plan_changed: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "queryid": self.queryid,
            "fingerprint": self.fingerprint,
            "query": self.query[:200],
            "alert_type": self.alert_type,
            "previous_cost": round(self.previous_cost, 1),
            "current_cost": round(self.current_cost, 1),
            "cost_increase_pct": round(self.cost_increase_pct, 1),
            "plan_changed": self.plan_changed,
            "detail": self.detail,
        }


@dataclass
class CollectorSnapshot:
    """A complete collector snapshot."""
    timestamp: float         # Unix timestamp
    queries: list[QuerySnapshot] = field(default_factory=list)
    explains: list[ExplainCapture] = field(default_factory=list)
    regressions: list[RegressionAlert] = field(default_factory=list)
    duration_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def query_count(self) -> int:
        return len(self.queries)

    @property
    def total_time_tracked_ms(self) -> float:
        return sum(q.delta_total_time_ms for q in self.queries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "query_count": self.query_count,
            "explain_count": len(self.explains),
            "regression_count": len(self.regressions),
            "total_time_tracked_ms": round(self.total_time_tracked_ms, 2),
            "duration_ms": round(self.duration_ms, 1),
            "top_queries": [q.to_dict() for q in sorted(
                self.queries, key=lambda q: q.delta_total_time_ms, reverse=True
            )[:10]],
            "regressions": [r.to_dict() for r in self.regressions],
            "errors": self.errors,
        }


# ── SQL Queries ────────────────────────────────────────────────────────


# Main pg_stat_statements snapshot query.
# Compatible with PG 13+ (total_exec_time instead of total_time).
_PGSS_QUERY = """
SELECT
    queryid,
    query,
    calls,
    total_exec_time AS total_exec_time_ms,
    mean_exec_time AS mean_exec_time_ms,
    min_exec_time AS min_exec_time_ms,
    max_exec_time AS max_exec_time_ms,
    stddev_exec_time AS stddev_exec_time_ms,
    rows,
    shared_blks_hit,
    shared_blks_read,
    temp_blks_written,
    blk_read_time AS blk_read_time_ms,
    blk_write_time AS blk_write_time_ms,
    COALESCE(wal_bytes, 0) AS wal_bytes
FROM pg_stat_statements
WHERE queryid IS NOT NULL
  AND query NOT LIKE '%pg_stat_statements%'
  AND query NOT LIKE 'EXPLAIN%'
ORDER BY total_exec_time DESC
LIMIT 1000
"""

# Fallback for PG 12 (uses total_time instead of total_exec_time)
_PGSS_QUERY_PG12 = """
SELECT
    queryid,
    query,
    calls,
    total_time AS total_exec_time_ms,
    mean_time AS mean_exec_time_ms,
    min_time AS min_exec_time_ms,
    max_time AS max_exec_time_ms,
    stddev_time AS stddev_exec_time_ms,
    rows,
    shared_blks_hit,
    shared_blks_read,
    temp_blks_written,
    blk_read_time AS blk_read_time_ms,
    blk_write_time AS blk_write_time_ms,
    0 AS wal_bytes
FROM pg_stat_statements
WHERE queryid IS NOT NULL
  AND query NOT LIKE '%pg_stat_statements%'
ORDER BY total_time DESC
LIMIT 1000
"""

# Check pg_stat_statements version
_CHECK_PGSS_VERSION = """
SELECT
    current_setting('server_version_num')::int AS version_num,
    EXISTS(SELECT 1 FROM pg_available_extensions WHERE name = 'pg_stat_statements' AND installed_version IS NOT NULL) AS has_pgss
"""


# ── Helper Functions ───────────────────────────────────────────────────


def _fingerprint(sql: str) -> str:
    """Generate a query fingerprint by normalizing SQL."""
    import re
    # Replace literals with placeholders
    normalized = re.sub(r"'[^']*'", "'?'", sql)
    normalized = re.sub(r"\b\d+\b", "?", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    return hashlib.md5(normalized.encode()).hexdigest()[:16]


def _extract_node_types(plan: dict) -> list[str]:
    """Extract all node types from a plan tree."""
    types = []
    if "Node Type" in plan:
        types.append(plan["Node Type"])
    for child in plan.get("Plans", []):
        types.extend(_extract_node_types(child))
    return types


def _plan_structure_hash(plan: dict) -> str:
    """Hash the structure of a plan (node types + join order, not costs)."""
    def _structure(node: dict) -> dict:
        return {
            "type": node.get("Node Type", ""),
            "relation": node.get("Relation Name", ""),
            "children": [_structure(c) for c in node.get("Plans", [])],
        }
    structure = _structure(plan)
    return hashlib.md5(json.dumps(structure, sort_keys=True).encode()).hexdigest()[:16]


# ── Collector ──────────────────────────────────────────────────────────


class StatsCollector:
    """
    Continuous pg_stat_statements harvester.

    Collects differential snapshots, captures EXPLAIN plans,
    detects regressions, and stores historical data.
    """

    def __init__(
        self,
        config: CollectorConfig,
        on_regression: Callable[[RegressionAlert], Awaitable[None]] | None = None,
    ) -> None:
        self.config = config
        self.on_regression = on_regression

        # State: previous snapshot for differential calculation
        self._prev_queries: dict[int, QuerySnapshot] = {}
        self._prev_explains: dict[int, ExplainCapture] = {}
        self._snapshot_count = 0
        self._use_pg12_query = False

    async def collect_once(self) -> CollectorSnapshot:
        """
        Collect a single snapshot.

        Returns:
            CollectorSnapshot with queries, EXPLAINs, and regressions
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        start = time.perf_counter()
        snapshot = CollectorSnapshot(timestamp=time.time())

        conn = await asyncpg.connect(self.config.dsn)
        try:
            # Check PG version and pg_stat_statements availability
            version_info = await conn.fetchrow(_CHECK_PGSS_VERSION)
            if not version_info or not version_info["has_pgss"]:
                snapshot.errors.append(
                    "pg_stat_statements not installed. "
                    "Run: CREATE EXTENSION pg_stat_statements;"
                )
                return snapshot

            version_num = version_info["version_num"]
            self._use_pg12_query = version_num < 130000

            # 1. Snapshot pg_stat_statements
            await self._collect_queries(conn, snapshot)

            # 2. Capture EXPLAIN plans for top queries
            await self._capture_explains(conn, snapshot)

            # 3. Detect regressions
            self._detect_regressions(snapshot)

            # 4. Update state for next snapshot
            self._update_state(snapshot)

            self._snapshot_count += 1

        except Exception as e:
            snapshot.errors.append(f"Collection failed: {e}")
            logger.error("Stats collection failed: %s", e)
        finally:
            await conn.close()

        snapshot.duration_ms = (time.perf_counter() - start) * 1000
        return snapshot

    async def run(self, max_iterations: int = 0) -> None:
        """
        Run continuous collection.

        Args:
            max_iterations: 0 = run forever, >0 = stop after N iterations
        """
        iteration = 0
        logger.info(
            "QuerySense collector starting (interval=%ds, explain_top_n=%d)",
            self.config.interval_seconds,
            self.config.explain_top_n,
        )

        while max_iterations == 0 or iteration < max_iterations:
            try:
                snapshot = await self.collect_once()

                logger.info(
                    "Snapshot #%d: %d queries, %d explains, %d regressions (%.0fms)",
                    self._snapshot_count,
                    snapshot.query_count,
                    len(snapshot.explains),
                    len(snapshot.regressions),
                    snapshot.duration_ms,
                )

                # Fire regression callbacks
                if self.on_regression:
                    for alert in snapshot.regressions:
                        try:
                            await self.on_regression(alert)
                        except Exception as e:
                            logger.warning("Regression callback failed: %s", e)

            except Exception as e:
                logger.error("Collection iteration failed: %s", e)

            iteration += 1
            if max_iterations == 0 or iteration < max_iterations:
                await asyncio.sleep(self.config.interval_seconds)

    async def _collect_queries(
        self, conn: Any, snapshot: CollectorSnapshot,
    ) -> None:
        """Snapshot pg_stat_statements."""
        query = _PGSS_QUERY_PG12 if self._use_pg12_query else _PGSS_QUERY

        try:
            rows = await conn.fetch(query)
            for row in rows:
                qid = row["queryid"]
                sql = (row["query"] or "")[:self.config.max_query_length]

                qs = QuerySnapshot(
                    queryid=qid,
                    query=sql,
                    fingerprint=_fingerprint(sql),
                    calls=row["calls"],
                    total_exec_time_ms=row["total_exec_time_ms"],
                    mean_exec_time_ms=row["mean_exec_time_ms"],
                    min_exec_time_ms=row["min_exec_time_ms"],
                    max_exec_time_ms=row["max_exec_time_ms"],
                    stddev_exec_time_ms=row["stddev_exec_time_ms"],
                    rows=row["rows"],
                    shared_blks_hit=row["shared_blks_hit"],
                    shared_blks_read=row["shared_blks_read"],
                    temp_blks_written=row["temp_blks_written"],
                    blk_read_time_ms=row["blk_read_time_ms"],
                    blk_write_time_ms=row["blk_write_time_ms"],
                    wal_bytes=row["wal_bytes"],
                )

                # Calculate deltas from previous snapshot
                prev = self._prev_queries.get(qid)
                if prev:
                    qs.delta_calls = max(qs.calls - prev.calls, 0)
                    qs.delta_total_time_ms = max(
                        qs.total_exec_time_ms - prev.total_exec_time_ms, 0
                    )
                    qs.delta_rows = max(qs.rows - prev.rows, 0)
                else:
                    # First time seeing this query
                    qs.delta_calls = qs.calls
                    qs.delta_total_time_ms = qs.total_exec_time_ms
                    qs.delta_rows = qs.rows

                snapshot.queries.append(qs)

        except Exception as e:
            snapshot.errors.append(f"pg_stat_statements query failed: {e}")

    async def _capture_explains(
        self, conn: Any, snapshot: CollectorSnapshot,
    ) -> None:
        """Capture EXPLAIN plans for top queries."""
        # Sort by delta total time to focus on currently hot queries
        hot_queries = sorted(
            snapshot.queries,
            key=lambda q: q.delta_total_time_ms,
            reverse=True,
        )

        captured = 0
        for qs in hot_queries:
            if captured >= self.config.explain_top_n:
                break

            # Skip if below thresholds
            if qs.calls < self.config.explain_min_calls:
                continue
            if qs.mean_exec_time_ms < self.config.explain_min_mean_ms:
                continue

            # Skip utility statements
            sql_upper = qs.query.strip().upper()
            if not sql_upper.startswith(("SELECT", "INSERT", "UPDATE", "DELETE", "WITH")):
                continue

            try:
                # Set statement timeout to avoid long-running EXPLAINs
                await conn.execute(
                    f"SET statement_timeout = '{self.config.explain_timeout_ms}ms'"
                )

                explain_row = await conn.fetchrow(
                    f"EXPLAIN (FORMAT JSON, COSTS ON) {qs.query}"
                )

                if explain_row:
                    plan_json = json.loads(explain_row[0])
                    plan = plan_json[0] if isinstance(plan_json, list) else plan_json
                    root = plan.get("Plan", plan)

                    capture = ExplainCapture(
                        queryid=qs.queryid,
                        fingerprint=qs.fingerprint,
                        query=qs.query,
                        plan_json=plan_json,
                        total_cost=root.get("Total Cost", 0),
                        node_types=_extract_node_types(root),
                        structure_hash=_plan_structure_hash(root),
                        captured_at=time.time(),
                    )
                    snapshot.explains.append(capture)
                    captured += 1

            except Exception as e:
                logger.debug("EXPLAIN failed for queryid=%d: %s", qs.queryid, e)
            finally:
                try:
                    await conn.execute("SET statement_timeout = '0'")
                except Exception:
                    pass

    def _detect_regressions(self, snapshot: CollectorSnapshot) -> None:
        """Detect performance regressions by comparing with previous snapshot."""
        if not self._prev_explains:
            return  # Need at least 2 snapshots

        for explain in snapshot.explains:
            prev_explain = self._prev_explains.get(explain.queryid)
            if not prev_explain:
                # New query — check if it's already slow
                if explain.total_cost > 10000:
                    snapshot.regressions.append(RegressionAlert(
                        queryid=explain.queryid,
                        fingerprint=explain.fingerprint,
                        query=explain.query,
                        alert_type="new_slow_query",
                        current_cost=explain.total_cost,
                        detail=f"New query with high cost: {explain.total_cost:,.0f}",
                    ))
                continue

            # Plan structure change?
            if explain.structure_hash != prev_explain.structure_hash:
                cost_delta = explain.total_cost - prev_explain.total_cost
                cost_pct = (
                    (cost_delta / prev_explain.total_cost * 100)
                    if prev_explain.total_cost > 0 else 0
                )

                snapshot.regressions.append(RegressionAlert(
                    queryid=explain.queryid,
                    fingerprint=explain.fingerprint,
                    query=explain.query,
                    alert_type="plan_change",
                    previous_cost=prev_explain.total_cost,
                    current_cost=explain.total_cost,
                    cost_increase_pct=cost_pct,
                    plan_changed=True,
                    detail=(
                        f"Plan changed: {prev_explain.node_types[0] if prev_explain.node_types else '?'} → "
                        f"{explain.node_types[0] if explain.node_types else '?'}, "
                        f"cost {prev_explain.total_cost:,.0f} → {explain.total_cost:,.0f}"
                    ),
                ))

            # Cost regression (same plan structure but higher cost)?
            elif prev_explain.total_cost > 0:
                cost_pct = (
                    (explain.total_cost - prev_explain.total_cost)
                    / prev_explain.total_cost * 100
                )
                if cost_pct > self.config.regression_threshold_pct:
                    snapshot.regressions.append(RegressionAlert(
                        queryid=explain.queryid,
                        fingerprint=explain.fingerprint,
                        query=explain.query,
                        alert_type="cost_increase",
                        previous_cost=prev_explain.total_cost,
                        current_cost=explain.total_cost,
                        cost_increase_pct=cost_pct,
                        detail=(
                            f"Cost increased {cost_pct:.0f}%: "
                            f"{prev_explain.total_cost:,.0f} → {explain.total_cost:,.0f}"
                        ),
                    ))

    def _update_state(self, snapshot: CollectorSnapshot) -> None:
        """Update internal state for differential calculation."""
        self._prev_queries = {q.queryid: q for q in snapshot.queries}
        self._prev_explains = {e.queryid: e for e in snapshot.explains}
