"""
querysense/benchmark.py

Features derived from pganalyze blog posts:
  1. BufferCacheEvict   - evict tables/indexes from Postgres shared buffer cache
                          (pg_buffercache_evict, Postgres 17+)
  2. DoubleBufferProbe  - detect OS page cache vs shared buffer cache effects;
                          warn when "shared read" is deceptively fast
  3. SAOPAnalyzer       - detect IN-list / ANY= queries that generate excessive
                          primitive index scans, and flag Postgres 17 upgrade wins
  4. BenchmarkRunner    - orchestrate cold/warm/hot cache benchmark runs cleanly

Usage:
    from querysense.benchmark import BenchmarkRunner, SAOPAnalyzer

    # Detect IN-list primitive scan problem from an EXPLAIN JSON
    analyzer = SAOPAnalyzer()
    findings = analyzer.analyze(explain_json)

    # Run a reproducible cache benchmark
    async with BenchmarkRunner(dsn) as bench:
        result = await bench.run(sql, cache_mode="cold")
        print(result)
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import re
import textwrap
from typing import Any, Optional

__all__ = [
    "CacheMode",
    "BenchmarkResult",
    "BufferCacheEvict",
    "DoubleBufferProbe",
    "SAOPAnalyzer",
    "SAOPFinding",
    "BenchmarkRunner",
]


# ---------------------------------------------------------------------------
# 1. Enumerations / data classes
# ---------------------------------------------------------------------------

class CacheMode(enum.Enum):
    """Which caches are warm when the benchmark query runs."""
    HOT = "hot"      # shared buffers + OS page cache both warm
    WARM = "warm"    # only OS page cache warm (shared buffers evicted)
    COLD = "cold"    # both caches empty (requires superuser + Linux)


@dataclasses.dataclass
class BufferStats:
    shared_hit: int = 0
    shared_read: int = 0
    local_hit: int = 0
    local_read: int = 0

    @property
    def total_blocks(self) -> int:
        return self.shared_hit + self.shared_read

    @property
    def hit_rate(self) -> float:
        if self.total_blocks == 0:
            return 0.0
        return self.shared_hit / self.total_blocks


@dataclasses.dataclass
class BenchmarkResult:
    sql: str
    cache_mode: CacheMode
    planning_time_ms: float
    execution_time_ms: float
    buffers: BufferStats
    rows: int
    iterations: int = 1
    pg_version: Optional[str] = None
    warnings: list[str] = dataclasses.field(default_factory=list)

    def __str__(self) -> str:
        hit_pct = self.buffers.hit_rate * 100
        lines = [
            f"Cache mode     : {self.cache_mode.value}",
            f"Planning time  : {self.planning_time_ms:.3f} ms",
            f"Execution time : {self.execution_time_ms:.3f} ms",
            f"Rows returned  : {self.rows}",
            f"Shared buffers : {self.buffers.shared_hit:,} hit / {self.buffers.shared_read:,} read  ({hit_pct:.1f}% hit rate)",
        ]
        if self.warnings:
            lines.append("")
            for w in self.warnings:
                lines.append(f"  WARNING: {w}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2. BufferCacheEvict - shared buffer eviction (requires pg_buffercache)
# ---------------------------------------------------------------------------

class BufferCacheEvict:
    """
    Evict specific tables or indexes from PostgreSQL shared buffer cache.

    Requires:
        - pg_buffercache extension
        - Postgres 17+ for pg_buffercache_evict()
        - Superuser or pg_monitor role

    Intended for testing/benchmarking only.
    """

    _ENSURE_EXT_SQL = "CREATE EXTENSION IF NOT EXISTS pg_buffercache"
    _VERSION_SQL = "SELECT current_setting('server_version_num')::int"

    _EVICT_SQL = textwrap.dedent("""\
        SELECT
            count(*) FILTER (WHERE pg_buffercache_evict(bufferid) IS TRUE) AS evicted,
            count(*)                                                        AS total
        FROM pg_buffercache
        WHERE relfilenode = pg_relation_filenode($1::regclass)
    """)

    _EVICT_ALL_SQL = textwrap.dedent("""\
        SELECT
            count(*) FILTER (WHERE pg_buffercache_evict(bufferid) IS TRUE) AS evicted,
            count(*)                                                        AS total
        FROM pg_buffercache
        WHERE relfilenode IS NOT NULL
    """)

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._pg_version: Optional[int] = None

    async def ensure_extension(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(self._ENSURE_EXT_SQL)
            self._pg_version = await conn.fetchval(self._VERSION_SQL)

    async def check_version(self) -> tuple[bool, str]:
        """Returns (supported, message). pg_buffercache_evict requires PG 17+."""
        async with self._pool.acquire() as conn:
            ver = await conn.fetchval(self._VERSION_SQL)
        if ver >= 170000:
            return True, f"Postgres {ver} supports pg_buffercache_evict"
        return False, (
            f"pg_buffercache_evict requires Postgres 17+ (you have {ver}). "
            "On older versions, restart Postgres or use OS-level cache eviction."
        )

    async def evict_relation(self, relation: str) -> dict[str, int]:
        """Evict all shared buffer pages for *relation*."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(self._EVICT_SQL, relation)
        return {"evicted": row["evicted"], "total": row["total"]}

    async def evict_all(self) -> dict[str, int]:
        """Evict ALL user-relation pages from shared buffers."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(self._EVICT_ALL_SQL)
        return {"evicted": row["evicted"], "total": row["total"]}

    async def load_relation(self, relation: str) -> int:
        """Pre-warm *relation* into shared buffers via pg_prewarm."""
        async with self._pool.acquire() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS pg_prewarm")
            blocks = await conn.fetchval(
                "SELECT pg_prewarm($1::regclass)", relation
            )
        return blocks

    async def buffer_contents(self, top_n: int = 20) -> list[dict]:
        """Return top-N relations by buffer count in shared cache."""
        sql = textwrap.dedent("""\
            SELECT
                n.nspname                       AS schema,
                c.relname                       AS relation,
                c.relkind                       AS kind,
                count(*)                        AS buffers,
                count(*) * 8 / 1024             AS size_mb
            FROM pg_buffercache b
            JOIN pg_class     c ON b.relfilenode = pg_relation_filenode(c.oid)
                               AND b.reldatabase IN (
                                       0,
                                       (SELECT oid FROM pg_database
                                         WHERE datname = current_database())
                                   )
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE b.relfilenode IS NOT NULL
            GROUP BY n.nspname, c.relname, c.relkind
            ORDER BY 4 DESC
            LIMIT $1
        """)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, top_n)
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# 3. DoubleBufferProbe - detect OS page cache masking cold latency
# ---------------------------------------------------------------------------

class DoubleBufferProbe:
    """
    Detect "double buffering" - Postgres evicts shared buffer cache but the
    OS page cache still serves data quickly, making "shared read" look as fast
    as "shared hit".

    From pganalyze: "The performance didn't really change... The reason is
    that the table is still in the operating system's internal caches."
    """

    _MS_PER_MB_DISK_FLOOR = 5.0
    _READ_RATIO_THRESHOLD = 0.5

    def __init__(
        self,
        ms_per_mb_disk_floor: float = _MS_PER_MB_DISK_FLOOR,
        read_ratio_threshold: float = _READ_RATIO_THRESHOLD,
    ) -> None:
        self.ms_per_mb_disk_floor = ms_per_mb_disk_floor
        self.read_ratio_threshold = read_ratio_threshold

    def analyze(self, result: BenchmarkResult) -> list[str]:
        """Inspect a BenchmarkResult and return warning strings."""
        warnings: list[str] = []
        stats = result.buffers

        if stats.total_blocks == 0:
            return warnings

        read_ratio = stats.shared_read / stats.total_blocks
        if read_ratio < self.read_ratio_threshold:
            return warnings

        mb_read = stats.shared_read * 8 / 1024
        if mb_read == 0:
            return warnings

        ms_per_mb = result.execution_time_ms / mb_read

        if ms_per_mb < self.ms_per_mb_disk_floor:
            warnings.append(
                f"Double-buffering suspected: {stats.shared_read} blocks reported as "
                f"'shared read' (disk) but execution was {result.execution_time_ms:.1f} ms "
                f"({ms_per_mb:.2f} ms/MB). Genuine disk I/O rarely exceeds "
                f"{self.ms_per_mb_disk_floor} ms/MB. "
                "The OS page cache is likely still serving this data. "
                "Run the OS page cache flush commands below for a true cold-cache test."
            )

        if result.cache_mode == CacheMode.WARM:
            warnings.append(
                "Cache mode is WARM (shared buffers evicted, OS page cache intact). "
                "Execution time reflects OS page cache speed, not true disk I/O."
            )

        return warnings

    @staticmethod
    def os_evict_commands(data_dir: str, relation_filepath: str) -> str:
        """Return Linux shell commands to flush a file from the OS page cache."""
        full_path = f"{data_dir.rstrip('/')}/{relation_filepath}"
        return textwrap.dedent(f"""\
            # 1. Check what's currently in the OS page cache for this file:
            fincore {full_path}

            # 2. Evict the file from the OS page cache (requires filesystem access):
            dd oflag=nocache conv=notrunc,fdatasync count=0 of={full_path}

            # 3. Confirm it was evicted (RES should now be 0B):
            fincore {full_path}

            # NOTE: Uses POSIX_FADV_DONTNEED hint via dd's oflag=nocache.
            # Does NOT modify the file (count=0, conv=notrunc).
        """)

    @staticmethod
    def get_filepath_sql(relation: str) -> str:
        """SQL to retrieve a relation's physical filepath."""
        return (
            f"SELECT current_setting('data_directory') || '/' "
            f"    || pg_relation_filepath('{relation}');"
        )

    @staticmethod
    def check_fincore_sql() -> str:
        """SQL to verify how much of a relation is in the OS page cache."""
        return textwrap.dedent("""\
            -- pg_prewarm can tell you how many blocks are cached at the OS level:
            SELECT pg_prewarm('your_table', 'prefetch');
        """)


# ---------------------------------------------------------------------------
# 4. SAOPAnalyzer - IN-list / ANY= primitive index scan detector
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class SAOPFinding:
    """A single finding from the SAOP analyzer."""
    severity: str       # "CRITICAL" | "WARNING" | "INFO"
    title: str
    detail: str
    suggestion: str
    score: float        # 0-10 impact score
    pg17_win: bool = False


class SAOPAnalyzer:
    """
    Analyze EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) output to detect queries
    that generate excessive "primitive" B-tree index scans due to IN lists or
    ANY= operators (ScalarArrayOpExpr / SAOP).

    On PG 16 and earlier, each value in an IN list triggers a separate
    _bt_first() call. PG 17 processes the whole array in one scan.
    """

    _SAOP_PATTERN = re.compile(r"= ANY \(|IN \(|NOT IN \(", re.IGNORECASE)
    _IN_LIST_DETAIL = re.compile(r"'(\{[^}]+\})'::[\w\[\]]+", re.IGNORECASE)
    _BTREE_NODES = {"Bitmap Index Scan", "Index Scan", "Index Only Scan"}

    def analyze(self, plan: list | dict) -> list[SAOPFinding]:
        if isinstance(plan, list):
            plan = plan[0]

        findings: list[SAOPFinding] = []
        self._walk(plan.get("Plan", plan), findings)
        findings.sort(key=lambda f: f.score, reverse=True)
        return findings

    def _walk(self, node: dict, findings: list[SAOPFinding]) -> None:
        node_type = node.get("Node Type", "")
        self._check_node(node, node_type, findings)
        for child in node.get("Plans", []):
            self._walk(child, findings)

    def _check_node(
        self, node: dict, node_type: str, findings: list[SAOPFinding]
    ) -> None:
        index_cond = node.get("Index Cond", "")
        recheck_cond = node.get("Recheck Cond", "")
        filter_cond = node.get("Filter", "")
        all_cond = " ".join([index_cond, recheck_cond, filter_cond])

        # 1. B-tree scan with ANY= in the index condition
        if node_type in self._BTREE_NODES and self._SAOP_PATTERN.search(all_cond):
            in_values = self._IN_LIST_DETAIL.findall(all_cond)
            value_counts = [len(v.split(",")) for v in in_values]
            max_values = max(value_counts) if value_counts else 1
            multi_col = len(in_values) > 1

            shared_hit = node.get("Shared Hit Blocks", 0)
            shared_read = node.get("Shared Read Blocks", 0)
            total_buffers = shared_hit + shared_read
            estimated_wasted = max(0, total_buffers - total_buffers // max_values)
            score = min(9.5, 3.5 + (max_values * 0.3) + (2.5 if multi_col else 0.0))

            if multi_col:
                title = (
                    f"Multi-column SAOP scan: {len(in_values)} IN-list columns "
                    f"(up to {max_values} values each)"
                )
                detail = (
                    f"Node '{node_type}' on '{node.get('Index Name', '?')}' has "
                    f"{len(in_values)} columns with IN-list filters. On Postgres 16 "
                    f"this executes up to {max_values ** len(in_values)} primitive "
                    f"index scans per loop. Postgres 17's MDAM technique handles "
                    f"multi-dimensional arrays in a single traversal."
                )
                suggestion = (
                    "Upgrade to Postgres 17 for automatic improvement. "
                    "Alternatively, rewrite using JOIN against VALUES() or a temp table."
                )
            elif max_values >= 10:
                title = f"Long IN list ({max_values} values) on B-tree index scan"
                detail = (
                    f"Node '{node_type}' processes a {max_values}-element array. "
                    f"On PG16 this triggers {max_values} separate B-tree traversals, "
                    f"hitting ~{total_buffers} buffer pages. PG17 collapses into 1 "
                    f"traversal, eliminating ~{estimated_wasted} redundant accesses."
                )
                suggestion = (
                    f"Upgrade to PG17, or split into smaller IN lists (<= 7 values), "
                    f"or rewrite as JOIN against VALUES()."
                )
            else:
                title = f"IN-list / ANY= B-tree scan ({max_values} values)"
                detail = (
                    f"Node '{node_type}' uses a {max_values}-value array condition. "
                    f"PG17 avoids duplicative leaf page access for this pattern."
                )
                suggestion = "Upgrade to Postgres 17 for automatic improvement."

            findings.append(SAOPFinding(
                severity="WARNING" if score >= 6 else "INFO",
                title=title,
                detail=detail,
                suggestion=suggestion,
                score=round(score, 1),
                pg17_win=True,
            ))

        # 2. SAOP in Filter but NOT in Index Cond (PG16 pattern)
        if (
            node_type in self._BTREE_NODES
            and self._SAOP_PATTERN.search(filter_cond)
            and not self._SAOP_PATTERN.search(index_cond)
        ):
            rows_removed = node.get("Rows Removed by Filter", 0)
            actual_rows = node.get("Actual Rows", 0)
            if rows_removed > actual_rows * 5:
                ratio = rows_removed / max(actual_rows, 1)
                score = min(9.0, 4.0 + min(5.0, ratio / 1000))
                findings.append(SAOPFinding(
                    severity="CRITICAL" if score >= 7 else "WARNING",
                    title="IN-list filter applied after index scan (index not used for filtering)",
                    detail=(
                        f"The B-tree index is used for sort order only. "
                        f"The IN-list/ANY= condition is applied as a post-scan filter, "
                        f"removing {rows_removed:,} rows after reading them "
                        f"({ratio:.0f}:1 filter ratio). PG17 can push this into "
                        f"the index scan as an 'Index Cond'."
                    ),
                    suggestion=(
                        "Upgrade to Postgres 17 for ScalarArrayOpExpr push-down. "
                        "In the meantime, add a composite index covering sort + filter columns."
                    ),
                    score=round(score, 1),
                    pg17_win=True,
                ))

        # 3. Excessive primitive scan count (custom stats injection)
        primitive_scans = node.get("_qs_primitive_scans")
        if primitive_scans and primitive_scans > 1:
            findings.append(SAOPFinding(
                severity="INFO",
                title=f"Excessive primitive index scans detected ({primitive_scans})",
                detail=(
                    f"pg_stat_all_indexes.idx_scan incremented {primitive_scans}x "
                    f"for this query. On PG17 this would be 1 scan."
                ),
                suggestion="Upgrade to Postgres 17.",
                score=min(7.0, 3.0 + primitive_scans * 0.1),
                pg17_win=True,
            ))

    @staticmethod
    def get_primitive_scan_sql(relation: str) -> str:
        """SQL to capture idx_scan before/after running a query."""
        return textwrap.dedent(f"""\
            SELECT
                indexrelname,
                idx_scan,
                idx_tup_read,
                idx_tup_fetch
            FROM pg_stat_user_indexes
            WHERE relname = '{relation}'
            ORDER BY idx_scan DESC;
        """)

    @staticmethod
    def pg17_candidate_report(findings: list[SAOPFinding]) -> str:
        """Summarize which findings would be fixed by upgrading to PG17."""
        pg17_wins = [f for f in findings if f.pg17_win]
        if not pg17_wins:
            return "No Postgres 17 SAOP improvements identified for this plan."

        lines = [
            f"Postgres 17 upgrade would address {len(pg17_wins)} finding(s):",
            "",
        ]
        for f in pg17_wins:
            lines.append(f"  [{f.severity}] {f.title}")
            lines.append(f"    Impact score: {f.score}/10")
            lines.append(f"    Detail: {f.detail[:120]}...")
            lines.append("")
        lines.append(
            "Reference: Postgres 17 commit by Peter Geoghegan -- "
            "'Enhance nbtree ScalarArrayOp execution'"
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 5. BenchmarkRunner - orchestrate reproducible cache benchmarks
# ---------------------------------------------------------------------------

class BenchmarkRunner:
    """
    Run a SQL query under controlled cache conditions.

    Modes:
        HOT  - both shared buffers and OS page cache warm
        WARM - OS page cache only (evict shared buffers)
        COLD - both caches empty (requires filesystem access)
    """

    _VERSION_SQL = "SELECT version()"

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._evict = BufferCacheEvict(pool)
        self._probe = DoubleBufferProbe()

    async def setup(self) -> None:
        """Install required extensions."""
        await self._evict.ensure_extension()
        async with self._pool.acquire() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS pg_prewarm")

    async def run(
        self,
        sql: str,
        cache_mode: CacheMode = CacheMode.HOT,
        relation: Optional[str] = None,
        iterations: int = 1,
    ) -> BenchmarkResult:
        await self._prepare_cache(cache_mode, relation)

        result: Optional[BenchmarkResult] = None
        for _ in range(iterations):
            result = await self._execute_explain(sql, cache_mode)

        assert result is not None
        result.iterations = iterations
        result.warnings.extend(self._probe.analyze(result))
        return result

    async def compare(
        self,
        sql: str,
        relation: Optional[str] = None,
    ) -> dict[str, BenchmarkResult]:
        """Run in HOT and WARM modes, return both results."""
        results = {}
        for mode in (CacheMode.HOT, CacheMode.WARM):
            results[mode.value] = await self.run(sql, mode, relation)
        return results

    async def _prepare_cache(
        self, mode: CacheMode, relation: Optional[str]
    ) -> None:
        if mode == CacheMode.HOT:
            if relation:
                await self._evict.load_relation(relation)
        elif mode == CacheMode.WARM:
            if relation:
                await self._evict.evict_relation(relation)
            else:
                await self._evict.evict_all()
        elif mode == CacheMode.COLD:
            if relation:
                await self._evict.evict_relation(relation)
            else:
                await self._evict.evict_all()
            raise RuntimeError(
                "CacheMode.COLD requires OS page cache eviction, which needs "
                "filesystem-level access (not possible via SQL alone).\n\n"
                "Run these commands on the database host before calling run():\n\n"
                + DoubleBufferProbe.os_evict_commands(
                    "<data_directory>",
                    "<output of pg_relation_filepath('{}')>".format(
                        relation or "your_table"
                    ),
                )
            )

    async def _execute_explain(
        self, sql: str, cache_mode: CacheMode
    ) -> BenchmarkResult:
        explain_sql = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}"
        async with self._pool.acquire() as conn:
            version_str = await conn.fetchval(self._VERSION_SQL)
            rows = await conn.fetch(explain_sql)

        plan_json: list = rows[0][0]
        plan = plan_json[0]
        root_node = plan.get("Plan", {})

        buffers = BufferStats(
            shared_hit=root_node.get("Shared Hit Blocks", 0),
            shared_read=root_node.get("Shared Read Blocks", 0),
            local_hit=root_node.get("Local Hit Blocks", 0),
            local_read=root_node.get("Local Read Blocks", 0),
        )

        return BenchmarkResult(
            sql=sql,
            cache_mode=cache_mode,
            planning_time_ms=plan.get("Planning Time", 0.0),
            execution_time_ms=plan.get("Execution Time", 0.0),
            buffers=buffers,
            rows=root_node.get("Actual Rows", 0),
            pg_version=version_str,
        )
