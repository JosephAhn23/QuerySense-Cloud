"""
Partition Advisor — suggest partitioning strategies based on table size and query patterns.

Closes the pganalyze gap: "Partition advisor — suggests partitioning strategies
based on query patterns."

Analyzes:
1. Large unpartitioned tables (>1M rows, >1GB)
2. Sequential scan frequency on large tables
3. Time-based query patterns (WHERE created_at > ...)
4. Range-based access patterns
5. Existing partitioned tables for pruning efficiency

Recommends:
- RANGE partitioning (time-series data)
- LIST partitioning (categorical columns like status, region)
- HASH partitioning (evenly distributed access)

Usage:
    from querysense.partition_advisor import PartitionAdvisor

    advisor = PartitionAdvisor()
    report = advisor.analyze_from_data(table_stats, query_patterns)
    for rec in report.recommendations:
        print(rec)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PartitionCandidate:
    """A table that would benefit from partitioning."""

    schema: str
    table: str
    estimated_rows: int
    table_size_mb: float
    seq_scan_count: int
    idx_scan_count: int
    strategy: str  # "range", "list", "hash"
    partition_key: str  # Suggested column
    rationale: str
    implementation_sql: list[str]
    estimated_improvement: str
    severity: str  # "critical", "warning", "info"


@dataclass(frozen=True)
class PartitionIssue:
    """An issue with existing partitioned tables."""

    schema: str
    table: str
    issue_type: str  # "pruning_failure", "imbalanced", "too_many_partitions"
    description: str
    fix_suggestion: str
    severity: str


@dataclass
class PartitionReport:
    """Complete partition analysis report."""

    candidates: list[PartitionCandidate] = field(default_factory=list)
    issues: list[PartitionIssue] = field(default_factory=list)
    total_tables_analyzed: int = 0
    tables_needing_partitioning: int = 0
    estimated_total_improvement: str = ""

    def summary(self) -> str:
        parts = [f"{self.total_tables_analyzed} tables analyzed"]
        if self.candidates:
            parts.append(f"{len(self.candidates)} partition candidates found")
        if self.issues:
            parts.append(f"{len(self.issues)} partition issues")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "total_analyzed": self.total_tables_analyzed,
            "candidates": [
                {
                    "table": f"{c.schema}.{c.table}",
                    "rows": c.estimated_rows,
                    "size_mb": round(c.table_size_mb, 1),
                    "strategy": c.strategy,
                    "partition_key": c.partition_key,
                    "rationale": c.rationale,
                    "sql": c.implementation_sql,
                    "improvement": c.estimated_improvement,
                    "severity": c.severity,
                }
                for c in self.candidates
            ],
            "issues": [
                {
                    "table": f"{i.schema}.{i.table}",
                    "type": i.issue_type,
                    "description": i.description,
                    "fix": i.fix_suggestion,
                    "severity": i.severity,
                }
                for i in self.issues
            ],
        }


# ── Catalog queries ───────────────────────────────────────────────────

LARGE_TABLES_QUERY = """
SELECT
    schemaname,
    relname AS tablename,
    n_live_tup AS estimated_rows,
    pg_total_relation_size(relid) AS total_size_bytes,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch,
    n_tup_ins,
    n_tup_upd,
    n_tup_del
FROM pg_stat_user_tables
WHERE n_live_tup > 100000
ORDER BY pg_total_relation_size(relid) DESC;
"""

TABLE_COLUMNS_QUERY = """
SELECT
    c.table_schema,
    c.table_name,
    c.column_name,
    c.data_type,
    c.is_nullable,
    c.column_default
FROM information_schema.columns c
JOIN pg_stat_user_tables t ON t.schemaname = c.table_schema AND t.relname = c.table_name
WHERE t.n_live_tup > 100000
  AND c.table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY c.table_schema, c.table_name, c.ordinal_position;
"""

PARTITIONED_TABLES_QUERY = """
SELECT
    nmsp_parent.nspname AS parent_schema,
    parent.relname AS parent_table,
    nmsp_child.nspname AS child_schema,
    child.relname AS child_table,
    pg_total_relation_size(child.oid) AS child_size_bytes,
    child.reltuples AS child_rows
FROM pg_inherits
JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
JOIN pg_class child ON pg_inherits.inhrelid = child.oid
JOIN pg_namespace nmsp_parent ON parent.relnamespace = nmsp_parent.oid
JOIN pg_namespace nmsp_child ON child.relnamespace = nmsp_child.oid
WHERE nmsp_parent.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY parent.relname, child.relname;
"""


# ── Time-column detection patterns ───────────────────────────────────

_TIME_COLUMNS = re.compile(
    r"(created_at|updated_at|inserted_at|timestamp|date|event_time|"
    r"log_time|modified_at|recorded_at|created_date|event_date|"
    r"partition_date|log_date|ts|occurred_at)",
    re.IGNORECASE,
)

_TIME_TYPES = {"timestamp without time zone", "timestamp with time zone", "date", "timestamptz"}

_LIST_COLUMNS = re.compile(
    r"(status|type|category|region|country|state|department|"
    r"priority|level|tenant_id|org_id|account_id)",
    re.IGNORECASE,
)


class PartitionAdvisor:
    """Analyze tables for partitioning opportunities."""

    # Thresholds
    MIN_ROWS_FOR_PARTITION = 1_000_000  # 1M rows
    MIN_SIZE_MB_FOR_PARTITION = 1024    # 1GB
    HIGH_SEQ_SCAN_RATIO = 10           # seq_scan > 10 * idx_scan

    def analyze_from_data(
        self,
        table_stats: list[dict[str, Any]],
        table_columns: list[dict[str, Any]] | None = None,
        partitioned_tables: list[dict[str, Any]] | None = None,
    ) -> PartitionReport:
        """Analyze tables for partitioning opportunities.

        Args:
            table_stats: Results from LARGE_TABLES_QUERY
            table_columns: Results from TABLE_COLUMNS_QUERY (optional, improves suggestions)
            partitioned_tables: Results from PARTITIONED_TABLES_QUERY (optional)
        """
        report = PartitionReport()
        report.total_tables_analyzed = len(table_stats)

        # Build column index
        cols_by_table: dict[str, list[dict[str, Any]]] = {}
        if table_columns:
            for col in table_columns:
                key = f"{col.get('table_schema', 'public')}.{col['table_name']}"
                cols_by_table.setdefault(key, []).append(col)

        for stat in table_stats:
            schema = stat.get("schemaname", "public")
            table = stat.get("tablename", "")
            rows = stat.get("estimated_rows", 0) or stat.get("n_live_tup", 0)
            size_bytes = stat.get("total_size_bytes", 0)
            size_mb = size_bytes / (1024 * 1024)
            seq_scan = stat.get("seq_scan", 0)
            idx_scan = stat.get("idx_scan", 0)

            # Skip small tables
            if rows < self.MIN_ROWS_FOR_PARTITION and size_mb < self.MIN_SIZE_MB_FOR_PARTITION:
                continue

            # Determine partition strategy based on columns
            key = f"{schema}.{table}"
            columns = cols_by_table.get(key, [])

            candidate = self._suggest_strategy(
                schema, table, rows, size_mb, seq_scan, idx_scan, columns
            )
            if candidate:
                report.candidates.append(candidate)

        # Check existing partitioned tables for issues
        if partitioned_tables:
            report.issues.extend(self._check_partition_health(partitioned_tables))

        report.tables_needing_partitioning = len(report.candidates)

        # Sort candidates by severity and size
        severity_order = {"critical": 0, "warning": 1, "info": 2}
        report.candidates.sort(
            key=lambda c: (severity_order.get(c.severity, 3), -c.table_size_mb)
        )

        return report

    def _suggest_strategy(
        self,
        schema: str,
        table: str,
        rows: int,
        size_mb: float,
        seq_scan: int,
        idx_scan: int,
        columns: list[dict[str, Any]],
    ) -> PartitionCandidate | None:
        """Suggest a partitioning strategy for a table."""

        # Look for time-based columns first (most common partition strategy)
        for col in columns:
            col_name = col.get("column_name", "")
            col_type = col.get("data_type", "")

            if _TIME_COLUMNS.match(col_name) and col_type in _TIME_TYPES:
                return self._suggest_range_partition(
                    schema, table, rows, size_mb, seq_scan, idx_scan, col_name
                )

        # Look for list/categorical columns
        for col in columns:
            col_name = col.get("column_name", "")
            col_type = col.get("data_type", "")

            if _LIST_COLUMNS.match(col_name) and col_type in (
                "character varying", "text", "varchar", "integer", "smallint",
            ):
                return self._suggest_list_partition(
                    schema, table, rows, size_mb, seq_scan, idx_scan, col_name
                )

        # Fallback: if table is very large with high seq scans, suggest hash
        if rows > self.MIN_ROWS_FOR_PARTITION * 5 and seq_scan > idx_scan * self.HIGH_SEQ_SCAN_RATIO:
            # Find a good hash key (primary key or unique column)
            for col in columns:
                col_name = col.get("column_name", "")
                if col_name in ("id", "uuid", "pk"):
                    return self._suggest_hash_partition(
                        schema, table, rows, size_mb, seq_scan, idx_scan, col_name
                    )

        # No partition recommendation if we can't find a good key
        return None

    def _suggest_range_partition(
        self, schema: str, table: str, rows: int, size_mb: float,
        seq_scan: int, idx_scan: int, time_col: str,
    ) -> PartitionCandidate:
        """Suggest RANGE partitioning on a time column."""
        fqn = f"{schema}.{table}"

        # Determine partition interval based on table size
        if size_mb > 10240:  # >10GB
            interval = "1 month"
            interval_sql = "INTERVAL '1 month'"
        elif size_mb > 1024:  # >1GB
            interval = "3 months"
            interval_sql = "INTERVAL '3 months'"
        else:
            interval = "1 year"
            interval_sql = "INTERVAL '1 year'"

        severity = "critical" if rows > 10_000_000 and seq_scan > idx_scan * 5 else "warning"

        sql = [
            f"-- Step 1: Create new partitioned table",
            f"CREATE TABLE {fqn}_partitioned (",
            f"    LIKE {fqn} INCLUDING ALL",
            f") PARTITION BY RANGE ({time_col});",
            f"",
            f"-- Step 2: Create partitions (adjust date ranges to your data)",
            f"CREATE TABLE {fqn}_y2025 PARTITION OF {fqn}_partitioned",
            f"    FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');",
            f"CREATE TABLE {fqn}_y2026 PARTITION OF {fqn}_partitioned",
            f"    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');",
            f"CREATE TABLE {fqn}_default PARTITION OF {fqn}_partitioned DEFAULT;",
            f"",
            f"-- Step 3: Migrate data (in batches for large tables)",
            f"INSERT INTO {fqn}_partitioned SELECT * FROM {fqn};",
            f"",
            f"-- Step 4: Swap tables",
            f"ALTER TABLE {fqn} RENAME TO {table}_old;",
            f"ALTER TABLE {fqn}_partitioned RENAME TO {table};",
            f"",
            f"-- Step 5: Verify and drop old table",
            f"-- DROP TABLE {fqn}_old;  -- After verification",
        ]

        return PartitionCandidate(
            schema=schema,
            table=table,
            estimated_rows=rows,
            table_size_mb=size_mb,
            seq_scan_count=seq_scan,
            idx_scan_count=idx_scan,
            strategy="range",
            partition_key=time_col,
            rationale=(
                f"Table has {rows:,} rows ({size_mb:.0f}MB) with time column '{time_col}'. "
                f"RANGE partitioning by {interval} enables partition pruning for time-range queries, "
                f"faster VACUUM (per-partition), and efficient bulk deletion of old data."
            ),
            implementation_sql=sql,
            estimated_improvement=(
                f"10-100x faster for queries filtering on {time_col}. "
                f"Instant deletion of old partitions instead of DELETE."
            ),
            severity=severity,
        )

    def _suggest_list_partition(
        self, schema: str, table: str, rows: int, size_mb: float,
        seq_scan: int, idx_scan: int, list_col: str,
    ) -> PartitionCandidate:
        """Suggest LIST partitioning on a categorical column."""
        fqn = f"{schema}.{table}"
        severity = "warning"

        sql = [
            f"-- Step 1: Create new partitioned table",
            f"CREATE TABLE {fqn}_partitioned (",
            f"    LIKE {fqn} INCLUDING ALL",
            f") PARTITION BY LIST ({list_col});",
            f"",
            f"-- Step 2: Create partitions (adjust values to your data)",
            f"-- First, check distinct values:",
            f"-- SELECT DISTINCT {list_col}, COUNT(*) FROM {fqn} GROUP BY 1;",
            f"CREATE TABLE {fqn}_active PARTITION OF {fqn}_partitioned",
            f"    FOR VALUES IN ('active');",
            f"CREATE TABLE {fqn}_inactive PARTITION OF {fqn}_partitioned",
            f"    FOR VALUES IN ('inactive', 'archived');",
            f"CREATE TABLE {fqn}_default PARTITION OF {fqn}_partitioned DEFAULT;",
            f"",
            f"-- Step 3: Migrate and swap (same as RANGE)",
        ]

        return PartitionCandidate(
            schema=schema,
            table=table,
            estimated_rows=rows,
            table_size_mb=size_mb,
            seq_scan_count=seq_scan,
            idx_scan_count=idx_scan,
            strategy="list",
            partition_key=list_col,
            rationale=(
                f"Table has {rows:,} rows ({size_mb:.0f}MB) with categorical column '{list_col}'. "
                f"LIST partitioning groups rows by {list_col} value, enabling partition pruning "
                f"for queries filtering on specific values."
            ),
            implementation_sql=sql,
            estimated_improvement=(
                f"5-50x faster for queries filtering on {list_col} values. "
                f"Smaller partitions improve VACUUM and index maintenance."
            ),
            severity=severity,
        )

    def _suggest_hash_partition(
        self, schema: str, table: str, rows: int, size_mb: float,
        seq_scan: int, idx_scan: int, hash_col: str,
    ) -> PartitionCandidate:
        """Suggest HASH partitioning for even distribution."""
        fqn = f"{schema}.{table}"

        # Determine number of partitions
        if size_mb > 10240:
            num_partitions = 16
        elif size_mb > 1024:
            num_partitions = 8
        else:
            num_partitions = 4

        sql = [
            f"-- Step 1: Create new partitioned table",
            f"CREATE TABLE {fqn}_partitioned (",
            f"    LIKE {fqn} INCLUDING ALL",
            f") PARTITION BY HASH ({hash_col});",
            f"",
            f"-- Step 2: Create {num_partitions} hash partitions",
        ]
        for i in range(num_partitions):
            sql.append(
                f"CREATE TABLE {fqn}_p{i} PARTITION OF {fqn}_partitioned "
                f"FOR VALUES WITH (MODULUS {num_partitions}, REMAINDER {i});"
            )
        sql.extend([
            f"",
            f"-- Step 3: Migrate and swap (same as RANGE)",
        ])

        return PartitionCandidate(
            schema=schema,
            table=table,
            estimated_rows=rows,
            table_size_mb=size_mb,
            seq_scan_count=seq_scan,
            idx_scan_count=idx_scan,
            strategy="hash",
            partition_key=hash_col,
            rationale=(
                f"Table has {rows:,} rows ({size_mb:.0f}MB) with very high seq scan ratio "
                f"({seq_scan:,} seq scans vs {idx_scan:,} idx scans). "
                f"HASH partitioning by '{hash_col}' distributes data evenly across "
                f"{num_partitions} partitions, enabling parallel maintenance."
            ),
            implementation_sql=sql,
            estimated_improvement=(
                f"Parallel VACUUM across {num_partitions} partitions. "
                f"Smaller B-tree indexes per partition."
            ),
            severity="info",
        )

    def _check_partition_health(
        self, partitioned_tables: list[dict[str, Any]],
    ) -> list[PartitionIssue]:
        """Check existing partitions for health issues."""
        issues: list[PartitionIssue] = []

        # Group by parent
        parents: dict[str, list[dict[str, Any]]] = {}
        for row in partitioned_tables:
            key = f"{row.get('parent_schema', 'public')}.{row.get('parent_table', '')}"
            parents.setdefault(key, []).append(row)

        for parent, children in parents.items():
            schema = children[0].get("parent_schema", "public")
            table = children[0].get("parent_table", "")

            # Too many partitions
            if len(children) > 100:
                issues.append(PartitionIssue(
                    schema=schema,
                    table=table,
                    issue_type="too_many_partitions",
                    description=(
                        f"Table has {len(children)} partitions. PostgreSQL performance "
                        f"degrades above ~100 partitions due to planning overhead."
                    ),
                    fix_suggestion=(
                        f"Consider wider partition ranges (monthly → quarterly) or "
                        f"DETACH and archive old partitions."
                    ),
                    severity="warning",
                ))

            # Imbalanced partitions (one partition has >80% of data)
            total_rows = sum(c.get("child_rows", 0) for c in children)
            if total_rows > 0:
                for child in children:
                    child_rows = child.get("child_rows", 0)
                    if child_rows > total_rows * 0.8 and len(children) > 2:
                        issues.append(PartitionIssue(
                            schema=schema,
                            table=table,
                            issue_type="imbalanced",
                            description=(
                                f"Partition '{child.get('child_table', '')}' contains "
                                f"{child_rows / total_rows:.0%} of all rows. "
                                f"Partitioning benefit is minimal if data is concentrated."
                            ),
                            fix_suggestion=(
                                f"Re-evaluate partition key. Consider splitting the large "
                                f"partition or using a different partition strategy."
                            ),
                            severity="warning",
                        ))
                        break

        return issues

    @staticmethod
    def get_catalog_queries() -> dict[str, str]:
        """Return catalog queries for partition analysis."""
        return {
            "large_tables": LARGE_TABLES_QUERY,
            "columns": TABLE_COLUMNS_QUERY,
            "partitioned": PARTITIONED_TABLES_QUERY,
        }
