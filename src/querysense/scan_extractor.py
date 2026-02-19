"""
Scan Extraction — extract column access patterns from EXPLAIN plans and SQL.

This is the critical input to the CP-SAT index advisor. For each query, we
extract which columns are accessed in WHERE, JOIN, ORDER BY, and GROUP BY
clauses, and which scan type the planner chose.

The output feeds directly into the CP-SAT model's Scan dataclass.

Mirrors pganalyze's internal scan extraction from their collector, adapted
to work from EXPLAIN JSON + pg_stat_statements.

Usage:
    from querysense.scan_extractor import ScanExtractor

    extractor = ScanExtractor()
    scans = await extractor.extract_from_database(dsn)
    # Or from EXPLAIN plans:
    scans = extractor.extract_from_plan(explain_output)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ColumnAccess:
    """A column accessed in a specific context."""
    table: str
    column: str
    access_type: str  # filter, join, order_by, group_by, output
    operator: str = ""  # =, <, >, >=, <=, LIKE, IN, IS NULL, etc.
    selectivity_hint: float = 0.0  # 0-1, from planner estimates


@dataclass
class ExtractedScan:
    """A scan extracted from a query, ready to feed into CP-SAT."""
    scan_id: str
    table: str
    schema: str = "public"
    scan_type: str = ""  # Seq Scan, Index Scan, Bitmap Heap Scan, etc.
    filter_columns: list[ColumnAccess] = field(default_factory=list)
    join_columns: list[ColumnAccess] = field(default_factory=list)
    order_columns: list[ColumnAccess] = field(default_factory=list)
    group_columns: list[ColumnAccess] = field(default_factory=list)
    output_columns: list[str] = field(default_factory=list)
    sequential_cost: float = 0.0
    actual_cost: float = 0.0
    rows_estimated: int = 0
    rows_actual: int = 0
    frequency: int = 1  # calls from pg_stat_statements
    query_hash: str = ""
    sql_snippet: str = ""

    @property
    def all_filter_column_names(self) -> list[str]:
        """All columns used in filtering (WHERE/JOIN)."""
        cols = [c.column for c in self.filter_columns]
        cols.extend(c.column for c in self.join_columns)
        return cols

    @property
    def is_sequential(self) -> bool:
        return "Seq Scan" in self.scan_type

    def to_cp_scan(self) -> dict[str, Any]:
        """Convert to format accepted by CP-SAT model."""
        return {
            "Name": self.scan_id,
            "Sequential Cost": int(self.sequential_cost),
            "Frequency": self.frequency,
            "Index Costs": [],  # Filled by HypoPG costing
        }


@dataclass
class WorkloadScans:
    """Complete set of scans extracted from a workload."""
    scans: list[ExtractedScan] = field(default_factory=list)
    tables: set[str] = field(default_factory=set)
    total_queries: int = 0

    @property
    def hot_tables(self) -> list[str]:
        """Tables with the most scan activity."""
        from collections import Counter
        counts: Counter[str] = Counter()
        for scan in self.scans:
            counts[scan.table] += scan.frequency
        return [t for t, _ in counts.most_common(20)]

    def scans_for_table(self, table: str) -> list[ExtractedScan]:
        return [s for s in self.scans if s.table == table]

    def aggregate(self) -> WorkloadScans:
        """
        Aggregate scans: merge identical scan patterns, sum frequencies.

        Two scans are "identical" if they hit the same table with the same
        set of filter/join/order/group columns. This deduplication is critical
        for the CP-SAT model — it reduces the problem size and gives accurate
        frequency weights.
        """
        from collections import defaultdict

        groups: dict[str, list[ExtractedScan]] = defaultdict(list)
        for scan in self.scans:
            # Build a structural key from table + sorted column names
            filter_key = ",".join(sorted(scan.all_filter_column_names))
            order_key = ",".join(c.column for c in scan.order_columns)
            group_key = ",".join(c.column for c in scan.group_columns)
            key = f"{scan.table}|{filter_key}|{order_key}|{group_key}"
            groups[key].append(scan)

        merged: list[ExtractedScan] = []
        for _, group in groups.items():
            base = group[0]
            total_freq = sum(s.frequency for s in group)
            max_cost = max(s.sequential_cost for s in group)

            merged_scan = ExtractedScan(
                scan_id=base.scan_id,
                table=base.table,
                schema=base.schema,
                scan_type=base.scan_type,
                filter_columns=base.filter_columns,
                join_columns=base.join_columns,
                order_columns=base.order_columns,
                group_columns=base.group_columns,
                output_columns=base.output_columns,
                sequential_cost=max_cost,
                actual_cost=max(s.actual_cost for s in group),
                rows_estimated=max(s.rows_estimated for s in group),
                frequency=total_freq,
                query_hash=base.query_hash,
                sql_snippet=base.sql_snippet,
            )
            merged.append(merged_scan)

        return WorkloadScans(
            scans=merged,
            tables=self.tables,
            total_queries=self.total_queries,
        )


class ScanExtractor:
    """
    Extract scan operations from EXPLAIN plans, SQL text, and live databases.

    This is the bridge between raw query data and the CP-SAT optimizer.
    """

    def extract_from_plan(
        self,
        plan_data: Any,
        sql: str = "",
        frequency: int = 1,
    ) -> list[ExtractedScan]:
        """
        Extract scans from an EXPLAIN JSON plan.

        Walks the plan tree and extracts every scan node with its
        filter conditions, join conditions, and sort requirements.
        """
        scans: list[ExtractedScan] = []
        nodes = self._collect_scan_nodes(plan_data)
        query_hash = hashlib.md5(sql.encode()).hexdigest()[:12] if sql else ""

        for node in nodes:
            scan = self._node_to_scan(node, frequency, query_hash, sql)
            if scan and scan.table:
                scans.append(scan)

        return scans

    async def extract_from_database(
        self,
        dsn: str,
        top_n: int = 100,
        min_calls: int = 5,
    ) -> WorkloadScans:
        """
        Extract scans from a live database using pg_stat_statements + EXPLAIN.

        For each top query, runs EXPLAIN to get the plan tree, then extracts
        scan nodes. This gives us the real workload's column access patterns.
        """
        try:
            import asyncpg
        except ImportError:
            raise RuntimeError("asyncpg required: pip install asyncpg")

        conn = await asyncpg.connect(dsn)
        try:
            result = WorkloadScans()

            # Get top queries from pg_stat_statements
            rows = await conn.fetch("""
                SELECT
                    queryid,
                    query,
                    calls,
                    mean_exec_time AS mean_time_ms,
                    rows
                FROM pg_stat_statements
                WHERE calls >= $1
                  AND query NOT LIKE '%pg_stat%'
                  AND query NOT LIKE 'SET %'
                  AND query NOT LIKE 'SHOW %'
                ORDER BY calls * mean_exec_time DESC
                LIMIT $2
            """, min_calls, top_n)

            result.total_queries = len(rows)

            for row in rows:
                query = row["query"]
                calls = row["calls"]

                # Try to get EXPLAIN plan for this query
                try:
                    # Replace parameter placeholders for EXPLAIN
                    explain_query = self._prepare_for_explain(query)
                    if not explain_query:
                        continue

                    plan_rows = await conn.fetch(
                        f"EXPLAIN (FORMAT JSON) {explain_query}"
                    )
                    if plan_rows:
                        plan_json = plan_rows[0][0]
                        if isinstance(plan_json, list) and plan_json:
                            plan = plan_json[0]
                        elif isinstance(plan_json, str):
                            import json
                            plan = json.loads(plan_json)
                            if isinstance(plan, list):
                                plan = plan[0]
                        else:
                            plan = plan_json

                        scans = self.extract_from_plan(plan, sql=query, frequency=calls)
                        for scan in scans:
                            result.scans.append(scan)
                            result.tables.add(scan.table)
                except Exception:
                    # Skip queries that can't be EXPLAINed (DDL, etc.)
                    continue

            return result
        finally:
            await conn.close()

    def _collect_scan_nodes(self, plan_data: Any) -> list[dict]:
        """Recursively collect all scan nodes from an EXPLAIN plan."""
        nodes: list[dict] = []

        if hasattr(plan_data, "plan"):
            # ExplainOutput object
            plan = plan_data.plan
            if hasattr(plan, "_raw"):
                plan_dict = plan._raw
            else:
                return nodes
        elif isinstance(plan_data, dict):
            plan_dict = plan_data.get("Plan", plan_data)
        else:
            return nodes

        self._walk_plan(plan_dict, nodes)
        return nodes

    def _walk_plan(self, node: dict, scan_nodes: list[dict]) -> None:
        """Walk plan tree, collecting scan nodes."""
        node_type = node.get("Node Type", "")

        # Collect scan nodes (leaf nodes that access tables)
        if any(kw in node_type for kw in ("Scan", "Seek")):
            scan_nodes.append(node)

        # Recurse into children
        for child in node.get("Plans", []):
            self._walk_plan(child, scan_nodes)

    def _node_to_scan(
        self, node: dict, frequency: int, query_hash: str, sql: str,
    ) -> ExtractedScan | None:
        """Convert a plan node to an ExtractedScan."""
        node_type = node.get("Node Type", "")
        table = node.get("Relation Name", "")
        schema = node.get("Schema", "public")

        if not table:
            return None

        scan_id = f"{query_hash}_{table}_{node_type.replace(' ', '_').lower()}"

        scan = ExtractedScan(
            scan_id=scan_id,
            table=table,
            schema=schema,
            scan_type=node_type,
            sequential_cost=node.get("Total Cost", 0),
            actual_cost=node.get("Actual Total Time", 0),
            rows_estimated=node.get("Plan Rows", 0),
            rows_actual=node.get("Actual Rows", 0),
            frequency=frequency,
            query_hash=query_hash,
            sql_snippet=sql[:200] if sql else "",
        )

        # Extract filter conditions
        filter_cond = node.get("Filter", "")
        if filter_cond:
            scan.filter_columns.extend(
                self._parse_condition_columns(table, filter_cond, "filter")
            )

        # Index conditions (still useful — shows what the planner used)
        index_cond = node.get("Index Cond", "")
        if index_cond:
            scan.filter_columns.extend(
                self._parse_condition_columns(table, index_cond, "filter")
            )

        # Recheck conditions (bitmap scans)
        recheck = node.get("Recheck Cond", "")
        if recheck:
            scan.filter_columns.extend(
                self._parse_condition_columns(table, recheck, "filter")
            )

        # Join filter
        join_filter = node.get("Join Filter", "")
        if join_filter:
            scan.join_columns.extend(
                self._parse_condition_columns(table, join_filter, "join")
            )

        # Hash condition
        hash_cond = node.get("Hash Cond", "")
        if hash_cond:
            scan.join_columns.extend(
                self._parse_condition_columns(table, hash_cond, "join")
            )

        # Merge condition
        merge_cond = node.get("Merge Cond", "")
        if merge_cond:
            scan.join_columns.extend(
                self._parse_condition_columns(table, merge_cond, "join")
            )

        # Sort keys
        sort_key = node.get("Sort Key", [])
        if sort_key:
            for key in sort_key:
                col = self._extract_column_name(key)
                if col:
                    scan.order_columns.append(
                        ColumnAccess(table=table, column=col, access_type="order_by")
                    )

        # Group keys
        group_key = node.get("Group Key", [])
        if group_key:
            for key in group_key:
                col = self._extract_column_name(key)
                if col:
                    scan.group_columns.append(
                        ColumnAccess(table=table, column=col, access_type="group_by")
                    )

        # Output columns
        output = node.get("Output", [])
        if output:
            scan.output_columns = [self._extract_column_name(o) or o for o in output]

        return scan

    def _parse_condition_columns(
        self, table: str, condition: str, access_type: str,
    ) -> list[ColumnAccess]:
        """Parse a condition string to extract column names and operators."""
        columns: list[ColumnAccess] = []

        # Pattern: (table.column operator value)
        patterns = [
            (r"(\w+)\.(\w+)\s*(=|<>|!=|>=|<=|>|<)\s*", r"\2", r"\3"),
            (r"\((\w+)\s*(=|<>|!=|>=|<=|>|<|~~|IS)\s*", r"\1", r"\2"),
            (r"(\w+)\s*(=|<>|!=|>=|<=|>|<|~~|IS NOT NULL|IS NULL)\s*", r"\1", r"\2"),
        ]

        # Simple column extraction from condition string
        col_matches = re.findall(r"(?:\w+\.)?(\w+)\s*(?:=|<>|!=|>=|<=|>|<|~~|IS|IN|ANY)", condition)
        for col in col_matches:
            if col.upper() not in ("AND", "OR", "NOT", "NULL", "TRUE", "FALSE", "ANY", "ALL"):
                op_match = re.search(rf"{re.escape(col)}\s*(=|<>|!=|>=|<=|>|<|~~|IS|IN)", condition)
                op = op_match.group(1) if op_match else "="
                columns.append(ColumnAccess(
                    table=table, column=col, access_type=access_type, operator=op,
                ))

        return columns

    def _extract_column_name(self, expr: str) -> str | None:
        """Extract bare column name from an expression."""
        expr = expr.strip()
        # table.column -> column
        if "." in expr:
            parts = expr.split(".")
            return parts[-1].strip()
        # Remove type casts, functions
        col = re.match(r"^(\w+)", expr)
        return col.group(1) if col else None

    def _prepare_for_explain(self, query: str) -> str | None:
        """Prepare a pg_stat_statements query for EXPLAIN."""
        q = query.strip()
        upper = q.upper()

        # Only EXPLAIN SELECT, INSERT, UPDATE, DELETE
        if not any(upper.startswith(k) for k in ("SELECT", "INSERT", "UPDATE", "DELETE", "WITH")):
            return None

        # Replace $1, $2, ... with NULL for EXPLAIN
        q = re.sub(r"\$\d+", "NULL", q)

        return q
