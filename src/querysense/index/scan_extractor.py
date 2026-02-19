"""
Scan Extractor — Parse SQL queries and EXPLAIN plans into CP model Scans.

This is the bridge between QuerySense's existing SQL parser / EXPLAIN analyzer
and the Constraint Programming index advisor. It converts real-world queries
into the abstract "Scan" objects that the CP-SAT solver operates on.

pganalyze's process:
    1. Collect queries from pg_stat_statements
    2. Parse each query to extract WHERE/JOIN conditions per table
    3. Generate candidate indexes for each condition set
    4. Cost each candidate using the planner (HypoPG or modified planner copy)

This module implements steps 1-3. Step 4 is handled by CostSimulator.

Usage:
    from querysense.index.scan_extractor import ScanExtractor

    extractor = ScanExtractor()

    # From SQL queries
    scans, candidates = extractor.extract_from_sql(
        "SELECT * FROM orders WHERE customer_id = 42 AND status = 'active'",
        table="orders",
    )

    # From EXPLAIN plan JSON
    scans, candidates = extractor.extract_from_plan(explain_json)
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Any

from querysense.index.cp_model import Index, Scan


@dataclass
class CandidateSet:
    """
    A set of candidate indexes generated for a table's scans.

    Contains:
    - The scans extracted from queries on this table
    - The candidate indexes generated from those scans
    - Column metadata for index generation
    """

    table: str
    scans: list[Scan] = field(default_factory=list)
    candidates: list[Index] = field(default_factory=list)
    columns_referenced: list[str] = field(default_factory=list)


class ScanExtractor:
    """
    Extract CP model Scans and candidate indexes from SQL queries and EXPLAIN plans.

    Two extraction modes:
    1. SQL-based: Parse queries using querysense.analyzer.sql_parser
    2. Plan-based: Extract from EXPLAIN JSON output

    Both modes produce Scan objects (with estimated sequential costs)
    and candidate Index objects (without cost — costs must be filled
    by the CostSimulator using HypoPG).
    """

    def __init__(self, max_composite_width: int = 3) -> None:
        """
        Args:
            max_composite_width: Maximum number of columns in a composite index.
                Limits combinatorial explosion when generating candidates.
        """
        self.max_composite_width = max_composite_width

    # ------------------------------------------------------------------
    # SQL-based extraction
    # ------------------------------------------------------------------

    def extract_from_sql(
        self,
        sql: str,
        table: str | None = None,
        frequency: int = 1,
    ) -> CandidateSet:
        """
        Extract scans and candidate indexes from a SQL query.

        Uses querysense's SQL parser to break the query into per-table
        column references, then generates candidate B-tree indexes from
        the column combinations.

        Args:
            sql: SQL query string.
            table: Optional table filter (only extract for this table).
            frequency: How often this query executes (for weighting).

        Returns:
            CandidateSet with scans and candidate indexes.
        """
        from querysense.analyzer.sql_parser import SQLQueryAnalyzer

        analyzer = SQLQueryAnalyzer()
        query_info = analyzer.analyze(sql)

        # Determine which tables to extract for
        target_tables = [table] if table else query_info.tables

        all_scans: list[Scan] = []
        all_candidates: list[Index] = []
        all_columns: list[str] = []

        for tbl in target_tables:
            columns = query_info.get_columns_for_table(tbl)
            if not columns:
                continue

            # Build a single scan per WHERE/JOIN condition group
            col_names = []
            for col in columns:
                if col.column not in col_names:
                    col_names.append(col.column)

            if not col_names:
                continue

            all_columns.extend(col_names)

            # Create a scan representing this query's access pattern on this table
            scan_id = f"q_{tbl}_{'_'.join(col_names[:3])}"
            scan = Scan(
                id=scan_id,
                name=f"Query on {tbl} filtering {', '.join(col_names)}",
                sequential_cost=0,  # Filled by CostSimulator
                index_costs={},     # Filled by CostSimulator
                frequency=frequency,
            )
            all_scans.append(scan)

            # Generate candidate indexes following composite index ordering:
            # equality columns first, then range, then sort
            composite = query_info.suggest_composite_index(tbl)
            if not composite:
                composite = col_names

            candidates = self._generate_candidates(tbl, composite)
            all_candidates.extend(candidates)

        return CandidateSet(
            table=table or (target_tables[0] if target_tables else ""),
            scans=all_scans,
            candidates=all_candidates,
            columns_referenced=all_columns,
        )

    def extract_from_queries(
        self,
        queries: list[dict[str, Any]],
        table: str | None = None,
    ) -> CandidateSet:
        """
        Extract from multiple queries (e.g., from pg_stat_statements).

        Args:
            queries: List of dicts with 'sql' and optional 'frequency' keys.
            table: Optional table filter.

        Returns:
            Merged CandidateSet across all queries.
        """
        all_scans: list[Scan] = []
        all_candidates: list[Index] = []
        all_columns: list[str] = []
        seen_candidate_ids: set[str] = set()

        for q in queries:
            sql = q.get("sql", "")
            freq = q.get("frequency", q.get("calls", 1))
            if not sql:
                continue

            result = self.extract_from_sql(sql, table=table, frequency=freq)
            all_scans.extend(result.scans)
            all_columns.extend(result.columns_referenced)

            for c in result.candidates:
                if c.id not in seen_candidate_ids:
                    seen_candidate_ids.add(c.id)
                    all_candidates.append(c)

        return CandidateSet(
            table=table or "",
            scans=all_scans,
            candidates=all_candidates,
            columns_referenced=all_columns,
        )

    # ------------------------------------------------------------------
    # EXPLAIN-based extraction
    # ------------------------------------------------------------------

    def extract_from_plan(
        self,
        plan_json: dict[str, Any],
        frequency: int = 1,
    ) -> CandidateSet:
        """
        Extract scans from an EXPLAIN JSON plan.

        Walks the plan tree looking for Seq Scan and Index Scan nodes,
        extracting the table, filter conditions, and costs.

        Args:
            plan_json: EXPLAIN (FORMAT JSON) output.
            frequency: Query frequency.

        Returns:
            CandidateSet with scans extracted from the plan.
        """
        # Handle EXPLAIN wrapper format: [{"Plan": {...}}]
        if isinstance(plan_json, list) and plan_json:
            plan_json = plan_json[0]
        plan_node = plan_json.get("Plan", plan_json)

        all_scans: list[Scan] = []
        all_candidates: list[Index] = []
        tables_seen: set[str] = set()

        self._walk_plan(plan_node, all_scans, all_candidates, tables_seen, frequency)

        return CandidateSet(
            table="",
            scans=all_scans,
            candidates=all_candidates,
            columns_referenced=[],
        )

    def _walk_plan(
        self,
        node: dict[str, Any],
        scans: list[Scan],
        candidates: list[Index],
        tables_seen: set[str],
        frequency: int,
    ) -> None:
        """Recursively walk EXPLAIN plan tree."""
        node_type = node.get("Node Type", "")
        relation = node.get("Relation Name", "")

        if node_type == "Seq Scan" and relation:
            filt = node.get("Filter", "")
            total_cost = int(node.get("Total Cost", 0))
            actual_rows = node.get("Actual Rows", node.get("Plan Rows", 0))
            rows_removed = node.get("Rows Removed by Filter", 0)

            # Extract column names from filter
            columns = self._extract_columns_from_filter(filt)

            if columns and total_cost > 0:
                scan_id = f"plan_{relation}_{'_'.join(columns[:3])}"
                scan = Scan(
                    id=scan_id,
                    name=f"Seq Scan on {relation}: {filt}" if filt else f"Seq Scan on {relation}",
                    sequential_cost=total_cost,
                    index_costs={},
                    frequency=frequency,
                )
                scans.append(scan)

                if relation not in tables_seen:
                    tables_seen.add(relation)
                    cands = self._generate_candidates(relation, columns)
                    candidates.extend(cands)

        # Recurse into child plans
        for child in node.get("Plans", []):
            self._walk_plan(child, scans, candidates, tables_seen, frequency)

    # ------------------------------------------------------------------
    # Candidate generation
    # ------------------------------------------------------------------

    def _generate_candidates(
        self, table: str, columns: list[str]
    ) -> list[Index]:
        """
        Generate candidate B-tree indexes from column combinations.

        For columns [a, b, c] with max_width=3, generates:
            (a), (b), (c),
            (a, b), (a, c), (b, c),
            (a, b, c)

        Plus the "optimal" composite (preserving input order which
        follows equality-first, range-second, sort-third).
        """
        candidates: list[Index] = []
        seen: set[tuple[str, ...]] = set()

        # Single-column indexes
        for col in columns:
            key = (col,)
            if key not in seen:
                seen.add(key)
                idx_id = f"idx_{table}_{col}"
                candidates.append(
                    Index(
                        id=idx_id,
                        name=idx_id,
                        columns=key,
                        table=table,
                        index_type="btree",
                    )
                )

        # Multi-column combinations up to max_composite_width
        for width in range(2, min(len(columns), self.max_composite_width) + 1):
            for combo in itertools.combinations(columns, width):
                if combo not in seen:
                    seen.add(combo)
                    cols_str = "_".join(combo[:3])
                    idx_id = f"idx_{table}_{cols_str}"
                    candidates.append(
                        Index(
                            id=idx_id,
                            name=idx_id,
                            columns=combo,
                            table=table,
                            index_type="btree",
                        )
                    )

        # Also the full composite in the optimal order (if not already there)
        if len(columns) > 1:
            full = tuple(columns[:self.max_composite_width])
            if full not in seen:
                seen.add(full)
                cols_str = "_".join(full[:3])
                idx_id = f"idx_{table}_{cols_str}_composite"
                candidates.append(
                    Index(
                        id=idx_id,
                        name=idx_id,
                        columns=full,
                        table=table,
                        index_type="btree",
                    )
                )

        return candidates

    def _extract_columns_from_filter(self, filt: str) -> list[str]:
        """Extract column names from a PostgreSQL filter string."""
        if not filt:
            return []

        columns: list[str] = []
        seen: set[str] = set()

        # Pattern: column_name operator value
        # We strip parens first to simplify matching
        clean = filt.replace("(", " ").replace(")", " ")
        col_pattern = re.compile(
            r"(?<!\w)([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|>=|<=|<>|!=|>|<|~~|LIKE|ILIKE|IN\b|IS\b|ANY\b|BETWEEN\b)",
            re.IGNORECASE,
        )
        keywords = {
            "AND", "OR", "NOT", "NULL", "TRUE", "FALSE", "SELECT",
            "FROM", "WHERE", "IN", "IS", "BETWEEN", "LIKE", "ILIKE",
            "ANY", "ALL", "EXISTS", "SOME",
        }

        for match in col_pattern.finditer(clean):
            col = match.group(1)
            if col.upper() not in keywords and col not in seen:
                seen.add(col)
                columns.append(col)

        return columns[:5]  # Cap to avoid noise
