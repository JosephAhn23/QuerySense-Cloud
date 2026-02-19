"""
Index Design Advisor — Educational multi-column index design.

Implements the core insight from pganalyze's "Efficient Search" guide (p.17-18):
- High-cardinality columns first in composite indexes
- Sort elimination via index ordering
- Covering indexes to avoid heap fetches
- Index-only scan opportunities

Unlike pganalyze, this is FREE, CLI-first, and explains *why* every
decision is made — acting as a teaching tool, not just a recommendation engine.

Usage:
    from querysense.analysis.index_design import IndexDesignAdvisor

    advisor = IndexDesignAdvisor()
    # From column list
    result = advisor.design(
        table="product_events",
        columns=["organization_id", "occurred_at"],
        order={"occurred_at": "DESC"},
        where_columns=["organization_id"],
        select_columns=["id", "name"],
    )
    print(result.explanation)
    print(result.sql)

    # From live database + query
    result = await advisor.design_from_query(conn, sql_query)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class ColumnStats:
    """Statistics for a single column."""

    name: str = ""
    cardinality: int = 0  # n_distinct (approx unique values)
    null_frac: float = 0.0
    avg_width: int = 0
    data_type: str = ""
    is_in_where: bool = False
    is_in_order_by: bool = False
    is_in_select: bool = False
    order_direction: str = "ASC"
    is_equality: bool = True  # = vs range (>, <, BETWEEN)

    @property
    def selectivity(self) -> float:
        """Estimated selectivity (lower = more selective)."""
        if self.cardinality <= 0:
            return 1.0
        return 1.0 / self.cardinality


@dataclass
class IndexDesign:
    """Result of the index design analysis."""

    table: str = ""
    schema: str = "public"

    # Recommended column ordering
    recommended_columns: list[tuple[str, str]] = field(default_factory=list)  # (name, direction)
    include_columns: list[str] = field(default_factory=list)

    # Explanation sections
    column_analysis: list[str] = field(default_factory=list)
    ordering_rationale: list[str] = field(default_factory=list)
    performance_notes: list[str] = field(default_factory=list)

    # Estimated improvement
    estimated_speedup: str = ""
    sort_eliminated: bool = False
    covers_query: bool = False

    # Generated SQL
    index_name: str = ""

    @property
    def sql(self) -> str:
        """Generate the CREATE INDEX statement."""
        if not self.recommended_columns:
            return "-- No index recommendation"

        cols: list[str] = []
        for name, direction in self.recommended_columns:
            if direction == "DESC":
                cols.append(f"{name} DESC")
            else:
                cols.append(name)

        fqn = f"{self.schema}.{self.table}" if self.schema != "public" else self.table
        idx_name = self.index_name or self._generate_name()

        parts = [f"CREATE INDEX CONCURRENTLY {idx_name}"]
        parts.append(f"ON {fqn}({', '.join(cols)})")

        if self.include_columns:
            parts.append(f"INCLUDE ({', '.join(self.include_columns)})")

        return "\n".join(parts) + ";"

    @property
    def explanation(self) -> str:
        """Full educational explanation of the design decision."""
        sections: list[str] = []

        sections.append("INDEX DESIGN ANALYSIS")
        sections.append("=" * 60)
        sections.append("")

        # Column analysis
        if self.column_analysis:
            sections.append("Column Analysis:")
            for line in self.column_analysis:
                sections.append(f"  {line}")
            sections.append("")

        # Ordering rationale
        if self.ordering_rationale:
            sections.append("Recommended Column Order:")
            for i, (name, direction) in enumerate(self.recommended_columns, 1):
                sections.append(f"  {i}. {name} {direction}")
            sections.append("")
            sections.append("Why this order:")
            for line in self.ordering_rationale:
                sections.append(f"  {line}")
            sections.append("")

        # Performance notes
        if self.performance_notes:
            sections.append("Performance Impact:")
            for line in self.performance_notes:
                sections.append(f"  {line}")
            sections.append("")

        if self.sort_eliminated:
            sections.append("Sort Elimination: YES")
            sections.append(
                "  The index provides pre-sorted output, eliminating"
            )
            sections.append(
                "  a separate Sort step (often 10-100x speedup for ORDER BY)."
            )
            sections.append("")

        if self.covers_query:
            sections.append("Index-Only Scan: POSSIBLE")
            sections.append(
                "  All selected columns are included in the index."
            )
            sections.append(
                "  PostgreSQL can answer the query from the index alone,"
            )
            sections.append(
                "  avoiding heap fetches entirely."
            )
            sections.append("")

        if self.estimated_speedup:
            sections.append(f"Estimated Improvement: {self.estimated_speedup}")
            sections.append("")

        sections.append("Generated SQL:")
        sections.append(f"  {self.sql}")
        sections.append("")

        return "\n".join(sections)

    def _generate_name(self) -> str:
        """Generate a descriptive index name."""
        parts = ["idx", self.table]
        for name, _ in self.recommended_columns[:3]:
            parts.append(name)
        return "_".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "schema": self.schema,
            "recommended_columns": [
                {"name": n, "direction": d} for n, d in self.recommended_columns
            ],
            "include_columns": self.include_columns,
            "column_analysis": self.column_analysis,
            "ordering_rationale": self.ordering_rationale,
            "performance_notes": self.performance_notes,
            "estimated_speedup": self.estimated_speedup,
            "sort_eliminated": self.sort_eliminated,
            "covers_query": self.covers_query,
            "sql": self.sql,
            "explanation": self.explanation,
        }


# ── Advisor ──────────────────────────────────────────────────────────────


class IndexDesignAdvisor:
    """
    Educational index design advisor.

    Takes columns, cardinality data, and query context to recommend
    the optimal multi-column index ordering — and explains *why*.

    Core principles (from pganalyze Efficient Search p.17-18):
    1. Equality-filter columns first (exact match narrows most efficiently)
    2. Among equality columns, higher cardinality first (reduces B-tree pages traversed)
    3. Range-filter columns next (>, <, BETWEEN, LIKE)
    4. ORDER BY columns last (enables sort elimination)
    5. INCLUDE columns for index-only scans (avoid heap fetches)
    """

    def design(
        self,
        table: str,
        columns: list[str],
        cardinalities: dict[str, int] | None = None,
        order: dict[str, str] | None = None,
        where_columns: list[str] | None = None,
        range_columns: list[str] | None = None,
        select_columns: list[str] | None = None,
        schema: str = "public",
        table_rows: int = 0,
    ) -> IndexDesign:
        """
        Design an optimal multi-column index.

        Args:
            table: Table name
            columns: Columns to consider for the index
            cardinalities: Estimated n_distinct per column (from pg_stats)
            order: ORDER BY directions {"col": "DESC"}
            where_columns: Columns used in WHERE equality conditions
            range_columns: Columns used in range conditions (>, <, BETWEEN)
            select_columns: Columns in SELECT (for covering index)
            schema: Schema name
            table_rows: Approximate table row count

        Returns:
            IndexDesign with recommended ordering and educational explanation.
        """
        cardinalities = cardinalities or {}
        order = order or {}
        where_columns = where_columns or []
        range_columns = range_columns or []
        select_columns = select_columns or []

        # Build ColumnStats for each column
        stats: list[ColumnStats] = []
        for col in columns:
            card = cardinalities.get(col, 0)
            stats.append(ColumnStats(
                name=col,
                cardinality=card,
                is_in_where=col in where_columns or col in range_columns,
                is_in_order_by=col in order,
                is_in_select=col in select_columns,
                order_direction=order.get(col, "ASC"),
                is_equality=col in where_columns and col not in range_columns,
            ))

        # Step 1: Classify columns
        equality_cols = [s for s in stats if s.is_equality and s.is_in_where]
        range_cols = [s for s in stats if not s.is_equality and s.is_in_where]
        sort_cols = [s for s in stats if s.is_in_order_by and not s.is_in_where]
        other_cols = [s for s in stats if not s.is_in_where and not s.is_in_order_by]

        # Step 2: Order equality columns by cardinality (high first)
        equality_cols.sort(key=lambda s: s.cardinality, reverse=True)

        # Step 3: Order range columns by cardinality
        range_cols.sort(key=lambda s: s.cardinality, reverse=True)

        # Step 4: Sort columns keep their ORDER BY sequence
        # (they're already in the order specified)

        # Build recommended order
        ordered: list[ColumnStats] = equality_cols + range_cols + sort_cols

        # If all columns are in ORDER BY and none in WHERE, order by sort direction
        if not equality_cols and not range_cols and sort_cols:
            ordered = sort_cols

        # Include remaining columns not yet in the list
        seen = {s.name for s in ordered}
        for s in other_cols:
            if s.name not in seen:
                ordered.append(s)
                seen.add(s.name)

        # Build result
        result = IndexDesign(
            table=table,
            schema=schema,
        )

        # Recommended columns with direction
        for s in ordered:
            direction = order.get(s.name, "ASC")
            result.recommended_columns.append((s.name, direction))

        # Column analysis
        for s in ordered:
            card_str = f"cardinality: {s.cardinality:,}" if s.cardinality > 0 else "cardinality: unknown"
            role_parts: list[str] = []
            if s.is_equality:
                role_parts.append("equality filter")
            elif s.is_in_where:
                role_parts.append("range filter")
            if s.is_in_order_by:
                role_parts.append(f"ORDER BY {s.order_direction}")
            if s.is_in_select and not s.is_in_where and not s.is_in_order_by:
                role_parts.append("selected column")
            role = ", ".join(role_parts) if role_parts else "index column"

            result.column_analysis.append(
                f"{s.name} ({card_str}) — {role}"
            )

        # Ordering rationale
        if equality_cols:
            result.ordering_rationale.append(
                "Equality columns first: exact matches (=) narrow the B-tree "
                "most efficiently. PostgreSQL can skip directly to matching pages."
            )
            if len(equality_cols) > 1:
                top = equality_cols[0]
                bottom = equality_cols[-1]
                if top.cardinality > 0 and bottom.cardinality > 0:
                    result.ordering_rationale.append(
                        f"'{top.name}' before '{bottom.name}': "
                        f"{top.name} has {top.cardinality:,} distinct values vs "
                        f"{bottom.name}'s {bottom.cardinality:,}. Higher cardinality first "
                        f"means more selective initial B-tree traversal."
                    )

        if range_cols:
            result.ordering_rationale.append(
                "Range columns after equality: range conditions (>, <, BETWEEN) "
                "can only use the index after all equality prefixes are satisfied. "
                "Only one range column per index can be efficiently used."
            )

        if sort_cols:
            result.ordering_rationale.append(
                "Sort columns last: placing ORDER BY columns at the end of the "
                "index enables sort elimination — the index returns rows in the "
                "desired order, removing the need for an explicit Sort step."
            )
            result.sort_eliminated = True

        # Check for covering index opportunity
        all_index_cols = {s.name for s in ordered}
        uncovered_selects = [
            c for c in select_columns if c not in all_index_cols
        ]
        if select_columns and not uncovered_selects:
            result.covers_query = True
        elif uncovered_selects:
            result.include_columns = uncovered_selects
            result.performance_notes.append(
                f"INCLUDE ({', '.join(uncovered_selects)}) enables index-only scans: "
                f"PostgreSQL reads the index alone without touching the heap table."
            )
            result.covers_query = True

        # Performance estimates
        if table_rows > 0:
            estimated_pct = _estimate_scan_fraction(
                table_rows, equality_cols, range_cols,
            )
            if estimated_pct < 10:
                result.performance_notes.append(
                    f"This index should scan ~{estimated_pct:.1f}% of the table "
                    f"({int(table_rows * estimated_pct / 100):,} of {table_rows:,} rows). "
                    f"This is a highly selective index."
                )
                result.estimated_speedup = f"~{int(100 / max(estimated_pct, 0.1))}x vs sequential scan"
            elif estimated_pct < 50:
                result.estimated_speedup = f"~{int(100 / max(estimated_pct, 1))}x vs sequential scan"
            else:
                result.performance_notes.append(
                    "This index may not be very selective for this query. "
                    "Consider adding more WHERE conditions or different columns."
                )

        if result.sort_eliminated:
            result.performance_notes.append(
                "Sort elimination: the Sort node will disappear from the plan. "
                "For LIMIT queries, this is dramatic — PostgreSQL reads only the "
                "exact number of rows needed instead of sorting the entire result."
            )

        return result

    async def design_from_query(
        self,
        conn: Any,
        sql: str,
        schema: str = "public",
    ) -> IndexDesign:
        """
        Design an index by analyzing a SQL query against live database stats.

        Extracts columns from the query, fetches cardinality from pg_stats,
        and produces the optimal index design.

        Args:
            conn: asyncpg connection
            sql: SQL query to optimize
            schema: Schema to look up stats from

        Returns:
            IndexDesign with full educational explanation.
        """
        # Extract table and columns from SQL
        table, where_cols, order_cols, select_cols, range_cols = _parse_query(sql)

        if not table:
            return IndexDesign(
                table="<unknown>",
                ordering_rationale=["Could not parse table name from query"],
            )

        all_columns = list(
            dict.fromkeys(where_cols + range_cols + list(order_cols.keys()) + select_cols)
        )

        if not all_columns:
            return IndexDesign(
                table=table,
                ordering_rationale=["No indexable columns found in query"],
            )

        # Fetch cardinalities from pg_stats
        cardinalities: dict[str, int] = {}
        table_rows = 0

        try:
            stats_query = """
                SELECT attname, n_distinct, null_frac, avg_width
                FROM pg_stats
                WHERE schemaname = $1 AND tablename = $2
                  AND attname = ANY($3)
            """
            rows = await conn.fetch(stats_query, schema, table, all_columns)
            for row in rows:
                n_distinct = float(row["n_distinct"])
                if n_distinct < 0:
                    # Negative means fraction of rows
                    row_count = await conn.fetchval(
                        "SELECT reltuples::bigint FROM pg_class WHERE relname = $1",
                        table,
                    )
                    table_rows = int(row_count or 0)
                    n_distinct = abs(n_distinct) * table_rows
                cardinalities[row["attname"]] = max(1, int(n_distinct))

            if table_rows == 0:
                row_count = await conn.fetchval(
                    "SELECT reltuples::bigint FROM pg_class WHERE relname = $1",
                    table,
                )
                table_rows = int(row_count or 0)

        except Exception:
            pass  # Fall back to design without stats

        return self.design(
            table=table,
            columns=all_columns,
            cardinalities=cardinalities,
            order=order_cols,
            where_columns=where_cols,
            range_columns=range_cols,
            select_columns=select_cols,
            schema=schema,
            table_rows=table_rows,
        )


# ── SQL parsing helpers ──────────────────────────────────────────────────


def _parse_query(
    sql: str,
) -> tuple[str, list[str], dict[str, str], list[str], list[str]]:
    """
    Extract table, WHERE columns, ORDER BY columns, SELECT columns,
    and range columns from a SQL query.

    Returns:
        (table, where_cols, order_cols, select_cols, range_cols)
    """
    sql_upper = sql.upper()
    sql_clean = re.sub(r"\s+", " ", sql).strip()

    table = ""
    where_cols: list[str] = []
    order_cols: dict[str, str] = {}
    select_cols: list[str] = []
    range_cols: list[str] = []

    # Extract table from FROM clause
    from_match = re.search(r"\bFROM\s+(\w+(?:\.\w+)?)", sql_clean, re.IGNORECASE)
    if from_match:
        table = from_match.group(1)
        if "." in table:
            table = table.split(".")[-1]

    # Extract WHERE columns
    where_match = re.search(
        r"\bWHERE\s+(.*?)(?:\bGROUP\b|\bORDER\b|\bLIMIT\b|\bHAVING\b|$)",
        sql_clean, re.IGNORECASE,
    )
    if where_match:
        where_clause = where_match.group(1)
        # Equality: col = value
        for m in re.finditer(r"(\w+)\s*=\s*(?![\s]*>)", where_clause):
            col = m.group(1).lower()
            if col not in ("and", "or", "not", "in", "is", "null", "true", "false"):
                where_cols.append(col)

        # Range: col > value, col < value, col BETWEEN, col >= value
        for m in re.finditer(r"(\w+)\s*(?:>|<|>=|<=|BETWEEN)\s", where_clause, re.IGNORECASE):
            col = m.group(1).lower()
            if col not in ("and", "or", "not"):
                range_cols.append(col)
                # Remove from equality if also there
                if col in where_cols:
                    where_cols.remove(col)

        # IN clause: col IN (...)
        for m in re.finditer(r"(\w+)\s+IN\s*\(", where_clause, re.IGNORECASE):
            col = m.group(1).lower()
            if col not in ("and", "or", "not") and col not in where_cols:
                where_cols.append(col)

    # Extract ORDER BY columns
    order_match = re.search(
        r"\bORDER\s+BY\s+(.*?)(?:\bLIMIT\b|\bOFFSET\b|$)",
        sql_clean, re.IGNORECASE,
    )
    if order_match:
        order_clause = order_match.group(1)
        for part in order_clause.split(","):
            part = part.strip()
            direction = "ASC"
            if "DESC" in part.upper():
                direction = "DESC"
            col_match = re.match(r"(\w+(?:\.\w+)?)", part)
            if col_match:
                col = col_match.group(1)
                if "." in col:
                    col = col.split(".")[-1]
                order_cols[col.lower()] = direction

    # Extract SELECT columns (simplified)
    select_match = re.search(
        r"\bSELECT\s+(.*?)\bFROM\b",
        sql_clean, re.IGNORECASE,
    )
    if select_match:
        select_clause = select_match.group(1)
        if "*" not in select_clause:
            for part in select_clause.split(","):
                part = part.strip()
                # Handle aliases
                alias_match = re.search(r"(?:AS\s+)?(\w+)\s*$", part, re.IGNORECASE)
                col_match = re.match(r"(\w+(?:\.\w+)?)", part)
                if col_match:
                    col = col_match.group(1)
                    if "." in col:
                        col = col.split(".")[-1]
                    if col.lower() not in ("as",):
                        select_cols.append(col.lower())

    return table, where_cols, order_cols, select_cols, range_cols


def _estimate_scan_fraction(
    table_rows: int,
    equality_cols: list[ColumnStats],
    range_cols: list[ColumnStats],
) -> float:
    """Estimate what fraction of the table an index scan would touch."""
    fraction = 100.0

    for col in equality_cols:
        if col.cardinality > 0:
            fraction *= (1.0 / col.cardinality)

    for col in range_cols:
        if col.cardinality > 0:
            # Range conditions typically scan ~10-30% of distinct values
            fraction *= 0.3

    return max(fraction, 0.001)  # At least 0.001%
