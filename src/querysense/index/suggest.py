"""
Unified Index Suggestion Engine.

Reverse-engineered from Lukas Fittl's "Effective Indexing in Postgres"
(pganalyze, 2024). Combines type selection, partial index detection,
expression index detection, covering index analysis, and multi-column
ordering into a single pass over a SQL query.

This is the spec that pganalyze charges $149-399/mo for. QuerySense
does it for free, in your CLI, with full explanations.

Architecture
------------
IndexTypeSuggestor   - BTREE vs GIN vs GiST vs BRIN based on operators
PartialIndexDetector - WHERE constants that filter <20% of rows
ExpressionDetector   - Function calls on columns in WHERE
CoveringAdvisor      - INCLUDE columns for index-only scans
ColumnOrderOptimizer - Equality first, then range, then sort (high cardinality first)
UnifiedSuggestor     - Orchestrator combining all of the above

References
----------
- Fittl, "Effective Indexing in Postgres" (pganalyze, 2024)
- Dombrovskaya et al., "PostgreSQL Query Optimization" (2024), Ch. 5
- PostgreSQL docs: Index Types, Partial Indexes, Expression Indexes
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Enums ────────────────────────────────────────────────────────────────


class SuggestedIndexType(str, Enum):
    """PostgreSQL index access methods."""
    BTREE = "btree"
    GIN = "gin"
    GIST = "gist"
    BRIN = "brin"
    HASH = "hash"
    SPGIST = "spgist"


class OperatorClass(str, Enum):
    """Operator classes that influence index type selection."""
    EQUALITY = "equality"           # =, IN
    RANGE = "range"                 # <, >, <=, >=, BETWEEN
    PATTERN = "pattern"             # LIKE 'val%'
    WILDCARD = "wildcard"           # LIKE '%val%'
    FTS = "full_text_search"        # @@ tsvector
    TRIGRAM = "trigram"             # %, similarity()
    JSONB = "jsonb"                 # @>, ?, ?|, ?&
    ARRAY = "array"                 # @>, &&, <@
    GEOMETRIC = "geometric"         # <->, <<, >>
    RANGE_TYPE = "range_type"       # @>, <@, && on range types
    ORDERING = "ordering"           # ORDER BY
    IS_NULL = "is_null"             # IS NULL, IS NOT NULL


# ── Data classes ─────────────────────────────────────────────────────────


@dataclass
class ColumnRef:
    """A column reference extracted from SQL."""
    name: str
    table: str = ""
    alias: str = ""
    data_type: str = ""             # Inferred from operators/values
    operators: list[OperatorClass] = field(default_factory=list)
    literal_value: str = ""         # For partial index WHERE clause
    function_name: str = ""         # e.g. "lower", "date_trunc"
    function_args: str = ""         # Full expression: "lower(email)"
    sort_direction: str = "ASC"
    is_in_where: bool = False
    is_in_select: bool = False
    is_in_order: bool = False
    is_in_join: bool = False
    is_in_group: bool = False
    is_equality: bool = False
    is_range: bool = False
    estimated_selectivity: float = 0.5


@dataclass
class TypeSuggestion:
    """Index type recommendation with rationale."""
    index_type: SuggestedIndexType
    operator_class: str = ""
    ops_suffix: str = ""            # e.g. "gin_trgm_ops", "jsonb_path_ops"
    rationale: str = ""
    alternative: str = ""
    textbook_ref: str = ""


@dataclass
class PartialSuggestion:
    """Partial index opportunity."""
    where_clause: str               # The WHERE predicate for the partial index
    column: str
    literal_value: str
    estimated_selectivity: float     # Fraction of table matching the filter
    size_reduction_pct: float        # How much smaller the index is
    rationale: str = ""


@dataclass
class ExpressionSuggestion:
    """Expression index opportunity."""
    expression: str                  # e.g. "lower(email)"
    original_column: str
    function_name: str
    rationale: str = ""


@dataclass
class CoveringSuggestion:
    """Covering index (INCLUDE) opportunity."""
    include_columns: list[str]       # Columns to add via INCLUDE
    rationale: str = ""
    enables_index_only_scan: bool = True


@dataclass
class IndexSuggestion:
    """Complete index recommendation from the unified engine."""
    # The SQL
    create_sql: str
    table: str
    schema: str = "public"

    # Key columns (in recommended order)
    key_columns: list[tuple[str, str]] = field(default_factory=list)  # (col, direction)
    include_columns: list[str] = field(default_factory=list)

    # Sub-suggestions
    type_suggestion: TypeSuggestion | None = None
    partial_suggestions: list[PartialSuggestion] = field(default_factory=list)
    expression_suggestions: list[ExpressionSuggestion] = field(default_factory=list)
    covering_suggestion: CoveringSuggestion | None = None

    # Column ordering rationale
    ordering_rationale: list[str] = field(default_factory=list)

    # Impact estimates
    estimated_speedup: str = ""
    estimated_size_mb: str = ""

    # Explanation
    summary: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "create_sql": self.create_sql,
            "table": self.table,
            "key_columns": [{"column": c, "direction": d} for c, d in self.key_columns],
            "include_columns": self.include_columns,
            "type": self.type_suggestion.index_type.value if self.type_suggestion else "btree",
            "ops_suffix": self.type_suggestion.ops_suffix if self.type_suggestion else "",
            "partial_indexes": [
                {
                    "where_clause": p.where_clause,
                    "column": p.column,
                    "selectivity": round(p.estimated_selectivity, 3),
                    "size_reduction_pct": round(p.size_reduction_pct, 1),
                    "rationale": p.rationale,
                }
                for p in self.partial_suggestions
            ],
            "expression_indexes": [
                {
                    "expression": e.expression,
                    "column": e.original_column,
                    "function": e.function_name,
                    "rationale": e.rationale,
                }
                for e in self.expression_suggestions
            ],
            "covering": {
                "include_columns": self.covering_suggestion.include_columns,
                "enables_index_only_scan": self.covering_suggestion.enables_index_only_scan,
            } if self.covering_suggestion else None,
            "ordering_rationale": self.ordering_rationale,
            "estimated_speedup": self.estimated_speedup,
            "summary": self.summary,
            "notes": self.notes,
        }


@dataclass
class SuggestResult:
    """Complete result from the unified suggest engine."""
    sql: str
    table: str = ""
    primary_suggestion: IndexSuggestion | None = None
    alternatives: list[IndexSuggestion] = field(default_factory=list)
    columns_analyzed: list[ColumnRef] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sql": self.sql[:500],
            "table": self.table,
            "primary": self.primary_suggestion.to_dict() if self.primary_suggestion else None,
            "alternatives": [a.to_dict() for a in self.alternatives],
            "columns": [
                {
                    "name": c.name,
                    "operators": [o.value for o in c.operators],
                    "is_equality": c.is_equality,
                    "is_range": c.is_range,
                    "function": c.function_name or None,
                }
                for c in self.columns_analyzed
            ],
            "notes": self.notes,
        }


# ── SQL parsing helpers ──────────────────────────────────────────────────


_FROM_RE = re.compile(r"\bFROM\s+(\w+(?:\.\w+)?)", re.IGNORECASE)
_WHERE_RE = re.compile(r"\bWHERE\s+(.+?)(?:\bGROUP\b|\bORDER\b|\bLIMIT\b|\bHAVING\b|;|$)", re.IGNORECASE | re.DOTALL)
_SELECT_RE = re.compile(r"\bSELECT\s+(.+?)\s+FROM\b", re.IGNORECASE | re.DOTALL)
_ORDER_RE = re.compile(r"\bORDER\s+BY\s+(.+?)(?:\bLIMIT\b|\bOFFSET\b|;|$)", re.IGNORECASE | re.DOTALL)
_GROUP_RE = re.compile(r"\bGROUP\s+BY\s+(.+?)(?:\bHAVING\b|\bORDER\b|\bLIMIT\b|;|$)", re.IGNORECASE | re.DOTALL)
_JOIN_RE = re.compile(r"\bJOIN\s+\w+\s+\w*\s*ON\s+(.+?)(?:\bWHERE\b|\bJOIN\b|\bGROUP\b|\bORDER\b|$)", re.IGNORECASE | re.DOTALL)

# Function calls in WHERE: lower(col), upper(col), date_trunc('day', col), etc.
_FUNC_CALL_RE = re.compile(
    r"(lower|upper|trim|ltrim|rtrim|date_trunc|substr|substring|coalesce|cast|"
    r"extract|date_part|to_char|length|reverse|md5|left|right|"
    r"regexp_replace|translate|btrim|initcap)\s*\(\s*"
    r"(?:'[^']*'\s*,\s*)?(\w+(?:\.\w+)?)",
    re.IGNORECASE,
)

# Equality: col = 'val' or col = $1 or col IN (...)
_EQ_RE = re.compile(r"(\w+(?:\.\w+)?)\s*=\s*('([^']*)'|\$\d+|\?)", re.IGNORECASE)
_IN_RE = re.compile(r"(\w+(?:\.\w+)?)\s+IN\s*\(", re.IGNORECASE)

# Range: col > val, col < val, col BETWEEN, col >= val
_RANGE_RE = re.compile(r"(\w+(?:\.\w+)?)\s*(>=?|<=?|BETWEEN)\s*", re.IGNORECASE)

# LIKE / ILIKE
_LIKE_RE = re.compile(r"(\w+(?:\.\w+)?)\s+(NOT\s+)?(I?LIKE)\s+'([^']*)'", re.IGNORECASE)

# FTS
_FTS_RE = re.compile(r"to_tsvector\s*\(.*?(\w+(?:\.\w+)?)\s*\)\s*@@", re.IGNORECASE)

# Trigram
_TRGM_RE = re.compile(r"(\w+(?:\.\w+)?)\s+%\s+|similarity\s*\(\s*(\w+)", re.IGNORECASE)

# JSONB
_JSONB_RE = re.compile(r"(\w+(?:\.\w+)?)\s+@>\s+'?\{", re.IGNORECASE)
_JSONB_EXISTS_RE = re.compile(r"(\w+(?:\.\w+)?)\s+\?\s*'", re.IGNORECASE)

# Array
_ARRAY_OP_RE = re.compile(r"(\w+(?:\.\w+)?)\s+(@>|<@|&&)\s+ARRAY", re.IGNORECASE)

# IS NULL / IS NOT NULL
_NULL_RE = re.compile(r"(\w+(?:\.\w+)?)\s+IS\s+(NOT\s+)?NULL", re.IGNORECASE)

# ORDER BY columns
_ORDER_COL_RE = re.compile(r"(\w+(?:\.\w+)?)\s*(DESC|ASC)?", re.IGNORECASE)

# SELECT column list (excluding *)
_SELECT_COL_RE = re.compile(r"(\w+(?:\.\w+)?)\s*(?:,|$)", re.IGNORECASE)


# Constant literals that indicate partial-index-friendly patterns
_STATUS_LIKE = re.compile(
    r"(status|state|type|kind|category|active|deleted|archived|role|"
    r"is_\w+|has_\w+|enabled|disabled|published|draft|pending|verified)",
    re.IGNORECASE,
)


# ── Index Type Decision Matrix (Fittl, p.3) ─────────────────────────────


_TYPE_MATRIX: dict[OperatorClass, TypeSuggestion] = {
    OperatorClass.EQUALITY: TypeSuggestion(
        index_type=SuggestedIndexType.BTREE,
        rationale="BTREE is optimal for equality (=) and IN lookups. O(log n) per lookup.",
        alternative="HASH index is even faster for equality-only, but doesn't support range scans.",
        textbook_ref="Fittl, 'Effective Indexing', Index Types: BTREE",
    ),
    OperatorClass.RANGE: TypeSuggestion(
        index_type=SuggestedIndexType.BTREE,
        rationale="BTREE handles range scans (>, <, >=, <=, BETWEEN) by walking leaf pages in order.",
        textbook_ref="Fittl, 'Effective Indexing', Index Types: BTREE",
    ),
    OperatorClass.PATTERN: TypeSuggestion(
        index_type=SuggestedIndexType.BTREE,
        ops_suffix="text_pattern_ops",
        rationale="Anchored prefix patterns (LIKE 'val%') use BTREE with text_pattern_ops.",
        alternative="pg_trgm GIN if you also need wildcard (%val%) support.",
        textbook_ref="Fittl, 'Effective Indexing', Index Types: BTREE with opclass",
    ),
    OperatorClass.WILDCARD: TypeSuggestion(
        index_type=SuggestedIndexType.GIN,
        ops_suffix="gin_trgm_ops",
        rationale="Leading-wildcard LIKE ('%val%', '%val') requires pg_trgm GIN. BTREE cannot help.",
        textbook_ref="pganalyze 'Efficient Search', p.3: Trigram",
    ),
    OperatorClass.FTS: TypeSuggestion(
        index_type=SuggestedIndexType.GIN,
        rationale="GIN on tsvector for full-text search. Supports stemming, ranking, phrase queries.",
        alternative="GiST tsvector: smaller, faster updates, supports KNN, but slower reads.",
        textbook_ref="Fittl, 'Effective Indexing', Index Types: GIN",
    ),
    OperatorClass.TRIGRAM: TypeSuggestion(
        index_type=SuggestedIndexType.GIN,
        ops_suffix="gin_trgm_ops",
        rationale="GIN with pg_trgm for similarity() and % operator. Fuzzy matching, typo tolerance.",
        textbook_ref="pganalyze 'Efficient Search', p.3: Trigram",
    ),
    OperatorClass.JSONB: TypeSuggestion(
        index_type=SuggestedIndexType.GIN,
        ops_suffix="jsonb_path_ops",
        rationale="GIN with jsonb_path_ops for JSONB @> containment. 2-3x smaller than default GIN.",
        alternative="GIN (default ops): supports @>, ?, ?|, ?&. Use if you need ? operator.",
        textbook_ref="Fittl, 'Effective Indexing', Index Types: GIN for JSONB",
    ),
    OperatorClass.ARRAY: TypeSuggestion(
        index_type=SuggestedIndexType.GIN,
        rationale="GIN for array @>, &&, <@ operators. Default array_ops.",
        textbook_ref="Fittl, 'Effective Indexing', Index Types: GIN for arrays",
    ),
    OperatorClass.GEOMETRIC: TypeSuggestion(
        index_type=SuggestedIndexType.GIST,
        rationale="GiST for geometric and spatial operators (<->, <<, >>). Also PostGIS.",
        textbook_ref="Fittl, 'Effective Indexing', Index Types: GiST",
    ),
    OperatorClass.RANGE_TYPE: TypeSuggestion(
        index_type=SuggestedIndexType.GIST,
        rationale="GiST for range type operators (@>, <@, &&). Handles overlapping ranges.",
        textbook_ref="Fittl, 'Effective Indexing', Index Types: GiST for ranges",
    ),
    OperatorClass.ORDERING: TypeSuggestion(
        index_type=SuggestedIndexType.BTREE,
        rationale="BTREE provides ordered output, eliminating explicit sort operations.",
        textbook_ref="Fittl, 'Effective Indexing', Sort Elimination",
    ),
    OperatorClass.IS_NULL: TypeSuggestion(
        index_type=SuggestedIndexType.BTREE,
        rationale="BTREE includes NULLs (since PG 8.3). IS NULL/IS NOT NULL can use BTREE index.",
        textbook_ref="PostgreSQL docs: Indexes and NULL",
    ),
}


# ── UnifiedSuggestor ─────────────────────────────────────────────────────


class UnifiedSuggestor:
    """
    Unified index suggestion engine.

    From a single SQL query, produces recommendations covering:
    - Index type (BTREE/GIN/GiST/BRIN/HASH)
    - Partial indexes (WHERE clause for constants)
    - Expression indexes (function calls on columns)
    - Covering indexes (INCLUDE columns for index-only scans)
    - Multi-column ordering (equality first, range, then sort)
    """

    def suggest(self, sql: str) -> SuggestResult:
        """Analyze a SQL query and produce index recommendations."""
        result = SuggestResult(sql=sql)

        # 1. Extract table
        table = self._extract_table(sql)
        result.table = table

        # 2. Extract column references from all clauses
        columns = self._extract_columns(sql, table)
        result.columns_analyzed = columns

        if not columns:
            result.notes.append("No indexable column patterns detected.")
            return result

        # 3. Determine index type
        type_suggestion = self._suggest_type(columns)

        # 4. Detect partial index opportunities
        partial_suggestions = self._detect_partial(columns)

        # 5. Detect expression index opportunities
        expression_suggestions = self._detect_expressions(columns)

        # 6. Determine column order (equality -> range -> sort)
        key_columns, ordering_rationale = self._optimize_column_order(columns)

        # 7. Detect covering index opportunities
        covering = self._detect_covering(columns, key_columns)

        # 8. Build primary recommendation
        primary = self._build_suggestion(
            table=table,
            key_columns=key_columns,
            type_suggestion=type_suggestion,
            partial_suggestions=partial_suggestions,
            expression_suggestions=expression_suggestions,
            covering=covering,
            ordering_rationale=ordering_rationale,
        )
        result.primary_suggestion = primary

        # 9. Build alternatives
        result.alternatives = self._build_alternatives(
            table, columns, key_columns, type_suggestion,
            partial_suggestions, expression_suggestions, covering,
        )

        return result

    # ── Extract table ────────────────────────────────────────────────

    def _extract_table(self, sql: str) -> str:
        m = _FROM_RE.search(sql)
        return m.group(1) if m else ""

    # ── Extract columns ──────────────────────────────────────────────

    def _extract_columns(self, sql: str, table: str) -> list[ColumnRef]:
        """Extract all column references with their contexts."""
        columns: dict[str, ColumnRef] = {}

        def _get_or_create(name: str) -> ColumnRef:
            clean = name.split(".")[-1] if "." in name else name
            if clean not in columns:
                columns[clean] = ColumnRef(name=clean, table=table)
            return columns[clean]

        # WHERE clause
        where_match = _WHERE_RE.search(sql)
        where_text = where_match.group(1) if where_match else ""

        # Equality in WHERE
        for m in _EQ_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            col.is_equality = True
            if OperatorClass.EQUALITY not in col.operators:
                col.operators.append(OperatorClass.EQUALITY)
            if m.group(3):  # Literal value
                col.literal_value = m.group(3)

        # IN in WHERE
        for m in _IN_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            col.is_equality = True
            if OperatorClass.EQUALITY not in col.operators:
                col.operators.append(OperatorClass.EQUALITY)

        # Range in WHERE
        for m in _RANGE_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            col.is_range = True
            if OperatorClass.RANGE not in col.operators:
                col.operators.append(OperatorClass.RANGE)

        # LIKE/ILIKE
        for m in _LIKE_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            value = m.group(4)
            if value.startswith("%"):
                if OperatorClass.WILDCARD not in col.operators:
                    col.operators.append(OperatorClass.WILDCARD)
            else:
                if OperatorClass.PATTERN not in col.operators:
                    col.operators.append(OperatorClass.PATTERN)

        # FTS
        for m in _FTS_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            if OperatorClass.FTS not in col.operators:
                col.operators.append(OperatorClass.FTS)

        # Trigram
        for m in _TRGM_RE.finditer(where_text):
            name = m.group(1) or m.group(2)
            if name:
                col = _get_or_create(name)
                col.is_in_where = True
                if OperatorClass.TRIGRAM not in col.operators:
                    col.operators.append(OperatorClass.TRIGRAM)

        # JSONB
        for m in _JSONB_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            if OperatorClass.JSONB not in col.operators:
                col.operators.append(OperatorClass.JSONB)
        for m in _JSONB_EXISTS_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            if OperatorClass.JSONB not in col.operators:
                col.operators.append(OperatorClass.JSONB)

        # Array
        for m in _ARRAY_OP_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            if OperatorClass.ARRAY not in col.operators:
                col.operators.append(OperatorClass.ARRAY)

        # IS NULL
        for m in _NULL_RE.finditer(where_text):
            col = _get_or_create(m.group(1))
            col.is_in_where = True
            if OperatorClass.IS_NULL not in col.operators:
                col.operators.append(OperatorClass.IS_NULL)

        # Function calls in WHERE (expression indexes)
        for m in _FUNC_CALL_RE.finditer(where_text):
            func_name = m.group(1).lower()
            col_name = m.group(2)
            col = _get_or_create(col_name)
            col.is_in_where = True
            col.function_name = func_name
            col.function_args = f"{func_name}({col_name})"

        # ORDER BY
        order_match = _ORDER_RE.search(sql)
        if order_match:
            for m in _ORDER_COL_RE.finditer(order_match.group(1)):
                name = m.group(1)
                if name.upper() in ("ASC", "DESC", "NULLS", "FIRST", "LAST", "LIMIT"):
                    continue
                col = _get_or_create(name)
                col.is_in_order = True
                col.sort_direction = (m.group(2) or "ASC").upper()
                if OperatorClass.ORDERING not in col.operators:
                    col.operators.append(OperatorClass.ORDERING)

        # GROUP BY
        group_match = _GROUP_RE.search(sql)
        if group_match:
            for m in _ORDER_COL_RE.finditer(group_match.group(1)):
                name = m.group(1)
                if name.upper() in ("ASC", "DESC"):
                    continue
                col = _get_or_create(name)
                col.is_in_group = True

        # SELECT columns
        select_match = _SELECT_RE.search(sql)
        if select_match:
            select_text = select_match.group(1).strip()
            if select_text != "*":
                for m in _SELECT_COL_RE.finditer(select_text):
                    name = m.group(1)
                    if name.upper() in ("DISTINCT", "AS", "COUNT", "SUM", "AVG", "MIN", "MAX"):
                        continue
                    col = _get_or_create(name)
                    col.is_in_select = True

        # JOIN ON
        for m in _JOIN_RE.finditer(sql):
            for eq in _EQ_RE.finditer(m.group(1)):
                col = _get_or_create(eq.group(1))
                col.is_in_join = True
                col.is_equality = True
                if OperatorClass.EQUALITY not in col.operators:
                    col.operators.append(OperatorClass.EQUALITY)

        # Estimate selectivity for partial-index candidates
        for col in columns.values():
            if col.literal_value and _STATUS_LIKE.match(col.name):
                col.estimated_selectivity = 0.1  # Status-like columns are typically selective

        return list(columns.values())

    # ── Index type selection ─────────────────────────────────────────

    def _suggest_type(self, columns: list[ColumnRef]) -> TypeSuggestion:
        """Select the optimal index type based on operators used."""
        # Priority order for non-BTREE types (these override BTREE)
        priority = [
            OperatorClass.FTS,
            OperatorClass.TRIGRAM,
            OperatorClass.WILDCARD,
            OperatorClass.JSONB,
            OperatorClass.ARRAY,
            OperatorClass.GEOMETRIC,
            OperatorClass.RANGE_TYPE,
        ]

        for op_class in priority:
            for col in columns:
                if op_class in col.operators:
                    return _TYPE_MATRIX[op_class]

        # Default to BTREE
        if any(OperatorClass.RANGE in c.operators for c in columns):
            return _TYPE_MATRIX[OperatorClass.RANGE]
        if any(OperatorClass.PATTERN in c.operators for c in columns):
            return _TYPE_MATRIX[OperatorClass.PATTERN]

        return _TYPE_MATRIX[OperatorClass.EQUALITY]

    # ── Partial index detection ──────────────────────────────────────

    def _detect_partial(self, columns: list[ColumnRef]) -> list[PartialSuggestion]:
        """Detect opportunities for partial indexes."""
        suggestions: list[PartialSuggestion] = []

        for col in columns:
            if not col.literal_value or not col.is_equality:
                continue

            # Heuristic: status-like columns with constant values
            selectivity = col.estimated_selectivity
            if selectivity > 0.3:
                continue  # Not selective enough

            size_reduction = (1 - selectivity) * 100

            suggestions.append(PartialSuggestion(
                where_clause=f"{col.name} = '{col.literal_value}'",
                column=col.name,
                literal_value=col.literal_value,
                estimated_selectivity=selectivity,
                size_reduction_pct=size_reduction,
                rationale=(
                    f"Column '{col.name}' is filtered to a constant value "
                    f"('{col.literal_value}'). A partial index on the remaining "
                    f"columns WHERE {col.name} = '{col.literal_value}' would be "
                    f"~{size_reduction:.0f}% smaller while serving this query identically."
                ),
            ))

        return suggestions

    # ── Expression index detection ───────────────────────────────────

    def _detect_expressions(self, columns: list[ColumnRef]) -> list[ExpressionSuggestion]:
        """Detect function calls on columns that need expression indexes."""
        suggestions: list[ExpressionSuggestion] = []

        for col in columns:
            if not col.function_name:
                continue

            suggestions.append(ExpressionSuggestion(
                expression=col.function_args,
                original_column=col.name,
                function_name=col.function_name,
                rationale=(
                    f"Query uses {col.function_name}({col.name}) in WHERE. "
                    f"A regular index on '{col.name}' cannot be used because the "
                    f"planner sees {col.function_name}() as a black box. Create an "
                    f"expression index on {col.function_args} to enable index scans."
                ),
            ))

        return suggestions

    # ── Column order optimization ────────────────────────────────────

    def _optimize_column_order(
        self, columns: list[ColumnRef]
    ) -> tuple[list[tuple[str, str]], list[str]]:
        """
        Optimal multi-column index ordering (Fittl, p.17-18):
        1. Equality columns first (highest selectivity first)
        2. Range columns next
        3. ORDER BY columns last (for sort elimination)
        """
        rationale: list[str] = []
        equality_cols: list[ColumnRef] = []
        range_cols: list[ColumnRef] = []
        order_cols: list[ColumnRef] = []

        for col in columns:
            if col.function_name:
                continue
            # Skip non-BTREE-friendly operators
            if any(op in col.operators for op in (
                OperatorClass.FTS, OperatorClass.TRIGRAM,
                OperatorClass.JSONB, OperatorClass.ARRAY,
                OperatorClass.GEOMETRIC, OperatorClass.RANGE_TYPE,
            )):
                continue

            if col.is_equality and col.is_in_where:
                equality_cols.append(col)
            elif col.is_range and col.is_in_where:
                range_cols.append(col)
            elif col.is_in_order and not col.is_in_where:
                order_cols.append(col)

        # Sort equality columns by selectivity (most selective first)
        equality_cols.sort(key=lambda c: c.estimated_selectivity)

        if equality_cols:
            names = [c.name for c in equality_cols]
            rationale.append(
                f"Equality columns first: {', '.join(names)} "
                f"(narrows search via tree traversal)"
            )

        if range_cols:
            names = [c.name for c in range_cols]
            rationale.append(
                f"Range columns next: {', '.join(names)} "
                f"(only the first range column can use the index efficiently)"
            )

        if order_cols:
            names = [f"{c.name} {c.sort_direction}" for c in order_cols]
            rationale.append(
                f"Sort columns last: {', '.join(names)} "
                f"(eliminates explicit sort, enables index-ordered output)"
            )

        result: list[tuple[str, str]] = []
        for col in equality_cols:
            result.append((col.name, "ASC"))
        for col in range_cols:
            result.append((col.name, "ASC"))
        for col in order_cols:
            result.append((col.name, col.sort_direction))

        return result, rationale

    # ── Covering index detection ─────────────────────────────────────

    def _detect_covering(
        self,
        columns: list[ColumnRef],
        key_columns: list[tuple[str, str]],
    ) -> CoveringSuggestion | None:
        """Detect INCLUDE columns for covering index / index-only scans."""
        key_names = {k for k, _ in key_columns}
        select_only = [
            c for c in columns
            if c.is_in_select and c.name not in key_names
            and not c.is_in_where and not c.is_in_order
        ]

        if not select_only:
            return None

        # Check if there are SELECT * (no specific columns)
        has_star = any(c.name == "*" for c in columns)
        if has_star:
            return None

        include_names = [c.name for c in select_only]
        return CoveringSuggestion(
            include_columns=include_names,
            rationale=(
                f"Query SELECTs {', '.join(include_names)} which are not in the "
                f"index key. Adding them via INCLUDE enables index-only scans, "
                f"eliminating heap access and reducing I/O by 80-90%."
            ),
            enables_index_only_scan=True,
        )

    # ── Build suggestion ─────────────────────────────────────────────

    def _build_suggestion(
        self,
        table: str,
        key_columns: list[tuple[str, str]],
        type_suggestion: TypeSuggestion,
        partial_suggestions: list[PartialSuggestion],
        expression_suggestions: list[ExpressionSuggestion],
        covering: CoveringSuggestion | None,
        ordering_rationale: list[str],
    ) -> IndexSuggestion:
        """Build the primary index suggestion with CREATE SQL."""
        safe_table = table.replace(".", "_") or "table"
        idx_type = type_suggestion.index_type
        ops = type_suggestion.ops_suffix

        # Build column list for CREATE INDEX
        if expression_suggestions and idx_type == SuggestedIndexType.BTREE:
            # Expression index: use function calls as key columns
            col_parts = []
            for expr in expression_suggestions:
                col_parts.append(expr.expression)
            for name, direction in key_columns:
                if name not in [e.original_column for e in expression_suggestions]:
                    part = f"{name} {direction}" if direction == "DESC" else name
                    col_parts.append(part)
        else:
            col_parts = []
            for name, direction in key_columns:
                if ops:
                    col_parts.append(f"{name} {ops}")
                elif direction == "DESC":
                    col_parts.append(f"{name} DESC")
                else:
                    col_parts.append(name)

        if not col_parts:
            col_parts = ["<column>"]

        # Index name
        col_names = "_".join(
            c.split("(")[-1].rstrip(")").split(" ")[0]
            for c in col_parts[:3]
        )
        suffix = f"_{idx_type.value}" if idx_type != SuggestedIndexType.BTREE else ""
        idx_name = f"idx_{safe_table}_{col_names}{suffix}"

        # USING clause
        using = ""
        if idx_type != SuggestedIndexType.BTREE:
            using = f" USING {idx_type.value.upper()}"

        # INCLUDE clause
        include_clause = ""
        include_cols: list[str] = []
        if covering and idx_type == SuggestedIndexType.BTREE:
            include_cols = covering.include_columns
            include_clause = f" INCLUDE ({', '.join(include_cols)})"

        # WHERE clause (partial)
        where_clause = ""
        best_partial = None
        if partial_suggestions:
            best_partial = max(partial_suggestions, key=lambda p: p.size_reduction_pct)
            where_clause = f"\n    WHERE {best_partial.where_clause}"

        # Assemble CREATE INDEX
        col_str = ", ".join(col_parts)
        create_sql = (
            f"CREATE INDEX CONCURRENTLY {idx_name}\n"
            f"    ON {table or '<table>'}{using} ({col_str})"
            f"{include_clause}{where_clause};"
        )

        # Estimate speedup
        if idx_type in (SuggestedIndexType.GIN, SuggestedIndexType.GIST):
            speedup = "50-1000x"
        elif best_partial:
            speedup = "50-200x (partial: smaller index, faster writes)"
        elif covering:
            speedup = "10-100x (index-only scan: no heap access)"
        else:
            speedup = "10-100x"

        # Summary
        parts = [type_suggestion.index_type.value.upper()]
        if expression_suggestions:
            parts.append("expression")
        if best_partial:
            parts.append(f"partial (WHERE {best_partial.where_clause})")
        if covering:
            parts.append(f"covering (INCLUDE {', '.join(include_cols)})")
        if len(key_columns) > 1:
            parts.append("composite")

        summary = f"{' + '.join(parts)} index on {table or '<table>'}"

        return IndexSuggestion(
            create_sql=create_sql,
            table=table,
            key_columns=key_columns,
            include_columns=include_cols,
            type_suggestion=type_suggestion,
            partial_suggestions=partial_suggestions,
            expression_suggestions=expression_suggestions,
            covering_suggestion=covering,
            ordering_rationale=ordering_rationale,
            estimated_speedup=speedup,
            summary=summary,
            notes=[type_suggestion.rationale],
        )

    # ── Alternatives ─────────────────────────────────────────────────

    def _build_alternatives(
        self,
        table: str,
        columns: list[ColumnRef],
        key_columns: list[tuple[str, str]],
        type_suggestion: TypeSuggestion,
        partial_suggestions: list[PartialSuggestion],
        expression_suggestions: list[ExpressionSuggestion],
        covering: CoveringSuggestion | None,
    ) -> list[IndexSuggestion]:
        """Build alternative index suggestions."""
        alts: list[IndexSuggestion] = []
        safe_table = table.replace(".", "_") or "table"

        # Alt 1: If we suggested partial, also offer the non-partial version
        if partial_suggestions:
            col_parts = []
            for name, direction in key_columns:
                part = f"{name} DESC" if direction == "DESC" else name
                col_parts.append(part)
            col_str = ", ".join(col_parts) if col_parts else "<column>"
            col_names = "_".join(n for n, _ in key_columns[:3])
            create_sql = (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{col_names}_full\n"
                f"    ON {table or '<table>'} ({col_str});"
            )
            alts.append(IndexSuggestion(
                create_sql=create_sql,
                table=table,
                key_columns=key_columns,
                summary=f"Full (non-partial) BTREE index on {table}",
                notes=["Covers all rows, not just the filtered subset. "
                       "Larger, but works for queries without the WHERE filter."],
                estimated_speedup="10-50x",
            ))

        # Alt 2: If BTREE, suggest BRIN if data is likely time-ordered
        if type_suggestion.index_type == SuggestedIndexType.BTREE:
            time_cols = [c for c in columns if c.is_range and
                         any(t in c.name.lower() for t in
                             ("date", "time", "created", "updated", "occurred", "ts"))]
            if time_cols:
                col = time_cols[0]
                alts.append(IndexSuggestion(
                    create_sql=(
                        f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{col.name}_brin\n"
                        f"    ON {table or '<table>'} USING BRIN ({col.name});"
                    ),
                    table=table,
                    key_columns=[(col.name, "ASC")],
                    type_suggestion=TypeSuggestion(
                        index_type=SuggestedIndexType.BRIN,
                        rationale="BRIN indexes are 1000x smaller than BTREE for "
                                  "physically-ordered data (e.g. time-series). Only "
                                  "stores min/max per block range.",
                        textbook_ref="Fittl, 'Effective Indexing', Index Types: BRIN",
                    ),
                    summary=f"BRIN index on {table}.{col.name} (if data is time-ordered)",
                    notes=["Only useful if rows are inserted roughly in order of this column. "
                           "1000x smaller than BTREE but slower for random access."],
                    estimated_speedup="10-50x (with 1000x less storage)",
                ))

        # Alt 3: If covering suggested, offer version without INCLUDE
        if covering:
            col_parts = []
            for name, direction in key_columns:
                part = f"{name} DESC" if direction == "DESC" else name
                col_parts.append(part)
            col_str = ", ".join(col_parts) if col_parts else "<column>"
            col_names = "_".join(n for n, _ in key_columns[:3])
            alts.append(IndexSuggestion(
                create_sql=(
                    f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{col_names}\n"
                    f"    ON {table or '<table>'} ({col_str});"
                ),
                table=table,
                key_columns=key_columns,
                summary=f"BTREE without INCLUDE (smaller, still fast for filtering)",
                notes=["Skips INCLUDE columns — smaller index but requires heap "
                       "access for non-key columns. Use if storage is a concern."],
                estimated_speedup="10-50x",
            ))

        return alts


# ── Convenience function ─────────────────────────────────────────────────


def suggest_index(sql: str) -> SuggestResult:
    """Analyze a SQL query and recommend optimal indexes."""
    return UnifiedSuggestor().suggest(sql)
