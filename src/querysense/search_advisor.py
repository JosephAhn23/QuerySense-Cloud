"""
Search Query Optimization Advisor.

Reverse-engineered from pganalyze "Efficient Search in Rails with PostgreSQL"
ebook (2024). Automates the decision matrix from p.3: given a search pattern,
recommend the optimal index type, extension, rewrite, and expected speedup.

Architecture
------------
SearchClassifier  → Identify search type (exact, prefix, wildcard, trigram, FTS)
SearchIndexAdvisor → Recommend optimal index (BTREE, GIN trgm, GIN tsvector, GiST)
ExtensionChecker  → Verify required extensions (pg_trgm, unaccent, pg_bigm)
SearchRewriter    → Convert LIKE → FTS / trigram where beneficial
SearchPatternDetector → Scan pg_stat_statements for unindexed search patterns
SearchMonitor     → Track search query performance over time
BenchmarkGenerator → Create realistic search test data

References
----------
- pganalyze, "Efficient Search in Rails with PostgreSQL" (2024)
- Dombrovskaya et al., "PostgreSQL Query Optimization" (2024), Ch. 5-6
- PostgreSQL docs: pg_trgm, Full Text Search, GIN/GiST indexes
"""

from __future__ import annotations

import hashlib
import re
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Search pattern taxonomy (pganalyze p.3 decision matrix) ─────────────


class SearchType(str, Enum):
    """Search pattern types from pganalyze's decision matrix."""
    EXACT = "exact"                   # WHERE col = 'value'
    PREFIX = "prefix"                 # WHERE col LIKE 'value%'
    SUFFIX = "suffix"                 # WHERE col LIKE '%value'
    WILDCARD = "wildcard"             # WHERE col LIKE '%value%'
    ILIKE_EXACT = "ilike_exact"       # WHERE col ILIKE 'value'
    ILIKE_PREFIX = "ilike_prefix"     # WHERE col ILIKE 'value%'
    ILIKE_WILDCARD = "ilike_wildcard" # WHERE col ILIKE '%value%'
    TRIGRAM = "trigram"               # WHERE col % 'value' or similarity(col, 'value')
    FTS = "full_text_search"          # WHERE to_tsvector(col) @@ to_tsquery(...)
    REGEX = "regex"                   # WHERE col ~ 'pattern'
    ARRAY_CONTAINS = "array_contains" # WHERE col @> ARRAY[...]
    JSONB_CONTAINS = "jsonb_contains" # WHERE col @> '{"key": "val"}'
    UNKNOWN = "unknown"


class IndexType(str, Enum):
    """PostgreSQL index types for search optimization."""
    BTREE = "btree"
    GIN_TRGM = "gin_trgm"
    GIST_TRGM = "gist_trgm"
    GIN_TSVECTOR = "gin_tsvector"
    GIST_TSVECTOR = "gist_tsvector"
    GIN_JSONB = "gin_jsonb"
    GIN_ARRAY = "gin_array"
    BTREE_LOWER = "btree_lower"      # expression index on lower(col)
    BTREE_PREFIX = "btree_prefix"     # text_pattern_ops
    NONE = "none"


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


# ── Data classes ─────────────────────────────────────────────────────────


@dataclass
class SearchPattern:
    """A detected search pattern in a SQL query."""
    search_type: SearchType
    table: str = ""
    column: str = ""
    pattern_value: str = ""         # The literal or parameter
    is_case_insensitive: bool = False
    has_leading_wildcard: bool = False
    has_trailing_wildcard: bool = False
    original_fragment: str = ""     # The WHERE clause fragment


@dataclass
class IndexRecommendation:
    """A recommended index for a search pattern."""
    index_type: IndexType
    create_sql: str
    explanation: str
    estimated_speedup: str = ""     # e.g. "50-100x"
    prerequisite_sql: str = ""      # e.g. CREATE EXTENSION IF NOT EXISTS pg_trgm
    alternative_approaches: list[str] = field(default_factory=list)
    textbook_ref: str = ""
    severity: Severity = Severity.WARNING


@dataclass
class SearchClassification:
    """Full classification + recommendation for a search query."""
    sql: str
    patterns: list[SearchPattern] = field(default_factory=list)
    recommendations: list[IndexRecommendation] = field(default_factory=list)
    current_plan_type: str = ""     # e.g. "Seq Scan"
    estimated_rows: int = 0
    is_indexable: bool = True
    summary: str = ""
    search_type_label: str = ""     # Human-readable label

    def to_dict(self) -> dict[str, Any]:
        return {
            "sql": self.sql[:500],
            "patterns": [
                {
                    "search_type": p.search_type.value,
                    "table": p.table,
                    "column": p.column,
                    "is_case_insensitive": p.is_case_insensitive,
                    "has_leading_wildcard": p.has_leading_wildcard,
                    "has_trailing_wildcard": p.has_trailing_wildcard,
                }
                for p in self.patterns
            ],
            "recommendations": [
                {
                    "index_type": r.index_type.value,
                    "create_sql": r.create_sql,
                    "explanation": r.explanation,
                    "estimated_speedup": r.estimated_speedup,
                    "prerequisite_sql": r.prerequisite_sql,
                    "alternative_approaches": r.alternative_approaches,
                    "severity": r.severity.value,
                }
                for r in self.recommendations
            ],
            "is_indexable": self.is_indexable,
            "summary": self.summary,
            "search_type_label": self.search_type_label,
        }


@dataclass
class ExtensionStatus:
    """Status of a required PostgreSQL extension."""
    name: str
    installed: bool = False
    available: bool = False
    version: str = ""
    install_sql: str = ""
    purpose: str = ""


@dataclass
class ExtensionReport:
    """Report on all search-related extensions."""
    extensions: list[ExtensionStatus] = field(default_factory=list)

    @property
    def all_installed(self) -> bool:
        return all(e.installed for e in self.extensions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "all_installed": self.all_installed,
            "extensions": [
                {
                    "name": e.name,
                    "installed": e.installed,
                    "available": e.available,
                    "version": e.version,
                    "install_sql": e.install_sql,
                    "purpose": e.purpose,
                }
                for e in self.extensions
            ],
        }


@dataclass
class SearchAuditResult:
    """Result of auditing search patterns in a workload."""
    total_queries: int = 0
    search_queries: int = 0
    unindexed_count: int = 0
    patterns: list[SearchClassification] = field(default_factory=list)
    top_offenders: list[SearchClassification] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_queries": self.total_queries,
            "search_queries": self.search_queries,
            "unindexed_count": self.unindexed_count,
            "top_offenders": [o.to_dict() for o in self.top_offenders],
        }


@dataclass
class SearchMonitorResult:
    """Search performance monitoring result."""
    period: str = ""
    total_search_queries: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    by_type: dict[str, dict[str, Any]] = field(default_factory=dict)
    recommendations: list[IndexRecommendation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "period": self.period,
            "total_search_queries": self.total_search_queries,
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "p95_latency_ms": round(self.p95_latency_ms, 1),
            "p99_latency_ms": round(self.p99_latency_ms, 1),
            "by_type": self.by_type,
            "recommendations": [
                {
                    "index_type": r.index_type.value,
                    "create_sql": r.create_sql,
                    "estimated_speedup": r.estimated_speedup,
                }
                for r in self.recommendations
            ],
        }


@dataclass
class BenchmarkSpec:
    """Specification for search benchmark data generation."""
    table_name: str = "companies"
    row_count: int = 250_000
    columns: dict[str, str] = field(default_factory=dict)
    seed: int = 42
    extra_tables: list[dict[str, Any]] = field(default_factory=list)


# ── Regex patterns for SQL parsing ───────────────────────────────────────


# Match LIKE / ILIKE with their patterns
_LIKE_RE = re.compile(
    r"""
    (\w+(?:\.\w+)?)       # table.column or column
    \s+
    (NOT\s+)?             # optional NOT
    (I?LIKE)              # LIKE or ILIKE
    \s+
    '([^']*)'             # the pattern string
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Match tsvector @@ tsquery
_FTS_RE = re.compile(
    r"""
    to_tsvector\s*\(\s*
    (?:'(\w+)'\s*,\s*)?   # optional language config
    (\w+(?:\.\w+)?)       # column
    \s*\)
    \s*@@\s*
    (?:plain)?to_tsquery\s*\(
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Match similarity() or word_similarity() or % operator
_TRGM_RE = re.compile(
    r"""
    (?:
        (?:word_)?similarity\s*\(\s*(\w+(?:\.\w+)?)\s*,  # similarity(col, ...)
        |
        (\w+(?:\.\w+)?)\s+%\s+                            # col % 'value'
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Match regex operators ~ and ~*
_REGEX_RE = re.compile(
    r"""
    (\w+(?:\.\w+)?)       # column
    \s+
    (~\*?|!\~\*?)         # ~ or ~* or !~ or !~*
    \s+
    '([^']*)'             # pattern
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Match exact equality on text/varchar columns
_EXACT_RE = re.compile(
    r"""
    (\w+(?:\.\w+)?)       # column
    \s*=\s*
    (?:'[^']*'|\$\d+|\?)  # literal, $1, or ?
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Match JSONB containment
_JSONB_RE = re.compile(
    r"""
    (\w+(?:\.\w+)?)       # column
    \s+@>\s+
    '?\{                   # JSON object start
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Match array containment
_ARRAY_RE = re.compile(
    r"""
    (\w+(?:\.\w+)?)       # column
    \s+@>\s+
    ARRAY\[                # ARRAY[...]
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Match lower(col) or upper(col) in WHERE
_LOWER_RE = re.compile(
    r"""
    (?:lower|upper)\s*\(\s*
    (\w+(?:\.\w+)?)       # column
    \s*\)
    \s*=\s*
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Extract FROM clause table name (simplified)
_FROM_RE = re.compile(
    r"FROM\s+(\w+(?:\.\w+)?)", re.IGNORECASE
)


# ── The decision matrix (pganalyze p.3) ─────────────────────────────────


_DECISION_MATRIX: dict[SearchType, dict[str, Any]] = {
    SearchType.EXACT: {
        "label": "Exact match (=)",
        "indexable": True,
        "index_type": IndexType.BTREE,
        "speedup": "100-1000x",
        "explanation": (
            "Standard BTREE index. O(log n) lookup. Best possible "
            "performance for equality checks."
        ),
        "extension": None,
        "textbook_ref": "Dombrovskaya Ch. 5: Short Queries and Indexes",
    },
    SearchType.PREFIX: {
        "label": "Prefix search (LIKE 'val%')",
        "indexable": True,
        "index_type": IndexType.BTREE_PREFIX,
        "speedup": "50-500x",
        "explanation": (
            "BTREE with text_pattern_ops. Anchored prefix searches "
            "use index range scans efficiently."
        ),
        "extension": None,
        "textbook_ref": "Dombrovskaya Ch. 5: text_pattern_ops for LIKE",
    },
    SearchType.SUFFIX: {
        "label": "Suffix search (LIKE '%val')",
        "indexable": True,
        "index_type": IndexType.GIN_TRGM,
        "speedup": "10-50x",
        "explanation": (
            "Suffix searches need trigram indexes. BTREE cannot handle "
            "leading wildcards. pg_trgm GIN breaks text into 3-char chunks."
        ),
        "extension": "pg_trgm",
        "textbook_ref": "pganalyze Efficient Search, p.3: LIKE/ILIKE",
    },
    SearchType.WILDCARD: {
        "label": "Wildcard search (LIKE '%val%')",
        "indexable": True,
        "index_type": IndexType.GIN_TRGM,
        "speedup": "50-100x",
        "explanation": (
            "Leading + trailing wildcard requires trigram index. "
            "Standard BTREE cannot help — forces sequential scan. "
            "pg_trgm GIN indexes split text into 3-character trigrams, "
            "enabling indexed lookup for arbitrary substrings."
        ),
        "extension": "pg_trgm",
        "textbook_ref": "pganalyze Efficient Search, p.3: Trigram (pg_trgm)",
    },
    SearchType.ILIKE_EXACT: {
        "label": "Case-insensitive exact match (ILIKE 'val')",
        "indexable": True,
        "index_type": IndexType.BTREE_LOWER,
        "speedup": "100-500x",
        "explanation": (
            "Expression index on lower(col). ILIKE without wildcards "
            "is equivalent to lower(col) = lower('val'). Faster than "
            "trigram for exact case-insensitive matches."
        ),
        "extension": None,
        "textbook_ref": "Dombrovskaya Ch. 5: Expression indexes",
    },
    SearchType.ILIKE_PREFIX: {
        "label": "Case-insensitive prefix (ILIKE 'val%')",
        "indexable": True,
        "index_type": IndexType.BTREE_LOWER,
        "speedup": "50-200x",
        "explanation": (
            "Expression index on lower(col) with text_pattern_ops. "
            "For case-insensitive prefix searches, a BTREE on lower() "
            "is more efficient than a trigram index."
        ),
        "extension": None,
        "textbook_ref": "pganalyze Efficient Search, p.3: ILIKE prefix",
    },
    SearchType.ILIKE_WILDCARD: {
        "label": "Case-insensitive wildcard (ILIKE '%val%')",
        "indexable": True,
        "index_type": IndexType.GIN_TRGM,
        "speedup": "50-100x",
        "explanation": (
            "pg_trgm GIN index. ILIKE with leading wildcard cannot use "
            "BTREE. Trigram indexes are case-insensitive by default when "
            "used with ILIKE."
        ),
        "extension": "pg_trgm",
        "textbook_ref": "pganalyze Efficient Search, p.3: Trigram (pg_trgm)",
    },
    SearchType.TRIGRAM: {
        "label": "Trigram similarity search",
        "indexable": True,
        "index_type": IndexType.GIN_TRGM,
        "speedup": "20-100x",
        "explanation": (
            "GIN trigram index for similarity() or % operator. "
            "Best for fuzzy matching, typo tolerance, and 'did you mean?' "
            "features. Set pg_trgm.similarity_threshold for tuning."
        ),
        "extension": "pg_trgm",
        "textbook_ref": "pganalyze Efficient Search, p.3: Trigram (pg_trgm)",
    },
    SearchType.FTS: {
        "label": "Full-text search (tsvector @@ tsquery)",
        "indexable": True,
        "index_type": IndexType.GIN_TSVECTOR,
        "speedup": "100-1000x",
        "explanation": (
            "GIN index on tsvector column or expression. Supports "
            "stemming, stop words, ranking, phrase search, and boolean "
            "operators. Best for natural language search."
        ),
        "extension": None,
        "textbook_ref": "pganalyze Efficient Search, p.3: Full Text Search",
    },
    SearchType.REGEX: {
        "label": "Regex search (~ / ~*)",
        "indexable": True,
        "index_type": IndexType.GIN_TRGM,
        "speedup": "10-50x",
        "explanation": (
            "pg_trgm GIN can accelerate regex searches by extracting "
            "trigrams from the pattern. Not all patterns benefit — "
            "very short or highly variable patterns may still scan."
        ),
        "extension": "pg_trgm",
        "textbook_ref": "PostgreSQL docs: pg_trgm regex support",
    },
    SearchType.JSONB_CONTAINS: {
        "label": "JSONB containment (@>)",
        "indexable": True,
        "index_type": IndexType.GIN_JSONB,
        "speedup": "50-500x",
        "explanation": (
            "GIN index on JSONB column. Supports @>, ?, ?|, ?& operators. "
            "Use jsonb_path_ops for containment-only queries (smaller, faster)."
        ),
        "extension": None,
        "textbook_ref": "PostgreSQL docs: JSONB indexing",
    },
    SearchType.ARRAY_CONTAINS: {
        "label": "Array containment (@>)",
        "indexable": True,
        "index_type": IndexType.GIN_ARRAY,
        "speedup": "50-200x",
        "explanation": (
            "GIN index on array column. Supports @>, &&, <@ operators."
        ),
        "extension": None,
        "textbook_ref": "PostgreSQL docs: GIN array indexes",
    },
}


# ── SearchClassifier ─────────────────────────────────────────────────────


class SearchClassifier:
    """
    Classify SQL search patterns and recommend optimal indexing.

    Implements the decision matrix from pganalyze "Efficient Search in
    Rails with PostgreSQL" (2024), p.3.
    """

    def classify(self, sql: str) -> SearchClassification:
        """Classify search patterns in a SQL query."""
        result = SearchClassification(sql=sql)
        result.patterns = self._detect_patterns(sql)

        if not result.patterns:
            result.summary = "No search patterns detected in this query."
            result.search_type_label = "Non-search query"
            return result

        # Generate recommendations for each pattern
        for pattern in result.patterns:
            rec = self._recommend_index(pattern, sql)
            if rec:
                result.recommendations.append(rec)

        # Determine overall classification
        primary = result.patterns[0]
        matrix_entry = _DECISION_MATRIX.get(primary.search_type, {})
        result.search_type_label = matrix_entry.get("label", primary.search_type.value)
        result.is_indexable = matrix_entry.get("indexable", False)

        # Build summary
        if result.recommendations:
            best = result.recommendations[0]
            result.summary = (
                f"{result.search_type_label} on "
                f"{primary.table + '.' if primary.table else ''}"
                f"{primary.column}: "
                f"use {best.index_type.value} index "
                f"(estimated {best.estimated_speedup} speedup)"
            )
        else:
            result.summary = f"Search type: {result.search_type_label}"

        return result

    def _detect_patterns(self, sql: str) -> list[SearchPattern]:
        """Extract all search patterns from SQL."""
        patterns: list[SearchPattern] = []

        # Extract table name from FROM clause
        table = ""
        from_match = _FROM_RE.search(sql)
        if from_match:
            table = from_match.group(1)

        # 1. Check for LIKE/ILIKE patterns
        for m in _LIKE_RE.finditer(sql):
            col = m.group(1)
            is_not = bool(m.group(2))
            operator = m.group(3).upper()
            value = m.group(4)

            is_ilike = operator == "ILIKE"
            has_leading = value.startswith("%")
            has_trailing = value.endswith("%")

            # Determine search type
            if is_ilike:
                if has_leading and has_trailing:
                    stype = SearchType.ILIKE_WILDCARD
                elif has_leading:
                    stype = SearchType.ILIKE_WILDCARD  # suffix = needs trgm too
                elif has_trailing:
                    stype = SearchType.ILIKE_PREFIX
                else:
                    stype = SearchType.ILIKE_EXACT
            else:
                if has_leading and has_trailing:
                    stype = SearchType.WILDCARD
                elif has_leading:
                    stype = SearchType.SUFFIX
                elif has_trailing:
                    stype = SearchType.PREFIX
                else:
                    stype = SearchType.EXACT

            patterns.append(SearchPattern(
                search_type=stype,
                table=table,
                column=col.split(".")[-1] if "." in col else col,
                pattern_value=value,
                is_case_insensitive=is_ilike,
                has_leading_wildcard=has_leading,
                has_trailing_wildcard=has_trailing,
                original_fragment=m.group(0),
            ))

        # 2. Check for full-text search
        for m in _FTS_RE.finditer(sql):
            col = m.group(2) or m.group(1)
            patterns.append(SearchPattern(
                search_type=SearchType.FTS,
                table=table,
                column=col.split(".")[-1] if "." in col else col,
                original_fragment=m.group(0),
            ))

        # 3. Check for trigram operators
        for m in _TRGM_RE.finditer(sql):
            col = m.group(1) or m.group(2)
            if col:
                patterns.append(SearchPattern(
                    search_type=SearchType.TRIGRAM,
                    table=table,
                    column=col.split(".")[-1] if "." in col else col,
                    original_fragment=m.group(0),
                ))

        # 4. Check for regex
        for m in _REGEX_RE.finditer(sql):
            col = m.group(1)
            patterns.append(SearchPattern(
                search_type=SearchType.REGEX,
                table=table,
                column=col.split(".")[-1] if "." in col else col,
                pattern_value=m.group(3),
                is_case_insensitive="*" in m.group(2),
                original_fragment=m.group(0),
            ))

        # 5. Check for JSONB containment
        for m in _JSONB_RE.finditer(sql):
            col = m.group(1)
            patterns.append(SearchPattern(
                search_type=SearchType.JSONB_CONTAINS,
                table=table,
                column=col.split(".")[-1] if "." in col else col,
                original_fragment=m.group(0),
            ))

        # 6. Check for array containment
        for m in _ARRAY_RE.finditer(sql):
            col = m.group(1)
            patterns.append(SearchPattern(
                search_type=SearchType.ARRAY_CONTAINS,
                table=table,
                column=col.split(".")[-1] if "." in col else col,
                original_fragment=m.group(0),
            ))

        # 7. Check for lower()/upper() in WHERE (case-insensitive without ILIKE)
        for m in _LOWER_RE.finditer(sql):
            col = m.group(1)
            patterns.append(SearchPattern(
                search_type=SearchType.ILIKE_EXACT,
                table=table,
                column=col.split(".")[-1] if "." in col else col,
                is_case_insensitive=True,
                original_fragment=m.group(0),
            ))

        return patterns

    def _recommend_index(
        self, pattern: SearchPattern, sql: str
    ) -> IndexRecommendation | None:
        """Generate index recommendation for a search pattern."""
        matrix = _DECISION_MATRIX.get(pattern.search_type)
        if not matrix:
            return None

        idx_type: IndexType = matrix["index_type"]
        table = pattern.table or "<table>"
        col = pattern.column or "<column>"

        # Build CREATE INDEX statement
        create_sql = self._build_create_index(idx_type, table, col)

        # Build prerequisite
        ext = matrix.get("extension")
        prereq = ""
        if ext:
            prereq = f"CREATE EXTENSION IF NOT EXISTS {ext};"

        # Build alternatives
        alternatives = self._build_alternatives(pattern)

        return IndexRecommendation(
            index_type=idx_type,
            create_sql=create_sql,
            explanation=matrix["explanation"],
            estimated_speedup=matrix["speedup"],
            prerequisite_sql=prereq,
            alternative_approaches=alternatives,
            textbook_ref=matrix.get("textbook_ref", ""),
            severity=(
                Severity.CRITICAL
                if pattern.has_leading_wildcard
                else Severity.WARNING
            ),
        )

    def _build_create_index(
        self, idx_type: IndexType, table: str, column: str
    ) -> str:
        """Generate CREATE INDEX SQL for the given type."""
        safe_table = table.replace(".", "_")
        safe_col = column.replace(".", "_")

        if idx_type == IndexType.BTREE:
            return (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col} "
                f"ON {table} ({column});"
            )
        elif idx_type == IndexType.BTREE_PREFIX:
            return (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_prefix "
                f"ON {table} ({column} text_pattern_ops);"
            )
        elif idx_type == IndexType.BTREE_LOWER:
            return (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_lower "
                f"ON {table} (lower({column}));"
            )
        elif idx_type == IndexType.GIN_TRGM:
            return (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_trgm "
                f"ON {table} USING GIN ({column} gin_trgm_ops);"
            )
        elif idx_type == IndexType.GIST_TRGM:
            return (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_trgm "
                f"ON {table} USING GiST ({column} gist_trgm_ops);"
            )
        elif idx_type == IndexType.GIN_TSVECTOR:
            return (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_fts "
                f"ON {table} USING GIN (to_tsvector('english', {column}));"
            )
        elif idx_type == IndexType.GIN_JSONB:
            return (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_jsonb "
                f"ON {table} USING GIN ({column} jsonb_path_ops);"
            )
        elif idx_type == IndexType.GIN_ARRAY:
            return (
                f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_arr "
                f"ON {table} USING GIN ({column});"
            )
        return f"-- No index recommendation for {idx_type.value}"

    def _build_alternatives(self, pattern: SearchPattern) -> list[str]:
        """Build alternative approaches for a search pattern."""
        alts: list[str] = []
        table = pattern.table or "<table>"
        col = pattern.column or "<column>"

        if pattern.search_type in (
            SearchType.WILDCARD,
            SearchType.ILIKE_WILDCARD,
            SearchType.SUFFIX,
        ):
            alts.append(
                f"Exact match: WHERE {col} = 'value' "
                f"(BTREE index, 100x faster — if exact match suffices)"
            )
            alts.append(
                f"Full-text: WHERE to_tsvector('english', {col}) @@ "
                f"to_tsquery('value') (GIN index, linguistic features)"
            )
            if not pattern.is_case_insensitive:
                alts.append(
                    f"Prefix: WHERE {col} LIKE 'value%' "
                    f"(BTREE text_pattern_ops — if prefix search suffices)"
                )

        elif pattern.search_type == SearchType.FTS:
            alts.append(
                f"Trigram: WHERE {col} % 'value' "
                f"(pg_trgm, better for typo tolerance)"
            )
            alts.append(
                "GiST index: Slower reads, but supports KNN distance operator"
            )

        elif pattern.search_type == SearchType.TRIGRAM:
            alts.append(
                f"Full-text: WHERE to_tsvector('english', {col}) @@ "
                f"to_tsquery('value') (better for natural language)"
            )

        elif pattern.search_type == SearchType.PREFIX:
            alts.append(
                f"Trigram: USING GIN ({col} gin_trgm_ops) — "
                f"also handles wildcards, slightly larger index"
            )

        elif pattern.search_type in (SearchType.ILIKE_EXACT, SearchType.ILIKE_PREFIX):
            alts.append(
                f"Trigram: USING GIN ({col} gin_trgm_ops) — "
                f"handles wildcards too, one index for all ILIKE patterns"
            )

        return alts


# ── ExtensionChecker ─────────────────────────────────────────────────────


# Search-related extensions to check
_SEARCH_EXTENSIONS = [
    {
        "name": "pg_trgm",
        "purpose": (
            "Trigram indexes for LIKE '%value%', ILIKE, similarity(), "
            "and regex. Required for wildcard search optimization."
        ),
        "install_sql": "CREATE EXTENSION IF NOT EXISTS pg_trgm;",
    },
    {
        "name": "unaccent",
        "purpose": (
            "Remove accents for accent-insensitive search. "
            "Combine with pg_trgm for robust text search."
        ),
        "install_sql": "CREATE EXTENSION IF NOT EXISTS unaccent;",
    },
    {
        "name": "pg_bigm",
        "purpose": (
            "2-gram indexes. Alternative to pg_trgm for CJK text "
            "(Chinese, Japanese, Korean) where 3-grams are too long."
        ),
        "install_sql": "CREATE EXTENSION IF NOT EXISTS pg_bigm;",
    },
    {
        "name": "fuzzystrmatch",
        "purpose": (
            "Soundex, Levenshtein, Metaphone distance functions. "
            "Phonetic matching for 'sounds like' queries."
        ),
        "install_sql": "CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;",
    },
]

_EXTENSIONS_QUERY = """
SELECT e.extname, e.extversion
FROM pg_extension e
WHERE e.extname = ANY($1::text[])
"""

_AVAILABLE_QUERY = """
SELECT name
FROM pg_available_extensions
WHERE name = ANY($1::text[])
"""


class ExtensionChecker:
    """Check PostgreSQL search-related extensions."""

    async def check(self, conn: Any) -> ExtensionReport:
        """Check installed and available search extensions."""
        ext_names = [e["name"] for e in _SEARCH_EXTENSIONS]
        report = ExtensionReport()

        # Check installed
        installed: dict[str, str] = {}
        try:
            rows = await conn.fetch(_EXTENSIONS_QUERY, ext_names)
            installed = {r["extname"]: r["extversion"] for r in rows}
        except Exception:
            pass

        # Check available
        available: set[str] = set()
        try:
            rows = await conn.fetch(_AVAILABLE_QUERY, ext_names)
            available = {r["name"] for r in rows}
        except Exception:
            pass

        for ext_def in _SEARCH_EXTENSIONS:
            name = ext_def["name"]
            report.extensions.append(ExtensionStatus(
                name=name,
                installed=name in installed,
                available=name in available,
                version=installed.get(name, ""),
                install_sql=ext_def["install_sql"],
                purpose=ext_def["purpose"],
            ))

        return report


# ── SearchPatternDetector (workload audit) ───────────────────────────────


_PGSS_SEARCH_QUERY = """
SELECT
    queryid,
    query,
    calls,
    total_exec_time / 1000.0 AS total_time_sec,
    mean_exec_time AS mean_ms,
    rows
FROM pg_stat_statements
WHERE
    dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
    AND (
        query ~* 'LIKE\\s' OR
        query ~* 'ILIKE\\s' OR
        query ~* 'to_tsvector' OR
        query ~* 'similarity' OR
        query ~* '\\s~\\s' OR
        query ~* '\\s~\\*\\s' OR
        query ~* 'gin_trgm_ops' OR
        query ~* 'tsvector.*@@' OR
        query ~* '%\\$\\d'
    )
ORDER BY total_exec_time DESC
LIMIT $1
"""

# Check if columns have appropriate indexes
_SEARCH_INDEX_CHECK = """
SELECT
    schemaname, tablename, indexname, indexdef
FROM pg_indexes
WHERE tablename = $1
  AND (
    indexdef ILIKE '%gin_trgm_ops%' OR
    indexdef ILIKE '%tsvector%' OR
    indexdef ILIKE '%text_pattern_ops%' OR
    indexdef ILIKE '%gin%' OR
    indexdef ILIKE '%gist%'
  )
"""


class SearchPatternDetector:
    """
    Detect unindexed search patterns in a live PostgreSQL workload.

    Scans pg_stat_statements for LIKE, ILIKE, FTS, trigram, and regex
    queries, then checks whether appropriate indexes exist.
    """

    def __init__(self) -> None:
        self._classifier = SearchClassifier()

    async def audit(self, conn: Any, top_n: int = 50) -> SearchAuditResult:
        """Audit search patterns in the current workload."""
        result = SearchAuditResult()

        try:
            rows = await conn.fetch(_PGSS_SEARCH_QUERY, top_n)
        except Exception:
            return result

        result.total_queries = len(rows)
        result.search_queries = len(rows)

        for row in rows:
            query = row["query"]
            classification = self._classifier.classify(query)

            if classification.patterns:
                result.patterns.append(classification)

                # Check if indexes exist for the detected tables
                for pattern in classification.patterns:
                    if pattern.table:
                        try:
                            idx_rows = await conn.fetch(
                                _SEARCH_INDEX_CHECK, pattern.table
                            )
                            if not idx_rows:
                                result.unindexed_count += 1
                                result.top_offenders.append(classification)
                        except Exception:
                            pass

        # Sort offenders by importance (no index + high latency)
        result.top_offenders = result.top_offenders[:20]
        return result


# ── SearchRewriter ───────────────────────────────────────────────────────


@dataclass
class SearchRewrite:
    """A suggested rewrite for a search query."""
    original_sql: str
    rewritten_sql: str
    rewrite_type: str           # "like_to_fts", "like_to_trigram", "ilike_to_lower"
    explanation: str
    estimated_speedup: str = ""
    prerequisite_sql: str = ""
    index_sql: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_sql": self.original_sql[:500],
            "rewritten_sql": self.rewritten_sql[:500],
            "rewrite_type": self.rewrite_type,
            "explanation": self.explanation,
            "estimated_speedup": self.estimated_speedup,
            "prerequisite_sql": self.prerequisite_sql,
            "index_sql": self.index_sql,
        }


class SearchRewriter:
    """
    Rewrite search queries for better performance.

    Conversions:
    - LIKE '%val%'  → similarity(col, 'val') > 0.3  (with pg_trgm)
    - LIKE '%val%'  → to_tsvector(col) @@ to_tsquery('val')  (FTS)
    - ILIKE 'val'   → lower(col) = lower('val')  (expression index)
    - ILIKE 'val%'  → lower(col) LIKE lower('val%')  (expression index)
    """

    def rewrite(self, sql: str) -> list[SearchRewrite]:
        """Generate all possible rewrites for a search query."""
        rewrites: list[SearchRewrite] = []

        # 1. LIKE '%val%' → trigram
        for m in _LIKE_RE.finditer(sql):
            col = m.group(1)
            operator = m.group(3).upper()
            value = m.group(4)
            table = ""
            from_m = _FROM_RE.search(sql)
            if from_m:
                table = from_m.group(1)

            if value.startswith("%") and value.endswith("%"):
                inner = value.strip("%")
                safe_table = (table or "table").replace(".", "_")
                safe_col = col.split(".")[-1] if "." in col else col

                # Option A: Trigram
                trgm_rewrite = sql.replace(
                    m.group(0),
                    f"{col} % '{inner}'"
                )
                rewrites.append(SearchRewrite(
                    original_sql=sql,
                    rewritten_sql=trgm_rewrite,
                    rewrite_type="like_to_trigram",
                    explanation=(
                        f"Replace {operator} '%{inner}%' with trigram similarity. "
                        f"pg_trgm GIN index enables indexed search for arbitrary "
                        f"substrings using 3-character chunks."
                    ),
                    estimated_speedup="50-100x",
                    prerequisite_sql="CREATE EXTENSION IF NOT EXISTS pg_trgm;",
                    index_sql=(
                        f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_trgm "
                        f"ON {table or '<table>'} USING GIN ({col} gin_trgm_ops);"
                    ),
                ))

                # Option B: Full-text search
                fts_rewrite = sql.replace(
                    m.group(0),
                    f"to_tsvector('english', {col}) @@ plainto_tsquery('english', '{inner}')"
                )
                rewrites.append(SearchRewrite(
                    original_sql=sql,
                    rewritten_sql=fts_rewrite,
                    rewrite_type="like_to_fts",
                    explanation=(
                        f"Replace {operator} with full-text search. Provides "
                        f"stemming (search -> searches), stop word removal, "
                        f"ranking (ts_rank), and phrase search."
                    ),
                    estimated_speedup="100-1000x",
                    prerequisite_sql="",
                    index_sql=(
                        f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_fts "
                        f"ON {table or '<table>'} USING GIN (to_tsvector('english', {col}));"
                    ),
                ))

            elif value.startswith("%") and not value.endswith("%"):
                # Suffix only → trigram is the only option
                inner = value.lstrip("%")
                safe_table = (table or "table").replace(".", "_")
                safe_col = col.split(".")[-1] if "." in col else col

                trgm_rewrite = sql.replace(
                    m.group(0),
                    f"{col} % '{inner}'"
                )
                rewrites.append(SearchRewrite(
                    original_sql=sql,
                    rewritten_sql=trgm_rewrite,
                    rewrite_type="like_to_trigram",
                    explanation=(
                        f"Suffix search (LIKE '%{inner}') requires trigram index. "
                        f"No BTREE can handle trailing-only wildcards."
                    ),
                    estimated_speedup="10-50x",
                    prerequisite_sql="CREATE EXTENSION IF NOT EXISTS pg_trgm;",
                    index_sql=(
                        f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_trgm "
                        f"ON {table or '<table>'} USING GIN ({col} gin_trgm_ops);"
                    ),
                ))

        # 2. ILIKE without wildcard → lower() expression
        for m in _LIKE_RE.finditer(sql):
            col = m.group(1)
            operator = m.group(3).upper()
            value = m.group(4)

            if operator == "ILIKE" and "%" not in value:
                table = ""
                from_m = _FROM_RE.search(sql)
                if from_m:
                    table = from_m.group(1)
                safe_table = (table or "table").replace(".", "_")
                safe_col = col.split(".")[-1] if "." in col else col

                lower_rewrite = sql.replace(
                    m.group(0),
                    f"lower({col}) = lower('{value}')"
                )
                rewrites.append(SearchRewrite(
                    original_sql=sql,
                    rewritten_sql=lower_rewrite,
                    rewrite_type="ilike_to_lower",
                    explanation=(
                        f"Replace ILIKE '{value}' (no wildcards) with "
                        f"lower() comparison. An expression index on lower({col}) "
                        f"is smaller and faster than a trigram index for exact "
                        f"case-insensitive matches."
                    ),
                    estimated_speedup="100-500x",
                    prerequisite_sql="",
                    index_sql=(
                        f"CREATE INDEX CONCURRENTLY idx_{safe_table}_{safe_col}_lower "
                        f"ON {table or '<table>'} (lower({col}));"
                    ),
                ))

        return rewrites


# ── SearchMonitor ────────────────────────────────────────────────────────


_SEARCH_PERF_QUERY = """
WITH search_queries AS (
    SELECT
        queryid,
        query,
        calls,
        total_exec_time / 1000.0 AS total_sec,
        mean_exec_time AS mean_ms,
        min_exec_time AS min_ms,
        max_exec_time AS max_ms,
        stddev_exec_time AS stddev_ms,
        rows,
        CASE
            WHEN query ~* 'ILIKE\\s' THEN 'ilike'
            WHEN query ~* '\\sLIKE\\s' THEN 'like'
            WHEN query ~* 'to_tsvector|@@' THEN 'fts'
            WHEN query ~* 'similarity|\\s%\\s' THEN 'trigram'
            WHEN query ~* '\\s~\\*?\\s' THEN 'regex'
            ELSE 'exact'
        END AS search_category
    FROM pg_stat_statements
    WHERE
        dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
        AND (
            query ~* 'LIKE\\s' OR query ~* 'ILIKE\\s' OR
            query ~* 'to_tsvector' OR query ~* 'similarity' OR
            query ~* '\\s~\\s' OR query ~* '\\s=\\s'
        )
        AND query !~* '^(SET|SHOW|BEGIN|COMMIT|ROLLBACK)'
)
SELECT
    search_category,
    COUNT(*) AS query_count,
    SUM(calls) AS total_calls,
    AVG(mean_ms) AS avg_mean_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY mean_ms) AS p95_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY mean_ms) AS p99_ms,
    SUM(total_sec) AS total_time_sec
FROM search_queries
GROUP BY search_category
ORDER BY total_time_sec DESC
"""


class SearchMonitor:
    """Monitor search query performance over time."""

    def __init__(self) -> None:
        self._classifier = SearchClassifier()

    async def monitor(self, conn: Any, period: str = "all") -> SearchMonitorResult:
        """Get search performance metrics from pg_stat_statements."""
        result = SearchMonitorResult(period=period)

        try:
            rows = await conn.fetch(_SEARCH_PERF_QUERY)
        except Exception:
            return result

        total_calls = 0
        total_time = 0.0
        weighted_latency = 0.0

        for row in rows:
            cat = row["search_category"]
            calls = row["total_calls"] or 0
            avg_ms = float(row["avg_mean_ms"] or 0)
            p95 = float(row["p95_ms"] or 0)
            p99 = float(row["p99_ms"] or 0)
            time_sec = float(row["total_time_sec"] or 0)

            total_calls += calls
            total_time += time_sec
            weighted_latency += avg_ms * calls

            is_indexed = cat in ("fts", "exact")  # Likely indexed
            result.by_type[cat] = {
                "query_count": row["query_count"],
                "total_calls": calls,
                "avg_ms": round(avg_ms, 1),
                "p95_ms": round(p95, 1),
                "p99_ms": round(p99, 1),
                "total_time_sec": round(time_sec, 1),
                "likely_indexed": is_indexed,
                "pct_of_calls": 0,  # Filled below
            }

        # Calculate percentages
        result.total_search_queries = total_calls
        if total_calls > 0:
            result.avg_latency_ms = weighted_latency / total_calls
            for cat_data in result.by_type.values():
                cat_data["pct_of_calls"] = round(
                    100 * cat_data["total_calls"] / total_calls, 1
                )

        # Set p95/p99 from the worst category
        if result.by_type:
            result.p95_latency_ms = max(
                v["p95_ms"] for v in result.by_type.values()
            )
            result.p99_latency_ms = max(
                v["p99_ms"] for v in result.by_type.values()
            )

        # Generate recommendations for slow categories
        for cat, data in result.by_type.items():
            if not data["likely_indexed"] and data["avg_ms"] > 100:
                if cat in ("like", "ilike"):
                    result.recommendations.append(IndexRecommendation(
                        index_type=IndexType.GIN_TRGM,
                        create_sql=(
                            "-- Add trigram indexes on columns used in LIKE/ILIKE:\n"
                            "-- CREATE INDEX CONCURRENTLY idx_<table>_<col>_trgm\n"
                            "--   ON <table> USING GIN (<col> gin_trgm_ops);"
                        ),
                        explanation=(
                            f"{cat.upper()} queries averaging {data['avg_ms']:.0f}ms. "
                            f"Trigram GIN index would reduce to ~{data['avg_ms'] * 0.05:.0f}ms."
                        ),
                        estimated_speedup="50-100x",
                        prerequisite_sql="CREATE EXTENSION IF NOT EXISTS pg_trgm;",
                        severity=Severity.CRITICAL if data["avg_ms"] > 500 else Severity.WARNING,
                    ))
                elif cat == "trigram":
                    result.recommendations.append(IndexRecommendation(
                        index_type=IndexType.GIN_TRGM,
                        create_sql=(
                            "-- Ensure GIN trigram index exists:\n"
                            "-- CREATE INDEX CONCURRENTLY idx_<table>_<col>_trgm\n"
                            "--   ON <table> USING GIN (<col> gin_trgm_ops);"
                        ),
                        explanation=(
                            f"Trigram queries averaging {data['avg_ms']:.0f}ms — "
                            f"likely missing GIN index."
                        ),
                        estimated_speedup="20-100x",
                        prerequisite_sql="CREATE EXTENSION IF NOT EXISTS pg_trgm;",
                        severity=Severity.WARNING,
                    ))
                elif cat == "regex":
                    result.recommendations.append(IndexRecommendation(
                        index_type=IndexType.GIN_TRGM,
                        create_sql=(
                            "-- pg_trgm can accelerate some regex patterns:\n"
                            "-- CREATE INDEX CONCURRENTLY idx_<table>_<col>_trgm\n"
                            "--   ON <table> USING GIN (<col> gin_trgm_ops);"
                        ),
                        explanation=(
                            f"Regex queries averaging {data['avg_ms']:.0f}ms. "
                            f"pg_trgm GIN can accelerate patterns with "
                            f"extractable trigrams."
                        ),
                        estimated_speedup="10-50x",
                        prerequisite_sql="CREATE EXTENSION IF NOT EXISTS pg_trgm;",
                        severity=Severity.WARNING,
                    ))

        return result


# ── BenchmarkGenerator ───────────────────────────────────────────────────


class BenchmarkGenerator:
    """
    Generate realistic search benchmark data.

    Based on pganalyze ebook's test dataset: 253k companies with mixed
    real and fake data for search testing.
    """

    # Name prefixes/suffixes for realistic company names
    _PREFIXES = [
        "Global", "United", "National", "Pacific", "Trans", "Inter",
        "American", "Euro", "First", "New", "Prime", "Atlas", "Apex",
        "Nova", "Sigma", "Delta", "Omega", "Alpha", "Quantum", "Nexus",
        "Vertex", "Summit", "Pinnacle", "Horizon", "Catalyst", "Zenith",
    ]
    _SUFFIXES = [
        "Corp", "Inc", "Ltd", "LLC", "Group", "Holdings", "Industries",
        "Technologies", "Solutions", "Systems", "Networks", "Digital",
        "Capital", "Ventures", "Partners", "Associates", "Dynamics",
        "Labs", "Analytics", "Enterprises", "Services", "International",
    ]
    _DOMAINS = [
        "Technology", "Finance", "Healthcare", "Energy", "Manufacturing",
        "Retail", "Telecom", "Media", "Aerospace", "Automotive", "Pharma",
        "Biotech", "Real Estate", "Agriculture", "Mining", "Insurance",
        "Education", "Logistics", "Defense", "Entertainment", "Food",
    ]
    _EXCHANGES = ["NYSE", "NASDAQ", "LSE"]

    def generate_sql(self, spec: BenchmarkSpec | None = None) -> str:
        """Generate SQL for search benchmark tables and data."""
        if spec is None:
            spec = BenchmarkSpec()

        parts: list[str] = []
        parts.append(self._preamble())
        parts.append(self._create_tables())
        parts.append(self._generate_exchanges())
        parts.append(self._generate_companies(spec.row_count, spec.seed))
        parts.append(self._generate_stock_prices(spec.row_count))
        parts.append(self._create_indexes())
        parts.append(self._create_test_queries())
        return "\n\n".join(parts)

    def _preamble(self) -> str:
        return textwrap.dedent("""\
        -- ================================================================
        -- QuerySense Search Benchmark Dataset
        -- Based on pganalyze "Efficient Search in Rails" (2024), p.4
        -- ================================================================
        -- Tables: companies (250k), exchanges (3), stock_prices (1M)
        -- Purpose: Test and benchmark search optimization strategies
        -- ================================================================

        SET client_min_messages TO WARNING;
        """)

    def _create_tables(self) -> str:
        return textwrap.dedent("""\
        -- Create tables
        DROP TABLE IF EXISTS stock_prices CASCADE;
        DROP TABLE IF EXISTS companies CASCADE;
        DROP TABLE IF EXISTS exchanges CASCADE;

        CREATE TABLE exchanges (
            id SERIAL PRIMARY KEY,
            name VARCHAR(20) NOT NULL UNIQUE,
            full_name VARCHAR(100) NOT NULL,
            country VARCHAR(50) NOT NULL
        );

        CREATE TABLE companies (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            legal_name VARCHAR(500),
            ticker VARCHAR(10),
            exchange_id INTEGER REFERENCES exchanges(id),
            industry VARCHAR(100),
            description TEXT,
            founded_year INTEGER,
            employee_count INTEGER,
            revenue_millions NUMERIC(12,2),
            website VARCHAR(255),
            headquarters_city VARCHAR(100),
            headquarters_country VARCHAR(100),
            tags TEXT[],
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE stock_prices (
            id SERIAL PRIMARY KEY,
            company_id INTEGER REFERENCES companies(id),
            trade_date DATE NOT NULL,
            open_price NUMERIC(10,2),
            close_price NUMERIC(10,2),
            high_price NUMERIC(10,2),
            low_price NUMERIC(10,2),
            volume BIGINT,
            UNIQUE(company_id, trade_date)
        );
        """)

    def _generate_exchanges(self) -> str:
        return textwrap.dedent("""\
        -- Insert exchanges
        INSERT INTO exchanges (name, full_name, country) VALUES
            ('NYSE', 'New York Stock Exchange', 'United States'),
            ('NASDAQ', 'NASDAQ Stock Market', 'United States'),
            ('LSE', 'London Stock Exchange', 'United Kingdom');
        """)

    def _generate_companies(self, count: int, seed: int) -> str:
        lines: list[str] = []
        lines.append(f"-- Generate {count:,} companies with realistic names")
        lines.append(f"-- Using deterministic generation (seed={seed})")
        lines.append("")
        lines.append(textwrap.dedent(f"""\
        INSERT INTO companies (name, legal_name, ticker, exchange_id, industry,
                               description, founded_year, employee_count,
                               revenue_millions, headquarters_city,
                               headquarters_country, tags, metadata)
        SELECT
            -- Company name: prefix + domain + suffix
            (
                (ARRAY{self._PREFIXES!r})[1 + (hashint4(i * {seed}) & 25)] || ' ' ||
                (ARRAY{self._DOMAINS!r})[1 + (hashint4(i * {seed} + 1) & 20)] || ' ' ||
                (ARRAY{self._SUFFIXES!r})[1 + (hashint4(i * {seed} + 2) & 21)]
            ) AS name,
            -- Legal name: name + legal suffix
            (
                (ARRAY{self._PREFIXES!r})[1 + (hashint4(i * {seed}) & 25)] || ' ' ||
                (ARRAY{self._DOMAINS!r})[1 + (hashint4(i * {seed} + 1) & 20)] || ' ' ||
                (ARRAY{self._SUFFIXES!r})[1 + (hashint4(i * {seed} + 2) & 21)] || ', ' ||
                (ARRAY['Inc.', 'LLC', 'Corp.', 'Ltd.', 'PLC'])[1 + (hashint4(i * {seed} + 3) & 4)]
            ) AS legal_name,
            -- Ticker: 3-4 uppercase letters
            upper(substr(md5(i::text || '{seed}'), 1, 3 + (i % 2))) AS ticker,
            -- Exchange
            1 + (abs(hashint4(i * {seed} + 4)) % 3) AS exchange_id,
            -- Industry
            (ARRAY{self._DOMAINS!r})[1 + (hashint4(i * {seed} + 5) & 20)] AS industry,
            -- Description: lorem-ish text for FTS testing
            'A leading company in ' ||
                (ARRAY{self._DOMAINS!r})[1 + (hashint4(i * {seed} + 5) & 20)] ||
                ' focused on innovative solutions for global markets. Founded in ' ||
                (1950 + abs(hashint4(i * {seed} + 6)) % 75)::text ||
                '. Specializing in ' ||
                (ARRAY['artificial intelligence', 'cloud computing', 'data analytics',
                       'cybersecurity', 'blockchain', 'IoT', 'machine learning',
                       'quantum computing', 'edge computing', 'sustainability'])[1 + (abs(hashint4(i * {seed} + 7)) % 10)] ||
                ' and ' ||
                (ARRAY['enterprise software', 'consumer products', 'financial services',
                       'healthcare solutions', 'supply chain', 'digital transformation',
                       'process automation', 'risk management', 'talent development',
                       'market research'])[1 + (abs(hashint4(i * {seed} + 8)) % 10)] ||
                '.' AS description,
            -- Founded year
            1950 + abs(hashint4(i * {seed} + 6)) % 75 AS founded_year,
            -- Employees
            10 + abs(hashint4(i * {seed} + 9)) % 100000 AS employee_count,
            -- Revenue
            round((random() * 50000)::numeric, 2) AS revenue_millions,
            -- City
            (ARRAY['New York', 'San Francisco', 'London', 'Tokyo', 'Berlin',
                   'Singapore', 'Sydney', 'Toronto', 'Mumbai', 'Seoul',
                   'Shanghai', 'Paris', 'Zurich', 'Dubai', 'Sao Paulo'])[1 + (abs(hashint4(i * {seed} + 10)) % 15)] AS city,
            -- Country
            (ARRAY['United States', 'United Kingdom', 'Japan', 'Germany',
                   'Singapore', 'Australia', 'Canada', 'India', 'South Korea',
                   'China', 'France', 'Switzerland', 'UAE', 'Brazil'])[1 + (abs(hashint4(i * {seed} + 11)) % 14)] AS country,
            -- Tags (array for GIN testing)
            ARRAY[
                (ARRAY['tech', 'finance', 'healthcare', 'energy', 'retail',
                       'growth', 'value', 'dividend', 'esg', 'small-cap',
                       'large-cap', 'blue-chip'])[1 + (abs(hashint4(i * {seed} + 12)) % 12)],
                (ARRAY['public', 'private', 'startup', 'unicorn', 'mature',
                       'emerging', 'established', 'innovative', 'disruptive'])[1 + (abs(hashint4(i * {seed} + 13)) % 9)]
            ]::text[] AS tags,
            -- JSONB metadata (for JSONB GIN testing)
            jsonb_build_object(
                'sector', (ARRAY{self._DOMAINS!r})[1 + (hashint4(i * {seed} + 14) & 20)],
                'risk_rating', (ARRAY['AAA', 'AA', 'A', 'BBB', 'BB', 'B'])[1 + (abs(hashint4(i * {seed} + 15)) % 6)],
                'market_cap_usd', round((random() * 1e12)::numeric, 0)
            ) AS metadata
        FROM generate_series(1, {count}) AS i;
        """))
        return "\n".join(lines)

    def _generate_stock_prices(self, company_count: int) -> str:
        price_count = min(company_count * 4, 1_000_000)
        return textwrap.dedent(f"""\
        -- Generate {price_count:,} stock price records
        INSERT INTO stock_prices (company_id, trade_date, open_price, close_price,
                                  high_price, low_price, volume)
        SELECT
            1 + (abs(hashint4(i)) % {company_count}) AS company_id,
            current_date - (i % 365) AS trade_date,
            round((50 + random() * 450)::numeric, 2) AS open_price,
            round((50 + random() * 450)::numeric, 2) AS close_price,
            round((60 + random() * 460)::numeric, 2) AS high_price,
            round((40 + random() * 440)::numeric, 2) AS low_price,
            (1000 + (random() * 10000000)::bigint) AS volume
        FROM generate_series(1, {price_count}) AS i
        ON CONFLICT (company_id, trade_date) DO NOTHING;
        """)

    def _create_indexes(self) -> str:
        return textwrap.dedent("""\
        -- ================================================================
        -- Search indexes for benchmarking
        -- ================================================================

        -- 1. Standard BTREE (exact match baseline)
        CREATE INDEX idx_companies_name_btree ON companies (name);
        CREATE INDEX idx_companies_industry ON companies (industry);

        -- 2. Text pattern ops (prefix search: LIKE 'val%')
        CREATE INDEX idx_companies_name_prefix ON companies (name text_pattern_ops);

        -- 3. Expression index (case-insensitive exact: lower(name) = ...)
        CREATE INDEX idx_companies_name_lower ON companies (lower(name));

        -- 4. Trigram GIN (wildcard: LIKE '%val%', ILIKE, similarity)
        -- Requires: CREATE EXTENSION IF NOT EXISTS pg_trgm;
        -- CREATE INDEX idx_companies_name_trgm ON companies USING GIN (name gin_trgm_ops);

        -- 5. Full-text search GIN (natural language search)
        CREATE INDEX idx_companies_desc_fts ON companies
            USING GIN (to_tsvector('english', description));

        -- 6. GIN for array containment
        CREATE INDEX idx_companies_tags_gin ON companies USING GIN (tags);

        -- 7. GIN for JSONB containment
        CREATE INDEX idx_companies_metadata_gin ON companies USING GIN (metadata jsonb_path_ops);

        -- Analyze for accurate statistics
        ANALYZE companies;
        ANALYZE stock_prices;
        ANALYZE exchanges;
        """)

    def _create_test_queries(self) -> str:
        return textwrap.dedent("""\
        -- ================================================================
        -- Test queries for benchmarking (use with EXPLAIN ANALYZE)
        -- ================================================================

        -- Q1: Exact match (BTREE)
        -- EXPLAIN ANALYZE SELECT * FROM companies WHERE name = 'Global Technology Corp';

        -- Q2: Prefix search (text_pattern_ops)
        -- EXPLAIN ANALYZE SELECT * FROM companies WHERE name LIKE 'Global%';

        -- Q3: Wildcard search WITHOUT trigram index (Seq Scan)
        -- EXPLAIN ANALYZE SELECT * FROM companies WHERE name LIKE '%Tech%';

        -- Q4: Case-insensitive exact (expression index)
        -- EXPLAIN ANALYZE SELECT * FROM companies WHERE lower(name) = lower('GLOBAL TECHNOLOGY CORP');

        -- Q5: ILIKE wildcard (needs pg_trgm)
        -- EXPLAIN ANALYZE SELECT * FROM companies WHERE name ILIKE '%technology%';

        -- Q6: Full-text search (GIN tsvector)
        -- EXPLAIN ANALYZE SELECT * FROM companies
        --   WHERE to_tsvector('english', description) @@ to_tsquery('artificial & intelligence');

        -- Q7: Array containment (GIN)
        -- EXPLAIN ANALYZE SELECT * FROM companies WHERE tags @> ARRAY['tech', 'growth'];

        -- Q8: JSONB containment (GIN jsonb_path_ops)
        -- EXPLAIN ANALYZE SELECT * FROM companies WHERE metadata @> '{"risk_rating": "AAA"}';

        -- Q9: Trigram similarity (requires pg_trgm + GIN index)
        -- EXPLAIN ANALYZE SELECT * FROM companies WHERE name % 'Gobal Technlogy'
        --   ORDER BY similarity(name, 'Gobal Technlogy') DESC LIMIT 10;

        -- Q10: Combined search: FTS + filter
        -- EXPLAIN ANALYZE SELECT * FROM companies
        --   WHERE to_tsvector('english', description) @@ to_tsquery('cloud & computing')
        --     AND industry = 'Technology'
        --   ORDER BY revenue_millions DESC LIMIT 20;
        """)


# ── Convenience top-level functions ──────────────────────────────────────


def classify_search(sql: str) -> SearchClassification:
    """Classify a search query and recommend indexes."""
    return SearchClassifier().classify(sql)


def rewrite_search(sql: str) -> list[SearchRewrite]:
    """Generate optimized rewrites for a search query."""
    return SearchRewriter().rewrite(sql)


async def audit_search_workload(conn: Any, top_n: int = 50) -> SearchAuditResult:
    """Audit search patterns in a PostgreSQL workload."""
    return await SearchPatternDetector().audit(conn, top_n)


async def check_search_extensions(conn: Any) -> ExtensionReport:
    """Check search-related PostgreSQL extensions."""
    return await ExtensionChecker().check(conn)


async def monitor_search_performance(conn: Any) -> SearchMonitorResult:
    """Monitor search query performance."""
    return await SearchMonitor().monitor(conn)


def generate_search_benchmark(
    row_count: int = 250_000, seed: int = 42
) -> str:
    """Generate SQL for a search benchmark dataset."""
    spec = BenchmarkSpec(row_count=row_count, seed=seed)
    return BenchmarkGenerator().generate_sql(spec)
