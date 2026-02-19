"""
Expanded Rewrite Pattern Library with Safety Validation.

Complements the core rewriter (rewriter.py) with:
- Pattern matching via compiled regexes
- Safety scoring (0.0–1.0) per pattern
- NULL-aware validation for NOT IN → NOT EXISTS
- Duplicate-aware validation for UNION → UNION ALL
- Schema-aware validation when DB metadata is available
- Counterexample tracking (known failure cases)

Usage:
    from querysense.rewrite_patterns import RewritePatternLibrary

    library = RewritePatternLibrary()
    matches = library.find_matches("SELECT * FROM orders WHERE id NOT IN (SELECT ...)")
    for match in matches:
        safety = match.validate_safety(sql)
        if safety.safe:
            print(f"Rewrite: {match.name} (confidence: {safety.confidence:.0%})")
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SafetyReport:
    """Result of safety validation for a rewrite."""
    safe: bool
    confidence: float = 1.0
    reason: str = ""
    alternative: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe": self.safe,
            "confidence": self.confidence,
            "reason": self.reason,
            "alternative": self.alternative,
            "warnings": self.warnings,
        }


@dataclass
class RewriteExample:
    """A before/after example of a rewrite."""
    before: str
    after: str
    explanation: str = ""


@dataclass
class RewritePattern:
    """A named rewrite pattern with safety validation."""
    name: str
    description: str
    pattern: str                    # regex pattern
    rewrite_template: str           # replacement template
    safety: float = 0.9            # base safety score (0.0–1.0)
    category: str = "general"       # indexing / join / subquery / aggregate / type
    examples: list[RewriteExample] = field(default_factory=list)
    counterexamples: list[str] = field(default_factory=list)
    _compiled: re.Pattern[str] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        try:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
        except re.error:
            self._compiled = None

    def matches(self, sql: str) -> bool:
        """Check if this pattern matches the SQL."""
        if self._compiled is None:
            return False
        return bool(self._compiled.search(sql))

    def validate_safety(
        self,
        sql: str,
        schema_info: dict[str, Any] | None = None,
    ) -> SafetyReport:
        """
        Validate whether this rewrite is safe for the given SQL.

        Uses schema info (column nullability, unique constraints, etc.)
        when available for more accurate safety assessment.
        """
        warnings: list[str] = []

        # NOT IN → NOT EXISTS: check for NULLs
        if self.name == "NOT_IN_TO_NOT_EXISTS":
            return self._validate_not_in(sql, schema_info)

        # UNION → UNION ALL: check for duplicates
        if self.name == "UNION_TO_UNION_ALL":
            return self._validate_union(sql, schema_info)

        # DISTINCT removal: check if truly redundant
        if self.name == "REMOVE_DISTINCT":
            return self._validate_distinct(sql, schema_info)

        # COALESCE to OR: edge cases with NULLs
        if self.name == "COALESCE_TO_OR":
            warnings.append(
                "Verify NULL handling matches original COALESCE behavior"
            )

        return SafetyReport(
            safe=True,
            confidence=self.safety,
            warnings=warnings,
        )

    def _validate_not_in(
        self, sql: str, schema: dict[str, Any] | None
    ) -> SafetyReport:
        """NOT IN with NULLs returns no rows — NOT EXISTS is safer."""
        # If we have schema info, check column nullability
        if schema:
            # Extract subquery column
            m = re.search(
                r"NOT\s+IN\s*\(\s*SELECT\s+(\w+)\s+FROM\s+(\w+)",
                sql,
                re.IGNORECASE,
            )
            if m:
                column = m.group(1)
                table = m.group(2)
                columns = schema.get("columns", {})
                col_info = columns.get(f"{table}.{column}", {})
                if col_info.get("nullable", True):
                    return SafetyReport(
                        safe=True,
                        confidence=0.95,
                        reason=(
                            f"Column {table}.{column} is nullable. "
                            f"NOT EXISTS handles NULLs correctly where NOT IN does not."
                        ),
                        warnings=[
                            "NOT IN returns no rows when subquery contains NULL. "
                            "NOT EXISTS is strictly safer here."
                        ],
                    )

        return SafetyReport(
            safe=True,
            confidence=self.safety,
            reason="NOT EXISTS handles NULLs correctly",
        )

    def _validate_union(
        self, sql: str, schema: dict[str, Any] | None
    ) -> SafetyReport:
        """UNION ALL skips deduplication — only safe when no duplicates."""
        # Check if both sides have DISTINCT or different tables
        parts = re.split(r"\bUNION\b", sql, flags=re.IGNORECASE)
        if len(parts) < 2:
            return SafetyReport(safe=True, confidence=self.safety)

        # If both sides select from different tables, likely safe
        tables = set()
        for part in parts:
            table_m = re.search(r"FROM\s+(\w+)", part, re.IGNORECASE)
            if table_m:
                tables.add(table_m.group(1).lower())

        if len(tables) >= 2:
            return SafetyReport(
                safe=True,
                confidence=0.85,
                reason="Different source tables — duplicates unlikely",
                warnings=["Verify no overlapping rows between tables"],
            )

        return SafetyReport(
            safe=False,
            confidence=0.5,
            reason="Same table in both UNION branches — duplicates possible",
            alternative="Keep UNION or add explicit DISTINCT",
        )

    def _validate_distinct(
        self, sql: str, schema: dict[str, Any] | None
    ) -> SafetyReport:
        """DISTINCT is redundant when result is already unique."""
        # Check if selecting by primary key
        if schema:
            m = re.search(r"SELECT\s+DISTINCT\s+(.+?)\s+FROM\s+(\w+)", sql, re.IGNORECASE)
            if m:
                columns_str = m.group(1)
                table = m.group(2)
                pk_cols = schema.get("primary_keys", {}).get(table, [])
                if pk_cols and all(c in columns_str for c in pk_cols):
                    return SafetyReport(
                        safe=True,
                        confidence=0.99,
                        reason=f"Primary key {pk_cols} guarantees uniqueness",
                    )

        return SafetyReport(
            safe=True,
            confidence=0.7,
            warnings=["Verify that the result set is naturally unique before removing DISTINCT"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "safety": self.safety,
            "examples": [
                {"before": e.before, "after": e.after, "explanation": e.explanation}
                for e in self.examples
            ],
        }


class RewritePatternLibrary:
    """
    Registry of SQL rewrite patterns with safety validation.

    Contains 20+ patterns covering:
    - Subquery optimization (NOT IN, IN, correlated)
    - Join optimization (implicit to explicit, left to inner)
    - Aggregation (COUNT, DISTINCT, GROUP BY)
    - Predicate optimization (OR to IN, LIKE, SARGable)
    - Type optimization (COALESCE, CAST, implicit)
    """

    def __init__(self) -> None:
        self.patterns = self._build_patterns()

    def _build_patterns(self) -> list[RewritePattern]:
        return [
            RewritePattern(
                name="NOT_IN_TO_NOT_EXISTS",
                description="Convert NOT IN (subquery) to NOT EXISTS for NULL safety",
                pattern=r"WHERE\s+\w+\s+NOT\s+IN\s*\(\s*SELECT\s+\w+\s+FROM\s+\w+",
                rewrite_template=(
                    "WHERE NOT EXISTS (SELECT 1 FROM {subquery_table} "
                    "WHERE {subquery_table}.{subquery_col} = {outer_table}.{outer_col})"
                ),
                safety=0.95,
                category="subquery",
                examples=[
                    RewriteExample(
                        before="SELECT * FROM orders WHERE user_id NOT IN (SELECT id FROM banned_users)",
                        after="SELECT * FROM orders WHERE NOT EXISTS (SELECT 1 FROM banned_users WHERE banned_users.id = orders.user_id)",
                        explanation="NOT IN returns no rows when subquery has NULLs",
                    ),
                ],
                counterexamples=[
                    "NOT IN with a literal list: WHERE id NOT IN (1, 2, 3) — no rewrite needed",
                ],
            ),
            RewritePattern(
                name="IN_SUBQUERY_TO_JOIN",
                description="Convert IN (subquery) to JOIN for better plan selection",
                pattern=r"WHERE\s+\w+\s+IN\s*\(\s*SELECT\s+\w+\s+FROM\s+\w+",
                rewrite_template=(
                    "INNER JOIN {subquery_table} ON {outer_table}.{col} = {subquery_table}.{col}"
                ),
                safety=0.9,
                category="subquery",
                examples=[
                    RewriteExample(
                        before="SELECT * FROM orders WHERE customer_id IN (SELECT id FROM customers WHERE active)",
                        after="SELECT orders.* FROM orders INNER JOIN customers ON orders.customer_id = customers.id WHERE customers.active",
                    ),
                ],
            ),
            RewritePattern(
                name="OR_TO_IN",
                description="Convert multiple OR conditions on same column to IN",
                pattern=r"WHERE\s+(\w+)\s*=\s*'[^']+'\s+OR\s+\1\s*=\s*'[^']+'",
                rewrite_template="WHERE {col} IN ({values})",
                safety=1.0,
                category="predicate",
                examples=[
                    RewriteExample(
                        before="WHERE status = 'active' OR status = 'pending' OR status = 'review'",
                        after="WHERE status IN ('active', 'pending', 'review')",
                    ),
                ],
            ),
            RewritePattern(
                name="COALESCE_TO_OR",
                description="Rewrite COALESCE comparison to OR for index usage",
                pattern=r"COALESCE\s*\(\s*\w+\s*,\s*'[^']+'\s*\)\s*=\s*'[^']+'",
                rewrite_template="({col} = {value} OR ({col} IS NULL AND {default} = {value}))",
                safety=0.9,
                category="predicate",
            ),
            RewritePattern(
                name="UNION_TO_UNION_ALL",
                description="Replace UNION with UNION ALL when duplicates are impossible",
                pattern=r"SELECT.*\bUNION\b\s+SELECT",
                rewrite_template="... UNION ALL ...",
                safety=0.7,
                category="aggregate",
            ),
            RewritePattern(
                name="REMOVE_DISTINCT",
                description="Remove redundant DISTINCT when result is naturally unique",
                pattern=r"SELECT\s+DISTINCT\s+\*\s+FROM",
                rewrite_template="SELECT * FROM ...",
                safety=0.6,
                category="aggregate",
                counterexamples=[
                    "DISTINCT is needed after a JOIN that produces duplicates",
                ],
            ),
            RewritePattern(
                name="DISTINCT_TO_GROUP_BY",
                description="Convert SELECT DISTINCT to GROUP BY for aggregation potential",
                pattern=r"SELECT\s+DISTINCT\s+(\w+(?:\s*,\s*\w+)*)\s+FROM",
                rewrite_template="SELECT {cols} FROM ... GROUP BY {cols}",
                safety=0.85,
                category="aggregate",
            ),
            RewritePattern(
                name="LIKE_LEADING_WILDCARD",
                description="Leading wildcard LIKE prevents index usage — suggest trigram index",
                pattern=r"WHERE\s+\w+\s+(?:I?LIKE)\s+'%[^']+",
                rewrite_template=(
                    "-- Add trigram index:\n"
                    "CREATE INDEX CONCURRENTLY idx_{table}_{col}_trgm "
                    "ON {table} USING GIN ({col} gin_trgm_ops);\n"
                    "-- Then keep original LIKE"
                ),
                safety=0.8,
                category="indexing",
            ),
            RewritePattern(
                name="OFFSET_TO_KEYSET",
                description="Convert OFFSET pagination to keyset pagination",
                pattern=r"ORDER\s+BY\s+\w+\s+(ASC|DESC)?\s*LIMIT\s+\d+\s+OFFSET\s+\d+",
                rewrite_template="WHERE {sort_col} > {last_seen_value} ORDER BY {sort_col} LIMIT {page_size}",
                safety=0.8,
                category="predicate",
                examples=[
                    RewriteExample(
                        before="SELECT * FROM products ORDER BY id LIMIT 20 OFFSET 10000",
                        after="SELECT * FROM products WHERE id > 10000 ORDER BY id LIMIT 20",
                        explanation="Keyset pagination is O(1) vs OFFSET's O(n)",
                    ),
                ],
            ),
            RewritePattern(
                name="COUNT_STAR_TO_RELTUPLES",
                description="Approximate COUNT(*) using pg_class.reltuples for huge tables",
                pattern=r"SELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\s+\w+\s*;?\s*$",
                rewrite_template=(
                    "SELECT reltuples::bigint FROM pg_class WHERE relname = '{table}';"
                ),
                safety=0.6,
                category="aggregate",
                counterexamples=["Need exact count for financial reconciliation"],
            ),
            RewritePattern(
                name="LEFT_JOIN_TO_INNER",
                description="Convert LEFT JOIN to INNER JOIN when WHERE filters NULLs",
                pattern=r"LEFT\s+(?:OUTER\s+)?JOIN\s+\w+.+WHERE\s+\w+\.\w+\s+IS\s+NOT\s+NULL",
                rewrite_template="INNER JOIN ...",
                safety=0.85,
                category="join",
            ),
            RewritePattern(
                name="IMPLICIT_JOIN_TO_EXPLICIT",
                description="Convert comma-separated FROM to explicit JOIN",
                pattern=r"FROM\s+(\w+)\s*,\s*(\w+)\s+WHERE\s+\1\.\w+\s*=\s*\2\.\w+",
                rewrite_template="FROM {t1} INNER JOIN {t2} ON {t1}.{col} = {t2}.{col}",
                safety=1.0,
                category="join",
            ),
            RewritePattern(
                name="EXISTS_SELECT_STAR_TO_ONE",
                description="Simplify EXISTS (SELECT *) to EXISTS (SELECT 1)",
                pattern=r"EXISTS\s*\(\s*SELECT\s+\*\s+FROM",
                rewrite_template="EXISTS (SELECT 1 FROM ...",
                safety=1.0,
                category="subquery",
            ),
            RewritePattern(
                name="HAVING_WITHOUT_GROUPBY",
                description="Replace HAVING without GROUP BY with WHERE",
                pattern=r"(?<!GROUP\s+BY\s+\w+\s+)HAVING\s+",
                rewrite_template="WHERE ...",
                safety=0.9,
                category="aggregate",
            ),
            RewritePattern(
                name="CAST_IN_WHERE",
                description="Remove CAST in WHERE for index usage",
                pattern=r"WHERE\s+CAST\s*\(\s*\w+\s+AS\s+\w+\s*\)",
                rewrite_template="WHERE {col} = {value}::{type}",
                safety=0.75,
                category="predicate",
            ),
            RewritePattern(
                name="FUNCTION_ON_INDEXED_COL",
                description="Function on indexed column prevents index usage",
                pattern=r"WHERE\s+(?:UPPER|LOWER|TRIM|COALESCE|TO_CHAR|EXTRACT)\s*\(\s*\w+",
                rewrite_template="-- Create expression index or rewrite predicate",
                safety=0.7,
                category="indexing",
            ),
            RewritePattern(
                name="CORRELATED_SUBQUERY_TO_JOIN",
                description="Convert correlated subquery to JOIN",
                pattern=r"WHERE\s+\w+\s*=\s*\(\s*SELECT.*WHERE\s+\w+\.\w+\s*=\s*\w+\.\w+",
                rewrite_template="JOIN (SELECT ... GROUP BY ...) ON ...",
                safety=0.75,
                category="subquery",
            ),
            RewritePattern(
                name="COUNT_1_TO_COUNT_STAR",
                description="COUNT(1) offers no benefit over COUNT(*) — normalize",
                pattern=r"COUNT\s*\(\s*1\s*\)",
                rewrite_template="COUNT(*)",
                safety=1.0,
                category="aggregate",
            ),
            RewritePattern(
                name="BETWEEN_TIMESTAMPS",
                description="BETWEEN on timestamps is inclusive — use >= and < for ranges",
                pattern=r"BETWEEN\s+'[\d-]+\s+[\d:]+'\s+AND\s+'[\d-]+\s+[\d:]+'",
                rewrite_template=">= '{start}' AND < '{end}'",
                safety=0.9,
                category="predicate",
            ),
            RewritePattern(
                name="SELECT_STAR",
                description="Replace SELECT * with explicit columns to reduce I/O",
                pattern=r"SELECT\s+\*\s+FROM",
                rewrite_template="SELECT {needed_columns} FROM ...",
                safety=0.7,
                category="general",
                counterexamples=["Acceptable in EXISTS subqueries"],
            ),
        ]

    def find_matches(self, sql: str) -> list[RewritePattern]:
        """Find all patterns that match the given SQL."""
        return [p for p in self.patterns if p.matches(sql)]

    def find_safe_matches(
        self,
        sql: str,
        min_safety: float = 0.7,
        schema_info: dict[str, Any] | None = None,
    ) -> list[tuple[RewritePattern, SafetyReport]]:
        """Find matches and validate safety, returning only safe rewrites."""
        results: list[tuple[RewritePattern, SafetyReport]] = []

        for pattern in self.find_matches(sql):
            report = pattern.validate_safety(sql, schema_info)
            if report.safe and report.confidence >= min_safety:
                results.append((pattern, report))

        return results

    def get_by_category(self, category: str) -> list[RewritePattern]:
        """Get all patterns in a category."""
        return [p for p in self.patterns if p.category == category]

    def to_json(self) -> str:
        """Export the pattern library as JSON."""
        return json.dumps(
            [p.to_dict() for p in self.patterns],
            indent=2,
        )
