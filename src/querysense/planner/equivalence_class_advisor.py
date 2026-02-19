"""
Equivalence Class & Join Condition Advisor.

Based on pganalyze blog:
  - "Postgres Planner Quirks: JOIN Equivalence Classes and IN/ANY filters" (E117)
  - "Postgres IN vs ANY performance" (E75)
  - "Forcing Join Order in Postgres Using Optimization Barriers" (E67)

PostgreSQL's equivalence class mechanism propagates equality conditions
transitively across joins.  For example:

    SELECT * FROM a JOIN b ON a.id = b.id WHERE a.id = 42;

The planner deduces ``b.id = 42`` automatically via the equivalence class
``{a.id, b.id, 42}``.

**Limitation**: This ONLY works for plain equality (``=``).  It does NOT
work for ``IN``, ``ANY``, ``>``, ``BETWEEN``, or ``@>``.  This means:

    SELECT * FROM a JOIN b USING (id) WHERE a.id IN (1,2,3);

does NOT automatically add ``b.id IN (1,2,3)`` — and the planner may
choose a full table scan on ``b`` instead of an index lookup.

The fix is to manually duplicate the filter on both sides of the join.
In benchmarks from the article, this yielded up to **2 000x speedup**.

Usage:
    from querysense.planner.equivalence_class_advisor import EquivalenceClassAdvisor

    adv = EquivalenceClassAdvisor()
    issues = adv.analyze_query(sql)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class JoinFilterIssueType(str, Enum):
    IN_NOT_PROPAGATED = "in_not_propagated"
    ANY_NOT_PROPAGATED = "any_not_propagated"
    RANGE_NOT_PROPAGATED = "range_not_propagated"


@dataclass(frozen=True)
class JoinCondition:
    """A parsed join between two table aliases."""
    left_table: str
    right_table: str
    column: str
    join_type: str = "INNER"


@dataclass(frozen=True)
class FilterCondition:
    """A parsed WHERE-clause filter."""
    table: str
    column: str
    operator: str  # '=', 'IN', 'ANY', '>', '<', 'BETWEEN'
    raw_text: str = ""


@dataclass(frozen=True)
class JoinFilterIssue:
    """A detected missing-filter optimisation opportunity."""
    issue_type: JoinFilterIssueType
    description: str
    join_tables: tuple[str, str]
    join_column: str
    filtered_table: str
    missing_table: str
    operator: str
    severity: str  # 'critical', 'warning', 'info'
    estimated_speedup: str
    fix_sql: str
    explanation: str


class EquivalenceClassAdvisor:
    """
    Detect queries where a WHERE filter on one side of a join
    should be duplicated on the other side for optimal plans.
    """

    _NON_PROPAGATING_OPS = {"IN", "ANY", ">", "<", ">=", "<=", "BETWEEN"}

    _JOIN_RE = re.compile(
        r"(?:INNER\s+|LEFT\s+|RIGHT\s+)?JOIN\s+(\w+)"
        r"(?:\s+\w+)?"
        r"\s+(?:ON\s+(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)"
        r"|USING\s*\(\s*(\w+)\s*\))",
        re.IGNORECASE,
    )
    _FROM_RE = re.compile(
        r"FROM\s+(\w+)(?:\s+(\w+))?(?=\s+(?:INNER\s+|LEFT\s+|RIGHT\s+)?JOIN\b|\s+WHERE\b|\s*$)",
        re.IGNORECASE,
    )
    _WHERE_RE = re.compile(
        r"WHERE\s+(.+?)(?=\s*(?:GROUP|ORDER|LIMIT|HAVING|WINDOW|UNION|INTERSECT|EXCEPT|;|$))",
        re.IGNORECASE | re.DOTALL,
    )

    _FILTER_ANY_RE = re.compile(
        r"(\w+)\.(\w+)\s*=\s*ANY\s*\(",
        re.IGNORECASE,
    )
    _FILTER_IN_RE = re.compile(
        r"(\w+)\.(\w+)\s+IN\s*\(",
        re.IGNORECASE,
    )
    _FILTER_RANGE_RE = re.compile(
        r"(\w+)\.(\w+)\s*(>|<|>=|<=|BETWEEN)\s*",
        re.IGNORECASE,
    )

    def analyze_query(self, query: str) -> list[JoinFilterIssue]:
        """Return issues where a filter should be duplicated."""
        joins = self._parse_joins(query)
        filters = self._parse_filters(query)
        if not joins or not filters:
            return []

        issues: list[JoinFilterIssue] = []
        for j in joins:
            for f in filters:
                if issue := self._check_missing_propagation(j, f, query):
                    issues.append(issue)
        return issues

    def generate_test_queries(self) -> list[dict[str, Any]]:
        """Return canned test-case pairs demonstrating the issue."""
        return [
            {
                "name": "IN filter not propagated across JOIN",
                "setup": (
                    "CREATE TABLE t1 (a int);\n"
                    "CREATE TABLE t2 (a int);\n"
                    "INSERT INTO t1 SELECT i FROM generate_series(1,100000) s(i);\n"
                    "INSERT INTO t2 SELECT mod(i,100000) FROM generate_series(1,10000000) s(i);\n"
                    "CREATE INDEX ON t1(a); CREATE INDEX ON t2(a);\n"
                    "VACUUM ANALYZE t1, t2;"
                ),
                "slow_query": (
                    "SELECT t1.a, t2.a\n"
                    "FROM t1 JOIN t2 USING (a)\n"
                    "WHERE t1.a IN (99000, 99001)\n"
                    "ORDER BY t1.a LIMIT 100;"
                ),
                "fast_query": (
                    "SELECT t1.a, t2.a\n"
                    "FROM t1 JOIN t2 USING (a)\n"
                    "WHERE t1.a IN (99000, 99001)\n"
                    "  AND t2.a IN (99000, 99001)\n"
                    "ORDER BY t1.a LIMIT 100;"
                ),
                "expected_speedup": "~2000x",
            },
            {
                "name": "ANY filter not propagated across JOIN",
                "setup": (
                    "CREATE TABLE docs (id int); CREATE TABLE tags (doc_id int, tag text);\n"
                    "INSERT INTO docs SELECT i FROM generate_series(1,500000) s(i);\n"
                    "INSERT INTO tags SELECT mod(i,500000), 'tag' || mod(i,100) FROM generate_series(1,5000000) s(i);\n"
                    "CREATE INDEX ON docs(id); CREATE INDEX ON tags(doc_id);\n"
                    "VACUUM ANALYZE docs, tags;"
                ),
                "slow_query": (
                    "SELECT * FROM docs\n"
                    "JOIN tags ON docs.id = tags.doc_id\n"
                    "WHERE docs.id = ANY(ARRAY[1,2,3]);"
                ),
                "fast_query": (
                    "SELECT * FROM docs\n"
                    "JOIN tags ON docs.id = tags.doc_id\n"
                    "WHERE docs.id = ANY(ARRAY[1,2,3])\n"
                    "  AND tags.doc_id = ANY(ARRAY[1,2,3]);"
                ),
                "expected_speedup": "~500x",
            },
        ]

    def explain_equivalence_classes(self) -> str:
        """Return a human-readable explanation of the mechanism."""
        return (
            "PostgreSQL Equivalence Classes\n"
            "==============================\n"
            "\n"
            "When the planner sees  A = B  and  B = C  it deduces  A = C.\n"
            "If a filter  A = 42  exists, it applies to all members.\n"
            "\n"
            "Limitation: this ONLY works for plain equality (=).\n"
            "  - IN (1,2,3)       -- NOT propagated\n"
            "  - = ANY(array)     -- NOT propagated\n"
            "  - > 100            -- NOT propagated\n"
            "  - BETWEEN 10 AND 20-- NOT propagated\n"
            "\n"
            "Workaround: manually duplicate the filter on both sides.\n"
            "Expected improvement: 100x - 2000x in affected queries.\n"
        )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_joins(self, query: str) -> list[JoinCondition]:
        joins: list[JoinCondition] = []
        from_match = self._FROM_RE.search(query)
        from_table = from_match.group(2) or from_match.group(1) if from_match else ""

        for m in self._JOIN_RE.finditer(query):
            right = m.group(1)
            if m.group(6):  # USING
                col = m.group(6)
                joins.append(JoinCondition(from_table, right, col))
            elif m.group(2):  # ON
                joins.append(JoinCondition(m.group(2), m.group(4), m.group(3)))
        return joins

    def _parse_filters(self, query: str) -> list[FilterCondition]:
        where = self._WHERE_RE.search(query)
        if not where:
            return []
        clause = where.group(1)

        filters: list[FilterCondition] = []
        for m in self._FILTER_ANY_RE.finditer(clause):
            filters.append(FilterCondition(m.group(1), m.group(2), "ANY", m.group(0)))
        for m in self._FILTER_IN_RE.finditer(clause):
            filters.append(FilterCondition(m.group(1), m.group(2), "IN", m.group(0)))
        for m in self._FILTER_RANGE_RE.finditer(clause):
            filters.append(FilterCondition(m.group(1), m.group(2), m.group(3).upper(), m.group(0)))
        return filters

    def _check_missing_propagation(
        self,
        join: JoinCondition,
        filt: FilterCondition,
        query: str,
    ) -> JoinFilterIssue | None:
        tables = (join.left_table, join.right_table)
        if filt.table not in tables:
            return None
        if filt.column != join.column:
            return None
        if filt.operator not in self._NON_PROPAGATING_OPS:
            return None

        other = join.right_table if filt.table == join.left_table else join.left_table

        other_has = re.search(
            rf"{re.escape(other)}\.{re.escape(filt.column)}\s*(?:=\s*ANY|IN\s*\(|>|<|>=|<=|BETWEEN)",
            query,
            re.IGNORECASE,
        )
        if other_has:
            return None

        if filt.operator in ("IN", "ANY"):
            issue_type = (
                JoinFilterIssueType.IN_NOT_PROPAGATED
                if filt.operator == "IN"
                else JoinFilterIssueType.ANY_NOT_PROPAGATED
            )
            severity = "critical"
            speedup = "up to 2000x"
        else:
            issue_type = JoinFilterIssueType.RANGE_NOT_PROPAGATED
            severity = "warning"
            speedup = "up to 500x"

        fix_line = (
            f"  AND {other}.{filt.column} {filt.raw_text.split('.', 1)[-1].strip()}"
            if filt.raw_text
            else f"  AND {other}.{filt.column} {filt.operator} ..."
        )

        return JoinFilterIssue(
            issue_type=issue_type,
            description=(
                f"{filt.operator} filter on {filt.table}.{filt.column} is not "
                f"propagated to {other}.{filt.column} via equivalence class"
            ),
            join_tables=(join.left_table, join.right_table),
            join_column=join.column,
            filtered_table=filt.table,
            missing_table=other,
            operator=filt.operator,
            severity=severity,
            estimated_speedup=speedup,
            fix_sql=f"-- Add duplicate filter:\n{fix_line}",
            explanation=(
                "PostgreSQL equivalence classes only propagate plain equality (=). "
                f"The {filt.operator} operator is not propagated, so {other} may "
                "be fully scanned instead of using an index."
            ),
        )
