"""
Human Explainer — translate technical findings to plain English.

Addresses the #1 UX pain point: "EXPLAIN plans are intimidating — I just
want to know what to fix" (Reddit r/PostgreSQL, daily complaints).

Design philosophy:
- Every finding gets three parts: What happened, Why it matters, How to fix
- Use analogies non-DBAs understand (phone book, traffic, filing cabinet)
- Never assume DBA knowledge
- Show estimated impact in human terms ("57x faster" not "cost reduced from 12345 to 216")

Usage:
    from querysense.explainer import HumanExplainer

    explainer = HumanExplainer()
    plain = explainer.translate(finding)
    print(plain.what_happened)
    print(plain.why_it_matters)
    print(plain.how_to_fix)
    print(plain.analogy)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import Finding


@dataclass(frozen=True)
class HumanExplanation:
    """A plain-English explanation of a technical finding."""

    what_happened: str
    why_it_matters: str
    how_to_fix: str
    analogy: str
    estimated_impact: str
    difficulty: str  # "easy", "medium", "hard"
    time_to_fix: str  # "2 minutes", "30 minutes", etc.


# ── Rule-specific translations ───────────────────────────────────────

_TRANSLATIONS: dict[str, dict[str, str]] = {
    "SEQ_SCAN_LARGE_TABLE": {
        "what": "Your query is reading the ENTIRE table row by row.",
        "why": (
            "Like flipping through every page of a phone book to find one name. "
            "As your table grows, this gets proportionally slower. A table with "
            "1 million rows takes 1 million row reads."
        ),
        "fix": "Create an index on the column(s) in your WHERE clause.",
        "analogy": "Phone book without an alphabetical index — you read every page.",
        "difficulty": "easy",
        "time": "2 minutes",
    },
    "SEQ_SCAN_NO_FILTER": {
        "what": "Your query reads the entire table with no filter at all.",
        "why": (
            "You're loading every single row into memory. If this table has "
            "millions of rows, that's a lot of wasted work and memory."
        ),
        "fix": "Add a WHERE clause to filter rows, or check if SELECT * is intentional.",
        "analogy": "Photocopying an entire filing cabinet when you only need one folder.",
        "difficulty": "easy",
        "time": "5 minutes",
    },
    "BAD_ROW_ESTIMATE": {
        "what": (
            "PostgreSQL's planner guessed wrong about how many rows your query "
            "would return. It expected a few rows but got thousands (or vice versa)."
        ),
        "why": (
            "When the planner guesses wrong, it picks the wrong strategy. "
            "Imagine GPS routing you through a 'shortcut' that's actually a dirt road — "
            "the planner chose a fast-for-small-results plan on a large result set."
        ),
        "fix": "Run ANALYZE on the table to update PostgreSQL's statistics.",
        "analogy": "GPS using a 10-year-old map — it doesn't know the new highway exists.",
        "difficulty": "easy",
        "time": "1 minute",
    },
    "STALE_STATISTICS": {
        "what": "Your table statistics are outdated — PostgreSQL doesn't know the current data distribution.",
        "why": (
            "PostgreSQL makes query plans based on statistics about your data. "
            "If those stats are stale, it's like a weather forecast from last week — "
            "technically a forecast, but useless for planning today."
        ),
        "fix": "Run ANALYZE on the affected table(s).",
        "analogy": "Planning your outfit based on last week's weather forecast.",
        "difficulty": "easy",
        "time": "1 minute",
    },
    "NESTED_LOOP_LARGE_TABLE": {
        "what": "PostgreSQL is using a nested loop to join two large tables — checking every combination.",
        "why": (
            "A nested loop on large tables is like comparing every student in School A "
            "with every student in School B to find matches. For 10,000 students each, "
            "that's 100 million comparisons. A hash join would do it in ~20,000 steps."
        ),
        "fix": "Ensure join columns have indexes, or increase work_mem to allow hash joins.",
        "analogy": "Comparing 10,000 × 10,000 student lists by hand instead of sorting them first.",
        "difficulty": "medium",
        "time": "10 minutes",
    },
    "CORRELATED_SUBQUERY": {
        "what": "Your query has a subquery that runs once PER ROW of the outer query.",
        "why": (
            "If your outer query has 10,000 rows, the subquery runs 10,000 times. "
            "That's 10,000 mini-queries instead of one. It's the database equivalent "
            "of making 10,000 individual API calls instead of one batch request."
        ),
        "fix": "Rewrite as a JOIN or use EXISTS instead of the correlated subquery.",
        "analogy": "Asking the librarian to check one book 10,000 times vs. getting a list all at once.",
        "difficulty": "medium",
        "time": "15 minutes",
    },
    "SPILLING_TO_DISK": {
        "what": "Your query ran out of memory and had to write temporary data to disk.",
        "why": (
            "Disk is 100x slower than RAM. Your sort or hash join was too big to fit "
            "in memory, so PostgreSQL wrote overflow data to disk. This is like when "
            "your desk is too small and you have to keep running to the filing cabinet."
        ),
        "fix": "Increase work_mem (SET work_mem = '256MB') or reduce the data set size.",
        "analogy": "Desk too small for your papers — constantly running to the filing cabinet.",
        "difficulty": "easy",
        "time": "2 minutes",
    },
    "HASH_JOIN_BATCHES": {
        "what": "A hash join needed multiple passes because the hash table didn't fit in memory.",
        "why": (
            "Each extra batch means re-reading data from disk. More batches = proportionally "
            "slower. Think of it as having to make multiple trips to carry groceries because "
            "you can't carry them all at once."
        ),
        "fix": "Increase work_mem to fit the hash table in one batch.",
        "analogy": "Making 5 trips to carry groceries because your bags are too small.",
        "difficulty": "easy",
        "time": "2 minutes",
    },
    "REDUNDANT_SORT": {
        "what": "Your query sorts the same data twice — the second sort is unnecessary.",
        "why": (
            "Sorting is expensive, especially for large result sets. If the data is "
            "already sorted from a previous step, sorting again wastes CPU time."
        ),
        "fix": "Remove the redundant ORDER BY, or restructure CTEs to preserve sort order.",
        "analogy": "Alphabetizing a stack of papers that's already alphabetized.",
        "difficulty": "easy",
        "time": "5 minutes",
    },
    "IMPLICIT_CAST_FILTER": {
        "what": "PostgreSQL is silently converting data types in your WHERE clause, preventing index use.",
        "why": (
            "When you compare an integer column to a string, PostgreSQL converts every "
            "row's value to match. This means it can't use the index — it has to check "
            "every row. It's like having an alphabetical index but searching by number."
        ),
        "fix": "Match data types in your query: use integers for integer columns, strings for text.",
        "analogy": "Searching a phone book by street number when it's organized by name.",
        "difficulty": "easy",
        "time": "2 minutes",
    },
    "PARTITION_PRUNING_FAILURE": {
        "what": "PostgreSQL is scanning ALL partitions instead of just the relevant one(s).",
        "why": (
            "Partitioning splits a large table into smaller pieces for faster queries. "
            "But your query isn't taking advantage of this — it reads every partition. "
            "Like having files organized by year but opening every drawer anyway."
        ),
        "fix": "Include the partition key in your WHERE clause.",
        "analogy": "Opening every drawer in a filing cabinet organized by year, instead of just 2024.",
        "difficulty": "easy",
        "time": "5 minutes",
    },
    "WORK_MEM_TUNING": {
        "what": "PostgreSQL's work_mem setting is too low for this query's sorting/hashing needs.",
        "why": (
            "work_mem controls how much RAM each sort/hash operation can use. "
            "Too low, and operations spill to slow disk. Too high, and concurrent "
            "queries might exhaust server memory."
        ),
        "fix": "Increase work_mem for this session: SET work_mem = '256MB';",
        "analogy": "Giving an employee a tiny desk then wondering why they're slow — give them more space.",
        "difficulty": "easy",
        "time": "1 minute",
    },
    "PARALLEL_QUERY_NOT_USED": {
        "what": "This query could run in parallel across multiple CPU cores, but it isn't.",
        "why": (
            "Modern servers have 8, 16, or 32+ cores. Using only one core for a big "
            "query is like having 16 cashiers but only one register open."
        ),
        "fix": "Check max_parallel_workers_per_gather and parallel_tuple_cost settings.",
        "analogy": "16 cashiers available but only 1 register open during rush hour.",
        "difficulty": "medium",
        "time": "10 minutes",
    },
    "MATERIALIZE_LARGE": {
        "what": "PostgreSQL is materializing (buffering) a large intermediate result in memory.",
        "why": (
            "Materialization stores the entire subquery result before proceeding. "
            "For large results, this consumes significant memory and slows the query."
        ),
        "fix": "Rewrite the CTE as a subquery (PG12+ can auto-inline) or add LIMIT.",
        "analogy": "Printing an entire encyclopedia to find one paragraph, instead of looking it up.",
        "difficulty": "medium",
        "time": "15 minutes",
    },
    "SORT_AVOIDABLE_WITH_INDEX": {
        "what": "PostgreSQL is sorting results that could already be ordered by an index.",
        "why": (
            "Sorting is O(n log n) work. An index delivers rows pre-sorted at zero "
            "extra cost. It's the difference between shuffling a deck of cards vs. "
            "pulling them from a sorted pile."
        ),
        "fix": "Create an index that matches your ORDER BY clause.",
        "analogy": "Shuffling and re-sorting a deck of cards that was already in order.",
        "difficulty": "easy",
        "time": "2 minutes",
    },
    "LIMIT_WITHOUT_INDEX": {
        "what": "Your query uses LIMIT but still reads the entire table to find the top N rows.",
        "why": (
            "Without an index matching your ORDER BY, PostgreSQL must sort ALL rows "
            "before picking the top N. For LIMIT 10 on a million-row table, it sorts "
            "1,000,000 rows to return 10."
        ),
        "fix": "Create an index on the ORDER BY column(s).",
        "analogy": "Reading every book in the library to find the 3 newest ones, instead of checking the 'New Arrivals' shelf.",
        "difficulty": "easy",
        "time": "2 minutes",
    },
    "ORM_N_PLUS_ONE": {
        "what": "Your ORM is generating N+1 queries — one query to get a list, then one query per item.",
        "why": (
            "If you load 100 users and then their orders, the ORM sends 1 query for "
            "users + 100 queries for orders = 101 queries. A single JOIN would do it "
            "in 1 query. This is the #1 ORM performance killer."
        ),
        "fix": (
            "Rails: add .includes(:orders). Django: use select_related() or prefetch_related(). "
            "SQLAlchemy: use joinedload(). Or rewrite as a single JOIN query."
        ),
        "analogy": "Ordering 100 items from Amazon in 100 separate orders instead of one cart.",
        "difficulty": "medium",
        "time": "10 minutes",
    },
    "LATERAL_JOIN_INDEX": {
        "what": "Your LATERAL subquery with ORDER BY + LIMIT needs a composite index.",
        "why": (
            "Without the right index, PostgreSQL scans the entire child table for EACH "
            "row of the parent. With a composite index on (parent_id, sort_column), "
            "it can jump directly to the right rows."
        ),
        "fix": "CREATE INDEX CONCURRENTLY ON child_table (parent_id, sort_column DESC);",
        "analogy": "Looking up each student's latest grade by scanning ALL grades instead of having a sorted index card per student.",
        "difficulty": "easy",
        "time": "2 minutes",
    },
}

# Catch-all for unknown rules
_DEFAULT_TRANSLATION = {
    "what": "A performance issue was detected in your query plan.",
    "why": "This could cause slower query execution or increased resource usage.",
    "fix": "See the suggestion above for specific remediation steps.",
    "analogy": "Your query could be taking the long way around instead of a shortcut.",
    "difficulty": "medium",
    "time": "varies",
}


class HumanExplainer:
    """Translates technical query plan findings into plain English."""

    def __init__(self, *, custom_translations: dict[str, dict[str, str]] | None = None) -> None:
        self._translations = dict(_TRANSLATIONS)
        if custom_translations:
            self._translations.update(custom_translations)

    def translate(self, finding: Any) -> HumanExplanation:
        """Translate a Finding into a human-readable explanation."""
        rule_id = getattr(finding, "rule_id", "") or ""
        t = self._translations.get(rule_id, _DEFAULT_TRANSLATION)

        # Enrich with finding-specific context
        what = t["what"]
        why = t["why"]
        fix = t["fix"]

        # Override fix with finding's actual suggestion if available
        suggestion = getattr(finding, "suggestion", None)
        if suggestion and suggestion.strip():
            fix = suggestion.strip()

        # Extract estimated impact
        metrics = getattr(finding, "metrics", None) or {}
        speedup = metrics.get("estimated_speedup", "")
        impact_score = getattr(finding, "impact_score", 0) or 0

        if speedup:
            estimated_impact = f"Estimated {speedup} faster after fix"
        elif impact_score >= 8:
            estimated_impact = "Major performance improvement expected"
        elif impact_score >= 5:
            estimated_impact = "Moderate performance improvement expected"
        elif impact_score >= 2:
            estimated_impact = "Minor performance improvement expected"
        else:
            estimated_impact = "Performance improvement possible"

        # Add relation context if available
        context = getattr(finding, "context", None)
        relation = getattr(context, "relation_name", None) if context else None
        if relation:
            what = what.replace("table", f"table '{relation}'", 1)
            what = what.replace("your query", f"your query on '{relation}'", 1)

        return HumanExplanation(
            what_happened=what,
            why_it_matters=why,
            how_to_fix=fix,
            analogy=t.get("analogy", ""),
            estimated_impact=estimated_impact,
            difficulty=t.get("difficulty", "medium"),
            time_to_fix=t.get("time", "varies"),
        )

    def translate_to_dict(self, finding: Any) -> dict[str, str]:
        """Translate a Finding to a plain dict (useful for JSON/templates)."""
        exp = self.translate(finding)
        return {
            "what_happened": exp.what_happened,
            "why_it_matters": exp.why_it_matters,
            "how_to_fix": exp.how_to_fix,
            "analogy": exp.analogy,
            "estimated_impact": exp.estimated_impact,
            "difficulty": exp.difficulty,
            "time_to_fix": exp.time_to_fix,
        }

    @property
    def supported_rules(self) -> list[str]:
        """Return list of rule IDs that have human translations."""
        return sorted(self._translations.keys())
