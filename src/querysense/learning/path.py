"""
Personalized Learning Path Generator.

Turns query analysis findings into progressive lessons that teach
users how to optimize their databases. This is the "education moat"
that no competitor has.

Categories:
- Indexing fundamentals (B-tree, GIN, partial, covering)
- Statistics & ANALYZE
- Query rewriting (SQL anti-patterns)
- Configuration tuning (work_mem, shared_buffers)
- Schema design (normalization, types, constraints)
- Concurrency & locking
- Monitoring & observability

Usage:
    from querysense.learning import generate_learning_path

    path = generate_learning_path(findings, user_level="beginner")
    for lesson in path.lessons:
        print(f"Lesson: {lesson.title}")
        print(f"  Concepts: {lesson.concepts}")
        print(f"  Practice: {lesson.practice_sql}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Quiz:
    """A quiz question for validating understanding."""
    question: str
    options: list[str] = field(default_factory=list)
    correct_answer: int = 0  # index into options
    explanation: str = ""


@dataclass
class Lesson:
    """A single learning lesson tied to real findings."""
    title: str
    category: str               # indexing / statistics / rewrite / config / schema / concurrency
    level: str = "beginner"     # beginner / intermediate / advanced
    concepts: list[str] = field(default_factory=list)
    explanation: str = ""
    practice_sql: str = ""      # SQL to try
    finding_rule_ids: list[str] = field(default_factory=list)
    quizzes: list[Quiz] = field(default_factory=list)
    further_reading: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "level": self.level,
            "concepts": self.concepts,
            "explanation": self.explanation,
            "practice_sql": self.practice_sql,
            "finding_rule_ids": self.finding_rule_ids,
            "quizzes": [
                {
                    "question": q.question,
                    "options": q.options,
                    "correct_answer": q.correct_answer,
                    "explanation": q.explanation,
                }
                for q in self.quizzes
            ],
            "further_reading": self.further_reading,
        }


@dataclass
class LearningPath:
    """A personalized sequence of lessons."""
    user_level: str
    total_lessons: int = 0
    estimated_time_minutes: int = 0
    lessons: list[Lesson] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_level": self.user_level,
            "total_lessons": self.total_lessons,
            "estimated_time_minutes": self.estimated_time_minutes,
            "lessons": [l.to_dict() for l in self.lessons],
        }

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  QUERYSENSE LEARNING PATH")
        lines.append("  " + "=" * 50)
        lines.append(f"  Level: {self.user_level}")
        lines.append(f"  Lessons: {self.total_lessons}")
        lines.append(f"  Estimated time: {self.estimated_time_minutes} minutes")
        lines.append("")

        for i, lesson in enumerate(self.lessons, 1):
            lines.append(f"  Lesson {i}: {lesson.title}")
            lines.append(f"  Category: {lesson.category} | Level: {lesson.level}")

            if lesson.concepts:
                lines.append(f"  Concepts: {', '.join(lesson.concepts)}")

            if lesson.explanation:
                words = lesson.explanation.split()
                current: list[str] = []
                for w in words:
                    if len(" ".join(current)) + len(w) > 60 and current:
                        lines.append("    " + " ".join(current))
                        current = [w]
                    else:
                        current.append(w)
                if current:
                    lines.append("    " + " ".join(current))

            if lesson.practice_sql:
                lines.append(f"  Try: {lesson.practice_sql}")

            if lesson.quizzes:
                for q in lesson.quizzes[:1]:
                    lines.append(f"  Quiz: {q.question}")

            lines.append("")

        return "\n".join(lines)


# ── Rule-to-category mapping ────────────────────────────────────────

_RULE_CATEGORY: dict[str, str] = {
    "SEQ_SCAN_LARGE_TABLE": "indexing",
    "SEQ_SCAN_NO_FILTER": "indexing",
    "EXCESSIVE_SEQ_SCANS": "indexing",
    "SORT_AVOIDABLE_WITH_INDEX": "indexing",
    "LIMIT_WITHOUT_INDEX": "indexing",
    "BACKWARD_INDEX_SCAN": "indexing",
    "INEFFICIENT_INDEX_SCAN": "indexing",
    "INDEX_ONLY_HEAP_FETCHES": "indexing",
    "FOREIGN_KEY_INDEX": "indexing",
    "GIN_INDEX_OPPORTUNITY": "indexing",
    "PARTIAL_INDEX_OPPORTUNITY": "indexing",
    "BAD_ROW_ESTIMATE": "statistics",
    "CARDINALITY_DRIFT": "statistics",
    "STALE_STATISTICS": "statistics",
    "SPILLING_TO_DISK": "config",
    "HASH_JOIN_BATCHES": "config",
    "WORK_MEM_TUNING": "config",
    "GATHER_WORKER_SHORTAGE": "config",
    "PARALLEL_QUERY_NOT_USED": "config",
    "PLANNING_TIME_EXCEEDED": "config",
    "NESTED_LOOP_LARGE_TABLE": "rewrite",
    "CTE_MATERIALIZATION": "rewrite",
    "CORRELATED_SUBQUERY": "rewrite",
    "NON_SARGABLE_FILTER": "rewrite",
    "IMPLICIT_CAST_FILTER": "rewrite",
    "SQL_REWRITE_OPPORTUNITIES": "rewrite",
    "TABLE_BLOAT": "maintenance",
    "LOSSY_BITMAP": "indexing",
    "BUFFER_ANALYSIS": "config",
    "TIME_SKEW": "config",
}


# ── Lesson templates ─────────────────────────────────────────────────

def _indexing_lesson(rule_ids: list[str], level: str) -> Lesson:
    if level == "beginner":
        return Lesson(
            title="Understanding Indexes",
            category="indexing",
            level="beginner",
            concepts=["B-tree index", "Index Scan vs Seq Scan", "CREATE INDEX CONCURRENTLY"],
            explanation=(
                "An index is like a book's table of contents. Without it, PostgreSQL "
                "must read every row (sequential scan). With an index, it jumps directly "
                "to the matching rows. For tables with >10,000 rows, indexes are essential "
                "for WHERE, JOIN, and ORDER BY columns."
            ),
            practice_sql=(
                "-- Check if your table has indexes:\n"
                "SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'your_table';\n\n"
                "-- Create an index (safe for production):\n"
                "CREATE INDEX CONCURRENTLY idx_orders_status ON orders(status);"
            ),
            finding_rule_ids=rule_ids,
            quizzes=[
                Quiz(
                    question="Why does PostgreSQL sometimes choose a Seq Scan even when an index exists?",
                    options=[
                        "The index is corrupt",
                        "The query returns most of the table, so Seq Scan is faster",
                        "PostgreSQL is buggy",
                        "The table is too small to index",
                    ],
                    correct_answer=1,
                    explanation=(
                        "When a query needs >10-20% of a table, the overhead of random "
                        "index lookups exceeds the cost of a sequential read. The planner "
                        "correctly chooses Seq Scan in this case."
                    ),
                ),
            ],
            further_reading=[
                "PostgreSQL docs: CREATE INDEX",
                "Use The Index, Luke! (use-the-index-luke.com)",
            ],
        )
    else:
        return Lesson(
            title="Advanced Index Strategies",
            category="indexing",
            level="intermediate",
            concepts=["Covering indexes (INCLUDE)", "Partial indexes", "Expression indexes", "GIN/GiST"],
            explanation=(
                "Beyond basic B-tree indexes, PostgreSQL supports: "
                "(1) Covering indexes that include extra columns to avoid table heap lookups, "
                "(2) Partial indexes that only index rows matching a WHERE condition, "
                "(3) Expression indexes on computed values like LOWER(email), "
                "(4) GIN indexes for JSONB, full-text search, and array operations."
            ),
            practice_sql=(
                "-- Covering index (Index-Only Scan):\n"
                "CREATE INDEX idx_orders_covering ON orders(status) INCLUDE (total, created_at);\n\n"
                "-- Partial index (only active orders):\n"
                "CREATE INDEX idx_orders_active ON orders(created_at) WHERE status = 'active';\n\n"
                "-- Expression index:\n"
                "CREATE INDEX idx_users_email_lower ON users(LOWER(email));"
            ),
            finding_rule_ids=rule_ids,
            quizzes=[
                Quiz(
                    question="When should you use a partial index?",
                    options=[
                        "When the table is very large",
                        "When queries consistently filter on a specific condition",
                        "When you want faster INSERTs",
                        "Always, for every index",
                    ],
                    correct_answer=1,
                    explanation=(
                        "Partial indexes are smaller and faster because they only index "
                        "rows matching the WHERE condition. Perfect for status='active' "
                        "queries when most rows are archived."
                    ),
                ),
            ],
        )


def _statistics_lesson(rule_ids: list[str], level: str) -> Lesson:
    return Lesson(
        title="Statistics & Row Estimation" if level == "beginner" else "Advanced Statistics Tuning",
        category="statistics",
        level=level,
        concepts=["ANALYZE", "pg_statistic", "row estimation", "default_statistics_target"],
        explanation=(
            "PostgreSQL decides HOW to execute a query based on statistics — estimated "
            "row counts, data distribution, and correlation. When these statistics are "
            "stale or inaccurate, the planner makes bad decisions: choosing Nested Loop "
            "when Hash Join would be better, or Seq Scan when Index Scan would be faster. "
            "ANALYZE refreshes these statistics."
        ),
        practice_sql=(
            "-- See current statistics for a table:\n"
            "SELECT attname, n_distinct, most_common_vals, correlation\n"
            "FROM pg_stats WHERE tablename = 'orders';\n\n"
            "-- Refresh statistics:\n"
            "ANALYZE orders;\n\n"
            "-- Increase statistics granularity for skewed columns:\n"
            "ALTER TABLE orders ALTER COLUMN status SET STATISTICS 1000;\n"
            "ANALYZE orders;"
        ),
        finding_rule_ids=rule_ids,
        quizzes=[
            Quiz(
                question="What happens when row estimates are 100x off?",
                options=[
                    "The query fails with an error",
                    "The planner picks the wrong execution strategy, making the query much slower",
                    "Nothing, PostgreSQL auto-corrects at runtime",
                    "The data becomes corrupt",
                ],
                correct_answer=1,
                explanation=(
                    "Bad row estimates are the #1 cause of slow queries. If the planner "
                    "thinks a table has 50 rows but it actually has 500,000, it might "
                    "choose Nested Loop (O(n*m)) instead of Hash Join (O(n+m))."
                ),
            ),
        ],
    )


def _config_lesson(rule_ids: list[str], level: str) -> Lesson:
    return Lesson(
        title="PostgreSQL Memory Configuration" if level == "beginner" else "Advanced Performance Tuning",
        category="config",
        level=level,
        concepts=["work_mem", "shared_buffers", "effective_cache_size", "random_page_cost"],
        explanation=(
            "PostgreSQL's default configuration is designed for a system with 128MB RAM. "
            "On modern servers, you need to tune: "
            "(1) shared_buffers: 25% of RAM for the buffer cache, "
            "(2) work_mem: memory per sort/hash operation (increase to avoid disk spill), "
            "(3) effective_cache_size: 75% of RAM (tells planner about OS cache), "
            "(4) random_page_cost: reduce to 1.1 for SSD storage."
        ),
        practice_sql=(
            "-- Check current settings:\n"
            "SHOW shared_buffers; SHOW work_mem; SHOW random_page_cost;\n\n"
            "-- Increase work_mem for current session only (safe):\n"
            "SET LOCAL work_mem = '128MB';\n"
            "-- Your query here\n"
            "RESET work_mem;\n\n"
            "-- Use QuerySense config audit:\n"
            "-- querysense audit config --dsn $DATABASE_URL"
        ),
        finding_rule_ids=rule_ids,
        quizzes=[
            Quiz(
                question="Why shouldn't you set work_mem to 4GB globally?",
                options=[
                    "PostgreSQL doesn't support values that large",
                    "Each query can allocate work_mem multiple times, risking OOM with many connections",
                    "It would make queries slower",
                    "work_mem only affects VACUUM",
                ],
                correct_answer=1,
                explanation=(
                    "A complex query might use 5-10 work_mem allocations (one per sort/hash). "
                    "With 100 connections, that's 100 * 10 * 4GB = 4TB of potential memory usage. "
                    "Set per-session with SET LOCAL instead."
                ),
            ),
        ],
    )


def _rewrite_lesson(rule_ids: list[str], level: str) -> Lesson:
    return Lesson(
        title="SQL Anti-patterns & Rewrites",
        category="rewrite",
        level=level,
        concepts=["NOT IN vs NOT EXISTS", "Correlated subqueries", "SARGable filters", "CTE materialization"],
        explanation=(
            "Many slow queries can be fixed by rewriting the SQL. Common anti-patterns: "
            "(1) NOT IN with NULLs — use NOT EXISTS instead, "
            "(2) Correlated subqueries that run once per row — use JOINs, "
            "(3) Non-SARGable filters like WHERE UPPER(name) = 'FOO' — use expression index, "
            "(4) CTEs that force materialization — use subqueries in PG12+."
        ),
        practice_sql=(
            "-- NOT IN -> NOT EXISTS:\n"
            "-- Slow: SELECT * FROM orders WHERE user_id NOT IN (SELECT id FROM inactive_users)\n"
            "-- Fast: SELECT * FROM orders WHERE NOT EXISTS (\n"
            "--   SELECT 1 FROM inactive_users WHERE inactive_users.id = orders.user_id\n"
            "-- )\n\n"
            "-- Use QuerySense rewriter:\n"
            "-- querysense rewrite 'SELECT * FROM orders WHERE user_id NOT IN (SELECT id FROM users)'"
        ),
        finding_rule_ids=rule_ids,
    )


def _maintenance_lesson(rule_ids: list[str], level: str) -> Lesson:
    return Lesson(
        title="Table Maintenance & Bloat",
        category="maintenance",
        level=level,
        concepts=["VACUUM", "autovacuum", "table bloat", "dead tuples", "FILLFACTOR"],
        explanation=(
            "PostgreSQL uses MVCC (Multi-Version Concurrency Control), which means "
            "UPDATE and DELETE leave dead tuples behind. VACUUM reclaims this space. "
            "If autovacuum can't keep up, tables bloat — wasting disk and slowing scans."
        ),
        practice_sql=(
            "-- Check bloat:\n"
            "SELECT relname, n_dead_tup, last_vacuum, last_autovacuum\n"
            "FROM pg_stat_user_tables ORDER BY n_dead_tup DESC;\n\n"
            "-- Manual vacuum:\n"
            "VACUUM (VERBOSE) orders;\n\n"
            "-- Use QuerySense health check:\n"
            "-- querysense health --dsn $DATABASE_URL"
        ),
        finding_rule_ids=rule_ids,
    )


# ── Generator ────────────────────────────────────────────────────────

def generate_learning_path(
    findings: list[Any],
    user_level: str = "beginner",
) -> LearningPath:
    """
    Generate a personalized learning path from analysis findings.

    Groups findings by category, then generates progressive lessons
    that teach the user how to fix their specific issues.

    Args:
        findings: List of Finding objects from analysis
        user_level: beginner / intermediate / advanced

    Returns:
        LearningPath with ordered lessons
    """
    # Group findings by category
    categories: dict[str, list[str]] = {}
    for f in findings:
        rule_id = getattr(f, "rule_id", str(f))
        category = _RULE_CATEGORY.get(rule_id, "other")
        categories.setdefault(category, []).append(rule_id)

    lessons: list[Lesson] = []

    # Generate lessons in priority order (most impactful first)
    lesson_generators = {
        "statistics": _statistics_lesson,
        "indexing": _indexing_lesson,
        "config": _config_lesson,
        "rewrite": _rewrite_lesson,
        "maintenance": _maintenance_lesson,
    }

    # Statistics first (most common root cause)
    for cat in ["statistics", "indexing", "config", "rewrite", "maintenance"]:
        if cat in categories:
            generator = lesson_generators.get(cat)
            if generator:
                lessons.append(generator(categories[cat], user_level))

    # Add level-appropriate lessons even if no findings in that category
    if user_level == "beginner" and "indexing" not in categories:
        lessons.append(_indexing_lesson([], user_level))

    estimated_time = len(lessons) * 10  # ~10 min per lesson

    return LearningPath(
        user_level=user_level,
        total_lessons=len(lessons),
        estimated_time_minutes=estimated_time,
        lessons=lessons,
    )
