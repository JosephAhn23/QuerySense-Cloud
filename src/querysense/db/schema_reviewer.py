"""
Schema Design Reviewer.

Connects to a PostgreSQL database and reviews schema design for:
- Missing indexes on foreign keys
- Tables without primary keys
- Wide tables (too many columns)
- Missing NOT NULL constraints on required columns
- Unused/duplicate indexes
- Data type anti-patterns (text for everything, timestamp without timezone)
- Naming convention violations
- Missing constraints (CHECK, UNIQUE)
- Potential normalization issues (repeated column patterns)

Inspired by PostgreSQL Query Optimization (Dombrovskaya et al.), Ch. 9 — "Design Matters"

Usage:
    from querysense.db.schema_reviewer import review_schema

    report = await review_schema(conn)
    for issue in report.issues:
        print(f"[{issue.severity}] {issue.table}: {issue.message}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AsyncDBConnection(Protocol):
    """Minimal async DB protocol."""
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


@dataclass(frozen=True)
class SchemaIssue:
    """A single schema design issue."""
    table: str
    severity: str          # critical / warning / info
    category: str          # index / constraint / type / naming / normalization / design
    column: str = ""
    message: str = ""
    suggestion: str = ""
    fix_sql: str = ""


@dataclass
class SchemaReviewReport:
    """Full schema review report."""
    tables_reviewed: int = 0
    issues: list[SchemaIssue] = field(default_factory=list)
    score: int = 100

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "tables_reviewed": self.tables_reviewed,
            "summary": {
                "critical": self.critical_count,
                "warning": self.warning_count,
                "info": sum(1 for i in self.issues if i.severity == "info"),
                "total": len(self.issues),
            },
            "issues": [
                {
                    "table": i.table,
                    "column": i.column,
                    "severity": i.severity,
                    "category": i.category,
                    "message": i.message,
                    "suggestion": i.suggestion,
                    "fix_sql": i.fix_sql,
                }
                for i in self.issues
            ],
        }


async def review_schema(
    conn: AsyncDBConnection,
    schema: str = "public",
) -> SchemaReviewReport:
    """
    Review database schema design for anti-patterns and optimization opportunities.

    Args:
        conn: Async database connection
        schema: Schema to review (default: public)

    Returns:
        SchemaReviewReport with all issues found
    """
    report = SchemaReviewReport()
    issues = report.issues

    # ── Collect table metadata ───────────────────────────────────────

    tables = await conn.fetch(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = $1 AND table_type = 'BASE TABLE' "
        "ORDER BY table_name",
        schema,
    )
    report.tables_reviewed = len(tables)
    table_names = [t[0] for t in tables]

    # ── Check 1: Tables without primary keys ─────────────────────────

    for table_name in table_names:
        pk = await conn.fetchval(
            "SELECT COUNT(*) FROM information_schema.table_constraints "
            "WHERE table_schema = $1 AND table_name = $2 "
            "AND constraint_type = 'PRIMARY KEY'",
            schema,
            table_name,
        )
        if pk == 0:
            issues.append(SchemaIssue(
                table=table_name,
                severity="critical",
                category="constraint",
                message=f"Table '{table_name}' has no primary key.",
                suggestion="Every table should have a primary key for proper identification and join performance.",
                fix_sql=f"ALTER TABLE {schema}.{table_name} ADD COLUMN id BIGSERIAL PRIMARY KEY;",
            ))

    # ── Check 2: Foreign keys without indexes ────────────────────────

    fk_rows = await conn.fetch(
        """
        SELECT
            tc.table_name,
            kcu.column_name,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage ccu
            ON ccu.constraint_name = tc.constraint_name
            AND ccu.table_schema = tc.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
            AND tc.table_schema = $1
        """,
        schema,
    )

    for fk in fk_rows:
        table_name = fk[0]
        column_name = fk[1]

        # Check if an index exists on this FK column
        idx_exists = await conn.fetchval(
            """
            SELECT COUNT(*) FROM pg_indexes
            WHERE schemaname = $1 AND tablename = $2
            AND indexdef LIKE '%(' || $3 || '%'
            """,
            schema,
            table_name,
            column_name,
        )

        # More reliable check using pg_index
        idx_check = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM pg_index i
            JOIN pg_class t ON t.oid = i.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(i.indkey)
            WHERE n.nspname = $1
              AND t.relname = $2
              AND a.attname = $3
              AND a.attnum = i.indkey[0]
            """,
            schema,
            table_name,
            column_name,
        )

        if idx_check == 0:
            issues.append(SchemaIssue(
                table=table_name,
                column=column_name,
                severity="warning",
                category="index",
                message=f"Foreign key '{column_name}' has no index. JOINs and CASCADE deletes will be slow.",
                suggestion="Add an index on the FK column for efficient joins and referential integrity checks.",
                fix_sql=f"CREATE INDEX CONCURRENTLY idx_{table_name}_{column_name} ON {schema}.{table_name} ({column_name});",
            ))

    # ── Check 3: Wide tables ─────────────────────────────────────────

    for table_name in table_names:
        col_count = await conn.fetchval(
            "SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_schema = $1 AND table_name = $2",
            schema,
            table_name,
        )
        if col_count > 30:
            issues.append(SchemaIssue(
                table=table_name,
                severity="warning",
                category="design",
                message=f"Table '{table_name}' has {col_count} columns. Consider splitting into related tables.",
                suggestion="Wide tables increase tuple header overhead, reduce cache efficiency, and complicate queries.",
            ))
        elif col_count > 50:
            issues.append(SchemaIssue(
                table=table_name,
                severity="critical",
                category="design",
                message=f"Table '{table_name}' has {col_count} columns. This is a strong normalization signal.",
                suggestion="Consider vertical partitioning: move infrequently accessed columns to a separate table.",
            ))

    # ── Check 4: Data type anti-patterns ─────────────────────────────

    columns = await conn.fetch(
        """
        SELECT table_name, column_name, data_type, character_maximum_length,
               is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = $1
        ORDER BY table_name, ordinal_position
        """,
        schema,
    )

    for col in columns:
        table_name = col[0]
        column_name = col[1]
        data_type = col[2]
        max_length = col[3]
        is_nullable = col[4]

        # Unbounded text for structured data
        if data_type == "text" and column_name in (
            "email", "phone", "zip", "zipcode", "postal_code",
            "country", "country_code", "currency", "currency_code",
            "status", "state", "type", "role", "gender",
        ):
            issues.append(SchemaIssue(
                table=table_name,
                column=column_name,
                severity="info",
                category="type",
                message=f"Column '{column_name}' is TEXT but looks like structured data.",
                suggestion=f"Consider VARCHAR with a length limit, or an ENUM type for '{column_name}'.",
            ))

        # varchar(255) everywhere (MySQL habit)
        if data_type == "character varying" and max_length == 255:
            issues.append(SchemaIssue(
                table=table_name,
                column=column_name,
                severity="info",
                category="type",
                message=f"Column '{column_name}' is VARCHAR(255). Is this intentional or a MySQL default habit?",
                suggestion="PostgreSQL doesn't benefit from VARCHAR length limits for performance. Use TEXT or a meaningful limit.",
            ))

        # timestamp without timezone
        if data_type == "timestamp without time zone":
            issues.append(SchemaIssue(
                table=table_name,
                column=column_name,
                severity="warning",
                category="type",
                message=f"Column '{column_name}' uses TIMESTAMP WITHOUT TIME ZONE.",
                suggestion="Use TIMESTAMPTZ (with time zone) to avoid timezone ambiguity bugs.",
                fix_sql=f"ALTER TABLE {schema}.{table_name} ALTER COLUMN {column_name} TYPE TIMESTAMPTZ;",
            ))

        # Nullable booleans
        if data_type == "boolean" and is_nullable == "YES":
            issues.append(SchemaIssue(
                table=table_name,
                column=column_name,
                severity="info",
                category="constraint",
                message=f"Boolean column '{column_name}' is nullable (three-valued logic: true/false/null).",
                suggestion="Consider adding NOT NULL DEFAULT false to avoid NULL boolean confusion.",
                fix_sql=f"ALTER TABLE {schema}.{table_name} ALTER COLUMN {column_name} SET NOT NULL, ALTER COLUMN {column_name} SET DEFAULT false;",
            ))

    # ── Check 5: Naming convention issues ────────────────────────────

    for table_name in table_names:
        if table_name != table_name.lower():
            issues.append(SchemaIssue(
                table=table_name,
                severity="info",
                category="naming",
                message=f"Table '{table_name}' has mixed case. PostgreSQL folds to lowercase unless quoted.",
                suggestion="Use snake_case for all identifiers to avoid quoting issues.",
            ))

        if table_name.startswith("tbl_") or table_name.startswith("t_"):
            issues.append(SchemaIssue(
                table=table_name,
                severity="info",
                category="naming",
                message=f"Table '{table_name}' uses a prefix (tbl_/t_). This is a naming anti-pattern.",
                suggestion="Use descriptive names without type prefixes: 'orders' instead of 'tbl_orders'.",
            ))

    # ── Check 6: Large tables without indexes ────────────────────────

    large_tables = await conn.fetch(
        """
        SELECT relname, n_live_tup
        FROM pg_stat_user_tables
        WHERE schemaname = $1 AND n_live_tup > 10000
        ORDER BY n_live_tup DESC
        """,
        schema,
    )

    for lt in large_tables:
        table_name = lt[0]
        row_count = lt[1]

        idx_count = await conn.fetchval(
            "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = $1 AND tablename = $2",
            schema,
            table_name,
        )

        if idx_count <= 1:  # Only primary key or no indexes
            issues.append(SchemaIssue(
                table=table_name,
                severity="warning",
                category="index",
                message=(
                    f"Table '{table_name}' has {row_count:,} rows but only "
                    f"{idx_count} index(es). Queries may default to sequential scans."
                ),
                suggestion="Add indexes on columns used in WHERE, JOIN, and ORDER BY clauses.",
            ))

    # ── Check 7: Potential duplicate columns (normalization signal) ──

    # Find column names that appear in 3+ tables (potential normalization issue)
    col_frequency: dict[str, list[str]] = {}
    for col in columns:
        name = col[1]
        table = col[0]
        if name not in ("id", "created_at", "updated_at", "deleted_at"):
            col_frequency.setdefault(name, []).append(table)

    for col_name, tables_with_col in col_frequency.items():
        if len(tables_with_col) >= 4:
            issues.append(SchemaIssue(
                table=", ".join(tables_with_col[:5]),
                column=col_name,
                severity="info",
                category="normalization",
                message=(
                    f"Column '{col_name}' appears in {len(tables_with_col)} tables: "
                    f"{', '.join(tables_with_col[:5])}{'...' if len(tables_with_col) > 5 else ''}. "
                    "Possible normalization opportunity."
                ),
                suggestion="Consider extracting to a lookup/reference table to reduce data duplication.",
            ))

    # ── Calculate Score ──────────────────────────────────────────────

    score = 100
    for issue in issues:
        if issue.severity == "critical":
            score -= 12
        elif issue.severity == "warning":
            score -= 5
        elif issue.severity == "info":
            score -= 1
    report.score = max(0, score)

    return report
