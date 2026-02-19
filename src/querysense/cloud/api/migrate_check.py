"""
Migration safety check API endpoint.

    POST /api/v1/migrate-check
    {
        "sql": "ALTER TABLE orders ADD COLUMN status TEXT NOT NULL;"
    }

Returns risk analysis and optional rollback SQL.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


class MigrateCheckRequest(BaseModel):
    """Request body for migration safety check."""

    sql: str = Field(
        ...,
        description="SQL migration to check for safety risks",
        examples=["ALTER TABLE orders ADD COLUMN status TEXT NOT NULL;"],
    )
    generate_rollback: bool = Field(
        default=False,
        description="Whether to include rollback SQL in the response",
    )


class RiskItem(BaseModel):
    """A single risk identified in a migration."""

    severity: str
    rule: str
    message: str
    suggestion: str = ""


class MigrateCheckResponse(BaseModel):
    """Response with migration safety analysis."""

    safe: bool = Field(description="Whether the migration has no critical risks")
    summary: str = Field(description="Human-readable summary")
    statements_count: int
    risks: list[RiskItem]
    rollback_sql: str | None = Field(
        default=None,
        description="Rollback SQL if generate_rollback was true",
    )


@router.post("/migrate-check", response_model=MigrateCheckResponse)
async def check_migration(request: MigrateCheckRequest) -> MigrateCheckResponse:
    """
    Check migration SQL for safety risks.

    Analyzes DDL statements for:
    - Exclusive locks (ADD COLUMN NOT NULL without DEFAULT)
    - Missing CONCURRENTLY on index creation
    - Irreversible operations (DROP TABLE/COLUMN)
    - Type changes that require table rewrites
    - Missing lock_timeout settings
    - Foreign key validation overhead

    **Example:**
    ```bash
    curl -X POST http://localhost:8000/api/v1/migrate-check \\
      -H 'Content-Type: application/json' \\
      -d '{"sql": "CREATE INDEX idx_orders_status ON orders(status);", "generate_rollback": true}'
    ```
    """
    from querysense.migration_safety import check_and_report, generate_rollback

    report = check_and_report(request.sql)

    rollback = None
    if request.generate_rollback:
        rollback = generate_rollback(request.sql)

    return MigrateCheckResponse(
        safe=report.safe,
        summary=report.summary(),
        statements_count=len(report.statements),
        risks=[
            RiskItem(
                severity=r.severity,
                rule=r.rule,
                message=r.message,
                suggestion=r.suggestion,
            )
            for r in report.risks
        ],
        rollback_sql=rollback,
    )
