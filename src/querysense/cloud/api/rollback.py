"""
Rollback API endpoint: generate intelligent rollback SQL via REST.

    POST /api/v1/rollback
    {
        "migration_sql": "ALTER TABLE orders ADD COLUMN status TEXT NOT NULL;"
    }

Returns dependency-aware rollback plan with phased SQL.
What Liquibase Pro charges for, we give away via API.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


class RollbackRequest(BaseModel):
    """Request body for rollback generation."""

    migration_sql: str = Field(
        ...,
        description="SQL migration to generate rollback for",
        examples=["ALTER TABLE orders ADD COLUMN status TEXT NOT NULL;"],
    )


class DependentObjectResponse(BaseModel):
    """A dependent object in the rollback plan."""

    type: str
    name: str
    depends_on: str


class RollbackResponse(BaseModel):
    """Response with the rollback plan."""

    is_safe: bool = Field(description="Whether all operations are safely reversible")
    rollback_sql: str = Field(description="Full rollback SQL with dependency preservation")
    rollback_statements: list[str] = Field(description="Individual rollback statements")
    pre_rollback: list[str] = Field(description="Statements to drop dependent objects")
    post_rollback: list[str] = Field(description="Statements to restore dependent objects")
    warnings: list[str] = Field(description="Warnings about the rollback")
    dependent_objects: list[DependentObjectResponse] = Field(
        default_factory=list,
        description="Objects that depend on modified tables",
    )
    irreversible_count: int = Field(description="Number of irreversible operations")


@router.post("/rollback", response_model=RollbackResponse)
async def generate_rollback(request: RollbackRequest) -> RollbackResponse:
    """
    Generate intelligent rollback SQL for a migration.

    Unlike Liquibase Pro and Flyway Teams, this:
    - Tracks view, function, and trigger dependencies
    - Generates phased rollback (drop deps → undo → restore deps)
    - Warns about irreversible operations with clear instructions
    - Is completely free and available via API

    **Example:**
    ```bash
    curl -X POST http://localhost:8000/api/v1/rollback \\
      -H 'Content-Type: application/json' \\
      -d '{"migration_sql": "ALTER TABLE orders ADD COLUMN status TEXT;"}'
    ```
    """
    from querysense.rollback import generate_smart_rollback

    plan = generate_smart_rollback(request.migration_sql)

    return RollbackResponse(
        is_safe=plan.is_safe,
        rollback_sql=plan.rollback_sql,
        rollback_statements=plan.rollback_statements,
        pre_rollback=plan.pre_rollback,
        post_rollback=plan.post_rollback,
        warnings=plan.warnings,
        dependent_objects=[
            DependentObjectResponse(
                type=d.object_type,
                name=f"{d.schema}.{d.name}",
                depends_on=d.depends_on_table,
            )
            for d in plan.dependent_objects
        ],
        irreversible_count=len(plan.irreversible_statements),
    )
