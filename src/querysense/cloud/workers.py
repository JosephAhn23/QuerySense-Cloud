"""
Async analysis workers for QuerySense Cloud.

Uses background tasks by default (single-process), with optional
Celery/Redis for horizontal scaling in production.

Architecture:
    1. API endpoint receives plan → enqueues task → returns task_id
    2. Worker picks up task → runs analysis → stores result + publishes event
    3. Client polls task status OR receives WebSocket push

This module provides the worker functions that can run either:
- Inline via FastAPI BackgroundTasks (dev/small deploys)
- Via Celery tasks (production horizontal scaling)
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)


def hash_plan(plan_json: str) -> str:
    """Compute a stable hash of a plan for caching."""
    return hashlib.sha256(plan_json.encode("utf-8")).hexdigest()[:32]


async def run_analysis_task(
    task_id: str,
    plan_json: str,
    sql_text: str | None = None,
    workspace_id: str | None = None,
    user_id: str | None = None,
) -> dict[str, Any]:
    """
    Run analysis as an async task. Can be called from BackgroundTasks or Celery.

    Steps:
        1. Update task status → "processing"
        2. Check cache for existing result
        3. Run analysis
        4. Cache result
        5. Store metrics
        6. Update task status → "completed"
        7. Broadcast completion via pub/sub
    """
    from querysense.cloud.cache import (
        cache_analysis,
        get_cached_analysis,
        publish_event,
        set_task_status,
    )
    from querysense.cloud.services import analyze_plan_to_dict

    await set_task_status(task_id, "processing")

    try:
        # Check cache
        plan_hash = hash_plan(plan_json)
        cached = await get_cached_analysis(plan_hash)
        if cached is not None:
            result = json.loads(cached)
            await set_task_status(task_id, "completed", result=result)
            return result

        # Run analysis (CPU-bound, runs in thread pool for async compat)
        import asyncio

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: analyze_plan_to_dict(plan_json, sql_text),
        )

        # Cache result
        await cache_analysis(plan_hash, json.dumps(result), ttl=3600)

        # Update status
        await set_task_status(task_id, "completed", result=result)

        # Broadcast to workspace WebSocket channel
        if workspace_id:
            await publish_event(
                f"workspace:{workspace_id}",
                {
                    "type": "analysis_completed",
                    "task_id": task_id,
                    "plan_hash": plan_hash,
                    "user_id": user_id,
                    "findings_count": result.get("summary", {}).get("total", 0),
                },
            )

        return result

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.error("Analysis task %s failed: %s", task_id, error_msg)
        await set_task_status(task_id, "failed", result={"error": error_msg})
        return {"error": error_msg}


def create_task_id() -> str:
    """Generate a unique task ID."""
    return uuid.uuid4().hex[:16]
