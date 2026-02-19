"""
Main API router — aggregates all /api/v1 sub-routers.

API-first architecture: every feature available programmatically.
This is what pgMustard (no API) and EverSQL (no offline API) can't do.
"""

from __future__ import annotations

from fastapi import APIRouter

from querysense.cloud.api.activities import router as activities_router
from querysense.cloud.api.analyze import router as analyze_router
from querysense.cloud.api.comments import router as comments_router
from querysense.cloud.api.compare import router as compare_router
from querysense.cloud.api.keys import router as keys_router
from querysense.cloud.api.metrics import router as metrics_router
from querysense.cloud.api.migrate_check import router as migrate_check_router
from querysense.cloud.api.plans import router as plans_router
from querysense.cloud.api.rewrite import router as rewrite_router
from querysense.cloud.api.rollback import router as rollback_router
from querysense.cloud.api.share import router as share_router
from querysense.cloud.api.trends import router as trends_router
from querysense.cloud.api.websocket import router as websocket_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(analyze_router, tags=["analyze"])
api_router.include_router(compare_router, tags=["compare"])
api_router.include_router(rewrite_router, tags=["rewrite"])
api_router.include_router(rollback_router, tags=["rollback"])
api_router.include_router(migrate_check_router, tags=["migrations"])
api_router.include_router(metrics_router, tags=["metrics"])
api_router.include_router(plans_router, tags=["plans"])
api_router.include_router(share_router, tags=["share"])
api_router.include_router(keys_router, tags=["keys"])
api_router.include_router(comments_router, tags=["collaboration"])
api_router.include_router(activities_router, tags=["collaboration"])
api_router.include_router(trends_router, tags=["trends"])
api_router.include_router(websocket_router, tags=["websocket"])