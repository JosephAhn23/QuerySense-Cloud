"""
QuerySense Cloud — SaaS layer for deterministic query plan analysis.

Run with:
    python -m querysense.cloud
    uvicorn querysense.cloud.app:create_app --factory
"""

from querysense.cloud.app import create_app

__all__ = ["create_app"]
