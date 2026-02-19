"""
Redis caching layer for QuerySense Cloud.

Provides:
- Analysis result caching (avoid re-analyzing the same plan)
- Task status tracking (for async analysis via workers)
- Pub/sub event bus (for WebSocket real-time updates)

Falls back gracefully to in-memory dict when Redis is unavailable
(local dev, offline, or when redis extra is not installed).
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Singleton connection
_redis: Any | None = None
_fallback: dict[str, str] = {}  # In-memory fallback when Redis unavailable
_use_fallback = False


async def init_redis(url: str = "redis://localhost:6379/0") -> None:
    """
    Initialize Redis connection pool.

    Falls back to in-memory dict if Redis is not available.
    """
    global _redis, _use_fallback

    try:
        import redis.asyncio as aioredis

        _redis = aioredis.from_url(url, decode_responses=True)
        await _redis.ping()
        logger.info("Redis connected: %s", url.split("@")[-1])
        _use_fallback = False
    except Exception as e:
        logger.warning("Redis unavailable, using in-memory fallback: %s", e)
        _redis = None
        _use_fallback = True


async def close_redis() -> None:
    """Close Redis connection pool."""
    global _redis
    if _redis is not None:
        await _redis.close()
        _redis = None


# ── Key-Value Cache ─────────────────────────────────────────────────────


async def cache_get(key: str) -> str | None:
    """Get a cached value by key."""
    if _use_fallback:
        return _fallback.get(key)
    if _redis is None:
        return None
    try:
        return await _redis.get(key)
    except Exception:
        return _fallback.get(key)


async def cache_set(key: str, value: str, ttl_seconds: int = 3600) -> None:
    """Set a cached value with TTL."""
    if _use_fallback:
        _fallback[key] = value
        return
    if _redis is None:
        return
    try:
        await _redis.setex(key, ttl_seconds, value)
    except Exception:
        _fallback[key] = value


async def cache_delete(key: str) -> None:
    """Delete a cached value."""
    _fallback.pop(key, None)
    if _redis is not None:
        try:
            await _redis.delete(key)
        except Exception:
            pass


# ── Analysis-Specific Cache ─────────────────────────────────────────────


async def cache_analysis(plan_hash: str, result_json: str, ttl: int = 3600) -> None:
    """Cache an analysis result by plan hash."""
    await cache_set(f"analysis:{plan_hash}", result_json, ttl)


async def get_cached_analysis(plan_hash: str) -> str | None:
    """Get cached analysis result by plan hash."""
    return await cache_get(f"analysis:{plan_hash}")


# ── Task Status Tracking ────────────────────────────────────────────────


async def set_task_status(
    task_id: str,
    status: str,
    result: dict[str, Any] | None = None,
    ttl: int = 600,
) -> None:
    """Track async task status for polling and WebSocket delivery."""
    payload = {"status": status}
    if result is not None:
        payload["result"] = result
    await cache_set(f"task:{task_id}", json.dumps(payload), ttl)


async def get_task_status(task_id: str) -> dict[str, Any] | None:
    """Get async task status."""
    raw = await cache_get(f"task:{task_id}")
    if raw is None:
        return None
    return json.loads(raw)


# ── Pub/Sub Event Bus ───────────────────────────────────────────────────


async def publish_event(channel: str, event: dict[str, Any]) -> None:
    """Publish an event to a Redis channel (for WebSocket fanout)."""
    if _redis is None:
        return  # Silently skip if Redis unavailable
    try:
        await _redis.publish(channel, json.dumps(event))
    except Exception as e:
        logger.debug("Failed to publish event to %s: %s", channel, e)


async def subscribe(channel: str):
    """
    Subscribe to a Redis channel. Returns an async generator of events.

    Usage:
        async for event in subscribe("workspace:abc123"):
            await websocket.send_json(event)
    """
    if _redis is None:
        return

    try:
        pubsub = _redis.pubsub()
        await pubsub.subscribe(channel)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield json.loads(message["data"])
        finally:
            await pubsub.unsubscribe(channel)
    except Exception as e:
        logger.debug("Subscription error on %s: %s", channel, e)
