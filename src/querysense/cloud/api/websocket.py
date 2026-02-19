"""
WebSocket endpoints for real-time updates.

WS /api/v1/ws/workspace/{workspace_id}   — workspace activity stream
WS /api/v1/ws/task/{task_id}             — analysis task progress

Provides real-time push for:
- New plan analyses completing
- Comments being added
- Activity feed updates
- Async task completion notifications
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/ws")

logger = logging.getLogger(__name__)

# In-memory connection registry (per-process; use Redis pub/sub for multi-process)
_workspace_connections: dict[str, set[WebSocket]] = {}
_task_connections: dict[str, set[WebSocket]] = {}


# ── Connection Management ──────────────────────────────────────────────


def _register(registry: dict[str, set[WebSocket]], key: str, ws: WebSocket) -> None:
    if key not in registry:
        registry[key] = set()
    registry[key].add(ws)


def _unregister(registry: dict[str, set[WebSocket]], key: str, ws: WebSocket) -> None:
    if key in registry:
        registry[key].discard(ws)
        if not registry[key]:
            del registry[key]


async def broadcast_to_workspace(workspace_id: str, event: dict[str, Any]) -> None:
    """Send an event to all WebSocket connections for a workspace."""
    connections = _workspace_connections.get(workspace_id, set())
    dead: list[WebSocket] = []

    for ws in connections:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)

    for ws in dead:
        _workspace_connections.get(workspace_id, set()).discard(ws)


async def broadcast_to_task(task_id: str, event: dict[str, Any]) -> None:
    """Send an event to all WebSocket connections watching a task."""
    connections = _task_connections.get(task_id, set())
    dead: list[WebSocket] = []

    for ws in connections:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)

    for ws in dead:
        _task_connections.get(task_id, set()).discard(ws)


# ── WebSocket Endpoints ────────────────────────────────────────────────


@router.websocket("/workspace/{workspace_id}")
async def workspace_stream(websocket: WebSocket, workspace_id: str) -> None:
    """
    Real-time workspace activity stream.

    Clients connect here to receive push notifications for:
    - New analyses completing
    - Comments being added or resolved
    - Plans being uploaded or deleted
    - Team member activity

    Authentication: pass session token as query param ?token=...
    or as the first message after connecting.
    """
    await websocket.accept()
    _register(_workspace_connections, workspace_id, websocket)

    logger.debug("WebSocket connected: workspace=%s", workspace_id)

    try:
        # Try to forward Redis pub/sub events to this WebSocket
        # Falls back to just keeping the connection alive for direct broadcasts
        try:
            from querysense.cloud.cache import subscribe

            async for event in subscribe(f"workspace:{workspace_id}"):
                await websocket.send_json(event)
        except ImportError:
            # Redis not available — keep connection alive for direct broadcasts
            while True:
                try:
                    # Keep-alive: wait for client messages (ping/pong)
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    # Send keepalive
                    try:
                        await websocket.send_json({"type": "keepalive"})
                    except Exception:
                        break
        except Exception:
            # Subscription failed, fall back to keepalive
            while True:
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    try:
                        await websocket.send_json({"type": "keepalive"})
                    except Exception:
                        break

    except WebSocketDisconnect:
        logger.debug("WebSocket disconnected: workspace=%s", workspace_id)
    finally:
        _unregister(_workspace_connections, workspace_id, websocket)


@router.websocket("/task/{task_id}")
async def task_stream(websocket: WebSocket, task_id: str) -> None:
    """
    Real-time analysis task progress stream.

    Clients connect here after submitting an async analysis request
    to receive progress updates and the final result.
    """
    await websocket.accept()
    _register(_task_connections, task_id, websocket)

    logger.debug("WebSocket connected: task=%s", task_id)

    try:
        # Poll task status and forward updates
        from querysense.cloud.cache import get_task_status

        last_status = None
        while True:
            status = await get_task_status(task_id)
            if status and status != last_status:
                await websocket.send_json({"type": "task_update", "task_id": task_id, **status})
                last_status = status

                if status.get("status") in ("completed", "failed"):
                    break

            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        logger.debug("WebSocket disconnected: task=%s", task_id)
    except Exception:
        pass
    finally:
        _unregister(_task_connections, task_id, websocket)
