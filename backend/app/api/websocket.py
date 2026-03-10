"""
WebSocket endpoint for real-time scan updates.

Uses Redis pub/sub as the bridge between Celery workers and API process.
"""
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import get_settings

router = APIRouter()
settings = get_settings()


async def _redis_subscriber(websocket: WebSocket, scan_id: str):
    """Subscribe to Redis channel and forward messages to WebSocket."""
    import redis.asyncio as aioredis

    redis_url = settings.redis_url
    r = aioredis.from_url(redis_url, decode_responses=True)
    pubsub = r.pubsub()
    channel = f"scan:{scan_id}"
    await pubsub.subscribe(channel)

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                await websocket.send_text(message["data"])
    except Exception:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await r.aclose()


@router.websocket("/scans/{scan_id}/live")
async def scan_live(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    # Start Redis subscriber in background
    task = asyncio.create_task(_redis_subscriber(websocket, scan_id))

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        task.cancel()


async def publish_scan_event(scan_id: str, event: dict):
    """Publish a scan event to Redis (called from Celery worker or API)."""
    import redis.asyncio as aioredis

    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        channel = f"scan:{scan_id}"
        await r.publish(channel, json.dumps(event, default=str))
        await r.aclose()
    except Exception:
        pass
