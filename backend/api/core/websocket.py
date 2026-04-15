import json
from typing import Dict, Set
from fastapi import WebSocket
import logging
import redis.asyncio as aioredis
import os

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")


class ConnectionManager:
    """Manages WebSocket connections per scan."""

    def __init__(self):
        self.active: Dict[str, Set[WebSocket]] = {}

    async def connect(self, scan_id: str,
                      ws: WebSocket):
        await ws.accept()
        if scan_id not in self.active:
            self.active[scan_id] = set()
        self.active[scan_id].add(ws)
        logger.info(f"WS connected: scan={scan_id}")

    def disconnect(self, scan_id: str, ws: WebSocket):
        if scan_id in self.active:
            self.active[scan_id].discard(ws)
            if not self.active[scan_id]:
                del self.active[scan_id]
        logger.info(f"WS disconnected: scan={scan_id}")

    async def broadcast(self, scan_id: str,
                        data: dict):
        if scan_id not in self.active:
            return
        dead = set()
        for ws in self.active[scan_id]:
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active[scan_id].discard(ws)


ws_manager = ConnectionManager()


async def push_scan_event(scan_id: str, event: dict):
    """
    Push event to all connected WebSocket clients.
    Also stores in Redis for clients that reconnect.
    """
    await ws_manager.broadcast(scan_id, event)

    try:
        r = aioredis.from_url(REDIS_URL)
        key = f"ws:events:{scan_id}"
        await r.lpush(key, json.dumps(event))
        await r.expire(key, 86400)
        await r.aclose()
    except Exception as e:
        logger.warning(f"Redis push failed: {e}")


def push_scan_event_sync(scan_id: str, event: dict):
    """Sync version for use inside Celery tasks."""
    import redis as sync_redis
    try:
        r = sync_redis.from_url(REDIS_URL)
        key = f"ws:events:{scan_id}"
        r.lpush(key, json.dumps(event))
        r.expire(key, 86400)
        r.close()
    except Exception as e:
        logger.warning(f"Redis sync push failed: {e}")


def ws_emit(scan_id: str, message: str,
            pct: int = None, tool: str = None,
            event_type: str = "progress",
            target_url: str = None,
            result: str = None):
    """
    Called from Celery tasks to emit progress events.
    Stores in Redis - WebSocket handler reads and forwards.
    """
    event = {
        "type": event_type,
        "message": message,
        "progress_pct": pct,
        "tool": tool,
        "target_url": target_url,
        "result": result,
    }
    push_scan_event_sync(scan_id, event)
