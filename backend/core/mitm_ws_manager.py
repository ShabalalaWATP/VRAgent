"""WebSocket manager for MITM Workbench streaming."""
import asyncio
import json
from typing import Dict, Set, Any, Optional
from fastapi import WebSocket
from backend.core.logging import get_logger

logger = get_logger(__name__)


class MITMStreamManager:
    """Manages WebSocket connections for MITM traffic streaming."""

    def __init__(self) -> None:
        self._connections: Dict[str, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, websocket: WebSocket, proxy_id: str) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.setdefault(proxy_id, set()).add(websocket)
        logger.debug(f"MITM WebSocket connected for proxy {proxy_id}")

    async def disconnect(self, websocket: WebSocket, proxy_id: str) -> None:
        async with self._lock:
            if proxy_id in self._connections:
                self._connections[proxy_id].discard(websocket)
                if not self._connections[proxy_id]:
                    del self._connections[proxy_id]
        logger.debug(f"MITM WebSocket disconnected for proxy {proxy_id}")

    async def broadcast(self, proxy_id: str, message: Dict[str, Any]) -> None:
        """Broadcast message to all connections for a specific proxy."""
        message_json = json.dumps(message, default=str)
        async with self._lock:
            connections = list(self._connections.get(proxy_id, set()))

        dead = []
        for websocket in connections:
            try:
                await websocket.send_text(message_json)
            except Exception:
                dead.append(websocket)

        # Only clean dead connections from THIS proxy, not all proxies
        if dead:
            async with self._lock:
                if proxy_id in self._connections:
                    for ws in dead:
                        self._connections[proxy_id].discard(ws)
                    # Clean up empty proxy entry
                    if not self._connections[proxy_id]:
                        del self._connections[proxy_id]

    def emit(self, proxy_id: str, message: Dict[str, Any]) -> None:
        """Thread-safe broadcast from non-async contexts."""
        if not self._loop or self._loop.is_closed():
            return
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(proxy_id, message), self._loop)
        except Exception as exc:
            logger.debug(f"MITM WebSocket emit failed: {exc}")


mitm_stream_manager = MITMStreamManager()
