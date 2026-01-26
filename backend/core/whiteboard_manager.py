"""
Whiteboard WebSocket manager for real-time collaboration.
Handles live cursors, element updates, and presence broadcasting.
"""
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from fastapi import WebSocket, WebSocketDisconnect
from jose import jwt, JWTError

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Stale connection timeout (no activity for 5 minutes)
STALE_CONNECTION_TIMEOUT = timedelta(minutes=5)

# Rate limiting for whiteboard operations (excluding cursor moves)
WHITEBOARD_RATE_LIMIT = 60  # Operations per minute
WHITEBOARD_RATE_WINDOW = 60  # Window in seconds


@dataclass
class UserConnection:
    """Represents a user's WebSocket connection to a whiteboard."""
    websocket: WebSocket
    user_id: int
    username: str
    cursor_x: float = 0
    cursor_y: float = 0
    viewport_x: float = 0
    viewport_y: float = 0
    viewport_zoom: float = 1.0
    selected_element_id: Optional[str] = None
    color: str = "#3b82f6"  # User's cursor color
    last_activity: datetime = field(default_factory=datetime.utcnow)
    operation_timestamps: List[float] = field(default_factory=list)  # Rate limiting
    
    def is_stale(self) -> bool:
        """Check if connection is stale (no activity for too long)."""
        return datetime.utcnow() - self.last_activity > STALE_CONNECTION_TIMEOUT
    
    def check_rate_limit(self) -> bool:
        """Check if user is within rate limit. Returns True if allowed."""
        import time
        now = time.time()
        # Clean old entries outside the window
        self.operation_timestamps = [
            t for t in self.operation_timestamps 
            if now - t < WHITEBOARD_RATE_WINDOW
        ]
        
        if len(self.operation_timestamps) >= WHITEBOARD_RATE_LIMIT:
            return False
        
        self.operation_timestamps.append(now)
        return True


class WhiteboardConnectionManager:
    """
    Manages WebSocket connections for whiteboard collaboration.
    Handles real-time cursor positions, element updates, and presence.
    Thread-safe with asyncio locks.
    """
    
    # Color palette for user cursors
    CURSOR_COLORS = [
        "#3b82f6",  # Blue
        "#10b981",  # Green
        "#f59e0b",  # Amber
        "#ef4444",  # Red
        "#8b5cf6",  # Purple
        "#ec4899",  # Pink
        "#06b6d4",  # Cyan
        "#f97316",  # Orange
        "#14b8a6",  # Teal
        "#6366f1",  # Indigo
    ]
    
    def __init__(self):
        # whiteboard_id -> set of UserConnection
        self.connections: Dict[int, Dict[int, UserConnection]] = {}
        # Track color assignments per whiteboard
        self.color_index: Dict[int, int] = {}
        # Lock for thread-safe connection management
        self._lock = asyncio.Lock()
        # Background cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        
    async def start_cleanup_task(self):
        """Start the background cleanup task for stale connections."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_stale_connections())
    
    async def _cleanup_stale_connections(self):
        """Periodically clean up stale connections."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._remove_stale_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
    
    async def _remove_stale_connections(self):
        """Remove connections that haven't had activity in a while."""
        async with self._lock:
            stale = []
            for wb_id, users in self.connections.items():
                for user_id, conn in users.items():
                    if conn.is_stale():
                        stale.append((wb_id, user_id))
            
        # Disconnect outside the lock to avoid deadlock
        for wb_id, user_id in stale:
            logger.info(f"Removing stale connection: whiteboard={wb_id}, user={user_id}")
            await self.disconnect(wb_id, user_id)
        
    def _get_next_color(self, whiteboard_id: int) -> str:
        """Get next available color for a user cursor."""
        if whiteboard_id not in self.color_index:
            self.color_index[whiteboard_id] = 0
        
        color = self.CURSOR_COLORS[self.color_index[whiteboard_id] % len(self.CURSOR_COLORS)]
        self.color_index[whiteboard_id] += 1
        return color
    
    async def connect(
        self, 
        websocket: WebSocket, 
        whiteboard_id: int, 
        user_id: int,
        username: str
    ) -> UserConnection:
        """
        Accept a new WebSocket connection for whiteboard collaboration.
        """
        await websocket.accept()
        
        async with self._lock:
            if whiteboard_id not in self.connections:
                self.connections[whiteboard_id] = {}
            
            # Close existing connection if user reconnects
            old_conn = None
            if user_id in self.connections[whiteboard_id]:
                old_conn = self.connections[whiteboard_id][user_id]
            
            # Create user connection with assigned color
            connection = UserConnection(
                websocket=websocket,
                user_id=user_id,
                username=username,
                color=self._get_next_color(whiteboard_id)
            )
            
            self.connections[whiteboard_id][user_id] = connection
        
        # Close old connection OUTSIDE the lock to avoid race condition
        if old_conn:
            try:
                await old_conn.websocket.close(code=1000, reason="Reconnected from another session")
            except Exception:
                pass  # Old connection may already be closed
        
        # Start cleanup task if not running
        await self.start_cleanup_task()
        
        # Notify others of new user joining (outside lock)
        await self.broadcast_presence_update(whiteboard_id, user_id)
        
        # Send current users to the new connection
        await self.send_current_users(websocket, whiteboard_id, user_id)
        
        logger.info(f"User {username} (ID: {user_id}) joined whiteboard {whiteboard_id}")
        
        return connection
    
    async def disconnect(self, whiteboard_id: int, user_id: int):
        """
        Handle user disconnection from whiteboard.
        """
        async with self._lock:
            if whiteboard_id not in self.connections:
                return
            if user_id not in self.connections[whiteboard_id]:
                return
                
            del self.connections[whiteboard_id][user_id]
            
            # Clean up empty whiteboards
            should_cleanup = not self.connections[whiteboard_id]
            if should_cleanup:
                del self.connections[whiteboard_id]
                if whiteboard_id in self.color_index:
                    del self.color_index[whiteboard_id]
        
        # Notify others outside the lock
        try:
            await self.broadcast(whiteboard_id, {
                "type": "user_left",
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat()
            }, exclude_user=user_id)
        except Exception as e:
            logger.warning(f"Failed to broadcast user_left for user {user_id}: {e}")
    
    async def send_current_users(
        self, 
        websocket: WebSocket, 
        whiteboard_id: int,
        exclude_user_id: int
    ):
        """Send list of current users to a newly connected user."""
        async with self._lock:
            if whiteboard_id not in self.connections:
                return
            
            users = []
            for uid, conn in self.connections[whiteboard_id].items():
                if uid != exclude_user_id:
                    users.append({
                        "user_id": conn.user_id,
                        "username": conn.username,
                        "cursor_x": conn.cursor_x,
                        "cursor_y": conn.cursor_y,
                        "color": conn.color,
                        "selected_element_id": conn.selected_element_id
                    })
        
        try:
            await websocket.send_json({
                "type": "current_users",
                "users": users,
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.warning(f"Failed to send current users: {e}")
    
    async def broadcast_presence_update(self, whiteboard_id: int, user_id: int):
        """Broadcast that a new user has joined."""
        async with self._lock:
            if whiteboard_id not in self.connections:
                return
            
            connection = self.connections[whiteboard_id].get(user_id)
            if not connection:
                return
            
            username = connection.username
            color = connection.color
        
        await self.broadcast(whiteboard_id, {
            "type": "user_joined",
            "user_id": user_id,
            "username": username,
            "color": color,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
    
    async def broadcast_cursor_update(
        self,
        whiteboard_id: int,
        user_id: int,
        cursor_x: float,
        cursor_y: float
    ):
        """Broadcast cursor position update to all users on whiteboard."""
        async with self._lock:
            if whiteboard_id not in self.connections:
                return
            
            connection = self.connections[whiteboard_id].get(user_id)
            if connection:
                connection.cursor_x = cursor_x
                connection.cursor_y = cursor_y
                connection.last_activity = datetime.utcnow()
        
        await self.broadcast(whiteboard_id, {
            "type": "cursor_move",
            "user_id": user_id,
            "cursor_x": cursor_x,
            "cursor_y": cursor_y,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
    
    async def broadcast_selection_update(
        self,
        whiteboard_id: int,
        user_id: int,
        element_id: Optional[str]
    ):
        """Broadcast element selection update."""
        async with self._lock:
            if whiteboard_id not in self.connections:
                return
            
            connection = self.connections[whiteboard_id].get(user_id)
            if connection:
                connection.selected_element_id = element_id
                connection.last_activity = datetime.utcnow()
        
        await self.broadcast(whiteboard_id, {
            "type": "selection_change",
            "user_id": user_id,
            "element_id": element_id,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
    
    async def broadcast_element_create(
        self,
        whiteboard_id: int,
        user_id: int,
        element: dict
    ):
        """Broadcast new element creation."""
        await self._update_activity(whiteboard_id, user_id)
        await self.broadcast(whiteboard_id, {
            "type": "element_create",
            "user_id": user_id,
            "element": element,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
    
    async def broadcast_element_update(
        self,
        whiteboard_id: int,
        user_id: int,
        element_id: str,
        updates: dict
    ):
        """Broadcast element update."""
        await self._update_activity(whiteboard_id, user_id)
        await self.broadcast(whiteboard_id, {
            "type": "element_update",
            "user_id": user_id,
            "element_id": element_id,
            "updates": updates,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
    
    async def broadcast_element_delete(
        self,
        whiteboard_id: int,
        user_id: int,
        element_id: str
    ):
        """Broadcast element deletion."""
        await self._update_activity(whiteboard_id, user_id)
        await self.broadcast(whiteboard_id, {
            "type": "element_delete",
            "user_id": user_id,
            "element_id": element_id,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
    
    async def broadcast_batch_update(
        self,
        whiteboard_id: int,
        user_id: int,
        updates: List[dict]
    ):
        """Broadcast batch element updates."""
        await self._update_activity(whiteboard_id, user_id)
        await self.broadcast(whiteboard_id, {
            "type": "batch_update",
            "user_id": user_id,
            "updates": updates,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
    
    async def _update_activity(self, whiteboard_id: int, user_id: int):
        """Update last activity timestamp for a user."""
        async with self._lock:
            if whiteboard_id in self.connections:
                conn = self.connections[whiteboard_id].get(user_id)
                if conn:
                    conn.last_activity = datetime.utcnow()
    
    async def broadcast(
        self,
        whiteboard_id: int,
        message: dict,
        exclude_user: Optional[int] = None
    ):
        """
        Broadcast a message to all users on a whiteboard.
        Optionally exclude a specific user (usually the sender).
        Thread-safe - takes a snapshot of connections before iterating.
        """
        # Take snapshot under lock to avoid iteration issues
        async with self._lock:
            if whiteboard_id not in self.connections:
                return
            # Create a copy of connections to iterate safely
            connections_snapshot = list(self.connections[whiteboard_id].items())
        
        disconnected = []
        
        for user_id, connection in connections_snapshot:
            if exclude_user and user_id == exclude_user:
                continue
            
            try:
                # Check if websocket is still connected
                if connection.websocket.client_state.name != "CONNECTED":
                    disconnected.append(user_id)
                    continue
                    
                await asyncio.wait_for(
                    connection.websocket.send_json(message),
                    timeout=5.0  # 5 second timeout for sends
                )
            except asyncio.TimeoutError:
                logger.warning(f"Timeout sending to user {user_id}")
                disconnected.append(user_id)
            except Exception as e:
                logger.warning(f"Failed to send to user {user_id}: {e}")
                disconnected.append(user_id)
        
        # Clean up disconnected users (outside the broadcast loop)
        for user_id in disconnected:
            await self.disconnect(whiteboard_id, user_id)
    
    def get_active_users(self, whiteboard_id: int) -> List[dict]:
        """Get list of active users on a whiteboard."""
        if whiteboard_id not in self.connections:
            return []
        
        return [{
            "user_id": conn.user_id,
            "username": conn.username,
            "cursor_x": conn.cursor_x,
            "cursor_y": conn.cursor_y,
            "color": conn.color,
            "selected_element_id": conn.selected_element_id,
            "last_activity": conn.last_activity.isoformat()
        } for conn in self.connections[whiteboard_id].values()]
    
    def get_user_count(self, whiteboard_id: int) -> int:
        """Get number of active users on a whiteboard."""
        if whiteboard_id not in self.connections:
            return 0
        return len(self.connections[whiteboard_id])
    
    async def shutdown(self):
        """Gracefully shutdown the manager."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        async with self._lock:
            for wb_id, users in list(self.connections.items()):
                for user_id, conn in list(users.items()):
                    try:
                        await conn.websocket.close(code=1001, reason="Server shutdown")
                    except Exception:
                        pass
            self.connections.clear()
            self.color_index.clear()


# Singleton instance
whiteboard_manager = WhiteboardConnectionManager()


def decode_token(token: str) -> Optional[dict]:
    """Decode JWT token to get user info."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        return payload
    except JWTError:
        return None
