"""
Kanban WebSocket manager for real-time collaboration.
Handles card/column updates, presence broadcasting, and live sync.
"""
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from fastapi import WebSocket
from jose import jwt, JWTError

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class KanbanUserConnection:
    """Represents a user's WebSocket connection to a Kanban board."""
    websocket: WebSocket
    user_id: int
    username: str
    color: str = "#3b82f6"
    viewing_column_id: Optional[int] = None
    last_activity: datetime = field(default_factory=datetime.utcnow)


class KanbanConnectionManager:
    """
    Manages WebSocket connections for Kanban board collaboration.
    Handles real-time card/column updates and presence tracking.
    """

    # Color palette for user indicators
    USER_COLORS = [
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
        # board_id -> {user_id -> KanbanUserConnection}
        self.connections: Dict[int, Dict[int, KanbanUserConnection]] = {}
        # Track color assignments per board
        self.color_index: Dict[int, int] = {}
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

    def _get_next_color(self, board_id: int) -> str:
        """Get next available color for a user."""
        if board_id not in self.color_index:
            self.color_index[board_id] = 0

        color = self.USER_COLORS[self.color_index[board_id] % len(self.USER_COLORS)]
        self.color_index[board_id] += 1
        return color

    async def connect(
        self,
        websocket: WebSocket,
        board_id: int,
        user_id: int,
        username: str
    ) -> KanbanUserConnection:
        """Accept a new WebSocket connection for Kanban collaboration."""
        await websocket.accept()

        async with self._lock:
            if board_id not in self.connections:
                self.connections[board_id] = {}

            # Create user connection with assigned color
            connection = KanbanUserConnection(
                websocket=websocket,
                user_id=user_id,
                username=username,
                color=self._get_next_color(board_id)
            )

            self.connections[board_id][user_id] = connection

        # Notify others of new user joining
        await self.broadcast_user_joined(board_id, user_id)

        # Send current users to the new connection
        await self.send_current_users(websocket, board_id, user_id)

        logger.info(f"User {username} (ID: {user_id}) joined Kanban board {board_id}")

        return connection

    async def disconnect(self, board_id: int, user_id: int):
        """Handle user disconnection from Kanban board."""
        async with self._lock:
            if board_id in self.connections:
                if user_id in self.connections[board_id]:
                    del self.connections[board_id][user_id]

                    # Notify others of user leaving
                    await self._broadcast_internal(board_id, {
                        "type": "user_left",
                        "user_id": user_id,
                        "timestamp": datetime.utcnow().isoformat()
                    }, exclude_user=user_id)

                    # Clean up empty boards
                    if not self.connections[board_id]:
                        del self.connections[board_id]
                        if board_id in self.color_index:
                            del self.color_index[board_id]

    async def send_current_users(
        self,
        websocket: WebSocket,
        board_id: int,
        exclude_user_id: int
    ):
        """Send list of current users to a newly connected user."""
        if board_id not in self.connections:
            return

        users = []
        for uid, conn in self.connections[board_id].items():
            if uid != exclude_user_id:
                users.append({
                    "user_id": conn.user_id,
                    "username": conn.username,
                    "color": conn.color,
                    "viewing_column_id": conn.viewing_column_id
                })

        await websocket.send_json({
            "type": "current_users",
            "users": users,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def broadcast_user_joined(self, board_id: int, user_id: int):
        """Broadcast that a new user has joined."""
        if board_id not in self.connections:
            return

        connection = self.connections[board_id].get(user_id)
        if not connection:
            return

        await self.broadcast(board_id, {
            "type": "user_joined",
            "user_id": user_id,
            "username": connection.username,
            "color": connection.color,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    async def broadcast_viewing_column(
        self,
        board_id: int,
        user_id: int,
        column_id: Optional[int]
    ):
        """Broadcast which column a user is viewing/focused on."""
        if board_id not in self.connections:
            return

        connection = self.connections[board_id].get(user_id)
        if connection:
            connection.viewing_column_id = column_id
            connection.last_activity = datetime.utcnow()

        await self.broadcast(board_id, {
            "type": "user_viewing_column",
            "user_id": user_id,
            "column_id": column_id,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    # Card broadcast methods
    async def broadcast_card_create(
        self,
        board_id: int,
        user_id: int,
        card: dict
    ):
        """Broadcast new card creation."""
        await self.broadcast(board_id, {
            "type": "card_created",
            "user_id": user_id,
            "card": card,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    async def broadcast_card_update(
        self,
        board_id: int,
        user_id: int,
        card_id: int,
        updates: dict
    ):
        """Broadcast card update."""
        await self.broadcast(board_id, {
            "type": "card_updated",
            "user_id": user_id,
            "card_id": card_id,
            "updates": updates,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    async def broadcast_card_move(
        self,
        board_id: int,
        user_id: int,
        card_id: int,
        source_column_id: int,
        target_column_id: int,
        position: int
    ):
        """Broadcast card movement between columns."""
        await self.broadcast(board_id, {
            "type": "card_moved",
            "user_id": user_id,
            "card_id": card_id,
            "source_column_id": source_column_id,
            "target_column_id": target_column_id,
            "position": position,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    async def broadcast_card_delete(
        self,
        board_id: int,
        user_id: int,
        card_id: int
    ):
        """Broadcast card deletion."""
        await self.broadcast(board_id, {
            "type": "card_deleted",
            "user_id": user_id,
            "card_id": card_id,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    # Column broadcast methods
    async def broadcast_column_create(
        self,
        board_id: int,
        user_id: int,
        column: dict
    ):
        """Broadcast new column creation."""
        await self.broadcast(board_id, {
            "type": "column_created",
            "user_id": user_id,
            "column": column,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    async def broadcast_column_update(
        self,
        board_id: int,
        user_id: int,
        column_id: int,
        updates: dict
    ):
        """Broadcast column update."""
        await self.broadcast(board_id, {
            "type": "column_updated",
            "user_id": user_id,
            "column_id": column_id,
            "updates": updates,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    async def broadcast_column_delete(
        self,
        board_id: int,
        user_id: int,
        column_id: int
    ):
        """Broadcast column deletion."""
        await self.broadcast(board_id, {
            "type": "column_deleted",
            "user_id": user_id,
            "column_id": column_id,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    async def broadcast_columns_reorder(
        self,
        board_id: int,
        user_id: int,
        column_ids: List[int]
    ):
        """Broadcast columns reorder."""
        await self.broadcast(board_id, {
            "type": "columns_reordered",
            "user_id": user_id,
            "column_ids": column_ids,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)

    async def _broadcast_internal(
        self,
        board_id: int,
        message: dict,
        exclude_user: Optional[int] = None
    ):
        """Internal broadcast without lock (called when lock is already held)."""
        if board_id not in self.connections:
            return

        disconnected = []

        for user_id, connection in self.connections[board_id].items():
            if exclude_user and user_id == exclude_user:
                continue

            try:
                await connection.websocket.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send to user {user_id}: {e}")
                disconnected.append(user_id)

        # Note: Don't clean up here since we're under lock, mark for later
        return disconnected

    async def broadcast(
        self,
        board_id: int,
        message: dict,
        exclude_user: Optional[int] = None
    ):
        """
        Broadcast a message to all users on a board.
        Optionally exclude a specific user (usually the sender).
        """
        if board_id not in self.connections:
            return

        disconnected = []

        for user_id, connection in list(self.connections.get(board_id, {}).items()):
            if exclude_user and user_id == exclude_user:
                continue

            try:
                await connection.websocket.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send to user {user_id}: {e}")
                disconnected.append(user_id)

        # Clean up disconnected users
        for user_id in disconnected:
            await self.disconnect(board_id, user_id)

    def get_active_users(self, board_id: int) -> List[dict]:
        """Get list of active users on a board."""
        if board_id not in self.connections:
            return []

        return [{
            "user_id": conn.user_id,
            "username": conn.username,
            "color": conn.color,
            "viewing_column_id": conn.viewing_column_id,
            "last_activity": conn.last_activity.isoformat()
        } for conn in self.connections[board_id].values()]

    def get_user_count(self, board_id: int) -> int:
        """Get number of active users on a board."""
        if board_id not in self.connections:
            return 0
        return len(self.connections[board_id])

    def is_connected(self, board_id: int) -> bool:
        """Check if any users are connected to a board."""
        return board_id in self.connections and len(self.connections[board_id]) > 0


# Singleton instance
kanban_manager = KanbanConnectionManager()


def decode_token(token: str) -> Optional[dict]:
    """Decode JWT token to get user info."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        return payload
    except JWTError:
        return None
