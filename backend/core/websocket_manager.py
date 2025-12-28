"""WebSocket connection manager for real-time chat."""
import asyncio
import json
from collections import defaultdict
from datetime import datetime
from time import time
from typing import Dict, Set, Optional, Any, List
from fastapi import WebSocket
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Security limits
MAX_CONNECTIONS_PER_USER = 5  # Max tabs/devices per user
MESSAGE_RATE_LIMIT = 30  # Messages per minute per user
RATE_WINDOW_SECONDS = 60  # Rate limit window


class ConnectionManager:
    """Manages WebSocket connections for real-time messaging."""
    
    def __init__(self):
        # user_id -> set of WebSocket connections (user can have multiple tabs/devices)
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        # conversation_id -> set of user_ids currently viewing
        self.conversation_viewers: Dict[int, Set[int]] = {}
        # user_id -> typing state (conversation_id, timestamp)
        self.typing_states: Dict[int, tuple] = {}
        # Rate limiting: user_id -> list of message timestamps
        self.message_rates: Dict[int, List[float]] = defaultdict(list)
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, user_id: int) -> bool:
        """Accept and register a WebSocket connection. Returns False if connection limit exceeded."""
        async with self._lock:
            current_count = len(self.active_connections.get(user_id, set()))
            if current_count >= MAX_CONNECTIONS_PER_USER:
                logger.warning(f"Connection limit exceeded for user {user_id}: {current_count}/{MAX_CONNECTIONS_PER_USER}")
                await websocket.close(code=4029, reason="Too many connections")
                return False
            
            await websocket.accept()
            if user_id not in self.active_connections:
                self.active_connections[user_id] = set()
            self.active_connections[user_id].add(websocket)
        logger.info(f"WebSocket connected: user {user_id} ({current_count + 1}/{MAX_CONNECTIONS_PER_USER})")
        return True
    
    async def disconnect(self, websocket: WebSocket, user_id: int) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            if user_id in self.active_connections:
                self.active_connections[user_id].discard(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
            # Clean up typing states
            if user_id in self.typing_states:
                del self.typing_states[user_id]
            # Clean up conversation viewers
            for conv_id in list(self.conversation_viewers.keys()):
                self.conversation_viewers[conv_id].discard(user_id)
                if not self.conversation_viewers[conv_id]:
                    del self.conversation_viewers[conv_id]
        logger.info(f"WebSocket disconnected: user {user_id}")
    
    def is_online(self, user_id: int) -> bool:
        """Check if a user is currently online."""
        return user_id in self.active_connections and len(self.active_connections[user_id]) > 0
    
    def get_online_users(self, user_ids: list[int]) -> list[int]:
        """Get list of online users from provided user IDs."""
        return [uid for uid in user_ids if self.is_online(uid)]
    
    async def set_viewing_conversation(self, user_id: int, conversation_id: Optional[int]) -> None:
        """Set which conversation a user is currently viewing."""
        async with self._lock:
            # Remove from previous conversation
            for conv_id in list(self.conversation_viewers.keys()):
                self.conversation_viewers[conv_id].discard(user_id)
                if not self.conversation_viewers[conv_id]:
                    del self.conversation_viewers[conv_id]
            # Add to new conversation
            if conversation_id:
                if conversation_id not in self.conversation_viewers:
                    self.conversation_viewers[conversation_id] = set()
                self.conversation_viewers[conversation_id].add(user_id)
    
    def get_conversation_viewers(self, conversation_id: int) -> Set[int]:
        """Get users currently viewing a conversation."""
        return self.conversation_viewers.get(conversation_id, set())
    
    def check_rate_limit(self, user_id: int) -> bool:
        """Check if user is within rate limit. Returns True if allowed, False if rate limited."""
        now = time()
        # Clean old entries outside the window
        self.message_rates[user_id] = [
            t for t in self.message_rates[user_id] 
            if now - t < RATE_WINDOW_SECONDS
        ]
        
        if len(self.message_rates[user_id]) >= MESSAGE_RATE_LIMIT:
            logger.warning(f"Rate limit exceeded for user {user_id}: {len(self.message_rates[user_id])}/{MESSAGE_RATE_LIMIT} per minute")
            return False
        
        self.message_rates[user_id].append(now)
        return True
    
    def get_connection_count(self, user_id: int) -> int:
        """Get the number of active connections for a user."""
        return len(self.active_connections.get(user_id, set()))
    
    async def send_personal(self, user_id: int, message: dict) -> None:
        """Send a message to all connections of a specific user."""
        if user_id in self.active_connections:
            message_json = json.dumps(message, default=str)
            dead_connections = []
            for websocket in self.active_connections[user_id]:
                try:
                    await websocket.send_text(message_json)
                except Exception as e:
                    logger.warning(f"Failed to send to user {user_id}: {e}")
                    dead_connections.append(websocket)
            # Clean up dead connections
            for ws in dead_connections:
                await self.disconnect(ws, user_id)
    
    async def send_to_users(self, user_ids: list[int], message: dict) -> None:
        """Send a message to multiple users."""
        for user_id in user_ids:
            await self.send_personal(user_id, message)
    
    async def broadcast_to_conversation(
        self, 
        conversation_id: int, 
        participant_ids: list[int], 
        message: dict,
        exclude_user_id: Optional[int] = None
    ) -> None:
        """Broadcast a message to all participants of a conversation."""
        message["conversation_id"] = conversation_id
        for user_id in participant_ids:
            if user_id != exclude_user_id:
                await self.send_personal(user_id, message)
    
    async def send_typing_indicator(
        self, 
        conversation_id: int, 
        participant_ids: list[int],
        user_id: int,
        username: str,
        is_typing: bool
    ) -> None:
        """Send typing indicator to conversation participants."""
        message = {
            "type": "typing",
            "conversation_id": conversation_id,
            "user_id": user_id,
            "username": username,
            "is_typing": is_typing,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_conversation(
            conversation_id, 
            participant_ids, 
            message, 
            exclude_user_id=user_id
        )
    
    async def send_online_status(
        self,
        user_id: int,
        username: str,
        is_online: bool,
        friend_ids: list[int]
    ) -> None:
        """Notify friends when a user comes online/offline."""
        message = {
            "type": "presence",
            "user_id": user_id,
            "username": username,
            "is_online": is_online,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.send_to_users(friend_ids, message)


# Global connection manager instance
chat_manager = ConnectionManager()
