"""
WebSocket endpoints for real-time notes collaboration.
Supports live cursor presence, typing indicators, and collaborative editing.
"""
import asyncio
import json
from datetime import datetime
from typing import Dict, Set, Optional, List, Any
from collections import defaultdict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, status
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from backend.core.logging import get_logger
from backend.core.database import get_db
from backend.core.config import settings
from backend.models.models import ProjectNote, Project, User, ProjectCollaborator

logger = get_logger(__name__)

router = APIRouter()


# Generate user colors for presence
USER_COLORS = [
    "#f44336", "#e91e63", "#9c27b0", "#673ab7", "#3f51b5",
    "#2196f3", "#03a9f4", "#00bcd4", "#009688", "#4caf50",
    "#8bc34a", "#cddc39", "#ffc107", "#ff9800", "#ff5722",
]


class NotesCollaborationManager:
    """Manages WebSocket connections for notes collaboration."""
    
    def __init__(self):
        # project_id -> set of (WebSocket, user_info) connections
        self.project_connections: Dict[int, Set[tuple]] = defaultdict(set)
        # project_id -> note_id -> set of user_ids currently editing
        self.active_editors: Dict[int, Dict[int, Set[int]]] = defaultdict(lambda: defaultdict(set))
        # project_id -> note_id -> user_id -> cursor position
        self.cursor_positions: Dict[int, Dict[int, Dict[int, dict]]] = defaultdict(lambda: defaultdict(dict))
        # project_id -> note_id -> user_id -> timestamp of last typing
        self.typing_states: Dict[int, Dict[int, Dict[int, float]]] = defaultdict(lambda: defaultdict(dict))
        # user_id -> color (for consistent user colors)
        self.user_colors: Dict[int, str] = {}
        self._color_index = 0
        self._lock = asyncio.Lock()
    
    def _get_user_color(self, user_id: int) -> str:
        """Get a consistent color for a user."""
        if user_id not in self.user_colors:
            self.user_colors[user_id] = USER_COLORS[self._color_index % len(USER_COLORS)]
            self._color_index += 1
        return self.user_colors[user_id]
    
    async def connect(
        self, 
        websocket: WebSocket, 
        project_id: int, 
        user_id: int, 
        username: str
    ) -> bool:
        """Accept and register a WebSocket connection for notes collaboration."""
        try:
            await websocket.accept()
            
            user_info = {
                "user_id": user_id,
                "username": username,
                "color": self._get_user_color(user_id),
                "connected_at": datetime.utcnow().isoformat(),
            }
            
            async with self._lock:
                self.project_connections[project_id].add((websocket, json.dumps(user_info)))
            
            logger.info(f"Notes WebSocket connected: user {username} (ID: {user_id}) on project {project_id}")
            
            # Notify others of new user
            await self.broadcast_to_project(
                project_id,
                {
                    "type": "user_joined",
                    "user": user_info,
                    "timestamp": datetime.utcnow().isoformat(),
                },
                exclude_websocket=websocket
            )
            
            # Send current active users to the new connection
            active_users = await self.get_active_users(project_id)
            await websocket.send_text(json.dumps({
                "type": "presence_sync",
                "users": active_users,
                "active_editors": dict(self.active_editors.get(project_id, {})),
                "timestamp": datetime.utcnow().isoformat(),
            }))
            
            return True
        except Exception as e:
            logger.error(f"Failed to connect notes WebSocket: {e}")
            return False
    
    async def disconnect(self, websocket: WebSocket, project_id: int, user_id: int, username: str) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            # Remove from connections
            to_remove = None
            for conn in self.project_connections.get(project_id, set()):
                if conn[0] == websocket:
                    to_remove = conn
                    break
            
            if to_remove:
                self.project_connections[project_id].discard(to_remove)
                if not self.project_connections[project_id]:
                    del self.project_connections[project_id]
            
            # Clean up editor states
            if project_id in self.active_editors:
                for note_id in list(self.active_editors[project_id].keys()):
                    self.active_editors[project_id][note_id].discard(user_id)
                    if not self.active_editors[project_id][note_id]:
                        del self.active_editors[project_id][note_id]
            
            # Clean up cursor positions
            if project_id in self.cursor_positions:
                for note_id in list(self.cursor_positions[project_id].keys()):
                    if user_id in self.cursor_positions[project_id][note_id]:
                        del self.cursor_positions[project_id][note_id][user_id]
            
            # Clean up typing states
            if project_id in self.typing_states:
                for note_id in list(self.typing_states[project_id].keys()):
                    if user_id in self.typing_states[project_id][note_id]:
                        del self.typing_states[project_id][note_id][user_id]
        
        logger.info(f"Notes WebSocket disconnected: user {username} (ID: {user_id}) from project {project_id}")
        
        # Notify others of user leaving
        await self.broadcast_to_project(
            project_id,
            {
                "type": "user_left",
                "user_id": user_id,
                "username": username,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    async def get_active_users(self, project_id: int) -> List[dict]:
        """Get list of active users in a project's notes."""
        users = []
        for ws, user_info_json in self.project_connections.get(project_id, set()):
            try:
                user_info = json.loads(user_info_json)
                users.append(user_info)
            except:
                pass
        return users
    
    async def broadcast_to_project(
        self, 
        project_id: int, 
        message: dict, 
        exclude_websocket: Optional[WebSocket] = None
    ) -> None:
        """Broadcast a message to all connections in a project."""
        message_json = json.dumps(message, default=str)
        dead_connections = []
        
        for ws, user_info in self.project_connections.get(project_id, set()):
            if ws == exclude_websocket:
                continue
            try:
                await ws.send_text(message_json)
            except Exception as e:
                logger.warning(f"Failed to send to websocket: {e}")
                dead_connections.append((ws, user_info))
        
        # Clean up dead connections
        for conn in dead_connections:
            self.project_connections[project_id].discard(conn)
    
    async def handle_cursor_move(
        self, 
        project_id: int, 
        note_id: int, 
        user_id: int,
        username: str,
        position: dict
    ) -> None:
        """Handle cursor position update."""
        self.cursor_positions[project_id][note_id][user_id] = {
            "position": position,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        await self.broadcast_to_project(
            project_id,
            {
                "type": "cursor_move",
                "note_id": note_id,
                "user_id": user_id,
                "username": username,
                "color": self._get_user_color(user_id),
                "position": position,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    async def handle_typing_start(
        self, 
        project_id: int, 
        note_id: int, 
        user_id: int,
        username: str
    ) -> None:
        """Handle typing indicator start."""
        import time
        self.typing_states[project_id][note_id][user_id] = time.time()
        
        await self.broadcast_to_project(
            project_id,
            {
                "type": "typing_start",
                "note_id": note_id,
                "user_id": user_id,
                "username": username,
                "color": self._get_user_color(user_id),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    async def handle_typing_stop(
        self, 
        project_id: int, 
        note_id: int, 
        user_id: int,
        username: str
    ) -> None:
        """Handle typing indicator stop."""
        if project_id in self.typing_states:
            if note_id in self.typing_states[project_id]:
                if user_id in self.typing_states[project_id][note_id]:
                    del self.typing_states[project_id][note_id][user_id]
        
        await self.broadcast_to_project(
            project_id,
            {
                "type": "typing_stop",
                "note_id": note_id,
                "user_id": user_id,
                "username": username,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    async def handle_note_edit(
        self, 
        project_id: int, 
        note_id: int, 
        user_id: int,
        username: str,
        changes: dict,
        websocket: WebSocket
    ) -> None:
        """Handle note content edit - broadcast to others."""
        await self.broadcast_to_project(
            project_id,
            {
                "type": "note_edit",
                "note_id": note_id,
                "user_id": user_id,
                "username": username,
                "color": self._get_user_color(user_id),
                "changes": changes,
                "timestamp": datetime.utcnow().isoformat(),
            },
            exclude_websocket=websocket
        )
    
    async def handle_note_focus(
        self, 
        project_id: int, 
        note_id: int, 
        user_id: int,
        username: str
    ) -> None:
        """Handle user focusing on a note."""
        self.active_editors[project_id][note_id].add(user_id)
        
        await self.broadcast_to_project(
            project_id,
            {
                "type": "note_focus",
                "note_id": note_id,
                "user_id": user_id,
                "username": username,
                "color": self._get_user_color(user_id),
                "editors": list(self.active_editors[project_id][note_id]),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    async def handle_note_blur(
        self, 
        project_id: int, 
        note_id: int, 
        user_id: int,
        username: str
    ) -> None:
        """Handle user leaving focus from a note."""
        self.active_editors[project_id][note_id].discard(user_id)
        
        # Also clear typing state
        if project_id in self.typing_states:
            if note_id in self.typing_states[project_id]:
                if user_id in self.typing_states[project_id][note_id]:
                    del self.typing_states[project_id][note_id][user_id]
        
        await self.broadcast_to_project(
            project_id,
            {
                "type": "note_blur",
                "note_id": note_id,
                "user_id": user_id,
                "username": username,
                "editors": list(self.active_editors[project_id][note_id]),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    async def handle_note_created(
        self, 
        project_id: int, 
        note: dict,
        user_id: int,
        username: str,
        websocket: WebSocket
    ) -> None:
        """Broadcast when a new note is created."""
        await self.broadcast_to_project(
            project_id,
            {
                "type": "note_created",
                "note": note,
                "user_id": user_id,
                "username": username,
                "timestamp": datetime.utcnow().isoformat(),
            },
            exclude_websocket=websocket
        )
    
    async def handle_note_deleted(
        self, 
        project_id: int, 
        note_id: int,
        user_id: int,
        username: str,
        websocket: WebSocket
    ) -> None:
        """Broadcast when a note is deleted."""
        # Clean up any state for this note
        if project_id in self.active_editors and note_id in self.active_editors[project_id]:
            del self.active_editors[project_id][note_id]
        if project_id in self.cursor_positions and note_id in self.cursor_positions[project_id]:
            del self.cursor_positions[project_id][note_id]
        if project_id in self.typing_states and note_id in self.typing_states[project_id]:
            del self.typing_states[project_id][note_id]
        
        await self.broadcast_to_project(
            project_id,
            {
                "type": "note_deleted",
                "note_id": note_id,
                "user_id": user_id,
                "username": username,
                "timestamp": datetime.utcnow().isoformat(),
            },
            exclude_websocket=websocket
        )


# Global manager instance
notes_manager = NotesCollaborationManager()


async def verify_ws_token_and_access(websocket: WebSocket, project_id: int, token: str) -> Optional[tuple]:
    """
    Verify JWT token and check project access for WebSocket connection.
    Returns (user_id, username) if valid, None otherwise.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            return None
        user_id = int(user_id)
    except (JWTError, ValueError):
        return None
    
    # Get database session
    from backend.core.database import SessionLocal
    db = SessionLocal()
    try:
        # Check user exists
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
        
        # Check project access
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            return None
        
        # Owner always has access
        if project.owner_id == user_id:
            return (user_id, user.username)
        
        # Check collaborator access
        collaborator = db.query(ProjectCollaborator).filter(
            ProjectCollaborator.project_id == project_id,
            ProjectCollaborator.user_id == user_id
        ).first()
        
        if collaborator:
            return (user_id, user.username)
        
        return None
    finally:
        db.close()


@router.websocket("/ws/notes/{project_id}")
async def websocket_notes_collaboration(
    websocket: WebSocket,
    project_id: int,
    token: str = Query(..., description="JWT access token"),
):
    """
    WebSocket endpoint for real-time notes collaboration.
    
    Connect to receive live updates for notes in a project:
    - User presence (join/leave)
    - Cursor positions
    - Typing indicators
    - Note edits
    - Note creation/deletion
    
    Message types to send:
    - cursor_move: {note_id, position: {start, end}}
    - typing_start: {note_id}
    - typing_stop: {note_id}
    - note_edit: {note_id, changes: {content?, title?}}
    - note_focus: {note_id}
    - note_blur: {note_id}
    - note_created: {note: {...}}
    - note_deleted: {note_id}
    - ping: (keepalive)
    """
    # Verify token and project access
    auth_result = await verify_ws_token_and_access(websocket, project_id, token)
    if not auth_result:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    user_id, username = auth_result
    connected = await notes_manager.connect(websocket, project_id, user_id, username)
    
    if not connected:
        return
    
    try:
        while True:
            data = await websocket.receive_text()
            
            # Handle ping/pong for keepalive
            if data == "ping":
                await websocket.send_text("pong")
                continue
            
            try:
                message = json.loads(data)
                msg_type = message.get("type")
                
                if msg_type == "cursor_move":
                    await notes_manager.handle_cursor_move(
                        project_id,
                        message.get("note_id"),
                        user_id,
                        username,
                        message.get("position", {})
                    )
                
                elif msg_type == "typing_start":
                    await notes_manager.handle_typing_start(
                        project_id,
                        message.get("note_id"),
                        user_id,
                        username
                    )
                
                elif msg_type == "typing_stop":
                    await notes_manager.handle_typing_stop(
                        project_id,
                        message.get("note_id"),
                        user_id,
                        username
                    )
                
                elif msg_type == "note_edit":
                    await notes_manager.handle_note_edit(
                        project_id,
                        message.get("note_id"),
                        user_id,
                        username,
                        message.get("changes", {}),
                        websocket
                    )
                
                elif msg_type == "note_focus":
                    await notes_manager.handle_note_focus(
                        project_id,
                        message.get("note_id"),
                        user_id,
                        username
                    )
                
                elif msg_type == "note_blur":
                    await notes_manager.handle_note_blur(
                        project_id,
                        message.get("note_id"),
                        user_id,
                        username
                    )
                
                elif msg_type == "note_created":
                    await notes_manager.handle_note_created(
                        project_id,
                        message.get("note"),
                        user_id,
                        username,
                        websocket
                    )
                
                elif msg_type == "note_deleted":
                    await notes_manager.handle_note_deleted(
                        project_id,
                        message.get("note_id"),
                        user_id,
                        username,
                        websocket
                    )
                
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON received from user {user_id}")
            except Exception as e:
                logger.error(f"Error handling message from user {user_id}: {e}")
    
    except WebSocketDisconnect:
        pass
    finally:
        await notes_manager.disconnect(websocket, project_id, user_id, username)
