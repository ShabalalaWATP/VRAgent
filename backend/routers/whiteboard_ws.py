"""
Whiteboard WebSocket endpoint for real-time collaboration.
"""
import json
import html
import re
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.whiteboard_manager import whiteboard_manager, decode_token
from backend.core.logging import get_logger
from backend.models.models import User, Whiteboard, WhiteboardElement, Project, ProjectCollaborator

logger = get_logger(__name__)

router = APIRouter(prefix="/ws/whiteboard", tags=["whiteboard-websocket"])

# Security constants
MAX_BATCH_UPDATES = 100
MAX_CONTENT_LENGTH = 50000  # 50KB max for text content
ALLOWED_IMAGE_SCHEMES = {'http', 'https', 'data'}
ALLOWED_ELEMENT_UPDATES = {
    'x', 'y', 'width', 'height', 'rotation', 'fill_color', 'stroke_color',
    'stroke_width', 'opacity', 'content', 'font_size', 'font_family',
    'text_align', 'z_index', 'points', 'start_element_id', 'end_element_id',
    'arrow_start', 'arrow_end'
}


def check_project_access(db: Session, user_id: int, project_id: int) -> Tuple[bool, str]:
    """Check if user has access to project. Returns (has_access, role)."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return False, "none"
    
    if project.owner_id == user_id:
        return True, "owner"
    
    from sqlalchemy import and_
    collab = db.query(ProjectCollaborator).filter(
        and_(
            ProjectCollaborator.project_id == project_id,
            ProjectCollaborator.user_id == user_id,
            ProjectCollaborator.status == "accepted"
        )
    ).first()
    
    if collab:
        return True, collab.role or "viewer"
    return False, "none"


def sanitize_content(content: Optional[str]) -> Optional[str]:
    """Sanitize text content to prevent XSS."""
    if content is None:
        return None
    # Truncate overly long content
    if len(content) > MAX_CONTENT_LENGTH:
        content = content[:MAX_CONTENT_LENGTH]
    # HTML escape to prevent XSS
    return html.escape(content)


def validate_image_url(url: Optional[str]) -> Optional[str]:
    """Validate image URL to prevent SSRF and XSS."""
    if url is None:
        return None
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_IMAGE_SCHEMES:
            logger.warning(f"Blocked image URL with invalid scheme: {parsed.scheme}")
            return None
        # Block obvious javascript: or data: with suspicious content
        if parsed.scheme == 'data':
            # Only allow image data URIs
            if not url.startswith('data:image/'):
                return None
        return url
    except Exception:
        return None


@router.websocket("/{whiteboard_id}")
async def whiteboard_websocket(
    websocket: WebSocket,
    whiteboard_id: int,
    token: str = Query(...)
):
    """
    WebSocket endpoint for real-time whiteboard collaboration.
    
    Message types (client -> server):
        - cursor_move: { type: "cursor_move", x: float, y: float }
        - select: { type: "select", element_id: string | null }
        - create: { type: "create", element: {...element data} }
        - update: { type: "update", element_id: string, updates: {...} }
        - delete: { type: "delete", element_id: string }
        - batch_update: { type: "batch_update", updates: [...] }
        - viewport: { type: "viewport", x: float, y: float, zoom: float }
    
    Message types (server -> client):
        - current_users: List of currently active users
        - user_joined: New user joined
        - user_left: User disconnected
        - cursor_move: Other user's cursor position
        - selection_change: Other user's selection changed
        - element_create: New element created by another user
        - element_update: Element updated by another user
        - element_delete: Element deleted by another user
        - batch_update: Multiple elements updated
        - error: Error message
    """
    # Validate token
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid token")
        return

    # Verify this is an access token, not a refresh token
    if payload.get("type") != "access":
        await websocket.close(code=4001, reason="Invalid token type")
        return

    user_id = payload.get("sub")
    if not user_id:
        await websocket.close(code=4001, reason="Invalid token")
        return
    
    # Get database session
    from backend.core.database import SessionLocal
    db = SessionLocal()
    
    try:
        # Get user
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            await websocket.close(code=4001, reason="User not found")
            return
        
        # Get whiteboard and check access
        whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
        if not whiteboard:
            await websocket.close(code=4004, reason="Whiteboard not found")
            return
        
        has_access, user_role = check_project_access(db, user.id, whiteboard.project_id)
        if not has_access:
            await websocket.close(code=4003, reason="Access denied")
            return
        
        # Viewers can only observe, not edit
        is_editor = user_role in ("owner", "editor", "admin")
        
        # Connect to whiteboard
        connection = await whiteboard_manager.connect(
            websocket=websocket,
            whiteboard_id=whiteboard_id,
            user_id=user.id,
            username=user.username
        )
        
        logger.info(f"User {user.username} connected to whiteboard {whiteboard_id}")
        
        try:
            while True:
                # Receive message
                data = await websocket.receive_json()
                msg_type = data.get("type")
                
                if msg_type == "cursor_move":
                    # Cursor position update
                    await whiteboard_manager.broadcast_cursor_update(
                        whiteboard_id=whiteboard_id,
                        user_id=user.id,
                        cursor_x=data.get("x", 0),
                        cursor_y=data.get("y", 0)
                    )
                
                elif msg_type == "select":
                    # Element selection
                    await whiteboard_manager.broadcast_selection_update(
                        whiteboard_id=whiteboard_id,
                        user_id=user.id,
                        element_id=data.get("element_id")
                    )
                
                elif msg_type == "create":
                    # Create new element
                    if not is_editor:
                        await websocket.send_json({"type": "error", "message": "Viewers cannot create elements"})
                        continue
                    
                    # Rate limit check for modification operations
                    if not connection.check_rate_limit():
                        await websocket.send_json({"type": "error", "message": "Rate limit exceeded. Please slow down."})
                        continue
                    
                    # Check if whiteboard is locked
                    db.refresh(whiteboard)
                    if whiteboard.is_locked and whiteboard.locked_by != user.id:
                        await websocket.send_json({"type": "error", "message": "Whiteboard is locked"})
                        continue
                    
                    element_data = data.get("element", {})
                    
                    # Sanitize content and validate image URL
                    content = sanitize_content(element_data.get("content"))
                    image_url = validate_image_url(element_data.get("image_url"))
                    
                    # Save to database
                    import uuid
                    element = WhiteboardElement(
                        whiteboard_id=whiteboard_id,
                        element_id=element_data.get("element_id", str(uuid.uuid4())),
                        element_type=element_data.get("element_type", "rectangle"),
                        x=element_data.get("x", 0),
                        y=element_data.get("y", 0),
                        width=element_data.get("width", 100),
                        height=element_data.get("height", 100),
                        rotation=element_data.get("rotation", 0),
                        fill_color=element_data.get("fill_color"),
                        stroke_color=element_data.get("stroke_color", "#ffffff"),
                        stroke_width=element_data.get("stroke_width", 2),
                        opacity=element_data.get("opacity", 1.0),
                        content=content,
                        font_size=element_data.get("font_size", 16),
                        font_family=element_data.get("font_family", "Inter"),
                        text_align=element_data.get("text_align", "left"),
                        image_url=image_url,
                        points=element_data.get("points"),
                        z_index=element_data.get("z_index", 0),
                        created_by=user.id
                    )
                    db.add(element)
                    db.commit()
                    db.refresh(element)
                    
                    # Broadcast to others
                    element_data["id"] = element.id
                    element_data["element_id"] = element.element_id
                    await whiteboard_manager.broadcast_element_create(
                        whiteboard_id=whiteboard_id,
                        user_id=user.id,
                        element=element_data
                    )
                    
                    # Confirm to sender
                    await websocket.send_json({
                        "type": "create_confirmed",
                        "element_id": element.element_id,
                        "id": element.id
                    })
                
                elif msg_type == "update":
                    # Update element
                    if not is_editor:
                        await websocket.send_json({"type": "error", "message": "Viewers cannot update elements"})
                        continue
                    
                    # Rate limit check for modification operations
                    if not connection.check_rate_limit():
                        await websocket.send_json({"type": "error", "message": "Rate limit exceeded. Please slow down."})
                        continue
                    
                    # Check if whiteboard is locked
                    db.refresh(whiteboard)
                    if whiteboard.is_locked and whiteboard.locked_by != user.id:
                        await websocket.send_json({"type": "error", "message": "Whiteboard is locked"})
                        continue
                    
                    element_id = data.get("element_id")
                    updates = data.get("updates", {})
                    
                    if element_id:
                        from sqlalchemy import and_
                        element = db.query(WhiteboardElement).filter(
                            and_(
                                WhiteboardElement.whiteboard_id == whiteboard_id,
                                WhiteboardElement.element_id == element_id
                            )
                        ).first()
                        
                        if element:
                            # Apply only whitelisted attributes
                            for key, value in updates.items():
                                if key in ALLOWED_ELEMENT_UPDATES and hasattr(element, key):
                                    # Sanitize content field
                                    if key == 'content':
                                        value = sanitize_content(value)
                                    elif key == 'image_url':
                                        value = validate_image_url(value)
                                    setattr(element, key, value)
                            db.commit()
                        
                        # Broadcast to others (filter updates to allowed keys)
                        safe_updates = {k: v for k, v in updates.items() if k in ALLOWED_ELEMENT_UPDATES}
                        await whiteboard_manager.broadcast_element_update(
                            whiteboard_id=whiteboard_id,
                            user_id=user.id,
                            element_id=element_id,
                            updates=safe_updates
                        )
                
                elif msg_type == "delete":
                    # Delete element
                    if not is_editor:
                        await websocket.send_json({"type": "error", "message": "Viewers cannot delete elements"})
                        continue
                    
                    # Rate limit check for modification operations
                    if not connection.check_rate_limit():
                        await websocket.send_json({"type": "error", "message": "Rate limit exceeded. Please slow down."})
                        continue
                    
                    # Check if whiteboard is locked
                    db.refresh(whiteboard)
                    if whiteboard.is_locked and whiteboard.locked_by != user.id:
                        await websocket.send_json({"type": "error", "message": "Whiteboard is locked"})
                        continue
                    
                    element_id = data.get("element_id")
                    
                    if element_id:
                        from sqlalchemy import and_
                        element = db.query(WhiteboardElement).filter(
                            and_(
                                WhiteboardElement.whiteboard_id == whiteboard_id,
                                WhiteboardElement.element_id == element_id
                            )
                        ).first()
                        
                        if element:
                            db.delete(element)
                            db.commit()
                        
                        # Broadcast to others
                        await whiteboard_manager.broadcast_element_delete(
                            whiteboard_id=whiteboard_id,
                            user_id=user.id,
                            element_id=element_id
                        )
                
                elif msg_type == "batch_update":
                    # Batch update multiple elements
                    if not is_editor:
                        await websocket.send_json({"type": "error", "message": "Viewers cannot update elements"})
                        continue
                    
                    # Rate limit check for modification operations
                    if not connection.check_rate_limit():
                        await websocket.send_json({"type": "error", "message": "Rate limit exceeded. Please slow down."})
                        continue
                    
                    # Check if whiteboard is locked
                    db.refresh(whiteboard)
                    if whiteboard.is_locked and whiteboard.locked_by != user.id:
                        await websocket.send_json({"type": "error", "message": "Whiteboard is locked"})
                        continue
                    
                    updates = data.get("updates", [])
                    
                    # Enforce batch limit to prevent DoS
                    if len(updates) > MAX_BATCH_UPDATES:
                        logger.warning(f"User {user.id} exceeded batch update limit: {len(updates)}")
                        updates = updates[:MAX_BATCH_UPDATES]
                    
                    # Track successful and failed updates
                    successful_updates = []
                    failed_updates = []
                    
                    for update in updates:
                        element_id = update.get("element_id")
                        if element_id:
                            try:
                                from sqlalchemy import and_
                                element = db.query(WhiteboardElement).filter(
                                    and_(
                                        WhiteboardElement.whiteboard_id == whiteboard_id,
                                        WhiteboardElement.element_id == element_id
                                    )
                                ).first()
                                
                                if element:
                                    # Apply only whitelisted attributes
                                    for key, value in update.items():
                                        if key != "element_id" and key in ALLOWED_ELEMENT_UPDATES and hasattr(element, key):
                                            if key == 'content':
                                                value = sanitize_content(value)
                                            elif key == 'image_url':
                                                value = validate_image_url(value)
                                            setattr(element, key, value)
                                    successful_updates.append(update)
                                else:
                                    failed_updates.append({"element_id": element_id, "reason": "not_found"})
                            except Exception as e:
                                logger.warning(f"Failed to update element {element_id}: {e}")
                                failed_updates.append({"element_id": element_id, "reason": "error"})
                    
                    db.commit()
                    
                    # Notify client of any failures
                    if failed_updates:
                        await websocket.send_json({
                            "type": "batch_update_partial",
                            "successful": len(successful_updates),
                            "failed": failed_updates
                        })
                    
                    # Broadcast to others (filter updates to allowed keys, only successful ones)
                    safe_updates = [
                        {k: v for k, v in u.items() if k == 'element_id' or k in ALLOWED_ELEMENT_UPDATES}
                        for u in successful_updates
                    ]
                    await whiteboard_manager.broadcast_batch_update(
                        whiteboard_id=whiteboard_id,
                        user_id=user.id,
                        updates=safe_updates
                    )
                
                elif msg_type == "viewport":
                    # Viewport update (for showing what others are looking at)
                    connection.viewport_x = data.get("x", 0)
                    connection.viewport_y = data.get("y", 0)
                    connection.viewport_zoom = data.get("zoom", 1.0)
                
                elif msg_type == "ping":
                    # Keep-alive ping
                    await websocket.send_json({"type": "pong"})
                
                else:
                    logger.warning(f"Unknown message type: {msg_type}")
        
        except WebSocketDisconnect:
            logger.info(f"User {user.username} disconnected from whiteboard {whiteboard_id}")
        
        except Exception as e:
            logger.error(f"WebSocket error for user {user.username}: {e}")
            try:
                await websocket.send_json({
                    "type": "error",
                    "message": "An unexpected error occurred"
                })
            except:
                pass
        
        finally:
            await whiteboard_manager.disconnect(whiteboard_id, user.id)
    
    finally:
        db.close()
