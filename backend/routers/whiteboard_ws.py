"""
Whiteboard WebSocket endpoint for real-time collaboration.
"""
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.whiteboard_manager import whiteboard_manager, decode_token
from backend.core.logging import get_logger
from backend.models.models import User, Whiteboard, WhiteboardElement, Project, ProjectCollaborator

logger = get_logger(__name__)

router = APIRouter(prefix="/ws/whiteboard", tags=["whiteboard-websocket"])


def check_project_access(db: Session, user_id: int, project_id: int) -> bool:
    """Check if user has access to project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return False
    
    if project.owner_id == user_id:
        return True
    
    from sqlalchemy import and_
    collab = db.query(ProjectCollaborator).filter(
        and_(
            ProjectCollaborator.project_id == project_id,
            ProjectCollaborator.user_id == user_id,
            ProjectCollaborator.status == "accepted"
        )
    ).first()
    
    return collab is not None


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
        
        if not check_project_access(db, user.id, whiteboard.project_id):
            await websocket.close(code=4003, reason="Access denied")
            return
        
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
                    element_data = data.get("element", {})
                    
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
                        content=element_data.get("content"),
                        font_size=element_data.get("font_size", 16),
                        font_family=element_data.get("font_family", "Inter"),
                        text_align=element_data.get("text_align", "left"),
                        image_url=element_data.get("image_url"),
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
                            for key, value in updates.items():
                                if hasattr(element, key):
                                    setattr(element, key, value)
                            db.commit()
                        
                        # Broadcast to others
                        await whiteboard_manager.broadcast_element_update(
                            whiteboard_id=whiteboard_id,
                            user_id=user.id,
                            element_id=element_id,
                            updates=updates
                        )
                
                elif msg_type == "delete":
                    # Delete element
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
                    updates = data.get("updates", [])
                    
                    for update in updates:
                        element_id = update.get("element_id")
                        if element_id:
                            from sqlalchemy import and_
                            element = db.query(WhiteboardElement).filter(
                                and_(
                                    WhiteboardElement.whiteboard_id == whiteboard_id,
                                    WhiteboardElement.element_id == element_id
                                )
                            ).first()
                            
                            if element:
                                for key, value in update.items():
                                    if key != "element_id" and hasattr(element, key):
                                        setattr(element, key, value)
                    
                    db.commit()
                    
                    # Broadcast to others
                    await whiteboard_manager.broadcast_batch_update(
                        whiteboard_id=whiteboard_id,
                        user_id=user.id,
                        updates=updates
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
                    "message": str(e)
                })
            except:
                pass
        
        finally:
            await whiteboard_manager.disconnect(whiteboard_id, user.id)
    
    finally:
        db.close()
