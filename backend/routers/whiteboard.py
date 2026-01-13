"""
Whiteboard API routes for collaborative editing.
Provides CRUD operations for whiteboards and elements, plus real-time collaboration.
"""
import json
import os
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File
from pydantic import BaseModel
from sqlalchemy import and_
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.auth import get_current_user
from backend.core.config import settings
from backend.core.logging import get_logger
from backend.models.models import (
    User, Project, ProjectCollaborator, Whiteboard, WhiteboardElement, 
    WhiteboardPresence, Annotation, Mention
)

logger = get_logger(__name__)

router = APIRouter(prefix="/whiteboard", tags=["Whiteboard"])


# ============== Pydantic Schemas ==============

class WhiteboardCreate(BaseModel):
    project_id: int
    name: str
    description: Optional[str] = None
    canvas_width: int = 3000
    canvas_height: int = 2000
    background_color: str = "#1e1e2e"
    grid_enabled: bool = True


class WhiteboardUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    canvas_width: Optional[int] = None
    canvas_height: Optional[int] = None
    background_color: Optional[str] = None
    grid_enabled: Optional[bool] = None
    is_locked: Optional[bool] = None


class ElementCreate(BaseModel):
    element_type: str
    x: float = 0
    y: float = 0
    width: float = 100
    height: float = 100
    rotation: float = 0
    fill_color: Optional[str] = None
    stroke_color: str = "#ffffff"
    stroke_width: float = 2
    opacity: float = 1.0
    content: Optional[str] = None
    font_size: int = 16
    font_family: str = "Inter"
    text_align: str = "left"
    image_url: Optional[str] = None
    points: Optional[List[dict]] = None
    start_element_id: Optional[str] = None
    end_element_id: Optional[str] = None
    arrow_start: bool = False
    arrow_end: bool = True
    z_index: int = 0


class ElementUpdate(BaseModel):
    x: Optional[float] = None
    y: Optional[float] = None
    width: Optional[float] = None
    height: Optional[float] = None
    rotation: Optional[float] = None
    fill_color: Optional[str] = None
    stroke_color: Optional[str] = None
    stroke_width: Optional[float] = None
    opacity: Optional[float] = None
    content: Optional[str] = None
    font_size: Optional[int] = None
    font_family: Optional[str] = None
    text_align: Optional[str] = None
    points: Optional[List[dict]] = None
    z_index: Optional[int] = None


class AnnotationCreate(BaseModel):
    project_id: int
    original_image_url: str
    annotated_image_url: Optional[str] = None
    annotations_data: Optional[dict] = None
    title: Optional[str] = None
    description: Optional[str] = None
    finding_id: Optional[int] = None
    note_id: Optional[int] = None
    whiteboard_id: Optional[int] = None


class MentionCreate(BaseModel):
    mentioned_user_id: int
    note_id: Optional[int] = None
    whiteboard_element_id: Optional[int] = None
    message_id: Optional[int] = None
    context_text: Optional[str] = None


# ============== Helper Functions ==============

def check_project_access(db: Session, user_id: int, project_id: int) -> bool:
    """Check if user has access to project (owner or collaborator)."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return False
    
    # Owner always has access
    if project.owner_id == user_id:
        return True
    
    # Check if collaborator
    collab = db.query(ProjectCollaborator).filter(
        and_(
            ProjectCollaborator.project_id == project_id,
            ProjectCollaborator.user_id == user_id,
            ProjectCollaborator.status == "accepted"
        )
    ).first()
    
    return collab is not None


# ============== Whiteboard CRUD ==============

@router.post("/create")
async def create_whiteboard(
    data: WhiteboardCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new whiteboard for a project."""
    if not check_project_access(db, current_user.id, data.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    whiteboard = Whiteboard(
        project_id=data.project_id,
        name=data.name,
        description=data.description,
        canvas_width=data.canvas_width,
        canvas_height=data.canvas_height,
        background_color=data.background_color,
        grid_enabled=data.grid_enabled,
        created_by=current_user.id
    )
    db.add(whiteboard)
    db.commit()
    db.refresh(whiteboard)
    
    return {
        "id": whiteboard.id,
        "name": whiteboard.name,
        "description": whiteboard.description,
        "canvas_width": whiteboard.canvas_width,
        "canvas_height": whiteboard.canvas_height,
        "background_color": whiteboard.background_color,
        "grid_enabled": whiteboard.grid_enabled,
        "created_at": whiteboard.created_at.isoformat() if whiteboard.created_at else None
    }


@router.get("/project/{project_id}")
async def get_project_whiteboards(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all whiteboards for a project."""
    if not check_project_access(db, current_user.id, project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    whiteboards = db.query(Whiteboard).filter(Whiteboard.project_id == project_id).all()
    
    return [{
        "id": wb.id,
        "name": wb.name,
        "description": wb.description,
        "canvas_width": wb.canvas_width,
        "canvas_height": wb.canvas_height,
        "is_locked": wb.is_locked,
        "created_at": wb.created_at.isoformat() if wb.created_at else None,
        "updated_at": wb.updated_at.isoformat() if wb.updated_at else None,
        "element_count": len(wb.elements) if wb.elements else 0,
        "active_users": len([p for p in wb.active_users if p.is_active]) if wb.active_users else 0
    } for wb in whiteboards]


@router.get("/{whiteboard_id}")
async def get_whiteboard(
    whiteboard_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a whiteboard with all its elements."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    # Get active users
    active_presence = db.query(WhiteboardPresence).filter(
        and_(
            WhiteboardPresence.whiteboard_id == whiteboard_id,
            WhiteboardPresence.is_active == True
        )
    ).all()
    
    return {
        "id": whiteboard.id,
        "project_id": whiteboard.project_id,
        "name": whiteboard.name,
        "description": whiteboard.description,
        "canvas_width": whiteboard.canvas_width,
        "canvas_height": whiteboard.canvas_height,
        "background_color": whiteboard.background_color,
        "grid_enabled": whiteboard.grid_enabled,
        "is_locked": whiteboard.is_locked,
        "locked_by": whiteboard.locked_by,
        "created_at": whiteboard.created_at.isoformat() if whiteboard.created_at else None,
        "updated_at": whiteboard.updated_at.isoformat() if whiteboard.updated_at else None,
        "elements": [{
            "id": el.id,
            "element_id": el.element_id,
            "element_type": el.element_type,
            "x": el.x,
            "y": el.y,
            "width": el.width,
            "height": el.height,
            "rotation": el.rotation,
            "fill_color": el.fill_color,
            "stroke_color": el.stroke_color,
            "stroke_width": el.stroke_width,
            "opacity": el.opacity,
            "content": el.content,
            "font_size": el.font_size,
            "font_family": el.font_family,
            "text_align": el.text_align,
            "image_url": el.image_url,
            "points": el.points,
            "start_element_id": el.start_element_id,
            "end_element_id": el.end_element_id,
            "arrow_start": el.arrow_start,
            "arrow_end": el.arrow_end,
            "z_index": el.z_index,
            "created_by": el.created_by
        } for el in whiteboard.elements],
        "active_users": [{
            "user_id": p.user_id,
            "username": p.user.username if p.user else None,
            "cursor_x": p.cursor_x,
            "cursor_y": p.cursor_y,
            "selected_element_id": p.selected_element_id,
            "last_activity": p.last_activity.isoformat() if p.last_activity else None
        } for p in active_presence]
    }


@router.put("/{whiteboard_id}")
async def update_whiteboard(
    whiteboard_id: int,
    data: WhiteboardUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update whiteboard settings."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(whiteboard, key, value)
    
    if data.is_locked is not None:
        whiteboard.locked_by = current_user.id if data.is_locked else None
    
    db.commit()
    db.refresh(whiteboard)
    
    return {"success": True, "message": "Whiteboard updated"}


@router.delete("/{whiteboard_id}")
async def delete_whiteboard(
    whiteboard_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a whiteboard."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    db.delete(whiteboard)
    db.commit()
    
    return {"success": True, "message": "Whiteboard deleted"}


# ============== Element CRUD ==============

@router.post("/{whiteboard_id}/element")
async def create_element(
    whiteboard_id: int,
    data: ElementCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add an element to a whiteboard."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    if whiteboard.is_locked and whiteboard.locked_by != current_user.id:
        raise HTTPException(status_code=423, detail="Whiteboard is locked")
    
    element = WhiteboardElement(
        whiteboard_id=whiteboard_id,
        element_id=str(uuid.uuid4()),
        element_type=data.element_type,
        x=data.x,
        y=data.y,
        width=data.width,
        height=data.height,
        rotation=data.rotation,
        fill_color=data.fill_color,
        stroke_color=data.stroke_color,
        stroke_width=data.stroke_width,
        opacity=data.opacity,
        content=data.content,
        font_size=data.font_size,
        font_family=data.font_family,
        text_align=data.text_align,
        image_url=data.image_url,
        points=data.points,
        start_element_id=data.start_element_id,
        end_element_id=data.end_element_id,
        arrow_start=data.arrow_start,
        arrow_end=data.arrow_end,
        z_index=data.z_index,
        created_by=current_user.id
    )
    db.add(element)
    db.commit()
    db.refresh(element)
    
    return {
        "id": element.id,
        "element_id": element.element_id,
        "element_type": element.element_type,
        "x": element.x,
        "y": element.y,
        "width": element.width,
        "height": element.height,
        "created_by": element.created_by
    }


@router.put("/{whiteboard_id}/element/{element_id}")
async def update_element(
    whiteboard_id: int,
    element_id: str,
    data: ElementUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an element on a whiteboard."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    element = db.query(WhiteboardElement).filter(
        and_(
            WhiteboardElement.whiteboard_id == whiteboard_id,
            WhiteboardElement.element_id == element_id
        )
    ).first()
    
    if not element:
        raise HTTPException(status_code=404, detail="Element not found")
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(element, key, value)
    
    db.commit()
    
    return {"success": True, "message": "Element updated"}


@router.delete("/{whiteboard_id}/element/{element_id}")
async def delete_element(
    whiteboard_id: int,
    element_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete an element from a whiteboard."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    element = db.query(WhiteboardElement).filter(
        and_(
            WhiteboardElement.whiteboard_id == whiteboard_id,
            WhiteboardElement.element_id == element_id
        )
    ).first()
    
    if not element:
        raise HTTPException(status_code=404, detail="Element not found")
    
    db.delete(element)
    db.commit()
    
    return {"success": True, "message": "Element deleted"}


@router.post("/{whiteboard_id}/elements/batch")
async def batch_update_elements(
    whiteboard_id: int,
    updates: List[dict],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Batch update multiple elements at once."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    updated_count = 0
    for update in updates:
        element_id = update.get("element_id")
        if not element_id:
            continue
        
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
            updated_count += 1
    
    db.commit()
    
    return {"success": True, "updated_count": updated_count}


# ============== Annotations ==============

@router.post("/annotation")
async def create_annotation(
    data: AnnotationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a screenshot annotation."""
    if not check_project_access(db, current_user.id, data.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    annotation = Annotation(
        project_id=data.project_id,
        original_image_url=data.original_image_url,
        annotated_image_url=data.annotated_image_url,
        annotations_data=data.annotations_data,
        title=data.title,
        description=data.description,
        finding_id=data.finding_id,
        note_id=data.note_id,
        whiteboard_id=data.whiteboard_id,
        created_by=current_user.id
    )
    db.add(annotation)
    db.commit()
    db.refresh(annotation)
    
    return {
        "id": annotation.id,
        "title": annotation.title,
        "original_image_url": annotation.original_image_url,
        "annotated_image_url": annotation.annotated_image_url,
        "created_at": annotation.created_at.isoformat() if annotation.created_at else None
    }


@router.get("/annotation/project/{project_id}")
async def get_project_annotations(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all annotations for a project."""
    if not check_project_access(db, current_user.id, project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    annotations = db.query(Annotation).filter(Annotation.project_id == project_id).all()
    
    return [{
        "id": a.id,
        "title": a.title,
        "description": a.description,
        "original_image_url": a.original_image_url,
        "annotated_image_url": a.annotated_image_url,
        "annotations_data": a.annotations_data,
        "finding_id": a.finding_id,
        "note_id": a.note_id,
        "whiteboard_id": a.whiteboard_id,
        "created_at": a.created_at.isoformat() if a.created_at else None
    } for a in annotations]


@router.put("/annotation/{annotation_id}")
async def update_annotation(
    annotation_id: int,
    annotations_data: dict,
    annotated_image_url: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update annotation data."""
    annotation = db.query(Annotation).filter(Annotation.id == annotation_id).first()
    if not annotation:
        raise HTTPException(status_code=404, detail="Annotation not found")
    
    if not check_project_access(db, current_user.id, annotation.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    annotation.annotations_data = annotations_data
    if annotated_image_url:
        annotation.annotated_image_url = annotated_image_url
    
    db.commit()
    
    return {"success": True, "message": "Annotation updated"}


@router.delete("/annotation/{annotation_id}")
async def delete_annotation(
    annotation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete an annotation."""
    annotation = db.query(Annotation).filter(Annotation.id == annotation_id).first()
    if not annotation:
        raise HTTPException(status_code=404, detail="Annotation not found")
    
    if not check_project_access(db, current_user.id, annotation.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    db.delete(annotation)
    db.commit()
    
    return {"success": True, "message": "Annotation deleted"}


# ============== Mentions ==============

@router.post("/mention")
async def create_mention(
    data: MentionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a mention notification."""
    mention = Mention(
        mentioned_user_id=data.mentioned_user_id,
        mentioned_by_id=current_user.id,
        note_id=data.note_id,
        whiteboard_element_id=data.whiteboard_element_id,
        message_id=data.message_id,
        context_text=data.context_text
    )
    db.add(mention)
    db.commit()
    db.refresh(mention)
    
    return {"id": mention.id, "created_at": mention.created_at.isoformat() if mention.created_at else None}


@router.get("/mentions/unread")
async def get_unread_mentions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get unread mentions for current user."""
    mentions = db.query(Mention).filter(
        and_(
            Mention.mentioned_user_id == current_user.id,
            Mention.is_read == False
        )
    ).order_by(Mention.created_at.desc()).all()
    
    return [{
        "id": m.id,
        "mentioned_by": {
            "id": m.mentioned_by.id,
            "username": m.mentioned_by.username
        } if m.mentioned_by else None,
        "note_id": m.note_id,
        "whiteboard_element_id": m.whiteboard_element_id,
        "message_id": m.message_id,
        "context_text": m.context_text,
        "created_at": m.created_at.isoformat() if m.created_at else None
    } for m in mentions]


@router.put("/mention/{mention_id}/read")
async def mark_mention_read(
    mention_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark a mention as read."""
    mention = db.query(Mention).filter(
        and_(
            Mention.id == mention_id,
            Mention.mentioned_user_id == current_user.id
        )
    ).first()
    
    if not mention:
        raise HTTPException(status_code=404, detail="Mention not found")
    
    mention.is_read = True
    mention.read_at = datetime.utcnow()
    db.commit()
    
    return {"success": True}


@router.put("/mentions/read-all")
async def mark_all_mentions_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark all mentions as read."""
    db.query(Mention).filter(
        and_(
            Mention.mentioned_user_id == current_user.id,
            Mention.is_read == False
        )
    ).update({"is_read": True, "read_at": datetime.utcnow()})
    db.commit()
    
    return {"success": True}


# ============== Presence ==============

@router.post("/{whiteboard_id}/presence")
async def update_presence(
    whiteboard_id: int,
    cursor_x: Optional[float] = None,
    cursor_y: Optional[float] = None,
    viewport_x: float = 0,
    viewport_y: float = 0,
    viewport_zoom: float = 1.0,
    selected_element_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user presence on whiteboard."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    presence = db.query(WhiteboardPresence).filter(
        and_(
            WhiteboardPresence.whiteboard_id == whiteboard_id,
            WhiteboardPresence.user_id == current_user.id
        )
    ).first()
    
    if presence:
        presence.cursor_x = cursor_x
        presence.cursor_y = cursor_y
        presence.viewport_x = viewport_x
        presence.viewport_y = viewport_y
        presence.viewport_zoom = viewport_zoom
        presence.selected_element_id = selected_element_id
        presence.is_active = True
        presence.last_activity = datetime.utcnow()
    else:
        presence = WhiteboardPresence(
            whiteboard_id=whiteboard_id,
            user_id=current_user.id,
            cursor_x=cursor_x,
            cursor_y=cursor_y,
            viewport_x=viewport_x,
            viewport_y=viewport_y,
            viewport_zoom=viewport_zoom,
            selected_element_id=selected_element_id
        )
        db.add(presence)
    
    db.commit()
    
    return {"success": True}


@router.delete("/{whiteboard_id}/presence")
async def leave_whiteboard(
    whiteboard_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark user as no longer active on whiteboard."""
    presence = db.query(WhiteboardPresence).filter(
        and_(
            WhiteboardPresence.whiteboard_id == whiteboard_id,
            WhiteboardPresence.user_id == current_user.id
        )
    ).first()
    
    if presence:
        presence.is_active = False
        db.commit()
    
    return {"success": True}


@router.get("/{whiteboard_id}/users")
async def get_active_users(
    whiteboard_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get list of users currently on whiteboard."""
    whiteboard = db.query(Whiteboard).filter(Whiteboard.id == whiteboard_id).first()
    if not whiteboard:
        raise HTTPException(status_code=404, detail="Whiteboard not found")
    
    if not check_project_access(db, current_user.id, whiteboard.project_id):
        raise HTTPException(status_code=403, detail="No access to this project")
    
    presences = db.query(WhiteboardPresence).filter(
        and_(
            WhiteboardPresence.whiteboard_id == whiteboard_id,
            WhiteboardPresence.is_active == True
        )
    ).all()
    
    return [{
        "user_id": p.user_id,
        "username": p.user.username if p.user else None,
        "first_name": p.user.first_name if p.user else None,
        "avatar_url": p.user.avatar_url if p.user else None,
        "cursor_x": p.cursor_x,
        "cursor_y": p.cursor_y,
        "selected_element_id": p.selected_element_id,
        "last_activity": p.last_activity.isoformat() if p.last_activity else None
    } for p in presences]


# ============== AI Chat Endpoint ==============

class AIChatMessage(BaseModel):
    role: str
    content: str


class AIChatRequest(BaseModel):
    messages: List[AIChatMessage]


class AIChatResponse(BaseModel):
    message: str


@router.post("/ai/chat", response_model=AIChatResponse)
async def whiteboard_ai_chat(
    request: AIChatRequest,
    current_user: User = Depends(get_current_user)
):
    """
    AI-powered chat for whiteboard features like summarize, categorize, and idea generation.
    Uses Gemini for generating responses.
    """
    try:
        from google import genai
        
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise HTTPException(
                status_code=500,
                detail="AI API key not configured"
            )
        
        client = genai.Client(api_key=api_key)
        
        # System prompt for whiteboard AI
        system_prompt = """You are an AI assistant for a collaborative whiteboard application. 
Your role is to help with:
1. Summarizing brainstorming ideas from sticky notes
2. Categorizing and organizing ideas into themes
3. Generating creative ideas based on user prompts

Guidelines:
- Be concise and actionable
- When asked to return JSON, respond ONLY with valid JSON, no explanation
- When summarizing, use bullet points
- When categorizing, use short 1-2 word category names
- When generating ideas, keep each idea under 50 characters
- Focus on being helpful for brainstorming and ideation sessions"""

        # Build conversation messages
        messages = []
        for msg in request.messages:
            messages.append({
                "role": "user" if msg.role == "user" else "model",
                "parts": [{"text": msg.content}]
            })
        
        # Generate response
        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=messages,
            config={
                "system_instruction": system_prompt,
                "temperature": 0.7,
                "max_output_tokens": 2048,
            }
        )
        
        if response.text:
            return AIChatResponse(message=response.text)
        else:
            return AIChatResponse(
                message="I apologize, but I couldn't generate a response. Please try again."
            )
            
    except ImportError:
        logger.error("google-genai not installed")
        raise HTTPException(
            status_code=500,
            detail="AI module not available. Please check server configuration."
        )
    except Exception as e:
        logger.error(f"Whiteboard AI chat error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate response: {str(e)}"
        )
