"""Service for user presence management."""
from datetime import datetime, timedelta
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session

from backend.models.models import User, UserPresence
from backend.core.logging import get_logger
from backend.core.websocket_manager import chat_manager

logger = get_logger(__name__)


def get_or_create_presence(db: Session, user_id: int) -> UserPresence:
    """Get or create presence record for a user."""
    presence = db.query(UserPresence).filter(UserPresence.user_id == user_id).first()
    if not presence:
        presence = UserPresence(user_id=user_id, status="offline")
        db.add(presence)
        db.commit()
        db.refresh(presence)
    return presence


def update_user_presence(
    db: Session,
    user_id: int,
    status: Optional[str] = None,
    custom_status: Optional[str] = None,
    status_emoji: Optional[str] = None,
    status_duration_hours: Optional[int] = None,
    clear_custom_status: bool = False
) -> Tuple[UserPresence, Optional[str]]:
    """Update user presence status."""
    presence = get_or_create_presence(db, user_id)
    
    if status:
        presence.status = status
    
    if clear_custom_status:
        presence.custom_status = None
        presence.status_emoji = None
        presence.status_expires_at = None
    else:
        if custom_status is not None:
            presence.custom_status = custom_status
        if status_emoji is not None:
            presence.status_emoji = status_emoji
        if status_duration_hours:
            presence.status_expires_at = datetime.utcnow() + timedelta(hours=status_duration_hours)
        elif custom_status and status_duration_hours is None:
            # If setting custom status without duration, clear expiry
            presence.status_expires_at = None
    
    presence.last_seen_at = datetime.utcnow()
    
    db.commit()
    db.refresh(presence)
    
    return presence, None


def set_user_online(db: Session, user_id: int) -> UserPresence:
    """Set user as online when they connect."""
    presence = get_or_create_presence(db, user_id)
    
    # Only change status if it was offline
    if presence.status == "offline":
        presence.status = "online"
    
    presence.last_seen_at = datetime.utcnow()
    presence.last_active_at = datetime.utcnow()
    
    db.commit()
    db.refresh(presence)
    
    return presence


def set_user_offline(db: Session, user_id: int) -> UserPresence:
    """Set user as offline when they disconnect."""
    presence = get_or_create_presence(db, user_id)
    presence.status = "offline"
    presence.last_seen_at = datetime.utcnow()
    
    db.commit()
    db.refresh(presence)
    
    return presence


def update_last_activity(db: Session, user_id: int) -> None:
    """Update user's last activity timestamp."""
    presence = db.query(UserPresence).filter(UserPresence.user_id == user_id).first()
    if presence:
        presence.last_active_at = datetime.utcnow()
        presence.last_seen_at = datetime.utcnow()
        db.commit()


def get_user_presence(db: Session, user_id: int, viewer_id: int) -> Optional[dict]:
    """Get presence info for a user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None
    
    presence = get_or_create_presence(db, user_id)
    
    # Check if custom status has expired
    if presence.status_expires_at and presence.status_expires_at < datetime.utcnow():
        presence.custom_status = None
        presence.status_emoji = None
        presence.status_expires_at = None
        db.commit()
    
    # Check real-time online status from WebSocket manager
    is_online = chat_manager.is_online(user_id)
    
    # If WebSocket says online but DB says offline, update DB
    if is_online and presence.status == "offline":
        presence.status = "online"
        db.commit()
    
    return {
        "user_id": user.id,
        "username": user.username,
        "first_name": user.first_name,
        "avatar_url": user.avatar_url,
        "status": presence.status,
        "custom_status": presence.custom_status,
        "status_emoji": presence.status_emoji,
        "status_expires_at": presence.status_expires_at,
        "last_seen_at": presence.last_seen_at,
        "is_online": is_online or presence.status in ["online", "away", "busy", "dnd"]
    }


def get_bulk_presence(db: Session, user_ids: List[int], viewer_id: int) -> List[dict]:
    """Get presence info for multiple users."""
    if not user_ids:
        return []
    
    users = db.query(User).filter(User.id.in_(user_ids)).all()
    user_map = {u.id: u for u in users}
    
    presences = db.query(UserPresence).filter(UserPresence.user_id.in_(user_ids)).all()
    presence_map = {p.user_id: p for p in presences}
    
    # Get real-time online status
    online_users = set(chat_manager.get_online_users(user_ids))
    
    results = []
    for user_id in user_ids:
        user = user_map.get(user_id)
        if not user:
            continue
        
        presence = presence_map.get(user_id)
        is_online = user_id in online_users
        
        # Check if custom status expired
        custom_status = None
        status_emoji = None
        status_expires_at = None
        
        if presence:
            if presence.status_expires_at and presence.status_expires_at < datetime.utcnow():
                # Expired - clear it
                presence.custom_status = None
                presence.status_emoji = None
                presence.status_expires_at = None
            else:
                custom_status = presence.custom_status
                status_emoji = presence.status_emoji
                status_expires_at = presence.status_expires_at
        
        results.append({
            "user_id": user.id,
            "username": user.username,
            "first_name": user.first_name,
            "avatar_url": user.avatar_url,
            "status": presence.status if presence else "offline",
            "custom_status": custom_status,
            "status_emoji": status_emoji,
            "status_expires_at": status_expires_at,
            "last_seen_at": presence.last_seen_at if presence else None,
            "is_online": is_online or (presence and presence.status in ["online", "away", "busy", "dnd"])
        })
    
    return results


def get_friends_presence(db: Session, user_id: int) -> List[dict]:
    """Get presence for all friends of a user."""
    from backend.services.social_service import get_friend_ids
    
    friend_ids = get_friend_ids(db, user_id)
    if not friend_ids:
        return []
    
    return get_bulk_presence(db, friend_ids, user_id)
