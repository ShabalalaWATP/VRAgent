"""WebSocket endpoint for real-time chat functionality."""
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.core.websocket_manager import chat_manager
from backend.models.models import User
from backend.services.auth_service import decode_token
from backend.services.messaging_service import (
    is_conversation_participant,
    get_conversation_participant_ids,
    mark_conversation_read
)
from backend.services.social_service import get_friend_ids

logger = get_logger(__name__)

router = APIRouter(tags=["websocket"])


async def get_user_from_token(token: str, db: Session) -> Optional[User]:
    """Validate JWT token and return user."""
    payload = decode_token(token)
    if not payload:
        return None

    # Verify token type
    if payload.get("type") != "access":
        return None

    user_id = payload.get("sub")
    if user_id is None:
        return None

    try:
        user = db.query(User).filter(User.id == int(user_id)).first()
        return user
    except (TypeError, ValueError):
        return None


@router.websocket("/ws/chat")
async def websocket_chat_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time chat.
    
    Connect with: ws://host/api/ws/chat?token=<jwt_token>
    
    Client -> Server messages:
    - {"type": "typing", "conversation_id": 123, "is_typing": true}
    - {"type": "viewing", "conversation_id": 123}  # Set active conversation
    - {"type": "read", "conversation_id": 123}  # Mark as read
    - {"type": "ping"}  # Keep-alive
    
    Server -> Client messages:
    - {"type": "new_message", "conversation_id": 123, "message": {...}}
    - {"type": "message_edited", "conversation_id": 123, "message_id": 456, "content": "..."}
    - {"type": "message_deleted", "conversation_id": 123, "message_id": 456}
    - {"type": "reaction_added", "conversation_id": 123, "message_id": 456, "user_id": 789, "username": "...", "emoji": "👍"}
    - {"type": "reaction_removed", ...}
    - {"type": "typing", "conversation_id": 123, "user_id": 789, "username": "...", "is_typing": true}
    - {"type": "presence", "user_id": 789, "username": "...", "is_online": true}
    - {"type": "read_receipt", "conversation_id": 123, "user_id": 789, "username": "...", "last_read_at": "..."}
    - {"type": "pong"}  # Response to ping
    """
    # Authenticate user
    user = await get_user_from_token(token, db)
    if not user:
        await websocket.close(code=4001, reason="Invalid token")
        return
    
    # Check user status
    if user.status != "approved":
        await websocket.close(code=4003, reason="Account not approved")
        return
    
    # Connect (with connection limit check)
    connected = await chat_manager.connect(websocket, user.id)
    if not connected:
        return  # Connection was rejected due to limit
    
    # Notify friends that user is online
    friend_ids = get_friend_ids(db, user.id)
    await chat_manager.send_online_status(user.id, user.username, True, friend_ids)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            
            # Enforce message size limit (prevent oversized messages)
            if len(data) > 65536:  # 64KB max
                logger.warning(f"Oversized WebSocket message from user {user.id}: {len(data)} bytes")
                continue
            
            try:
                message = json.loads(data)
                msg_type = message.get("type")

                # Update activity timestamp on any message
                chat_manager.update_activity(user.id, websocket)

                # Rate limit check for non-ping messages
                if msg_type != "ping" and not chat_manager.check_rate_limit(user.id):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Rate limit exceeded. Please slow down."
                    }))
                    continue
                
                if msg_type == "ping":
                    # Update activity timestamp and respond to keep-alive
                    chat_manager.update_activity(user.id, websocket)
                    await websocket.send_text(json.dumps({"type": "pong"}))
                
                elif msg_type == "typing":
                    # Handle typing indicator
                    conversation_id = message.get("conversation_id")
                    is_typing = message.get("is_typing", False)
                    
                    if conversation_id and is_conversation_participant(db, conversation_id, user.id):
                        participant_ids = get_conversation_participant_ids(db, conversation_id)
                        await chat_manager.send_typing_indicator(
                            conversation_id,
                            participant_ids,
                            user.id,
                            user.username,
                            is_typing
                        )
                
                elif msg_type == "viewing":
                    # Set which conversation user is viewing
                    conversation_id = message.get("conversation_id")
                    if conversation_id is None or is_conversation_participant(db, conversation_id, user.id):
                        await chat_manager.set_viewing_conversation(user.id, conversation_id)
                
                elif msg_type == "read":
                    # Mark conversation as read and notify others
                    conversation_id = message.get("conversation_id")
                    if conversation_id and is_conversation_participant(db, conversation_id, user.id):
                        mark_conversation_read(db, conversation_id, user.id)
                        # Notify other participants about the read receipt
                        participant_ids = get_conversation_participant_ids(db, conversation_id)
                        await chat_manager.broadcast_to_conversation(
                            conversation_id,
                            participant_ids,
                            {
                                "type": "read_receipt",
                                "conversation_id": conversation_id,
                                "user_id": user.id,
                                "username": user.username,
                                "last_read_at": datetime.utcnow().isoformat()
                            },
                            exclude_user_id=user.id
                        )
                
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from user {user.id}: {data}")
            except Exception as e:
                logger.error(f"Error processing WebSocket message: {e}")
    
    except WebSocketDisconnect:
        logger.debug(f"WebSocket disconnected for user {user.id} ({user.username})")
    finally:
        # Clear typing state and notify if user was typing
        typing_state = chat_manager.typing_states.get(user.id)
        if typing_state:
            conversation_id, _ = typing_state
            try:
                participant_ids = get_conversation_participant_ids(db, conversation_id)
                await chat_manager.send_typing_indicator(
                    conversation_id,
                    participant_ids,
                    user.id,
                    user.username,
                    False  # User stopped typing (disconnected)
                )
            except Exception as e:
                logger.debug(f"Failed to send typing stop on disconnect: {e}")
        
        # Disconnect and notify friends
        await chat_manager.disconnect(websocket, user.id)
        friend_ids = get_friend_ids(db, user.id)
        await chat_manager.send_online_status(user.id, user.username, False, friend_ids)


# Helper function to broadcast messages (called from other routers)
async def broadcast_new_message(conversation_id: int, message_data: dict, participant_ids: list, sender_id: int):
    """Broadcast a new message to all conversation participants."""
    await chat_manager.broadcast_to_conversation(
        conversation_id,
        participant_ids,
        {
            "type": "new_message",
            "conversation_id": conversation_id,
            "message": message_data
        },
        exclude_user_id=sender_id
    )


async def broadcast_message_edit(conversation_id: int, message_id: int, content: str, participant_ids: list):
    """Broadcast message edit to all conversation participants."""
    await chat_manager.broadcast_to_conversation(
        conversation_id,
        participant_ids,
        {
            "type": "message_edited",
            "conversation_id": conversation_id,
            "message_id": message_id,
            "content": content
        }
    )


async def broadcast_message_delete(conversation_id: int, message_id: int, participant_ids: list):
    """Broadcast message deletion to all conversation participants."""
    await chat_manager.broadcast_to_conversation(
        conversation_id,
        participant_ids,
        {
            "type": "message_deleted",
            "conversation_id": conversation_id,
            "message_id": message_id
        }
    )


async def broadcast_reaction(
    conversation_id: int,
    message_id: int,
    user_id: int,
    username: str,
    emoji: str,
    added: bool,
    participant_ids: list
):
    """Broadcast reaction add/remove to all conversation participants."""
    await chat_manager.broadcast_to_conversation(
        conversation_id,
        participant_ids,
        {
            "type": "reaction_added" if added else "reaction_removed",
            "conversation_id": conversation_id,
            "message_id": message_id,
            "user_id": user_id,
            "username": username,
            "emoji": emoji
        }
    )


async def broadcast_pin_event(
    conversation_id: int,
    message_id: int,
    user_id: int,
    username: str,
    is_pinned: bool,
    participant_ids: list
):
    """Broadcast message pin/unpin to all conversation participants."""
    await chat_manager.broadcast_to_conversation(
        conversation_id,
        participant_ids,
        {
            "type": "message_pinned" if is_pinned else "message_unpinned",
            "conversation_id": conversation_id,
            "message_id": message_id,
            "user_id": user_id,
            "username": username,
            "pinned_at": datetime.utcnow().isoformat() if is_pinned else None
        }
    )


async def broadcast_read_receipt(
    conversation_id: int,
    user_id: int,
    username: str,
    message_id: int,
    participant_ids: list
):
    """Broadcast read receipt update to all conversation participants."""
    await chat_manager.broadcast_to_conversation(
        conversation_id,
        participant_ids,
        {
            "type": "read_receipt",
            "conversation_id": conversation_id,
            "user_id": user_id,
            "username": username,
            "last_read_message_id": message_id,
            "read_at": datetime.utcnow().isoformat()
        },
        exclude_user_id=user_id
    )


async def broadcast_forward_message(
    conversation_id: int,
    message_data: dict,
    participant_ids: list,
    forwarder_id: int
):
    """Broadcast a forwarded message to all conversation participants."""
    await chat_manager.broadcast_to_conversation(
        conversation_id,
        participant_ids,
        {
            "type": "forwarded_message",
            "conversation_id": conversation_id,
            "message": message_data
        },
        exclude_user_id=forwarder_id
    )


async def broadcast_mention_notification(
    user_id: int,
    conversation_id: int,
    message_id: int,
    sender_username: str,
    content_preview: str
):
    """Send mention notification to a specific user."""
    await chat_manager.send_to_user(
        user_id,
        {
            "type": "mention",
            "conversation_id": conversation_id,
            "message_id": message_id,
            "sender_username": sender_username,
            "content_preview": content_preview[:100]  # Limit preview length
        }
    )
