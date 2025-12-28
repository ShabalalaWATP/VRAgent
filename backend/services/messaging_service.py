"""Service for messaging features: conversations and messages."""
from datetime import datetime, timedelta
from typing import List, Optional, Tuple, Dict
import html
import re

from sqlalchemy import or_, and_, func, desc
from sqlalchemy.orm import Session, joinedload

from backend.core.logging import get_logger
from backend.models.models import User, Conversation, ConversationParticipant, Message, MessageReaction, Friendship, PinnedMessage, MessageReadReceipt
from backend.services.social_service import are_friends

logger = get_logger(__name__)

# Security constants
MAX_MESSAGE_LENGTH = 10000  # Maximum message content length
MAX_GROUP_NAME_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 500


def sanitize_content(content: str) -> str:
    """Sanitize message content to prevent XSS and limit length."""
    if not content:
        return ""
    # Escape HTML entities to prevent XSS
    sanitized = html.escape(content)
    # Limit length
    return sanitized[:MAX_MESSAGE_LENGTH]


def sanitize_name(name: str, max_length: int = MAX_GROUP_NAME_LENGTH) -> str:
    """Sanitize group name or similar short text."""
    if not name:
        return ""
    return html.escape(name.strip())[:max_length]


# ============================================================================
# Helper Functions
# ============================================================================

def get_participant_role(db: Session, conversation_id: int, user_id: int) -> Optional[str]:
    """Get user's role in a conversation."""
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).first()
    return participant.role if participant else None


def is_group_admin(db: Session, conversation_id: int, user_id: int) -> bool:
    """Check if user is owner or admin of a group."""
    role = get_participant_role(db, conversation_id, user_id)
    return role in ("owner", "admin")


# ============================================================================
# Group Chats
# ============================================================================

def create_group(
    db: Session,
    creator_id: int,
    name: str,
    description: Optional[str] = None,
    avatar_url: Optional[str] = None,
    participant_ids: Optional[List[int]] = None
) -> Tuple[Optional[Conversation], str]:
    """Create a new group chat."""
    # Create conversation
    conversation = Conversation(
        name=name,
        description=description,
        avatar_url=avatar_url,
        is_group="true",
        created_by=creator_id
    )
    db.add(conversation)
    db.flush()
    
    # Add creator as owner
    owner_participant = ConversationParticipant(
        conversation_id=conversation.id,
        user_id=creator_id,
        role="owner"
    )
    db.add(owner_participant)
    
    # Add other participants (must be friends with creator)
    if participant_ids:
        for uid in participant_ids:
            if uid != creator_id:
                if not are_friends(db, creator_id, uid):
                    continue  # Skip non-friends silently
                participant = ConversationParticipant(
                    conversation_id=conversation.id,
                    user_id=uid,
                    role="member",
                    added_by=creator_id
                )
                db.add(participant)
    
    db.commit()
    db.refresh(conversation)
    
    logger.info(f"Group '{name}' created by user {creator_id}")
    return conversation, ""


def update_group(
    db: Session,
    conversation_id: int,
    user_id: int,
    name: Optional[str] = None,
    description: Optional[str] = None,
    avatar_url: Optional[str] = None
) -> Tuple[Optional[Conversation], str]:
    """Update group settings (admins only)."""
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id,
        Conversation.is_group == "true"
    ).first()
    
    if not conversation:
        return None, "Group not found"
    
    if not is_group_admin(db, conversation_id, user_id):
        return None, "Only admins can update group settings"
    
    if name is not None:
        conversation.name = name
    if description is not None:
        conversation.description = description
    if avatar_url is not None:
        conversation.avatar_url = avatar_url
    
    conversation.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(conversation)
    
    return conversation, ""


def add_group_members(
    db: Session,
    conversation_id: int,
    adder_id: int,
    user_ids: List[int]
) -> Tuple[List[int], str]:
    """Add members to a group (admins only). Returns list of added user IDs."""
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id,
        Conversation.is_group == "true"
    ).first()
    
    if not conversation:
        return [], "Group not found"
    
    if not is_group_admin(db, conversation_id, adder_id):
        return [], "Only admins can add members"
    
    added = []
    for uid in user_ids:
        # Check not already a member
        existing = db.query(ConversationParticipant).filter(
            ConversationParticipant.conversation_id == conversation_id,
            ConversationParticipant.user_id == uid
        ).first()
        
        if existing:
            continue
        
        # Check is friend of adder (or any group admin)
        if not are_friends(db, adder_id, uid):
            continue
        
        participant = ConversationParticipant(
            conversation_id=conversation_id,
            user_id=uid,
            role="member",
            added_by=adder_id
        )
        db.add(participant)
        added.append(uid)
    
    if added:
        db.commit()
        logger.info(f"Added {len(added)} members to group {conversation_id}")
    
    return added, ""


def remove_group_member(
    db: Session,
    conversation_id: int,
    remover_id: int,
    user_id: int
) -> Tuple[bool, str]:
    """Remove a member from a group."""
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id,
        Conversation.is_group == "true"
    ).first()
    
    if not conversation:
        return False, "Group not found"
    
    remover_role = get_participant_role(db, conversation_id, remover_id)
    target_role = get_participant_role(db, conversation_id, user_id)
    
    if not remover_role:
        return False, "You are not a member of this group"
    
    if not target_role:
        return False, "User is not a member of this group"
    
    # Users can remove themselves (leave)
    if remover_id == user_id:
        if target_role == "owner":
            # Owner must transfer ownership first
            return False, "Owner cannot leave without transferring ownership"
        
        db.query(ConversationParticipant).filter(
            ConversationParticipant.conversation_id == conversation_id,
            ConversationParticipant.user_id == user_id
        ).delete()
        db.commit()
        return True, "You have left the group"
    
    # Only admins can remove others
    if remover_role not in ("owner", "admin"):
        return False, "Only admins can remove members"
    
    # Owners can remove admins, admins cannot remove other admins
    if target_role == "owner":
        return False, "Cannot remove the group owner"
    
    if target_role == "admin" and remover_role != "owner":
        return False, "Only the owner can remove admins"
    
    db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).delete()
    db.commit()
    
    return True, "Member removed"


def update_member_role(
    db: Session,
    conversation_id: int,
    updater_id: int,
    user_id: int,
    new_role: str
) -> Tuple[bool, str]:
    """Update a member's role (owner only for admin promotion)."""
    if new_role not in ("owner", "admin", "member"):
        return False, "Invalid role"
    
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id,
        Conversation.is_group == "true"
    ).first()
    
    if not conversation:
        return False, "Group not found"
    
    updater_role = get_participant_role(db, conversation_id, updater_id)
    
    if updater_role != "owner":
        return False, "Only the owner can change member roles"
    
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).first()
    
    if not participant:
        return False, "User is not a member of this group"
    
    # Handle ownership transfer
    if new_role == "owner":
        # Demote current owner to admin
        current_owner = db.query(ConversationParticipant).filter(
            ConversationParticipant.conversation_id == conversation_id,
            ConversationParticipant.user_id == updater_id
        ).first()
        if current_owner:
            current_owner.role = "admin"
        
        participant.role = "owner"
        conversation.created_by = user_id
    else:
        participant.role = new_role
    
    db.commit()
    return True, f"Role updated to {new_role}"


def get_group_members(
    db: Session,
    conversation_id: int,
    user_id: int
) -> Tuple[List[dict], str]:
    """Get list of group members with details."""
    if not is_conversation_participant(db, conversation_id, user_id):
        return [], "You are not a member of this group"
    
    participants = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id
    ).all()
    
    members = []
    for p in participants:
        user = db.query(User).filter(User.id == p.user_id).first()
        added_by_user = None
        if p.added_by:
            added_by_user = db.query(User).filter(User.id == p.added_by).first()
        
        if user:
            members.append({
                "user_id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "avatar_url": user.avatar_url,
                "role": p.role,
                "nickname": p.nickname,
                "is_muted": p.is_muted == "true",
                "joined_at": p.joined_at,
                "added_by_username": added_by_user.username if added_by_user else None
            })
    
    # Sort: owner first, then admins, then members
    role_order = {"owner": 0, "admin": 1, "member": 2}
    members.sort(key=lambda x: role_order.get(x["role"], 3))
    
    return members, ""


# ============================================================================
# Conversations
# ============================================================================

def get_or_create_dm_conversation(
    db: Session,
    user1_id: int,
    user2_id: int
) -> Tuple[Optional[Conversation], str]:
    """
    Get existing DM conversation or create a new one.
    Users must be friends to start a conversation.
    """
    # Check if users are friends
    if not are_friends(db, user1_id, user2_id):
        return None, "You must be friends to start a conversation"
    
    # Look for existing 1-on-1 conversation between these users
    existing = db.query(Conversation).join(
        ConversationParticipant, Conversation.id == ConversationParticipant.conversation_id
    ).filter(
        Conversation.is_group == "false",
        ConversationParticipant.user_id.in_([user1_id, user2_id])
    ).group_by(Conversation.id).having(
        func.count(ConversationParticipant.id) == 2
    ).all()
    
    # Check which conversations have both users
    for conv in existing:
        participant_ids = [p.user_id for p in conv.participants]
        if set(participant_ids) == {user1_id, user2_id}:
            return conv, ""
    
    # Create new conversation
    conversation = Conversation(is_group="false")
    db.add(conversation)
    db.flush()
    
    # Add participants
    for uid in [user1_id, user2_id]:
        participant = ConversationParticipant(
            conversation_id=conversation.id,
            user_id=uid
        )
        db.add(participant)
    
    db.commit()
    db.refresh(conversation)
    
    logger.info(f"DM conversation created: {user1_id} <-> {user2_id}")
    return conversation, ""


def get_user_conversations(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 50
) -> Tuple[List[dict], int]:
    """Get all conversations for a user with preview info."""
    # Get conversation IDs where user is a participant
    participant_subquery = db.query(ConversationParticipant.conversation_id).filter(
        ConversationParticipant.user_id == user_id
    ).subquery()
    
    conversations = db.query(Conversation).filter(
        Conversation.id.in_(participant_subquery)
    ).order_by(
        Conversation.last_message_at.desc().nullslast(),
        Conversation.created_at.desc()
    ).offset(skip).limit(limit).all()
    
    total = db.query(func.count(Conversation.id)).filter(
        Conversation.id.in_(participant_subquery)
    ).scalar()
    
    result = []
    for conv in conversations:
        # Get participants info
        participants = []
        current_user_participant = None
        my_role = None
        
        for p in conv.participants:
            user = db.query(User).filter(User.id == p.user_id).first()
            if user:
                participant_info = {
                    "user_id": user.id,
                    "username": user.username,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "avatar_url": user.avatar_url,
                    "joined_at": p.joined_at,
                    "role": p.role,
                    "nickname": p.nickname,
                    "is_muted": p.is_muted == "true"
                }
                participants.append(participant_info)
                
                if user.id == user_id:
                    current_user_participant = p
                    my_role = p.role
        
        # Get last message preview
        last_message = db.query(Message).filter(
            Message.conversation_id == conv.id,
            Message.is_deleted == "false"
        ).order_by(desc(Message.created_at)).first()
        
        last_message_preview = None
        last_message_sender = None
        if last_message:
            sender = db.query(User).filter(User.id == last_message.sender_id).first()
            last_message_preview = last_message.content[:100] + ("..." if len(last_message.content) > 100 else "")
            last_message_sender = sender.username if sender else "Unknown"
        
        # Count unread messages
        unread_count = 0
        if current_user_participant and current_user_participant.last_read_at:
            unread_count = db.query(func.count(Message.id)).filter(
                Message.conversation_id == conv.id,
                Message.created_at > current_user_participant.last_read_at,
                Message.sender_id != user_id,
                Message.is_deleted == "false"
            ).scalar()
        elif current_user_participant:
            # Never read - count all messages from others
            unread_count = db.query(func.count(Message.id)).filter(
                Message.conversation_id == conv.id,
                Message.sender_id != user_id,
                Message.is_deleted == "false"
            ).scalar()
        
        # For DMs, use other user's name as conversation name
        display_name = conv.name
        if conv.is_group == "false" and not display_name:
            other_participants = [p for p in participants if p["user_id"] != user_id]
            if other_participants:
                other = other_participants[0]
                display_name = f"{other['first_name'] or ''} {other['last_name'] or ''}".strip() or other['username']
        
        result.append({
            "id": conv.id,
            "name": display_name,
            "description": conv.description,
            "avatar_url": conv.avatar_url,
            "is_group": conv.is_group == "true",
            "participants": participants,
            "participant_count": len(participants),
            "last_message_preview": last_message_preview,
            "last_message_sender": last_message_sender,
            "last_message_at": conv.last_message_at,
            "unread_count": unread_count,
            "created_at": conv.created_at,
            "created_by": conv.created_by,
            "my_role": my_role
        })
    
    return result, total


def get_conversation(
    db: Session,
    conversation_id: int,
    user_id: int
) -> Optional[dict]:
    """Get conversation details if user is a participant."""
    # Check user is participant
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).first()
    
    if not participant:
        return None
    
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id
    ).first()
    
    if not conversation:
        return None
    
    # Get participants info
    participants = []
    my_role = None
    for p in conversation.participants:
        user = db.query(User).filter(User.id == p.user_id).first()
        if user:
            participants.append({
                "user_id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "avatar_url": user.avatar_url,
                "joined_at": p.joined_at,
                "role": p.role,
                "nickname": p.nickname,
                "is_muted": p.is_muted == "true"
            })
            if user.id == user_id:
                my_role = p.role
    
    # For DMs, use other user's name as conversation name
    display_name = conversation.name
    if conversation.is_group == "false" and not display_name:
        other_participants = [p for p in participants if p["user_id"] != user_id]
        if other_participants:
            other = other_participants[0]
            display_name = f"{other['first_name'] or ''} {other['last_name'] or ''}".strip() or other['username']
    
    return {
        "id": conversation.id,
        "name": display_name,
        "description": conversation.description,
        "avatar_url": conversation.avatar_url,
        "is_group": conversation.is_group == "true",
        "participants": participants,
        "participant_count": len(participants),
        "created_at": conversation.created_at,
        "created_by": conversation.created_by,
        "my_role": my_role
    }


def is_conversation_participant(db: Session, conversation_id: int, user_id: int) -> bool:
    """Check if user is a participant in a conversation."""
    return db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).first() is not None


def get_conversation_participant_ids(db: Session, conversation_id: int) -> List[int]:
    """Get all participant IDs for a conversation."""
    participants = db.query(ConversationParticipant.user_id).filter(
        ConversationParticipant.conversation_id == conversation_id
    ).all()
    return [p.user_id for p in participants]


def _get_reactions_for_message(db: Session, message_id: int, user_id: int) -> Dict[str, Dict]:
    """Internal helper to get reactions for a message, keyed by emoji."""
    reactions = db.query(MessageReaction).filter(
        MessageReaction.message_id == message_id
    ).all()
    
    # Group by emoji
    emoji_groups: Dict[str, Dict] = {}
    for r in reactions:
        user = db.query(User).filter(User.id == r.user_id).first()
        if r.emoji not in emoji_groups:
            emoji_groups[r.emoji] = {
                "emoji": r.emoji,
                "count": 0,
                "users": [],
                "user_ids": [],
                "has_reacted": False
            }
        emoji_groups[r.emoji]["count"] += 1
        if user:
            emoji_groups[r.emoji]["users"].append(user.username)
            emoji_groups[r.emoji]["user_ids"].append(user.id)
        if r.user_id == user_id:
            emoji_groups[r.emoji]["has_reacted"] = True
    
    return emoji_groups


def _get_reply_info(db: Session, message_id: int) -> Optional[Dict]:
    """Internal helper to get info about a message for reply preview."""
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        return None
    
    sender = db.query(User).filter(User.id == message.sender_id).first()
    
    return {
        "id": message.id,
        "sender_username": sender.username if sender else "Unknown",
        "content_preview": message.content[:100] + ("..." if len(message.content) > 100 else ""),
        "message_type": message.message_type
    }


# ============================================================================
# Messages
# ============================================================================

def send_message(
    db: Session,
    conversation_id: int,
    sender_id: int,
    content: str,
    message_type: str = "text",
    attachment_data: Optional[dict] = None
) -> Tuple[Optional[Message], str]:
    """Send a message to a conversation."""
    # Check sender is participant
    if not is_conversation_participant(db, conversation_id, sender_id):
        return None, "You are not a participant in this conversation"
    
    # Validate and sanitize content
    if not content or not content.strip():
        return None, "Message content cannot be empty"
    
    sanitized_content = sanitize_content(content)
    if len(sanitized_content) > MAX_MESSAGE_LENGTH:
        return None, f"Message too long (max {MAX_MESSAGE_LENGTH} characters)"
    
    # Create message
    message = Message(
        conversation_id=conversation_id,
        sender_id=sender_id,
        content=sanitized_content,
        message_type=message_type,
        attachment_data=attachment_data
    )
    
    db.add(message)
    
    # Update conversation last_message_at
    conversation = db.query(Conversation).filter(Conversation.id == conversation_id).first()
    if conversation:
        conversation.last_message_at = datetime.utcnow()
    
    # Update sender's last_read_at
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == sender_id
    ).first()
    if participant:
        participant.last_read_at = datetime.utcnow()
    
    db.commit()
    db.refresh(message)
    
    return message, ""


def get_messages(
    db: Session,
    conversation_id: int,
    user_id: int,
    skip: int = 0,
    limit: int = 50,
    before_id: Optional[int] = None
) -> Tuple[List[dict], int, bool]:
    """
    Get messages in a conversation.
    Returns (messages, total, has_more).
    """
    # Check user is participant
    if not is_conversation_participant(db, conversation_id, user_id):
        return [], 0, False
    
    query = db.query(Message).filter(
        Message.conversation_id == conversation_id,
        Message.is_deleted == "false"
    )
    
    if before_id:
        query = query.filter(Message.id < before_id)
    
    total = query.count()
    
    messages = query.order_by(desc(Message.created_at)).offset(skip).limit(limit + 1).all()
    
    has_more = len(messages) > limit
    messages = messages[:limit]
    
    # Reverse to get chronological order
    messages = list(reversed(messages))
    
    result = []
    for msg in messages:
        sender = db.query(User).filter(User.id == msg.sender_id).first()
        
        # Get reactions summary
        reactions = _get_reactions_for_message(db, msg.id, user_id)
        
        # Get reply info if this is a reply
        reply_to = None
        if msg.reply_to_id:
            reply_to = _get_reply_info(db, msg.reply_to_id)
        
        result.append({
            "id": msg.id,
            "conversation_id": msg.conversation_id,
            "sender_id": msg.sender_id,
            "sender_username": sender.username if sender else "Unknown",
            "sender_first_name": sender.first_name if sender else None,
            "sender_avatar_url": sender.avatar_url if sender else None,
            "content": msg.content,
            "message_type": msg.message_type,
            "attachment_data": msg.attachment_data,
            "reply_to": reply_to,
            "reactions": reactions,
            "created_at": msg.created_at,
            "updated_at": msg.updated_at,
            "is_edited": msg.is_edited == "true",
            "is_deleted": msg.is_deleted == "true",
            "is_own_message": msg.sender_id == user_id
        })
    
    return result, total, has_more


def mark_conversation_read(db: Session, conversation_id: int, user_id: int) -> bool:
    """Mark all messages in a conversation as read."""
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).first()
    
    if not participant:
        return False
    
    participant.last_read_at = datetime.utcnow()
    db.commit()
    return True


def edit_message(
    db: Session,
    message_id: int,
    user_id: int,
    new_content: str
) -> Tuple[Optional[Message], str]:
    """Edit a message (only by sender). Saves previous content to edit history."""
    message = db.query(Message).filter(
        Message.id == message_id,
        Message.sender_id == user_id,
        Message.is_deleted == "false"
    ).first()
    
    if not message:
        return None, "Message not found or you don't have permission to edit it"
    
    # Validate and sanitize content
    if not new_content or not new_content.strip():
        return None, "Message content cannot be empty"
    
    sanitized_content = sanitize_content(new_content)
    
    # Save previous content to edit history
    from backend.models.models import MessageEditHistory
    current_count = db.query(MessageEditHistory).filter(
        MessageEditHistory.message_id == message_id
    ).count()
    
    history_entry = MessageEditHistory(
        message_id=message_id,
        previous_content=message.content,
        edit_number=current_count + 1
    )
    db.add(history_entry)
    
    message.content = sanitized_content
    message.is_edited = "true"
    message.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(message)
    
    return message, ""


def delete_message(
    db: Session,
    message_id: int,
    user_id: int
) -> Tuple[bool, str]:
    """Soft delete a message (only by sender)."""
    message = db.query(Message).filter(
        Message.id == message_id,
        Message.sender_id == user_id
    ).first()
    
    if not message:
        return False, "Message not found or you don't have permission to delete it"
    
    message.is_deleted = "true"
    message.content = "[Message deleted]"
    db.commit()
    
    return True, "Message deleted"


def get_unread_counts(db: Session, user_id: int) -> dict:
    """Get unread message counts for all conversations."""
    # Get all conversations user is in
    participations = db.query(ConversationParticipant).filter(
        ConversationParticipant.user_id == user_id
    ).all()
    
    counts = {}
    total = 0
    
    for p in participations:
        if p.last_read_at:
            count = db.query(func.count(Message.id)).filter(
                Message.conversation_id == p.conversation_id,
                Message.created_at > p.last_read_at,
                Message.sender_id != user_id,
                Message.is_deleted == "false"
            ).scalar()
        else:
            count = db.query(func.count(Message.id)).filter(
                Message.conversation_id == p.conversation_id,
                Message.sender_id != user_id,
                Message.is_deleted == "false"
            ).scalar()
        
        if count > 0:
            counts[p.conversation_id] = count
            total += count
    
    return {
        "total_unread": total,
        "by_conversation": counts
    }


# ============================================================================
# Message Reactions
# ============================================================================

def add_reaction(
    db: Session,
    message_id: int,
    user_id: int,
    emoji: str
) -> Tuple[Optional[MessageReaction], str]:
    """Add a reaction to a message."""
    # Get the message and check user is in the conversation
    message = db.query(Message).filter(
        Message.id == message_id,
        Message.is_deleted == "false"
    ).first()
    
    if not message:
        return None, "Message not found"
    
    if not is_conversation_participant(db, message.conversation_id, user_id):
        return None, "You are not a participant in this conversation"
    
    # Check if user already has this reaction
    existing = db.query(MessageReaction).filter(
        MessageReaction.message_id == message_id,
        MessageReaction.user_id == user_id,
        MessageReaction.emoji == emoji
    ).first()
    
    if existing:
        return existing, ""  # Already exists, return it
    
    # Create reaction
    reaction = MessageReaction(
        message_id=message_id,
        user_id=user_id,
        emoji=emoji
    )
    db.add(reaction)
    db.commit()
    db.refresh(reaction)
    
    return reaction, ""


def remove_reaction(
    db: Session,
    message_id: int,
    user_id: int,
    emoji: str
) -> Tuple[bool, str]:
    """Remove a reaction from a message."""
    reaction = db.query(MessageReaction).filter(
        MessageReaction.message_id == message_id,
        MessageReaction.user_id == user_id,
        MessageReaction.emoji == emoji
    ).first()
    
    if not reaction:
        return False, "Reaction not found"
    
    db.delete(reaction)
    db.commit()
    
    return True, "Reaction removed"


def get_message_reactions(
    db: Session,
    message_id: int,
    user_id: int
) -> Tuple[Dict[str, Dict], int]:
    """Get all reactions for a message, grouped by emoji."""
    # Get the message first
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        return {}, 0
    
    # Check user is in conversation
    if not is_conversation_participant(db, message.conversation_id, user_id):
        return {}, 0
    
    reactions = _get_reactions_for_message(db, message_id, user_id)
    total = sum(r["count"] for r in reactions.values())
    
    return reactions, total


# ============================================================================
# Reply/Thread Support
# ============================================================================

def get_reply_info(db: Session, message_id: int) -> Optional[Dict]:
    """Get info about a message for reply preview (public API)."""
    return _get_reply_info(db, message_id)

def send_reply(
    db: Session,
    conversation_id: int,
    sender_id: int,
    content: str,
    reply_to_id: int,
    message_type: str = "text",
    attachment_data: Optional[dict] = None
) -> Tuple[Optional[Message], str]:
    """Send a reply to a specific message."""
    # Check the message being replied to exists
    original = db.query(Message).filter(
        Message.id == reply_to_id,
        Message.conversation_id == conversation_id,
        Message.is_deleted == "false"
    ).first()
    
    if not original:
        return None, "Original message not found"
    
    # Check sender is participant
    if not is_conversation_participant(db, conversation_id, sender_id):
        return None, "You are not a participant in this conversation"
    
    # Create reply message
    message = Message(
        conversation_id=conversation_id,
        sender_id=sender_id,
        content=content,
        message_type=message_type,
        attachment_data=attachment_data,
        reply_to_id=reply_to_id
    )
    
    db.add(message)
    
    # Update conversation last_message_at
    conversation = db.query(Conversation).filter(Conversation.id == conversation_id).first()
    if conversation:
        conversation.last_message_at = datetime.utcnow()
    
    # Update sender's last_read_at
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == sender_id
    ).first()
    if participant:
        participant.last_read_at = datetime.utcnow()
    
    db.commit()
    db.refresh(message)
    
    return message, ""


# ============================================================================
# Message Pinning
# ============================================================================

def pin_message(
    db: Session,
    conversation_id: int,
    message_id: int,
    user_id: int
) -> Tuple[Optional[PinnedMessage], str]:
    """Pin a message in a conversation."""
    # Check user is participant
    if not is_conversation_participant(db, conversation_id, user_id):
        return None, "You are not a participant in this conversation"
    
    # Check message exists and belongs to conversation
    message = db.query(Message).filter(
        Message.id == message_id,
        Message.conversation_id == conversation_id,
        Message.is_deleted == "false"
    ).first()
    
    if not message:
        return None, "Message not found"
    
    # Check if already pinned
    existing = db.query(PinnedMessage).filter(
        PinnedMessage.conversation_id == conversation_id,
        PinnedMessage.message_id == message_id
    ).first()
    
    if existing:
        return None, "Message is already pinned"
    
    # Check pin limit (max 50 per conversation)
    pin_count = db.query(PinnedMessage).filter(
        PinnedMessage.conversation_id == conversation_id
    ).count()
    
    if pin_count >= 50:
        return None, "Maximum pinned messages limit reached (50)"
    
    # Create pin
    pinned = PinnedMessage(
        conversation_id=conversation_id,
        message_id=message_id,
        pinned_by=user_id
    )
    db.add(pinned)
    db.commit()
    db.refresh(pinned)
    
    return pinned, ""


def unpin_message(
    db: Session,
    conversation_id: int,
    message_id: int,
    user_id: int
) -> Tuple[bool, str]:
    """Unpin a message from a conversation."""
    # Check user is participant
    if not is_conversation_participant(db, conversation_id, user_id):
        return False, "You are not a participant in this conversation"
    
    # Find the pin
    pinned = db.query(PinnedMessage).filter(
        PinnedMessage.conversation_id == conversation_id,
        PinnedMessage.message_id == message_id
    ).first()
    
    if not pinned:
        return False, "Message is not pinned"
    
    db.delete(pinned)
    db.commit()
    
    return True, ""


def get_pinned_messages(
    db: Session,
    conversation_id: int,
    user_id: int
) -> Tuple[List[Dict], str]:
    """Get all pinned messages in a conversation."""
    # Check user is participant
    if not is_conversation_participant(db, conversation_id, user_id):
        return [], "You are not a participant in this conversation"
    
    pinned = db.query(PinnedMessage).filter(
        PinnedMessage.conversation_id == conversation_id
    ).order_by(desc(PinnedMessage.pinned_at)).all()
    
    result = []
    for p in pinned:
        msg = db.query(Message).filter(Message.id == p.message_id).first()
        pinner = db.query(User).filter(User.id == p.pinned_by).first() if p.pinned_by else None
        sender = db.query(User).filter(User.id == msg.sender_id).first() if msg else None
        
        if msg:
            result.append({
                "id": p.id,
                "message_id": p.message_id,
                "conversation_id": p.conversation_id,
                "pinned_by": p.pinned_by,
                "pinned_by_username": pinner.username if pinner else None,
                "pinned_at": p.pinned_at,
                "message_content": msg.content if msg.is_deleted == "false" else "[Deleted]",
                "message_sender_username": sender.username if sender else "Unknown",
                "message_created_at": msg.created_at
            })
    
    return result, ""


# ============================================================================
# Message Forwarding
# ============================================================================

def forward_message(
    db: Session,
    message_id: int,
    user_id: int,
    target_conversation_ids: List[int],
    include_original_sender: bool = True
) -> Tuple[List[int], List[int], str]:
    """Forward a message to multiple conversations. Returns (success_ids, failed_ids, error)."""
    # Get original message
    original = db.query(Message).filter(
        Message.id == message_id,
        Message.is_deleted == "false"
    ).first()
    
    if not original:
        return [], target_conversation_ids, "Original message not found"
    
    # Check user can see original message
    if not is_conversation_participant(db, original.conversation_id, user_id):
        return [], target_conversation_ids, "You cannot access this message"
    
    original_sender = db.query(User).filter(User.id == original.sender_id).first()
    
    success_ids = []
    failed_ids = []
    
    for conv_id in target_conversation_ids:
        # Check user is participant in target conversation
        if not is_conversation_participant(db, conv_id, user_id):
            failed_ids.append(conv_id)
            continue
        
        # Build forwarded message content
        if include_original_sender and original_sender:
            forward_prefix = f"[Forwarded from {original_sender.username}]\n"
        else:
            forward_prefix = "[Forwarded]\n"
        
        fwd_content = forward_prefix + original.content
        
        # Build attachment data with forward info
        fwd_attachment = original.attachment_data.copy() if original.attachment_data else {}
        fwd_attachment["forwarded"] = {
            "original_message_id": original.id,
            "original_sender_username": original_sender.username if original_sender else None,
            "original_conversation_id": original.conversation_id,
            "forwarded_at": datetime.utcnow().isoformat()
        }
        
        # Create forwarded message
        fwd_msg = Message(
            conversation_id=conv_id,
            sender_id=user_id,
            content=fwd_content,
            message_type=original.message_type,
            attachment_data=fwd_attachment
        )
        db.add(fwd_msg)
        
        # Update conversation timestamp
        conv = db.query(Conversation).filter(Conversation.id == conv_id).first()
        if conv:
            conv.last_message_at = datetime.utcnow()
        
        success_ids.append(conv_id)
    
    if success_ids:
        db.commit()
    
    return success_ids, failed_ids, ""


# ============================================================================
# Read Receipts
# ============================================================================

def update_read_receipt(
    db: Session,
    conversation_id: int,
    user_id: int,
    message_id: int
) -> Tuple[Optional[MessageReadReceipt], str]:
    """Update user's read receipt for a conversation."""
    # Check user is participant
    if not is_conversation_participant(db, conversation_id, user_id):
        return None, "You are not a participant in this conversation"
    
    # Check message exists and belongs to conversation
    msg = db.query(Message).filter(
        Message.id == message_id,
        Message.conversation_id == conversation_id
    ).first()
    
    if not msg:
        return None, "Message not found"
    
    # Find or create read receipt
    receipt = db.query(MessageReadReceipt).filter(
        MessageReadReceipt.conversation_id == conversation_id,
        MessageReadReceipt.user_id == user_id
    ).first()
    
    if receipt:
        # Only update if new message is newer
        if message_id > receipt.last_read_message_id:
            receipt.last_read_message_id = message_id
            receipt.read_at = datetime.utcnow()
    else:
        receipt = MessageReadReceipt(
            conversation_id=conversation_id,
            user_id=user_id,
            last_read_message_id=message_id
        )
        db.add(receipt)
    
    db.commit()
    db.refresh(receipt)
    
    return receipt, ""


def get_conversation_read_receipts(
    db: Session,
    conversation_id: int,
    user_id: int
) -> Tuple[List[Dict], str]:
    """Get read receipts for all participants in a conversation."""
    # Check user is participant
    if not is_conversation_participant(db, conversation_id, user_id):
        return [], "You are not a participant in this conversation"
    
    receipts = db.query(MessageReadReceipt).filter(
        MessageReadReceipt.conversation_id == conversation_id
    ).all()
    
    result = []
    for r in receipts:
        u = db.query(User).filter(User.id == r.user_id).first()
        if u:
            result.append({
                "user_id": r.user_id,
                "username": u.username,
                "avatar_url": u.avatar_url,
                "last_read_message_id": r.last_read_message_id,
                "read_at": r.read_at
            })
    
    return result, ""


def get_message_read_by(
    db: Session,
    conversation_id: int,
    message_id: int,
    user_id: int
) -> Tuple[List[Dict], int, str]:
    """Get list of users who have read a specific message."""
    # Check user is participant
    if not is_conversation_participant(db, conversation_id, user_id):
        return [], 0, "You are not a participant in this conversation"
    
    # Get participants count
    participant_count = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id
    ).count()
    
    # Get receipts where last_read_message_id >= message_id
    receipts = db.query(MessageReadReceipt).filter(
        MessageReadReceipt.conversation_id == conversation_id,
        MessageReadReceipt.last_read_message_id >= message_id
    ).all()
    
    result = []
    for r in receipts:
        u = db.query(User).filter(User.id == r.user_id).first()
        if u and u.id != user_id:  # Exclude current user
            result.append({
                "user_id": r.user_id,
                "username": u.username,
                "avatar_url": u.avatar_url,
                "last_read_message_id": r.last_read_message_id,
                "read_at": r.read_at
            })
    
    return result, participant_count, ""


# ============================================================================
# Mention Detection
# ============================================================================

# Regex pattern for @mentions: @username (alphanumeric and underscore)
MENTION_PATTERN = re.compile(r'@(\w+)')


def parse_mentions(content: str) -> List[str]:
    """Extract @mentions from message content."""
    return MENTION_PATTERN.findall(content)


def resolve_mentions(
    db: Session,
    content: str,
    conversation_id: int
) -> List[Dict]:
    """Parse mentions and resolve to user IDs (only participants)."""
    usernames = parse_mentions(content)
    if not usernames:
        return []
    
    # Get conversation participants
    participants = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id
    ).all()
    participant_ids = {p.user_id for p in participants}
    
    # Find users with matching usernames who are participants
    users = db.query(User).filter(
        User.username.in_(usernames)
    ).all()
    
    mentions = []
    for u in users:
        if u.id in participant_ids:
            # Find position in content
            pattern = f"@{u.username}"
            for match in re.finditer(re.escape(pattern), content, re.IGNORECASE):
                mentions.append({
                    "user_id": u.id,
                    "username": u.username,
                    "start_index": match.start(),
                    "end_index": match.end()
                })
    
    return mentions


def get_mentioned_user_ids(
    db: Session,
    content: str,
    conversation_id: int
) -> List[int]:
    """Get list of user IDs mentioned in content (only participants)."""
    mentions = resolve_mentions(db, content, conversation_id)
    return list(set(m["user_id"] for m in mentions))


def format_mentions_for_notification(
    db: Session,
    msg: Message,
    mentioned_user_ids: List[int]
) -> Dict[int, str]:
    """Create notification text for each mentioned user."""
    sender = db.query(User).filter(User.id == msg.sender_id).first()
    sender_name = sender.username if sender else "Someone"
    
    preview = msg.content[:100] + ("..." if len(msg.content) > 100 else "")
    
    notifications = {}
    for uid in mentioned_user_ids:
        notifications[uid] = f"{sender_name} mentioned you: {preview}"
    
    return notifications


# ============================================================================
# Message Search
# ============================================================================

def search_messages(
    db: Session,
    user_id: int,
    query: str,
    conversation_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 50
) -> Tuple[List[Dict], int, bool]:
    """
    Search messages in conversations the user is part of.
    Returns (results, total_count, has_more).
    """
    if not query or len(query) < 2:
        return [], 0, False
    
    # Get conversations user is part of
    user_conversations = db.query(ConversationParticipant.conversation_id).filter(
        ConversationParticipant.user_id == user_id
    ).subquery()
    
    # Base query
    base_query = db.query(Message).join(
        Conversation, Message.conversation_id == Conversation.id
    ).filter(
        Message.conversation_id.in_(user_conversations),
        Message.is_deleted != "true",
        Message.content.ilike(f"%{query}%")
    )
    
    # Filter by specific conversation if provided
    if conversation_id:
        base_query = base_query.filter(Message.conversation_id == conversation_id)
    
    # Get total count
    total = base_query.count()
    
    # Get results with ordering
    messages = base_query.order_by(
        desc(Message.created_at)
    ).offset(skip).limit(limit + 1).all()
    
    has_more = len(messages) > limit
    messages = messages[:limit]
    
    # Build results
    results = []
    for msg in messages:
        conversation = db.query(Conversation).filter(Conversation.id == msg.conversation_id).first()
        sender = db.query(User).filter(User.id == msg.sender_id).first()
        
        # Create highlighted content with <mark> tags for frontend display
        content_lower = msg.content.lower()
        query_lower = query.lower()
        highlight_start = content_lower.find(query_lower)
        
        if highlight_start >= 0:
            # Get context around the match
            start = max(0, highlight_start - 30)
            end = min(len(msg.content), highlight_start + len(query) + 30)
            
            # Build snippet with highlight
            prefix = "..." if start > 0 else ""
            suffix = "..." if end < len(msg.content) else ""
            
            # Escape HTML in the content first
            before_match = html.escape(msg.content[start:highlight_start])
            match_text = html.escape(msg.content[highlight_start:highlight_start + len(query)])
            after_match = html.escape(msg.content[highlight_start + len(query):end])
            
            highlighted_content = f"{prefix}{before_match}<mark>{match_text}</mark>{after_match}{suffix}"
        else:
            highlighted_content = html.escape(msg.content[:100]) + ("..." if len(msg.content) > 100 else "")
        
        results.append({
            "message_id": msg.id,
            "conversation_id": msg.conversation_id,
            "conversation_name": conversation.name if conversation else None,
            "sender_username": sender.username if sender else "Unknown",
            "content": msg.content,
            "highlighted_content": highlighted_content,
            "message_type": msg.message_type,
            "created_at": msg.created_at,
        })
    
    return results, total, has_more


# ============================================================================
# Poll Functions
# ============================================================================

from backend.models.models import Poll, PollOption, PollVote


def create_poll(
    db: Session,
    conversation_id: int,
    creator_id: int,
    question: str,
    options: List[str],
    poll_type: str = "single",
    is_anonymous: bool = False,
    allow_add_options: bool = False,
    closes_at: Optional[datetime] = None
) -> Tuple[Optional[Poll], Optional[Message], str]:
    """Create a poll in a conversation."""
    # Verify participant
    if not is_conversation_participant(db, conversation_id, creator_id):
        return None, None, "Not a participant"
    
    # Create the poll
    poll = Poll(
        conversation_id=conversation_id,
        created_by=creator_id,
        question=question,
        poll_type=poll_type,
        is_anonymous="true" if is_anonymous else "false",
        allow_add_options="true" if allow_add_options else "false",
        closes_at=closes_at
    )
    db.add(poll)
    db.flush()
    
    # Add options
    for option_text in options:
        option = PollOption(
            poll_id=poll.id,
            text=option_text.strip(),
            added_by=creator_id
        )
        db.add(option)
    
    # Create associated message
    message = Message(
        conversation_id=conversation_id,
        sender_id=creator_id,
        content=f"📊 Poll: {question}",
        message_type="poll"
    )
    db.add(message)
    db.flush()
    
    # Link poll to message
    poll.message_id = message.id
    
    db.commit()
    db.refresh(poll)
    
    return poll, message, ""


def get_poll(
    db: Session,
    poll_id: int,
    user_id: int
) -> Optional[Dict]:
    """Get poll with vote counts and user's vote status."""
    poll = db.query(Poll).filter(Poll.id == poll_id).first()
    if not poll:
        return None
    
    # Verify user is participant
    if not is_conversation_participant(db, poll.conversation_id, user_id):
        return None
    
    creator = db.query(User).filter(User.id == poll.created_by).first()
    is_anonymous = poll.is_anonymous == "true"
    
    # Get options with votes - first pass to count total
    options_data = []
    total_votes = 0
    voters_set = set()
    user_voted = False
    option_vote_counts = []
    
    for option in poll.options:
        votes = db.query(PollVote).filter(PollVote.option_id == option.id).all()
        vote_count = len(votes)
        total_votes += vote_count
        
        voters = []
        has_voted = False
        for vote in votes:
            voters_set.add(vote.user_id)
            if vote.user_id == user_id:
                has_voted = True
                user_voted = True
            if not is_anonymous:
                voter = db.query(User).filter(User.id == vote.user_id).first()
                if voter:
                    voters.append(voter.username)
        
        added_by_user = db.query(User).filter(User.id == option.added_by).first() if option.added_by else None
        
        option_vote_counts.append({
            "id": option.id,
            "text": option.text,
            "vote_count": vote_count,
            "voters": voters if not is_anonymous else [],
            "has_voted": has_voted,
            "added_by_username": added_by_user.username if added_by_user else None
        })
    
    # Second pass to calculate percentages
    for opt_data in option_vote_counts:
        opt_data["percentage"] = (opt_data["vote_count"] / total_votes * 100) if total_votes > 0 else 0
        options_data.append(opt_data)
    
    return {
        "id": poll.id,
        "conversation_id": poll.conversation_id,
        "message_id": poll.message_id,
        "question": poll.question,
        "poll_type": poll.poll_type,
        "is_anonymous": is_anonymous,
        "allow_add_options": poll.allow_add_options == "true",
        "closes_at": poll.closes_at,
        "is_closed": poll.is_closed == "true",
        "created_by": poll.created_by,
        "created_by_username": creator.username if creator else None,
        "created_at": poll.created_at,
        "total_votes": total_votes,
        "total_voters": len(voters_set),
        "options": options_data,
        "has_voted": user_voted
    }


def vote_on_poll(
    db: Session,
    poll_id: int,
    user_id: int,
    option_ids: List[int]
) -> Tuple[bool, str]:
    """Vote on a poll. Returns (success, error_message)."""
    poll = db.query(Poll).filter(Poll.id == poll_id).first()
    if not poll:
        return False, "Poll not found"
    
    # Check if poll is closed
    if poll.is_closed == "true":
        return False, "Poll is closed"
    
    if poll.closes_at and datetime.utcnow() > poll.closes_at:
        poll.is_closed = "true"
        db.commit()
        return False, "Poll has expired"
    
    # Verify participant
    if not is_conversation_participant(db, poll.conversation_id, user_id):
        return False, "Not a participant"
    
    # Validate option IDs
    valid_option_ids = {o.id for o in poll.options}
    for opt_id in option_ids:
        if opt_id not in valid_option_ids:
            return False, f"Invalid option ID: {opt_id}"
    
    # Check poll type
    if poll.poll_type == "single" and len(option_ids) > 1:
        return False, "Only one choice allowed"
    
    # Remove existing votes for this user on this poll
    existing_votes = db.query(PollVote).join(PollOption).filter(
        PollOption.poll_id == poll_id,
        PollVote.user_id == user_id
    ).all()
    
    for vote in existing_votes:
        db.delete(vote)
    
    # Add new votes
    for opt_id in option_ids:
        vote = PollVote(
            option_id=opt_id,
            user_id=user_id
        )
        db.add(vote)
    
    db.commit()
    return True, ""


def add_poll_option(
    db: Session,
    poll_id: int,
    user_id: int,
    text: str
) -> Tuple[Optional[PollOption], str]:
    """Add an option to a poll (if allowed)."""
    poll = db.query(Poll).filter(Poll.id == poll_id).first()
    if not poll:
        return None, "Poll not found"
    
    if poll.allow_add_options != "true":
        return None, "Adding options not allowed"
    
    if poll.is_closed == "true":
        return None, "Poll is closed"
    
    if not is_conversation_participant(db, poll.conversation_id, user_id):
        return None, "Not a participant"
    
    # Check for duplicate
    existing = db.query(PollOption).filter(
        PollOption.poll_id == poll_id,
        func.lower(PollOption.text) == text.lower().strip()
    ).first()
    if existing:
        return None, "Option already exists"
    
    option = PollOption(
        poll_id=poll_id,
        text=text.strip(),
        added_by=user_id
    )
    db.add(option)
    db.commit()
    db.refresh(option)
    
    return option, ""


def close_poll(
    db: Session,
    poll_id: int,
    user_id: int
) -> Tuple[bool, str]:
    """Close a poll (only creator can close)."""
    poll = db.query(Poll).filter(Poll.id == poll_id).first()
    if not poll:
        return False, "Poll not found"
    
    if poll.created_by != user_id:
        # Check if admin
        if not is_group_admin(db, poll.conversation_id, user_id):
            return False, "Only creator or admin can close poll"
    
    poll.is_closed = "true"
    db.commit()
    
    return True, ""


def get_conversation_polls(
    db: Session,
    conversation_id: int,
    user_id: int,
    include_closed: bool = True
) -> List[Dict]:
    """Get all polls in a conversation."""
    if not is_conversation_participant(db, conversation_id, user_id):
        return []
    
    query = db.query(Poll).filter(Poll.conversation_id == conversation_id)
    if not include_closed:
        query = query.filter(Poll.is_closed != "true")
    
    polls = query.order_by(desc(Poll.created_at)).all()
    
    return [get_poll(db, p.id, user_id) for p in polls]


# ============================================================================
# Mute Conversation Functions
# ============================================================================

def mute_conversation(
    db: Session,
    conversation_id: int,
    user_id: int,
    mute: bool,
    duration_hours: Optional[int] = None
) -> Tuple[bool, Optional[datetime], str]:
    """
    Mute or unmute a conversation.
    Returns (is_muted, muted_until, error).
    """
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).first()
    
    if not participant:
        return False, None, "Not a participant"
    
    if mute:
        participant.is_muted = "true"
        if duration_hours:
            participant.muted_until = datetime.utcnow() + timedelta(hours=duration_hours)
        else:
            participant.muted_until = None  # Muted forever
    else:
        participant.is_muted = "false"
        participant.muted_until = None
    
    db.commit()
    
    return participant.is_muted == "true", participant.muted_until, ""


def get_mute_status(
    db: Session,
    conversation_id: int,
    user_id: int
) -> Tuple[bool, Optional[datetime]]:
    """Get mute status for a conversation."""
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).first()
    
    if not participant:
        return False, None
    
    is_muted = participant.is_muted == "true"
    
    # Check if mute has expired
    if is_muted and participant.muted_until:
        if datetime.utcnow() > participant.muted_until:
            # Auto-unmute
            participant.is_muted = "false"
            participant.muted_until = None
            db.commit()
            return False, None
    
    return is_muted, participant.muted_until


def is_conversation_muted(
    db: Session,
    conversation_id: int,
    user_id: int
) -> bool:
    """Check if conversation is muted for user (respects expiry)."""
    is_muted, _ = get_mute_status(db, conversation_id, user_id)
    return is_muted


# ============================================================================
# Delete/Leave Conversation Functions
# ============================================================================

def delete_conversation(
    db: Session,
    conversation_id: int,
    user_id: int
) -> Tuple[bool, str]:
    """
    Delete or leave a conversation.
    - For DMs: Both users can delete; it removes the user from the conversation.
               If both users leave, the conversation is fully deleted.
    - For groups: Non-owners leave the group. Owners must transfer ownership first
                  or the group is deleted if they're the only member.
    """
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id
    ).first()
    
    if not conversation:
        return False, "Conversation not found"
    
    # Check user is a participant
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == user_id
    ).first()
    
    if not participant:
        return False, "You are not a participant in this conversation"
    
    is_group = conversation.is_group == "true"
    
    if is_group:
        # For groups, check if owner
        if participant.role == "owner":
            # Count other participants
            other_count = db.query(ConversationParticipant).filter(
                ConversationParticipant.conversation_id == conversation_id,
                ConversationParticipant.user_id != user_id
            ).count()
            
            if other_count > 0:
                return False, "Transfer ownership before leaving, or remove all members first"
            
            # Owner is the only member - delete the entire conversation
            _delete_conversation_completely(db, conversation_id)
            return True, "Group deleted"
        else:
            # Non-owner can just leave
            db.query(ConversationParticipant).filter(
                ConversationParticipant.conversation_id == conversation_id,
                ConversationParticipant.user_id == user_id
            ).delete()
            db.commit()
            return True, "You have left the group"
    else:
        # For DMs
        # Remove user from conversation
        db.query(ConversationParticipant).filter(
            ConversationParticipant.conversation_id == conversation_id,
            ConversationParticipant.user_id == user_id
        ).delete()
        
        # Check if any participants remain
        remaining = db.query(ConversationParticipant).filter(
            ConversationParticipant.conversation_id == conversation_id
        ).count()
        
        if remaining == 0:
            # No one left - delete everything
            _delete_conversation_completely(db, conversation_id)
            return True, "Conversation deleted"
        
        db.commit()
        return True, "Conversation deleted for you"


def _delete_conversation_completely(db: Session, conversation_id: int) -> None:
    """Internal function to completely delete a conversation and all associated data."""
    from backend.models.models import Poll, PollOption, PollVote
    
    # Delete poll votes
    poll_ids = [p.id for p in db.query(Poll.id).filter(Poll.conversation_id == conversation_id).all()]
    if poll_ids:
        option_ids = [o.id for o in db.query(PollOption.id).filter(PollOption.poll_id.in_(poll_ids)).all()]
        if option_ids:
            db.query(PollVote).filter(PollVote.option_id.in_(option_ids)).delete(synchronize_session=False)
        db.query(PollOption).filter(PollOption.poll_id.in_(poll_ids)).delete(synchronize_session=False)
        db.query(Poll).filter(Poll.id.in_(poll_ids)).delete(synchronize_session=False)
    
    # Delete message-related data
    message_ids = [m.id for m in db.query(Message.id).filter(Message.conversation_id == conversation_id).all()]
    if message_ids:
        db.query(MessageReaction).filter(MessageReaction.message_id.in_(message_ids)).delete(synchronize_session=False)
        db.query(PinnedMessage).filter(PinnedMessage.message_id.in_(message_ids)).delete(synchronize_session=False)
        db.query(MessageReadReceipt).filter(MessageReadReceipt.message_id.in_(message_ids)).delete(synchronize_session=False)
    
    # Delete messages
    db.query(Message).filter(Message.conversation_id == conversation_id).delete(synchronize_session=False)
    
    # Delete participants
    db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id
    ).delete(synchronize_session=False)
    
    # Delete conversation
    db.query(Conversation).filter(Conversation.id == conversation_id).delete(synchronize_session=False)
    
    db.commit()
    logger.info(f"Conversation {conversation_id} completely deleted")


# ============================================================================
# Message Bookmark Functions
# ============================================================================

from backend.models.models import MessageBookmark, MessageEditHistory


def add_bookmark(
    db: Session,
    user_id: int,
    message_id: int,
    note: Optional[str] = None
) -> Tuple[Optional[Dict], str]:
    """Add a bookmark to a message."""
    # Get message and verify access
    message = db.query(Message).filter(
        Message.id == message_id,
        Message.is_deleted == "false"
    ).first()
    
    if not message:
        return None, "Message not found"
    
    if not is_conversation_participant(db, message.conversation_id, user_id):
        return None, "You are not a participant in this conversation"
    
    # Check if already bookmarked
    existing = db.query(MessageBookmark).filter(
        MessageBookmark.user_id == user_id,
        MessageBookmark.message_id == message_id
    ).first()
    
    if existing:
        return None, "Message is already bookmarked"
    
    # Create bookmark
    bookmark = MessageBookmark(
        user_id=user_id,
        message_id=message_id,
        note=note
    )
    db.add(bookmark)
    db.commit()
    db.refresh(bookmark)
    
    return _format_bookmark(db, bookmark), ""


def update_bookmark(
    db: Session,
    user_id: int,
    bookmark_id: int,
    note: Optional[str]
) -> Tuple[Optional[Dict], str]:
    """Update a bookmark's note."""
    bookmark = db.query(MessageBookmark).filter(
        MessageBookmark.id == bookmark_id,
        MessageBookmark.user_id == user_id
    ).first()
    
    if not bookmark:
        return None, "Bookmark not found"
    
    bookmark.note = note
    db.commit()
    db.refresh(bookmark)
    
    return _format_bookmark(db, bookmark), ""


def remove_bookmark(
    db: Session,
    user_id: int,
    message_id: int
) -> Tuple[bool, str]:
    """Remove a bookmark from a message."""
    bookmark = db.query(MessageBookmark).filter(
        MessageBookmark.user_id == user_id,
        MessageBookmark.message_id == message_id
    ).first()
    
    if not bookmark:
        return False, "Bookmark not found"
    
    db.delete(bookmark)
    db.commit()
    
    return True, ""


def get_user_bookmarks(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 50
) -> Tuple[List[Dict], int]:
    """Get all bookmarks for a user."""
    query = db.query(MessageBookmark).filter(
        MessageBookmark.user_id == user_id
    ).order_by(desc(MessageBookmark.created_at))
    
    total = query.count()
    bookmarks = query.offset(skip).limit(limit).all()
    
    return [_format_bookmark(db, b) for b in bookmarks], total


def is_message_bookmarked(
    db: Session,
    user_id: int,
    message_id: int
) -> bool:
    """Check if a message is bookmarked by the user."""
    return db.query(MessageBookmark).filter(
        MessageBookmark.user_id == user_id,
        MessageBookmark.message_id == message_id
    ).first() is not None


def _format_bookmark(db: Session, bookmark: MessageBookmark) -> Dict:
    """Format bookmark for response."""
    message = db.query(Message).filter(Message.id == bookmark.message_id).first()
    sender = db.query(User).filter(User.id == message.sender_id).first() if message else None
    conversation = db.query(Conversation).filter(Conversation.id == message.conversation_id).first() if message else None
    
    return {
        "id": bookmark.id,
        "user_id": bookmark.user_id,
        "message_id": bookmark.message_id,
        "conversation_id": message.conversation_id if message else None,
        "conversation_name": conversation.name if conversation else None,
        "message_content": message.content if message else "[Deleted]",
        "message_sender_username": sender.username if sender else "Unknown",
        "message_sender_avatar_url": sender.avatar_url if sender else None,
        "message_type": message.message_type if message else "text",
        "message_created_at": message.created_at if message else None,
        "note": bookmark.note,
        "created_at": bookmark.created_at
    }


# ============================================================================
# Message Edit History Functions
# ============================================================================

def save_edit_history(
    db: Session,
    message_id: int,
    previous_content: str
) -> MessageEditHistory:
    """Save the previous content before an edit."""
    # Get current edit count
    current_count = db.query(MessageEditHistory).filter(
        MessageEditHistory.message_id == message_id
    ).count()
    
    history_entry = MessageEditHistory(
        message_id=message_id,
        previous_content=previous_content,
        edit_number=current_count + 1
    )
    db.add(history_entry)
    db.commit()
    db.refresh(history_entry)
    
    return history_entry


def get_message_edit_history(
    db: Session,
    message_id: int,
    user_id: int
) -> Tuple[Optional[Dict], str]:
    """Get the edit history for a message."""
    message = db.query(Message).filter(Message.id == message_id).first()
    
    if not message:
        return None, "Message not found"
    
    # Check user is in the conversation
    if not is_conversation_participant(db, message.conversation_id, user_id):
        return None, "You are not a participant in this conversation"
    
    # Get edit history
    history = db.query(MessageEditHistory).filter(
        MessageEditHistory.message_id == message_id
    ).order_by(desc(MessageEditHistory.edit_number)).all()
    
    return {
        "message_id": message_id,
        "current_content": message.content,
        "edit_count": len(history),
        "history": [
            {
                "id": h.id,
                "message_id": h.message_id,
                "previous_content": h.previous_content,
                "edited_at": h.edited_at,
                "edit_number": h.edit_number
            }
            for h in history
        ]
    }, ""