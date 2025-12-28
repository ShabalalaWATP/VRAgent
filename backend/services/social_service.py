"""Service for social features: user search, friend requests, and friendships."""
from datetime import datetime
from typing import List, Optional, Tuple

from sqlalchemy import or_, and_, func, desc
from sqlalchemy.orm import Session, joinedload

from backend.core.logging import get_logger
from backend.models.models import User, FriendRequest, Friendship, UserNote

logger = get_logger(__name__)


# ============================================================================
# User Search
# ============================================================================

def get_suggested_users(
    db: Session,
    current_user_id: int,
    skip: int = 0,
    limit: int = 20,
) -> Tuple[List[dict], int]:
    """
    Get suggested users to connect with.
    Returns all approved users except the current user, ordered by most recent.
    """
    # Get IDs of users who are already friends
    friend_ids = set()
    friendships = db.query(Friendship).filter(
        or_(
            Friendship.user1_id == current_user_id,
            Friendship.user2_id == current_user_id
        )
    ).all()
    for f in friendships:
        if f.user1_id == current_user_id:
            friend_ids.add(f.user2_id)
        else:
            friend_ids.add(f.user1_id)
    
    # Base query - exclude current user and only approved users
    base_query = db.query(User).filter(
        User.id != current_user_id,
        User.status == "approved",
    )
    
    total = base_query.count()
    users = base_query.order_by(desc(User.created_at)).offset(skip).limit(limit).all()
    
    # Get friendship status for each user
    result = []
    for user in users:
        friendship_info = get_friendship_status(db, current_user_id, user.id)
        result.append({
            "id": user.id,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "bio": user.bio,
            "avatar_url": user.avatar_url,
            "created_at": user.created_at,
            **friendship_info
        })
    
    return result, total


def search_users(
    db: Session,
    query: str,
    current_user_id: int,
    skip: int = 0,
    limit: int = 20,
    exclude_friends: bool = False
) -> Tuple[List[dict], int]:
    """
    Search for users by username, first name, or last name.
    Returns users with their friendship status relative to current user.
    """
    search_term = f"%{query.lower()}%"
    
    # Base query - exclude current user and only approved users
    base_query = db.query(User).filter(
        User.id != current_user_id,
        User.status == "approved",
        or_(
            func.lower(User.username).like(search_term),
            func.lower(User.first_name).like(search_term),
            func.lower(User.last_name).like(search_term),
        )
    )
    
    total = base_query.count()
    users = base_query.offset(skip).limit(limit).all()
    
    # Get friendship status for each user
    result = []
    for user in users:
        friendship_info = get_friendship_status(db, current_user_id, user.id)
        
        # Skip friends if requested
        if exclude_friends and friendship_info["is_friend"]:
            continue
            
        result.append({
            "id": user.id,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "bio": user.bio,
            "avatar_url": user.avatar_url,
            "created_at": user.created_at,
            **friendship_info
        })
    
    return result, total


def get_user_public_profile(
    db: Session,
    user_id: int,
    current_user_id: int
) -> Optional[dict]:
    """Get public profile of a user with friendship status."""
    user = db.query(User).filter(
        User.id == user_id,
        User.status == "approved"
    ).first()
    
    if not user:
        return None
    
    friendship_info = get_friendship_status(db, current_user_id, user_id)
    
    return {
        "id": user.id,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "bio": user.bio,
        "avatar_url": user.avatar_url,
        "created_at": user.created_at,
        **friendship_info
    }


def get_friendship_status(db: Session, user1_id: int, user2_id: int) -> dict:
    """Check friendship status between two users."""
    # Check if they're friends
    friendship = db.query(Friendship).filter(
        or_(
            and_(Friendship.user1_id == user1_id, Friendship.user2_id == user2_id),
            and_(Friendship.user1_id == user2_id, Friendship.user2_id == user1_id)
        )
    ).first()
    
    if friendship:
        return {
            "is_friend": True,
            "has_pending_request": False,
            "request_direction": None
        }
    
    # Check for pending friend request
    pending_request = db.query(FriendRequest).filter(
        FriendRequest.status == "pending",
        or_(
            and_(FriendRequest.sender_id == user1_id, FriendRequest.receiver_id == user2_id),
            and_(FriendRequest.sender_id == user2_id, FriendRequest.receiver_id == user1_id)
        )
    ).first()
    
    if pending_request:
        direction = "sent" if pending_request.sender_id == user1_id else "received"
        return {
            "is_friend": False,
            "has_pending_request": True,
            "request_direction": direction
        }
    
    return {
        "is_friend": False,
        "has_pending_request": False,
        "request_direction": None
    }


# ============================================================================
# Friend Requests
# ============================================================================

def create_friend_request(
    db: Session,
    sender_id: int,
    receiver_id: int,
    message: Optional[str] = None
) -> Tuple[Optional[FriendRequest], str]:
    """
    Create a friend request.
    Returns (request, error_message).
    """
    # Can't send request to yourself
    if sender_id == receiver_id:
        return None, "Cannot send friend request to yourself"
    
    # Check receiver exists and is approved
    receiver = db.query(User).filter(
        User.id == receiver_id,
        User.status == "approved"
    ).first()
    
    if not receiver:
        return None, "User not found"
    
    # Check if already friends
    existing_friendship = db.query(Friendship).filter(
        or_(
            and_(Friendship.user1_id == sender_id, Friendship.user2_id == receiver_id),
            and_(Friendship.user1_id == receiver_id, Friendship.user2_id == sender_id)
        )
    ).first()
    
    if existing_friendship:
        return None, "Already friends with this user"
    
    # Check for existing pending request in either direction
    existing_request = db.query(FriendRequest).filter(
        FriendRequest.status == "pending",
        or_(
            and_(FriendRequest.sender_id == sender_id, FriendRequest.receiver_id == receiver_id),
            and_(FriendRequest.sender_id == receiver_id, FriendRequest.receiver_id == sender_id)
        )
    ).first()
    
    if existing_request:
        if existing_request.sender_id == sender_id:
            return None, "Friend request already sent"
        else:
            # They sent us a request, auto-accept by accepting theirs
            return None, "This user already sent you a request. Check your incoming requests."
    
    # Create the request
    friend_request = FriendRequest(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message=message,
        status="pending"
    )
    
    db.add(friend_request)
    db.commit()
    db.refresh(friend_request)
    
    logger.info(f"Friend request created: {sender_id} -> {receiver_id}")
    return friend_request, ""


def get_friend_requests(
    db: Session,
    user_id: int
) -> Tuple[List[dict], List[dict]]:
    """Get incoming and outgoing friend requests for a user."""
    # Incoming requests
    incoming = db.query(FriendRequest).options(
        joinedload(FriendRequest.sender)
    ).filter(
        FriendRequest.receiver_id == user_id,
        FriendRequest.status == "pending"
    ).order_by(FriendRequest.created_at.desc()).all()
    
    # Outgoing requests
    outgoing = db.query(FriendRequest).options(
        joinedload(FriendRequest.receiver)
    ).filter(
        FriendRequest.sender_id == user_id,
        FriendRequest.status == "pending"
    ).order_by(FriendRequest.created_at.desc()).all()
    
    incoming_list = []
    for req in incoming:
        incoming_list.append({
            "id": req.id,
            "sender_id": req.sender_id,
            "receiver_id": req.receiver_id,
            "sender_username": req.sender.username,
            "receiver_username": "",  # Not needed for incoming
            "sender_first_name": req.sender.first_name,
            "sender_last_name": req.sender.last_name,
            "receiver_first_name": None,
            "receiver_last_name": None,
            "status": req.status,
            "message": req.message,
            "created_at": req.created_at,
            "responded_at": req.responded_at
        })
    
    outgoing_list = []
    for req in outgoing:
        outgoing_list.append({
            "id": req.id,
            "sender_id": req.sender_id,
            "receiver_id": req.receiver_id,
            "sender_username": "",  # Not needed for outgoing
            "receiver_username": req.receiver.username,
            "sender_first_name": None,
            "sender_last_name": None,
            "receiver_first_name": req.receiver.first_name,
            "receiver_last_name": req.receiver.last_name,
            "status": req.status,
            "message": req.message,
            "created_at": req.created_at,
            "responded_at": req.responded_at
        })
    
    return incoming_list, outgoing_list


def respond_to_friend_request(
    db: Session,
    request_id: int,
    user_id: int,
    accept: bool
) -> Tuple[bool, str]:
    """
    Accept or reject a friend request.
    Returns (success, message).
    """
    friend_request = db.query(FriendRequest).filter(
        FriendRequest.id == request_id,
        FriendRequest.receiver_id == user_id,
        FriendRequest.status == "pending"
    ).first()
    
    if not friend_request:
        return False, "Friend request not found"
    
    friend_request.responded_at = datetime.utcnow()
    
    if accept:
        friend_request.status = "accepted"
        
        # Create friendship (always store with lower user_id first for consistency)
        user1_id = min(friend_request.sender_id, friend_request.receiver_id)
        user2_id = max(friend_request.sender_id, friend_request.receiver_id)
        
        friendship = Friendship(
            user1_id=user1_id,
            user2_id=user2_id
        )
        db.add(friendship)
        
        message = "Friend request accepted"
        logger.info(f"Friendship created: {user1_id} <-> {user2_id}")
    else:
        friend_request.status = "rejected"
        message = "Friend request rejected"
    
    db.commit()
    return True, message


def cancel_friend_request(
    db: Session,
    request_id: int,
    user_id: int
) -> Tuple[bool, str]:
    """Cancel an outgoing friend request."""
    friend_request = db.query(FriendRequest).filter(
        FriendRequest.id == request_id,
        FriendRequest.sender_id == user_id,
        FriendRequest.status == "pending"
    ).first()
    
    if not friend_request:
        return False, "Friend request not found"
    
    db.delete(friend_request)
    db.commit()
    
    return True, "Friend request cancelled"


# ============================================================================
# Friendships
# ============================================================================

def get_friends(db: Session, user_id: int) -> List[dict]:
    """Get all friends of a user."""
    # Get friendships where user is either user1 or user2
    friendships = db.query(Friendship).filter(
        or_(
            Friendship.user1_id == user_id,
            Friendship.user2_id == user_id
        )
    ).all()
    
    friends = []
    for fs in friendships:
        # Get the other user
        friend_id = fs.user2_id if fs.user1_id == user_id else fs.user1_id
        friend = db.query(User).filter(User.id == friend_id).first()
        
        if friend:
            friends.append({
                "id": fs.id,
                "user_id": friend.id,
                "username": friend.username,
                "first_name": friend.first_name,
                "last_name": friend.last_name,
                "bio": friend.bio,
                "avatar_url": friend.avatar_url,
                "friends_since": fs.created_at,
                "last_login": friend.last_login
            })
    
    # Sort by username
    friends.sort(key=lambda x: x["username"].lower())
    return friends


def remove_friend(db: Session, user_id: int, friend_id: int) -> Tuple[bool, str]:
    """Remove a friend."""
    friendship = db.query(Friendship).filter(
        or_(
            and_(Friendship.user1_id == user_id, Friendship.user2_id == friend_id),
            and_(Friendship.user1_id == friend_id, Friendship.user2_id == user_id)
        )
    ).first()
    
    if not friendship:
        return False, "Friendship not found"
    
    db.delete(friendship)
    db.commit()
    
    logger.info(f"Friendship removed: {user_id} <-> {friend_id}")
    return True, "Friend removed"


def are_friends(db: Session, user1_id: int, user2_id: int) -> bool:
    """Check if two users are friends."""
    friendship = db.query(Friendship).filter(
        or_(
            and_(Friendship.user1_id == user1_id, Friendship.user2_id == user2_id),
            and_(Friendship.user1_id == user2_id, Friendship.user2_id == user1_id)
        )
    ).first()
    
    return friendship is not None


def get_friend_ids(db: Session, user_id: int) -> List[int]:
    """Get all friend IDs for a user."""
    friendships = db.query(Friendship).filter(
        or_(Friendship.user1_id == user_id, Friendship.user2_id == user_id)
    ).all()
    
    friend_ids = []
    for f in friendships:
        if f.user1_id == user_id:
            friend_ids.append(f.user2_id)
        else:
            friend_ids.append(f.user1_id)
    
    return friend_ids


# ============================================================================
# User Notes
# ============================================================================

def get_user_note(db: Session, owner_id: int, subject_id: int) -> Optional[dict]:
    """Get a note about a specific user."""
    note = db.query(UserNote).filter(
        UserNote.owner_id == owner_id,
        UserNote.subject_id == subject_id
    ).first()
    
    if not note:
        return None
    
    subject = db.query(User).filter(User.id == subject_id).first()
    
    return {
        "id": note.id,
        "owner_id": note.owner_id,
        "subject_id": note.subject_id,
        "subject_username": subject.username if subject else "Unknown",
        "subject_first_name": subject.first_name if subject else None,
        "subject_avatar_url": subject.avatar_url if subject else None,
        "content": note.content,
        "created_at": note.created_at,
        "updated_at": note.updated_at
    }


def create_or_update_user_note(
    db: Session,
    owner_id: int,
    subject_id: int,
    content: str
) -> Tuple[dict, bool, str]:
    """
    Create or update a note about a user.
    Returns (note_dict, is_new, message).
    """
    # Check subject user exists
    subject = db.query(User).filter(User.id == subject_id).first()
    if not subject:
        return {}, False, "User not found"
    
    # Check if note already exists
    existing = db.query(UserNote).filter(
        UserNote.owner_id == owner_id,
        UserNote.subject_id == subject_id
    ).first()
    
    if existing:
        existing.content = content
        existing.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        
        return {
            "id": existing.id,
            "owner_id": existing.owner_id,
            "subject_id": existing.subject_id,
            "subject_username": subject.username,
            "subject_first_name": subject.first_name,
            "subject_avatar_url": subject.avatar_url,
            "content": existing.content,
            "created_at": existing.created_at,
            "updated_at": existing.updated_at
        }, False, "Note updated"
    
    # Create new note
    note = UserNote(
        owner_id=owner_id,
        subject_id=subject_id,
        content=content
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    
    logger.info(f"User {owner_id} created note about user {subject_id}")
    
    return {
        "id": note.id,
        "owner_id": note.owner_id,
        "subject_id": note.subject_id,
        "subject_username": subject.username,
        "subject_first_name": subject.first_name,
        "subject_avatar_url": subject.avatar_url,
        "content": note.content,
        "created_at": note.created_at,
        "updated_at": note.updated_at
    }, True, "Note created"


def delete_user_note(db: Session, owner_id: int, subject_id: int) -> Tuple[bool, str]:
    """Delete a note about a user."""
    note = db.query(UserNote).filter(
        UserNote.owner_id == owner_id,
        UserNote.subject_id == subject_id
    ).first()
    
    if not note:
        return False, "Note not found"
    
    db.delete(note)
    db.commit()
    
    return True, "Note deleted"


def get_all_user_notes(db: Session, owner_id: int) -> List[dict]:
    """Get all notes created by a user."""
    notes = db.query(UserNote).filter(
        UserNote.owner_id == owner_id
    ).order_by(UserNote.updated_at.desc()).all()
    
    result = []
    for note in notes:
        subject = db.query(User).filter(User.id == note.subject_id).first()
        result.append({
            "id": note.id,
            "owner_id": note.owner_id,
            "subject_id": note.subject_id,
            "subject_username": subject.username if subject else "Unknown",
            "subject_first_name": subject.first_name if subject else None,
            "subject_avatar_url": subject.avatar_url if subject else None,
            "content": note.content,
            "created_at": note.created_at,
            "updated_at": note.updated_at
        })
    
    return result
