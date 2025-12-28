"""Social routes for user search, friend requests, friendships, and messaging."""
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.core.auth import get_current_active_user
from backend.models.models import User
from backend.schemas.social import (
    UserPublicProfile,
    UserSearchResponse,
    FriendRequestCreate,
    FriendRequestResponse,
    FriendRequestAction,
    FriendRequestListResponse,
    FriendResponse,
    FriendsListResponse,
    ConversationCreate,
    ConversationSummary,
    ConversationsListResponse,
    MessageCreate,
    MessageUpdate,
    MessageResponse,
    MessagesListResponse,
    ConversationDetail,
    SocialMessageResponse,
    UnreadCountResponse,
    GroupCreate,
    GroupUpdate,
    GroupMemberAdd,
    GroupMemberUpdate,
    GroupMemberInfo,
    GroupDetailResponse,
    UserNoteCreate,
    UserNoteUpdate,
    UserNoteResponse,
    UserNotesListResponse,
    ParticipantRole,
    ReactionCreate,
    ReactionSummary,
    MessageReactionsResponse,
    FileUploadResponse,
    PinnedMessageInfo,
    PinnedMessagesResponse,
    ForwardMessageRequest,
    ForwardMessageResponse,
    ReadReceiptInfo,
    ConversationReadReceipts,
    MessageReadBy,
    MentionInfo,
    # New schemas for search, polls, GIFs, mute
    MessageSearchResponse,
    MessageSearchResult,
    PollCreate,
    PollResponse,
    PollVoteRequest,
    PollAddOptionRequest,
    GifSearchResponse,
    GifTrendingResponse,
    GifItem,
    MuteRequest,
    MuteStatusResponse,
    # Bookmark and edit history schemas
    BookmarkCreate,
    BookmarkUpdate,
    BookmarkResponse,
    BookmarksListResponse,
    EditHistoryEntry,
    MessageEditHistoryResponse,
)
from backend.services.social_service import (
    search_users,
    get_user_public_profile,
    create_friend_request,
    get_friend_requests,
    respond_to_friend_request,
    cancel_friend_request,
    get_friends,
    remove_friend,
    get_user_note,
    create_or_update_user_note,
    delete_user_note,
    get_all_user_notes,
)
from backend.services.messaging_service import (
    get_or_create_dm_conversation,
    get_user_conversations,
    get_conversation,
    send_message,
    get_messages,
    mark_conversation_read,
    edit_message,
    delete_message,
    get_unread_counts,
    create_group,
    update_group,
    add_group_members,
    remove_group_member,
    update_member_role,
    get_group_members,
    get_participant_role,
    add_reaction,
    remove_reaction,
    get_message_reactions,
    get_conversation_participant_ids,
    send_reply,
    pin_message,
    unpin_message,
    get_pinned_messages,
    forward_message,
    update_read_receipt,
    get_conversation_read_receipts,
    get_message_read_by,
    resolve_mentions,
    get_mentioned_user_ids,
    # New functions for search, polls, mute
    search_messages,
    create_poll,
    get_poll,
    vote_on_poll,
    add_poll_option,
    close_poll,
    get_conversation_polls,
    mute_conversation,
    get_mute_status,
    # Bookmark and edit history functions
    add_bookmark,
    update_bookmark,
    remove_bookmark,
    get_user_bookmarks,
    is_message_bookmarked,
    get_message_edit_history,
)
import httpx
import os

router = APIRouter(prefix="/social", tags=["social"])
logger = get_logger(__name__)


# ============================================================================
# User Search Endpoints
# ============================================================================

@router.get("/users/suggested", response_model=UserSearchResponse)
async def get_suggested_users_endpoint(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Get suggested users to connect with.
    Returns all approved users except the current user, showing newest first.
    """
    from backend.services.social_service import get_suggested_users
    users, total = get_suggested_users(db, current_user.id, skip, limit)
    return UserSearchResponse(users=users, total=total, query="")


@router.get("/users/search", response_model=UserSearchResponse)
async def search_users_endpoint(
    q: str = Query(..., min_length=1, max_length=100),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    exclude_friends: bool = Query(False),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Search for users by username, first name, or last name.
    Returns matching users with their friendship status relative to current user.
    """
    users, total = search_users(db, q, current_user.id, skip, limit, exclude_friends)
    return UserSearchResponse(users=users, total=total, query=q)


@router.get("/users/{user_id}", response_model=UserPublicProfile)
async def get_user_profile(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get public profile of a user."""
    profile = get_user_public_profile(db, user_id, current_user.id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return profile


# ============================================================================
# Friend Request Endpoints
# ============================================================================

@router.post("/friend-requests", response_model=FriendRequestResponse)
async def send_friend_request(
    request: FriendRequestCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Send a friend request to another user."""
    friend_request, error = create_friend_request(
        db, current_user.id, request.receiver_id, request.message
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Get receiver info for response
    receiver = db.query(User).filter(User.id == request.receiver_id).first()
    
    return FriendRequestResponse(
        id=friend_request.id,
        sender_id=friend_request.sender_id,
        receiver_id=friend_request.receiver_id,
        sender_username=current_user.username,
        receiver_username=receiver.username if receiver else "",
        sender_first_name=current_user.first_name,
        sender_last_name=current_user.last_name,
        receiver_first_name=receiver.first_name if receiver else None,
        receiver_last_name=receiver.last_name if receiver else None,
        status=friend_request.status,
        message=friend_request.message,
        created_at=friend_request.created_at,
        responded_at=friend_request.responded_at
    )


@router.get("/friend-requests", response_model=FriendRequestListResponse)
async def get_friend_requests_endpoint(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all pending friend requests (incoming and outgoing)."""
    incoming, outgoing = get_friend_requests(db, current_user.id)
    
    return FriendRequestListResponse(
        incoming=incoming,
        outgoing=outgoing,
        incoming_count=len(incoming),
        outgoing_count=len(outgoing)
    )


@router.post("/friend-requests/{request_id}/respond", response_model=SocialMessageResponse)
async def respond_to_request(
    request_id: int,
    action: FriendRequestAction,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Accept or reject a friend request."""
    accept = action.action == "accept"
    success, message = respond_to_friend_request(db, request_id, current_user.id, accept)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return SocialMessageResponse(message=message)


@router.delete("/friend-requests/{request_id}", response_model=SocialMessageResponse)
async def cancel_request(
    request_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Cancel an outgoing friend request."""
    success, message = cancel_friend_request(db, request_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return SocialMessageResponse(message=message)


# ============================================================================
# Friends Endpoints
# ============================================================================

@router.get("/friends", response_model=FriendsListResponse)
async def get_friends_list(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all friends of the current user."""
    friends = get_friends(db, current_user.id)
    return FriendsListResponse(friends=friends, total=len(friends))


@router.delete("/friends/{friend_id}", response_model=SocialMessageResponse)
async def remove_friend_endpoint(
    friend_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Remove a friend."""
    success, message = remove_friend(db, current_user.id, friend_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return SocialMessageResponse(message=message)


# ============================================================================
# Conversation Endpoints
# ============================================================================

@router.post("/conversations", response_model=ConversationSummary)
async def create_conversation(
    request: ConversationCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Create or get a conversation with another user.
    For DMs, returns existing conversation if one exists.
    """
    if len(request.participant_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Currently only 1-on-1 conversations are supported. Provide exactly one participant_id."
        )
    
    other_user_id = request.participant_ids[0]
    
    conversation, error = get_or_create_dm_conversation(db, current_user.id, other_user_id)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Send initial message if provided
    if request.initial_message:
        send_message(db, conversation.id, current_user.id, request.initial_message)
    
    # Get full conversation info
    conv_info = get_conversation(db, conversation.id, current_user.id)
    
    return ConversationSummary(
        id=conversation.id,
        name=conv_info["name"],
        is_group=conv_info["is_group"],
        participants=conv_info["participants"],
        last_message_preview=request.initial_message[:100] if request.initial_message else None,
        last_message_sender=current_user.username if request.initial_message else None,
        last_message_at=conversation.last_message_at,
        unread_count=0,
        created_at=conversation.created_at
    )


@router.get("/conversations", response_model=ConversationsListResponse)
async def get_conversations(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all conversations for the current user."""
    conversations, total = get_user_conversations(db, current_user.id, skip, limit)
    return ConversationsListResponse(conversations=conversations, total=total)


@router.get("/conversations/{conversation_id}", response_model=ConversationDetail)
async def get_conversation_detail(
    conversation_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get conversation details with messages."""
    conv_info = get_conversation(db, conversation_id, current_user.id)
    
    if not conv_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found"
        )
    
    messages, total, has_more = get_messages(db, conversation_id, current_user.id, skip, limit)
    
    # Mark as read
    mark_conversation_read(db, conversation_id, current_user.id)
    
    return ConversationDetail(
        id=conv_info["id"],
        name=conv_info["name"],
        description=conv_info.get("description"),
        avatar_url=conv_info.get("avatar_url"),
        is_group=conv_info["is_group"],
        participants=conv_info["participants"],
        participant_count=conv_info.get("participant_count", len(conv_info["participants"])),
        messages=messages,
        total_messages=total,
        has_more_messages=has_more,
        created_at=conv_info["created_at"],
        created_by=conv_info.get("created_by"),
        my_role=conv_info.get("my_role")
    )


@router.post("/conversations/{conversation_id}/read", response_model=SocialMessageResponse)
async def mark_as_read(
    conversation_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Mark all messages in a conversation as read."""
    success = mark_conversation_read(db, conversation_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found"
        )
    
    return SocialMessageResponse(message="Marked as read")


# ============================================================================
# Message Endpoints
# ============================================================================

@router.post("/conversations/{conversation_id}/messages", response_model=MessageResponse)
async def send_message_endpoint(
    conversation_id: int,
    request: MessageCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Send a message to a conversation."""
    message, error = send_message(
        db,
        conversation_id,
        current_user.id,
        request.content,
        request.message_type.value,
        request.attachment_data
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return MessageResponse(
        id=message.id,
        conversation_id=message.conversation_id,
        sender_id=message.sender_id,
        sender_username=current_user.username,
        sender_first_name=current_user.first_name,
        sender_avatar_url=current_user.avatar_url,
        content=message.content,
        message_type=message.message_type,
        attachment_data=message.attachment_data,
        created_at=message.created_at,
        updated_at=message.updated_at,
        is_edited=message.is_edited == "true",
        is_deleted=message.is_deleted == "true",
        is_own_message=True
    )


@router.get("/conversations/{conversation_id}/messages", response_model=MessagesListResponse)
async def get_messages_endpoint(
    conversation_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    before_id: int = Query(None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get messages in a conversation."""
    messages, total, has_more = get_messages(
        db, conversation_id, current_user.id, skip, limit, before_id
    )
    
    if total == 0:
        # Check if conversation exists and user has access
        conv = get_conversation(db, conversation_id, current_user.id)
        if not conv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conversation not found"
            )
    
    return MessagesListResponse(
        messages=messages,
        total=total,
        has_more=has_more,
        conversation_id=conversation_id
    )


@router.put("/messages/{message_id}", response_model=MessageResponse)
async def edit_message_endpoint(
    message_id: int,
    request: MessageUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Edit a message (only own messages)."""
    message, error = edit_message(db, message_id, current_user.id, request.content)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return MessageResponse(
        id=message.id,
        conversation_id=message.conversation_id,
        sender_id=message.sender_id,
        sender_username=current_user.username,
        sender_first_name=current_user.first_name,
        sender_avatar_url=current_user.avatar_url,
        content=message.content,
        message_type=message.message_type,
        attachment_data=message.attachment_data,
        created_at=message.created_at,
        updated_at=message.updated_at,
        is_edited=message.is_edited == "true",
        is_deleted=message.is_deleted == "true",
        is_own_message=True
    )


@router.delete("/messages/{message_id}", response_model=SocialMessageResponse)
async def delete_message_endpoint(
    message_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete a message (only own messages)."""
    success, message = delete_message(db, message_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return SocialMessageResponse(message=message)


# ============================================================================
# Unread Counts
# ============================================================================

@router.get("/unread", response_model=UnreadCountResponse)
async def get_unread_counts_endpoint(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get unread message counts for all conversations."""
    counts = get_unread_counts(db, current_user.id)
    return UnreadCountResponse(**counts)


# ============================================================================
# Group Chat Endpoints
# ============================================================================

@router.post("/groups", response_model=ConversationSummary)
async def create_group_endpoint(
    request: GroupCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create a new group chat."""
    conversation, error = create_group(
        db,
        current_user.id,
        request.name,
        request.description,
        request.avatar_url,
        request.participant_ids
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Get full conversation info
    conv_info = get_conversation(db, conversation.id, current_user.id)
    
    return ConversationSummary(
        id=conversation.id,
        name=conv_info["name"],
        description=conv_info["description"],
        avatar_url=conv_info["avatar_url"],
        is_group=True,
        participants=conv_info["participants"],
        participant_count=len(conv_info["participants"]),
        last_message_preview=None,
        last_message_sender=None,
        last_message_at=None,
        unread_count=0,
        created_at=conversation.created_at,
        created_by=conversation.created_by,
        my_role=ParticipantRole.OWNER
    )


@router.put("/groups/{group_id}", response_model=SocialMessageResponse)
async def update_group_endpoint(
    group_id: int,
    request: GroupUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update group settings (name, description, avatar)."""
    conversation, error = update_group(
        db,
        group_id,
        current_user.id,
        request.name,
        request.description,
        request.avatar_url
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return SocialMessageResponse(message="Group updated successfully")


@router.get("/groups/{group_id}/members", response_model=list[GroupMemberInfo])
async def get_group_members_endpoint(
    group_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get list of group members."""
    members, error = get_group_members(db, group_id, current_user.id)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return members


@router.post("/groups/{group_id}/members", response_model=SocialMessageResponse)
async def add_group_members_endpoint(
    group_id: int,
    request: GroupMemberAdd,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Add members to a group."""
    added, error = add_group_members(db, group_id, current_user.id, request.user_ids)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return SocialMessageResponse(
        message=f"Added {len(added)} member(s) to the group",
        detail=f"User IDs added: {added}" if added else "No new members added"
    )


@router.delete("/groups/{group_id}/members/{user_id}", response_model=SocialMessageResponse)
async def remove_group_member_endpoint(
    group_id: int,
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Remove a member from the group or leave the group."""
    success, message = remove_group_member(db, group_id, current_user.id, user_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return SocialMessageResponse(message=message)


@router.put("/groups/{group_id}/members/{user_id}/role", response_model=SocialMessageResponse)
async def update_member_role_endpoint(
    group_id: int,
    user_id: int,
    request: GroupMemberUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update a member's role (promote/demote)."""
    success, message = update_member_role(
        db, group_id, current_user.id, user_id, request.role.value
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return SocialMessageResponse(message=message)


# ============================================================================
# User Notes Endpoints
# ============================================================================

@router.get("/notes", response_model=UserNotesListResponse)
async def get_all_notes(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all notes created by the current user."""
    notes = get_all_user_notes(db, current_user.id)
    return UserNotesListResponse(notes=notes, total=len(notes))


@router.get("/notes/{user_id}", response_model=UserNoteResponse)
async def get_note_for_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get note about a specific user."""
    note = get_user_note(db, current_user.id, user_id)
    
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No note found for this user"
        )
    
    return note


@router.post("/notes", response_model=UserNoteResponse)
async def create_note(
    request: UserNoteCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create or update a note about a user."""
    note, is_new, message = create_or_update_user_note(
        db, current_user.id, request.subject_id, request.content
    )
    
    if not note:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return note


@router.put("/notes/{user_id}", response_model=UserNoteResponse)
async def update_note(
    user_id: int,
    request: UserNoteUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update a note about a user."""
    note, is_new, message = create_or_update_user_note(
        db, current_user.id, user_id, request.content
    )
    
    if not note:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return note


@router.delete("/notes/{user_id}", response_model=SocialMessageResponse)
async def delete_note(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete a note about a user."""
    success, message = delete_user_note(db, current_user.id, user_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=message
        )
    
    return SocialMessageResponse(message=message)


# ============================================================================
# Message Reaction Endpoints
# ============================================================================

@router.post("/messages/{message_id}/reactions", response_model=SocialMessageResponse)
async def add_message_reaction(
    message_id: int,
    request: ReactionCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Add a reaction to a message."""
    reaction, error = add_reaction(db, message_id, current_user.id, request.emoji)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Broadcast to conversation participants via WebSocket
    from backend.models.models import Message
    from backend.routers.chat_websocket import broadcast_reaction
    
    message = db.query(Message).filter(Message.id == message_id).first()
    if message:
        participant_ids = get_conversation_participant_ids(db, message.conversation_id)
        background_tasks.add_task(
            broadcast_reaction,
            message.conversation_id,
            message_id,
            current_user.id,
            current_user.username,
            request.emoji,
            True,  # added
            participant_ids
        )
    
    return SocialMessageResponse(message=f"Reaction {request.emoji} added")


@router.delete("/messages/{message_id}/reactions/{emoji}", response_model=SocialMessageResponse)
async def remove_message_reaction(
    message_id: int,
    emoji: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Remove a reaction from a message."""
    # Get message info before deletion for broadcast
    from backend.models.models import Message
    from backend.routers.chat_websocket import broadcast_reaction
    
    message = db.query(Message).filter(Message.id == message_id).first()
    conversation_id = message.conversation_id if message else None
    participant_ids = get_conversation_participant_ids(db, conversation_id) if conversation_id else []
    
    success, error = remove_reaction(db, message_id, current_user.id, emoji)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=error
        )
    
    # Broadcast removal
    if conversation_id:
        background_tasks.add_task(
            broadcast_reaction,
            conversation_id,
            message_id,
            current_user.id,
            current_user.username,
            emoji,
            False,  # removed
            participant_ids
        )
    
    return SocialMessageResponse(message="Reaction removed")


@router.get("/messages/{message_id}/reactions", response_model=MessageReactionsResponse)
async def get_reactions(
    message_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all reactions for a message."""
    reactions, total = get_message_reactions(db, message_id, current_user.id)
    
    return MessageReactionsResponse(
        message_id=message_id,
        reactions=[ReactionSummary(**r) for r in reactions.values()],
        total_count=total
    )


# ============================================================================
# File Upload Endpoints
# ============================================================================

import os
import uuid
import aiofiles
from pathlib import Path

UPLOAD_DIR = Path("uploads/chat")

# Comprehensive file extension whitelist organized by category
ALLOWED_EXTENSIONS = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico", ".tiff", ".tif",
    
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".md", ".csv", ".json", ".xml", ".rtf", ".odt", ".ods", ".odp",
    
    # Archives (for folders/multiple files)
    ".zip", ".tar", ".gz", ".7z", ".rar", ".tar.gz", ".tgz", ".bz2", ".xz",
    
    # Code files - comprehensive list
    ".py", ".pyw", ".pyx",  # Python
    ".js", ".jsx", ".mjs", ".cjs",  # JavaScript
    ".ts", ".tsx", ".mts", ".cts",  # TypeScript
    ".html", ".htm", ".xhtml",  # HTML
    ".css", ".scss", ".sass", ".less",  # CSS
    ".java", ".class", ".jar",  # Java
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hxx",  # C/C++
    ".cs", ".csx",  # C#
    ".go",  # Go
    ".rs",  # Rust
    ".rb", ".erb",  # Ruby
    ".php", ".phtml",  # PHP
    ".swift",  # Swift
    ".kt", ".kts",  # Kotlin
    ".scala", ".sc",  # Scala
    ".r", ".R",  # R
    ".pl", ".pm",  # Perl
    ".sh", ".bash", ".zsh", ".fish",  # Shell
    ".ps1", ".psm1", ".psd1",  # PowerShell
    ".lua",  # Lua
    ".sql",  # SQL
    ".yaml", ".yml",  # YAML
    ".toml",  # TOML
    ".ini", ".cfg", ".conf",  # Config
    ".dockerfile", ".containerfile",  # Docker
    ".tf", ".tfvars",  # Terraform
    ".vue",  # Vue
    ".svelte",  # Svelte
    ".asm", ".s",  # Assembly
    ".m", ".mm",  # Objective-C
    ".f", ".f90", ".f95",  # Fortran
    ".hs", ".lhs",  # Haskell
    ".clj", ".cljs", ".cljc", ".edn",  # Clojure
    ".ex", ".exs",  # Elixir
    ".erl", ".hrl",  # Erlang
    ".ml", ".mli",  # OCaml
    ".dart",  # Dart
    ".groovy", ".gradle",  # Groovy
    ".v", ".vh",  # Verilog
    ".vhd", ".vhdl",  # VHDL
    ".proto",  # Protocol Buffers
    ".graphql", ".gql",  # GraphQL
    ".wasm",  # WebAssembly
    
    # Mobile development
    ".apk",  # Android APK
    ".aab",  # Android App Bundle
    ".ipa",  # iOS App
    ".dex",  # Dalvik Executable
    ".smali",  # Smali (Android disassembly)
    ".xib", ".storyboard", ".plist",  # iOS
    
    # Binary/Executable analysis
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",  # Binaries
    ".elf", ".bin", ".rom",  # Embedded
    ".msi", ".msix",  # Windows installers
    ".deb", ".rpm",  # Linux packages
    ".dmg", ".pkg",  # macOS packages
    
    # Security/Forensics
    ".pcap", ".pcapng",  # Network captures
    ".mem", ".dmp", ".crash",  # Memory dumps
    ".evtx", ".evt",  # Windows event logs
    ".yar", ".yara",  # YARA rules
    ".rules",  # Snort/Suricata rules
    
    # Data files
    ".db", ".sqlite", ".sqlite3",  # Databases
    ".log",  # Logs
    ".bak",  # Backups
    
    # Certificates/Keys (be careful with these)
    ".pem", ".crt", ".cer", ".der", ".p12", ".pfx",
    ".pub",  # Public keys only, not private
    
    # Other common formats
    ".eml", ".msg",  # Emails
    ".ics",  # Calendar
    ".vcf",  # Contacts
}

# Extended mime types for better detection
MIME_TYPE_OVERRIDES = {
    ".apk": "application/vnd.android.package-archive",
    ".aab": "application/x-authorware-bin",
    ".ipa": "application/octet-stream",
    ".dex": "application/octet-stream",
    ".smali": "text/x-smali",
    ".pcap": "application/vnd.tcpdump.pcap",
    ".pcapng": "application/x-pcapng",
    ".yar": "text/x-yara",
    ".yara": "text/x-yara",
    ".exe": "application/x-msdownload",
    ".dll": "application/x-msdownload",
    ".so": "application/x-sharedlib",
    ".dylib": "application/x-mach-binary",
    ".elf": "application/x-executable",
    ".jar": "application/java-archive",
    ".class": "application/java-vm",
    ".wasm": "application/wasm",
}

# File categories for frontend display
FILE_CATEGORIES = {
    "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico", ".tiff", ".tif"},
    "document": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp"},
    "archive": {".zip", ".tar", ".gz", ".7z", ".rar", ".tar.gz", ".tgz", ".bz2", ".xz"},
    "code": {".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".css", ".java", ".c", ".cpp", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".cs", ".scala", ".vue", ".svelte"},
    "mobile": {".apk", ".aab", ".ipa", ".dex", ".smali"},
    "binary": {".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".msi", ".deb", ".rpm", ".dmg"},
    "security": {".pcap", ".pcapng", ".mem", ".dmp", ".yar", ".yara", ".rules"},
    "data": {".json", ".xml", ".yaml", ".yml", ".csv", ".sql", ".db", ".sqlite", ".log"},
    "text": {".txt", ".md", ".log", ".ini", ".cfg", ".conf"},
}

MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB for large APKs, archives, and binaries


def get_file_category(extension: str) -> str:
    """Determine the category of a file based on extension."""
    ext = extension.lower()
    for category, extensions in FILE_CATEGORIES.items():
        if ext in extensions:
            return category
    return "other"


@router.post("/upload", response_model=FileUploadResponse)
async def upload_chat_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
):
    """Upload a file for chat attachment. Supports a wide variety of file types."""
    # Get file extension - handle compound extensions like .tar.gz
    filename = file.filename or "unnamed"
    if filename.lower().endswith('.tar.gz'):
        ext = '.tar.gz'
    elif filename.lower().endswith('.tar.bz2'):
        ext = '.tar.bz2'
    else:
        ext = Path(filename).suffix.lower()
    
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type '{ext}' not allowed. Supported types include images, documents, code files, archives, APKs, and more."
        )
    
    # Read file content
    content = await file.read()
    
    # Validate file size
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
        )
    
    # Create upload directory if needed
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate unique filename - sanitize the original filename
    import re
    safe_original = re.sub(r'[^\w\-_\.]', '_', filename)
    unique_id = uuid.uuid4().hex[:12]
    safe_filename = f"{unique_id}_{safe_original}"
    file_path = UPLOAD_DIR / safe_filename
    
    # Save file
    async with aiofiles.open(file_path, 'wb') as f:
        await f.write(content)
    
    # Determine file category and thumbnail
    file_category = get_file_category(ext)
    is_image = file_category == "image"
    thumbnail_url = None
    
    # For images, the file itself can be the thumbnail
    if is_image:
        thumbnail_url = f"/api/uploads/chat/{safe_filename}"
    
    # Get mime type - use overrides for special file types
    import mimetypes
    mime_type = MIME_TYPE_OVERRIDES.get(ext) or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    
    return FileUploadResponse(
        file_url=f"/api/uploads/chat/{safe_filename}",
        filename=filename,
        file_size=len(content),
        mime_type=mime_type,
        thumbnail_url=thumbnail_url,
        file_category=file_category,
    )


@router.get("/upload/supported-types")
async def get_supported_file_types():
    """Get list of supported file types for upload."""
    return {
        "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024),
        "categories": {
            "images": [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico", ".tiff"],
            "documents": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".rtf", ".odt", ".ods", ".odp"],
            "archives": [".zip", ".tar", ".gz", ".7z", ".rar", ".tar.gz", ".tgz", ".bz2", ".xz"],
            "code": list({ext for ext in ALLOWED_EXTENSIONS if ext in {
                ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".cs", ".go", 
                ".rs", ".rb", ".php", ".swift", ".kt", ".scala", ".html", ".css", ".vue", ".svelte",
                ".sql", ".sh", ".ps1", ".yaml", ".yml", ".json", ".xml", ".dockerfile", ".tf"
            }}),
            "mobile": [".apk", ".aab", ".ipa", ".dex", ".smali"],
            "binary": [".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".msi", ".deb", ".rpm", ".dmg", ".jar", ".class"],
            "security": [".pcap", ".pcapng", ".mem", ".dmp", ".yar", ".yara", ".rules", ".evtx"],
            "data": [".db", ".sqlite", ".sqlite3", ".csv", ".log"],
        },
        "tip": "For folders with multiple files, zip them first. For unsupported file types, try renaming with a supported extension or zipping.",
    }


# ============================================================================
# Reply Endpoint
# ============================================================================

@router.post("/conversations/{conversation_id}/messages/{message_id}/reply", response_model=MessageResponse)
async def reply_to_message(
    conversation_id: int,
    message_id: int,
    request: MessageCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Reply to a specific message in a conversation."""
    message, error = send_reply(
        db,
        conversation_id,
        current_user.id,
        request.content,
        message_id,
        request.message_type.value,
        request.attachment_data
    )
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Prepare response
    from backend.services.messaging_service import _get_reactions_for_message, _get_reply_info
    reactions = _get_reactions_for_message(db, message.id, current_user.id)
    reply_to = _get_reply_info(db, message.reply_to_id) if message.reply_to_id else None
    
    response = MessageResponse(
        id=message.id,
        conversation_id=message.conversation_id,
        sender_id=message.sender_id,
        sender_username=current_user.username,
        sender_first_name=current_user.first_name,
        sender_avatar_url=current_user.avatar_url,
        content=message.content,
        message_type=message.message_type,
        attachment_data=message.attachment_data,
        created_at=message.created_at,
        updated_at=message.updated_at,
        is_edited=message.is_edited == "true",
        is_deleted=message.is_deleted == "true",
        is_own_message=True,
        reply_to=reply_to,
        reactions=reactions
    )
    
    # Broadcast via WebSocket
    from backend.routers.chat_websocket import broadcast_new_message
    participant_ids = get_conversation_participant_ids(db, conversation_id)
    background_tasks.add_task(
        broadcast_new_message,
        conversation_id,
        response.model_dump(),
        participant_ids,
        current_user.id
    )
    
    return response


# ============================================================================
# Message Pinning Endpoints
# ============================================================================

@router.post("/conversations/{conversation_id}/messages/{message_id}/pin")
async def pin_message_endpoint(
    conversation_id: int,
    message_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Pin a message in a conversation."""
    pinned, error = pin_message(db, conversation_id, message_id, current_user.id)
    
    if not pinned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Broadcast pin event via WebSocket
    from backend.routers.chat_websocket import broadcast_pin_event
    participant_ids = get_conversation_participant_ids(db, conversation_id)
    background_tasks.add_task(
        broadcast_pin_event,
        conversation_id,
        message_id,
        current_user.id,
        current_user.username,
        True,  # is_pinned
        participant_ids
    )
    
    return {"message": "Message pinned", "pinned_id": pinned.id}


@router.delete("/conversations/{conversation_id}/messages/{message_id}/pin")
async def unpin_message_endpoint(
    conversation_id: int,
    message_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Unpin a message from a conversation."""
    success, error = unpin_message(db, conversation_id, message_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Broadcast unpin event via WebSocket
    from backend.routers.chat_websocket import broadcast_pin_event
    participant_ids = get_conversation_participant_ids(db, conversation_id)
    background_tasks.add_task(
        broadcast_pin_event,
        conversation_id,
        message_id,
        current_user.id,
        current_user.username,
        False,  # is_pinned
        participant_ids
    )
    
    return {"message": "Message unpinned"}


@router.get("/conversations/{conversation_id}/pinned", response_model=PinnedMessagesResponse)
async def get_pinned_messages_endpoint(
    conversation_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all pinned messages in a conversation."""
    pinned_list, error = get_pinned_messages(db, conversation_id, current_user.id)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return PinnedMessagesResponse(
        pinned_messages=[PinnedMessageInfo(**p) for p in pinned_list],
        total=len(pinned_list),
        conversation_id=conversation_id
    )


# ============================================================================
# Message Forwarding Endpoints
# ============================================================================

@router.post("/messages/{message_id}/forward", response_model=ForwardMessageResponse)
async def forward_message_endpoint(
    message_id: int,
    request: ForwardMessageRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Forward a message to one or more conversations."""
    success_ids, failed_ids, error = forward_message(
        db,
        message_id,
        current_user.id,
        request.target_conversation_ids,
        request.include_original_sender
    )
    
    if not success_ids and error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return ForwardMessageResponse(
        success=len(success_ids) > 0,
        forwarded_to=success_ids,
        failed=failed_ids,
        messages_sent=len(success_ids)
    )


# ============================================================================
# Read Receipts Endpoints
# ============================================================================

@router.post("/conversations/{conversation_id}/read/{message_id}")
async def update_read_receipt_endpoint(
    conversation_id: int,
    message_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update read receipt for a conversation."""
    receipt, error = update_read_receipt(db, conversation_id, current_user.id, message_id)
    
    if not receipt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Broadcast read receipt via WebSocket
    from backend.routers.chat_websocket import broadcast_read_receipt
    participant_ids = get_conversation_participant_ids(db, conversation_id)
    background_tasks.add_task(
        broadcast_read_receipt,
        conversation_id,
        current_user.id,
        current_user.username,
        message_id,
        participant_ids
    )
    
    return {"message": "Read receipt updated", "last_read_message_id": message_id}


@router.get("/conversations/{conversation_id}/read-receipts", response_model=ConversationReadReceipts)
async def get_read_receipts_endpoint(
    conversation_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get read receipts for all participants in a conversation."""
    receipts, error = get_conversation_read_receipts(db, conversation_id, current_user.id)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return ConversationReadReceipts(
        conversation_id=conversation_id,
        receipts=[ReadReceiptInfo(**r) for r in receipts]
    )


@router.get("/messages/{message_id}/read-by", response_model=MessageReadBy)
async def get_message_read_by_endpoint(
    message_id: int,
    conversation_id: int = Query(...),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get list of users who have read a specific message."""
    read_by, total_participants, error = get_message_read_by(
        db, conversation_id, message_id, current_user.id
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return MessageReadBy(
        message_id=message_id,
        read_by=[ReadReceiptInfo(**r) for r in read_by],
        total_participants=total_participants,
        read_count=len(read_by) + 1  # +1 for sender
    )


# ============================================================================
# Mention Endpoints
# ============================================================================

@router.get("/conversations/{conversation_id}/mentions/check")
async def check_mentions_endpoint(
    conversation_id: int,
    content: str = Query(..., min_length=1),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Check which users are mentioned in the given content."""
    mentions = resolve_mentions(db, content, conversation_id)
    mentioned_ids = get_mentioned_user_ids(db, content, conversation_id)
    
    return {
        "mentions": [MentionInfo(**m) for m in mentions],
        "mentioned_user_ids": mentioned_ids
    }


# ============================================================================
# Message Search Endpoints
# ============================================================================

@router.get("/messages/search", response_model=MessageSearchResponse)
async def search_messages_endpoint(
    q: str = Query(..., min_length=2, max_length=200),
    conversation_id: int = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Search messages in conversations the user is part of.
    Optionally filter by specific conversation.
    """
    results, total, has_more = search_messages(
        db, current_user.id, q, conversation_id, skip, limit
    )
    
    return MessageSearchResponse(
        query=q,
        results=[MessageSearchResult(**r) for r in results],
        total=total,
        has_more=has_more
    )


# ============================================================================
# Poll Endpoints
# ============================================================================

@router.post("/conversations/{conversation_id}/polls", response_model=PollResponse)
async def create_poll_endpoint(
    conversation_id: int,
    poll_data: PollCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create a poll in a conversation."""
    poll, message, error = create_poll(
        db=db,
        conversation_id=conversation_id,
        creator_id=current_user.id,
        question=poll_data.question,
        options=poll_data.options,
        poll_type=poll_data.poll_type,
        is_anonymous=poll_data.is_anonymous,
        allow_add_options=poll_data.allow_add_options,
        closes_at=poll_data.closes_at
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return get_poll(db, poll.id, current_user.id)


@router.get("/conversations/{conversation_id}/polls", response_model=list)
async def get_conversation_polls_endpoint(
    conversation_id: int,
    include_closed: bool = Query(True),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all polls in a conversation."""
    return get_conversation_polls(db, conversation_id, current_user.id, include_closed)


@router.get("/polls/{poll_id}", response_model=PollResponse)
async def get_poll_endpoint(
    poll_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get a specific poll."""
    poll = get_poll(db, poll_id, current_user.id)
    
    if not poll:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Poll not found"
        )
    
    return poll


@router.post("/polls/{poll_id}/vote")
async def vote_on_poll_endpoint(
    poll_id: int,
    vote_data: PollVoteRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Vote on a poll."""
    success, error = vote_on_poll(db, poll_id, current_user.id, vote_data.option_ids)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return {"message": "Vote recorded", "poll": get_poll(db, poll_id, current_user.id)}


@router.post("/polls/{poll_id}/options")
async def add_poll_option_endpoint(
    poll_id: int,
    option_data: PollAddOptionRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Add an option to a poll (if allowed)."""
    option, error = add_poll_option(db, poll_id, current_user.id, option_data.text)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return {"message": "Option added", "poll": get_poll(db, poll_id, current_user.id)}


@router.post("/polls/{poll_id}/close")
async def close_poll_endpoint(
    poll_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Close a poll."""
    success, error = close_poll(db, poll_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return {"message": "Poll closed", "poll": get_poll(db, poll_id, current_user.id)}


# ============================================================================
# Mute Conversation Endpoints
# ============================================================================

@router.post("/conversations/{conversation_id}/mute", response_model=MuteStatusResponse)
async def mute_conversation_endpoint(
    conversation_id: int,
    mute_data: MuteRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Mute or unmute a conversation."""
    is_muted, muted_until, error = mute_conversation(
        db, conversation_id, current_user.id,
        mute=mute_data.mute,
        duration_hours=mute_data.duration_hours
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return MuteStatusResponse(
        conversation_id=conversation_id,
        is_muted=is_muted,
        muted_until=muted_until
    )


@router.get("/conversations/{conversation_id}/mute", response_model=MuteStatusResponse)
async def get_mute_status_endpoint(
    conversation_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get mute status for a conversation."""
    is_muted, muted_until = get_mute_status(db, conversation_id, current_user.id)
    
    return MuteStatusResponse(
        conversation_id=conversation_id,
        is_muted=is_muted,
        muted_until=muted_until
    )


# ============================================================================
# Delete/Leave Conversation
# ============================================================================

@router.delete("/conversations/{conversation_id}", response_model=SocialMessageResponse)
async def delete_conversation_endpoint(
    conversation_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Delete or leave a conversation.
    
    - For DMs: Removes the conversation from your view. If both users delete, it's fully removed.
    - For groups: Leaves the group. Owners must transfer ownership or remove all members first.
    """
    from backend.services.messaging_service import delete_conversation
    
    success, message = delete_conversation(db, conversation_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return SocialMessageResponse(message=message)


# ============================================================================
# Message Bookmark Endpoints
# ============================================================================


@router.post("/bookmarks", response_model=BookmarkResponse)
async def add_bookmark_endpoint(
    bookmark_data: BookmarkCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Bookmark a message."""
    bookmark, error = add_bookmark(
        db, current_user.id, bookmark_data.message_id, bookmark_data.note
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return bookmark


@router.get("/bookmarks", response_model=BookmarksListResponse)
async def get_bookmarks_endpoint(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all bookmarked messages for the current user."""
    bookmarks, total = get_user_bookmarks(db, current_user.id, skip, limit)
    
    return BookmarksListResponse(
        bookmarks=[BookmarkResponse(**b) for b in bookmarks],
        total=total
    )


@router.put("/bookmarks/{bookmark_id}", response_model=BookmarkResponse)
async def update_bookmark_endpoint(
    bookmark_id: int,
    bookmark_data: BookmarkUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update a bookmark's note."""
    bookmark, error = update_bookmark(
        db, current_user.id, bookmark_id, bookmark_data.note
    )
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return bookmark


@router.delete("/bookmarks/message/{message_id}", response_model=SocialMessageResponse)
async def remove_bookmark_endpoint(
    message_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Remove a bookmark from a message."""
    success, error = remove_bookmark(db, current_user.id, message_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return SocialMessageResponse(message="Bookmark removed")


@router.get("/messages/{message_id}/bookmarked")
async def check_bookmark_status(
    message_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Check if a message is bookmarked by the current user."""
    return {"is_bookmarked": is_message_bookmarked(db, current_user.id, message_id)}


# ============================================================================
# Message Edit History Endpoints
# ============================================================================

@router.get("/messages/{message_id}/history", response_model=MessageEditHistoryResponse)
async def get_edit_history_endpoint(
    message_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get the edit history for a message."""
    history, error = get_message_edit_history(db, message_id, current_user.id)
    
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return history
