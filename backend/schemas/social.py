"""Social/messaging schemas for request/response validation."""
from datetime import datetime
from typing import Optional, List
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class FriendRequestStatus(str, Enum):
    """Friend request status enumeration."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class MessageType(str, Enum):
    """Message type enumeration."""
    TEXT = "text"
    FILE = "file"
    IMAGE = "image"
    REPORT_SHARE = "report_share"
    FINDING_SHARE = "finding_share"
    SYSTEM = "system"
    POLL = "poll"


class ParticipantRole(str, Enum):
    """Participant role in group chats."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


# ============================================================================
# User Search Schemas
# ============================================================================

class UserPublicProfile(BaseModel):
    """Public profile info visible to other users."""
    id: int
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime
    
    # Friendship status with current user
    is_friend: bool = False
    has_pending_request: bool = False
    request_direction: Optional[str] = None  # "sent" or "received"
    
    model_config = ConfigDict(from_attributes=True)


class UserSearchResponse(BaseModel):
    """Response for user search."""
    users: List[UserPublicProfile]
    total: int
    query: str


# ============================================================================
# Friend Request Schemas
# ============================================================================

class FriendRequestCreate(BaseModel):
    """Schema for creating a friend request."""
    receiver_id: int
    message: Optional[str] = Field(None, max_length=500)


class FriendRequestResponse(BaseModel):
    """Schema for friend request response."""
    id: int
    sender_id: int
    receiver_id: int
    sender_username: str
    receiver_username: str
    sender_first_name: Optional[str] = None
    sender_last_name: Optional[str] = None
    receiver_first_name: Optional[str] = None
    receiver_last_name: Optional[str] = None
    status: FriendRequestStatus
    message: Optional[str] = None
    created_at: datetime
    responded_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class FriendRequestAction(BaseModel):
    """Schema for accepting/rejecting friend request."""
    action: str = Field(..., pattern="^(accept|reject)$")


class FriendRequestListResponse(BaseModel):
    """Response for list of friend requests."""
    incoming: List[FriendRequestResponse]
    outgoing: List[FriendRequestResponse]
    incoming_count: int
    outgoing_count: int


# ============================================================================
# Friendship Schemas
# ============================================================================

class FriendResponse(BaseModel):
    """Schema for a friend in friends list."""
    id: int
    user_id: int
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    friends_since: datetime
    last_login: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class FriendsListResponse(BaseModel):
    """Response for friends list."""
    friends: List[FriendResponse]
    total: int


# ============================================================================
# Conversation Schemas
# ============================================================================

class ConversationCreate(BaseModel):
    """Schema for creating a conversation."""
    participant_ids: List[int] = Field(..., min_length=1)
    name: Optional[str] = Field(None, max_length=100)  # For group chats
    initial_message: Optional[str] = None


class ConversationParticipantInfo(BaseModel):
    """Info about a conversation participant."""
    user_id: int
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    joined_at: datetime
    role: ParticipantRole = ParticipantRole.MEMBER
    nickname: Optional[str] = None
    is_muted: bool = False
    
    model_config = ConfigDict(from_attributes=True)


class ConversationSummary(BaseModel):
    """Summary of a conversation for list view."""
    id: int
    name: Optional[str] = None
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    is_group: bool
    participants: List[ConversationParticipantInfo]
    participant_count: int = 0
    last_message_preview: Optional[str] = None
    last_message_sender: Optional[str] = None
    last_message_at: Optional[datetime] = None
    unread_count: int = 0
    created_at: datetime
    created_by: Optional[int] = None
    my_role: Optional[ParticipantRole] = None
    
    model_config = ConfigDict(from_attributes=True)


class ConversationsListResponse(BaseModel):
    """Response for list of conversations."""
    conversations: List[ConversationSummary]
    total: int


# ============================================================================
# Message Schemas
# ============================================================================

class MessageCreate(BaseModel):
    """Schema for creating a message."""
    content: str = Field(..., min_length=1, max_length=10000)
    message_type: MessageType = MessageType.TEXT
    attachment_data: Optional[dict] = None


class MessageUpdate(BaseModel):
    """Schema for updating a message."""
    content: str = Field(..., min_length=1, max_length=10000)


class MessageResponse(BaseModel):
    """Schema for message response."""
    id: int
    conversation_id: int
    sender_id: int
    sender_username: str
    sender_first_name: Optional[str] = None
    sender_avatar_url: Optional[str] = None
    content: str
    message_type: MessageType
    attachment_data: Optional[dict] = None
    reply_to: Optional[dict] = None  # ReplyInfo
    reactions: List[dict] = []  # List of ReactionSummary
    reply_count: int = 0  # Number of replies in thread
    created_at: datetime
    updated_at: datetime
    is_edited: bool
    is_deleted: bool
    is_own_message: bool = False
    
    model_config = ConfigDict(from_attributes=True)


class MessagesListResponse(BaseModel):
    """Response for list of messages in a conversation."""
    messages: List[MessageResponse]
    total: int
    has_more: bool
    conversation_id: int


class ConversationDetail(BaseModel):
    """Full conversation detail with messages."""
    id: int
    name: Optional[str] = None
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    is_group: bool
    participants: List[ConversationParticipantInfo]
    participant_count: int = 0
    messages: List[MessageResponse]
    total_messages: int
    has_more_messages: bool
    created_at: datetime
    created_by: Optional[int] = None
    my_role: Optional[ParticipantRole] = None
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Group Chat Management Schemas
# ============================================================================

class GroupCreate(BaseModel):
    """Schema for creating a group chat."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = None
    participant_ids: List[int] = Field(default_factory=list)


class GroupUpdate(BaseModel):
    """Schema for updating group chat settings."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = None


class GroupMemberAdd(BaseModel):
    """Schema for adding members to a group."""
    user_ids: List[int] = Field(..., min_length=1)


class GroupMemberUpdate(BaseModel):
    """Schema for updating a member's role."""
    role: ParticipantRole


class GroupMemberInfo(BaseModel):
    """Detailed info about a group member."""
    user_id: int
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    role: ParticipantRole
    nickname: Optional[str] = None
    is_muted: bool = False
    joined_at: datetime
    added_by_username: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)


class GroupDetailResponse(BaseModel):
    """Full group details response."""
    id: int
    name: str
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime
    created_by: Optional[int] = None
    created_by_username: Optional[str] = None
    members: List[GroupMemberInfo]
    member_count: int
    my_role: ParticipantRole
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# User Notes Schemas
# ============================================================================

class UserNoteCreate(BaseModel):
    """Schema for creating a note about a user."""
    subject_id: int
    content: str = Field(..., min_length=1, max_length=5000)


class UserNoteUpdate(BaseModel):
    """Schema for updating a note."""
    content: str = Field(..., min_length=1, max_length=5000)


class UserNoteResponse(BaseModel):
    """Response for a user note."""
    id: int
    owner_id: int
    subject_id: int
    subject_username: str
    subject_first_name: Optional[str] = None
    subject_avatar_url: Optional[str] = None
    content: str
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class UserNotesListResponse(BaseModel):
    """Response for list of user notes."""
    notes: List[UserNoteResponse]
    total: int


# ============================================================================
# Generic Response Schemas
# ============================================================================

class SocialMessageResponse(BaseModel):
    """Generic message response for social operations."""
    message: str
    detail: Optional[str] = None


class UnreadCountResponse(BaseModel):
    """Response for unread message counts."""
    total_unread: int
    by_conversation: dict[int, int]  # conversation_id -> count


# ============================================================================
# Message Reactions Schemas
# ============================================================================

class ReactionCreate(BaseModel):
    """Schema for adding a reaction to a message."""
    emoji: str = Field(..., min_length=1, max_length=32)


class ReactionInfo(BaseModel):
    """Info about a single reaction."""
    id: int
    user_id: int
    username: str
    emoji: str
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class ReactionSummary(BaseModel):
    """Summary of reactions grouped by emoji."""
    emoji: str
    count: int
    users: List[str]  # usernames
    user_ids: List[int]
    has_reacted: bool = False  # if current user has this reaction


class MessageReactionsResponse(BaseModel):
    """All reactions on a message."""
    message_id: int
    reactions: List[ReactionSummary]
    total_count: int


# ============================================================================
# File Attachment Schemas
# ============================================================================

class AttachmentData(BaseModel):
    """Schema for file attachment data stored in message."""
    filename: str
    file_url: str
    file_size: int  # bytes
    mime_type: str
    thumbnail_url: Optional[str] = None  # for images
    width: Optional[int] = None  # for images
    height: Optional[int] = None  # for images


class FileUploadResponse(BaseModel):
    """Response after uploading a file."""
    file_url: str
    filename: str
    file_size: int
    mime_type: str
    thumbnail_url: Optional[str] = None
    file_category: Optional[str] = None  # image, document, archive, code, mobile, binary, security, data, text, other


# ============================================================================
# Reply/Thread Schemas
# ============================================================================

class ReplyInfo(BaseModel):
    """Info about a message being replied to."""
    id: int
    sender_username: str
    content_preview: str  # First 100 chars
    message_type: MessageType


class ThreadRepliesResponse(BaseModel):
    """Response for thread replies."""
    parent_message: "MessageResponse"
    replies: List["MessageResponse"]
    total_replies: int
    conversation_id: int


# ============================================================================
# WebSocket Event Schemas
# ============================================================================

class WSEventType(str, Enum):
    """WebSocket event types."""
    NEW_MESSAGE = "new_message"
    MESSAGE_EDITED = "message_edited"
    MESSAGE_DELETED = "message_deleted"
    REACTION_ADDED = "reaction_added"
    REACTION_REMOVED = "reaction_removed"
    TYPING = "typing"
    PRESENCE = "presence"
    READ_RECEIPT = "read_receipt"
    CONVERSATION_UPDATED = "conversation_updated"
    MEMBER_ADDED = "member_added"
    MEMBER_REMOVED = "member_removed"


class WSNewMessage(BaseModel):
    """WebSocket event for new message."""
    type: str = "new_message"
    conversation_id: int
    message: MessageResponse


class WSMessageEvent(BaseModel):
    """WebSocket event for message updates."""
    type: str  # message_edited, message_deleted
    conversation_id: int
    message_id: int
    content: Optional[str] = None  # for edits


class WSReactionEvent(BaseModel):
    """WebSocket event for reaction changes."""
    type: str  # reaction_added, reaction_removed
    conversation_id: int
    message_id: int
    user_id: int
    username: str
    emoji: str


class WSTypingEvent(BaseModel):
    """WebSocket event for typing indicator."""
    type: str = "typing"
    conversation_id: int
    user_id: int
    username: str
    is_typing: bool


class WSPresenceEvent(BaseModel):
    """WebSocket event for online/offline status."""
    type: str = "presence"
    user_id: int
    username: str
    is_online: bool


class WSReadReceipt(BaseModel):
    """WebSocket event for read receipts."""
    type: str = "read_receipt"
    conversation_id: int
    user_id: int
    username: str
    last_read_at: datetime


# ============================================================================
# Message Pinning Schemas
# ============================================================================

class PinnedMessageInfo(BaseModel):
    """Info about a pinned message."""
    id: int
    message_id: int
    conversation_id: int
    pinned_by: Optional[int] = None
    pinned_by_username: Optional[str] = None
    pinned_at: datetime
    message_content: str
    message_sender_username: str
    message_created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class PinnedMessagesResponse(BaseModel):
    """Response for list of pinned messages."""
    pinned_messages: List[PinnedMessageInfo]
    total: int
    conversation_id: int


# ============================================================================
# Message Forwarding Schemas
# ============================================================================

class ForwardMessageRequest(BaseModel):
    """Schema for forwarding a message."""
    target_conversation_ids: List[int] = Field(..., min_length=1, max_length=10)
    include_original_sender: bool = True  # Include "Forwarded from X" info


class ForwardedMessageInfo(BaseModel):
    """Info about a forwarded message."""
    original_message_id: int
    original_sender_username: str
    original_conversation_id: int
    forwarded_at: datetime


class ForwardMessageResponse(BaseModel):
    """Response after forwarding a message."""
    success: bool
    forwarded_to: List[int]  # conversation IDs
    failed: List[int]  # conversation IDs that failed
    messages_sent: int


# ============================================================================
# Read Receipts Schemas
# ============================================================================

class ReadReceiptInfo(BaseModel):
    """Info about who has read up to which message."""
    user_id: int
    username: str
    avatar_url: Optional[str] = None
    last_read_message_id: int
    read_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class ConversationReadReceipts(BaseModel):
    """Read receipts for a conversation."""
    conversation_id: int
    receipts: List[ReadReceiptInfo]


class MessageReadBy(BaseModel):
    """Who has read a specific message."""
    message_id: int
    read_by: List[ReadReceiptInfo]
    total_participants: int
    read_count: int


# ============================================================================
# Mention Schemas
# ============================================================================

class MentionInfo(BaseModel):
    """Info about a mention in a message."""
    user_id: int
    username: str
    start_index: int  # Position in message content
    end_index: int


class MessageWithMentions(BaseModel):
    """Message with parsed mentions."""
    message_id: int
    content: str
    mentions: List[MentionInfo]
    mentioned_user_ids: List[int]


# ============================================================================
# WebSocket Events for New Features
# ============================================================================

class WSPinEvent(BaseModel):
    """WebSocket event for message pin/unpin."""
    type: str  # message_pinned, message_unpinned
    conversation_id: int
    message_id: int
    pinned_by: Optional[int] = None
    pinned_by_username: Optional[str] = None


class WSForwardEvent(BaseModel):
    """WebSocket event for forwarded message."""
    type: str = "message_forwarded"
    original_message_id: int
    conversation_id: int  # destination
    message: MessageResponse


# ============================================================================
# Message Search Schemas
# ============================================================================

class MessageSearchResult(BaseModel):
    """A search result item."""
    message_id: int
    conversation_id: int
    conversation_name: Optional[str] = None
    sender_username: str
    content: str
    highlighted_content: Optional[str] = None  # Content with search term highlighted
    message_type: MessageType
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class MessageSearchResponse(BaseModel):
    """Response for message search."""
    query: str
    results: List[MessageSearchResult]
    total: int
    has_more: bool


# ============================================================================
# Poll Schemas
# ============================================================================

class PollOptionCreate(BaseModel):
    """Schema for creating a poll option."""
    text: str = Field(..., min_length=1, max_length=500)


class PollOptionResponse(BaseModel):
    """Response schema for a poll option."""
    id: int
    text: str
    vote_count: int
    percentage: float = 0.0  # Percentage of total votes
    voters: List[str] = []  # Usernames (empty if anonymous)
    has_voted: bool = False  # Current user voted for this
    added_by_username: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)


class PollCreate(BaseModel):
    """Schema for creating a poll."""
    question: str = Field(..., min_length=1, max_length=1000)
    options: List[str] = Field(..., min_length=2, max_length=10)
    poll_type: str = Field(default="single", pattern="^(single|multiple)$")
    is_anonymous: bool = False
    allow_add_options: bool = False
    closes_at: Optional[datetime] = None


class PollResponse(BaseModel):
    """Response schema for a poll."""
    id: int
    conversation_id: int
    message_id: Optional[int] = None
    question: str
    poll_type: str
    is_anonymous: bool
    allow_add_options: bool
    closes_at: Optional[datetime] = None
    is_closed: bool
    created_by: Optional[int] = None
    created_by_username: Optional[str] = None
    created_at: datetime
    total_votes: int
    total_voters: int
    options: List[PollOptionResponse]
    has_voted: bool = False  # Current user has voted
    
    model_config = ConfigDict(from_attributes=True)


class PollVoteRequest(BaseModel):
    """Schema for voting on a poll."""
    option_ids: List[int] = Field(..., min_length=1)


class PollAddOptionRequest(BaseModel):
    """Schema for adding an option to a poll."""
    text: str = Field(..., min_length=1, max_length=500)


# ============================================================================
# GIF Schemas
# ============================================================================

class GifItem(BaseModel):
    """Schema for a GIF item."""
    id: str
    title: str
    url: str  # Full size URL
    preview_url: str  # Small preview
    width: int
    height: int
    source: str = "giphy"  # or "tenor"


class GifSearchResponse(BaseModel):
    """Response for GIF search."""
    query: str
    gifs: List[GifItem]
    next_offset: Optional[str] = None  # For pagination


class GifTrendingResponse(BaseModel):
    """Response for trending GIFs."""
    gifs: List[GifItem]
    next_offset: Optional[str] = None


# ============================================================================
# Mute Conversation Schemas
# ============================================================================

class MuteRequest(BaseModel):
    """Schema for muting a conversation."""
    mute: bool
    duration_hours: Optional[int] = Field(None, ge=1, le=8760)  # Up to 1 year


class MuteStatusResponse(BaseModel):
    """Response for mute status."""
    conversation_id: int
    is_muted: bool
    muted_until: Optional[datetime] = None


# ============================================================================
# WebSocket Events for New Features (Extended)
# ============================================================================

class WSPollEvent(BaseModel):
    """WebSocket event for poll updates."""
    type: str  # poll_created, poll_voted, poll_closed
    conversation_id: int
    poll_id: int
    poll: Optional[PollResponse] = None


# ============================================================================
# Message Bookmark Schemas
# ============================================================================

class BookmarkCreate(BaseModel):
    """Schema for creating a bookmark."""
    message_id: int
    note: Optional[str] = Field(None, max_length=500)


class BookmarkUpdate(BaseModel):
    """Schema for updating a bookmark note."""
    note: Optional[str] = Field(None, max_length=500)


class BookmarkResponse(BaseModel):
    """Response schema for a bookmark."""
    id: int
    user_id: int
    message_id: int
    conversation_id: int
    conversation_name: Optional[str] = None
    message_content: str
    message_sender_username: str
    message_sender_avatar_url: Optional[str] = None
    message_type: MessageType
    message_created_at: datetime
    note: Optional[str] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class BookmarksListResponse(BaseModel):
    """Response for list of bookmarks."""
    bookmarks: List[BookmarkResponse]
    total: int


# ============================================================================
# Message Edit History Schemas
# ============================================================================

class EditHistoryEntry(BaseModel):
    """A single entry in the edit history."""
    id: int
    message_id: int
    previous_content: str
    edited_at: datetime
    edit_number: int
    
    model_config = ConfigDict(from_attributes=True)


class MessageEditHistoryResponse(BaseModel):
    """Response for message edit history."""
    message_id: int
    current_content: str
    edit_count: int
    history: List[EditHistoryEntry]


# ============================================================================
# Share Findings & Reports Schemas
# ============================================================================

class ShareFindingRequest(BaseModel):
    """Request to share a finding to a conversation."""
    finding_id: int
    conversation_id: int
    comment: Optional[str] = None  # Optional comment when sharing


class ShareReportRequest(BaseModel):
    """Request to share a report/scan to a conversation."""
    report_id: int
    conversation_id: int
    comment: Optional[str] = None  # Optional comment when sharing


class SharedFindingData(BaseModel):
    """Data structure for shared finding in message attachment."""
    finding_id: int
    project_id: int
    project_name: str
    scan_run_id: Optional[int] = None
    severity: str
    type: str
    summary: str
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    details: Optional[dict] = None
    shared_by_username: str
    shared_at: datetime


class SharedReportData(BaseModel):
    """Data structure for shared report in message attachment."""
    report_id: int
    project_id: int
    project_name: str
    scan_run_id: Optional[int] = None
    title: str
    summary: Optional[str] = None
    risk_score: Optional[float] = None
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    shared_by_username: str
    shared_at: datetime


class ShareResponse(BaseModel):
    """Response after sharing a finding or report."""
    success: bool
    message_id: int
    conversation_id: int


# ============================================================================
# User Presence Schemas
# ============================================================================

class PresenceStatus(str, Enum):
    """User presence status options."""
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    DND = "dnd"  # Do Not Disturb
    OFFLINE = "offline"


class UserPresenceUpdate(BaseModel):
    """Request to update user presence."""
    status: Optional[PresenceStatus] = None
    custom_status: Optional[str] = Field(None, max_length=100)
    status_emoji: Optional[str] = Field(None, max_length=10)
    # Duration in hours for custom status (null = indefinite)
    status_duration_hours: Optional[int] = Field(None, ge=1, le=168)  # Max 1 week
    clear_custom_status: Optional[bool] = False


class UserPresenceResponse(BaseModel):
    """Response with user presence info."""
    user_id: int
    username: str
    first_name: Optional[str] = None
    avatar_url: Optional[str] = None
    status: PresenceStatus
    custom_status: Optional[str] = None
    status_emoji: Optional[str] = None
    status_expires_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    is_online: bool = False
    
    model_config = ConfigDict(from_attributes=True)


class BulkPresenceRequest(BaseModel):
    """Request to get presence for multiple users."""
    user_ids: List[int]


class BulkPresenceResponse(BaseModel):
    """Response with presence for multiple users."""
    users: List[UserPresenceResponse]
