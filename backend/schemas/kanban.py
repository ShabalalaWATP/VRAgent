"""Kanban board schemas for project task management."""
from datetime import datetime
from enum import Enum
from typing import Optional, List, Any
from pydantic import BaseModel, Field, ConfigDict


class CardPriority(str, Enum):
    """Card priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CardLabel(BaseModel):
    """A label on a card."""
    name: str
    color: str  # Hex color


class ChecklistItem(BaseModel):
    """A checklist item on a card."""
    id: str
    text: str
    completed: bool = False


# ============================================================================
# Board Schemas
# ============================================================================

class BoardCreate(BaseModel):
    """Request to create a new board."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)


class BoardUpdate(BaseModel):
    """Request to update a board."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    settings: Optional[dict] = None


class BoardResponse(BaseModel):
    """Response with board info."""
    id: int
    project_id: int
    name: str
    description: Optional[str] = None
    created_by: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    settings: Optional[dict] = None
    column_count: int = 0
    card_count: int = 0
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Column Schemas
# ============================================================================

class ColumnCreate(BaseModel):
    """Request to create a new column."""
    name: str = Field(..., min_length=1, max_length=50)
    color: Optional[str] = None
    wip_limit: Optional[int] = Field(None, ge=1, le=100)


class ColumnUpdate(BaseModel):
    """Request to update a column."""
    name: Optional[str] = Field(None, min_length=1, max_length=50)
    color: Optional[str] = None
    wip_limit: Optional[int] = Field(None, ge=0, le=100)  # 0 = no limit


class ColumnReorder(BaseModel):
    """Request to reorder columns."""
    column_ids: List[int]


class ColumnResponse(BaseModel):
    """Response with column info."""
    id: int
    board_id: int
    name: str
    position: int
    color: Optional[str] = None
    wip_limit: Optional[int] = None
    card_count: int = 0
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Card Schemas
# ============================================================================

class CardCreate(BaseModel):
    """Request to create a new card."""
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    priority: Optional[CardPriority] = None
    labels: Optional[List[CardLabel]] = None
    due_date: Optional[datetime] = None
    estimated_hours: Optional[float] = Field(None, ge=0, le=1000)
    assignee_ids: Optional[List[int]] = None
    finding_id: Optional[int] = None
    checklist: Optional[List[ChecklistItem]] = None
    color: Optional[str] = None  # Card background color (hex)


class CardUpdate(BaseModel):
    """Request to update a card."""
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    priority: Optional[CardPriority] = None
    labels: Optional[List[CardLabel]] = None
    due_date: Optional[datetime] = None
    estimated_hours: Optional[float] = Field(None, ge=0, le=1000)
    assignee_ids: Optional[List[int]] = None
    checklist: Optional[List[ChecklistItem]] = None
    completed_at: Optional[datetime] = None
    color: Optional[str] = None  # Card background color (hex)


class CardMove(BaseModel):
    """Request to move a card to a different column/position."""
    column_id: int
    position: int


class CardReorder(BaseModel):
    """Request to reorder cards in a column."""
    card_ids: List[int]


class AssigneeInfo(BaseModel):
    """Info about a card assignee."""
    user_id: int
    username: str
    first_name: Optional[str] = None
    avatar_url: Optional[str] = None


class CardResponse(BaseModel):
    """Response with card info."""
    id: int
    column_id: int
    title: str
    description: Optional[str] = None
    position: int
    priority: Optional[str] = None
    labels: Optional[List[CardLabel]] = None
    due_date: Optional[datetime] = None
    estimated_hours: Optional[float] = None
    assignee_ids: Optional[List[int]] = None
    assignees: Optional[List[AssigneeInfo]] = None
    created_by: Optional[int] = None
    creator_username: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    finding_id: Optional[int] = None
    checklist: Optional[List[ChecklistItem]] = None
    attachment_count: int = 0
    comment_count: int = 0
    color: Optional[str] = None  # Card background color (hex)
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Comment Schemas
# ============================================================================

class CommentCreate(BaseModel):
    """Request to create a comment on a card."""
    content: str = Field(..., min_length=1, max_length=5000)


class CommentUpdate(BaseModel):
    """Request to update a comment."""
    content: str = Field(..., min_length=1, max_length=5000)


class CommentResponse(BaseModel):
    """Response with comment info."""
    id: int
    card_id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    user_avatar_url: Optional[str] = None
    content: str
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Full Board Response (with all data)
# ============================================================================

class ColumnWithCards(ColumnResponse):
    """Column with its cards."""
    cards: List[CardResponse] = []


class BoardDetailResponse(BoardResponse):
    """Full board with columns and cards."""
    columns: List[ColumnWithCards] = []
    creator_username: Optional[str] = None


# ============================================================================
# Activity/History Schemas
# ============================================================================

class BoardActivity(BaseModel):
    """Activity log entry for board."""
    id: int
    action: str  # created_card, moved_card, completed_card, etc.
    user_id: int
    username: str
    card_id: Optional[int] = None
    card_title: Optional[str] = None
    details: Optional[dict] = None
    created_at: datetime
