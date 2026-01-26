"""Service for Kanban board management."""
from datetime import datetime
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.models.models import (
    User, Project, ProjectCollaborator, Finding,
    KanbanBoard, KanbanColumn, KanbanCard, KanbanCardComment
)
from backend.core.logging import get_logger

logger = get_logger(__name__)


# ============================================================================
# Board Operations
# ============================================================================

def has_project_access(db: Session, project_id: int, user_id: int) -> bool:
    """Check if user has access to the project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return False
    
    # Owner always has access
    if project.owner_id == user_id:
        return True
    
    # Check collaborator access (only accepted collaborators)
    collaborator = db.query(ProjectCollaborator).filter(
        ProjectCollaborator.project_id == project_id,
        ProjectCollaborator.user_id == user_id,
        ProjectCollaborator.status == "accepted"
    ).first()
    
    return collaborator is not None


def get_or_create_board(db: Session, project_id: int, user_id: int) -> Tuple[Optional[KanbanBoard], Optional[str]]:
    """Get or create the default board for a project."""
    if not has_project_access(db, project_id, user_id):
        return None, "Access denied"
    
    # Check if board exists
    board = db.query(KanbanBoard).filter(KanbanBoard.project_id == project_id).first()
    
    if not board:
        # Create default board with standard columns
        board = KanbanBoard(
            project_id=project_id,
            name="Project Board",
            created_by=user_id
        )
        db.add(board)
        db.flush()
        
        # Create default columns
        default_columns = [
            {"name": "Backlog", "color": "#6b7280", "position": 0},
            {"name": "To Do", "color": "#3b82f6", "position": 1},
            {"name": "In Progress", "color": "#f59e0b", "position": 2},
            {"name": "Review", "color": "#8b5cf6", "position": 3},
            {"name": "Done", "color": "#10b981", "position": 4}
        ]
        
        for col_data in default_columns:
            column = KanbanColumn(
                board_id=board.id,
                name=col_data["name"],
                color=col_data["color"],
                position=col_data["position"]
            )
            db.add(column)
        
        db.commit()
        db.refresh(board)
    
    return board, None


def get_board_detail(db: Session, board_id: int, user_id: int) -> Tuple[Optional[dict], Optional[str]]:
    """Get full board with columns and cards."""
    board = db.query(KanbanBoard).filter(KanbanBoard.id == board_id).first()
    if not board:
        return None, "Board not found"
    
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    # Get creator info
    creator = db.query(User).filter(User.id == board.created_by).first() if board.created_by else None
    
    # Get columns with cards
    columns = db.query(KanbanColumn).filter(
        KanbanColumn.board_id == board_id
    ).order_by(KanbanColumn.position).all()
    
    columns_data = []
    total_cards = 0
    
    for column in columns:
        cards = db.query(KanbanCard).filter(
            KanbanCard.column_id == column.id
        ).order_by(KanbanCard.position).all()
        
        cards_data = []
        for card in cards:
            card_data = _format_card(db, card)
            cards_data.append(card_data)
        
        total_cards += len(cards)
        
        columns_data.append({
            "id": column.id,
            "board_id": column.board_id,
            "name": column.name,
            "position": column.position,
            "color": column.color,
            "wip_limit": column.wip_limit,
            "card_count": len(cards),
            "cards": cards_data
        })
    
    return {
        "id": board.id,
        "project_id": board.project_id,
        "name": board.name,
        "description": board.description,
        "created_by": board.created_by,
        "creator_username": creator.username if creator else None,
        "created_at": board.created_at,
        "updated_at": board.updated_at,
        "settings": board.settings,
        "column_count": len(columns),
        "card_count": total_cards,
        "columns": columns_data
    }, None


def update_board(
    db: Session, 
    board_id: int, 
    user_id: int,
    name: Optional[str] = None,
    description: Optional[str] = None,
    settings: Optional[dict] = None
) -> Tuple[Optional[KanbanBoard], Optional[str]]:
    """Update board settings."""
    board = db.query(KanbanBoard).filter(KanbanBoard.id == board_id).first()
    if not board:
        return None, "Board not found"
    
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    if name:
        board.name = name
    if description is not None:
        board.description = description
    if settings is not None:
        board.settings = settings
    
    db.commit()
    db.refresh(board)
    
    return board, None


# ============================================================================
# Column Operations
# ============================================================================

def create_column(
    db: Session,
    board_id: int,
    user_id: int,
    name: str,
    color: Optional[str] = None,
    wip_limit: Optional[int] = None
) -> Tuple[Optional[KanbanColumn], Optional[str]]:
    """Create a new column."""
    board = db.query(KanbanBoard).filter(KanbanBoard.id == board_id).first()
    if not board:
        return None, "Board not found"
    
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    # Get next position
    max_pos = db.query(func.max(KanbanColumn.position)).filter(
        KanbanColumn.board_id == board_id
    ).scalar() or -1
    
    column = KanbanColumn(
        board_id=board_id,
        name=name,
        position=max_pos + 1,
        color=color,
        wip_limit=wip_limit
    )
    db.add(column)
    db.commit()
    db.refresh(column)
    
    return column, None


def update_column(
    db: Session,
    column_id: int,
    user_id: int,
    name: Optional[str] = None,
    color: Optional[str] = None,
    wip_limit: Optional[int] = None
) -> Tuple[Optional[KanbanColumn], Optional[str]]:
    """Update a column."""
    column = db.query(KanbanColumn).filter(KanbanColumn.id == column_id).first()
    if not column:
        return None, "Column not found"
    
    board = db.query(KanbanBoard).filter(KanbanBoard.id == column.board_id).first()
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    if name:
        column.name = name
    if color is not None:
        column.color = color
    if wip_limit is not None:
        column.wip_limit = wip_limit if wip_limit > 0 else None
    
    db.commit()
    db.refresh(column)
    
    return column, None


def delete_column(db: Session, column_id: int, user_id: int) -> Tuple[bool, Optional[str]]:
    """Delete a column and all its cards."""
    column = db.query(KanbanColumn).filter(KanbanColumn.id == column_id).first()
    if not column:
        return False, "Column not found"
    
    board = db.query(KanbanBoard).filter(KanbanBoard.id == column.board_id).first()
    if not board:
        return False, "Board not found"
    if not has_project_access(db, board.project_id, user_id):
        return False, "Access denied"
    
    db.delete(column)
    db.commit()
    
    return True, None


def reorder_columns(
    db: Session,
    board_id: int,
    user_id: int,
    column_ids: List[int]
) -> Tuple[bool, Optional[str]]:
    """Reorder columns in a board."""
    board = db.query(KanbanBoard).filter(KanbanBoard.id == board_id).first()
    if not board:
        return False, "Board not found"
    
    if not has_project_access(db, board.project_id, user_id):
        return False, "Access denied"
    
    for position, column_id in enumerate(column_ids):
        column = db.query(KanbanColumn).filter(
            KanbanColumn.id == column_id,
            KanbanColumn.board_id == board_id
        ).first()
        if column:
            column.position = position
    
    db.commit()
    return True, None


# ============================================================================
# Card Operations
# ============================================================================

def _format_card(db: Session, card: KanbanCard) -> dict:
    """Format card data for response."""
    # Get creator info
    creator = db.query(User).filter(User.id == card.created_by).first() if card.created_by else None
    
    # Get assignee info
    assignees = []
    if card.assignee_ids:
        users = db.query(User).filter(User.id.in_(card.assignee_ids)).all()
        assignees = [{
            "user_id": u.id,
            "username": u.username,
            "first_name": u.first_name,
            "avatar_url": u.avatar_url
        } for u in users]
    
    return {
        "id": card.id,
        "column_id": card.column_id,
        "title": card.title,
        "description": card.description,
        "position": card.position,
        "priority": card.priority,
        "labels": card.labels,
        "due_date": card.due_date,
        "estimated_hours": card.estimated_hours,
        "assignee_ids": card.assignee_ids,
        "assignees": assignees,
        "created_by": card.created_by,
        "creator_username": creator.username if creator else None,
        "created_at": card.created_at,
        "updated_at": card.updated_at,
        "completed_at": card.completed_at,
        "finding_id": card.finding_id,
        "checklist": card.checklist,
        "attachment_count": card.attachment_count,
        "comment_count": card.comment_count,
        "color": card.color
    }


def get_card(db: Session, card_id: int, user_id: int) -> Tuple[Optional[dict], Optional[str]]:
    """Get a card by ID."""
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    if not card:
        return None, "Card not found"
    
    column = db.query(KanbanColumn).filter(KanbanColumn.id == card.column_id).first()
    if not column:
        return None, "Column not found"
    board = db.query(KanbanBoard).filter(KanbanBoard.id == column.board_id).first()
    if not board:
        return None, "Board not found"
    
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    return _format_card(db, card), None


def create_card(
    db: Session,
    column_id: int,
    user_id: int,
    title: str,
    description: Optional[str] = None,
    priority: Optional[str] = None,
    labels: Optional[List[dict]] = None,
    due_date: Optional[datetime] = None,
    estimated_hours: Optional[float] = None,
    assignee_ids: Optional[List[int]] = None,
    finding_id: Optional[int] = None,
    checklist: Optional[List[dict]] = None,
    color: Optional[str] = None
) -> Tuple[Optional[dict], Optional[str]]:
    """Create a new card."""
    column = db.query(KanbanColumn).filter(KanbanColumn.id == column_id).first()
    if not column:
        return None, "Column not found"
    
    board = db.query(KanbanBoard).filter(KanbanBoard.id == column.board_id).first()
    if not board:
        return None, "Board not found"
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    # Check WIP limit
    if column.wip_limit:
        current_count = db.query(func.count(KanbanCard.id)).filter(
            KanbanCard.column_id == column_id
        ).scalar()
        if current_count >= column.wip_limit:
            return None, f"Column WIP limit ({column.wip_limit}) reached"
    
    # Get next position
    max_pos = db.query(func.max(KanbanCard.position)).filter(
        KanbanCard.column_id == column_id
    ).scalar() or -1
    
    card = KanbanCard(
        column_id=column_id,
        title=title,
        description=description,
        position=max_pos + 1,
        priority=priority,
        labels=labels,
        due_date=due_date,
        estimated_hours=estimated_hours,
        assignee_ids=assignee_ids,
        finding_id=finding_id,
        checklist=checklist,
        created_by=user_id,
        color=color
    )
    db.add(card)
    db.commit()
    db.refresh(card)
    
    return _format_card(db, card), None


def update_card(
    db: Session,
    card_id: int,
    user_id: int,
    title: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[str] = None,
    labels: Optional[List[dict]] = None,
    due_date: Optional[datetime] = None,
    estimated_hours: Optional[float] = None,
    assignee_ids: Optional[List[int]] = None,
    checklist: Optional[List[dict]] = None,
    completed_at: Optional[datetime] = None,
    color: Optional[str] = None
) -> Tuple[Optional[dict], Optional[str]]:
    """Update a card."""
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    if not card:
        return None, "Card not found"
    
    column = db.query(KanbanColumn).filter(KanbanColumn.id == card.column_id).first()
    if not column:
        return None, "Column not found"
    board = db.query(KanbanBoard).filter(KanbanBoard.id == column.board_id).first()
    if not board:
        return None, "Board not found"
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    if title:
        card.title = title
    if description is not None:
        card.description = description
    if priority is not None:
        card.priority = priority
    if labels is not None:
        card.labels = labels
    if due_date is not None:
        card.due_date = due_date
    if estimated_hours is not None:
        card.estimated_hours = estimated_hours
    if assignee_ids is not None:
        card.assignee_ids = assignee_ids
    if checklist is not None:
        card.checklist = checklist
    if completed_at is not None:
        card.completed_at = completed_at
    if color is not None:
        card.color = color if color else None  # Allow clearing color with empty string
    
    db.commit()
    db.refresh(card)
    
    return _format_card(db, card), None


def move_card(
    db: Session,
    card_id: int,
    user_id: int,
    target_column_id: int,
    position: int
) -> Tuple[Optional[dict], Optional[str]]:
    """Move a card to a different column and/or position."""
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    if not card:
        return None, "Card not found"
    
    target_column = db.query(KanbanColumn).filter(KanbanColumn.id == target_column_id).first()
    if not target_column:
        return None, "Target column not found"
    
    board = db.query(KanbanBoard).filter(KanbanBoard.id == target_column.board_id).first()
    if not board:
        return None, "Board not found"
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    # Check WIP limit on target column (if moving to a different column)
    if card.column_id != target_column_id and target_column.wip_limit:
        current_count = db.query(func.count(KanbanCard.id)).filter(
            KanbanCard.column_id == target_column_id
        ).scalar()
        if current_count >= target_column.wip_limit:
            return None, f"Target column WIP limit ({target_column.wip_limit}) reached"
    
    old_column_id = card.column_id
    old_position = card.position
    
    # Update positions in old column (shift up)
    if card.column_id != target_column_id:
        db.query(KanbanCard).filter(
            KanbanCard.column_id == old_column_id,
            KanbanCard.position > old_position
        ).update({KanbanCard.position: KanbanCard.position - 1})
    
    # Update positions in target column (shift down)
    db.query(KanbanCard).filter(
        KanbanCard.column_id == target_column_id,
        KanbanCard.position >= position
    ).update({KanbanCard.position: KanbanCard.position + 1})
    
    # Move the card
    card.column_id = target_column_id
    card.position = position
    
    db.commit()
    db.refresh(card)
    
    return _format_card(db, card), None


def delete_card(db: Session, card_id: int, user_id: int) -> Tuple[bool, Optional[str]]:
    """Delete a card."""
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    if not card:
        return False, "Card not found"
    
    column = db.query(KanbanColumn).filter(KanbanColumn.id == card.column_id).first()
    if not column:
        return False, "Column not found"
    board = db.query(KanbanBoard).filter(KanbanBoard.id == column.board_id).first()
    if not board:
        return False, "Board not found"
    if not has_project_access(db, board.project_id, user_id):
        return False, "Access denied"
    
    column_id = card.column_id
    position = card.position
    
    db.delete(card)
    
    # Reorder remaining cards
    db.query(KanbanCard).filter(
        KanbanCard.column_id == column_id,
        KanbanCard.position > position
    ).update({KanbanCard.position: KanbanCard.position - 1})
    
    db.commit()
    
    return True, None


# ============================================================================
# Comment Operations
# ============================================================================

def add_comment(
    db: Session,
    card_id: int,
    user_id: int,
    content: str
) -> Tuple[Optional[dict], Optional[str]]:
    """Add a comment to a card."""
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    if not card:
        return None, "Card not found"
    
    column = db.query(KanbanColumn).filter(KanbanColumn.id == card.column_id).first()
    if not column:
        return None, "Column not found"
    board = db.query(KanbanBoard).filter(KanbanBoard.id == column.board_id).first()
    if not board:
        return None, "Board not found"
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    user = db.query(User).filter(User.id == user_id).first()
    
    comment = KanbanCardComment(
        card_id=card_id,
        user_id=user_id,
        content=content
    )
    db.add(comment)
    
    # Update comment count
    card.comment_count = (card.comment_count or 0) + 1
    
    db.commit()
    db.refresh(comment)
    
    return {
        "id": comment.id,
        "card_id": comment.card_id,
        "user_id": comment.user_id,
        "username": user.username if user else None,
        "user_avatar_url": user.avatar_url if user else None,
        "content": comment.content,
        "created_at": comment.created_at,
        "updated_at": comment.updated_at
    }, None


def get_card_comments(
    db: Session,
    card_id: int,
    user_id: int
) -> Tuple[List[dict], Optional[str]]:
    """Get all comments for a card."""
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    if not card:
        return [], "Card not found"
    
    column = db.query(KanbanColumn).filter(KanbanColumn.id == card.column_id).first()
    if not column:
        return [], "Column not found"
    board = db.query(KanbanBoard).filter(KanbanBoard.id == column.board_id).first()
    if not board:
        return [], "Board not found"
    if not has_project_access(db, board.project_id, user_id):
        return [], "Access denied"
    
    comments = db.query(KanbanCardComment).filter(
        KanbanCardComment.card_id == card_id
    ).order_by(KanbanCardComment.created_at.desc()).all()
    
    results = []
    for comment in comments:
        user = db.query(User).filter(User.id == comment.user_id).first() if comment.user_id else None
        results.append({
            "id": comment.id,
            "card_id": comment.card_id,
            "user_id": comment.user_id,
            "username": user.username if user else None,
            "user_avatar_url": user.avatar_url if user else None,
            "content": comment.content,
            "created_at": comment.created_at,
            "updated_at": comment.updated_at
        })
    
    return results, None


def delete_comment(db: Session, comment_id: int, user_id: int) -> Tuple[bool, Optional[str]]:
    """Delete a comment (only by owner)."""
    comment = db.query(KanbanCardComment).filter(KanbanCardComment.id == comment_id).first()
    if not comment:
        return False, "Comment not found"
    
    if comment.user_id != user_id:
        return False, "You can only delete your own comments"
    
    card = db.query(KanbanCard).filter(KanbanCard.id == comment.card_id).first()
    if card:
        card.comment_count = max(0, (card.comment_count or 0) - 1)
    
    db.delete(comment)
    db.commit()
    
    return True, None


# ============================================================================
# Finding Integration
# ============================================================================

def create_card_from_finding(
    db: Session,
    board_id: int,
    finding_id: int,
    user_id: int,
    column_name: str = "Backlog"
) -> Tuple[Optional[dict], Optional[str]]:
    """Create a card from a security finding."""
    board = db.query(KanbanBoard).filter(KanbanBoard.id == board_id).first()
    if not board:
        return None, "Board not found"
    
    if not has_project_access(db, board.project_id, user_id):
        return None, "Access denied"
    
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.project_id == board.project_id
    ).first()
    if not finding:
        return None, "Finding not found in this project"
    
    # Find target column
    column = db.query(KanbanColumn).filter(
        KanbanColumn.board_id == board_id,
        KanbanColumn.name == column_name
    ).first()
    if not column:
        # Use first column if target not found
        column = db.query(KanbanColumn).filter(
            KanbanColumn.board_id == board_id
        ).order_by(KanbanColumn.position).first()
    
    if not column:
        return None, "No columns in board"
    
    # Map severity to priority
    priority_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low"
    }
    priority = priority_map.get(finding.severity.lower(), "medium")
    
    # Create card
    return create_card(
        db=db,
        column_id=column.id,
        user_id=user_id,
        title=f"[{finding.severity.upper()}] {finding.type}",
        description=f"**Finding Summary:**\n{finding.summary}\n\n**File:** {finding.file_path or 'N/A'}\n**Lines:** {finding.start_line}-{finding.end_line}" if finding.file_path else finding.summary,
        priority=priority,
        labels=[{"name": finding.severity.capitalize(), "color": _get_severity_color(finding.severity)}],
        finding_id=finding_id
    )


def _get_severity_color(severity: str) -> str:
    """Get color for severity label."""
    colors = {
        "critical": "#dc2626",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#3b82f6",
        "info": "#6b7280"
    }
    return colors.get(severity.lower(), "#6b7280")
