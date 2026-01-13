"""Kanban board API routes for project task management."""
import asyncio
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List

from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.core.auth import get_current_active_user
from backend.core.kanban_manager import kanban_manager
from backend.models.models import User, KanbanColumn, KanbanCard
from backend.schemas.kanban import (
    BoardCreate,
    BoardUpdate,
    BoardResponse,
    BoardDetailResponse,
    ColumnCreate,
    ColumnUpdate,
    ColumnReorder,
    ColumnResponse,
    CardCreate,
    CardUpdate,
    CardMove,
    CardResponse,
    CommentCreate,
    CommentResponse,
)
from backend.services.kanban_service import (
    get_or_create_board,
    get_board_detail,
    update_board,
    create_column,
    update_column,
    delete_column,
    reorder_columns,
    create_card,
    get_card,
    update_card,
    move_card,
    delete_card,
    add_comment,
    get_card_comments,
    delete_comment,
    create_card_from_finding,
)

router = APIRouter(prefix="/kanban", tags=["kanban"])
logger = get_logger(__name__)


# ============================================================================
# Board Endpoints
# ============================================================================

@router.get("/projects/{project_id}/board", response_model=BoardDetailResponse)
async def get_project_board(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get or create the Kanban board for a project."""
    # Get or create the board
    board, error = get_or_create_board(db, project_id, current_user.id)
    if error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=error)
    
    # Get full board detail
    board_data, error = get_board_detail(db, board.id, current_user.id)
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    
    return BoardDetailResponse(**board_data)


@router.put("/boards/{board_id}", response_model=BoardResponse)
async def update_board_endpoint(
    board_id: int,
    request: BoardUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update board settings."""
    board, error = update_board(
        db, board_id, current_user.id,
        name=request.name,
        description=request.description,
        settings=request.settings
    )
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    
    return BoardResponse(
        id=board.id,
        project_id=board.project_id,
        name=board.name,
        description=board.description,
        created_by=board.created_by,
        created_at=board.created_at,
        updated_at=board.updated_at,
        settings=board.settings
    )


# ============================================================================
# Column Endpoints
# ============================================================================

@router.post("/boards/{board_id}/columns", response_model=ColumnResponse)
async def create_column_endpoint(
    board_id: int,
    request: ColumnCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create a new column."""
    column, error = create_column(
        db, board_id, current_user.id,
        name=request.name,
        color=request.color,
        wip_limit=request.wip_limit
    )
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Broadcast to WebSocket clients
    if kanban_manager.is_connected(board_id):
        asyncio.create_task(kanban_manager.broadcast_column_create(
            board_id=board_id,
            user_id=current_user.id,
            column={
                "id": column.id,
                "board_id": column.board_id,
                "name": column.name,
                "position": column.position,
                "color": column.color,
                "wip_limit": column.wip_limit,
                "cards": []
            }
        ))

    return ColumnResponse(
        id=column.id,
        board_id=column.board_id,
        name=column.name,
        position=column.position,
        color=column.color,
        wip_limit=column.wip_limit,
        card_count=0
    )


@router.put("/columns/{column_id}", response_model=ColumnResponse)
async def update_column_endpoint(
    column_id: int,
    request: ColumnUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update a column."""
    column, error = update_column(
        db, column_id, current_user.id,
        name=request.name,
        color=request.color,
        wip_limit=request.wip_limit
    )
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Broadcast to WebSocket clients
    board_id = column.board_id
    if kanban_manager.is_connected(board_id):
        updates = {}
        if request.name is not None:
            updates["name"] = request.name
        if request.color is not None:
            updates["color"] = request.color
        if request.wip_limit is not None:
            updates["wip_limit"] = request.wip_limit
        asyncio.create_task(kanban_manager.broadcast_column_update(
            board_id=board_id,
            user_id=current_user.id,
            column_id=column_id,
            updates=updates
        ))

    return ColumnResponse(
        id=column.id,
        board_id=column.board_id,
        name=column.name,
        position=column.position,
        color=column.color,
        wip_limit=column.wip_limit
    )


@router.delete("/columns/{column_id}")
async def delete_column_endpoint(
    column_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete a column and all its cards."""
    # Get board_id before deletion
    column = db.query(KanbanColumn).filter(KanbanColumn.id == column_id).first()
    board_id = column.board_id if column else None

    success, error = delete_column(db, column_id, current_user.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Broadcast to WebSocket clients
    if board_id and kanban_manager.is_connected(board_id):
        asyncio.create_task(kanban_manager.broadcast_column_delete(
            board_id=board_id,
            user_id=current_user.id,
            column_id=column_id
        ))

    return {"message": "Column deleted"}


@router.put("/boards/{board_id}/columns/reorder")
async def reorder_columns_endpoint(
    board_id: int,
    request: ColumnReorder,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Reorder columns in a board."""
    success, error = reorder_columns(db, board_id, current_user.id, request.column_ids)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Broadcast to WebSocket clients
    if kanban_manager.is_connected(board_id):
        asyncio.create_task(kanban_manager.broadcast_columns_reorder(
            board_id=board_id,
            user_id=current_user.id,
            column_ids=request.column_ids
        ))

    return {"message": "Columns reordered"}


# ============================================================================
# Card Endpoints
# ============================================================================

@router.post("/columns/{column_id}/cards", response_model=CardResponse)
async def create_card_endpoint(
    column_id: int,
    request: CardCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create a new card."""
    card_data, error = create_card(
        db, column_id, current_user.id,
        title=request.title,
        description=request.description,
        priority=request.priority.value if request.priority else None,
        labels=[l.model_dump() for l in request.labels] if request.labels else None,
        due_date=request.due_date,
        estimated_hours=request.estimated_hours,
        assignee_ids=request.assignee_ids,
        finding_id=request.finding_id,
        checklist=[c.model_dump() for c in request.checklist] if request.checklist else None,
        color=request.color
    )
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Broadcast to WebSocket clients
    column = db.query(KanbanColumn).filter(KanbanColumn.id == column_id).first()
    if column and kanban_manager.is_connected(column.board_id):
        asyncio.create_task(kanban_manager.broadcast_card_create(
            board_id=column.board_id,
            user_id=current_user.id,
            card=card_data
        ))

    return CardResponse(**card_data)


@router.get("/cards/{card_id}", response_model=CardResponse)
async def get_card_endpoint(
    card_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get a card's details."""
    card_data, error = get_card(db, card_id, current_user.id)
    if error:
        status_code = status.HTTP_404_NOT_FOUND if error == "Card not found" else status.HTTP_403_FORBIDDEN
        raise HTTPException(status_code=status_code, detail=error)
    
    return CardResponse(**card_data)


@router.put("/cards/{card_id}", response_model=CardResponse)
async def update_card_endpoint(
    card_id: int,
    request: CardUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update a card."""
    card_data, error = update_card(
        db, card_id, current_user.id,
        title=request.title,
        description=request.description,
        priority=request.priority.value if request.priority else None,
        labels=[l.model_dump() for l in request.labels] if request.labels else None,
        due_date=request.due_date,
        estimated_hours=request.estimated_hours,
        assignee_ids=request.assignee_ids,
        checklist=[c.model_dump() for c in request.checklist] if request.checklist else None,
        completed_at=request.completed_at,
        color=request.color
    )
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Broadcast to WebSocket clients
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    if card:
        column = db.query(KanbanColumn).filter(KanbanColumn.id == card.column_id).first()
        if column and kanban_manager.is_connected(column.board_id):
            # Build updates dict from request
            updates = {}
            if request.title is not None:
                updates["title"] = request.title
            if request.description is not None:
                updates["description"] = request.description
            if request.priority is not None:
                updates["priority"] = request.priority.value
            if request.labels is not None:
                updates["labels"] = [l.model_dump() for l in request.labels]
            if request.due_date is not None:
                updates["due_date"] = request.due_date.isoformat() if request.due_date else None
            if request.estimated_hours is not None:
                updates["estimated_hours"] = request.estimated_hours
            if request.assignee_ids is not None:
                updates["assignee_ids"] = request.assignee_ids
            if request.checklist is not None:
                updates["checklist"] = [c.model_dump() for c in request.checklist]
            if request.completed_at is not None:
                updates["completed_at"] = request.completed_at.isoformat() if request.completed_at else None
            if request.color is not None:
                updates["color"] = request.color

            asyncio.create_task(kanban_manager.broadcast_card_update(
                board_id=column.board_id,
                user_id=current_user.id,
                card_id=card_id,
                updates=updates
            ))

    return CardResponse(**card_data)


@router.put("/cards/{card_id}/move", response_model=CardResponse)
async def move_card_endpoint(
    card_id: int,
    request: CardMove,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Move a card to a different column/position."""
    # Get source column before move
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    source_column_id = card.column_id if card else None

    card_data, error = move_card(
        db, card_id, current_user.id,
        target_column_id=request.column_id,
        position=request.position
    )
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Broadcast to WebSocket clients
    target_column = db.query(KanbanColumn).filter(KanbanColumn.id == request.column_id).first()
    if target_column and kanban_manager.is_connected(target_column.board_id):
        asyncio.create_task(kanban_manager.broadcast_card_move(
            board_id=target_column.board_id,
            user_id=current_user.id,
            card_id=card_id,
            source_column_id=source_column_id,
            target_column_id=request.column_id,
            position=request.position
        ))

    return CardResponse(**card_data)


@router.delete("/cards/{card_id}")
async def delete_card_endpoint(
    card_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete a card."""
    # Get board_id before deletion
    card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
    board_id = None
    if card:
        column = db.query(KanbanColumn).filter(KanbanColumn.id == card.column_id).first()
        board_id = column.board_id if column else None

    success, error = delete_card(db, card_id, current_user.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    # Broadcast to WebSocket clients
    if board_id and kanban_manager.is_connected(board_id):
        asyncio.create_task(kanban_manager.broadcast_card_delete(
            board_id=board_id,
            user_id=current_user.id,
            card_id=card_id
        ))

    return {"message": "Card deleted"}


# ============================================================================
# Card from Finding
# ============================================================================

@router.post("/boards/{board_id}/cards/from-finding", response_model=CardResponse)
async def create_card_from_finding_endpoint(
    board_id: int,
    finding_id: int = Query(...),
    column_name: str = Query("Backlog"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create a card from a security finding."""
    card_data, error = create_card_from_finding(
        db, board_id, finding_id, current_user.id, column_name
    )
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    
    return CardResponse(**card_data)


# ============================================================================
# Comment Endpoints
# ============================================================================

@router.post("/cards/{card_id}/comments", response_model=CommentResponse)
async def add_comment_endpoint(
    card_id: int,
    request: CommentCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Add a comment to a card."""
    comment_data, error = add_comment(db, card_id, current_user.id, request.content)
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    
    return CommentResponse(**comment_data)


@router.get("/cards/{card_id}/comments", response_model=List[CommentResponse])
async def get_comments_endpoint(
    card_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get all comments for a card."""
    comments, error = get_card_comments(db, card_id, current_user.id)
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    
    return [CommentResponse(**c) for c in comments]


@router.delete("/comments/{comment_id}")
async def delete_comment_endpoint(
    comment_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete a comment (only by owner)."""
    success, error = delete_comment(db, comment_id, current_user.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    
    return {"message": "Comment deleted"}
