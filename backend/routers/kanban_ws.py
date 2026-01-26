"""
Kanban WebSocket endpoint for real-time collaboration.
"""
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.orm import Session

from backend.core.database import SessionLocal
from backend.core.kanban_manager import kanban_manager, decode_token
from backend.core.logging import get_logger
from backend.models.models import User, KanbanBoard, KanbanColumn, KanbanCard, Project, ProjectCollaborator

logger = get_logger(__name__)

router = APIRouter(prefix="/ws/kanban", tags=["kanban-websocket"])


def check_board_access(db: Session, user_id: int, board_id: int) -> bool:
    """Check if user has access to the Kanban board's project."""
    board = db.query(KanbanBoard).filter(KanbanBoard.id == board_id).first()
    if not board:
        return False

    project = db.query(Project).filter(Project.id == board.project_id).first()
    if not project:
        return False

    # Owner has access
    if project.owner_id == user_id:
        return True

    # Check if user is a collaborator
    from sqlalchemy import and_
    collab = db.query(ProjectCollaborator).filter(
        and_(
            ProjectCollaborator.project_id == project.id,
            ProjectCollaborator.user_id == user_id,
            ProjectCollaborator.status == "accepted"
        )
    ).first()

    return collab is not None


def format_card_response(card: KanbanCard, db: Session) -> dict:
    """Format card for WebSocket response."""
    # Get assignee info
    assignees = []
    if card.assignee_ids:
        for aid in card.assignee_ids:
            user = db.query(User).filter(User.id == aid).first()
            if user:
                assignees.append({
                    "user_id": user.id,
                    "username": user.username,
                    "first_name": user.first_name,
                    "avatar_url": user.avatar_url
                })

    return {
        "id": card.id,
        "column_id": card.column_id,
        "title": card.title,
        "description": card.description,
        "position": card.position,
        "priority": card.priority,
        "labels": card.labels or [],
        "due_date": card.due_date.isoformat() if card.due_date else None,
        "estimated_hours": card.estimated_hours,
        "assignee_ids": card.assignee_ids or [],
        "assignees": assignees,
        "checklist": card.checklist or [],
        "finding_id": card.finding_id,
        "comment_count": card.comment_count,
        "attachment_count": card.attachment_count,
        "created_by": card.created_by,
        "created_at": card.created_at.isoformat() if card.created_at else None,
        "updated_at": card.updated_at.isoformat() if card.updated_at else None,
        "completed_at": card.completed_at.isoformat() if card.completed_at else None,
    }


def format_column_response(column: KanbanColumn) -> dict:
    """Format column for WebSocket response."""
    return {
        "id": column.id,
        "board_id": column.board_id,
        "name": column.name,
        "position": column.position,
        "color": column.color,
        "wip_limit": column.wip_limit,
        "created_at": column.created_at.isoformat() if column.created_at else None,
    }


@router.websocket("/{board_id}")
async def kanban_websocket(
    websocket: WebSocket,
    board_id: int,
    token: str = Query(...)
):
    """
    WebSocket endpoint for real-time Kanban board collaboration.

    Message types (client -> server):
        - ping: Keepalive
        - viewing_column: {type: "viewing_column", column_id: int | null}
        - card_create: {type: "card_create", column_id: int, card: {...}}
        - card_update: {type: "card_update", card_id: int, updates: {...}}
        - card_move: {type: "card_move", card_id: int, column_id: int, position: int}
        - card_delete: {type: "card_delete", card_id: int}
        - column_create: {type: "column_create", name: str, ...}
        - column_update: {type: "column_update", column_id: int, updates: {...}}
        - column_delete: {type: "column_delete", column_id: int}
        - column_reorder: {type: "column_reorder", column_ids: [...]}

    Message types (server -> client):
        - pong: Keepalive response
        - current_users: List of currently active users
        - user_joined: New user joined
        - user_left: User disconnected
        - user_viewing_column: User is focusing on a column
        - card_created: Card created by another user
        - card_updated: Card updated by another user
        - card_moved: Card moved by another user
        - card_deleted: Card deleted by another user
        - column_created: Column created by another user
        - column_updated: Column updated by another user
        - column_deleted: Column deleted by another user
        - columns_reordered: Columns reordered by another user
        - error: Error message
    """
    # Validate token
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid token")
        return

    # Verify this is an access token, not a refresh token
    if payload.get("type") != "access":
        await websocket.close(code=4001, reason="Invalid token type")
        return

    user_id = payload.get("sub")
    if not user_id:
        await websocket.close(code=4001, reason="Invalid token")
        return

    # Get database session
    db = SessionLocal()

    try:
        # Get user
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            await websocket.close(code=4001, reason="User not found")
            return

        # Check board access
        if not check_board_access(db, user.id, board_id):
            await websocket.close(code=4003, reason="Access denied")
            return

        # Connect to board
        connection = await kanban_manager.connect(
            websocket=websocket,
            board_id=board_id,
            user_id=user.id,
            username=user.username
        )

        logger.info(f"User {user.username} connected to Kanban board {board_id}")

        try:
            while True:
                # Receive message
                data = await websocket.receive_text()

                # Handle ping keepalive
                if data == "ping":
                    await websocket.send_text("pong")
                    continue

                try:
                    message = json.loads(data)
                    msg_type = message.get("type")

                    if msg_type == "viewing_column":
                        # User is focusing on a column
                        column_id = message.get("column_id")
                        await kanban_manager.broadcast_viewing_column(
                            board_id=board_id,
                            user_id=user.id,
                            column_id=column_id
                        )

                    elif msg_type == "card_create":
                        # Create new card
                        column_id = message.get("column_id")
                        card_data = message.get("card", {})

                        column = db.query(KanbanColumn).filter(
                            KanbanColumn.id == column_id,
                            KanbanColumn.board_id == board_id
                        ).first()

                        if column:
                            # Get next position
                            max_pos = db.query(KanbanCard).filter(
                                KanbanCard.column_id == column_id
                            ).count()

                            card = KanbanCard(
                                column_id=column_id,
                                title=card_data.get("title", "New Card"),
                                description=card_data.get("description"),
                                position=max_pos,
                                priority=card_data.get("priority"),
                                labels=card_data.get("labels"),
                                created_by=user.id
                            )
                            db.add(card)
                            db.commit()
                            db.refresh(card)

                            # Broadcast to others
                            await kanban_manager.broadcast_card_create(
                                board_id=board_id,
                                user_id=user.id,
                                card=format_card_response(card, db)
                            )

                            # Confirm to sender
                            await websocket.send_json({
                                "type": "card_create_confirmed",
                                "card": format_card_response(card, db)
                            })

                    elif msg_type == "card_update":
                        # Update card
                        card_id = message.get("card_id")
                        updates = message.get("updates", {})

                        card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
                        if card:
                            # Verify card belongs to this board
                            column = db.query(KanbanColumn).filter(
                                KanbanColumn.id == card.column_id
                            ).first()
                            if column and column.board_id == board_id:
                                for key, value in updates.items():
                                    if hasattr(card, key) and key not in ['id', 'column_id', 'created_by', 'created_at']:
                                        setattr(card, key, value)
                                card.updated_at = datetime.utcnow()
                                db.commit()

                                await kanban_manager.broadcast_card_update(
                                    board_id=board_id,
                                    user_id=user.id,
                                    card_id=card_id,
                                    updates=updates
                                )

                    elif msg_type == "card_move":
                        # Move card
                        card_id = message.get("card_id")
                        target_column_id = message.get("column_id")
                        position = message.get("position", 0)

                        card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
                        if card:
                            source_column_id = card.column_id

                            # Verify target column belongs to this board
                            target_column = db.query(KanbanColumn).filter(
                                KanbanColumn.id == target_column_id,
                                KanbanColumn.board_id == board_id
                            ).first()

                            if target_column:
                                # Update positions in source column
                                if source_column_id != target_column_id:
                                    db.query(KanbanCard).filter(
                                        KanbanCard.column_id == source_column_id,
                                        KanbanCard.position > card.position
                                    ).update({KanbanCard.position: KanbanCard.position - 1})

                                # Update positions in target column
                                db.query(KanbanCard).filter(
                                    KanbanCard.column_id == target_column_id,
                                    KanbanCard.position >= position
                                ).update({KanbanCard.position: KanbanCard.position + 1})

                                # Move card
                                card.column_id = target_column_id
                                card.position = position
                                card.updated_at = datetime.utcnow()
                                db.commit()

                                await kanban_manager.broadcast_card_move(
                                    board_id=board_id,
                                    user_id=user.id,
                                    card_id=card_id,
                                    source_column_id=source_column_id,
                                    target_column_id=target_column_id,
                                    position=position
                                )

                    elif msg_type == "card_delete":
                        # Delete card
                        card_id = message.get("card_id")

                        card = db.query(KanbanCard).filter(KanbanCard.id == card_id).first()
                        if card:
                            column = db.query(KanbanColumn).filter(
                                KanbanColumn.id == card.column_id
                            ).first()
                            if column and column.board_id == board_id:
                                column_id = card.column_id
                                position = card.position
                                db.delete(card)

                                # Reorder remaining cards
                                db.query(KanbanCard).filter(
                                    KanbanCard.column_id == column_id,
                                    KanbanCard.position > position
                                ).update({KanbanCard.position: KanbanCard.position - 1})

                                db.commit()

                                await kanban_manager.broadcast_card_delete(
                                    board_id=board_id,
                                    user_id=user.id,
                                    card_id=card_id
                                )

                    elif msg_type == "column_create":
                        # Create new column
                        name = message.get("name", "New Column")
                        color = message.get("color")
                        wip_limit = message.get("wip_limit")

                        # Get next position
                        max_pos = db.query(KanbanColumn).filter(
                            KanbanColumn.board_id == board_id
                        ).count()

                        column = KanbanColumn(
                            board_id=board_id,
                            name=name,
                            position=max_pos,
                            color=color,
                            wip_limit=wip_limit
                        )
                        db.add(column)
                        db.commit()
                        db.refresh(column)

                        await kanban_manager.broadcast_column_create(
                            board_id=board_id,
                            user_id=user.id,
                            column=format_column_response(column)
                        )

                        await websocket.send_json({
                            "type": "column_create_confirmed",
                            "column": format_column_response(column)
                        })

                    elif msg_type == "column_update":
                        # Update column
                        column_id = message.get("column_id")
                        updates = message.get("updates", {})

                        column = db.query(KanbanColumn).filter(
                            KanbanColumn.id == column_id,
                            KanbanColumn.board_id == board_id
                        ).first()

                        if column:
                            for key, value in updates.items():
                                if hasattr(column, key) and key not in ['id', 'board_id', 'created_at']:
                                    setattr(column, key, value)
                            column.updated_at = datetime.utcnow()
                            db.commit()

                            await kanban_manager.broadcast_column_update(
                                board_id=board_id,
                                user_id=user.id,
                                column_id=column_id,
                                updates=updates
                            )

                    elif msg_type == "column_delete":
                        # Delete column
                        column_id = message.get("column_id")

                        column = db.query(KanbanColumn).filter(
                            KanbanColumn.id == column_id,
                            KanbanColumn.board_id == board_id
                        ).first()

                        if column:
                            position = column.position
                            db.delete(column)

                            # Reorder remaining columns
                            db.query(KanbanColumn).filter(
                                KanbanColumn.board_id == board_id,
                                KanbanColumn.position > position
                            ).update({KanbanColumn.position: KanbanColumn.position - 1})

                            db.commit()

                            await kanban_manager.broadcast_column_delete(
                                board_id=board_id,
                                user_id=user.id,
                                column_id=column_id
                            )

                    elif msg_type == "column_reorder":
                        # Reorder columns
                        column_ids = message.get("column_ids", [])

                        for idx, col_id in enumerate(column_ids):
                            db.query(KanbanColumn).filter(
                                KanbanColumn.id == col_id,
                                KanbanColumn.board_id == board_id
                            ).update({KanbanColumn.position: idx})

                        db.commit()

                        await kanban_manager.broadcast_columns_reorder(
                            board_id=board_id,
                            user_id=user.id,
                            column_ids=column_ids
                        )

                    else:
                        logger.warning(f"Unknown message type: {msg_type}")

                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received from user {user.id}")
                except Exception as e:
                    logger.error(f"Error handling message: {e}")
                    await websocket.send_json({
                        "type": "error",
                        "message": str(e)
                    })

        except WebSocketDisconnect:
            logger.info(f"User {user.username} disconnected from Kanban board {board_id}")

        except Exception as e:
            logger.error(f"WebSocket error for user {user.username}: {e}")
            try:
                await websocket.send_json({
                    "type": "error",
                    "message": str(e)
                })
            except:
                pass

        finally:
            await kanban_manager.disconnect(board_id, user.id)

    finally:
        db.close()
