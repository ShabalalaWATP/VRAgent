"""
WebSocket endpoints for real-time scan progress updates.
"""
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from sqlalchemy.orm import Session

from backend.core.logging import get_logger
from backend.core.database import SessionLocal
from backend.services.websocket_service import manager
from backend.services.auth_service import decode_token, get_user_by_id
from backend.models.models import Project, ScanRun

logger = get_logger(__name__)

router = APIRouter()


async def verify_websocket_token(token: Optional[str]) -> Optional[int]:
    """
    Verify JWT token for WebSocket connections.
    Returns user_id if valid, None otherwise.
    """
    if not token:
        return None

    payload = decode_token(token)
    if not payload:
        return None

    if payload.get("type") != "access":
        return None

    user_id = payload.get("sub")
    if user_id is None:
        return None

    try:
        return int(user_id)
    except (TypeError, ValueError):
        return None


def verify_scan_access(user_id: int, scan_run_id: int) -> bool:
    """
    Verify that the user has access to the specified scan.
    Returns True if user owns the project or is admin.
    """
    db = SessionLocal()
    try:
        scan = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
        if not scan:
            return False

        project = db.query(Project).filter(Project.id == scan.project_id).first()
        if not project:
            return False

        user = get_user_by_id(db, user_id)
        if not user:
            return False

        # Allow access if user owns project or is admin
        return project.user_id == user_id or user.role == "admin"
    finally:
        db.close()


def verify_project_access(user_id: int, project_id: int) -> bool:
    """
    Verify that the user has access to the specified project.
    Returns True if user owns the project or is admin.
    """
    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            return False

        user = get_user_by_id(db, user_id)
        if not user:
            return False

        # Allow access if user owns project or is admin
        return project.user_id == user_id or user.role == "admin"
    finally:
        db.close()


@router.websocket("/ws/scans/{scan_run_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_run_id: int,
    token: Optional[str] = Query(None, description="JWT access token for authentication"),
):
    """
    WebSocket endpoint for receiving real-time scan progress updates.

    Connect to receive live updates for a specific scan run.

    Requires authentication via token query parameter.

    Messages are JSON objects with:
    - scan_run_id: int
    - project_id: int
    - phase: string (current scan phase)
    - phase_progress: int (0-100 progress within phase)
    - overall_progress: int (0-100 total progress)
    - message: string (human-readable status)
    - details: object (optional additional data)
    - timestamp: string (ISO timestamp)
    """
    # Verify authentication
    user_id = await verify_websocket_token(token)
    if user_id is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication required")
        return

    # Verify user has access to this scan
    if not verify_scan_access(user_id, scan_run_id):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Access denied to this scan")
        return

    await manager.connect(websocket, scan_run_id=scan_run_id)
    logger.info(f"WebSocket client (user {user_id}) connected for scan {scan_run_id}")

    try:
        # Keep connection open and handle any incoming messages
        while True:
            data = await websocket.receive_text()
            # Client can send "ping" to keep connection alive
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from scan {scan_run_id}")
    finally:
        await manager.disconnect(websocket)


@router.websocket("/ws/projects/{project_id}")
async def websocket_project_progress(
    websocket: WebSocket,
    project_id: int,
    token: Optional[str] = Query(None, description="JWT access token for authentication"),
):
    """
    WebSocket endpoint for receiving progress updates for all scans in a project.

    Connect to receive live updates for any scan running on this project.

    Requires authentication via token query parameter.
    """
    # Verify authentication
    user_id = await verify_websocket_token(token)
    if user_id is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication required")
        return

    # Verify user has access to this project
    if not verify_project_access(user_id, project_id):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Access denied to this project")
        return

    await manager.connect(websocket, project_id=project_id)
    logger.info(f"WebSocket client (user {user_id}) connected for project {project_id}")

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from project {project_id}")
    finally:
        await manager.disconnect(websocket)
