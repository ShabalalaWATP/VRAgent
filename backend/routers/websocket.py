"""
WebSocket endpoints for real-time scan progress updates.
"""
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from backend.core.logging import get_logger
from backend.services.websocket_service import manager

logger = get_logger(__name__)

router = APIRouter()


@router.websocket("/ws/scans/{scan_run_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_run_id: int
):
    """
    WebSocket endpoint for receiving real-time scan progress updates.
    
    Connect to receive live updates for a specific scan run.
    
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
    await manager.connect(websocket, scan_run_id=scan_run_id)
    logger.info(f"WebSocket client connected for scan {scan_run_id}")
    
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
    project_id: int
):
    """
    WebSocket endpoint for receiving progress updates for all scans in a project.
    
    Connect to receive live updates for any scan running on this project.
    """
    await manager.connect(websocket, project_id=project_id)
    logger.info(f"WebSocket client connected for project {project_id}")
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from project {project_id}")
    finally:
        await manager.disconnect(websocket)
