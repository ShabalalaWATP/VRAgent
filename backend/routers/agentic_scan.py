"""
Agentic AI Scan Router

FastAPI endpoints for the agentic AI security scanner.
Provides endpoints to start scans, check progress, and retrieve results.
"""

import asyncio
from typing import List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from ..services.agentic_scan_service import (
    agentic_scan_service,
    result_to_dict,
    progress_to_dict,
    ScanPhase
)
from ..core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/agentic-scan", tags=["Agentic AI Scan"])


# ============================================================================
# Request/Response Models
# ============================================================================

class StartScanRequest(BaseModel):
    """Request to start an agentic scan"""
    project_id: int
    project_path: str
    file_extensions: Optional[List[str]] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "project_id": 1,
                "project_path": "/path/to/project",
                "file_extensions": [".py", ".js", ".ts"]
            }
        }


class ScanStatusResponse(BaseModel):
    """Response for scan status"""
    scan_id: str
    project_id: int
    phase: str
    phase_progress: float
    total_chunks: int
    analyzed_chunks: int
    entry_points_found: int
    flows_traced: int
    vulnerabilities_found: int
    message: str
    started_at: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "abc123",
                "project_id": 1,
                "phase": "flow_tracing",
                "phase_progress": 0.5,
                "total_chunks": 100,
                "analyzed_chunks": 50,
                "entry_points_found": 10,
                "flows_traced": 5,
                "vulnerabilities_found": 2,
                "message": "Tracing flow 50/100",
                "started_at": "2024-01-01T00:00:00"
            }
        }


# ============================================================================
# Background Task Handler
# ============================================================================

async def run_scan_background(
    project_id: int,
    project_path: str,
    file_extensions: List[str],
    scan_id: str
):
    """Run the scan in the background"""
    try:
        await agentic_scan_service.start_scan(
            project_id=project_id,
            project_path=project_path,
            file_extensions=file_extensions
        )
    except Exception as e:
        logger.error(f"Background scan failed: {e}")


# Active WebSocket connections for progress updates
active_connections: dict[str, WebSocket] = {}


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/start")
async def start_scan(request: StartScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new agentic AI security scan.
    
    The scan runs asynchronously. Use /status/{scan_id} or WebSocket to track progress.
    
    Returns the scan_id for tracking.
    """
    try:
        # Generate scan ID early for immediate response
        import hashlib
        from datetime import datetime
        
        scan_id = hashlib.md5(
            f"{request.project_id}:{request.project_path}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Set default extensions if not provided
        extensions = request.file_extensions or [".py", ".js", ".ts", ".jsx", ".tsx"]
        
        logger.info(f"Starting agentic scan {scan_id} for project {request.project_id}")
        
        # Start scan synchronously to get proper tracking
        # For larger projects, consider using Celery or similar
        asyncio.create_task(
            agentic_scan_service.start_scan(
                project_id=request.project_id,
                project_path=request.project_path,
                file_extensions=extensions
            )
        )
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "message": "Agentic scan started. Use /status/{scan_id} to track progress."
        }
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/start-sync")
async def start_scan_sync(request: StartScanRequest):
    """
    Start an agentic scan and wait for completion.
    
    Use this for smaller projects or when you need the results immediately.
    For larger projects, use /start and poll /status.
    """
    try:
        extensions = request.file_extensions or [".py", ".js", ".ts", ".jsx", ".tsx"]
        
        logger.info(f"Starting synchronous agentic scan for project {request.project_id}")
        
        scan_id = await agentic_scan_service.start_scan(
            project_id=request.project_id,
            project_path=request.project_path,
            file_extensions=extensions
        )
        
        result = agentic_scan_service.get_result(scan_id)
        if result:
            return result_to_dict(result)
        else:
            raise HTTPException(status_code=500, detail="Scan completed but result not found")
            
    except Exception as e:
        logger.error(f"Synchronous scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    Get the current status/progress of a scan.
    """
    progress = agentic_scan_service.get_progress(scan_id)
    
    if progress:
        return progress_to_dict(progress)
    
    # Check if scan is complete
    result = agentic_scan_service.get_result(scan_id)
    if result:
        return {
            "scan_id": scan_id,
            "project_id": result.project_id,
            "phase": result.phase.value if isinstance(result.phase, ScanPhase) else result.phase,
            "phase_progress": 1.0,
            "total_chunks": result.total_chunks,
            "analyzed_chunks": result.analyzed_chunks,
            "entry_points_found": len(result.entry_points),
            "flows_traced": len(result.traced_flows),
            "vulnerabilities_found": len(result.vulnerabilities),
            "message": "Scan complete",
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "status": result.status
        }
    
    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")


@router.get("/result/{scan_id}")
async def get_scan_result(scan_id: str):
    """
    Get the full result of a completed scan.
    """
    result = agentic_scan_service.get_result(scan_id)
    
    if not result:
        # Check if still in progress
        progress = agentic_scan_service.get_progress(scan_id)
        if progress:
            raise HTTPException(
                status_code=202, 
                detail=f"Scan still in progress: {progress.phase.value}"
            )
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    return result_to_dict(result)


@router.get("/vulnerabilities/{scan_id}")
async def get_vulnerabilities(scan_id: str, severity: Optional[str] = None):
    """
    Get just the vulnerabilities from a scan, optionally filtered by severity.
    """
    result = agentic_scan_service.get_result(scan_id)
    
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    vulnerabilities = result.vulnerabilities
    
    if severity:
        vulnerabilities = [v for v in vulnerabilities if v.severity.lower() == severity.lower()]
    
    return {
        "scan_id": scan_id,
        "total": len(result.vulnerabilities),
        "filtered": len(vulnerabilities),
        "vulnerabilities": [
            {
                "id": v.id,
                "type": v.vulnerability_type,
                "severity": v.severity,
                "cwe_id": v.cwe_id,
                "title": v.title,
                "file": v.flow.entry_point.file_path,
                "line": v.flow.entry_point.line_number,
                "confidence": v.confidence,
            }
            for v in vulnerabilities
        ]
    }


@router.get("/statistics/{scan_id}")
async def get_statistics(scan_id: str):
    """
    Get statistics from a completed scan.
    """
    result = agentic_scan_service.get_result(scan_id)
    
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    return {
        "scan_id": scan_id,
        "project_id": result.project_id,
        "duration_seconds": result.scan_duration_seconds,
        "total_chunks": result.total_chunks,
        "entry_points": len(result.entry_points),
        "sinks": len(result.sinks),
        "flows_traced": len(result.traced_flows),
        "vulnerabilities": len(result.vulnerabilities),
        "statistics": result.statistics
    }


@router.websocket("/ws/{scan_id}")
async def websocket_progress(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan progress updates.
    """
    await websocket.accept()
    active_connections[scan_id] = websocket
    
    try:
        while True:
            # Check progress
            progress = agentic_scan_service.get_progress(scan_id)
            
            if progress:
                await websocket.send_json(progress_to_dict(progress))
                
                if progress.phase in (ScanPhase.COMPLETE, ScanPhase.ERROR):
                    break
            else:
                # Check if scan is complete
                result = agentic_scan_service.get_result(scan_id)
                if result:
                    await websocket.send_json({
                        "scan_id": scan_id,
                        "phase": "complete",
                        "status": result.status,
                        "vulnerabilities_found": len(result.vulnerabilities)
                    })
                    break
            
            await asyncio.sleep(1)  # Poll every second
            
            # Check for client messages (keep-alive)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                pass
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    finally:
        if scan_id in active_connections:
            del active_connections[scan_id]


@router.get("/active")
async def list_active_scans():
    """
    List all currently active scans.
    """
    active = []
    for scan_id, progress in agentic_scan_service.active_scans.items():
        if progress.phase not in (ScanPhase.COMPLETE, ScanPhase.ERROR):
            active.append(progress_to_dict(progress))
    
    return {"active_scans": active, "count": len(active)}


@router.delete("/cancel/{scan_id}")
async def cancel_scan(scan_id: str):
    """
    Cancel an active scan (placeholder - actual cancellation requires task management).
    """
    progress = agentic_scan_service.get_progress(scan_id)
    
    if not progress:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    if progress.phase in (ScanPhase.COMPLETE, ScanPhase.ERROR):
        return {"message": "Scan already completed", "scan_id": scan_id}
    
    # Mark as cancelled (actual task cancellation would require Celery or similar)
    progress.phase = ScanPhase.ERROR
    progress.message = "Cancelled by user"
    
    return {"message": "Scan cancellation requested", "scan_id": scan_id}
