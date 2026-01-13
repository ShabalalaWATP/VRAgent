"""
Interactive & Replay Router

REST API and WebSocket endpoints for interactive fuzzing:
- Step mode control
- Request replay
- Finding verification
- Breakpoint management
"""

from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from enum import Enum

from backend.core.auth import get_current_active_user
from backend.models.models import User

from backend.services.interactive_replay_service import (
    get_interactive_controller,
    get_request_recorder,
    get_request_replayer,
    get_finding_verifier,
    get_breakpoint_manager,
    StepAction,
    BreakpointType,
)

router = APIRouter(prefix="/fuzzer-interactive")


# =============================================================================
# REQUEST MODELS
# =============================================================================

class StepActionEnum(str, Enum):
    """Step actions for API."""
    approve = "approve"
    skip = "skip"
    modify = "modify"
    approve_all = "approve_all"
    skip_similar = "skip_similar"
    stop = "stop"


class BreakpointTypeEnum(str, Enum):
    """Breakpoint types for API."""
    technique = "technique"
    severity = "severity"
    status_code = "status_code"
    response_contains = "response_contains"
    finding = "finding"
    error = "error"
    iteration = "iteration"


class EnableStepModeRequest(BaseModel):
    """Request to enable step mode."""
    session_id: str


class SubmitActionRequest(BaseModel):
    """Request to submit action for pending payload."""
    session_id: str
    action: StepActionEnum
    modified_payload: Optional[str] = None


class AddPatternRequest(BaseModel):
    """Request to add skip/approve pattern."""
    session_id: str
    pattern: str


class ReplayRequestModel(BaseModel):
    """Request to replay a recorded request."""
    session_id: str
    request_id: str
    modify_headers: Optional[Dict[str, str]] = None
    modify_body: Optional[str] = None
    modify_payload: Optional[str] = None
    timeout: float = Field(default=30.0, ge=1.0, le=120.0)


class ReplaySequenceRequest(BaseModel):
    """Request to replay a sequence of requests."""
    session_id: str
    request_ids: List[str]
    delay_ms: int = Field(default=100, ge=0, le=5000)


class VerifyFindingRequest(BaseModel):
    """Request to verify a finding."""
    session_id: str
    finding_id: str
    request_id: Optional[str] = None
    technique: Optional[str] = None
    attempts: int = Field(default=3, ge=1, le=10)


class AddBreakpointRequest(BaseModel):
    """Request to add a breakpoint."""
    session_id: str
    breakpoint_type: BreakpointTypeEnum
    condition: str


# =============================================================================
# STEP MODE ENDPOINTS
# =============================================================================

@router.post("/step-mode/enable")
async def enable_step_mode(
    request: EnableStepModeRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Enable step mode for a fuzzing session.
    
    In step mode, each payload requires manual approval before execution.
    """
    controller = get_interactive_controller()
    
    if controller.enable_step_mode(request.session_id):
        return {
            "status": "success",
            "message": "Step mode enabled",
            "session_id": request.session_id,
        }
    
    raise HTTPException(status_code=404, detail="Session not found")


@router.post("/step-mode/disable")
async def disable_step_mode(
    request: EnableStepModeRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Disable step mode and resume automatic execution.
    """
    controller = get_interactive_controller()
    
    if controller.disable_step_mode(request.session_id):
        return {
            "status": "success",
            "message": "Step mode disabled - resuming automatic execution",
            "session_id": request.session_id,
        }
    
    raise HTTPException(status_code=404, detail="Session not found")


@router.get("/step-mode/{session_id}")
async def get_step_mode_status(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current step mode status and pending payload (if any).
    """
    controller = get_interactive_controller()
    session = controller.get_session(session_id)
    
    if not session:
        raise HTTPException(status_code=404, detail="Interactive session not found")
    
    return {
        "session_id": session_id,
        "step_mode": session.step_mode,
        "state": session.state.value,
        "pending_payload": session.pending_payload.to_dict() if session.pending_payload else None,
        "stats": {
            "approved": session.approved_count,
            "skipped": session.skipped_count,
            "modified": session.modified_count,
        },
    }


@router.post("/step-mode/action")
async def submit_step_action(
    request: SubmitActionRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Submit action for the pending payload.
    
    Actions:
    - approve: Execute the payload as-is
    - skip: Skip this payload
    - modify: Execute with modified payload
    - approve_all: Approve all remaining (disables step mode)
    - skip_similar: Skip all similar payloads
    - stop: Stop the scan
    """
    controller = get_interactive_controller()
    
    action_map = {
        StepActionEnum.approve: StepAction.APPROVE,
        StepActionEnum.skip: StepAction.SKIP,
        StepActionEnum.modify: StepAction.MODIFY,
        StepActionEnum.approve_all: StepAction.APPROVE_ALL,
        StepActionEnum.skip_similar: StepAction.SKIP_SIMILAR,
        StepActionEnum.stop: StepAction.STOP,
    }
    
    if controller.submit_action(
        request.session_id,
        action_map[request.action],
        request.modified_payload,
    ):
        return {
            "status": "success",
            "action": request.action,
            "session_id": request.session_id,
        }
    
    raise HTTPException(
        status_code=400,
        detail="No pending payload or session not in waiting state"
    )


@router.post("/step-mode/skip-pattern")
async def add_skip_pattern(
    request: AddPatternRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Add a pattern to automatically skip matching payloads.
    
    Pattern format: "technique:parameter" or partial match string
    """
    controller = get_interactive_controller()
    
    if controller.add_skip_pattern(request.session_id, request.pattern):
        return {
            "status": "success",
            "message": f"Skip pattern added: {request.pattern}",
        }
    
    raise HTTPException(status_code=404, detail="Session not found")


@router.post("/step-mode/approve-pattern")
async def add_approve_pattern(
    request: AddPatternRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Add a pattern to automatically approve matching payloads.
    """
    controller = get_interactive_controller()
    
    if controller.add_approve_pattern(request.session_id, request.pattern):
        return {
            "status": "success",
            "message": f"Approve pattern added: {request.pattern}",
        }
    
    raise HTTPException(status_code=404, detail="Session not found")


# =============================================================================
# REQUEST RECORDING ENDPOINTS
# =============================================================================

@router.get("/requests/{session_id}")
async def get_recorded_requests(
    session_id: str,
    technique: Optional[str] = None,
    finding_only: bool = False,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get recorded requests for a session.
    
    Supports filtering by technique and finding status.
    """
    recorder = get_request_recorder()
    
    requests = recorder.get_requests(
        session_id,
        technique=technique,
        finding_only=finding_only,
        limit=min(limit, 500),
        offset=offset,
    )
    
    return {
        "session_id": session_id,
        "total": len(requests),
        "offset": offset,
        "limit": limit,
        "requests": [r.to_dict() for r in requests],
    }


@router.get("/requests/{session_id}/{request_id}")
async def get_request_details(
    session_id: str,
    request_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get full details of a specific recorded request.
    """
    recorder = get_request_recorder()
    request = recorder.get_request(session_id, request_id)
    
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Return full response body for detailed view
    result = request.to_dict()
    if request.response_body:
        result["response"]["body_full"] = request.response_body
    
    return result


@router.get("/requests/{session_id}/stats")
async def get_request_stats(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get statistics for recorded requests.
    """
    recorder = get_request_recorder()
    return recorder.get_session_stats(session_id)


# =============================================================================
# REPLAY ENDPOINTS
# =============================================================================

@router.post("/replay")
async def replay_request(
    request: ReplayRequestModel,
    current_user: User = Depends(get_current_active_user)
):
    """
    Replay a recorded request.
    
    Optionally modify headers, body, or payload before replaying.
    Returns comparison with original response.
    """
    replayer = get_request_replayer()
    
    result = await replayer.replay_request(
        session_id=request.session_id,
        request_id=request.request_id,
        modify_headers=request.modify_headers,
        modify_body=request.modify_body,
        modify_payload=request.modify_payload,
        timeout=request.timeout,
    )
    
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    
    return result


@router.post("/replay/sequence")
async def replay_sequence(
    request: ReplaySequenceRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Replay a sequence of requests in order.
    
    Useful for reproducing multi-step attack chains.
    """
    replayer = get_request_replayer()
    
    results = await replayer.replay_sequence(
        session_id=request.session_id,
        request_ids=request.request_ids,
        delay_ms=request.delay_ms,
    )
    
    return {
        "session_id": request.session_id,
        "sequence_count": len(request.request_ids),
        "results": results,
    }


# =============================================================================
# FINDING VERIFICATION ENDPOINTS
# =============================================================================

@router.post("/verify")
async def verify_finding(
    request: VerifyFindingRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Verify a finding by replaying its original request.
    
    Attempts to reproduce the vulnerability multiple times
    and reports confidence level.
    """
    verifier = get_finding_verifier()
    
    finding = {
        "id": request.finding_id,
        "request_id": request.request_id,
        "technique": request.technique,
    }
    
    result = await verifier.verify_finding(
        session_id=request.session_id,
        finding=finding,
        attempts=request.attempts,
    )
    
    return result.to_dict()


@router.post("/verify/batch")
async def verify_findings_batch(
    session_id: str,
    finding_ids: List[str],
    current_user: User = Depends(get_current_active_user)
):
    """
    Verify multiple findings in batch.
    """
    verifier = get_finding_verifier()
    results = []
    
    for finding_id in finding_ids:
        result = await verifier.verify_finding(
            session_id=session_id,
            finding={"id": finding_id},
            attempts=2,  # Fewer attempts for batch
        )
        results.append(result.to_dict())
    
    verified_count = sum(1 for r in results if r["verified"])
    
    return {
        "session_id": session_id,
        "total": len(finding_ids),
        "verified": verified_count,
        "unverified": len(finding_ids) - verified_count,
        "results": results,
    }


# =============================================================================
# BREAKPOINT ENDPOINTS
# =============================================================================

@router.post("/breakpoints")
async def add_breakpoint(
    request: AddBreakpointRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Add a breakpoint to pause execution on specific conditions.
    
    Breakpoint types:
    - technique: Pause on specific technique (e.g., "sql_injection")
    - severity: Pause on severity level (e.g., "critical")
    - status_code: Pause on HTTP status (e.g., "500")
    - response_contains: Pause when response contains text
    - finding: Pause on any finding detection
    - error: Pause on request errors
    - iteration: Pause at specific iteration number
    """
    manager = get_breakpoint_manager()
    
    type_map = {
        BreakpointTypeEnum.technique: BreakpointType.TECHNIQUE,
        BreakpointTypeEnum.severity: BreakpointType.SEVERITY,
        BreakpointTypeEnum.status_code: BreakpointType.STATUS_CODE,
        BreakpointTypeEnum.response_contains: BreakpointType.RESPONSE_CONTAINS,
        BreakpointTypeEnum.finding: BreakpointType.FINDING,
        BreakpointTypeEnum.error: BreakpointType.ERROR,
        BreakpointTypeEnum.iteration: BreakpointType.ITERATION,
    }
    
    bp = manager.add_breakpoint(
        request.session_id,
        type_map[request.breakpoint_type],
        request.condition,
    )
    
    return {
        "status": "success",
        "breakpoint": bp.to_dict(),
    }


@router.get("/breakpoints/{session_id}")
async def get_breakpoints(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all breakpoints for a session.
    """
    manager = get_breakpoint_manager()
    breakpoints = manager.get_breakpoints(session_id)
    
    return {
        "session_id": session_id,
        "breakpoints": [bp.to_dict() for bp in breakpoints],
    }


@router.delete("/breakpoints/{session_id}/{breakpoint_id}")
async def remove_breakpoint(
    session_id: str,
    breakpoint_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Remove a breakpoint.
    """
    manager = get_breakpoint_manager()
    
    if manager.remove_breakpoint(session_id, breakpoint_id):
        return {"status": "success", "message": "Breakpoint removed"}
    
    raise HTTPException(status_code=404, detail="Breakpoint not found")


@router.post("/breakpoints/{session_id}/{breakpoint_id}/toggle")
async def toggle_breakpoint(
    session_id: str,
    breakpoint_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Toggle a breakpoint's enabled state.
    """
    manager = get_breakpoint_manager()
    
    if manager.toggle_breakpoint(session_id, breakpoint_id):
        return {"status": "success", "message": "Breakpoint toggled"}
    
    raise HTTPException(status_code=404, detail="Breakpoint not found")


# =============================================================================
# WEBSOCKET FOR REAL-TIME STEP MODE
# =============================================================================

@router.websocket("/ws/{session_id}")
async def interactive_websocket(websocket: WebSocket, session_id: str):
    """
    WebSocket for real-time interactive mode.
    
    Receives:
    - {"command": "action", "action": "approve|skip|modify", "payload": "..."}
    - {"command": "enable_step"}
    - {"command": "disable_step"}
    - {"command": "add_breakpoint", "type": "...", "condition": "..."}
    
    Sends:
    - {"type": "pending_payload", "payload": {...}}
    - {"type": "status", "state": "..."}
    - {"type": "breakpoint_hit", "breakpoint": {...}}
    """
    await websocket.accept()
    
    controller = get_interactive_controller()
    session = controller.get_session(session_id)
    
    if not session:
        await websocket.send_json({"type": "error", "error": "Session not found"})
        await websocket.close()
        return
    
    try:
        while True:
            # Send current status
            await websocket.send_json({
                "type": "status",
                "session": session.to_dict(),
            })
            
            # Wait for commands
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=1.0)
                command = data.get("command")
                
                if command == "action":
                    action_str = data.get("action", "skip")
                    action_map = {
                        "approve": StepAction.APPROVE,
                        "skip": StepAction.SKIP,
                        "modify": StepAction.MODIFY,
                        "approve_all": StepAction.APPROVE_ALL,
                        "skip_similar": StepAction.SKIP_SIMILAR,
                        "stop": StepAction.STOP,
                    }
                    
                    if controller.submit_action(
                        session_id,
                        action_map.get(action_str, StepAction.SKIP),
                        data.get("payload"),
                    ):
                        await websocket.send_json({
                            "type": "action_accepted",
                            "action": action_str,
                        })
                
                elif command == "enable_step":
                    controller.enable_step_mode(session_id)
                    await websocket.send_json({
                        "type": "step_mode_enabled",
                    })
                
                elif command == "disable_step":
                    controller.disable_step_mode(session_id)
                    await websocket.send_json({
                        "type": "step_mode_disabled",
                    })
                
                elif command == "ping":
                    await websocket.send_json({"type": "pong"})
                    
            except asyncio.TimeoutError:
                # Check for pending payload
                if session.pending_payload:
                    await websocket.send_json({
                        "type": "pending_payload",
                        "payload": session.pending_payload.to_dict(),
                    })
                    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "error": str(e)})
        except:
            pass


# Import asyncio for WebSocket
import asyncio
