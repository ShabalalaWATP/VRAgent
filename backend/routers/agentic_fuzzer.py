"""
Agentic Fuzzer Router - Unified

Complete API for LLM-driven autonomous fuzzing:
- Core: start, quick-scan, websocket, sessions, techniques, presets
- Scan Control: timeout, dry-run, stop-on-critical, severity filtering
- Robustness: circuit breakers, rate limiting, watchdog, graceful degradation
- Quality: context-aware payloads, response analysis, attack surface mapping
- Automation: auto-pilot modes, coverage tracking, escalation
- Reports: save, list, export (markdown, PDF, docx)
- Authentication: configurable auth for fuzzing requests
"""

from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import StreamingResponse, Response
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session as DBSession
from datetime import datetime as dt
import json
import logging
import asyncio

from backend.core.auth import get_current_active_user
from backend.core.database import get_db
from backend.models.models import User, AgenticFuzzerReport

from backend.services.agentic_fuzzer_service import (
    # Core functions
    start_agentic_fuzzing,
    resume_agentic_fuzzing,
    get_session,
    stop_session,
    pause_session,
    list_sessions,
    get_saved_sessions,
    delete_session,
    FuzzingTechnique,
    # Robustness
    get_robustness_stats,
    reset_robustness_stats,
    # Authentication
    AuthType,
    AuthConfig,
    configure_auth,
    get_auth_status,
    clear_auth,
    # Deduplication
    get_deduplication_stats,
    reset_deduplication,
    # Advanced robustness
    get_degradation_status,
    get_error_stats,
    get_dead_letter_stats,
    get_watchdog_health,
    get_watchdog_alerts,
    restore_session_checkpoint,
    start_watchdog,
    stop_watchdog,
    # Quality features
    get_payload_generator_stats,
    get_response_analyzer_stats,
    get_attack_surface_stats,
    reset_quality_features,
    # Automation
    set_auto_pilot_mode,
    get_automation_stats,
    get_automation_coverage,
    get_automation_queue,
    reset_automation_engine,
    set_auto_escalation,
    # Wordlists
    get_wordlist_stats,
    get_wordlist_for_technique,
)
from backend.services.fuzzer_report_export_service import export_fuzzer_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agentic-fuzzer", tags=["Agentic Fuzzer"])


# =============================================================================
# REQUEST MODELS
# =============================================================================

class FuzzingTargetRequest(BaseModel):
    """A target endpoint for fuzzing."""
    url: str = Field(..., description="Target URL")
    method: str = Field(default="AUTO", description="HTTP method (AUTO = detect from JavaScript)")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    body: Optional[str] = Field(default=None, description="Request body")
    parameters: List[str] = Field(default_factory=list, description="Parameters to fuzz")


class StartAgenticFuzzingRequest(BaseModel):
    """Request to start agentic fuzzing session."""
    targets: List[FuzzingTargetRequest] = Field(..., description="Targets to fuzz")
    max_iterations: int = Field(default=50, ge=5, le=2000, description="Maximum LLM iterations")
    techniques: List[str] = Field(default_factory=list, description="Specific techniques to focus on (empty = all)")
    depth: str = Field(default="normal", description="Fuzzing depth: quick, normal, thorough")
    auto_save: bool = Field(default=True, description="Auto-save session periodically")
    save_interval: int = Field(default=5, description="Save every N iterations")
    auto_pilot_mode: str = Field(default="disabled", description="Auto-pilot mode: disabled, assisted, semi_auto, full_auto")
    auto_escalation: bool = Field(default=True, description="Automatically escalate testing when findings detected")
    # Discovery & Crawling
    enable_crawl: bool = Field(default=True, description="Enable intelligent crawling to discover endpoints")
    crawl_depth: int = Field(default=3, ge=1, le=10, description="Maximum crawl depth")
    crawl_max_pages: int = Field(default=100, ge=10, le=1000, description="Maximum pages to crawl")
    enable_recon: bool = Field(default=True, description="Enable reconnaissance (auth detection, fingerprinting)")
    # Phase 1: Scan Control Features
    max_duration_seconds: Optional[int] = Field(default=None, ge=60, le=86400, description="Maximum scan duration in seconds")
    dry_run: bool = Field(default=False, description="Preview mode - generates scan plan without making actual requests")
    stop_on_critical: bool = Field(default=False, description="Stop scan immediately when a critical severity finding is detected")
    min_severity_to_report: str = Field(default="low", description="Minimum severity level to report: info, low, medium, high, critical")
    log_full_requests: bool = Field(default=False, description="Log full request details for debugging")
    log_full_responses: bool = Field(default=False, description="Log full response bodies for debugging")
    # Stealth Mode - Evade detection by target security systems
    stealth_mode: bool = Field(default=False, description="Enable stealth mode for evasion")
    stealth_delay_min: float = Field(default=2.0, ge=0.5, le=30.0, description="Minimum delay between requests in seconds")
    stealth_delay_max: float = Field(default=5.0, ge=1.0, le=60.0, description="Maximum delay between requests in seconds")
    stealth_requests_before_pause: int = Field(default=10, ge=5, le=100, description="Requests before taking a longer pause")
    stealth_pause_duration: float = Field(default=30.0, ge=10.0, le=300.0, description="Duration of pause in seconds")
    stealth_randomize_user_agent: bool = Field(default=True, description="Randomize User-Agent header")
    stealth_randomize_headers: bool = Field(default=True, description="Add random benign headers to vary fingerprint")
    # IP Renewal - Periodically prompt for IP release/renew to avoid bans
    stealth_ip_renewal_enabled: bool = Field(default=False, description="Enable periodic IP renewal prompts")
    stealth_ip_renewal_interval: int = Field(default=50, ge=20, le=500, description="Requests before prompting for IP renewal")


class ResumeSessionRequest(BaseModel):
    """Request to resume a saved session."""
    session_id: str = Field(..., description="ID of saved session to resume")
    additional_iterations: int = Field(default=25, ge=5, le=100, description="Additional iterations to run")


class QuickScanRequest(BaseModel):
    """Request for quick agentic scan of a single URL."""
    url: str = Field(..., description="Target URL to scan")
    method: str = Field(default="AUTO", description="HTTP method (AUTO = detect from JavaScript)")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    max_iterations: int = Field(default=20, ge=5, le=50, description="Max iterations")
    max_duration_seconds: Optional[int] = Field(default=300, ge=60, le=1800, description="Maximum scan duration (default 5 min)")
    dry_run: bool = Field(default=False, description="Preview mode - show what would be tested")
    stop_on_critical: bool = Field(default=True, description="Stop on critical finding")
    min_severity_to_report: str = Field(default="medium", description="Minimum severity to report")


class AuthConfigRequest(BaseModel):
    """Request to configure authentication for fuzzing sessions."""
    auth_type: str = Field(..., description="Auth type: none, basic, bearer, api_key, jwt, oauth2, session, custom")
    username: Optional[str] = Field(default=None, description="Username for basic auth")
    password: Optional[str] = Field(default=None, description="Password for basic auth")
    token: Optional[str] = Field(default=None, description="Bearer token or API key")
    api_key_header: Optional[str] = Field(default="X-API-Key", description="Header name for API key")
    api_key_location: Optional[str] = Field(default="header", description="Location: header, query, cookie")
    client_id: Optional[str] = Field(default=None, description="OAuth2 client ID")
    client_secret: Optional[str] = Field(default=None, description="OAuth2 client secret")
    token_url: Optional[str] = Field(default=None, description="OAuth2 token endpoint")
    scopes: List[str] = Field(default_factory=list, description="OAuth2 scopes")
    login_url: Optional[str] = Field(default=None, description="Login URL for session auth")
    login_data: Optional[Dict[str, str]] = Field(default=None, description="Login form data")
    session_cookie_name: Optional[str] = Field(default="session", description="Session cookie name")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Custom auth headers")


class SetAutoPilotRequest(BaseModel):
    """Request to set auto-pilot mode."""
    mode: str = Field(..., description="Auto-pilot mode: disabled, assisted, semi_auto, full_auto")


class SaveReportRequest(BaseModel):
    """Request to save a fuzzing session report."""
    session_id: str = Field(..., description="Session ID to save")
    title: Optional[str] = Field(default=None, description="Custom report title")
    project_id: Optional[int] = Field(default=None, description="Associated project ID")


# =============================================================================
# CORE STREAMING ENDPOINTS
# =============================================================================

@router.post("/start")
async def start_fuzzing_stream(
    request: StartAgenticFuzzingRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Start an agentic fuzzing session with streaming results.
    
    The LLM will analyze endpoints, select techniques, execute payloads,
    adapt strategy based on results, and generate security assessments.
    
    Results are streamed as Server-Sent Events.
    """
    # Trust the frontend's max_iterations directly - it already maps depth to correct values:
    # minimal=25, quick=50, normal=150, thorough=500, aggressive=1500
    max_iter = request.max_iterations
    
    targets = [{"url": t.url, "method": t.method, "headers": t.headers, "body": t.body, "parameters": t.parameters} for t in request.targets]
    
    # Build stealth config if enabled
    stealth_config = None
    if request.stealth_mode:
        stealth_config = {
            "enabled": True,
            "delay_min": request.stealth_delay_min,
            "delay_max": request.stealth_delay_max,
            "requests_before_pause": request.stealth_requests_before_pause,
            "pause_duration": request.stealth_pause_duration,
            "randomize_user_agent": request.stealth_randomize_user_agent,
            "randomize_headers": request.stealth_randomize_headers,
            "ip_renewal_enabled": request.stealth_ip_renewal_enabled,
            "ip_renewal_interval": request.stealth_ip_renewal_interval,
        }
    
    async def event_generator():
        try:
            async for event in start_agentic_fuzzing(
                targets, max_iter, auto_save=request.auto_save, save_interval=request.save_interval,
                auto_pilot_mode=request.auto_pilot_mode, auto_escalation=request.auto_escalation,
                techniques=request.techniques, max_duration_seconds=request.max_duration_seconds,
                dry_run=request.dry_run, stop_on_critical=request.stop_on_critical,
                min_severity_to_report=request.min_severity_to_report, log_full_requests=request.log_full_requests,
                log_full_responses=request.log_full_responses,
                enable_crawl=request.enable_crawl, crawl_depth=request.crawl_depth,
                crawl_max_pages=request.crawl_max_pages, enable_recon=request.enable_recon,
                stealth_config=stealth_config,
            ):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.exception(f"Agentic fuzzing error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


@router.post("/quick-scan")
async def quick_scan(request: QuickScanRequest, current_user: User = Depends(get_current_active_user)):
    """Perform a quick agentic scan on a single URL with simplified configuration."""
    targets = [{"url": request.url, "method": request.method, "headers": request.headers}]
    
    async def event_generator():
        try:
            async for event in start_agentic_fuzzing(
                targets, request.max_iterations, max_duration_seconds=request.max_duration_seconds,
                dry_run=request.dry_run, stop_on_critical=request.stop_on_critical,
                min_severity_to_report=request.min_severity_to_report,
            ):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.exception(f"Quick scan error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


# =============================================================================
# WEBSOCKET ENDPOINT
# =============================================================================

@router.websocket("/ws")
async def websocket_fuzzing(websocket: WebSocket):
    """WebSocket endpoint for real-time agentic fuzzing with bidirectional communication."""
    await websocket.accept()
    current_session_id = None
    
    try:
        while True:
            data = await websocket.receive_json()
            command = data.get("command")
            
            if command == "start":
                targets = data.get("targets", [])
                max_iterations = data.get("max_iterations", 50)
                
                if not targets:
                    await websocket.send_json({"type": "error", "error": "No targets provided"})
                    continue
                
                async for event in start_agentic_fuzzing(targets, max_iterations):
                    await websocket.send_json(event)
                    if event.get("type") == "session_started":
                        current_session_id = event.get("session_id")
                    try:
                        incoming = await asyncio.wait_for(websocket.receive_json(), timeout=0.1)
                        if incoming.get("command") == "stop":
                            if current_session_id:
                                stop_session(current_session_id)
                            await websocket.send_json({"type": "stopped", "message": "Fuzzing stopped by user"})
                            break
                    except asyncio.TimeoutError:
                        pass
                
            elif command == "stop":
                if current_session_id:
                    stop_session(current_session_id)
                    await websocket.send_json({"type": "stopped", "message": "Session stopped"})
                else:
                    await websocket.send_json({"type": "error", "error": "No active session"})
                    
            elif command == "status":
                if current_session_id:
                    session = get_session(current_session_id)
                    if session:
                        await websocket.send_json({"type": "status", "session": session.to_dict()})
                    else:
                        await websocket.send_json({"type": "status", "message": "Session not found"})
                else:
                    await websocket.send_json({"type": "status", "sessions": list_sessions()})
                    
            elif command == "ping":
                await websocket.send_json({"type": "pong"})
            else:
                await websocket.send_json({"type": "error", "error": f"Unknown command: {command}"})
                
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
        if current_session_id:
            stop_session(current_session_id)
    except Exception as e:
        logger.exception(f"WebSocket error: {e}")
        try:
            await websocket.send_json({"type": "error", "error": str(e)})
        except:
            pass


# =============================================================================
# SESSION MANAGEMENT
# =============================================================================

@router.get("/sessions")
async def get_sessions(current_user: User = Depends(get_current_active_user)):
    """Get all active agentic fuzzing sessions."""
    return {"sessions": list_sessions()}


@router.get("/sessions/{session_id}")
async def get_session_details(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Get details of a specific session."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.to_dict()


@router.post("/sessions/{session_id}/stop")
async def stop_fuzzing_session(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Stop an active fuzzing session."""
    if stop_session(session_id):
        return {"message": "Session stopped", "session_id": session_id}
    raise HTTPException(status_code=404, detail="Session not found or already stopped")


@router.post("/sessions/{session_id}/pause")
async def pause_fuzzing_session(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Pause an active session and save it for later resumption."""
    save_path = pause_session(session_id)
    if save_path:
        return {"message": "Session paused and saved", "session_id": session_id, "save_path": save_path}
    raise HTTPException(status_code=404, detail="Session not found or could not be saved")


@router.post("/sessions/resume")
async def resume_session(request: ResumeSessionRequest, current_user: User = Depends(get_current_active_user)):
    """Resume a previously saved fuzzing session."""
    async def event_generator():
        try:
            async for event in resume_agentic_fuzzing(request.session_id, request.additional_iterations):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.exception(f"Resume session error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


@router.get("/sessions/saved")
async def get_saved_session_list(current_user: User = Depends(get_current_active_user)):
    """Get all saved sessions that can be resumed."""
    return {"sessions": get_saved_sessions()}


@router.delete("/sessions/saved/{session_id}")
async def delete_saved_session(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Delete a saved session from disk."""
    if delete_session(session_id):
        return {"message": "Session deleted", "session_id": session_id}
    raise HTTPException(status_code=404, detail="Saved session not found")


@router.post("/sessions/{session_id}/restore")
async def restore_from_checkpoint(session_id: str, checkpoint_id: Optional[str] = None, current_user: User = Depends(get_current_active_user)):
    """Restore a session from a checkpoint."""
    result = restore_session_checkpoint(session_id, checkpoint_id)
    if result:
        return {"message": "Session restored from checkpoint", "session_id": session_id, "checkpoint_id": checkpoint_id or "latest", "state": result}
    raise HTTPException(status_code=404, detail="Checkpoint not found")


# =============================================================================
# SCAN CONTROL (Phase 1 Features)
# =============================================================================

@router.get("/sessions/{session_id}/scan-control")
async def get_scan_control_status(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Get scan control status for a session (timeout, dry-run, severity filter, etc.)."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "session_id": session_id,
        "scan_control": {
            "max_duration_seconds": session.max_duration_seconds,
            "elapsed_seconds": session._get_elapsed_seconds(),
            "time_remaining_seconds": session._get_time_remaining(),
            "timeout_reached": session.timeout_reached,
            "dry_run": session.dry_run,
            "stop_on_critical": session.stop_on_critical,
            "critical_finding_detected": session.critical_finding_detected,
            "min_severity_to_report": session.min_severity_to_report,
            "log_full_requests": session.log_full_requests,
            "log_full_responses": session.log_full_responses,
            "requests_logged_count": len(session.requests_logged),
        },
    }


@router.get("/sessions/{session_id}/request-logs")
async def get_session_request_logs(session_id: str, limit: int = 100, offset: int = 0, current_user: User = Depends(get_current_active_user)):
    """Get request/response logs for a session (if logging was enabled)."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session.log_full_requests and not session.log_full_responses:
        return {"session_id": session_id, "logging_enabled": False, "message": "Request logging was not enabled for this session", "logs": []}
    
    limit = min(limit, 500)
    logs = session.requests_logged[offset:offset + limit]
    return {"session_id": session_id, "logging_enabled": True, "total_logs": len(session.requests_logged), "offset": offset, "limit": limit, "logs": logs}


@router.get("/sessions/{session_id}/dry-run-plan")
async def get_dry_run_plan(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Get the dry-run plan for a session (if dry-run mode was used)."""
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session.dry_run:
        return {"session_id": session_id, "dry_run": False, "message": "This session was not run in dry-run mode", "plan": None}
    return {"session_id": session_id, "dry_run": True, "plan": session.dry_run_plan}


@router.post("/validate-scan-config")
async def validate_scan_configuration(request: StartAgenticFuzzingRequest, current_user: User = Depends(get_current_active_user)):
    """Validate scan configuration without starting a scan."""
    warnings, errors = [], []
    
    for i, target in enumerate(request.targets):
        if not target.url.startswith(("http://", "https://")):
            errors.append(f"Target {i}: URL must start with http:// or https://")
    
    if request.techniques:
        valid_techniques = [t.value for t in FuzzingTechnique]
        for tech in request.techniques:
            if tech not in valid_techniques:
                warnings.append(f"Unknown technique '{tech}' will be ignored")
    
    valid_severities = ["info", "low", "medium", "high", "critical"]
    if request.min_severity_to_report.lower() not in valid_severities:
        errors.append(f"Invalid severity '{request.min_severity_to_report}'. Must be one of: {valid_severities}")
    
    if request.max_iterations > 100 and not request.max_duration_seconds:
        warnings.append("High iteration count without timeout - consider setting max_duration_seconds")
    if request.log_full_responses:
        warnings.append("log_full_responses=True may consume significant memory for large responses")
    
    estimated_requests = len(request.targets) * request.max_iterations * 10
    estimated_duration_minutes = estimated_requests * 0.5 / 60
    
    return {
        "valid": len(errors) == 0, "errors": errors, "warnings": warnings,
        "estimates": {"targets_count": len(request.targets), "max_iterations": request.max_iterations, "estimated_requests": estimated_requests, "estimated_duration_minutes": round(estimated_duration_minutes, 1), "timeout_configured": request.max_duration_seconds is not None},
    }


# =============================================================================
# TECHNIQUES & PRESETS
# =============================================================================

@router.get("/techniques")
async def get_techniques():
    """Get available fuzzing techniques."""
    techniques = []
    for tech in FuzzingTechnique:
        techniques.append({"id": tech.value, "name": tech.value.replace("_", " ").title(), "category": _get_technique_category(tech)})
    return {"techniques": techniques}


def _get_technique_category(tech: FuzzingTechnique) -> str:
    offensive = [FuzzingTechnique.C2_DETECTION, FuzzingTechnique.MALWARE_ANALYSIS, FuzzingTechnique.EVASION_TESTING]
    injection = [FuzzingTechnique.SQL_INJECTION, FuzzingTechnique.XSS, FuzzingTechnique.COMMAND_INJECTION, FuzzingTechnique.SSTI, FuzzingTechnique.XXE, FuzzingTechnique.HEADER_INJECTION]
    access = [FuzzingTechnique.IDOR, FuzzingTechnique.AUTH_BYPASS, FuzzingTechnique.SSRF]
    if tech in offensive:
        return "Offensive Security"
    elif tech in injection:
        return "Injection"
    elif tech in access:
        return "Access Control"
    return "Other"


@router.get("/presets")
async def get_fuzzing_presets():
    """Get preset fuzzing configurations."""
    return {
        "presets": [
            {"id": "web_app_quick", "name": "Web App Quick Scan", "description": "Fast scan for common web vulnerabilities", "max_iterations": 20, "techniques": ["sql_injection", "xss", "path_traversal"], "depth": "quick"},
            {"id": "web_app_thorough", "name": "Web App Thorough", "description": "Comprehensive web application security assessment", "max_iterations": 100, "techniques": [], "depth": "thorough"},
            {"id": "api_security", "name": "API Security Test", "description": "Focus on API-specific vulnerabilities", "max_iterations": 50, "techniques": ["sql_injection", "idor", "auth_bypass", "api_abuse", "parameter_pollution"], "depth": "normal"},
            {"id": "injection_focus", "name": "Injection Focus", "description": "Deep dive into injection vulnerabilities", "max_iterations": 75, "techniques": ["sql_injection", "command_injection", "ssti", "xxe", "header_injection"], "depth": "thorough"},
            {"id": "malware_analysis", "name": "Malware Analysis", "description": "Analyze sandboxed software for malicious behavior", "max_iterations": 50, "techniques": ["c2_detection", "malware_analysis", "evasion_testing"], "depth": "normal"},
        ]
    }


# =============================================================================
# ROBUSTNESS & HEALTH
# =============================================================================

@router.get("/health")
async def get_fuzzer_health():
    """Get fuzzer health status including robustness components."""
    stats = get_robustness_stats()
    http_healthy = stats["http_circuit_breaker"]["can_execute"]
    llm_healthy = stats["llm_circuit_breaker"]["can_execute"]
    
    status = "healthy"
    issues = []
    if not http_healthy:
        status = "degraded"
        issues.append("HTTP circuit breaker is open - target may be unavailable")
    if not llm_healthy:
        status = "degraded"
        issues.append("LLM circuit breaker is open - AI service may be unavailable")
    if stats["rate_limiter"]["current_rate"] < 2.0:
        issues.append("Rate limiter is heavily throttled - expect slower performance")
    
    return {"status": status, "http_circuit_breaker": stats["http_circuit_breaker"]["state"], "llm_circuit_breaker": stats["llm_circuit_breaker"]["state"], "rate_limit": f"{stats['rate_limiter']['current_rate']:.1f} req/s", "issues": issues, "ready": status == "healthy"}


@router.get("/robustness/stats")
async def get_robustness_statistics(current_user: User = Depends(get_current_active_user)):
    """Get current robustness component statistics (rate limiter, circuit breakers, etc.)."""
    return get_robustness_stats()


@router.post("/robustness/reset")
async def reset_robustness_statistics(current_user: User = Depends(get_current_active_user)):
    """Reset all robustness component statistics."""
    reset_robustness_stats()
    return {"message": "Robustness statistics reset", "new_stats": get_robustness_stats()}


@router.get("/degradation/status")
async def get_graceful_degradation_status(current_user: User = Depends(get_current_active_user)):
    """Get graceful degradation system status (degradation level, failure count, etc.)."""
    return get_degradation_status()


@router.get("/errors/stats")
async def get_error_classification_stats(current_user: User = Depends(get_current_active_user)):
    """Get error classification statistics."""
    return get_error_stats()


@router.get("/errors/deadletter")
async def get_dead_letter_queue_stats(current_user: User = Depends(get_current_active_user)):
    """Get dead letter queue statistics."""
    return get_dead_letter_stats()


# =============================================================================
# WATCHDOG & SELF-HEALING
# =============================================================================

@router.get("/watchdog/health")
async def get_watchdog_health_status(current_user: User = Depends(get_current_active_user)):
    """Get watchdog and self-healing system health."""
    return get_watchdog_health()


@router.get("/watchdog/alerts")
async def get_watchdog_alerts_list(limit: int = 20, current_user: User = Depends(get_current_active_user)):
    """Get recent watchdog alerts."""
    return get_watchdog_alerts(limit)


@router.post("/watchdog/start")
async def start_watchdog_service(current_user: User = Depends(get_current_active_user)):
    """Start the watchdog background service."""
    await start_watchdog()
    return {"message": "Watchdog started", "health": get_watchdog_health()}


@router.post("/watchdog/stop")
async def stop_watchdog_service(current_user: User = Depends(get_current_active_user)):
    """Stop the watchdog background service."""
    await stop_watchdog()
    return {"message": "Watchdog stopped"}


# =============================================================================
# AUTHENTICATION
# =============================================================================

@router.post("/auth/configure")
async def configure_authentication(request: AuthConfigRequest, current_user: User = Depends(get_current_active_user)):
    """Configure authentication for fuzzing requests (basic, bearer, API key, OAuth2, etc.)."""
    try:
        auth_type = AuthType[request.auth_type.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid auth type: {request.auth_type}. Must be one of: {[t.name.lower() for t in AuthType]}")
    
    config = AuthConfig(
        auth_type=auth_type, username=request.username, password=request.password, token=request.token,
        api_key_name=request.api_key_header or "X-API-Key", api_key_location=request.api_key_location or "header",
        oauth_client_id=request.client_id, oauth_client_secret=request.client_secret, oauth_token_url=request.token_url,
        oauth_scope=" ".join(request.scopes) if request.scopes else None, login_url=request.login_url, login_payload=request.login_data,
        session_cookie_name=request.session_cookie_name or "session",
    )
    configure_auth(config)
    return {"message": "Authentication configured successfully", "auth_type": auth_type.value, "status": get_auth_status()}


@router.get("/auth/status")
async def get_authentication_status(current_user: User = Depends(get_current_active_user)):
    """Get current authentication configuration status."""
    return get_auth_status()


@router.post("/auth/clear")
async def clear_authentication(current_user: User = Depends(get_current_active_user)):
    """Clear authentication configuration."""
    clear_auth()
    return {"message": "Authentication cleared", "status": get_auth_status()}


# =============================================================================
# DEDUPLICATION
# =============================================================================

@router.get("/deduplication/stats")
async def get_deduplication_statistics(current_user: User = Depends(get_current_active_user)):
    """Get finding deduplication statistics."""
    return get_deduplication_stats()


@router.post("/deduplication/reset")
async def reset_deduplication_stats(current_user: User = Depends(get_current_active_user)):
    """Reset deduplication tracking."""
    reset_deduplication()
    return {"message": "Deduplication tracking reset", "stats": get_deduplication_stats()}


# =============================================================================
# QUALITY FEATURES
# =============================================================================

@router.get("/quality/payloads/stats")
async def get_payload_stats(current_user: User = Depends(get_current_active_user)):
    """Get context-aware payload generator statistics."""
    return get_payload_generator_stats()


@router.get("/quality/analyzer/stats")
async def get_analyzer_stats(current_user: User = Depends(get_current_active_user)):
    """Get response analyzer statistics."""
    return get_response_analyzer_stats()


@router.get("/quality/attack-surface/stats")
async def get_attack_surface_stats_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get attack surface mapper statistics."""
    return get_attack_surface_stats()


@router.get("/quality/stats")
async def get_all_quality_stats(current_user: User = Depends(get_current_active_user)):
    """Get combined quality feature statistics."""
    return {"payload_generator": get_payload_generator_stats(), "response_analyzer": get_response_analyzer_stats(), "attack_surface_mapper": get_attack_surface_stats()}


@router.post("/quality/reset")
async def reset_quality_features_endpoint(current_user: User = Depends(get_current_active_user)):
    """Reset all quality feature caches and learned patterns."""
    reset_quality_features()
    return {"message": "Quality features reset", "stats": {"payload_generator": get_payload_generator_stats(), "response_analyzer": get_response_analyzer_stats(), "attack_surface_mapper": get_attack_surface_stats()}}


# =============================================================================
# AUTOMATION ENGINE
# =============================================================================

@router.get("/automation/stats")
async def get_automation_engine_stats(current_user: User = Depends(get_current_active_user)):
    """Get automation engine statistics."""
    return get_automation_stats()


@router.get("/automation/coverage")
async def get_automation_coverage_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get detailed coverage tracking information."""
    return get_automation_coverage()


@router.get("/automation/queue")
async def get_automation_queue_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get the current automation task queue."""
    return get_automation_queue()


@router.post("/automation/mode")
async def set_auto_pilot_mode_endpoint(request: SetAutoPilotRequest, current_user: User = Depends(get_current_active_user)):
    """Set the auto-pilot mode (disabled, assisted, semi_auto, full_auto)."""
    try:
        return set_auto_pilot_mode(request.mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/automation/escalation")
async def set_auto_escalation_endpoint(enabled: bool = True, current_user: User = Depends(get_current_active_user)):
    """Enable or disable auto-escalation."""
    return set_auto_escalation(enabled)


@router.post("/automation/reset")
async def reset_automation_endpoint(current_user: User = Depends(get_current_active_user)):
    """Reset the automation engine."""
    return reset_automation_engine()


# =============================================================================
# WORDLISTS
# =============================================================================

@router.get("/wordlists/stats")
async def get_wordlist_stats_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get statistics about available wordlists."""
    return get_wordlist_stats()


@router.get("/wordlists/{technique}")
async def get_wordlist_by_technique_endpoint(technique: str, limit: int = 100, current_user: User = Depends(get_current_active_user)):
    """Get wordlist payloads for a specific attack technique."""
    payloads = get_wordlist_for_technique(technique, limit=limit)
    return {"technique": technique, "count": len(payloads), "payloads": payloads}


# =============================================================================
# REPORTS - SAVE, LIST, EXPORT
# =============================================================================

@router.post("/reports/save")
async def save_fuzzer_report(request: SaveReportRequest, db: DBSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Save a completed fuzzing session as a report."""
    session = get_session(request.session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {request.session_id} not found")
    
    existing = db.query(AgenticFuzzerReport).filter(AgenticFuzzerReport.session_id == request.session_id).first()
    if existing:
        return {"success": True, "message": "Report already exists", "report_id": existing.id, "session_id": existing.session_id}
    
    session_dict = session if isinstance(session, dict) else session.to_dict() if hasattr(session, 'to_dict') else {}
    findings = session_dict.get("findings", [])
    
    findings_critical = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
    findings_high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
    findings_medium = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
    findings_low = sum(1 for f in findings if f.get("severity", "").lower() == "low")
    findings_info = sum(1 for f in findings if f.get("severity", "").lower() == "info")
    
    targets = session_dict.get("targets", [])
    target_url = targets[0].get("url", "Unknown") if targets else "Unknown"
    
    started_at = session_dict.get("started_at")
    completed_at = session_dict.get("completed_at")
    duration_seconds = None
    if started_at and completed_at:
        try:
            start = dt.fromisoformat(started_at.replace("Z", "+00:00")) if isinstance(started_at, str) else started_at
            end = dt.fromisoformat(completed_at.replace("Z", "+00:00")) if isinstance(completed_at, str) else completed_at
            duration_seconds = (end - start).total_seconds()
        except Exception:
            pass
    
    report = AgenticFuzzerReport(
        session_id=request.session_id, user_id=current_user.id, project_id=request.project_id,
        title=request.title or f"Security Scan: {target_url}", target_url=target_url,
        scan_profile=session_dict.get("scan_profile_name"),
        started_at=dt.fromisoformat(started_at.replace("Z", "+00:00")) if isinstance(started_at, str) else (started_at or dt.utcnow()),
        completed_at=dt.fromisoformat(completed_at.replace("Z", "+00:00")) if isinstance(completed_at, str) else (completed_at or dt.utcnow()),
        duration_seconds=duration_seconds, total_iterations=session_dict.get("iterations", 0), total_requests=session_dict.get("total_requests", 0),
        findings_critical=findings_critical, findings_high=findings_high, findings_medium=findings_medium, findings_low=findings_low, findings_info=findings_info,
        duplicates_filtered=session_dict.get("duplicate_findings_skipped", 0), executive_summary=session_dict.get("executive_summary"),
        ai_report=session_dict.get("ai_report") or session_dict.get("report"), findings=findings, techniques_used=session_dict.get("techniques_tried"),
        correlation_analysis=session_dict.get("correlation_analysis"), engine_stats=session_dict.get("engine_stats"), crawl_results=session_dict.get("sitemap"), session_data=session_dict,
    )
    
    db.add(report)
    db.commit()
    db.refresh(report)
    logger.info(f"Saved fuzzer report {report.id} for session {request.session_id}")
    
    return {"success": True, "message": "Report saved successfully", "report_id": report.id, "session_id": report.session_id, "title": report.title, "findings_count": findings_critical + findings_high + findings_medium + findings_low + findings_info}


@router.get("/reports")
async def list_fuzzer_reports(skip: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100), db: DBSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """List saved fuzzer reports for the current user."""
    query = db.query(AgenticFuzzerReport).filter(AgenticFuzzerReport.user_id == current_user.id).order_by(AgenticFuzzerReport.created_at.desc())
    total = query.count()
    reports = query.offset(skip).limit(limit).all()
    
    return {
        "total": total, "skip": skip, "limit": limit,
        "reports": [
            {"id": r.id, "session_id": r.session_id, "title": r.title, "target_url": r.target_url, "scan_profile": r.scan_profile,
             "completed_at": r.completed_at.isoformat() if r.completed_at else None, "duration_seconds": r.duration_seconds,
             "findings": {"critical": r.findings_critical, "high": r.findings_high, "medium": r.findings_medium, "low": r.findings_low, "info": r.findings_info,
                          "total": (r.findings_critical or 0) + (r.findings_high or 0) + (r.findings_medium or 0) + (r.findings_low or 0) + (r.findings_info or 0)}}
            for r in reports
        ],
    }


@router.get("/reports/{report_id}")
async def get_fuzzer_report(report_id: int, db: DBSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Get full details of a saved fuzzer report."""
    report = db.query(AgenticFuzzerReport).filter(AgenticFuzzerReport.id == report_id, AgenticFuzzerReport.user_id == current_user.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {
        "id": report.id, "session_id": report.session_id, "title": report.title, "target_url": report.target_url, "scan_profile": report.scan_profile,
        "started_at": report.started_at.isoformat() if report.started_at else None, "completed_at": report.completed_at.isoformat() if report.completed_at else None,
        "duration_seconds": report.duration_seconds, "total_iterations": report.total_iterations, "total_requests": report.total_requests,
        "findings_summary": {"critical": report.findings_critical, "high": report.findings_high, "medium": report.findings_medium, "low": report.findings_low, "info": report.findings_info,
                             "total": (report.findings_critical or 0) + (report.findings_high or 0) + (report.findings_medium or 0) + (report.findings_low or 0) + (report.findings_info or 0), "duplicates_filtered": report.duplicates_filtered},
        "executive_summary": report.executive_summary, "ai_report": report.ai_report, "findings": report.findings, "techniques_used": report.techniques_used,
        "correlation_analysis": report.correlation_analysis, "engine_stats": report.engine_stats, "crawl_results": report.crawl_results,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }


@router.get("/reports/{report_id}/export")
async def export_fuzzer_report_endpoint(report_id: int, format: str = Query(..., description="Export format: markdown, pdf, or docx"), db: DBSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Export a fuzzer report to Markdown, PDF, or Word format."""
    report = db.query(AgenticFuzzerReport).filter(AgenticFuzzerReport.id == report_id, AgenticFuzzerReport.user_id == current_user.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    try:
        buffer, filename, content_type = export_fuzzer_report(report, format)
        return Response(content=buffer.read(), media_type=content_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Export dependency missing: {e}")
    except Exception as e:
        logger.exception(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


@router.delete("/reports/{report_id}")
async def delete_fuzzer_report(report_id: int, db: DBSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Delete a saved fuzzer report."""
    report = db.query(AgenticFuzzerReport).filter(AgenticFuzzerReport.id == report_id, AgenticFuzzerReport.user_id == current_user.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    db.delete(report)
    db.commit()
    return {"success": True, "message": "Report deleted successfully"}


@router.post("/reports/save-from-final-report")
async def save_from_final_report(request_body: Dict[str, Any], db: DBSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Save a report directly from the final_report SSE event data."""
    # Handle both wrapped and unwrapped formats
    if "final_report" in request_body:
        # Frontend sends: {final_report: {...}, title: "...", project_id: ...}
        final_report = request_body.get("final_report", {})
        title = request_body.get("title")
        project_id = request_body.get("project_id")
    else:
        # Direct final_report object
        final_report = request_body
        title = None
        project_id = None
    
    logger.info(f"Saving report from final_report: keys={list(final_report.keys())}")
    
    session_summary = final_report.get("session_summary", {})
    
    # Debug: log if session_summary is empty
    if not session_summary or not session_summary.get("id"):
        logger.warning(f"Empty or invalid session_summary in final_report. Keys present: {list(final_report.keys())}")
    
    session_id = session_summary.get("id", f"manual_{dt.utcnow().timestamp()}")
    
    existing = db.query(AgenticFuzzerReport).filter(AgenticFuzzerReport.session_id == session_id).first()
    if existing:
        return {"success": True, "message": "Report already exists", "report_id": existing.id, "session_id": existing.session_id}
    
    findings = session_summary.get("findings", [])
    findings_critical = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
    findings_high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
    findings_medium = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
    findings_low = sum(1 for f in findings if f.get("severity", "").lower() == "low")
    findings_info = sum(1 for f in findings if f.get("severity", "").lower() == "info")
    
    targets = session_summary.get("targets", [])
    target_url = targets[0].get("url", "Unknown") if targets else "Unknown"
    
    ai_report = final_report.get("report", {})
    executive_summary_raw = ai_report.get("executive_summary") if isinstance(ai_report, dict) else None
    # executive_summary column is Text, not JSON - serialize if dict
    executive_summary = json.dumps(executive_summary_raw) if isinstance(executive_summary_raw, dict) else executive_summary_raw
    
    started_at = session_summary.get("started_at")
    completed_at = session_summary.get("completed_at")
    duration_seconds = None
    if started_at and completed_at:
        try:
            start = dt.fromisoformat(started_at.replace("Z", "+00:00")) if isinstance(started_at, str) else started_at
            end = dt.fromisoformat(completed_at.replace("Z", "+00:00")) if isinstance(completed_at, str) else completed_at
            duration_seconds = (end - start).total_seconds()
        except Exception:
            pass
    
    # Ensure all JSON fields are properly typed (dict/list for JSON columns, string for Text)
    def ensure_json_serializable(val):
        """Convert strings to dicts if they're JSON strings, or return as-is."""
        if val is None:
            return None
        if isinstance(val, str):
            try:
                return json.loads(val)
            except (json.JSONDecodeError, TypeError):
                return val
        return val
    
    report = AgenticFuzzerReport(
        session_id=session_id, user_id=current_user.id, project_id=project_id, title=title or f"Security Scan: {target_url}", target_url=target_url,
        scan_profile=session_summary.get("scan_profile_name"), started_at=dt.fromisoformat(started_at.replace("Z", "+00:00")) if isinstance(started_at, str) else (dt.utcnow()),
        completed_at=dt.fromisoformat(completed_at.replace("Z", "+00:00")) if isinstance(completed_at, str) else (dt.utcnow()), duration_seconds=duration_seconds,
        total_iterations=session_summary.get("iterations", 0), total_requests=session_summary.get("total_requests", 0),
        findings_critical=findings_critical, findings_high=findings_high, findings_medium=findings_medium, findings_low=findings_low, findings_info=findings_info,
        duplicates_filtered=session_summary.get("duplicate_findings_skipped", 0), executive_summary=executive_summary,
        ai_report=ensure_json_serializable(ai_report),
        findings=ensure_json_serializable(findings) if isinstance(findings, str) else findings,
        techniques_used=ensure_json_serializable(session_summary.get("techniques_tried")),
        correlation_analysis=ensure_json_serializable(final_report.get("correlation_analysis")),
        engine_stats=ensure_json_serializable(final_report.get("engine_stats")),
        crawl_results=ensure_json_serializable(final_report.get("crawl_results")),
        session_data=ensure_json_serializable(session_summary) if isinstance(session_summary, str) else session_summary,
    )
    
    db.add(report)
    db.commit()
    db.refresh(report)
    logger.info(f"Saved fuzzer report {report.id} from final_report")
    
    return {"success": True, "message": "Report saved successfully", "report_id": report.id, "session_id": report.session_id, "title": report.title, "findings_count": findings_critical + findings_high + findings_medium + findings_low + findings_info}
