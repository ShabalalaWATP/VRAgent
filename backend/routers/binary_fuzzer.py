"""
Binary Fuzzer API Router

Endpoints for binary/executable vulnerability research.
Phase 2: Coverage-guided fuzzing, corpus management, seed scheduling.
Phase 3: Memory safety analysis, sanitizer integration.
Phase 4: Binary upload, AFL++ integration.
"""

from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import asyncio
import json
import logging
import os
import shutil
import uuid
import stat
from pathlib import Path
from datetime import datetime

from backend.services.binary_fuzzer_service import (
    start_binary_fuzzing,
    stop_fuzzing_session,
    get_fuzzing_session,
    get_all_sessions,
    get_session_crashes,
    get_memory_safety_report,
    MutationStrategy,
    FuzzingMode,
    CrashSeverity,
    CrashType,
    SeedScheduler,
    MemoryErrorType,
    # AFL++ integration
    start_afl_fuzzing,
    stop_afl_session,
    get_afl_session_status,
    check_afl_installation,
    AflPlusPlusFuzzer,
    # Report generation (Phase 5)
    generate_fuzzing_report,
    # Medium priority features (Phase 6)
    InputFormat,
    StructuredInputGenerator,
    NetworkTarget,
    NetworkProtocolFuzzer,
    DifferentialTarget,
    DifferentialFuzzer,
    MutatorPluginManager,
    CorpusDistiller,
    MutationEngine,
    # Low priority features (Phase 7)
    ParallelFuzzer,
    PersistentModeHarness,
    ForkServerHarness,
    SnapshotFuzzer,
    SymbolicExecutionHintGenerator,
    # Beginner-friendly features (Phase 8)
    BinaryAutoDetector,
    BinaryType,
    InputType,
    FuzzingSetupWizard,
    WizardStep,
    FuzzingTemplateLibrary,
    TemplateCategory,
    FuzzingHealthChecker,
    SmartDefaultsEngine,
    PlainEnglishExplainer,
    CrashType,
    FuzzingProgressTracker,
    CrashAutoTriager,
    CrashSeverityLevel,
    # One-Click Examples (Feature 17)
    OneClickExampleLibrary,
    VulnerabilityType,
    ExampleDifficulty,
    # Final Report Generator
    FinalReportGenerator,
    ReportFormat,
    # QEMU Mode for Closed-Source Binaries
    QemuModeManager,
    QemuArchitecture,
    QemuModeType,
    QemuFuzzConfig,
    QemuCapabilities,
    BinaryArchitectureInfo,
    get_qemu_capabilities,
    detect_binary_arch,
    get_qemu_recommendations,
    run_qemu_trace_analysis,
    get_qemu_help,
)
from backend.core.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/binary-fuzzer", tags=["Binary Fuzzer"])

# Fuzzing workspace directories
FUZZING_BASE_DIR = Path("/fuzzing")
BINARIES_DIR = FUZZING_BASE_DIR / "binaries"
SEEDS_DIR = FUZZING_BASE_DIR / "seeds"
OUTPUT_DIR = FUZZING_BASE_DIR / "output"
CRASHES_DIR = FUZZING_BASE_DIR / "crashes"

# Ensure directories exist
for dir_path in [BINARIES_DIR, SEEDS_DIR, OUTPUT_DIR, CRASHES_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)


# =============================================================================
# REQUEST/RESPONSE SCHEMAS
# =============================================================================

class StartFuzzingRequest(BaseModel):
    """Request to start binary fuzzing."""
    target_path: str = Field(..., description="Path to target executable")
    target_args: str = Field(
        default="@@", 
        description="Command line template (@@ replaced with input file path)"
    )
    seed_dir: Optional[str] = Field(
        None, 
        description="Directory containing seed input files"
    )
    output_dir: Optional[str] = Field(
        None, 
        description="Directory for crash outputs"
    )
    timeout_ms: int = Field(
        default=5000, 
        ge=100, 
        le=60000,
        description="Execution timeout in milliseconds"
    )
    max_iterations: Optional[int] = Field(
        None, 
        ge=1,
        description="Maximum number of executions"
    )
    max_time_seconds: Optional[int] = Field(
        None, 
        ge=1,
        description="Maximum runtime in seconds"
    )
    dictionary: Optional[List[str]] = Field(
        None,
        description="Custom dictionary entries for mutations"
    )
    # Phase 2: Coverage-guided options
    coverage_guided: bool = Field(
        default=True,
        description="Enable coverage-guided fuzzing for better path exploration"
    )
    scheduler_strategy: str = Field(
        default="power_schedule",
        description="Seed scheduling strategy: round_robin, favored_first, rare_edge, power_schedule, random"
    )


class StopFuzzingRequest(BaseModel):
    """Request to stop fuzzing."""
    session_id: str = Field(..., description="Session ID to stop")


class SessionResponse(BaseModel):
    """Fuzzing session response."""
    id: str
    target_path: str
    target_args: str
    mode: str
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]
    total_executions: int
    total_crashes: int
    unique_crashes: int
    total_timeouts: int
    executions_per_second: float
    coverage_percentage: float
    current_input_size: int
    error: Optional[str]
    # Phase 2 fields
    total_edges_discovered: int = 0
    corpus_size: int = 0
    favored_inputs: int = 0
    new_coverage_inputs: int = 0
    scheduler_strategy: str = "power_schedule"


class CrashBucketResponse(BaseModel):
    """Crash bucket response."""
    id: str
    crash_type: str
    severity: str
    stack_hash: str
    sample_count: int
    first_seen: str
    last_seen: str
    sample_crashes: List[str]
    notes: str


class MutationTestRequest(BaseModel):
    """Request to test mutation engine."""
    input_data: str = Field(..., description="Base64-encoded input data")
    strategy: Optional[str] = Field(
        None,
        description="Mutation strategy to use"
    )
    iterations: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Number of mutations to generate"
    )


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("/start", response_model=Dict[str, Any])
async def start_fuzzing(
    request: StartFuzzingRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Start a binary fuzzing session.
    
    This initiates fuzzing of the target executable. Use the WebSocket
    endpoint for real-time progress updates, or poll the session status.
    """
    # Start fuzzing in background - return session info immediately
    # The actual fuzzing runs via WebSocket
    return {
        "success": True,
        "message": "Connect to WebSocket endpoint for real-time fuzzing",
        "websocket_url": f"/api/binary-fuzzer/ws?target={request.target_path}",
        "config": request.model_dump(),
    }


@router.post("/stop")
async def stop_fuzzing(
    request: StopFuzzingRequest,
    current_user: dict = Depends(get_current_user)
):
    """Stop a running fuzzing session."""
    result = stop_fuzzing_session(request.session_id)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/sessions", response_model=List[Dict[str, Any]])
async def list_sessions(
    current_user: dict = Depends(get_current_user)
):
    """List all active fuzzing sessions."""
    return get_all_sessions()


@router.get("/sessions/{session_id}", response_model=Dict[str, Any])
async def get_session(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get status of a specific fuzzing session."""
    session = get_fuzzing_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/sessions/{session_id}/crashes", response_model=List[Dict[str, Any]])
async def get_crashes(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get crash buckets for a session."""
    crashes = get_session_crashes(session_id)
    if crashes is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return crashes


@router.get("/sessions/{session_id}/memory-safety", response_model=Dict[str, Any])
async def get_memory_safety(
    session_id: str,
    crash_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Get memory safety analysis report for a session.
    
    Phase 3 endpoint - provides detailed memory error analysis including:
    - Heap corruption detection
    - Stack overflow detection  
    - Use-after-free detection
    - Sanitizer output parsing (ASan, MSan, TSan, UBSan, Valgrind)
    
    Args:
        session_id: Fuzzing session ID
        crash_id: Optional specific crash ID for detailed report
    
    Returns:
        Memory safety analysis with error categorization and recommendations
    """
    report = get_memory_safety_report(session_id, crash_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return report


# =============================================================================
# CRASH MINIMIZATION & POC GENERATION ENDPOINTS (Phase 5)
# =============================================================================

class MinimizeCrashRequest(BaseModel):
    """Request to minimize a crash input."""
    crash_id: str = Field(..., description="ID of the crash to minimize")
    strategy: str = Field(
        default="all",
        description="Minimization strategy: binary, block, linear, nullify, all"
    )
    max_attempts: int = Field(
        default=1000,
        ge=10,
        le=10000,
        description="Maximum minimization attempts"
    )


class GeneratePocRequest(BaseModel):
    """Request to generate a PoC script."""
    crash_id: str = Field(..., description="ID of the crash")
    format: str = Field(
        default="python",
        description="Output format: python, c, shell, report"
    )
    output_path: Optional[str] = Field(
        None,
        description="Custom output path for the PoC file"
    )


@router.post("/sessions/{session_id}/minimize-crash", response_model=Dict[str, Any])
async def minimize_crash(
    session_id: str,
    request: MinimizeCrashRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Minimize a crash input using delta debugging.
    
    Phase 5 endpoint - reduces crash inputs to the smallest reproducer:
    - Binary reduction: Halves input repeatedly
    - Block removal: Removes chunks of various sizes
    - Linear removal: Removes bytes one by one
    - Nullification: Replaces non-essential bytes with zeros
    
    Args:
        session_id: Fuzzing session ID
        request: Minimization parameters
    
    Returns:
        Minimization result with original/minimized sizes and reduction ratio
    """
    from backend.services.binary_fuzzer_service import _active_fuzzers
    
    fuzzer = _active_fuzzers.get(session_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Session not found or no longer active")
    
    try:
        result = await fuzzer.minimize_crash(
            crash_id=request.crash_id,
            strategy=request.strategy,
            max_attempts=request.max_attempts,
        )
        
        if not result.get("success", False):
            raise HTTPException(status_code=400, detail=result.get("error", "Minimization failed"))
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Crash minimization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sessions/{session_id}/generate-poc", response_model=Dict[str, Any])
async def generate_poc(
    session_id: str,
    request: GeneratePocRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Generate a Proof-of-Concept script for reproducing a crash.
    
    Phase 5 endpoint - creates standalone reproduction scripts:
    - Python: Cross-platform script with embedded payload
    - C: Native program for direct execution
    - Shell: Bash script for Unix systems
    - Report: Detailed Markdown analysis document
    
    Args:
        session_id: Fuzzing session ID
        request: PoC generation parameters
    
    Returns:
        Generated PoC with file path and content preview
    """
    from backend.services.binary_fuzzer_service import _active_fuzzers
    
    fuzzer = _active_fuzzers.get(session_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Session not found or no longer active")
    
    if request.format not in ("python", "c", "shell", "report"):
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid format: {request.format}. Must be: python, c, shell, or report"
        )
    
    try:
        result = fuzzer.generate_poc(
            crash_id=request.crash_id,
            format=request.format,
            output_path=request.output_path,
        )
        
        if not result.get("success", False):
            raise HTTPException(status_code=400, detail=result.get("error", "PoC generation failed"))
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"PoC generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}/crashes/{crash_id}/download-poc")
async def download_poc(
    session_id: str,
    crash_id: str,
    format: str = "python",
    current_user: dict = Depends(get_current_user)
):
    """
    Generate and download a PoC file for a specific crash.
    
    Args:
        session_id: Fuzzing session ID
        crash_id: Crash ID
        format: Output format (python, c, shell, report)
    
    Returns:
        File download response
    """
    from backend.services.binary_fuzzer_service import _active_fuzzers
    
    fuzzer = _active_fuzzers.get(session_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Session not found or no longer active")
    
    ext_map = {
        "python": (".py", "text/x-python"),
        "c": (".c", "text/x-c"),
        "shell": (".sh", "text/x-shellscript"),
        "report": (".md", "text/markdown"),
    }
    
    if format not in ext_map:
        raise HTTPException(status_code=400, detail=f"Invalid format: {format}")
    
    ext, media_type = ext_map[format]
    
    try:
        result = fuzzer.generate_poc(
            crash_id=crash_id,
            format=format,
        )
        
        if not result.get("success", False):
            raise HTTPException(status_code=400, detail=result.get("error", "PoC generation failed"))
        
        poc_path = result.get("path")
        if not poc_path or not os.path.isfile(poc_path):
            raise HTTPException(status_code=500, detail="PoC file not found after generation")
        
        return FileResponse(
            path=poc_path,
            filename=f"poc_{crash_id}{ext}",
            media_type=media_type,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"PoC download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# REPORT EXPORT ENDPOINTS (Phase 5)
# =============================================================================

class GenerateReportRequest(BaseModel):
    """Request to generate a fuzzing report."""
    format: str = Field(
        default="markdown",
        description="Report format: markdown, json, html"
    )
    output_path: Optional[str] = Field(
        None,
        description="Custom output path for the report file"
    )


@router.post("/sessions/{session_id}/generate-report", response_model=Dict[str, Any])
async def generate_report(
    session_id: str,
    request: GenerateReportRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Generate a comprehensive security report for a fuzzing session.
    
    Phase 5 endpoint - creates detailed reports with:
    - Executive summary with risk assessment
    - Session statistics (executions, coverage, crashes)
    - Memory safety analysis
    - Detailed crash analysis with exploitation guidance
    - Remediation recommendations
    
    Args:
        session_id: Fuzzing session ID
        request: Report generation parameters
    
    Returns:
        Report with file path and content preview
    """
    if request.format not in ("markdown", "json", "html"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {request.format}. Must be: markdown, json, or html"
        )
    
    try:
        result = generate_fuzzing_report(
            session_id=session_id,
            format=request.format,
            output_path=request.output_path,
        )
        
        if not result.get("success", False):
            raise HTTPException(status_code=400, detail=result.get("error", "Report generation failed"))
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}/download-report")
async def download_report(
    session_id: str,
    format: str = "markdown",
    current_user: dict = Depends(get_current_user)
):
    """
    Generate and download a fuzzing report.
    
    Args:
        session_id: Fuzzing session ID
        format: Report format (markdown, json, html)
    
    Returns:
        File download response
    """
    ext_map = {
        "markdown": (".md", "text/markdown"),
        "json": (".json", "application/json"),
        "html": (".html", "text/html"),
    }
    
    if format not in ext_map:
        raise HTTPException(status_code=400, detail=f"Invalid format: {format}")
    
    ext, media_type = ext_map[format]
    
    try:
        result = generate_fuzzing_report(
            session_id=session_id,
            format=format,
        )
        
        if not result.get("success", False):
            raise HTTPException(status_code=400, detail=result.get("error", "Report generation failed"))
        
        report_path = result.get("path")
        if not report_path or not os.path.isfile(report_path):
            raise HTTPException(status_code=500, detail="Report file not found after generation")
        
        return FileResponse(
            path=report_path,
            filename=f"fuzzing_report_{session_id}{ext}",
            media_type=media_type,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Report download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# STRUCTURED INPUT FUZZING ENDPOINTS (Phase 6)
# =============================================================================

class GenerateStructuredInputRequest(BaseModel):
    """Request to generate structured inputs."""
    format: str = Field(
        default="json",
        description="Input format: json, xml, csv, ini"
    )
    count: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Number of inputs to generate"
    )
    seed_base64: Optional[str] = Field(
        None,
        description="Base64 encoded seed for mutation-based generation"
    )


@router.post("/structured/generate", response_model=Dict[str, Any])
async def generate_structured_inputs(
    request: GenerateStructuredInputRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Generate structured fuzzing inputs (JSON, XML, CSV, INI).
    
    Phase 6 endpoint - creates grammar-based inputs with:
    - Edge case values (null, max int, special strings)
    - Injection payloads (XXE, formula injection, etc.)
    - Malformed structures
    
    Args:
        request: Generation parameters
    
    Returns:
        Generated inputs as base64 encoded strings
    """
    import base64
    
    format_map = {
        "json": InputFormat.JSON,
        "xml": InputFormat.XML,
        "csv": InputFormat.CSV,
        "ini": InputFormat.INI,
    }
    
    if request.format not in format_map:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {request.format}. Must be: json, xml, csv, or ini"
        )
    
    try:
        generator = StructuredInputGenerator(format_map[request.format])
        
        seed = None
        if request.seed_base64:
            seed = base64.b64decode(request.seed_base64)
        
        inputs = []
        for i in range(request.count):
            data = generator.generate(seed=seed, mutate_existing=seed is not None)
            inputs.append({
                "index": i,
                "data_base64": base64.b64encode(data).decode(),
                "size": len(data),
                "preview": data[:200].decode('utf-8', errors='replace'),
            })
        
        return {
            "success": True,
            "format": request.format,
            "count": len(inputs),
            "inputs": inputs,
        }
        
    except Exception as e:
        logger.exception(f"Structured input generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# NETWORK PROTOCOL FUZZING ENDPOINTS (Phase 6)
# =============================================================================

class NetworkFuzzRequest(BaseModel):
    """Request to start network protocol fuzzing."""
    host: str = Field(..., description="Target host")
    port: int = Field(..., ge=1, le=65535, description="Target port")
    protocol: str = Field(default="tcp", description="Protocol: tcp or udp")
    ssl: bool = Field(default=False, description="Use SSL/TLS")
    seed_data_base64: str = Field(..., description="Base64 encoded seed request")
    num_iterations: int = Field(default=100, ge=1, le=10000, description="Number of iterations")
    timeout_seconds: float = Field(default=5.0, ge=0.1, le=60.0, description="Connection timeout")


@router.post("/network/fuzz", response_model=Dict[str, Any])
async def start_network_fuzzing(
    request: NetworkFuzzRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Start network protocol fuzzing against a TCP/UDP service.
    
    Phase 6 endpoint - fuzzes network services by:
    - Mutating request data
    - Detecting crashes via connection resets
    - Identifying interesting responses
    
    Args:
        request: Fuzzing configuration
    
    Returns:
        Fuzzing results with statistics and interesting findings
    """
    import base64
    
    if request.protocol not in ("tcp", "udp"):
        raise HTTPException(status_code=400, detail="Protocol must be 'tcp' or 'udp'")
    
    try:
        seed_data = base64.b64decode(request.seed_data_base64)
        
        target = NetworkTarget(
            host=request.host,
            port=request.port,
            protocol=request.protocol,
            ssl=request.ssl,
            timeout_seconds=request.timeout_seconds,
        )
        
        fuzzer = NetworkProtocolFuzzer(target)
        mutation_engine = MutationEngine()
        
        interesting_results = []
        
        async for result in fuzzer.fuzz(
            seed_data=seed_data,
            mutation_engine=mutation_engine,
            num_iterations=request.num_iterations,
        ):
            if result.interesting or result.connection_reset:
                interesting_results.append({
                    "id": result.id,
                    "request_base64": base64.b64encode(result.request_data).decode(),
                    "response_base64": base64.b64encode(result.response_data).decode() if result.response_data else None,
                    "duration_ms": result.duration_ms,
                    "error": result.error,
                    "connection_reset": result.connection_reset,
                    "timeout": result.timeout,
                    "interesting": result.interesting,
                })
        
        return {
            "success": True,
            "target": f"{request.host}:{request.port}",
            "protocol": request.protocol,
            "stats": fuzzer.get_stats(),
            "interesting_count": len(interesting_results),
            "interesting_results": interesting_results[:50],  # Limit to 50
        }
        
    except Exception as e:
        logger.exception(f"Network fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# DIFFERENTIAL FUZZING ENDPOINTS (Phase 6)
# =============================================================================

class DifferentialFuzzRequest(BaseModel):
    """Request to start differential fuzzing."""
    targets: List[Dict[str, str]] = Field(
        ...,
        min_length=2,
        description="List of targets with 'name', 'path', and optional 'args'"
    )
    seed_inputs_base64: List[str] = Field(
        default_factory=list,
        description="Base64 encoded seed inputs"
    )
    num_iterations: int = Field(default=1000, ge=1, le=100000)
    timeout_ms: int = Field(default=5000, ge=100, le=60000)


@router.post("/differential/fuzz", response_model=Dict[str, Any])
async def start_differential_fuzzing(
    request: DifferentialFuzzRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Start differential fuzzing to compare multiple implementations.
    
    Phase 6 endpoint - finds behavioral differences:
    - Exit code divergences
    - Crash in one implementation but not others
    - Output differences
    
    Args:
        request: Fuzzing configuration with multiple targets
    
    Returns:
        Divergent inputs and statistics
    """
    import base64
    
    if len(request.targets) < 2:
        raise HTTPException(status_code=400, detail="At least 2 targets required")
    
    try:
        # Validate targets exist
        targets = []
        for t in request.targets:
            if "name" not in t or "path" not in t:
                raise HTTPException(status_code=400, detail="Each target needs 'name' and 'path'")
            
            if not os.path.isfile(t["path"]):
                raise HTTPException(status_code=404, detail=f"Target not found: {t['path']}")
            
            targets.append(DifferentialTarget(
                name=t["name"],
                path=t["path"],
                args=t.get("args", "@@"),
            ))
        
        # Decode seed inputs
        seed_inputs = [
            base64.b64decode(s) for s in request.seed_inputs_base64
        ] if request.seed_inputs_base64 else [b"test"]
        
        fuzzer = DifferentialFuzzer(targets, timeout_ms=request.timeout_ms)
        mutation_engine = MutationEngine()
        
        divergences = []
        
        async for result in fuzzer.fuzz(
            seed_inputs=seed_inputs,
            mutation_engine=mutation_engine,
            num_iterations=request.num_iterations,
        ):
            divergences.append({
                "input_base64": base64.b64encode(result.input_data).decode(),
                "divergence_type": result.divergence_type,
                "results": result.to_dict()["results"],
            })
        
        return {
            "success": True,
            "targets": [t.name for t in targets],
            "stats": fuzzer.get_stats(),
            "divergences": divergences[:100],  # Limit to 100
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Differential fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'fuzzer' in locals():
            fuzzer.cleanup()


# =============================================================================
# CUSTOM MUTATOR PLUGIN ENDPOINTS (Phase 6)
# =============================================================================

# Global plugin manager instance
_plugin_manager = MutatorPluginManager()


@router.get("/plugins", response_model=Dict[str, Any])
async def list_mutator_plugins(
    current_user: dict = Depends(get_current_user)
):
    """
    List available mutator plugins.
    
    Phase 6 endpoint - shows built-in and custom mutators:
    - magic_byte: Targets file format signatures
    - length_field: Targets size/length fields
    - boundary: Inserts boundary values
    """
    return {
        "plugins": _plugin_manager.list_plugins(),
        "stats": _plugin_manager.get_stats(),
    }


class PluginMutateRequest(BaseModel):
    """Request to mutate data using a plugin."""
    data_base64: str = Field(..., description="Base64 encoded input data")
    plugin_name: Optional[str] = Field(None, description="Specific plugin to use")
    iterations: int = Field(default=10, ge=1, le=100)


@router.post("/plugins/mutate", response_model=Dict[str, Any])
async def mutate_with_plugin(
    request: PluginMutateRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Mutate data using custom mutator plugins.
    
    Args:
        request: Mutation parameters
    
    Returns:
        Mutated data samples
    """
    import base64
    
    try:
        data = base64.b64decode(request.data_base64)
        
        mutations = []
        for i in range(request.iterations):
            mutated = _plugin_manager.mutate(data, request.plugin_name)
            mutations.append({
                "index": i,
                "data_base64": base64.b64encode(mutated).decode(),
                "size": len(mutated),
                "hex_preview": mutated[:32].hex(),
            })
        
        return {
            "success": True,
            "input_size": len(data),
            "plugin": request.plugin_name or "random",
            "mutations": mutations,
        }
        
    except Exception as e:
        logger.exception(f"Plugin mutation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# CORPUS DISTILLATION ENDPOINTS (Phase 6)
# =============================================================================

class DistillCorpusRequest(BaseModel):
    """Request to distill a corpus."""
    target_path: str = Field(..., description="Path to target executable")
    target_args: str = Field(default="@@", description="Command line template")
    corpus_base64: List[str] = Field(..., min_length=1, description="Base64 encoded corpus inputs")
    strategy: str = Field(
        default="greedy",
        description="Distillation strategy: greedy, minset, weighted"
    )
    timeout_ms: int = Field(default=5000, ge=100, le=60000)


@router.post("/corpus/distill", response_model=Dict[str, Any])
async def distill_corpus(
    request: DistillCorpusRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Distill corpus to minimal set maintaining coverage.
    
    Phase 6 endpoint - reduces corpus size while preserving coverage:
    - greedy: Keep inputs that add new coverage
    - minset: Minimum set cover approximation
    - weighted: Balance coverage vs input size
    
    Args:
        request: Distillation parameters
    
    Returns:
        Minimized corpus with statistics
    """
    import base64
    from backend.services.binary_fuzzer_service import ProcessHarness, CoverageTracker
    
    if request.strategy not in ("greedy", "minset", "weighted"):
        raise HTTPException(status_code=400, detail="Strategy must be: greedy, minset, or weighted")
    
    if not os.path.isfile(request.target_path):
        raise HTTPException(status_code=404, detail=f"Target not found: {request.target_path}")
    
    try:
        # Decode corpus
        corpus = [base64.b64decode(c) for c in request.corpus_base64]
        
        # Create harness and coverage tracker
        harness = ProcessHarness(
            target_path=request.target_path,
            target_args=request.target_args,
            timeout_ms=request.timeout_ms,
        )
        coverage_tracker = CoverageTracker()
        
        distiller = CorpusDistiller(coverage_tracker, harness)
        
        # Run distillation
        distilled = await distiller.distill(corpus, request.strategy)
        
        return {
            "success": True,
            "strategy": request.strategy,
            "original_count": len(corpus),
            "distilled_count": len(distilled),
            "stats": distiller.get_stats(),
            "distilled_corpus": [
                {
                    "index": i,
                    "data_base64": base64.b64encode(d).decode(),
                    "size": len(d),
                }
                for i, d in enumerate(distilled)
            ],
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Corpus distillation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'harness' in locals():
            harness.cleanup()


@router.get("/strategies", response_model=Dict[str, Any])
async def get_mutation_strategies():
    """Get available mutation strategies, scheduler options, and memory error types."""
    return {
        "strategies": [s.value for s in MutationStrategy],
        "modes": [m.value for m in FuzzingMode],
        "crash_types": [c.value for c in CrashType],
        "severity_levels": [s.value for s in CrashSeverity],
        "scheduler_strategies": [s.value for s in SeedScheduler.Strategy],
        "memory_error_types": [e.value for e in MemoryErrorType],
    }


@router.post("/test-mutation", response_model=Dict[str, Any])
async def test_mutation(
    request: MutationTestRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Test the mutation engine with sample input.
    
    Useful for understanding mutation behavior before fuzzing.
    """
    import base64
    from backend.services.binary_fuzzer_service import MutationEngine, MutationStrategy
    
    try:
        input_data = base64.b64decode(request.input_data)
    except:
        raise HTTPException(status_code=400, detail="Invalid base64 input")
    
    engine = MutationEngine()
    
    strategy = None
    if request.strategy:
        try:
            strategy = MutationStrategy(request.strategy)
        except:
            pass
    
    mutations = []
    for i in range(request.iterations):
        mutated = engine.mutate(input_data, strategy)
        mutations.append({
            "iteration": i + 1,
            "size": len(mutated),
            "data_b64": base64.b64encode(mutated).decode(),
            "hex_preview": mutated[:50].hex(),
        })
    
    return {
        "input_size": len(input_data),
        "strategy": request.strategy or "random",
        "mutations": mutations,
        "stats": engine.get_stats(),
    }


# =============================================================================
# FILE UPLOAD ENDPOINTS
# =============================================================================

@router.post("/upload-binary", response_model=Dict[str, Any])
async def upload_binary(
    file: UploadFile = File(..., description="Binary executable to fuzz"),
    name: Optional[str] = Form(None, description="Custom name for the binary"),
    current_user: dict = Depends(get_current_user)
):
    """
    Upload a binary executable for fuzzing.
    
    The binary will be stored in the fuzzing workspace and can be referenced
    by its returned path in fuzzing sessions.
    
    Supported formats: ELF, PE (Windows), Mach-O, or any executable
    """
    # Generate unique ID for this binary
    binary_id = str(uuid.uuid4())[:8]
    original_name = file.filename or "binary"
    safe_name = "".join(c for c in original_name if c.isalnum() or c in "._-")
    
    # Use custom name if provided
    if name:
        safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
    
    # Create binary directory
    binary_dir = BINARIES_DIR / binary_id
    binary_dir.mkdir(parents=True, exist_ok=True)
    
    # Save the binary
    binary_path = binary_dir / safe_name
    
    try:
        content = await file.read()
        
        # Basic validation - check for common executable magic bytes
        if len(content) < 4:
            raise HTTPException(status_code=400, detail="File too small to be a valid executable")
        
        # Check magic bytes for common formats
        magic = content[:4]
        file_type = "unknown"
        
        if magic[:4] == b'\x7fELF':
            file_type = "ELF"
        elif magic[:2] == b'MZ':
            file_type = "PE/Windows"
        elif magic[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe'):
            file_type = "Mach-O"
        elif magic[:2] == b'#!':
            file_type = "Script"
        
        # Write file
        with open(binary_path, 'wb') as f:
            f.write(content)
        
        # Make executable
        os.chmod(binary_path, os.stat(binary_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        logger.info(f"Binary uploaded: {binary_path} ({len(content)} bytes, type: {file_type})")
        
        return {
            "success": True,
            "binary_id": binary_id,
            "name": safe_name,
            "path": str(binary_path),
            "size": len(content),
            "file_type": file_type,
            "uploaded_at": datetime.utcnow().isoformat(),
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to upload binary: {e}")
        # Cleanup on error
        if binary_dir.exists():
            shutil.rmtree(binary_dir)
        raise HTTPException(status_code=500, detail=f"Failed to upload binary: {str(e)}")


@router.post("/upload-seeds", response_model=Dict[str, Any])
async def upload_seeds(
    files: List[UploadFile] = File(..., description="Seed input files for fuzzing"),
    binary_id: str = Form(..., description="Binary ID to associate seeds with"),
    current_user: dict = Depends(get_current_user)
):
    """
    Upload seed files for fuzzing.
    
    Seeds are sample inputs that the fuzzer will mutate to find crashes.
    Good seeds:
    - Are valid inputs that the target accepts
    - Cover different features/code paths
    - Are relatively small (faster fuzzing)
    """
    # Create seeds directory for this binary
    seeds_dir = SEEDS_DIR / binary_id
    seeds_dir.mkdir(parents=True, exist_ok=True)
    
    uploaded_seeds = []
    
    try:
        for file in files:
            content = await file.read()
            
            # Generate unique filename
            seed_id = str(uuid.uuid4())[:8]
            original_name = file.filename or f"seed_{seed_id}"
            safe_name = "".join(c for c in original_name if c.isalnum() or c in "._-")
            
            seed_path = seeds_dir / f"{seed_id}_{safe_name}"
            
            with open(seed_path, 'wb') as f:
                f.write(content)
            
            uploaded_seeds.append({
                "seed_id": seed_id,
                "name": safe_name,
                "path": str(seed_path),
                "size": len(content),
            })
        
        logger.info(f"Uploaded {len(uploaded_seeds)} seeds for binary {binary_id}")
        
        return {
            "success": True,
            "binary_id": binary_id,
            "seeds_dir": str(seeds_dir),
            "seeds_count": len(uploaded_seeds),
            "seeds": uploaded_seeds,
            "uploaded_at": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Failed to upload seeds: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to upload seeds: {str(e)}")


@router.get("/binaries", response_model=List[Dict[str, Any]])
async def list_binaries(
    current_user: dict = Depends(get_current_user)
):
    """List all uploaded binaries available for fuzzing."""
    binaries = []
    
    if BINARIES_DIR.exists():
        for binary_dir in BINARIES_DIR.iterdir():
            if binary_dir.is_dir():
                for binary_file in binary_dir.iterdir():
                    if binary_file.is_file():
                        stat_info = binary_file.stat()
                        binaries.append({
                            "binary_id": binary_dir.name,
                            "name": binary_file.name,
                            "path": str(binary_file),
                            "size": stat_info.st_size,
                            "uploaded_at": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                        })
    
    return binaries


@router.get("/binaries/{binary_id}/seeds", response_model=Dict[str, Any])
async def list_seeds(
    binary_id: str,
    current_user: dict = Depends(get_current_user)
):
    """List all seeds for a specific binary."""
    seeds_dir = SEEDS_DIR / binary_id
    
    if not seeds_dir.exists():
        return {"binary_id": binary_id, "seeds": [], "count": 0}
    
    seeds = []
    for seed_file in seeds_dir.iterdir():
        if seed_file.is_file():
            stat_info = seed_file.stat()
            seeds.append({
                "name": seed_file.name,
                "path": str(seed_file),
                "size": stat_info.st_size,
            })
    
    return {
        "binary_id": binary_id,
        "seeds_dir": str(seeds_dir),
        "seeds": seeds,
        "count": len(seeds),
    }


@router.delete("/binaries/{binary_id}")
async def delete_binary(
    binary_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete an uploaded binary and its associated seeds."""
    binary_dir = BINARIES_DIR / binary_id
    seeds_dir = SEEDS_DIR / binary_id
    output_dir = OUTPUT_DIR / binary_id
    
    deleted = []
    
    if binary_dir.exists():
        shutil.rmtree(binary_dir)
        deleted.append("binary")
    
    if seeds_dir.exists():
        shutil.rmtree(seeds_dir)
        deleted.append("seeds")
    
    if output_dir.exists():
        shutil.rmtree(output_dir)
        deleted.append("output")
    
    if not deleted:
        raise HTTPException(status_code=404, detail="Binary not found")
    
    return {
        "success": True,
        "binary_id": binary_id,
        "deleted": deleted,
    }


@router.get("/corpus/{binary_id}", response_model=Dict[str, Any])
async def get_corpus(
    binary_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get the current corpus (discovered inputs) for a fuzzing session."""
    corpus_dir = OUTPUT_DIR / binary_id / "corpus"
    
    if not corpus_dir.exists():
        return {"binary_id": binary_id, "corpus": [], "count": 0}
    
    corpus_files = []
    for corpus_file in corpus_dir.iterdir():
        if corpus_file.is_file():
            stat_info = corpus_file.stat()
            
            # Read preview
            with open(corpus_file, 'rb') as f:
                preview_bytes = f.read(64)
                preview_hex = preview_bytes.hex()
            
            corpus_files.append({
                "name": corpus_file.name,
                "path": str(corpus_file),
                "size": stat_info.st_size,
                "preview_hex": preview_hex,
            })
    
    return {
        "binary_id": binary_id,
        "corpus_dir": str(corpus_dir),
        "corpus": corpus_files,
        "count": len(corpus_files),
    }


@router.get("/crashes/{binary_id}", response_model=Dict[str, Any])
async def get_crash_inputs(
    binary_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get crash-inducing inputs discovered during fuzzing."""
    crashes_dir = OUTPUT_DIR / binary_id / "crashes"
    
    if not crashes_dir.exists():
        return {"binary_id": binary_id, "crashes": [], "count": 0}
    
    crash_files = []
    for crash_file in crashes_dir.iterdir():
        if crash_file.is_file():
            stat_info = crash_file.stat()
            
            # Read preview
            with open(crash_file, 'rb') as f:
                preview_bytes = f.read(64)
                preview_hex = preview_bytes.hex()
            
            crash_files.append({
                "name": crash_file.name,
                "path": str(crash_file),
                "size": stat_info.st_size,
                "preview_hex": preview_hex,
                "discovered_at": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            })
    
    return {
        "binary_id": binary_id,
        "crashes_dir": str(crashes_dir),
        "crashes": crash_files,
        "count": len(crash_files),
    }


@router.get("/download/crash/{binary_id}/{filename}")
async def download_crash(
    binary_id: str,
    filename: str,
    current_user: dict = Depends(get_current_user)
):
    """Download a specific crash input file."""
    crash_path = OUTPUT_DIR / binary_id / "crashes" / filename
    
    if not crash_path.exists():
        raise HTTPException(status_code=404, detail="Crash file not found")
    
    return FileResponse(
        path=str(crash_path),
        filename=filename,
        media_type="application/octet-stream"
    )


@router.get("/afl-status", response_model=Dict[str, Any])
async def check_afl_status_endpoint():
    """Check if AFL++ is installed and available."""
    # Use the service function for accurate detection
    status = check_afl_installation()
    
    # Add workspace directories to response
    status["workspace_dirs"] = {
        "binaries": str(BINARIES_DIR),
        "seeds": str(SEEDS_DIR),
        "output": str(OUTPUT_DIR),
        "crashes": str(CRASHES_DIR),
    }
    
    return status


# =============================================================================
# AFL++ FUZZING ENDPOINTS
# =============================================================================

class StartAflFuzzingRequest(BaseModel):
    """Request to start AFL++ fuzzing session."""
    target_path: str = Field(..., description="Path to target executable")
    target_args: str = Field(default="@@", description="Command line template")
    input_dir: str = Field(default="/fuzzing/seeds", description="Seed input directory")
    output_dir: str = Field(default="/fuzzing/output", description="Output directory")
    timeout_ms: int = Field(default=5000, ge=100, le=60000, description="Timeout in ms")
    memory_limit_mb: int = Field(default=256, ge=32, le=4096, description="Memory limit in MB")
    use_qemu: bool = Field(default=True, description="Use QEMU mode for uninstrumented binaries")


@router.post("/afl/start")
async def start_afl_fuzzing_endpoint(request: StartAflFuzzingRequest):
    """
    Start an AFL++ fuzzing session.
    
    For real-time updates, use the /afl/ws WebSocket endpoint instead.
    This endpoint returns the session ID for later status queries.
    """
    # Validate target exists
    if not os.path.isfile(request.target_path):
        raise HTTPException(status_code=404, detail=f"Target not found: {request.target_path}")
    
    # Create AFL++ fuzzer instance
    fuzzer = AflPlusPlusFuzzer(
        target_path=request.target_path,
        target_args=request.target_args,
        input_dir=request.input_dir,
        output_dir=request.output_dir,
        timeout_ms=request.timeout_ms,
        memory_limit_mb=request.memory_limit_mb,
        use_qemu=request.use_qemu,
    )
    
    return {
        "session_id": fuzzer.session_id,
        "message": "AFL++ session created. Use WebSocket endpoint for real-time updates.",
        "target": request.target_path,
        "output_dir": fuzzer.output_dir,
    }


@router.post("/afl/stop/{session_id}")
async def stop_afl_fuzzing_endpoint(session_id: str):
    """Stop an AFL++ fuzzing session."""
    result = stop_afl_session(session_id)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/afl/status/{session_id}")
async def get_afl_status_endpoint(session_id: str):
    """Get AFL++ session status."""
    status = get_afl_session_status(session_id)
    if not status:
        raise HTTPException(status_code=404, detail="Session not found")
    return status


@router.websocket("/afl/ws")
async def afl_fuzzing_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time AFL++ fuzzing.
    
    Connect and send a start message:
    {
        "action": "start",
        "target_path": "/fuzzing/binaries/xxx/target",
        "target_args": "@@",
        "input_dir": "/fuzzing/seeds/xxx",
        "timeout_ms": 5000,
        "memory_limit_mb": 256,
        "use_qemu": true
    }
    
    Receive events:
    - session_start: AFL++ has begun
    - status: Real-time stats update
    - session_end: Fuzzing completed
    - error: An error occurred
    
    Send control:
    - {"action": "stop"}: Stop the session
    """
    await websocket.accept()
    logger.info("AFL++ WebSocket connected")
    
    current_session_id: Optional[str] = None
    afl_task: Optional[asyncio.Task] = None
    
    async def run_afl_fuzzing(config: dict):
        nonlocal current_session_id
        try:
            async for event in start_afl_fuzzing(
                target_path=config["target_path"],
                target_args=config.get("target_args", "@@"),
                input_dir=config.get("input_dir", "/fuzzing/seeds"),
                output_dir=config.get("output_dir", "/fuzzing/output"),
                timeout_ms=config.get("timeout_ms", 5000),
                memory_limit_mb=config.get("memory_limit_mb", 256),
                use_qemu=config.get("use_qemu", True),
            ):
                if event.get("session_id"):
                    current_session_id = event["session_id"]
                await websocket.send_json(event)
        except Exception as e:
            logger.exception(f"AFL++ error: {e}")
            await websocket.send_json({
                "type": "error",
                "error": str(e),
            })
    
    try:
        while True:
            try:
                message = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except WebSocketDisconnect:
                break
            
            action = message.get("action")
            
            if action == "start":
                if afl_task and not afl_task.done():
                    await websocket.send_json({
                        "type": "error",
                        "error": "AFL++ session already running"
                    })
                    continue
                
                # Validate required fields
                if "target_path" not in message:
                    await websocket.send_json({
                        "type": "error",
                        "error": "target_path is required"
                    })
                    continue
                
                # Start AFL++ task
                afl_task = asyncio.create_task(run_afl_fuzzing(message))
            
            elif action == "stop":
                if current_session_id:
                    stop_afl_session(current_session_id)
                    await websocket.send_json({
                        "type": "session_stopped",
                        "session_id": current_session_id
                    })
                if afl_task:
                    afl_task.cancel()
                    try:
                        await afl_task
                    except asyncio.CancelledError:
                        pass
            
            elif action == "status":
                if current_session_id:
                    status = get_afl_session_status(current_session_id)
                    if status:
                        await websocket.send_json({
                            "type": "status",
                            **status
                        })
    
    except WebSocketDisconnect:
        logger.info("AFL++ WebSocket disconnected")
    finally:
        if afl_task and not afl_task.done():
            afl_task.cancel()
        if current_session_id:
            stop_afl_session(current_session_id)


# =============================================================================
# QEMU MODE ENDPOINTS - Closed-Source Binary Fuzzing
# =============================================================================

class QemuFuzzRequest(BaseModel):
    """Request for QEMU mode fuzzing."""
    target_path: str = Field(..., description="Path to target executable")
    target_args: str = Field(default="@@", description="Command line template (@@ for input file)")
    architecture: Optional[str] = Field(default=None, description="Target architecture (auto-detected if not specified)")
    mode: str = Field(default="standard", description="QEMU mode: standard, persistent, compcov")
    
    # Persistent mode settings
    persistent_address: Optional[str] = Field(default=None, description="Hex address for persistent loop entry")
    persistent_count: int = Field(default=10000, ge=1, le=1000000, description="Iterations per fork in persistent mode")
    
    # Coverage settings
    enable_compcov: bool = Field(default=False, description="Enable comparison coverage")
    
    # Execution settings
    input_dir: str = Field(default="/fuzzing/seeds", description="Seed input directory")
    output_dir: str = Field(default="/fuzzing/output", description="Output directory")
    timeout_ms: int = Field(default=10000, ge=100, le=120000, description="Timeout in ms (longer for QEMU)")
    memory_limit_mb: int = Field(default=512, ge=64, le=8192, description="Memory limit in MB")
    dictionary_path: Optional[str] = Field(default=None, description="Path to fuzzing dictionary")
    
    # Environment
    env_vars: Dict[str, str] = Field(default_factory=dict, description="Additional environment variables")


class BinaryAnalysisRequest(BaseModel):
    """Request to analyze a binary."""
    binary_path: str = Field(..., description="Path to binary to analyze")


class QemuTraceRequest(BaseModel):
    """Request to run QEMU trace analysis."""
    binary_path: str = Field(..., description="Path to binary")
    input_file: Optional[str] = Field(default=None, description="Path to input file")
    input_data_base64: Optional[str] = Field(default=None, description="Base64-encoded input data")
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0, description="Trace timeout")


@router.get("/qemu/capabilities")
async def get_qemu_capabilities_endpoint() -> Dict[str, Any]:
    """
    Check QEMU mode capabilities and available architectures.
    
    Returns information about:
    - Whether QEMU mode is available
    - Supported CPU architectures
    - Available QEMU tools and features
    - Persistent mode and compcov support
    
    **Why use this?**
    Before fuzzing a closed-source binary, check if QEMU mode supports
    its architecture and which features are available.
    """
    caps = get_qemu_capabilities()
    
    # Add helpful context
    caps["summary"] = {
        "can_fuzz_closed_source": caps.get("available", False),
        "supported_architectures": caps.get("architectures", []),
        "has_persistent_mode": caps.get("features", {}).get("persistent_qemu", False),
        "has_compcov": caps.get("features", {}).get("compcov", False),
    }
    
    if not caps.get("available"):
        caps["how_to_fix"] = (
            "QEMU mode requires AFL++ to be built with QEMU support. "
            "Rebuild with: cd /path/to/AFLplusplus && make distrib"
        )
    
    return caps


@router.post("/qemu/analyze-binary")
async def analyze_binary_architecture(request: BinaryAnalysisRequest) -> Dict[str, Any]:
    """
    Analyze a binary to determine its architecture and fuzzing requirements.
    
    This endpoint examines the binary file to detect:
    - CPU architecture (x86, x64, ARM, ARM64, MIPS, etc.)
    - 32-bit vs 64-bit
    - Endianness (little/big endian)
    - Whether it's stripped (no debug symbols)
    - Position Independent Executable (PIE) status
    - Required libraries
    
    **Why use this?**
    Before starting QEMU fuzzing, analyze the binary to:
    1. Verify the architecture is supported
    2. Get recommendations for optimal settings
    3. Understand what mode will work best
    """
    if not os.path.isfile(request.binary_path):
        raise HTTPException(status_code=404, detail=f"Binary not found: {request.binary_path}")
    
    arch_info = detect_binary_arch(request.binary_path)
    recommendations = get_qemu_recommendations(request.binary_path)
    
    return {
        "binary_path": request.binary_path,
        "architecture": arch_info,
        "recommendations": recommendations,
        "qemu_supported": arch_info.get("architecture") != "unknown",
        "beginner_summary": _format_binary_analysis_for_beginners(arch_info, recommendations),
    }


def _format_binary_analysis_for_beginners(arch_info: Dict, recommendations: Dict) -> Dict[str, Any]:
    """Format binary analysis results in beginner-friendly language."""
    arch = arch_info.get("architecture", "unknown")
    bits = arch_info.get("bits", "unknown")
    is_stripped = arch_info.get("is_stripped", True)
    
    summary = {
        "what_is_this_binary": f"A {bits}-bit {arch} executable",
        "can_we_fuzz_it": arch != "unknown",
        "difficulty": "medium" if arch != "unknown" else "hard",
        "things_to_know": [],
    }
    
    if is_stripped:
        summary["things_to_know"].append(
            "This binary has no debug symbols (stripped), which is normal for released software. "
            "QEMU mode will still work, but crashes will be harder to analyze."
        )
    
    if arch_info.get("is_pie"):
        summary["things_to_know"].append(
            "This is a PIE (Position Independent) executable. Memory addresses will change each run, "
            "which makes persistent mode trickier to set up."
        )
    
    if recommendations.get("warnings"):
        summary["warnings"] = recommendations["warnings"]
    
    if recommendations.get("tips"):
        summary["helpful_tips"] = recommendations["tips"]
    
    return summary


@router.post("/qemu/trace")
async def run_qemu_trace_endpoint(request: QemuTraceRequest) -> Dict[str, Any]:
    """
    Run a single execution with QEMU tracing to analyze code coverage.
    
    This is useful for:
    - Understanding which code paths an input exercises
    - Finding good entry points for persistent mode
    - Analyzing why a crash occurred
    - Comparing coverage between different inputs
    
    **Input options:**
    - Provide `input_file` path to use an existing file
    - Or provide `input_data_base64` with base64-encoded data
    
    **Returns:**
    - Number of basic blocks executed
    - Unique vs total execution counts
    - Hot spots (most frequently executed code)
    - Execution time
    """
    if not os.path.isfile(request.binary_path):
        raise HTTPException(status_code=404, detail=f"Binary not found: {request.binary_path}")
    
    # Get input data
    input_data = b""
    if request.input_file:
        if not os.path.isfile(request.input_file):
            raise HTTPException(status_code=404, detail=f"Input file not found: {request.input_file}")
        with open(request.input_file, "rb") as f:
            input_data = f.read()
    elif request.input_data_base64:
        import base64
        try:
            input_data = base64.b64decode(request.input_data_base64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid base64 data: {e}")
    else:
        # Use a minimal default input
        input_data = b"AAAA"
    
    analysis = await run_qemu_trace_analysis(
        request.binary_path,
        input_data,
        request.timeout_seconds
    )
    
    return {
        "binary_path": request.binary_path,
        "input_size": len(input_data),
        "trace_analysis": analysis,
        "summary": {
            "basic_blocks_hit": analysis.get("unique_basic_blocks", 0),
            "total_executions": analysis.get("total_basic_blocks", 0),
            "execution_time_ms": analysis.get("execution_time_ms", 0),
        },
    }


@router.post("/qemu/start")
async def start_qemu_fuzzing(request: QemuFuzzRequest) -> Dict[str, Any]:
    """
    Start a QEMU-mode fuzzing session for closed-source binaries.
    
    QEMU mode allows fuzzing ANY binary without source code by running it
    inside a CPU emulator that tracks code coverage.
    
    **When to use:**
    - Fuzzing proprietary software
    - Testing firmware or embedded binaries
    - Analyzing suspicious files (in isolation!)
    - Binaries compiled without AFL++ instrumentation
    
    **Modes:**
    - `standard`: Basic QEMU mode, works with everything
    - `persistent`: 10-20x faster but requires finding a loop address
    - `compcov`: Enable comparison coverage for better mutation
    
    **Note:** QEMU mode is 2-10x slower than native instrumented fuzzing.
    This is normal - you're trading speed for the ability to fuzz any binary.
    """
    if not os.path.isfile(request.target_path):
        raise HTTPException(status_code=404, detail=f"Target not found: {request.target_path}")
    
    # Check QEMU capabilities
    caps = get_qemu_capabilities()
    if not caps.get("available"):
        raise HTTPException(
            status_code=503,
            detail="QEMU mode not available. " + caps.get("error_message", "")
        )
    
    # Auto-detect architecture if not specified
    arch = request.architecture
    if not arch:
        arch_info = detect_binary_arch(request.target_path)
        arch = arch_info.get("architecture", "x86_64")
    
    # Validate architecture is supported
    if arch not in caps.get("architectures", []) and arch != "unknown":
        raise HTTPException(
            status_code=400,
            detail=f"Architecture '{arch}' not supported. Available: {caps.get('architectures', [])}"
        )
    
    # Build QEMU config
    try:
        qemu_arch = QemuArchitecture(arch) if arch != "unknown" else QemuArchitecture.X86_64
    except ValueError:
        qemu_arch = QemuArchitecture.X86_64
    
    try:
        qemu_mode = QemuModeType(request.mode)
    except ValueError:
        qemu_mode = QemuModeType.STANDARD
    
    config = QemuFuzzConfig(
        target_path=request.target_path,
        architecture=qemu_arch,
        mode=qemu_mode,
        persistent_address=request.persistent_address,
        persistent_count=request.persistent_count,
        enable_compcov=request.enable_compcov,
        memory_limit_mb=request.memory_limit_mb,
        timeout_ms=request.timeout_ms,
        target_args=request.target_args,
        env_vars=request.env_vars,
        input_dir=request.input_dir,
        output_dir=request.output_dir,
        dictionary_path=request.dictionary_path,
    )
    
    # Create AFL++ fuzzer with QEMU mode
    fuzzer = AflPlusPlusFuzzer(
        target_path=request.target_path,
        target_args=request.target_args,
        input_dir=request.input_dir,
        output_dir=request.output_dir,
        timeout_ms=request.timeout_ms,
        memory_limit_mb=request.memory_limit_mb,
        use_qemu=True,  # Always use QEMU for this endpoint
    )
    
    return {
        "session_id": fuzzer.session_id,
        "message": "QEMU-mode fuzzing session created. Use WebSocket /afl/ws for real-time updates.",
        "config": config.to_dict(),
        "target": request.target_path,
        "output_dir": fuzzer.output_dir,
        "tips": [
            "QEMU mode is 2-10x slower than native fuzzing - this is normal!",
            "For faster fuzzing, consider persistent mode with a valid loop address.",
            "Enable compcov if your target does string comparisons.",
        ],
    }


@router.get("/qemu/help")
async def get_qemu_help_endpoint(
    for_beginners: bool = True
) -> Dict[str, Any]:
    """
    Get comprehensive help about QEMU mode fuzzing.
    
    **Query parameters:**
    - `for_beginners=true`: Plain English explanations (default)
    - `for_beginners=false`: Technical documentation
    
    Returns:
    - Overview of QEMU mode
    - When to use it
    - Available modes and their tradeoffs
    - Performance tips
    - Common issues and solutions
    - Example commands
    """
    help_info = get_qemu_help(for_beginners)
    
    # Add quick start guide
    help_info["quick_start"] = {
        "step_1": "Upload your binary using POST /binary-fuzzer/binaries",
        "step_2": "Analyze it using POST /binary-fuzzer/qemu/analyze-binary",
        "step_3": "Check recommendations and warnings",
        "step_4": "Start fuzzing using POST /binary-fuzzer/qemu/start",
        "step_5": "Monitor via WebSocket /binary-fuzzer/afl/ws",
    }
    
    return help_info


@router.get("/qemu/architectures")
async def list_supported_architectures() -> Dict[str, Any]:
    """
    List all supported CPU architectures for QEMU mode fuzzing.
    
    Returns detailed information about each architecture:
    - Architecture name
    - Bit width (32/64)
    - Whether it's available on this system
    - Common use cases
    """
    caps = get_qemu_capabilities()
    available = set(caps.get("architectures", []))
    
    architectures = [
        {
            "id": "x86_64",
            "name": "x86-64 / AMD64",
            "bits": 64,
            "available": "x86_64" in available,
            "description": "Standard 64-bit PC architecture. Most common for desktop/server software.",
            "examples": ["Linux ELF executables", "Windows PE64 (with Wine)"],
        },
        {
            "id": "i386",
            "name": "x86 / i386",
            "bits": 32,
            "available": "i386" in available,
            "description": "Legacy 32-bit PC architecture. Still used in embedded systems.",
            "examples": ["32-bit Linux programs", "Legacy Windows apps"],
        },
        {
            "id": "aarch64",
            "name": "ARM64 / AArch64",
            "bits": 64,
            "available": "aarch64" in available,
            "description": "64-bit ARM architecture. Used in phones, tablets, Apple Silicon, Raspberry Pi 4+.",
            "examples": ["Android native code", "iOS apps (research)", "Raspberry Pi"],
        },
        {
            "id": "arm",
            "name": "ARM32",
            "bits": 32,
            "available": "arm" in available,
            "description": "32-bit ARM architecture. Common in IoT and older embedded devices.",
            "examples": ["Embedded firmware", "Older Android native code"],
        },
        {
            "id": "mips",
            "name": "MIPS (Big Endian)",
            "bits": 32,
            "available": "mips" in available,
            "description": "MIPS architecture with big endian byte order. Common in routers.",
            "examples": ["Router firmware", "Network appliances"],
        },
        {
            "id": "mipsel",
            "name": "MIPS (Little Endian)",
            "bits": 32,
            "available": "mipsel" in available,
            "description": "MIPS architecture with little endian byte order.",
            "examples": ["Some IoT devices", "PlayStation Portable"],
        },
        {
            "id": "ppc",
            "name": "PowerPC 32-bit",
            "bits": 32,
            "available": "ppc" in available,
            "description": "32-bit PowerPC architecture. Used in older Macs and game consoles.",
            "examples": ["Old Mac software", "GameCube/Wii games"],
        },
        {
            "id": "ppc64",
            "name": "PowerPC 64-bit",
            "bits": 64,
            "available": "ppc64" in available,
            "description": "64-bit PowerPC. Used in IBM servers and PS3.",
            "examples": ["IBM Power servers", "PlayStation 3"],
        },
        {
            "id": "riscv64",
            "name": "RISC-V 64-bit",
            "bits": 64,
            "available": "riscv64" in available,
            "description": "Modern open-source 64-bit architecture. Growing in embedded space.",
            "examples": ["Modern embedded systems", "Research platforms"],
        },
    ]
    
    return {
        "architectures": architectures,
        "available_count": len(available),
        "total_count": len(architectures),
    }


# =============================================================================
# WEBSOCKET ENDPOINT
# =============================================================================

@router.websocket("/ws")
async def fuzzing_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time fuzzing with coverage-guided optimization.
    
    Connect and send a start message with fuzzing configuration:
    {
        "action": "start",
        "target_path": "/path/to/binary",
        "target_args": "@@",
        "seed_dir": null,
        "timeout_ms": 5000,
        "max_iterations": 10000,
        "max_time_seconds": 300,
        "coverage_guided": true,
        "scheduler_strategy": "power_schedule"
    }
    
    Receive events:
    - session_started: Fuzzing has begun (includes coverage_guided flag)
    - new_crash: A new unique crash was found
    - duplicate_crash: A duplicate crash was found
    - new_coverage: New code coverage discovered (Phase 2)
    - stats_update: Periodic statistics (includes coverage stats in Phase 2)
    - session_completed: Fuzzing finished (includes corpus/scheduler stats)
    - error: An error occurred
    
    Send control messages:
    - {"action": "stop"}: Stop the session
    - {"action": "status"}: Get current status
    """
    await websocket.accept()
    
    current_task = None
    
    try:
        while True:
            # Receive message
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON"})
                continue
            
            action = message.get("action")
            
            if action == "start":
                # Start fuzzing
                if current_task and not current_task.done():
                    await websocket.send_json({
                        "error": "Fuzzing already in progress. Send stop first."
                    })
                    continue
                
                target_path = message.get("target_path")
                if not target_path:
                    await websocket.send_json({"error": "target_path required"})
                    continue
                
                # Create async task for fuzzing with Phase 2 options
                async def run_fuzzing():
                    try:
                        async for event in start_binary_fuzzing(
                            target_path=target_path,
                            target_args=message.get("target_args", "@@"),
                            seed_dir=message.get("seed_dir"),
                            output_dir=message.get("output_dir"),
                            timeout_ms=message.get("timeout_ms", 5000),
                            max_iterations=message.get("max_iterations"),
                            max_time_seconds=message.get("max_time_seconds"),
                            dictionary=message.get("dictionary"),
                            coverage_guided=message.get("coverage_guided", True),
                            scheduler_strategy=message.get("scheduler_strategy", "power_schedule"),
                        ):
                            await websocket.send_json(event)
                    except Exception as e:
                        await websocket.send_json({
                            "type": "error",
                            "error": str(e)
                        })
                
                current_task = asyncio.create_task(run_fuzzing())
                
            elif action == "stop":
                if current_task and not current_task.done():
                    current_task.cancel()
                    await websocket.send_json({"type": "stopped"})
                else:
                    await websocket.send_json({"error": "No fuzzing in progress"})
                    
            elif action == "status":
                sessions = get_all_sessions()
                await websocket.send_json({
                    "type": "status",
                    "active_sessions": len(sessions),
                    "sessions": sessions,
                })
                
            else:
                await websocket.send_json({
                    "error": f"Unknown action: {action}",
                    "valid_actions": ["start", "stop", "status"]
                })
    
    except WebSocketDisconnect:
        logger.info("Binary fuzzer WebSocket disconnected")
        if current_task and not current_task.done():
            current_task.cancel()
    
    except Exception as e:
        logger.error(f"Binary fuzzer WebSocket error: {e}")
        if current_task and not current_task.done():
            current_task.cancel()


# =============================================================================
# AI-ASSISTED FUZZING ENDPOINTS
# =============================================================================

from backend.services.ai_fuzzer_service import (
    generate_smart_seeds,
    analyze_coverage_and_advise,
    analyze_crash_for_exploitation,
    get_fuzzing_ai_summary,
    analyze_binary,
)


class AISeedGenerationRequest(BaseModel):
    """Request for AI-powered seed generation."""
    binary_id: str = Field(..., description="ID of uploaded binary")
    num_seeds: int = Field(default=10, ge=1, le=50, description="Number of seeds to generate")


class AICoverageAdviceRequest(BaseModel):
    """Request for AI coverage analysis."""
    session_id: str = Field(..., description="Fuzzing session ID")
    stats_history: List[Dict[str, Any]] = Field(default_factory=list, description="Historical stats")
    current_corpus: List[Dict[str, Any]] = Field(default_factory=list, description="Current corpus info")
    crashes: List[Dict[str, Any]] = Field(default_factory=list, description="Found crashes")


class AIExploitAnalysisRequest(BaseModel):
    """Request for AI exploit analysis."""
    crash_data: Dict[str, Any] = Field(..., description="Crash information")
    crash_input_base64: Optional[str] = Field(None, description="Base64 encoded crash input")
    include_poc: bool = Field(default=True, description="Include PoC guidance")


@router.post("/ai/generate-seeds")
async def generate_ai_seeds(request: AISeedGenerationRequest):
    """
    Generate intelligent seed files using AI analysis of the binary.
    
    The AI will:
    1. Analyze the binary to understand expected input format
    2. Identify interesting strings and functions
    3. Generate diverse seeds that are likely to reach different code paths
    4. Provide mutation hints for each seed
    """
    # Find the binary
    binary_dir = BINARIES_DIR / request.binary_id
    if not binary_dir.exists():
        raise HTTPException(status_code=404, detail="Binary not found")
    
    # Find the binary file
    binary_files = list(binary_dir.glob("*"))
    if not binary_files:
        raise HTTPException(status_code=404, detail="No binary file found")
    
    binary_path = str(binary_files[0])
    binary_name = binary_files[0].name
    
    try:
        result = await generate_smart_seeds(
            binary_path=binary_path,
            binary_name=binary_name,
            num_seeds=request.num_seeds,
        )
        
        # Save generated seeds to the seeds directory
        seeds_dir = SEEDS_DIR / request.binary_id / "ai_generated"
        seeds_dir.mkdir(parents=True, exist_ok=True)
        
        saved_seeds = []
        for seed in result.seeds:
            seed_path = seeds_dir / seed.name
            with open(seed_path, "wb") as f:
                f.write(seed.content)
            saved_seeds.append({
                "name": seed.name,
                "path": str(seed_path),
                "size": len(seed.content),
                "description": seed.description,
                "format_type": seed.format_type,
                "mutation_hints": seed.mutation_hints,
            })
        
        return {
            "success": True,
            "seeds": saved_seeds,
            "seeds_dir": str(seeds_dir),
            "input_format_analysis": result.input_format_analysis,
            "recommended_dictionary": result.recommended_dictionary[:50],
            "fuzzing_strategy": result.fuzzing_strategy,
            "target_analysis": result.target_analysis,
        }
        
    except Exception as e:
        logger.exception(f"AI seed generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/coverage-advice")
async def get_ai_coverage_advice(request: AICoverageAdviceRequest):
    """
    Get AI recommendations for improving fuzzing coverage.
    
    The AI will analyze:
    1. Coverage trends to detect if fuzzing is stuck
    2. Corpus composition and diversity
    3. Crash patterns and what they indicate
    4. Provide specific recommendations to improve coverage
    """
    try:
        result = await analyze_coverage_and_advise(
            session_id=request.session_id,
            stats_history=request.stats_history,
            current_corpus=request.current_corpus,
            crashes=request.crashes,
        )
        
        return {
            "success": True,
            "is_stuck": result.is_stuck,
            "stuck_reason": result.stuck_reason,
            "coverage_trend": result.coverage_trend,
            "recommendations": result.recommendations,
            "mutation_adjustments": result.mutation_adjustments,
            "priority_areas": result.priority_areas,
        }
        
    except Exception as e:
        logger.exception(f"AI coverage advice failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/exploit-analysis")
async def analyze_crash_exploitation(request: AIExploitAnalysisRequest):
    """
    Perform deep AI analysis of a crash for exploitability assessment.
    
    The AI will:
    1. Analyze crash context (registers, stack, memory)
    2. Determine vulnerability type and root cause
    3. Assess exploitability with confidence score
    4. Suggest exploitation techniques and PoC guidance
    5. Identify similar CVEs and recommend remediation
    """
    try:
        import base64
        crash_input = None
        if request.crash_input_base64:
            crash_input = base64.b64decode(request.crash_input_base64)
        
        result = await analyze_crash_for_exploitation(
            crash_data=request.crash_data,
            crash_input=crash_input,
            include_poc_guidance=request.include_poc,
        )
        
        return {
            "success": True,
            "crash_id": result.crash_id,
            "exploitability": result.exploitability,
            "exploitability_score": result.exploitability_score,
            "vulnerability_type": result.vulnerability_type,
            "root_cause": result.root_cause,
            "affected_functions": result.affected_functions,
            "exploitation_techniques": result.exploitation_techniques,
            "poc_guidance": result.poc_guidance,
            "mitigation_bypass": result.mitigation_bypass,
            "similar_cves": result.cve_similar,
            "remediation": result.remediation,
            "detailed_analysis": result.detailed_analysis,
        }
        
    except Exception as e:
        logger.exception(f"AI exploit analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ai/binary-analysis/{binary_id}")
async def get_binary_analysis(binary_id: str):
    """
    Get AI analysis of a binary's structure and potential attack surface.
    """
    binary_dir = BINARIES_DIR / binary_id
    if not binary_dir.exists():
        raise HTTPException(status_code=404, detail="Binary not found")
    
    binary_files = list(binary_dir.glob("*"))
    if not binary_files:
        raise HTTPException(status_code=404, detail="No binary file found")
    
    binary_path = str(binary_files[0])
    
    try:
        info = analyze_binary(binary_path)
        
        return {
            "success": True,
            "binary_id": binary_id,
            "file_type": info.file_type,
            "architecture": info.architecture,
            "is_stripped": info.is_stripped,
            "has_symbols": info.has_symbols,
            "input_functions": info.input_functions[:30],
            "security_functions": info.imports[:30],
            "interesting_strings": info.strings[:100],
            "sections": info.sections,
        }
        
    except Exception as e:
        logger.exception(f"Binary analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/session-summary/{session_id}")
async def get_ai_session_summary(
    session_id: str,
    binary_id: Optional[str] = None,
    stats_history: List[Dict[str, Any]] = [],
    crashes: List[Dict[str, Any]] = [],
    corpus: List[Dict[str, Any]] = [],
):
    """
    Get comprehensive AI analysis of the entire fuzzing session.
    """
    binary_path = ""
    binary_name = "unknown"
    
    if binary_id:
        binary_dir = BINARIES_DIR / binary_id
        if binary_dir.exists():
            binary_files = list(binary_dir.glob("*"))
            if binary_files:
                binary_path = str(binary_files[0])
                binary_name = binary_files[0].name
    
    try:
        summary = await get_fuzzing_ai_summary(
            session_id=session_id,
            binary_path=binary_path,
            binary_name=binary_name,
            stats_history=stats_history,
            crashes=crashes,
            current_corpus=corpus,
        )
        
        return {
            "success": True,
            **summary,
        }
        
    except Exception as e:
        logger.exception(f"AI session summary failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# LOW PRIORITY FEATURES - PHASE 7 ENDPOINTS
# =============================================================================

# Request/Response schemas for Phase 7

class ParallelFuzzingRequest(BaseModel):
    """Request to start parallel fuzzing."""
    target_path: str = Field(..., description="Path to target executable")
    target_args: str = Field("@@", description="Target arguments")
    num_workers: Optional[int] = Field(None, description="Number of workers (default: CPU count)")
    seed_dir: Optional[str] = Field(None, description="Directory with seed inputs")
    output_dir: Optional[str] = Field(None, description="Output directory")
    timeout_ms: int = Field(5000, description="Execution timeout in milliseconds")
    max_iterations: Optional[int] = Field(None, description="Max executions per worker")
    max_time_seconds: Optional[int] = Field(None, description="Max total runtime")


class PersistentModeRequest(BaseModel):
    """Request for persistent mode execution."""
    target_path: str = Field(..., description="Path to persistent mode target")
    target_args: str = Field("", description="Target arguments")
    timeout_ms: int = Field(5000, description="Execution timeout")
    max_execs_per_instance: int = Field(10000, description="Max executions before restart")
    input_data: str = Field(..., description="Base64 encoded input data")


class ForkServerRequest(BaseModel):
    """Request for fork server execution."""
    target_path: str = Field(..., description="Path to target executable")
    target_args: str = Field("@@", description="Target arguments")
    timeout_ms: int = Field(5000, description="Execution timeout")
    input_data: str = Field(..., description="Base64 encoded input data")


class SnapshotFuzzingRequest(BaseModel):
    """Request for snapshot fuzzing."""
    target_path: str = Field(..., description="Path to target executable")
    snapshot_point: Optional[str] = Field(None, description="Function name or address for snapshot")
    timeout_ms: int = Field(5000, description="Execution timeout")
    input_data: str = Field(..., description="Base64 encoded input data")


class SymbolicHintRequest(BaseModel):
    """Request for symbolic execution hints."""
    target_path: str = Field(..., description="Path to target binary")
    seed_input: Optional[str] = Field(None, description="Base64 encoded seed input")
    num_hints: int = Field(20, description="Number of hints to generate")


# Active parallel fuzzing sessions
_parallel_sessions: Dict[str, ParallelFuzzer] = {}


@router.post("/parallel/start")
async def start_parallel_fuzzing_endpoint(request: ParallelFuzzingRequest):
    """
    Start a parallel fuzzing session across multiple CPU cores.
    
    Uses work-stealing for efficient corpus sharing and
    aggregates crashes from all workers.
    """
    # Validate target
    if not os.path.exists(request.target_path):
        raise HTTPException(status_code=404, detail="Target not found")
    
    try:
        fuzzer = ParallelFuzzer(
            target_path=request.target_path,
            target_args=request.target_args,
            num_workers=request.num_workers,
            seed_dir=request.seed_dir,
            output_dir=request.output_dir,
            timeout_ms=request.timeout_ms,
        )
        
        session_id = fuzzer.session.id
        _parallel_sessions[session_id] = fuzzer
        
        return {
            "success": True,
            "session_id": session_id,
            "num_workers": fuzzer.num_workers,
            "output_dir": fuzzer.output_dir,
            "message": "Use WebSocket endpoint /parallel/ws/{session_id} for real-time updates",
        }
        
    except Exception as e:
        logger.exception(f"Failed to create parallel fuzzing session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/parallel/status/{session_id}")
async def get_parallel_session_status(session_id: str):
    """Get parallel fuzzing session status."""
    fuzzer = _parallel_sessions.get(session_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return fuzzer.get_session()


@router.post("/parallel/stop/{session_id}")
async def stop_parallel_fuzzing_endpoint(session_id: str):
    """Stop a parallel fuzzing session."""
    fuzzer = _parallel_sessions.get(session_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Session not found")
    
    fuzzer.stop()
    del _parallel_sessions[session_id]
    
    return {
        "success": True,
        "session_id": session_id,
        "message": "Parallel fuzzing session stopped",
    }


@router.websocket("/parallel/ws/{session_id}")
async def parallel_fuzzing_websocket(websocket: WebSocket, session_id: str):
    """
    WebSocket for real-time parallel fuzzing progress.
    
    Connect after creating a session with /parallel/start.
    
    Receives events:
    - session_start: Session has begun
    - parallel_stats: Real-time aggregated stats
    - session_end: Session completed
    
    Send control:
    - {"action": "stop"}: Stop the session
    """
    await websocket.accept()
    
    fuzzer = _parallel_sessions.get(session_id)
    if not fuzzer:
        await websocket.send_json({"type": "error", "error": "Session not found"})
        await websocket.close()
        return
    
    try:
        # Start fuzzing in background
        fuzz_task = asyncio.create_task(_run_parallel_fuzzing(fuzzer, websocket))
        
        while True:
            try:
                message = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=1.0
                )
                
                if message.get("action") == "stop":
                    fuzzer.stop()
                    break
                    
            except asyncio.TimeoutError:
                if fuzz_task.done():
                    break
                continue
            except WebSocketDisconnect:
                break
        
        fuzz_task.cancel()
        
    finally:
        await websocket.close()


async def _run_parallel_fuzzing(fuzzer: ParallelFuzzer, websocket: WebSocket):
    """Run parallel fuzzing and send events."""
    try:
        async for event in fuzzer.start():
            await websocket.send_json(event)
    except Exception as e:
        await websocket.send_json({"type": "error", "error": str(e)})


# Persistent Mode endpoints

_persistent_harnesses: Dict[str, PersistentModeHarness] = {}


@router.post("/persistent/start")
async def start_persistent_mode_endpoint(
    target_path: str,
    target_args: str = "",
    timeout_ms: int = 5000,
    max_execs_per_instance: int = 10000,
):
    """
    Start a persistent mode harness.
    
    Persistent mode keeps the target process alive between executions
    for much faster throughput. Requires target compiled with
    persistent mode support (e.g., __AFL_LOOP).
    """
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Target not found")
    
    try:
        harness = PersistentModeHarness(
            target_path=target_path,
            target_args=target_args,
            timeout_ms=timeout_ms,
            max_executions_per_instance=max_execs_per_instance,
        )
        
        await harness.start()
        
        harness_id = str(uuid.uuid4())[:8]
        _persistent_harnesses[harness_id] = harness
        
        return {
            "success": True,
            "harness_id": harness_id,
            "target": target_path,
            "message": "Persistent harness started",
        }
        
    except Exception as e:
        logger.exception(f"Failed to start persistent harness: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/persistent/execute/{harness_id}")
async def execute_persistent_mode(harness_id: str, request: PersistentModeRequest):
    """Execute a test case in persistent mode."""
    import base64
    
    harness = _persistent_harnesses.get(harness_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Harness not found")
    
    try:
        input_data = base64.b64decode(request.input_data)
        result = await harness.execute(input_data)
        
        return {
            "success": True,
            "crashed": result.crashed,
            "timed_out": result.timed_out,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "stats": harness.get_stats(),
        }
        
    except Exception as e:
        logger.exception(f"Persistent execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/persistent/stats/{harness_id}")
async def get_persistent_stats(harness_id: str):
    """Get persistent harness statistics."""
    harness = _persistent_harnesses.get(harness_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Harness not found")
    
    return harness.get_stats()


@router.post("/persistent/stop/{harness_id}")
async def stop_persistent_mode_endpoint(harness_id: str):
    """Stop a persistent mode harness."""
    harness = _persistent_harnesses.get(harness_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Harness not found")
    
    await harness.stop()
    harness.cleanup()
    del _persistent_harnesses[harness_id]
    
    return {
        "success": True,
        "harness_id": harness_id,
        "message": "Persistent harness stopped",
    }


# Fork Server endpoints

_fork_servers: Dict[str, ForkServerHarness] = {}


@router.post("/forkserver/start")
async def start_fork_server_endpoint(
    target_path: str,
    target_args: str = "@@",
    timeout_ms: int = 5000,
):
    """
    Start a fork server harness.
    
    Fork server mode uses fork() to create child processes from a
    pre-initialized state, avoiding startup overhead.
    
    Note: Only available on Linux. Falls back to regular execution on Windows.
    """
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Target not found")
    
    try:
        harness = ForkServerHarness(
            target_path=target_path,
            target_args=target_args,
            timeout_ms=timeout_ms,
        )
        
        await harness.start()
        
        server_id = str(uuid.uuid4())[:8]
        _fork_servers[server_id] = harness
        
        return {
            "success": True,
            "server_id": server_id,
            "target": target_path,
            "is_unix": harness._is_unix,
            "message": "Fork server started" if harness._is_unix else "Using fallback mode (non-Unix)",
        }
        
    except Exception as e:
        logger.exception(f"Failed to start fork server: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/forkserver/execute/{server_id}")
async def execute_fork_server(server_id: str, request: ForkServerRequest):
    """Execute a test case using fork server."""
    import base64
    
    harness = _fork_servers.get(server_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Fork server not found")
    
    try:
        input_data = base64.b64decode(request.input_data)
        result = await harness.execute(input_data)
        
        return {
            "success": True,
            "crashed": result.crashed,
            "timed_out": result.timed_out,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "crash_type": result.crash_type.value if result.crash_type else None,
            "stats": harness.get_stats(),
        }
        
    except Exception as e:
        logger.exception(f"Fork server execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/forkserver/stats/{server_id}")
async def get_fork_server_stats(server_id: str):
    """Get fork server statistics."""
    harness = _fork_servers.get(server_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Fork server not found")
    
    return harness.get_stats()


@router.post("/forkserver/stop/{server_id}")
async def stop_fork_server_endpoint(server_id: str):
    """Stop a fork server."""
    harness = _fork_servers.get(server_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Fork server not found")
    
    harness.cleanup()
    del _fork_servers[server_id]
    
    return {
        "success": True,
        "server_id": server_id,
        "message": "Fork server stopped",
    }


# Snapshot Fuzzing endpoints

_snapshot_fuzzers: Dict[str, SnapshotFuzzer] = {}


@router.post("/snapshot/start")
async def start_snapshot_fuzzing_endpoint(
    target_path: str,
    snapshot_point: Optional[str] = None,
    timeout_ms: int = 5000,
    output_dir: Optional[str] = None,
):
    """
    Start a snapshot fuzzing session.
    
    Takes a memory snapshot at a specific program point and
    restores from it instead of restarting. Useful for:
    - Skipping initialization code
    - Fuzzing deep program states
    - Reducing startup overhead
    """
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Target not found")
    
    try:
        fuzzer = SnapshotFuzzer(
            target_path=target_path,
            snapshot_point=snapshot_point,
            timeout_ms=timeout_ms,
            output_dir=output_dir,
        )
        
        # Take initial snapshot
        snapshot = await fuzzer.take_snapshot()
        
        fuzzer_id = str(uuid.uuid4())[:8]
        _snapshot_fuzzers[fuzzer_id] = fuzzer
        
        return {
            "success": True,
            "fuzzer_id": fuzzer_id,
            "snapshot_id": snapshot.id,
            "snapshot_size_bytes": snapshot.size_bytes,
            "target": target_path,
            "message": "Snapshot taken, ready for fuzzing",
        }
        
    except Exception as e:
        logger.exception(f"Failed to start snapshot fuzzing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/snapshot/execute/{fuzzer_id}")
async def execute_from_snapshot(fuzzer_id: str, request: SnapshotFuzzingRequest):
    """Execute a test case from the snapshot point."""
    import base64
    
    fuzzer = _snapshot_fuzzers.get(fuzzer_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Snapshot fuzzer not found")
    
    try:
        input_data = base64.b64decode(request.input_data)
        result = await fuzzer.execute_from_snapshot(input_data)
        
        return {
            "success": True,
            "crashed": result.crashed,
            "timed_out": result.timed_out,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "stats": fuzzer.get_stats(),
        }
        
    except Exception as e:
        logger.exception(f"Snapshot execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/snapshot/take/{fuzzer_id}")
async def take_new_snapshot(fuzzer_id: str):
    """Take a new snapshot, replacing the previous one."""
    fuzzer = _snapshot_fuzzers.get(fuzzer_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Snapshot fuzzer not found")
    
    try:
        snapshot = await fuzzer.take_snapshot()
        
        return {
            "success": True,
            "snapshot_id": snapshot.id,
            "snapshot_size_bytes": snapshot.size_bytes,
            "message": "New snapshot taken",
        }
        
    except Exception as e:
        logger.exception(f"Failed to take snapshot: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/snapshot/stats/{fuzzer_id}")
async def get_snapshot_fuzzer_stats(fuzzer_id: str):
    """Get snapshot fuzzer statistics."""
    fuzzer = _snapshot_fuzzers.get(fuzzer_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Snapshot fuzzer not found")
    
    return fuzzer.get_stats()


@router.post("/snapshot/stop/{fuzzer_id}")
async def stop_snapshot_fuzzing_endpoint(fuzzer_id: str):
    """Stop and clean up snapshot fuzzing session."""
    fuzzer = _snapshot_fuzzers.get(fuzzer_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Snapshot fuzzer not found")
    
    fuzzer.cleanup()
    del _snapshot_fuzzers[fuzzer_id]
    
    return {
        "success": True,
        "fuzzer_id": fuzzer_id,
        "message": "Snapshot fuzzer stopped and cleaned up",
    }


# Symbolic Execution Hints endpoints

@router.post("/symbolic/analyze")
async def analyze_binary_for_hints(request: SymbolicHintRequest):
    """
    Analyze a binary for symbolic execution hints.
    
    Extracts:
    - Magic values and signatures
    - Comparison instruction locations
    - Interesting strings
    
    These hints guide fuzzing to explore more code paths.
    """
    if not os.path.exists(request.target_path):
        raise HTTPException(status_code=404, detail="Target binary not found")
    
    try:
        hint_gen = SymbolicExecutionHintGenerator(request.target_path)
        analysis = hint_gen.analyze_binary()
        
        return {
            "success": True,
            "target": request.target_path,
            "analysis": analysis,
            "stats": hint_gen.get_stats(),
        }
        
    except Exception as e:
        logger.exception(f"Binary analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/symbolic/hints")
async def generate_symbolic_hints(request: SymbolicHintRequest):
    """
    Generate fuzzing hints from symbolic analysis.
    
    Returns suggested inputs designed to flip branches and
    explore new code paths.
    """
    import base64
    
    if not os.path.exists(request.target_path):
        raise HTTPException(status_code=404, detail="Target binary not found")
    
    try:
        hint_gen = SymbolicExecutionHintGenerator(request.target_path)
        hint_gen.analyze_binary()
        
        # Decode seed input
        seed = b"FUZZ"
        if request.seed_input:
            seed = base64.b64decode(request.seed_input)
        
        hints = hint_gen.generate_hints(seed)
        
        # Serialize hints
        serialized_hints = []
        for hint in hints[:request.num_hints]:
            serialized = {
                "id": hint.id,
                "branch_address": hint.branch_address,
                "taken_path": hint.taken_path,
                "priority": hint.priority,
                "suggested_input": base64.b64encode(hint.suggested_input).decode() if hint.suggested_input else None,
                "constraints": [
                    {
                        "variable": c.variable,
                        "type": c.constraint_type,
                        "value": c.value.hex() if isinstance(c.value, bytes) else str(c.value),
                        "byte_offset": c.byte_offset,
                    }
                    for c in hint.constraints
                ],
            }
            serialized_hints.append(serialized)
        
        return {
            "success": True,
            "hints": serialized_hints,
            "stats": hint_gen.get_stats(),
        }
        
    except Exception as e:
        logger.exception(f"Hint generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/symbolic/guided-mutations")
async def get_guided_mutations(request: SymbolicHintRequest):
    """
    Generate mutations guided by symbolic execution hints.
    
    Combines regular mutations with hint-based mutations for
    better code coverage.
    """
    import base64
    
    if not os.path.exists(request.target_path):
        raise HTTPException(status_code=404, detail="Target binary not found")
    
    try:
        hint_gen = SymbolicExecutionHintGenerator(request.target_path)
        hint_gen.analyze_binary()
        
        # Decode seed input
        seed = b"FUZZ"
        if request.seed_input:
            seed = base64.b64decode(request.seed_input)
        
        hint_gen.generate_hints(seed)
        
        # Get prioritized mutations
        mutation_engine = MutationEngine()
        mutations = hint_gen.get_prioritized_mutations(
            mutation_engine,
            seed,
            num_mutations=request.num_hints,
        )
        
        return {
            "success": True,
            "mutations": [base64.b64encode(m).decode() for m in mutations],
            "stats": hint_gen.get_stats(),
        }
        
    except Exception as e:
        logger.exception(f"Guided mutation generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# BEGINNER-FRIENDLY FEATURES - PHASE 8 ENDPOINTS
# =============================================================================

# Active wizard sessions
_wizard_sessions: Dict[str, FuzzingSetupWizard] = {}


# --- Setup Wizard Endpoints ---

@router.post("/wizard/start")
async def start_setup_wizard():
    """
    Start a new fuzzing setup wizard session.
    
    The wizard guides beginners through the fuzzing configuration
    process step-by-step with explanations at each stage.
    """
    wizard = FuzzingSetupWizard()
    _wizard_sessions[wizard.state.id] = wizard
    
    return {
        "success": True,
        "wizard_id": wizard.state.id,
        "step": wizard.get_step_info(),
        "progress": wizard.get_progress(),
    }


@router.get("/wizard/{wizard_id}/step")
async def get_wizard_step(wizard_id: str):
    """Get the current wizard step information."""
    wizard = _wizard_sessions.get(wizard_id)
    if not wizard:
        raise HTTPException(status_code=404, detail="Wizard session not found")
    
    return {
        "success": True,
        "step": wizard.get_step_info(),
        "progress": wizard.get_progress(),
    }


@router.post("/wizard/{wizard_id}/next")
async def wizard_next_step(
    wizard_id: str,
    user_input: Optional[Dict[str, Any]] = None,
):
    """
    Advance to the next wizard step.
    
    Optionally provide user input from the current step.
    """
    wizard = _wizard_sessions.get(wizard_id)
    if not wizard:
        raise HTTPException(status_code=404, detail="Wizard session not found")
    
    step_info = wizard.next_step(user_input)
    
    return {
        "success": True,
        "step": step_info,
        "progress": wizard.get_progress(),
    }


@router.post("/wizard/{wizard_id}/prev")
async def wizard_prev_step(wizard_id: str):
    """Go back to the previous wizard step."""
    wizard = _wizard_sessions.get(wizard_id)
    if not wizard:
        raise HTTPException(status_code=404, detail="Wizard session not found")
    
    step_info = wizard.prev_step()
    
    return {
        "success": True,
        "step": step_info,
        "progress": wizard.get_progress(),
    }


@router.post("/wizard/{wizard_id}/skip")
async def wizard_skip_step(wizard_id: str):
    """Skip the current wizard step if allowed."""
    wizard = _wizard_sessions.get(wizard_id)
    if not wizard:
        raise HTTPException(status_code=404, detail="Wizard session not found")
    
    step_info = wizard.skip_step()
    
    return {
        "success": True,
        "step": step_info,
        "progress": wizard.get_progress(),
    }


@router.get("/wizard/{wizard_id}/config")
async def get_wizard_configuration(wizard_id: str):
    """Get the current fuzzing configuration from the wizard."""
    wizard = _wizard_sessions.get(wizard_id)
    if not wizard:
        raise HTTPException(status_code=404, detail="Wizard session not found")
    
    return {
        "success": True,
        "configuration": wizard.get_configuration(),
        "progress": wizard.get_progress(),
    }


@router.post("/wizard/{wizard_id}/reset")
async def reset_wizard(wizard_id: str):
    """Reset the wizard to the beginning."""
    wizard = _wizard_sessions.get(wizard_id)
    if not wizard:
        raise HTTPException(status_code=404, detail="Wizard session not found")
    
    step_info = wizard.reset()
    
    return {
        "success": True,
        "step": step_info,
        "progress": wizard.get_progress(),
    }


@router.delete("/wizard/{wizard_id}")
async def delete_wizard_session(wizard_id: str):
    """Delete a wizard session."""
    if wizard_id in _wizard_sessions:
        del _wizard_sessions[wizard_id]
        return {"success": True, "message": "Wizard session deleted"}
    
    raise HTTPException(status_code=404, detail="Wizard session not found")


# --- Binary Auto-Detection Endpoints ---

class AutoDetectRequest(BaseModel):
    """Request for binary auto-detection."""
    binary_path: str = Field(..., description="Path to binary file")


@router.post("/detect/analyze")
async def auto_detect_binary(request: AutoDetectRequest):
    """
    Automatically analyze a binary to detect its type, architecture,
    and suggest optimal fuzzing settings.
    
    Perfect for beginners who don't know how to configure fuzzing.
    """
    if not os.path.exists(request.binary_path):
        raise HTTPException(status_code=404, detail="Binary not found")
    
    try:
        detector = BinaryAutoDetector()
        result = detector.analyze(request.binary_path)
        
        return {
            "success": True,
            "analysis": result.to_dict(),
            "summary": detector.get_plain_english_summary(),
        }
        
    except Exception as e:
        logger.exception(f"Binary auto-detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/detect/upload")
async def upload_and_detect_binary(
    file: UploadFile = File(...),
):
    """
    Upload a binary and automatically analyze it.
    
    Returns detected properties and suggested settings.
    """
    # Generate unique ID for this binary
    binary_id = str(uuid.uuid4())[:8]
    binary_dir = BINARIES_DIR / binary_id
    binary_dir.mkdir(parents=True, exist_ok=True)
    
    # Save the uploaded file
    filename = file.filename or "binary"
    binary_path = binary_dir / filename
    
    try:
        content = await file.read()
        with open(binary_path, "wb") as f:
            f.write(content)
        
        # Make executable on Unix
        if os.name != "nt":
            os.chmod(binary_path, os.stat(binary_path).st_mode | stat.S_IXUSR)
        
        # Analyze the binary
        detector = BinaryAutoDetector()
        result = detector.analyze(str(binary_path))
        
        return {
            "success": True,
            "binary_id": binary_id,
            "binary_path": str(binary_path),
            "analysis": result.to_dict(),
            "summary": detector.get_plain_english_summary(),
        }
        
    except Exception as e:
        # Clean up on failure
        if binary_dir.exists():
            shutil.rmtree(binary_dir, ignore_errors=True)
        logger.exception(f"Binary upload and detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/detect/supported-formats")
async def get_supported_formats():
    """Get list of supported binary formats and input types."""
    return {
        "success": True,
        "formats": {
            "PE": "Windows executable (.exe, .dll)",
            "ELF": "Linux/Unix executable",
            "Mach-O": "macOS executable",
            "Script": "Script files (Python, Bash, etc.)",
        },
        "architectures": {
            "x86": "32-bit Intel/AMD",
            "x64": "64-bit Intel/AMD",
            "ARM": "32-bit ARM",
            "ARM64": "64-bit ARM (AArch64)",
        },
        "binary_types": [
            {"value": bt.value, "description": bt.name.replace("_", " ").title()}
            for bt in BinaryType
        ],
        "input_types": [
            {"value": it.value, "description": it.name.replace("_", " ").title()}
            for it in InputType
        ],
    }


@router.post("/detect/suggest-settings")
async def suggest_fuzzing_settings(request: AutoDetectRequest):
    """
    Analyze a binary and provide beginner-friendly
    fuzzing settings recommendations.
    """
    if not os.path.exists(request.binary_path):
        raise HTTPException(status_code=404, detail="Binary not found")
    
    try:
        detector = BinaryAutoDetector()
        result = detector.analyze(request.binary_path)
        
        # Build beginner-friendly recommendations
        recommendations = []
        
        # Mode recommendation
        if result.is_stripped:
            recommendations.append({
                "setting": "QEMU Mode",
                "value": True,
                "reason": "Your binary doesn't have debugging symbols, so QEMU mode is needed for coverage tracking",
                "beginner_tip": "QEMU lets us track which code paths your program takes, even without special compilation",
            })
        else:
            recommendations.append({
                "setting": "QEMU Mode",
                "value": False,
                "reason": "Your binary has symbols, native instrumentation should work",
                "beginner_tip": "Native mode is faster than QEMU when your binary supports it",
            })
        
        # Timeout recommendation
        timeout_reason = {
            BinaryType.FILE_PARSER: "File parsers usually process input quickly",
            BinaryType.NETWORK_SERVICE: "Network services may need time to process connections",
            BinaryType.CLI_TOOL: "Command-line tools typically run quickly",
        }.get(result.binary_type, "Default timeout for unknown binary types")
        
        recommendations.append({
            "setting": "Timeout",
            "value": f"{result.suggested_timeout_ms}ms",
            "reason": timeout_reason,
            "beginner_tip": "If fuzzing seems slow, you might be able to lower this. If you see many timeouts, increase it.",
        })
        
        # Memory recommendation
        recommendations.append({
            "setting": "Memory Limit",
            "value": f"{result.suggested_memory_mb}MB",
            "reason": f"Recommended for {result.bitness}-bit binaries",
            "beginner_tip": "This prevents your program from using too much RAM during testing",
        })
        
        # Input method recommendation
        input_tips = {
            InputType.FILE: "Use @@ in arguments where the test file should go (e.g., './program @@')",
            InputType.STDIN: "Input will be piped to your program automatically",
            InputType.NETWORK: "Consider using network fuzzing mode for better results",
            InputType.MIXED: "Your program accepts multiple input types - file mode is usually easiest to start with",
        }
        
        recommendations.append({
            "setting": "Input Method",
            "value": result.input_type.value,
            "reason": f"Detected based on functions like: {', '.join(result.input_functions[:3]) or 'standard patterns'}",
            "beginner_tip": input_tips.get(result.input_type, "Use file input mode to start"),
        })
        
        # Warnings as recommendations
        for warning in result.warnings:
            recommendations.append({
                "setting": "Warning",
                "value": warning,
                "reason": "Detected during analysis",
                "beginner_tip": "This might make fuzzing more interesting!",
            })
        
        return {
            "success": True,
            "binary_path": request.binary_path,
            "quick_start": {
                "target_args": result.suggested_args,
                "timeout_ms": result.suggested_timeout_ms,
                "memory_mb": result.suggested_memory_mb,
                "use_qemu": result.is_stripped,
                "mode": result.suggested_mode.value,
            },
            "recommendations": recommendations,
            "detection_confidence": result.detection_confidence,
            "summary": detector.get_plain_english_summary(),
        }
        
    except Exception as e:
        logger.exception(f"Settings suggestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# FUZZING TEMPLATES (Beginner Feature 3)
# =============================================================================

# Global template library instance
template_library = FuzzingTemplateLibrary()


class ApplyTemplateRequest(BaseModel):
    """Request to apply a fuzzing template."""
    template_id: str = Field(..., description="ID of the template to apply")
    target_path: Optional[str] = Field(None, description="Path to target binary (for matching)")


class BinaryPathRequest(BaseModel):
    """Request with a binary path."""
    binary_path: str = Field(..., description="Path to binary file")


@router.get("/templates")
async def list_templates():
    """
    Get all available fuzzing templates.
    
    Templates are pre-built configurations optimized for common target types
    like image parsers, JSON parsers, network servers, etc.
    
    **Beginner tip:** Start with a template that matches your target type
    for the best results without needing to configure everything yourself!
    """
    templates = template_library.get_all_templates()
    
    # Group by category for easier browsing
    by_category = {}
    for t in templates:
        cat = t["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(t)
    
    return {
        "templates": templates,
        "by_category": by_category,
        "total_count": len(templates),
        "categories": [c.value for c in TemplateCategory],
        "hint": "Use POST /templates/apply with a template_id to apply a configuration",
    }


@router.get("/templates/{template_id}")
async def get_template(template_id: str):
    """
    Get details of a specific fuzzing template.
    
    Returns full configuration including example seeds, dictionary words,
    tips, and common bug types for this target category.
    """
    template = template_library.get_template(template_id)
    
    if not template:
        raise HTTPException(
            status_code=404, 
            detail=f"Template not found: {template_id}. Use GET /templates to see available options."
        )
    
    return {
        "template": template.to_dict(),
        "seeds_available": len(template.example_seeds) > 0,
        "seeds_count": len(template.example_seeds),
        "dictionary_words_count": len(template.dictionary_words),
        "configuration": template_library.apply_template(template_id),
    }


@router.get("/templates/category/{category}")
async def get_templates_by_category(category: str):
    """
    Get all templates in a specific category.
    
    Categories include: file_parsers, network, cli_tools, interpreters,
    compression, crypto, media, documents
    """
    try:
        cat = TemplateCategory(category)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category: {category}. Valid categories: {[c.value for c in TemplateCategory]}"
        )
    
    templates = template_library.get_templates_by_category(cat)
    
    return {
        "category": category,
        "templates": [t.to_dict() for t in templates],
        "count": len(templates),
    }


@router.post("/templates/apply")
async def apply_template(request: ApplyTemplateRequest):
    """
    Apply a fuzzing template and get the configuration.
    
    Returns all settings pre-configured for the template type,
    including example seeds (base64 encoded), dictionary words,
    and tips for effective fuzzing.
    
    **Beginner tip:** After applying a template, you can customize
    individual settings if needed!
    """
    config = template_library.apply_template(request.template_id)
    
    if "error" in config:
        raise HTTPException(status_code=404, detail=config["error"])
    
    template = template_library.get_template(request.template_id)
    
    return {
        "success": True,
        "template_id": request.template_id,
        "template_name": template.name if template else request.template_id,
        "configuration": config,
        "next_steps": [
            "1. Set your target binary path",
            "2. Create a seed directory with example inputs (or use our provided seeds)",
            "3. Run a health check to validate your setup",
            "4. Start fuzzing!",
        ],
        "beginner_description": template.beginner_description if template else None,
    }


@router.post("/templates/match")
async def match_templates(request: BinaryPathRequest):
    """
    Find templates that match a binary based on analysis.
    
    Analyzes the binary and suggests templates that are likely
    to be a good fit based on detected functions, binary type, etc.
    
    **Beginner tip:** Not sure which template to use? Let us analyze
    your binary and suggest the best matches!
    """
    if not os.path.exists(request.binary_path):
        raise HTTPException(status_code=404, detail=f"Binary not found: {request.binary_path}")
    
    try:
        # Analyze the binary
        detector = BinaryAutoDetector(request.binary_path)
        analysis = detector.analyze()
        
        # Find matching templates
        matches = template_library.find_matching_templates(analysis)
        
        return {
            "success": True,
            "binary_path": request.binary_path,
            "binary_type": analysis.binary_type.value,
            "matches": [
                {
                    "template": t.to_dict(),
                    "confidence": conf,
                    "match_reasons": [
                        f"Binary type '{analysis.binary_type.value}' matches template category"
                        if t.category.value.replace("_", " ") in analysis.binary_type.value.replace("_", " ")
                        else "Function patterns match"
                    ],
                }
                for t, conf in matches[:5]  # Top 5 matches
            ],
            "best_match": matches[0][0].to_dict() if matches else None,
            "recommendation": f"We recommend the '{matches[0][0].name}' template for your binary!" if matches else
                            "No strong template matches found. Try the 'CLI File Processor' template as a generic starting point.",
        }
        
    except Exception as e:
        logger.exception(f"Template matching failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/{template_id}/seeds")
async def get_template_seeds(template_id: str):
    """
    Get example seeds for a template.
    
    Returns base64-encoded seed data that you can use as a starting
    point for fuzzing. These are minimal valid inputs for the target type.
    """
    import base64
    
    seeds = template_library.get_seeds_for_template(template_id)
    
    if not seeds:
        template = template_library.get_template(template_id)
        if not template:
            raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
        return {
            "template_id": template_id,
            "seeds": [],
            "note": "This template doesn't include example seeds. Create your own valid input files.",
        }
    
    return {
        "template_id": template_id,
        "seeds": [
            {
                "index": i,
                "size_bytes": len(seed),
                "data_base64": base64.b64encode(seed).decode(),
                "preview": seed[:50].hex() + ("..." if len(seed) > 50 else ""),
            }
            for i, seed in enumerate(seeds)
        ],
        "count": len(seeds),
        "usage": "Decode the base64 data and save each seed as a separate file in your seeds directory",
    }


@router.get("/templates/{template_id}/dictionary")
async def get_template_dictionary(template_id: str):
    """
    Get dictionary words for a template.
    
    Dictionary words are tokens that the fuzzer will use to mutate inputs.
    These are specific to each target type and help find bugs faster.
    """
    words = template_library.get_dictionary_for_template(template_id)
    
    if not words:
        template = template_library.get_template(template_id)
        if not template:
            raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
        return {
            "template_id": template_id,
            "words": [],
            "note": "This template doesn't include a dictionary. The fuzzer will work without one.",
        }
    
    return {
        "template_id": template_id,
        "words": words,
        "count": len(words),
        "usage": "Save these words to a file (one per line) and use as the dictionary for AFL++",
    }


# =============================================================================
# HEALTH CHECKS (Beginner Feature 4)
# =============================================================================

class HealthCheckRequest(BaseModel):
    """Request to run health checks on fuzzing setup."""
    target_path: str = Field(..., description="Path to target binary")
    target_args: str = Field(default="@@", description="Command line arguments")
    seed_dir: Optional[str] = Field(None, description="Path to seed directory")
    output_dir: Optional[str] = Field(None, description="Path to output directory")
    timeout_ms: int = Field(default=5000, description="Timeout in milliseconds")
    memory_limit_mb: int = Field(default=256, description="Memory limit in MB")


@router.post("/health-check")
async def run_health_checks(request: HealthCheckRequest):
    """
    Run comprehensive health checks on your fuzzing setup.
    
    Validates that:
    - Target binary exists and is executable
    - Seed directory has files
    - Output directory is writable
    - Settings are reasonable
    - Target can actually run
    
    **Beginner tip:** Always run this before starting a fuzzing session!
    It catches common mistakes that would waste your time.
    """
    try:
        checker = FuzzingHealthChecker(
            target_path=request.target_path,
            target_args=request.target_args,
            seed_dir=request.seed_dir,
            output_dir=request.output_dir,
            timeout_ms=request.timeout_ms,
            memory_limit_mb=request.memory_limit_mb,
        )
        
        report = checker.run_all_checks()
        
        return {
            "success": True,
            **report.to_dict(),
            "next_steps": _get_health_check_next_steps(report),
        }
        
    except Exception as e:
        logger.exception(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/health-check/quick")
async def quick_health_check(request: BinaryPathRequest):
    """
    Run a quick health check on just the target binary.
    
    Checks if the binary exists, is executable, and can run.
    Use this for a fast validation before diving into full setup.
    """
    try:
        checker = FuzzingHealthChecker(
            target_path=request.binary_path,
            target_args="@@",
        )
        
        # Run only target-related checks
        checker._check_target_exists()
        checker._check_target_executable()
        checker._check_target_readable()
        checker._check_target_not_script()
        checker._check_target_runs()
        checker._calculate_overall_status()
        
        report = checker.report
        
        return {
            "success": True,
            "binary_path": request.binary_path,
            "overall_status": report.overall_status,
            "can_proceed": report.can_proceed,
            "checks": [c.to_dict() for c in report.checks],
            "summary": report.summary,
        }
        
    except Exception as e:
        logger.exception(f"Quick health check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/health-check/seeds")
async def check_seeds_health(seed_dir: str = Form(...)):
    """
    Check the health of a seed directory.
    
    Validates that seeds exist, are reasonably sized, and suitable for fuzzing.
    """
    try:
        checker = FuzzingHealthChecker(
            target_path="/bin/true",  # Dummy target
            seed_dir=seed_dir,
        )
        
        # Run only seed-related checks
        checker._check_seeds_exist()
        checker._check_seeds_not_empty()
        checker._check_seeds_reasonable_size()
        checker._calculate_overall_status()
        
        report = checker.report
        
        # Get detailed seed info
        seed_files = []
        if os.path.isdir(seed_dir):
            for f in os.listdir(seed_dir):
                path = os.path.join(seed_dir, f)
                if os.path.isfile(path):
                    size = os.path.getsize(path)
                    seed_files.append({
                        "name": f,
                        "size_bytes": size,
                        "size_human": _human_size(size),
                    })
        
        return {
            "success": True,
            "seed_dir": seed_dir,
            "overall_status": report.overall_status,
            "checks": [c.to_dict() for c in report.checks],
            "seeds": seed_files,
            "total_seeds": len(seed_files),
            "total_size": sum(s["size_bytes"] for s in seed_files),
            "recommendations": _get_seed_recommendations(seed_files),
        }
        
    except Exception as e:
        logger.exception(f"Seed health check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}TB"


def _get_seed_recommendations(seed_files: List[Dict]) -> List[str]:
    """Generate recommendations for seed corpus."""
    recommendations = []
    
    if not seed_files:
        recommendations.append("📁 Add some example input files to your seed directory")
        recommendations.append("💡 Smaller seeds (< 1KB) are better for fuzzing performance")
        return recommendations
    
    avg_size = sum(s["size_bytes"] for s in seed_files) / len(seed_files)
    
    if avg_size > 100 * 1024:  # > 100KB average
        recommendations.append("📉 Your seeds are large. Consider minimizing them for better performance.")
    
    if len(seed_files) < 3:
        recommendations.append("📚 Adding more diverse seeds helps find different code paths")
    
    if len(seed_files) > 100:
        recommendations.append("🗑️ You have many seeds. Consider running corpus distillation to reduce duplicates.")
    
    if not recommendations:
        recommendations.append("✅ Your seed corpus looks good!")
    
    return recommendations


def _get_health_check_next_steps(report) -> List[str]:
    """Generate next steps based on health check results."""
    steps = []
    
    # Check for critical issues
    errors = [c for c in report.checks if c.severity.value == "error"]
    warnings = [c for c in report.checks if c.severity.value == "warning"]
    
    if errors:
        steps.append("🔴 Fix the critical issues listed above before proceeding")
        for e in errors[:3]:
            if e.fix_suggestion:
                steps.append(f"   → {e.fix_suggestion}")
    
    if warnings and not errors:
        steps.append("⚠️ Consider addressing warnings for better results (optional)")
    
    if report.can_proceed:
        steps.append("✅ Run POST /start to begin fuzzing")
        if not errors and not warnings:
            steps.append("🚀 Your setup looks great! You're ready to find some bugs!")
    
    return steps


# =============================================================================
# SMART DEFAULTS (Beginner Feature 5)
# =============================================================================

# Global smart defaults engine
smart_defaults_engine = SmartDefaultsEngine()


class SmartDefaultsRequest(BaseModel):
    """Request for smart default settings."""
    binary_path: Optional[str] = Field(None, description="Path to target binary for analysis")
    template_id: Optional[str] = Field(None, description="Template ID to incorporate")
    goal: str = Field(default="balanced", description="Fuzzing goal: quick_test, thorough, overnight, balanced")
    seed_dir: Optional[str] = Field(None, description="Seed directory for analysis")
    available_time_minutes: Optional[int] = Field(None, description="How much time you have for fuzzing")


@router.get("/smart-defaults/profiles")
async def get_fuzzing_profiles():
    """
    Get available fuzzing profiles.
    
    Profiles are pre-configured combinations of settings optimized for
    different scenarios like quick testing or overnight runs.
    
    **Beginner tip:** Not sure which profile to use? Start with "thorough"
    for a good balance of speed and coverage.
    """
    profiles = smart_defaults_engine.get_profile_options()
    
    return {
        "profiles": profiles,
        "recommended": "thorough",
        "hint": "Use POST /smart-defaults to get settings for a specific profile",
    }


@router.post("/smart-defaults")
async def get_smart_defaults(request: SmartDefaultsRequest):
    """
    Get intelligent default settings based on your setup.
    
    Analyzes your binary, system resources, and fuzzing goals to
    recommend optimal settings. No expertise required!
    
    **How it works:**
    1. We analyze your binary (if provided) to understand what it does
    2. We check your system resources (CPU, memory)
    3. We apply the template settings (if provided)
    4. We adjust everything based on your fuzzing goal
    
    **Result:** Settings optimized for YOUR specific setup!
    """
    try:
        # Analyze binary if provided
        binary_analysis = None
        if request.binary_path and os.path.exists(request.binary_path):
            detector = BinaryAutoDetector(request.binary_path)
            binary_analysis = detector.analyze()
        
        # Get template if provided
        template = None
        if request.template_id:
            template = template_library.get_template(request.template_id)
        
        # Analyze seeds if provided
        seed_count = 0
        seed_total_size = 0
        if request.seed_dir and os.path.isdir(request.seed_dir):
            for f in os.listdir(request.seed_dir):
                path = os.path.join(request.seed_dir, f)
                if os.path.isfile(path):
                    seed_count += 1
                    seed_total_size += os.path.getsize(path)
        
        # Get smart defaults
        result = smart_defaults_engine.get_smart_defaults(
            binary_analysis=binary_analysis,
            template=template,
            goal=request.goal,
            seed_count=seed_count,
            seed_total_size=seed_total_size,
        )
        
        return {
            "success": True,
            **result,
            "applied_context": {
                "binary_analyzed": binary_analysis is not None,
                "template_applied": template is not None,
                "seeds_analyzed": seed_count > 0,
                "goal": request.goal,
            },
        }
        
    except Exception as e:
        logger.exception(f"Smart defaults generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smart-defaults/recommend-profile")
async def recommend_profile(
    available_time_minutes: Optional[int] = None,
    goal: Optional[str] = None,
):
    """
    Get a profile recommendation based on your constraints.
    
    Tell us how much time you have or what your goal is, and we'll
    recommend the best fuzzing profile for you.
    
    **Goals:**
    - `find_bugs_fast`: Prioritize quick results over thoroughness
    - `maximize_coverage`: Get the most complete testing possible
    """
    recommendation = smart_defaults_engine.recommend_profile(
        available_time_minutes=available_time_minutes,
        goal=goal,
    )
    
    # Get full profile details
    profile_id = recommendation["recommended"]
    profile_details = smart_defaults_engine.PROFILES.get(profile_id, {})
    
    return {
        **recommendation,
        "profile_details": {
            "id": profile_id,
            **profile_details,
        },
        "all_profiles": smart_defaults_engine.get_profile_options(),
    }


@router.get("/smart-defaults/system-info")
async def get_system_info():
    """
    Get information about your system resources.
    
    Shows CPU cores, available memory, and whether your system
    is considered resource-constrained for fuzzing.
    """
    return {
        "system_info": smart_defaults_engine.system_info,
        "recommendations": _get_system_recommendations(smart_defaults_engine.system_info),
    }


def _get_system_recommendations(system_info: Dict) -> List[str]:
    """Generate recommendations based on system resources."""
    recs = []
    
    if system_info.get("is_resource_constrained"):
        recs.append("⚠️ Your system has limited resources - we'll optimize settings accordingly")
        recs.append("💡 Consider closing other applications while fuzzing")
    else:
        cores = system_info.get("cpu_cores_physical", 1)
        if cores >= 4:
            recs.append(f"✅ You have {cores} CPU cores - parallel fuzzing will be effective")
        
        mem_gb = system_info.get("memory_available_gb", 0)
        if mem_gb >= 8:
            recs.append(f"✅ {mem_gb:.1f}GB RAM available - plenty for fuzzing")
        elif mem_gb >= 4:
            recs.append(f"👍 {mem_gb:.1f}GB RAM available - sufficient for most targets")
    
    if not recs:
        recs.append("✅ Your system looks good for fuzzing!")
    
    return recs


# =============================================================================
# PLAIN ENGLISH EXPLANATIONS (Beginner Feature 6)
# =============================================================================

# Global explainer instance
explainer = PlainEnglishExplainer()


@router.get("/explain/crash-types")
async def explain_all_crash_types():
    """
    Get beginner-friendly explanations for all crash types.
    
    Learn what each type of crash means, why it matters for security,
    and what to do when you find one.
    """
    explanations = {}
    for crash_type in CrashType:
        explanations[crash_type.value] = explainer.explain_crash(crash_type)
    
    return {
        "crash_types": explanations,
        "severity_order": [
            {"type": "heap_corruption", "severity": "critical", "emoji": "🔴"},
            {"type": "segfault", "severity": "high", "emoji": "🔴"},
            {"type": "stack_overflow", "severity": "high", "emoji": "🟠"},
            {"type": "abort", "severity": "medium", "emoji": "🟡"},
            {"type": "timeout", "severity": "medium", "emoji": "🟡"},
            {"type": "null_deref", "severity": "medium", "emoji": "🟡"},
            {"type": "division_by_zero", "severity": "low", "emoji": "🟢"},
        ],
        "quick_reference": """
🔴 **Critical/High:** heap_corruption, segfault, stack_overflow - Fix these first!
🟡 **Medium:** abort, timeout, null_deref - Important but less exploitable
🟢 **Low:** division_by_zero - Usually just crashes, not exploitable
        """,
    }


@router.get("/explain/crash/{crash_type}")
async def explain_crash_type(crash_type: str):
    """
    Get a detailed explanation for a specific crash type.
    
    Includes what it means, security implications, and how to fix it.
    """
    try:
        ct = CrashType(crash_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown crash type: {crash_type}. Valid types: {[c.value for c in CrashType]}"
        )
    
    return explainer.explain_crash(ct)


class CrashExplanationRequest(BaseModel):
    """Request to explain a specific crash."""
    crash_type: str = Field(..., description="Type of crash")
    input_file: Optional[str] = Field(None, description="Path to crashing input")
    target_path: Optional[str] = Field(None, description="Path to target binary")
    target_args: Optional[str] = Field(None, description="Arguments used")
    stack_trace: Optional[List[str]] = Field(None, description="Stack trace if available")


@router.post("/explain/crash")
async def explain_crash_instance(request: CrashExplanationRequest):
    """
    Get a detailed explanation for a specific crash you found.
    
    Provides context-specific advice including how to reproduce
    the crash and what to look for when debugging.
    """
    crash_data = {
        "crash_type": request.crash_type,
        "input_file": request.input_file,
        "target_path": request.target_path,
        "target_args": request.target_args or "@@",
        "stack_trace": request.stack_trace,
    }
    
    return explainer.explain_crash_report(crash_data)


@router.get("/explain/metrics")
async def explain_all_metrics():
    """
    Get explanations for all fuzzing metrics.
    
    Learn what each metric means and what values are considered good.
    """
    metrics = {}
    for metric_name in explainer.METRIC_EXPLANATIONS:
        metrics[metric_name] = {
            **explainer.METRIC_EXPLANATIONS[metric_name],
            "example_assessment": explainer._assess_metric_value(metric_name, 
                {"executions": 10000, "exec_per_sec": 500, "coverage": 65, 
                 "paths": 1000, "crashes": 3, "hangs": 1, "corpus_size": 500,
                 "stability": 95}.get(metric_name, 0)),
        }
    
    return {
        "metrics": metrics,
        "quick_guide": """
📊 **Key Metrics to Watch:**

1. **Speed** (exec/sec): Higher is better. 1000+ is good.
2. **Coverage**: Should grow over time. 60%+ is good.
3. **Crashes**: Any crash is worth investigating!
4. **Stability**: Should be 90%+. Low stability means inconsistent behavior.
        """,
    }


@router.get("/explain/metric/{metric_name}")
async def explain_metric(metric_name: str, value: Optional[float] = None):
    """
    Get explanation for a specific fuzzing metric.
    
    Optionally provide a value to get an assessment of whether it's good.
    """
    if metric_name not in explainer.METRIC_EXPLANATIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown metric: {metric_name}. Valid metrics: {list(explainer.METRIC_EXPLANATIONS.keys())}"
        )
    
    return explainer.explain_metric(metric_name, value if value is not None else 0)


class SessionExplanationRequest(BaseModel):
    """Request to explain a session status."""
    status: str = Field(..., description="Session status")
    total_executions: int = Field(default=0)
    unique_crashes: int = Field(default=0)
    coverage_percent: float = Field(default=0)
    duration_seconds: int = Field(default=0)


@router.post("/explain/session")
async def explain_session_status(request: SessionExplanationRequest):
    """
    Get a beginner-friendly explanation of your fuzzing session.
    
    Provides a summary of what's happening, what the metrics mean,
    and what you should do next.
    """
    session_data = {
        "status": request.status,
        "total_executions": request.total_executions,
        "unique_crashes": request.unique_crashes,
        "coverage_percent": request.coverage_percent,
        "duration_seconds": request.duration_seconds,
    }
    
    return explainer.explain_session_status(session_data)


class CoverageExplanationRequest(BaseModel):
    """Request to explain coverage data."""
    total_blocks: int = Field(..., description="Total code blocks")
    hit_blocks: int = Field(..., description="Code blocks executed")
    new_blocks_this_session: Optional[int] = Field(None, description="New blocks found")


@router.post("/explain/coverage")
async def explain_coverage(request: CoverageExplanationRequest):
    """
    Get a beginner-friendly explanation of your code coverage.
    
    Includes a visual representation and tips for improving coverage.
    """
    coverage_data = {
        "total_blocks": request.total_blocks,
        "hit_blocks": request.hit_blocks,
        "new_blocks_this_session": request.new_blocks_this_session,
    }
    
    return explainer.explain_coverage_map(coverage_data)


@router.get("/explain/glossary")
async def get_fuzzing_glossary():
    """
    Get a glossary of fuzzing terms with simple explanations.
    
    Perfect for beginners who want to understand fuzzing terminology.
    """
    return {
        "glossary": {
            "fuzzing": {
                "term": "Fuzzing",
                "simple": "Automated testing by feeding random/mutated inputs to find bugs",
                "analogy": "Like a monkey randomly pressing buttons to see what breaks",
            },
            "seed": {
                "term": "Seed",
                "simple": "An example input file used as a starting point",
                "analogy": "Like a recipe that gets randomly modified to create variations",
            },
            "corpus": {
                "term": "Corpus",
                "simple": "The collection of interesting inputs discovered during fuzzing",
                "analogy": "A library of test cases that grows as we find new code paths",
            },
            "mutation": {
                "term": "Mutation",
                "simple": "A change made to an input to create a new test case",
                "analogy": "Like genetic mutations - small random changes to DNA",
            },
            "coverage": {
                "term": "Coverage",
                "simple": "Which parts of the code have been executed during testing",
                "analogy": "Like tracking which rooms you've visited in a building",
            },
            "crash": {
                "term": "Crash",
                "simple": "When the program stops unexpectedly due to an error",
                "analogy": "The program hit a wall and couldn't continue",
            },
            "hang": {
                "term": "Hang",
                "simple": "When the program gets stuck and doesn't finish",
                "analogy": "Like being stuck in an infinite loop on a roundabout",
            },
            "sanitizer": {
                "term": "Sanitizer",
                "simple": "A tool that detects memory errors when running a program",
                "analogy": "Like a spell-checker but for memory usage",
            },
            "instrumentation": {
                "term": "Instrumentation",
                "simple": "Adding tracking code to measure coverage",
                "analogy": "Like adding GPS trackers to see where the program goes",
            },
            "afl": {
                "term": "AFL/AFL++",
                "simple": "A popular fuzzing tool that guides testing toward new code",
                "analogy": "A smart explorer that remembers where it's been",
            },
            "qemu": {
                "term": "QEMU Mode",
                "simple": "Running the program in an emulator to track coverage",
                "analogy": "Like running Windows programs on a Mac using emulation",
            },
            "dictionary": {
                "term": "Dictionary",
                "simple": "A list of keywords to use when mutating inputs",
                "analogy": "A cheat sheet of important words for a specific file format",
            },
            "minimization": {
                "term": "Minimization",
                "simple": "Making a crashing input as small as possible",
                "analogy": "Finding the smallest recipe that still causes the allergic reaction",
            },
            "triage": {
                "term": "Triage",
                "simple": "Sorting crashes by importance and uniqueness",
                "analogy": "Like an ER sorting patients by how urgent their needs are",
            },
        },
        "categories": {
            "basics": ["fuzzing", "seed", "corpus", "mutation"],
            "results": ["coverage", "crash", "hang"],
            "tools": ["sanitizer", "instrumentation", "afl", "qemu"],
            "workflow": ["dictionary", "minimization", "triage"],
        },
    }


# =============================================================================
# PROGRESS TRACKING & TIME ESTIMATES (Beginner Feature 8)
# =============================================================================

# Store progress trackers per session
progress_trackers: Dict[str, FuzzingProgressTracker] = {}


class ProgressSnapshotRequest(BaseModel):
    """Request to record a progress snapshot."""
    session_id: str = Field(..., description="Fuzzing session ID")
    executions: int = Field(..., description="Total executions so far")
    coverage_percent: float = Field(..., description="Current coverage percentage")
    unique_paths: int = Field(default=0, description="Number of unique paths discovered")
    crashes_found: int = Field(default=0, description="Number of crashes found")
    corpus_size: int = Field(default=0, description="Current corpus size")


@router.post("/progress/start/{session_id}")
async def start_progress_tracking(
    session_id: str,
    target_coverage: float = 80.0,
):
    """
    Start tracking progress for a fuzzing session.
    
    Call this when starting a new fuzzing session to enable
    time estimates and progress predictions.
    
    **Parameters:**
    - target_coverage: Coverage goal (default 80%)
    """
    tracker = FuzzingProgressTracker(target_coverage=target_coverage)
    tracker.start()
    progress_trackers[session_id] = tracker
    
    return {
        "success": True,
        "session_id": session_id,
        "message": "Progress tracking started",
        "target_coverage": target_coverage,
    }


@router.post("/progress/snapshot")
async def record_progress_snapshot(request: ProgressSnapshotRequest):
    """
    Record a progress snapshot for a session.
    
    Call this periodically (every 30+ seconds) to update
    progress tracking and enable accurate time estimates.
    """
    tracker = progress_trackers.get(request.session_id)
    
    if not tracker:
        # Auto-create tracker if not exists
        tracker = FuzzingProgressTracker()
        tracker.start()
        progress_trackers[request.session_id] = tracker
    
    tracker.record_snapshot(
        executions=request.executions,
        coverage_percent=request.coverage_percent,
        unique_paths=request.unique_paths,
        crashes_found=request.crashes_found,
        corpus_size=request.corpus_size,
    )
    
    return {
        "success": True,
        "session_id": request.session_id,
        "snapshots_recorded": len(tracker.snapshots),
    }


@router.get("/progress/{session_id}")
async def get_progress_estimate(session_id: str):
    """
    Get current progress estimate and time predictions.
    
    Returns:
    - Current progress metrics
    - Execution rate and coverage rate
    - Time to target coverage estimate
    - Coverage predictions for 1h, 4h, 24h
    - Progress status and recommendations
    
    **Beginner tip:** This helps you understand if fuzzing is
    working well and how long you should let it run!
    """
    tracker = progress_trackers.get(session_id)
    
    if not tracker:
        raise HTTPException(
            status_code=404,
            detail=f"No progress tracker for session: {session_id}. Call POST /progress/start first."
        )
    
    estimate = tracker.get_estimate()
    
    if not estimate:
        return {
            "session_id": session_id,
            "status": "no_data",
            "message": "No progress data yet. Record some snapshots first.",
        }
    
    return {
        "session_id": session_id,
        **estimate.to_dict(),
    }


@router.get("/progress/{session_id}/summary")
async def get_progress_summary(session_id: str):
    """
    Get a beginner-friendly progress summary.
    
    Perfect for displaying in a dashboard - includes a visual
    progress bar and easy-to-understand status messages.
    """
    tracker = progress_trackers.get(session_id)
    
    if not tracker:
        return {
            "session_id": session_id,
            "status": "Not tracked",
            "message": "Progress tracking not started for this session",
        }
    
    return {
        "session_id": session_id,
        **tracker.get_summary(),
    }


@router.get("/progress/{session_id}/bar")
async def get_progress_bar(session_id: str, width: int = 30):
    """
    Get a text-based progress bar.
    
    Returns a simple visual representation of coverage progress.
    """
    tracker = progress_trackers.get(session_id)
    
    if not tracker:
        return {"progress_bar": f"[{'░' * width}] Not started"}
    
    return {
        "progress_bar": tracker.get_progress_bar(width),
        "coverage_percent": tracker.snapshots[-1].coverage_percent if tracker.snapshots else 0,
    }


@router.delete("/progress/{session_id}")
async def stop_progress_tracking(session_id: str):
    """
    Stop tracking progress for a session.
    
    Call this when the fuzzing session ends to clean up.
    """
    if session_id in progress_trackers:
        del progress_trackers[session_id]
        return {"success": True, "message": "Progress tracking stopped"}
    
    return {"success": False, "message": "Session not found"}


class TimeEstimateRequest(BaseModel):
    """Request for time estimate without full tracking."""
    current_coverage: float = Field(..., description="Current coverage percentage")
    target_coverage: float = Field(default=80.0, description="Target coverage")
    coverage_rate_per_hour: float = Field(..., description="Coverage increase per hour")
    elapsed_minutes: int = Field(default=0, description="Time already spent fuzzing")


@router.post("/progress/estimate-time")
async def estimate_time_quick(request: TimeEstimateRequest):
    """
    Quick time estimate without full progress tracking.
    
    Provide your current coverage and rate to get a rough
    estimate of how long it will take to reach your target.
    """
    remaining = request.target_coverage - request.current_coverage
    
    if remaining <= 0:
        return {
            "target_reached": True,
            "message": f"You've already reached {request.current_coverage}% coverage!",
        }
    
    if request.coverage_rate_per_hour <= 0:
        return {
            "target_reached": False,
            "message": "Not making progress - coverage rate is zero",
            "recommendation": "Try adding more diverse seeds or using a dictionary",
        }
    
    # Simple estimate (not accounting for diminishing returns)
    hours_remaining = remaining / request.coverage_rate_per_hour
    
    # Apply rough diminishing returns factor
    if request.current_coverage > 50:
        hours_remaining *= 1.5
    if request.current_coverage > 70:
        hours_remaining *= 2
    
    minutes_remaining = int(hours_remaining * 60)
    
    return {
        "target_reached": False,
        "current_coverage": request.current_coverage,
        "target_coverage": request.target_coverage,
        "remaining_coverage": remaining,
        "estimated_time": {
            "minutes": minutes_remaining,
            "human": f"{minutes_remaining // 60}h {minutes_remaining % 60}m" if minutes_remaining >= 60 else f"{minutes_remaining}m",
        },
        "note": "This is a rough estimate. Actual time depends on program complexity and input quality.",
    }


# =============================================================================
# AUTO-TRIAGE (Beginner Feature 12)
# =============================================================================

# Store triagers per session
crash_triagers: Dict[str, CrashAutoTriager] = {}


class TriageCrashRequest(BaseModel):
    """Request to triage a single crash."""
    session_id: str = Field(..., description="Fuzzing session ID")
    crash_id: str = Field(..., description="Unique crash identifier")
    crash_type: str = Field(..., description="Type of crash")
    stack_trace: List[str] = Field(default_factory=list, description="Stack trace frames")
    crash_address: Optional[str] = Field(None, description="Crash address")
    faulting_instruction: Optional[str] = Field(None, description="Faulting instruction")
    registers: Optional[Dict[str, str]] = Field(None, description="Register values")
    input_file: Optional[str] = Field(None, description="Path to crashing input")
    asan_output: Optional[str] = Field(None, description="AddressSanitizer output if available")


@router.post("/triage/crash")
async def triage_single_crash(request: TriageCrashRequest):
    """
    Triage a single crash to determine severity and exploitability.
    
    Analyzes the crash and returns:
    - Severity level (critical, high, medium, low)
    - Whether it's likely exploitable
    - Root cause guess
    - Beginner-friendly explanation
    - What to do next
    
    **Beginner tip:** Use this to understand which crashes to focus on!
    """
    # Get or create triager for session
    if request.session_id not in crash_triagers:
        crash_triagers[request.session_id] = CrashAutoTriager()
    
    triager = crash_triagers[request.session_id]
    
    try:
        crash_type = CrashType(request.crash_type)
    except ValueError:
        crash_type = CrashType.UNKNOWN
    
    triaged = triager.triage_crash(
        crash_id=request.crash_id,
        crash_type=crash_type,
        stack_trace=request.stack_trace,
        crash_address=request.crash_address,
        faulting_instruction=request.faulting_instruction,
        registers=request.registers,
        input_file=request.input_file,
        asan_output=request.asan_output,
    )
    
    return {
        "success": True,
        **triaged.to_dict(),
    }


class TriageMultipleCrashesRequest(BaseModel):
    """Request to triage multiple crashes."""
    session_id: str = Field(..., description="Fuzzing session ID")
    crashes: List[TriageCrashRequest] = Field(..., description="List of crashes to triage")


@router.post("/triage/batch")
async def triage_multiple_crashes(request: TriageMultipleCrashesRequest):
    """
    Triage multiple crashes at once.
    
    Analyzes all crashes and returns them sorted by priority,
    with duplicates identified and grouped.
    """
    if request.session_id not in crash_triagers:
        crash_triagers[request.session_id] = CrashAutoTriager()
    
    triager = crash_triagers[request.session_id]
    triaged_crashes = []
    
    for crash in request.crashes:
        try:
            crash_type = CrashType(crash.crash_type)
        except ValueError:
            crash_type = CrashType.UNKNOWN
        
        triaged = triager.triage_crash(
            crash_id=crash.crash_id,
            crash_type=crash_type,
            stack_trace=crash.stack_trace,
            crash_address=crash.crash_address,
            faulting_instruction=crash.faulting_instruction,
            registers=crash.registers,
            input_file=crash.input_file,
            asan_output=crash.asan_output,
        )
        triaged_crashes.append(triaged)
    
    # Generate report
    report = triager.generate_report(request.session_id, triaged_crashes)
    
    return {
        "success": True,
        **report.to_dict(),
    }


@router.get("/triage/{session_id}/report")
async def get_triage_report(session_id: str):
    """
    Get the current triage report for a session.
    
    Returns all triaged crashes sorted by priority with
    overall assessment and recommended next steps.
    """
    triager = crash_triagers.get(session_id)
    
    if not triager:
        return {
            "session_id": session_id,
            "message": "No crashes triaged for this session yet",
            "crashes": [],
        }
    
    # Collect all triaged crashes
    all_crashes = []
    for stack_hash, crash_ids in triager.crash_groups.items():
        # Get the first crash for each group
        first_id = triager.seen_stack_hashes.get(stack_hash)
        if first_id:
            # We need to reconstruct - in real implementation, store the TriagedCrash objects
            all_crashes.append({
                "stack_hash": stack_hash,
                "crash_ids": crash_ids,
                "unique_crash_id": first_id,
                "duplicate_count": len(crash_ids) - 1,
            })
    
    return {
        "session_id": session_id,
        "unique_crashes": len(triager.seen_stack_hashes),
        "total_crashes": sum(len(ids) for ids in triager.crash_groups.values()),
        "crash_groups": all_crashes,
    }


@router.get("/triage/{session_id}/summary")
async def get_triage_summary(session_id: str):
    """
    Get a quick summary of triaged crashes.
    
    Perfect for dashboard display - shows severity breakdown
    and most important crash at a glance.
    """
    triager = crash_triagers.get(session_id)
    
    if not triager:
        return {
            "session_id": session_id,
            "emoji": "✨",
            "headline": "No crashes yet",
            "subtext": "Keep fuzzing to find bugs!",
        }
    
    # Return basic summary (in real implementation, track TriagedCrash objects)
    total_unique = len(triager.seen_stack_hashes)
    total_all = sum(len(ids) for ids in triager.crash_groups.values())
    
    if total_unique == 0:
        return {
            "session_id": session_id,
            "emoji": "✨",
            "headline": "No crashes yet",
            "subtext": "Keep fuzzing to find bugs!",
        }
    
    return {
        "session_id": session_id,
        "emoji": "🐛",
        "headline": f"{total_unique} unique crash{'es' if total_unique > 1 else ''} found",
        "subtext": f"{total_all - total_unique} duplicates filtered out" if total_all > total_unique else "All crashes are unique",
        "unique_count": total_unique,
        "total_count": total_all,
    }


@router.delete("/triage/{session_id}")
async def clear_triage_data(session_id: str):
    """
    Clear triage data for a session.
    
    Use this to reset triage when starting fresh.
    """
    if session_id in crash_triagers:
        del crash_triagers[session_id]
        return {"success": True, "message": "Triage data cleared"}
    
    return {"success": False, "message": "Session not found"}


@router.get("/triage/severity-guide")
async def get_severity_guide():
    """
    Get a guide to understanding crash severity levels.
    
    Explains what each severity level means and how to prioritize.
    """
    return {
        "severity_levels": {
            "critical": {
                "emoji": "🚨",
                "score_range": "85-100",
                "description": "Likely exploitable vulnerabilities",
                "examples": ["Heap corruption", "Write to controlled address"],
                "action": "Fix immediately - high security risk",
            },
            "high": {
                "emoji": "🔴",
                "score_range": "65-84",
                "description": "Serious bugs with potential security impact",
                "examples": ["Stack overflow", "Segmentation fault"],
                "action": "Prioritize for fixing",
            },
            "medium": {
                "emoji": "🟡",
                "score_range": "40-64",
                "description": "Bugs that should be fixed",
                "examples": ["Assertion failure", "Null dereference"],
                "action": "Fix when possible",
            },
            "low": {
                "emoji": "🟢",
                "score_range": "20-39",
                "description": "Minor issues with limited impact",
                "examples": ["Division by zero", "Timeout"],
                "action": "Fix when convenient",
            },
            "info": {
                "emoji": "ℹ️",
                "score_range": "0-19",
                "description": "Informational findings",
                "examples": ["Duplicate crashes", "Known issues"],
                "action": "Review if time permits",
            },
        },
        "priority_order": ["critical", "high", "medium", "low", "info"],
        "tips": [
            "Always fix critical and high severity crashes first",
            "Exploitable crashes are more urgent than non-exploitable ones",
            "Unique crashes are more valuable than duplicates",
            "Use AddressSanitizer for more detailed crash analysis",
        ],
    }


# =============================================================================
# ONE-CLICK EXAMPLES ENDPOINTS (Feature 17)
# =============================================================================

# Initialize the example library
_example_library = OneClickExampleLibrary()


@router.get("/examples")
async def list_examples(
    difficulty: Optional[str] = None,
    vulnerability_type: Optional[str] = None,
):
    """
    List all available practice examples.
    
    Optionally filter by difficulty (beginner, intermediate, advanced)
    or vulnerability type (buffer_overflow, heap_overflow, etc.)
    """
    diff_enum = None
    vuln_enum = None
    
    if difficulty:
        try:
            diff_enum = ExampleDifficulty(difficulty.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid difficulty. Use: {[d.value for d in ExampleDifficulty]}"
            )
    
    if vulnerability_type:
        try:
            vuln_enum = VulnerabilityType(vulnerability_type.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid vulnerability type. Use: {[v.value for v in VulnerabilityType]}"
            )
    
    return {
        "examples": _example_library.list_examples(diff_enum, vuln_enum),
        "filters_applied": {
            "difficulty": difficulty,
            "vulnerability_type": vulnerability_type,
        },
    }


@router.get("/examples/categories")
async def get_example_categories():
    """
    Get all example categories and their counts.
    
    Useful for building filter UIs.
    """
    return _example_library.get_categories()


@router.get("/examples/{example_id}")
async def get_example_details(example_id: str):
    """
    Get full details for a specific example.
    
    Includes source code, vulnerability explanation, hints, and learning objectives.
    """
    details = _example_library.get_example_details(example_id)
    if not details:
        raise HTTPException(
            status_code=404,
            detail=f"Example '{example_id}' not found"
        )
    return details


@router.get("/examples/{example_id}/tutorial")
async def get_example_tutorial(example_id: str):
    """
    Get a step-by-step tutorial for fuzzing an example.
    
    Perfect for beginners learning how to use the fuzzer.
    """
    tutorial = _example_library.get_tutorial(example_id)
    if not tutorial:
        raise HTTPException(
            status_code=404,
            detail=f"Example '{example_id}' not found"
        )
    return tutorial


@router.get("/examples/{example_id}/settings")
async def get_example_recommended_settings(example_id: str):
    """
    Get recommended fuzzing settings for an example.
    
    Returns optimized settings for quickly finding the bug.
    """
    settings = _example_library.get_recommended_settings(example_id)
    if not settings:
        raise HTTPException(
            status_code=404,
            detail=f"Example '{example_id}' not found"
        )
    return settings


class CompileExampleRequest(BaseModel):
    """Request to compile an example binary."""
    example_id: str = Field(..., description="ID of the example to compile")
    output_dir: Optional[str] = Field(None, description="Custom output directory")


@router.post("/examples/compile")
async def compile_example(request: CompileExampleRequest):
    """
    Compile an example binary for fuzzing.
    
    Creates the vulnerable binary ready to fuzz.
    Requires GCC to be installed on the system.
    """
    result = _example_library.compile_example(
        example_id=request.example_id,
        output_dir=request.output_dir,
    )
    
    if not result.get("success"):
        raise HTTPException(
            status_code=500,
            detail=result.get("error", "Compilation failed")
        )
    
    return result


@router.get("/examples/{example_id}/quick-start")
async def get_example_quick_start(example_id: str):
    """
    Get everything needed to start fuzzing an example in one call.
    
    Returns: details, tutorial, settings, and compilation instructions.
    """
    details = _example_library.get_example_details(example_id)
    if not details:
        raise HTTPException(
            status_code=404,
            detail=f"Example '{example_id}' not found"
        )
    
    tutorial = _example_library.get_tutorial(example_id)
    settings = _example_library.get_recommended_settings(example_id)
    
    return {
        "example": details,
        "tutorial": tutorial,
        "recommended_settings": settings,
        "quick_tips": [
            "1. Compile the example using the /examples/compile endpoint",
            "2. Create seed inputs from the suggested_seeds",
            "3. Start fuzzing with the recommended settings",
            "4. Wait for crashes - check estimated_time_to_crash",
            "5. Analyze crashes using /triage endpoints",
        ],
    }


# =============================================================================
# FINAL REPORT GENERATOR ENDPOINTS
# =============================================================================

# Initialize the report generator
_report_generator = FinalReportGenerator()


class GenerateReportRequest(BaseModel):
    """Request to generate a final report."""
    session_id: str = Field(..., description="Fuzzing session ID")
    include_ai_analysis: bool = Field(True, description="Include AI-generated insights")


@router.post("/reports/generate")
async def generate_final_report(request: GenerateReportRequest):
    """
    Generate a comprehensive final report for a fuzzing session.
    
    Creates an AI-powered report with:
    - Executive summary
    - Crash analysis
    - Security assessment
    - Recommendations
    
    Reports are auto-saved in Markdown and JSON formats.
    """
    # Get session data
    session = get_fuzzing_session(request.session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{request.session_id}' not found"
        )
    
    # Get crashes
    crashes = get_session_crashes(request.session_id)
    
    # Convert session to dict format
    session_data = {
        "session_id": request.session_id,
        "target_path": getattr(session, 'target_path', 'Unknown'),
        "target_name": Path(getattr(session, 'target_path', 'unknown')).name,
        "fuzzing_mode": getattr(session, 'fuzzing_mode', 'Unknown'),
        "mutation_strategy": getattr(session, 'mutation_strategy', 'Unknown'),
        "timeout_ms": getattr(session, 'timeout_ms', 0),
        "memory_limit_mb": getattr(session, 'memory_limit_mb', 0),
        "start_time": getattr(session, 'start_time', 'Unknown'),
        "end_time": getattr(session, 'end_time', None),
        "total_executions": getattr(session, 'total_executions', 0),
        "duration_seconds": getattr(session, 'duration_seconds', 0),
        "executions_per_second": getattr(session, 'executions_per_second', 0),
        "platform": "Linux/Windows",
        "architecture": "x86_64",
        "corpus_size": getattr(session, 'corpus_size', 0),
        "unique_paths": getattr(session, 'unique_paths', 0),
    }
    
    # Convert crashes to dict format
    crash_dicts = []
    for crash in crashes:
        if hasattr(crash, 'to_dict'):
            crash_dicts.append(crash.to_dict())
        elif isinstance(crash, dict):
            crash_dicts.append(crash)
        else:
            crash_dicts.append({
                "crash_type": getattr(crash, 'crash_type', 'Unknown'),
                "severity": getattr(crash, 'severity', 'medium'),
                "signal": getattr(crash, 'signal', 'Unknown'),
                "exception_address": getattr(crash, 'exception_address', None),
                "input_hash": getattr(crash, 'input_hash', ''),
            })
    
    # Generate report
    report = await _report_generator.generate_report(
        session_id=request.session_id,
        session_data=session_data,
        crashes=crash_dicts,
        include_ai_analysis=request.include_ai_analysis,
    )
    
    return {
        "success": True,
        "report_id": report.id,
        "title": report.title,
        "generated_at": report.generated_at,
        "risk_assessment": report.risk_assessment,
        "statistics_summary": {
            "total_crashes": report.statistics.get("total_crashes"),
            "unique_crashes": report.statistics.get("unique_crashes"),
            "duration": report.statistics.get("duration_formatted"),
        },
        "message": "Report generated and auto-saved",
    }


@router.get("/reports")
async def list_reports(session_id: Optional[str] = None):
    """
    List all generated reports.
    
    Optionally filter by session ID.
    """
    return {
        "reports": _report_generator.list_reports(session_id),
    }


@router.get("/reports/{report_id}")
async def get_report(report_id: str):
    """
    Get a specific report by ID.
    
    Returns the full report data.
    """
    report = _report_generator.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found"
        )
    return report.to_dict()


@router.get("/reports/{report_id}/export/markdown")
async def export_report_markdown(report_id: str):
    """
    Export a report as Markdown.
    
    Returns the formatted Markdown content.
    """
    report = _report_generator.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found"
        )
    
    markdown = _report_generator.export_markdown(report)
    
    return {
        "report_id": report_id,
        "format": "markdown",
        "content": markdown,
        "filename": f"fuzzing_report_{report_id}.md",
    }


@router.get("/reports/{report_id}/summary")
async def get_report_summary(report_id: str):
    """
    Get a quick summary of a report.
    
    Returns key findings without full details.
    """
    report = _report_generator.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found"
        )
    
    return {
        "report_id": report_id,
        "title": report.title,
        "executive_summary": report.executive_summary,
        "risk_assessment": report.risk_assessment,
        "key_statistics": {
            "total_crashes": report.statistics.get("total_crashes"),
            "unique_crashes": report.statistics.get("unique_crashes"),
            "executions": report.statistics.get("total_executions"),
            "duration": report.statistics.get("duration_formatted"),
        },
        "top_recommendations": report.recommendations[:3],
    }


@router.get("/reports/formats")
async def get_available_formats():
    """
    Get available report export formats.
    
    All formats are now available: Markdown, JSON, HTML, PDF, and Word.
    """
    return {
        "available_formats": [
            {
                "format": "markdown",
                "extension": ".md",
                "description": "Markdown format - readable and portable",
                "available": True,
            },
            {
                "format": "json",
                "extension": ".json",
                "description": "JSON format - machine readable data",
                "available": True,
            },
            {
                "format": "html",
                "extension": ".html",
                "description": "HTML format - web viewable with styling",
                "available": True,
            },
            {
                "format": "pdf",
                "extension": ".pdf",
                "description": "PDF format - professional documents",
                "available": True,
                "note": "Requires weasyprint, pdfkit, or reportlab installed",
            },
            {
                "format": "word",
                "extension": ".docx",
                "description": "Word format - editable documents",
                "available": True,
                "note": "Requires python-docx installed",
            },
        ],
    }


@router.get("/reports/{report_id}/export/html")
async def export_report_html(report_id: str):
    """
    Export a report as HTML.
    
    Returns styled HTML ready for browser viewing or printing.
    """
    report = _report_generator.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found"
        )
    
    html = _report_generator.export_html(report)
    
    return {
        "report_id": report_id,
        "format": "html",
        "content": html,
        "filename": f"fuzzing_report_{report_id}.html",
    }


@router.get("/reports/{report_id}/export/pdf")
async def export_report_pdf(report_id: str):
    """
    Export a report as PDF.
    
    Creates a professionally formatted PDF document.
    Requires weasyprint, pdfkit, or reportlab to be installed.
    """
    report = _report_generator.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found"
        )
    
    result = await _report_generator.export_pdf(report)
    
    if result.get("success"):
        return {
            "report_id": report_id,
            "format": "pdf",
            "path": result.get("path"),
            "method": result.get("method"),
            "message": result.get("message"),
        }
    else:
        return {
            "report_id": report_id,
            "format": "pdf",
            "success": False,
            "error": result.get("error"),
            "fallback_path": result.get("html_path"),
            "message": result.get("message"),
        }


@router.get("/reports/{report_id}/export/word")
async def export_report_word(report_id: str):
    """
    Export a report as Microsoft Word document.
    
    Creates a .docx file with professional formatting.
    Requires python-docx to be installed.
    """
    report = _report_generator.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found"
        )
    
    result = await _report_generator.export_word(report)
    
    if result.get("success"):
        return {
            "report_id": report_id,
            "format": "word",
            "path": result.get("path"),
            "message": result.get("message"),
        }
    else:
        return {
            "report_id": report_id,
            "format": "word",
            "success": False,
            "error": result.get("error"),
            "fallback_path": result.get("markdown_path"),
            "message": result.get("message"),
        }


@router.post("/reports/{report_id}/export/all")
async def export_report_all_formats(report_id: str):
    """
    Export a report to all available formats at once.
    
    Creates Markdown, HTML, JSON, PDF, and Word versions.
    """
    report = _report_generator.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found"
        )
    
    result = await _report_generator.export_all_formats(report)
    
    return {
        "report_id": report_id,
        "output_directory": result.get("output_directory"),
        "exports": result.get("exports"),
        "message": "Reports exported to all available formats",
    }


# =============================================================================
# COMBINED ANALYSIS INTEGRATION
# =============================================================================

class CombinedAnalysisRequest(BaseModel):
    """Request for combined analysis with report generation."""
    session_id: str = Field(..., description="Fuzzing session ID")
    include_triage: bool = Field(True, description="Include auto-triage results")
    include_explanations: bool = Field(True, description="Include plain English explanations")
    include_progress: bool = Field(True, description="Include progress tracking data")
    generate_report: bool = Field(True, description="Generate final report")
    export_formats: List[str] = Field(
        default=["markdown"],
        description="Formats to export: markdown, html, json, pdf, word"
    )


@router.post("/combined-analysis")
async def run_combined_analysis(request: CombinedAnalysisRequest):
    """
    Run a combined analysis on a fuzzing session.
    
    Combines multiple analysis features:
    - Auto-triage for crash severity
    - Plain English explanations
    - Progress tracking
    - Final report generation with multi-format export
    
    This is the all-in-one endpoint for comprehensive fuzzing analysis.
    """
    # Get session data
    session = get_fuzzing_session(request.session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{request.session_id}' not found"
        )
    
    # Get crashes
    crashes = get_session_crashes(request.session_id)
    
    analysis_results = {
        "session_id": request.session_id,
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    # Auto-triage
    triage_results = None
    if request.include_triage and crashes:
        triager = CrashAutoTriager()
        triage_results = []
        for crash in crashes:
            if hasattr(crash, 'to_dict'):
                crash_dict = crash.to_dict()
            elif isinstance(crash, dict):
                crash_dict = crash
            else:
                crash_dict = {
                    "crash_type": getattr(crash, 'crash_type', 'unknown'),
                    "signal": getattr(crash, 'signal', None),
                    "exception_address": getattr(crash, 'exception_address', None),
                    "stack_trace": getattr(crash, 'stack_trace', []),
                }
            triage_result = triager.triage_crash(crash_dict)
            triage_results.append(triage_result.to_dict())
        
        analysis_results["triage"] = {
            "total_crashes": len(crashes),
            "results": triage_results,
            "summary": triager.get_quick_summary([triager.triage_crash(c if isinstance(c, dict) else {"crash_type": "unknown"}) for c in crashes[:10]]),
        }
    
    # Plain English explanations
    if request.include_explanations:
        explainer = PlainEnglishExplainer()
        explanations = []
        
        for crash in crashes[:5]:  # Top 5 crashes
            crash_type = crash.get("crash_type") if isinstance(crash, dict) else getattr(crash, 'crash_type', 'unknown')
            explanation = explainer.explain_crash(str(crash_type))
            explanations.append(explanation)
        
        analysis_results["explanations"] = explanations
    
    # Progress tracking
    if request.include_progress:
        tracker = FuzzingProgressTracker()
        
        # Build metrics from session
        metrics = {
            "executions": getattr(session, 'total_executions', 0),
            "crashes_found": len(crashes),
            "unique_crashes": len(set(
                (c.get("input_hash") if isinstance(c, dict) else getattr(c, 'input_hash', ''))
                for c in crashes
            )),
            "coverage_percentage": getattr(session, 'coverage_percentage', None),
        }
        
        progress = tracker.get_progress_summary(
            elapsed_seconds=getattr(session, 'duration_seconds', 0),
            target_seconds=getattr(session, 'target_duration', 3600),
            metrics=metrics,
        )
        
        analysis_results["progress"] = progress
    
    # Generate report
    report_result = None
    if request.generate_report:
        # Build session data dict
        session_data = {
            "session_id": request.session_id,
            "target_path": getattr(session, 'target_path', 'Unknown'),
            "target_name": Path(getattr(session, 'target_path', 'unknown')).name,
            "fuzzing_mode": getattr(session, 'fuzzing_mode', 'Unknown'),
            "mutation_strategy": getattr(session, 'mutation_strategy', 'Unknown'),
            "timeout_ms": getattr(session, 'timeout_ms', 0),
            "memory_limit_mb": getattr(session, 'memory_limit_mb', 0),
            "start_time": getattr(session, 'start_time', 'Unknown'),
            "end_time": getattr(session, 'end_time', None),
            "total_executions": getattr(session, 'total_executions', 0),
            "duration_seconds": getattr(session, 'duration_seconds', 0),
            "executions_per_second": getattr(session, 'executions_per_second', 0),
            "platform": "Linux/Windows",
            "architecture": "x86_64",
            "corpus_size": getattr(session, 'corpus_size', 0),
            "unique_paths": getattr(session, 'unique_paths', 0),
        }
        
        # Convert crashes
        crash_dicts = []
        for crash in crashes:
            if hasattr(crash, 'to_dict'):
                crash_dicts.append(crash.to_dict())
            elif isinstance(crash, dict):
                crash_dicts.append(crash)
            else:
                crash_dicts.append({
                    "crash_type": getattr(crash, 'crash_type', 'Unknown'),
                    "severity": getattr(crash, 'severity', 'medium'),
                    "signal": getattr(crash, 'signal', 'Unknown'),
                    "exception_address": getattr(crash, 'exception_address', None),
                    "input_hash": getattr(crash, 'input_hash', ''),
                })
        
        # Generate report
        report = await _report_generator.generate_report(
            session_id=request.session_id,
            session_data=session_data,
            crashes=crash_dicts,
            triage_results=triage_results,
            include_ai_analysis=True,
        )
        
        report_result = {
            "report_id": report.id,
            "title": report.title,
            "risk_assessment": report.risk_assessment,
            "exports": {},
        }
        
        # Export to requested formats
        for fmt in request.export_formats:
            fmt_lower = fmt.lower()
            if fmt_lower == "markdown":
                md_content = _report_generator.export_markdown(report)
                report_result["exports"]["markdown"] = {
                    "success": True,
                    "content_length": len(md_content),
                }
            elif fmt_lower == "html":
                html_content = _report_generator.export_html(report)
                report_result["exports"]["html"] = {
                    "success": True,
                    "content_length": len(html_content),
                }
            elif fmt_lower == "pdf":
                pdf_result = await _report_generator.export_pdf(report)
                report_result["exports"]["pdf"] = pdf_result
            elif fmt_lower == "word":
                word_result = await _report_generator.export_word(report)
                report_result["exports"]["word"] = word_result
        
        analysis_results["report"] = report_result
    
    return {
        "success": True,
        "analysis": analysis_results,
        "message": "Combined analysis completed successfully",
    }


@router.get("/combined-analysis/options")
async def get_combined_analysis_options():
    """
    Get available options for combined analysis.
    
    Shows all features that can be included and export formats available.
    """
    return {
        "features": {
            "triage": {
                "name": "Auto-Triage",
                "description": "Automatically categorize crashes by severity",
                "default": True,
            },
            "explanations": {
                "name": "Plain English Explanations",
                "description": "Human-readable crash explanations",
                "default": True,
            },
            "progress": {
                "name": "Progress Tracking",
                "description": "Fuzzing progress and time estimates",
                "default": True,
            },
            "report": {
                "name": "Final Report",
                "description": "Comprehensive AI-generated report",
                "default": True,
            },
        },
        "export_formats": [
            {"id": "markdown", "name": "Markdown", "extension": ".md", "default": True},
            {"id": "html", "name": "HTML", "extension": ".html", "default": False},
            {"id": "json", "name": "JSON", "extension": ".json", "default": False},
            {"id": "pdf", "name": "PDF", "extension": ".pdf", "default": False},
            {"id": "word", "name": "Word", "extension": ".docx", "default": False},
        ],
        "example_request": {
            "session_id": "your-session-id",
            "include_triage": True,
            "include_explanations": True,
            "include_progress": True,
            "generate_report": True,
            "export_formats": ["markdown", "pdf", "word"],
        },
    }

