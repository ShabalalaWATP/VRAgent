"""
Reverse Engineering Router for VRAgent.

Provides endpoints for analyzing:
- Binary files (EXE, ELF, DLL, SO)
- Android APK files
- Docker image layers
"""

import shutil
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import asyncio
import json
import uuid
from types import SimpleNamespace

from fastapi import APIRouter, File, HTTPException, UploadFile, Query, Depends
from fastapi.responses import StreamingResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.core.logging import get_logger
from backend.core.database import get_db
from backend.core.config import settings
from backend.services import reverse_engineering_service as re_service

router = APIRouter(prefix="/reverse", tags=["reverse-engineering"])
logger = get_logger(__name__)

# Constants
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB - increased for real-world APKs
ALLOWED_BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".elf", ".bin", ".o", ".dylib", ".mach"}
ALLOWED_APK_EXTENSIONS = {".apk", ".aab"}

# Store active unified scans for cancellation (must be defined before endpoint functions)
_unified_scan_sessions: Dict[str, Dict[str, Any]] = {}
_unified_binary_scan_sessions: Dict[str, Dict[str, Any]] = {}


# ============================================================================
# Response Models
# ============================================================================

class BinaryStringResponse(BaseModel):
    """A string extracted from a binary."""
    value: str
    offset: int
    encoding: str
    category: Optional[str] = None


class ImportedFunctionResponse(BaseModel):
    """An imported function from a binary."""
    name: str
    library: str
    ordinal: Optional[int] = None
    is_suspicious: bool = False
    reason: Optional[str] = None


class RichHeaderEntryResponse(BaseModel):
    """An entry in the PE Rich header."""
    product_id: int
    build_id: int
    count: int
    product_name: Optional[str] = None
    vs_version: Optional[str] = None


class RichHeaderResponse(BaseModel):
    """PE Rich header information for compiler/linker identification."""
    entries: List[RichHeaderEntryResponse]
    rich_hash: str  # MD5 hash for malware identification
    checksum: int
    raw_data: str
    clear_data: str


class BinaryMetadataResponse(BaseModel):
    """Metadata from a binary file."""
    file_type: str
    architecture: str
    file_size: int
    entry_point: Optional[int] = None
    is_packed: bool = False
    packer_name: Optional[str] = None
    compile_time: Optional[str] = None
    sections: List[Dict[str, Any]] = []
    headers: Dict[str, Any] = {}
    # PE-specific
    rich_header: Optional[RichHeaderResponse] = None
    imphash: Optional[str] = None
    tls_callbacks: List[int] = []
    mitigations: Dict[str, Any] = {}
    resource_summary: Dict[str, Any] = {}
    version_info: Dict[str, Any] = {}
    authenticode: Optional[Dict[str, Any]] = None
    overlay: Optional[Dict[str, Any]] = None
    pe_delay_imports: List[Dict[str, Any]] = []
    pe_relocations: Dict[str, Any] = {}
    pe_debug: Dict[str, Any] = {}
    pe_data_directories: List[Dict[str, Any]] = []
    pe_manifest: Optional[str] = None
    # ELF-specific
    relro: Optional[str] = None
    stack_canary: bool = False
    nx_enabled: bool = False
    pie_enabled: bool = False
    interpreter: Optional[str] = None
    linked_libraries: List[str] = []
    elf_dynamic: Dict[str, Any] = {}
    elf_relocations: Dict[str, Any] = {}
    elf_version_info: Dict[str, Any] = {}
    elf_build_id: Optional[str] = None
    elf_program_headers: List[Dict[str, Any]] = []


class HexViewResponse(BaseModel):
    """Response for hex viewer."""
    offset: int
    length: int
    total_size: int
    hex_data: str  # Hex representation
    ascii_preview: str  # ASCII printable chars
    rows: List[Dict[str, Any]]  # Structured hex rows


class SecretResponse(BaseModel):
    """A potential secret found."""
    type: str
    value: str
    masked_value: str
    severity: str
    context: Optional[str] = None
    offset: Optional[int] = None


class SuspiciousIndicatorResponse(BaseModel):
    """A suspicious indicator found in analysis."""
    category: str
    severity: str
    description: str
    details: Optional[Any] = None


class BinaryAnalysisResponse(BaseModel):
    """Complete binary analysis response."""
    filename: str
    metadata: BinaryMetadataResponse
    strings_count: int
    strings_sample: List[BinaryStringResponse]
    imports: List[ImportedFunctionResponse]
    exports: List[str]
    secrets: List[SecretResponse]
    suspicious_indicators: List[SuspiciousIndicatorResponse]
    fuzzy_hashes: Dict[str, Optional[str]] = {}
    yara_matches: List[Dict[str, Any]] = []
    capa_summary: Optional[Dict[str, Any]] = None
    deobfuscated_strings: List[Dict[str, Any]] = []
    ai_analysis: Optional[str] = None
    ghidra_analysis: Optional[Dict[str, Any]] = None
    ghidra_ai_summaries: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None


class UnifiedBinaryScanPhase(BaseModel):
    """A phase in the unified binary scan."""
    id: str
    label: str
    description: str
    status: str  # "pending", "in_progress", "completed", "error"
    progress: int = 0  # 0-100
    details: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class UnifiedBinaryScanProgress(BaseModel):
    """Progress update for unified binary scan."""
    scan_id: str
    current_phase: str
    overall_progress: int  # 0-100
    phases: List[UnifiedBinaryScanPhase]
    message: str
    error: Optional[str] = None


class ApkPermissionResponse(BaseModel):
    """An Android permission."""
    name: str
    is_dangerous: bool
    description: Optional[str] = None


class ApkComponentResponse(BaseModel):
    """An Android app component."""
    name: str
    component_type: str
    is_exported: bool
    intent_filters: List[str] = []


class ApkSecurityIssueResponse(BaseModel):
    """A security issue found in APK."""
    category: str
    severity: str
    description: str
    details: Optional[Any] = None


class ApkAnalysisResponse(BaseModel):
    """Complete APK analysis response."""
    filename: str
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    permissions: List[ApkPermissionResponse]
    dangerous_permissions_count: int
    components: List[ApkComponentResponse]
    strings_count: int
    secrets: List[SecretResponse]
    urls: List[str]
    native_libraries: List[str]
    security_issues: List[ApkSecurityIssueResponse]
    ai_analysis: Optional[str] = None
    ai_report_functionality: Optional[str] = None  # "What does this APK do" report
    ai_report_security: Optional[str] = None  # Security findings report
    ai_architecture_diagram: Optional[str] = None  # AI-generated Mermaid architecture diagram
    ai_data_flow_diagram: Optional[str] = None  # AI-generated Mermaid data flow diagram
    error: Optional[str] = None


class DockerLayerResponse(BaseModel):
    """A Docker image layer."""
    id: str
    command: str
    size: int


class DockerSecretResponse(BaseModel):
    """A secret found in Docker layer."""
    layer_id: str
    layer_command: str
    secret_type: str
    value: str
    masked_value: str
    context: str
    severity: str


class DockerSecurityIssueResponse(BaseModel):
    """A security issue in Docker image."""
    category: str
    severity: str
    description: str
    command: Optional[str] = None


class DockerAnalysisResponse(BaseModel):
    """Complete Docker image analysis response."""
    image_name: str
    image_id: str
    total_layers: int
    total_size: int
    total_size_human: str
    base_image: Optional[str] = None
    layers: List[DockerLayerResponse]
    secrets: List[DockerSecretResponse]
    deleted_files: List[Dict[str, Any]]
    security_issues: List[DockerSecurityIssueResponse]
    ai_analysis: Optional[str] = None
    error: Optional[str] = None


class StatusResponse(BaseModel):
    """Status of reverse engineering capabilities."""
    binary_analysis: bool
    apk_analysis: bool
    docker_analysis: bool
    jadx_available: bool
    ghidra_available: bool
    docker_available: bool
    message: str


# ============================================================================
# Helper Functions
# ============================================================================

def format_size(size_bytes: int) -> str:
    """Format bytes to human readable string."""
    if size_bytes >= 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    elif size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def check_docker_available() -> bool:
    """Check if Docker CLI is available."""
    import subprocess
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False


def check_jadx_available() -> bool:
    """Check if jadx is available for APK decompilation."""
    import subprocess
    try:
        result = subprocess.run(["jadx", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/status", response_model=StatusResponse)
def get_status():
    """
    Check status of reverse engineering capabilities.
    """
    docker_available = check_docker_available()
    jadx_available = check_jadx_available()
    try:
        from backend.services.ghidra_service import ghidra_available
        ghidra_ok = ghidra_available()
    except Exception:
        ghidra_ok = False
    
    return StatusResponse(
        binary_analysis=True,  # Always available (pure Python)
        apk_analysis=True,     # Basic analysis always available
        docker_analysis=docker_available,
        jadx_available=jadx_available,
        ghidra_available=ghidra_ok,
        docker_available=docker_available,
        message="Reverse engineering tools ready" if docker_available else "Docker not available - Docker analysis disabled",
    )


@router.post("/analyze-binary", response_model=BinaryAnalysisResponse)
async def analyze_binary(
    file: UploadFile = File(..., description="Binary file to analyze (EXE, ELF, DLL, SO)"),
    include_ai: bool = Query(True, description="Include AI-powered analysis"),
    include_ghidra: bool = Query(True, description="Include Ghidra headless decompilation"),
    ghidra_max_functions: int = Query(200, ge=1, le=2000, description="Max functions to export from Ghidra"),
    ghidra_decomp_limit: int = Query(4000, ge=200, le=20000, description="Max decompilation chars per function"),
    include_ghidra_ai: bool = Query(True, description="Include Gemini summaries for decompiled functions"),
    ghidra_ai_max_functions: int = Query(20, ge=1, le=200, description="Max functions to summarize with Gemini"),
):
    """
    Analyze a binary executable file.
    
    Extracts:
    - File metadata (type, architecture, entry point)
    - Strings (ASCII and UTF-16)
    - Imported functions (with suspicious API detection)
    - Potential secrets and credentials
    - Packer/obfuscation detection
    
    Supported formats: EXE, DLL, ELF, SO, Mach-O
    """
    # Validate file extension
    filename = file.filename or "unknown"
    suffix = Path(filename).suffix.lower()
    
    # Allow any binary file (we'll detect type from content)
    if suffix not in ALLOWED_BINARY_EXTENSIONS and suffix not in {".bin", ""}:
        # Still allow if no extension - could be ELF
        pass
    
    tmp_dir = None
    try:
        # Save file to temp location
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_binary_"))
        tmp_path = tmp_dir / filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"Analyzing binary: {filename} ({file_size:,} bytes)")
        
        # Perform analysis
        result = re_service.analyze_binary(tmp_path)

        # Run Ghidra decompilation if requested
        if include_ghidra:
            result.ghidra_analysis = re_service.analyze_binary_with_ghidra(
                tmp_path,
                max_functions=ghidra_max_functions,
                decomp_limit=ghidra_decomp_limit,
            )

            if include_ghidra_ai and result.ghidra_analysis and "error" not in result.ghidra_analysis:
                result.ghidra_ai_summaries = await re_service.analyze_ghidra_functions_with_ai(
                    result.ghidra_analysis,
                    max_functions=ghidra_ai_max_functions,
                )

        # Run AI analysis if requested
        if include_ai and not result.error:
            result.ai_analysis = await re_service.analyze_binary_with_ai(result)
        
        # Convert to response model
        # Build rich header response if present
        rich_header_response = None
        if result.metadata.rich_header:
            rich_header_response = RichHeaderResponse(
                entries=[
                    RichHeaderEntryResponse(
                        product_id=e.product_id,
                        build_id=e.build_id,
                        count=e.count,
                        product_name=e.product_name,
                        vs_version=e.vs_version,
                    )
                    for e in result.metadata.rich_header.entries
                ],
                rich_hash=result.metadata.rich_header.rich_hash,
                checksum=result.metadata.rich_header.checksum,
                raw_data=result.metadata.rich_header.raw_data,
                clear_data=result.metadata.rich_header.clear_data,
            )
        
        return BinaryAnalysisResponse(
            filename=result.filename,
            metadata=BinaryMetadataResponse(
                file_type=result.metadata.file_type,
                architecture=result.metadata.architecture,
                file_size=result.metadata.file_size,
                entry_point=result.metadata.entry_point,
                is_packed=result.metadata.is_packed,
                packer_name=result.metadata.packer_name,
                compile_time=result.metadata.compile_time,
                sections=result.metadata.sections,
                headers=result.metadata.headers,
                # PE-specific
                rich_header=rich_header_response,
                imphash=result.metadata.imphash,
                tls_callbacks=result.metadata.tls_callbacks,
                mitigations=result.metadata.mitigations,
                resource_summary=result.metadata.resource_summary,
                version_info=result.metadata.version_info,
                authenticode=result.metadata.authenticode,
                overlay=result.metadata.overlay,
                pe_delay_imports=result.metadata.pe_delay_imports,
                pe_relocations=result.metadata.pe_relocations,
                pe_debug=result.metadata.pe_debug,
                pe_data_directories=result.metadata.pe_data_directories,
                pe_manifest=result.metadata.pe_manifest,
                # ELF-specific
                relro=result.metadata.relro,
                stack_canary=result.metadata.stack_canary,
                nx_enabled=result.metadata.nx_enabled,
                pie_enabled=result.metadata.pie_enabled,
                interpreter=result.metadata.interpreter,
                linked_libraries=result.metadata.linked_libraries,
                elf_dynamic=result.metadata.elf_dynamic,
                elf_relocations=result.metadata.elf_relocations,
                elf_version_info=result.metadata.elf_version_info,
                elf_build_id=result.metadata.elf_build_id,
                elf_program_headers=result.metadata.elf_program_headers,
            ),
            strings_count=len(result.strings),
            strings_sample=[
                BinaryStringResponse(
                    value=s.value[:500],
                    offset=s.offset,
                    encoding=s.encoding,
                    category=s.category,
                )
                for s in result.strings[:200]
            ],
            imports=[
                ImportedFunctionResponse(
                    name=imp.name,
                    library=imp.library,
                    ordinal=imp.ordinal,
                    is_suspicious=imp.is_suspicious,
                    reason=imp.reason,
                )
                for imp in result.imports
            ],
            exports=result.exports,
            secrets=[
                SecretResponse(
                    type=s["type"],
                    value=s["value"],
                    masked_value=s["masked_value"],
                    severity=s["severity"],
                    context=s.get("context"),
                    offset=s.get("offset"),
                )
                for s in result.secrets
            ],
            suspicious_indicators=[
                SuspiciousIndicatorResponse(
                    category=ind["category"],
                    severity=ind["severity"],
                    description=ind["description"],
                    details=ind.get("details"),
                )
                for ind in result.suspicious_indicators
            ],
            fuzzy_hashes=result.fuzzy_hashes,
            yara_matches=result.yara_matches,
            capa_summary=result.capa_summary,
            deobfuscated_strings=result.deobfuscated_strings,
            ai_analysis=result.ai_analysis,
            ghidra_analysis=result.ghidra_analysis,
            ghidra_ai_summaries=result.ghidra_ai_summaries,
            error=result.error,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Binary analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/binary/unified-scan")
async def unified_binary_scan(
    file: UploadFile = File(..., description="Binary file to analyze (EXE, ELF, DLL, SO)"),
    include_ai: bool = Query(True, description="Include AI-powered analysis"),
    include_ghidra: bool = Query(True, description="Include Ghidra headless decompilation"),
    ghidra_max_functions: int = Query(200, ge=1, le=2000, description="Max functions to export from Ghidra"),
    ghidra_decomp_limit: int = Query(4000, ge=200, le=20000, description="Max decompilation chars per function"),
    include_ghidra_ai: bool = Query(True, description="Include Gemini summaries for decompiled functions"),
    ghidra_ai_max_functions: int = Query(20, ge=1, le=200, description="Max functions to summarize with Gemini"),
):
    """
    Perform a complete binary analysis with streaming progress updates.
    This unified scan combines:
    - Static metadata, strings, imports, secrets
    - Optional Ghidra decompilation
    - Optional Gemini function summaries
    - Optional Gemini overall analysis
    """
    filename = file.filename or "unknown"
    suffix = Path(filename).suffix.lower()

    if suffix not in ALLOWED_BINARY_EXTENSIONS and suffix not in {".bin", ""}:
        pass

    tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_binary_unified_"))
    tmp_path = tmp_dir / filename
    file_size = 0

    try:
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)

        scan_id = str(uuid.uuid4())
        _unified_binary_scan_sessions[scan_id] = {"cancelled": False, "tmp_dir": str(tmp_dir)}

        phases: List[UnifiedBinaryScanPhase] = [
            UnifiedBinaryScanPhase(
                id="static",
                label="Static Analysis",
                description="Extract metadata, strings, imports, and secrets",
                status="pending",
            ),
        ]
        if include_ghidra:
            phases.append(UnifiedBinaryScanPhase(
                id="ghidra",
                label="Ghidra Decompilation",
                description="Run headless decompiler and export functions",
                status="pending",
            ))
        if include_ghidra and include_ghidra_ai:
            phases.append(UnifiedBinaryScanPhase(
                id="ghidra_ai",
                label="Ghidra AI Summaries",
                description="Summarize decompiled functions with Gemini",
                status="pending",
            ))
        if include_ai:
            phases.append(UnifiedBinaryScanPhase(
                id="ai_summary",
                label="AI Security Summary",
                description="Generate overall Gemini analysis",
                status="pending",
            ))

        current_phase_idx = 0

        def make_progress(message: str, phase_progress: int = 0) -> str:
            nonlocal phases, current_phase_idx
            overall = (current_phase_idx * 100 // max(len(phases), 1)) + (phase_progress // max(len(phases), 1))
            progress = UnifiedBinaryScanProgress(
                scan_id=scan_id,
                current_phase=phases[current_phase_idx].id,
                overall_progress=min(overall, 100),
                phases=phases,
                message=message,
            )
            return f"data: {json.dumps({'type': 'progress', 'data': progress.model_dump()})}\n\n"

        def update_phase(phase_id: str, status: str, details: str = None, progress: int = 0):
            for p in phases:
                if p.id == phase_id:
                    p.status = status
                    p.progress = progress
                    if details:
                        p.details = details
                    if status == "in_progress" and not p.started_at:
                        p.started_at = datetime.utcnow().isoformat()
                    if status in ("completed", "error"):
                        p.completed_at = datetime.utcnow().isoformat()
                        p.progress = 100

        async def run_unified_scan():
            nonlocal current_phase_idx
            result = None
            try:
                if _unified_binary_scan_sessions.get(scan_id, {}).get("cancelled"):
                    yield f"data: {json.dumps({'type': 'error', 'error': 'Scan cancelled'})}\n\n"
                    yield "data: {\"type\":\"done\"}\n\n"
                    return

                current_phase_idx = 0
                update_phase("static", "in_progress", progress=10)
                yield make_progress("Analyzing binary...", 10)
                result = re_service.analyze_binary(tmp_path)
                update_phase(
                    "static",
                    "completed",
                    f"{len(result.strings)} strings, {len(result.imports)} imports",
                    100,
                )
                yield make_progress("Static analysis complete", 100)

                if _unified_binary_scan_sessions.get(scan_id, {}).get("cancelled"):
                    yield f"data: {json.dumps({'type': 'error', 'error': 'Scan cancelled'})}\n\n"
                    yield "data: {\"type\":\"done\"}\n\n"
                    return

                if include_ghidra:
                    current_phase_idx = 1
                    update_phase("ghidra", "in_progress", progress=10)
                    yield make_progress("Running Ghidra decompilation...", 10)
                    result.ghidra_analysis = re_service.analyze_binary_with_ghidra(
                        tmp_path,
                        max_functions=ghidra_max_functions,
                        decomp_limit=ghidra_decomp_limit,
                    )
                    if result.ghidra_analysis and "error" in result.ghidra_analysis:
                        update_phase("ghidra", "error", result.ghidra_analysis.get("error"), 100)
                    else:
                        fn_total = (result.ghidra_analysis or {}).get("functions_total", 0)
                        update_phase("ghidra", "completed", f"Exported {fn_total} functions", 100)
                    yield make_progress("Ghidra decompilation complete", 100)

                    if _unified_binary_scan_sessions.get(scan_id, {}).get("cancelled"):
                        yield f"data: {json.dumps({'type': 'error', 'error': 'Scan cancelled'})}\n\n"
                        yield "data: {\"type\":\"done\"}\n\n"
                        return

                if include_ghidra and include_ghidra_ai:
                    current_phase_idx = 2
                    update_phase("ghidra_ai", "in_progress", progress=10)
                    yield make_progress("Summarizing functions with Gemini...", 10)
                    if result and result.ghidra_analysis and "error" not in result.ghidra_analysis:
                        result.ghidra_ai_summaries = await re_service.analyze_ghidra_functions_with_ai(
                            result.ghidra_analysis,
                            max_functions=ghidra_ai_max_functions,
                        )
                    update_phase("ghidra_ai", "completed", "Function summaries generated", 100)
                    yield make_progress("Ghidra AI summaries complete", 100)

                    if _unified_binary_scan_sessions.get(scan_id, {}).get("cancelled"):
                        yield f"data: {json.dumps({'type': 'error', 'error': 'Scan cancelled'})}\n\n"
                        yield "data: {\"type\":\"done\"}\n\n"
                        return

                if include_ai and result and not result.error:
                    current_phase_idx = len(phases) - 1
                    update_phase("ai_summary", "in_progress", progress=10)
                    yield make_progress("Generating AI security summary...", 10)
                    result.ai_analysis = await re_service.analyze_binary_with_ai(result)
                    update_phase("ai_summary", "completed", "AI summary generated", 100)
                    yield make_progress("AI summary complete", 100)

                if not result:
                    yield f"data: {json.dumps({'type': 'error', 'error': 'Analysis failed'})}\n\n"
                    yield "data: {\"type\":\"done\"}\n\n"
                    return

                rich_header_response = None
                if result.metadata.rich_header:
                    rich_header_response = RichHeaderResponse(
                        entries=[
                            RichHeaderEntryResponse(
                                product_id=e.product_id,
                                build_id=e.build_id,
                                count=e.count,
                                product_name=e.product_name,
                                vs_version=e.vs_version,
                            )
                            for e in result.metadata.rich_header.entries
                        ],
                        rich_hash=result.metadata.rich_header.rich_hash,
                        checksum=result.metadata.rich_header.checksum,
                        raw_data=result.metadata.rich_header.raw_data,
                        clear_data=result.metadata.rich_header.clear_data,
                    )

                response = BinaryAnalysisResponse(
                    filename=result.filename,
                    metadata=BinaryMetadataResponse(
                        file_type=result.metadata.file_type,
                        architecture=result.metadata.architecture,
                        file_size=result.metadata.file_size,
                        entry_point=result.metadata.entry_point,
                        is_packed=result.metadata.is_packed,
                        packer_name=result.metadata.packer_name,
                        compile_time=result.metadata.compile_time,
                        sections=result.metadata.sections,
                        headers=result.metadata.headers,
                        rich_header=rich_header_response,
                        imphash=result.metadata.imphash,
                        tls_callbacks=result.metadata.tls_callbacks,
                        mitigations=result.metadata.mitigations,
                        resource_summary=result.metadata.resource_summary,
                        version_info=result.metadata.version_info,
                        authenticode=result.metadata.authenticode,
                        overlay=result.metadata.overlay,
                        pe_delay_imports=result.metadata.pe_delay_imports,
                        pe_relocations=result.metadata.pe_relocations,
                        pe_debug=result.metadata.pe_debug,
                        pe_data_directories=result.metadata.pe_data_directories,
                        pe_manifest=result.metadata.pe_manifest,
                        relro=result.metadata.relro,
                        stack_canary=result.metadata.stack_canary,
                        nx_enabled=result.metadata.nx_enabled,
                        pie_enabled=result.metadata.pie_enabled,
                        interpreter=result.metadata.interpreter,
                        linked_libraries=result.metadata.linked_libraries,
                        elf_dynamic=result.metadata.elf_dynamic,
                        elf_relocations=result.metadata.elf_relocations,
                        elf_version_info=result.metadata.elf_version_info,
                        elf_build_id=result.metadata.elf_build_id,
                        elf_program_headers=result.metadata.elf_program_headers,
                    ),
                    strings_count=len(result.strings),
                    strings_sample=[
                        BinaryStringResponse(
                            value=s.value[:500],
                            offset=s.offset,
                            encoding=s.encoding,
                            category=s.category,
                        )
                        for s in result.strings[:200]
                    ],
                    imports=[
                        ImportedFunctionResponse(
                            name=imp.name,
                            library=imp.library,
                            ordinal=imp.ordinal,
                            is_suspicious=imp.is_suspicious,
                            reason=imp.reason,
                        )
                        for imp in result.imports
                    ],
                    exports=result.exports,
                    secrets=[
                        SecretResponse(
                            type=s["type"],
                            value=s["value"],
                            masked_value=s["masked_value"],
                            severity=s["severity"],
                            context=s.get("context"),
                            offset=s.get("offset"),
                        )
                        for s in result.secrets
                    ],
                    suspicious_indicators=[
                        SuspiciousIndicatorResponse(
                            category=ind["category"],
                            severity=ind["severity"],
                            description=ind["description"],
                            details=ind.get("details"),
                        )
                        for ind in result.suspicious_indicators
                    ],
                    fuzzy_hashes=result.fuzzy_hashes,
                    yara_matches=result.yara_matches,
                    capa_summary=result.capa_summary,
                    deobfuscated_strings=result.deobfuscated_strings,
                    ai_analysis=result.ai_analysis,
                    ghidra_analysis=result.ghidra_analysis,
                    ghidra_ai_summaries=result.ghidra_ai_summaries,
                    error=result.error,
                )

                yield f"data: {json.dumps({'type': 'result', 'data': response.model_dump()})}\n\n"
                yield "data: {\"type\":\"done\"}\n\n"

            except Exception as exc:
                logger.error(f"Unified binary scan failed: {exc}")
                yield f"data: {json.dumps({'type': 'error', 'error': str(exc)})}\n\n"
                yield "data: {\"type\":\"done\"}\n\n"
            finally:
                if scan_id in _unified_binary_scan_sessions:
                    del _unified_binary_scan_sessions[scan_id]
                if tmp_dir:
                    shutil.rmtree(tmp_dir, ignore_errors=True)

        return StreamingResponse(
            run_unified_scan(),
            media_type="text/event-stream",
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Unified binary scan failed: {exc}")
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(exc)}")


@router.post("/binary/unified-scan/{scan_id}/cancel")
async def cancel_unified_binary_scan(scan_id: str):
    """Cancel an in-progress unified binary scan."""
    if scan_id in _unified_binary_scan_sessions:
        _unified_binary_scan_sessions[scan_id]["cancelled"] = True
        return {"message": "Binary scan cancelled"}
    raise HTTPException(status_code=404, detail="Scan not found")


# ============================================================================
# AI Vulnerability Hunter
# ============================================================================

# Store active vulnerability hunts for cancellation
_vulnerability_hunt_sessions: Dict[str, Dict[str, Any]] = {}


class VulnerabilityHuntPhase(BaseModel):
    """A phase in the vulnerability hunt."""
    id: str
    label: str
    description: str
    status: str  # "pending", "in_progress", "completed", "error"
    progress: int = 0
    details: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class VulnerabilityHuntProgress(BaseModel):
    """Progress update for vulnerability hunt."""
    scan_id: str
    current_phase: str
    overall_progress: int
    phases: List[VulnerabilityHuntPhase]
    message: str
    targets_identified: int = 0
    vulnerabilities_found: int = 0


class VulnerabilityFindingResponse(BaseModel):
    """A vulnerability finding from the hunt."""
    id: str
    title: str
    severity: str
    category: str
    cwe_id: Optional[str] = None
    cvss_estimate: float
    function_name: str
    entry_address: str
    description: str
    technical_details: str
    proof_of_concept: str
    exploitation_steps: List[str]
    remediation: str
    confidence: float
    ai_reasoning: str
    code_snippet: str


class VulnerabilityHuntResultResponse(BaseModel):
    """Complete result of a vulnerability hunt."""
    scan_id: str
    filename: str
    passes_completed: int
    total_functions_analyzed: int
    targets_identified: int
    vulnerabilities: List[VulnerabilityFindingResponse]
    attack_surface_summary: Dict[str, Any]
    hunting_log: List[Dict[str, Any]]
    executive_summary: str
    risk_score: int
    recommended_focus_areas: List[str]


@router.post("/binary/vulnerability-hunt")
async def vulnerability_hunt(
    file: UploadFile = File(..., description="Binary file to analyze (EXE, ELF, DLL, SO)"),
    focus_categories: Optional[str] = Query(
        None, 
        description="Comma-separated vulnerability categories to focus on (buffer_overflow,format_string,integer_overflow,use_after_free,command_injection,path_traversal,race_condition,crypto_weakness)"
    ),
    max_passes: int = Query(3, ge=1, le=5, description="Maximum analysis passes"),
    max_targets_per_pass: int = Query(20, ge=5, le=50, description="Max targets to analyze per pass"),
    ghidra_max_functions: int = Query(500, ge=100, le=2000, description="Max functions for Ghidra to export"),
    ghidra_decomp_limit: int = Query(8000, ge=2000, le=20000, description="Max decompilation chars per function"),
):
    """
    AI-powered autonomous vulnerability hunting.
    
    Performs multi-pass analysis:
    1. **Pass 1 - Reconnaissance**: Ghidra decompilation + identify dangerous function calls
    2. **Pass 2 - AI Triage**: AI identifies highest-priority targets for deep analysis
    3. **Pass 3+ - Deep Analysis**: AI performs thorough vulnerability analysis on each target
    
    Streams progress updates via Server-Sent Events.
    
    Returns findings with:
    - Vulnerability details and severity
    - CWE classification and CVSS estimate
    - Proof of concept code
    - Exploitation steps
    - Remediation recommendations
    
    Categories: buffer_overflow, format_string, integer_overflow, use_after_free,
    command_injection, path_traversal, race_condition, crypto_weakness
    """
    filename = file.filename or "unknown"
    suffix = Path(filename).suffix.lower()
    
    if suffix not in ALLOWED_BINARY_EXTENSIONS and suffix not in {".bin", ""}:
        pass  # Allow any file for analysis
    
    tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_vuln_hunt_"))
    tmp_path = tmp_dir / filename
    file_size = 0
    
    try:
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        scan_id = str(uuid.uuid4())
        _vulnerability_hunt_sessions[scan_id] = {"cancelled": False, "tmp_dir": str(tmp_dir)}
        
        # Parse focus categories
        categories = None
        if focus_categories:
            categories = [c.strip() for c in focus_categories.split(",")]
        
        # Build phases
        phases: List[VulnerabilityHuntPhase] = [
            VulnerabilityHuntPhase(
                id="pass1",
                label="Reconnaissance",
                description="Ghidra decompilation and attack surface mapping",
                status="pending",
            ),
            VulnerabilityHuntPhase(
                id="pass2",
                label="AI Triage",
                description="AI identifies high-priority targets",
                status="pending",
            ),
        ]
        for i in range(3, max_passes + 1):
            phases.append(VulnerabilityHuntPhase(
                id=f"pass{i}",
                label=f"Deep Analysis Pass {i-2}",
                description="AI deep vulnerability analysis",
                status="pending",
            ))
        phases.append(VulnerabilityHuntPhase(
            id="summary",
            label="Summary",
            description="Generate executive summary",
            status="pending",
        ))
        
        current_phase_idx = 0
        targets_identified = 0
        vulns_found = 0
        
        def make_progress(message: str, phase_progress: int = 0) -> str:
            nonlocal phases, current_phase_idx, targets_identified, vulns_found
            overall = (current_phase_idx * 100 // max(len(phases), 1)) + (phase_progress // max(len(phases), 1))
            progress = VulnerabilityHuntProgress(
                scan_id=scan_id,
                current_phase=phases[current_phase_idx].id,
                overall_progress=min(overall, 100),
                phases=phases,
                message=message,
                targets_identified=targets_identified,
                vulnerabilities_found=vulns_found,
            )
            return f"data: {json.dumps({'type': 'progress', 'data': progress.model_dump()})}\n\n"
        
        def update_phase(phase_id: str, status: str, details: str = None, progress: int = 0):
            for p in phases:
                if p.id == phase_id:
                    p.status = status
                    p.progress = progress
                    if details:
                        p.details = details
                    if status == "in_progress" and not p.started_at:
                        p.started_at = datetime.utcnow().isoformat()
                    if status in ("completed", "error"):
                        p.completed_at = datetime.utcnow().isoformat()
                        p.progress = 100
        
        async def run_vulnerability_hunt():
            nonlocal current_phase_idx, targets_identified, vulns_found
            
            try:
                if _vulnerability_hunt_sessions.get(scan_id, {}).get("cancelled"):
                    yield f"data: {json.dumps({'type': 'error', 'error': 'Hunt cancelled'})}\n\n"
                    yield "data: {\"type\":\"done\"}\n\n"
                    return
                
                # Progress callback for the hunt
                async def on_progress(phase: str, progress: int, message: str):
                    nonlocal current_phase_idx, targets_identified, vulns_found
                    
                    # Map service phases to router phases
                    phase_map = {
                        "pass1": 0,
                        "pass2": 1,
                        "pass3": 2,
                        "pass4": 3,
                        "pass5": 4,
                        "summary": len(phases) - 1,
                        "complete": len(phases) - 1,
                    }
                    if phase in phase_map:
                        current_phase_idx = min(phase_map[phase], len(phases) - 1)
                    
                    # Update phase status
                    current_id = phases[current_phase_idx].id
                    if progress == 0:
                        update_phase(current_id, "in_progress", message, 0)
                    elif progress >= 100:
                        update_phase(current_id, "completed", message, 100)
                    else:
                        update_phase(current_id, "in_progress", message, progress)
                
                # Yield initial progress
                yield make_progress("Starting AI vulnerability hunt...", 0)
                
                # Run the hunt
                result = await re_service.ai_vulnerability_hunt(
                    tmp_path,
                    focus_categories=categories,
                    max_passes=max_passes,
                    max_targets_per_pass=max_targets_per_pass,
                    ghidra_max_functions=ghidra_max_functions,
                    ghidra_decomp_limit=ghidra_decomp_limit,
                    on_progress=on_progress,
                )
                
                targets_identified = result.targets_identified
                vulns_found = len(result.vulnerabilities)
                
                # Convert to response
                response = re_service.vulnerability_hunt_result_to_dict(result)
                
                # Final progress
                update_phase("summary", "completed", f"Found {vulns_found} vulnerabilities", 100)
                yield make_progress(f"Hunt complete: {vulns_found} vulnerabilities found", 100)
                
                # Yield final result
                yield f"data: {json.dumps({'type': 'result', 'data': response})}\n\n"
                yield "data: {\"type\":\"done\"}\n\n"
                
            except Exception as exc:
                logger.exception(f"Vulnerability hunt failed: {exc}")
                yield f"data: {json.dumps({'type': 'error', 'error': str(exc)})}\n\n"
                yield "data: {\"type\":\"done\"}\n\n"
            finally:
                # Cleanup in background
                try:
                    if scan_id in _vulnerability_hunt_sessions:
                        del _vulnerability_hunt_sessions[scan_id]
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except:
                    pass
        
        return StreamingResponse(
            run_vulnerability_hunt(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            }
        )
        
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Vulnerability hunt failed: {exc}")
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Hunt failed: {str(exc)}")


@router.post("/binary/vulnerability-hunt/{scan_id}/cancel")
async def cancel_vulnerability_hunt(scan_id: str):
    """Cancel an in-progress vulnerability hunt."""
    if scan_id in _vulnerability_hunt_sessions:
        _vulnerability_hunt_sessions[scan_id]["cancelled"] = True
        return {"message": "Vulnerability hunt cancelled"}
    raise HTTPException(status_code=404, detail="Hunt not found")


# ============================================================================
# Binary Purpose Analysis ("What does this Binary do?")
# ============================================================================

class BinaryPurposeProgress(BaseModel):
    """Progress update for binary purpose analysis."""
    phase: str
    progress: int
    message: str


class SuspiciousBehavior(BaseModel):
    """A suspicious behavior identified in the binary."""
    behavior: str
    severity: str  # low, medium, high, critical
    indicator: str


class BinaryPurposeResponse(BaseModel):
    """Response from binary purpose analysis."""
    filename: str
    purpose_summary: str
    detailed_description: str
    category: str
    functionality: List[str]
    capabilities: Dict[str, List[str]]
    api_usage: Dict[str, List[str]]
    suspicious_behaviors: List[SuspiciousBehavior]
    data_handling: Dict[str, Any]
    network_activity: Dict[str, Any]
    file_operations: Dict[str, Any]
    process_operations: Dict[str, Any]
    crypto_usage: Dict[str, Any]
    ui_type: str
    confidence: float
    analysis_notes: List[str]


@router.post("/binary/analyze-purpose")
async def analyze_binary_purpose(
    file: UploadFile = File(..., description="Binary file to analyze"),
    use_ghidra: bool = Query(True, description="Use Ghidra for deeper analysis"),
):
    """
    Analyze a binary to understand what it does.
    
    Provides:
    - Purpose summary and detailed description
    - Category classification (utility, malware, game, server, etc.)
    - Functionality list
    - API usage by category (file, network, process, crypto, etc.)
    - Suspicious behavior detection
    - Data handling analysis
    - Network activity patterns
    - UI type detection
    
    Streams progress updates via Server-Sent Events.
    """
    filename = file.filename or "unknown"
    suffix = Path(filename).suffix.lower()
    
    tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_purpose_"))
    tmp_path = tmp_dir / filename
    
    try:
        # Save file
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=400, detail=f"File too large (max {MAX_FILE_SIZE // (1024*1024)}MB)")
                f.write(chunk)
        
        logger.info(f"Analyzing binary purpose: {filename} ({file_size:,} bytes)")
        
        # Track progress
        progress_updates = []
        
        async def progress_callback(phase: str, pct: int, msg: str):
            progress_updates.append({"phase": phase, "progress": pct, "message": msg})
        
        # SSE generator
        async def generate_events():
            try:
                # Run analysis in background
                analysis_task = asyncio.create_task(
                    re_service.analyze_binary_purpose(
                        tmp_path,
                        use_ghidra=use_ghidra,
                        progress_callback=progress_callback,
                    )
                )
                
                last_idx = 0
                while not analysis_task.done():
                    # Send any new progress updates
                    while last_idx < len(progress_updates):
                        update = progress_updates[last_idx]
                        yield f"data: {json.dumps({'type': 'progress', 'data': update})}\n\n"
                        last_idx += 1
                    await asyncio.sleep(0.3)
                
                # Get result
                result = await analysis_task
                result_dict = re_service.binary_purpose_to_dict(result)
                
                yield f"data: {json.dumps({'type': 'result', 'data': result_dict})}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                
            except Exception as e:
                logger.error(f"Binary purpose analysis failed: {e}")
                yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
        
        return StreamingResponse(
            generate_events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            }
        )
        
    except Exception as exc:
        logger.error(f"Binary purpose analysis failed: {exc}")
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(exc)}")


# ============================================================================
# Proof-of-Concept Exploit Generation
# ============================================================================

class PoCExploitRequest(BaseModel):
    """Request to generate a PoC exploit."""
    vulnerability: Dict[str, Any] = Field(..., description="The vulnerability finding to generate exploit for")
    target_platform: str = Field("linux", description="Target platform: linux, windows, both")
    exploit_style: str = Field("python", description="Exploit language: python, c, shellcode")
    include_shellcode: bool = Field(False, description="Include raw shellcode in exploit")


class PoCExploitResponse(BaseModel):
    """A proof-of-concept exploit."""
    vuln_id: str
    vuln_title: str
    exploit_type: str
    language: str
    code: str
    description: str
    prerequisites: List[str]
    usage_instructions: str
    expected_outcome: str
    limitations: List[str]
    safety_notes: List[str]
    tested_on: str
    reliability: str
    evasion_notes: List[str]


class MultiplePoCRequest(BaseModel):
    """Request to generate multiple PoC exploits."""
    vulnerabilities: List[Dict[str, Any]] = Field(..., description="List of vulnerability findings")
    target_platform: str = Field("linux", description="Target platform: linux, windows, both")
    exploit_style: str = Field("python", description="Exploit language: python, c, shellcode")


class MultiplePoCResponse(BaseModel):
    """Response containing multiple PoC exploits."""
    success: bool
    exploits: List[PoCExploitResponse]
    generation_log: List[str]
    warnings: List[str]
    disclaimer: str


@router.post("/binary/generate-poc", response_model=PoCExploitResponse)
async def generate_poc_exploit(request: PoCExploitRequest):
    """
    Generate a proof-of-concept exploit for a vulnerability.
    
    Supports various vulnerability types:
    - Buffer overflows
    - Format string bugs
    - Use-after-free
    - Command injection
    - Integer overflows
    - Path traversal
    
    Returns working exploit code with:
    - Full commented code
    - Prerequisites and setup instructions
    - Usage instructions
    - Expected outcome
    - Safety notes and legal warnings
    """
    logger.info(f"Generating PoC for: {request.vulnerability.get('title', 'unknown')}")
    
    try:
        result = await re_service.generate_poc_exploit(
            vulnerability=request.vulnerability,
            target_platform=request.target_platform,
            exploit_style=request.exploit_style,
            include_shellcode=request.include_shellcode,
        )
        
        return PoCExploitResponse(
            vuln_id=result.vuln_id,
            vuln_title=result.vuln_title,
            exploit_type=result.exploit_type,
            language=result.language,
            code=result.code,
            description=result.description,
            prerequisites=result.prerequisites,
            usage_instructions=result.usage_instructions,
            expected_outcome=result.expected_outcome,
            limitations=result.limitations,
            safety_notes=result.safety_notes,
            tested_on=result.tested_on,
            reliability=result.reliability,
            evasion_notes=result.evasion_notes,
        )
        
    except Exception as e:
        logger.error(f"PoC generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate PoC: {str(e)}")


@router.post("/binary/generate-pocs", response_model=MultiplePoCResponse)
async def generate_multiple_pocs(request: MultiplePoCRequest):
    """
    Generate proof-of-concept exploits for multiple vulnerabilities.
    
    Batch generates exploits for all provided vulnerabilities.
    Returns a summary with all generated exploits and any failures.
    """
    logger.info(f"Generating PoCs for {len(request.vulnerabilities)} vulnerabilities")
    
    try:
        result = await re_service.generate_multiple_pocs(
            vulnerabilities=request.vulnerabilities,
            target_platform=request.target_platform,
            exploit_style=request.exploit_style,
        )
        
        return MultiplePoCResponse(
            success=result.success,
            exploits=[
                PoCExploitResponse(
                    vuln_id=e.vuln_id,
                    vuln_title=e.vuln_title,
                    exploit_type=e.exploit_type,
                    language=e.language,
                    code=e.code,
                    description=e.description,
                    prerequisites=e.prerequisites,
                    usage_instructions=e.usage_instructions,
                    expected_outcome=e.expected_outcome,
                    limitations=e.limitations,
                    safety_notes=e.safety_notes,
                    tested_on=e.tested_on,
                    reliability=e.reliability,
                    evasion_notes=e.evasion_notes,
                )
                for e in result.exploits
            ],
            generation_log=result.generation_log,
            warnings=result.warnings,
            disclaimer=result.disclaimer,
        )
        
    except Exception as e:
        logger.error(f"Multiple PoC generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate PoCs: {str(e)}")


# ============================================================================
# AI Chat for Analysis Context
# ============================================================================

class ChatMessage(BaseModel):
    """A single chat message."""
    role: str  # "user" or "assistant"
    content: str

class AnalysisChatRequest(BaseModel):
    """Request for chatting about analysis results."""
    message: str = Field(..., description="User's question")
    conversation_history: List[ChatMessage] = Field(default_factory=list, description="Previous messages")
    analysis_context: Dict[str, Any] = Field(..., description="Analysis context (vulnerabilities, purpose, etc.)")

class AnalysisChatResponse(BaseModel):
    """Response from the chat endpoint."""
    response: str
    error: Optional[str] = None

@router.post("/chat", response_model=AnalysisChatResponse)
async def chat_about_analysis(request: AnalysisChatRequest):
    """
    Chat with AI about vulnerability analysis results.
    
    Allows users to ask follow-up questions about:
    - Discovered vulnerabilities
    - Binary purpose analysis
    - PoC exploits
    - Remediation strategies
    - Technical details
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        return AnalysisChatResponse(
            response="",
            error="Chat unavailable: GEMINI_API_KEY not configured"
        )
    
    try:
        from google import genai
        from google.genai import types
        import json
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Extract context components
        binary_info = request.analysis_context.get("binary_info", {})
        purpose_analysis = request.analysis_context.get("purpose_analysis", {})
        vulnerabilities = request.analysis_context.get("vulnerabilities", [])
        poc_exploits = request.analysis_context.get("poc_exploits", [])
        attack_surface = request.analysis_context.get("attack_surface", {})
        hunt_result = request.analysis_context.get("hunt_result", {})
        
        # Build the system context
        context = f"""You are an expert binary security analyst and reverse engineering assistant. You have analyzed a binary file and have detailed context about its vulnerabilities, purpose, and security characteristics.

## BINARY ANALYSIS CONTEXT

### Binary Information
{json.dumps(binary_info, indent=2) if binary_info else "No binary info available."}

### Binary Purpose Analysis
{json.dumps(purpose_analysis, indent=2) if purpose_analysis else "Not yet analyzed for purpose."}

### Discovered Vulnerabilities ({len(vulnerabilities)} total)
{json.dumps(vulnerabilities[:10], indent=2) if vulnerabilities else "No vulnerabilities discovered yet."}
{f"... and {len(vulnerabilities) - 10} more" if len(vulnerabilities) > 10 else ""}

### Generated PoC Exploits ({len(poc_exploits)} total)
{json.dumps(poc_exploits[:5], indent=2) if poc_exploits else "No PoC exploits generated."}

### Attack Surface Summary
{json.dumps(attack_surface, indent=2) if attack_surface else "Not yet mapped."}

### Hunt Result Summary
- Risk Score: {hunt_result.get('risk_score', 'N/A')}
- Total Functions Analyzed: {hunt_result.get('total_functions_analyzed', 'N/A')}
- Executive Summary: {hunt_result.get('executive_summary', 'N/A')}
- Recommended Focus Areas: {json.dumps(hunt_result.get('recommended_focus_areas', []), indent=2)}

---

## YOUR ROLE
- Answer questions about the vulnerabilities, their severity, and exploitation
- Explain technical details in a clear way
- Provide remediation guidance and security best practices
- Help interpret the analysis results
- Suggest additional testing or analysis if relevant
- If asked about exploitation, always remind users that testing should only be done on authorized systems

Be precise, technical when needed, and always reference specific findings from the analysis when relevant. If a question is outside the scope of the analysis, let the user know what information is available."""

        # Build conversation history for multi-turn chat
        contents = []
        contents.append(types.Content(
            role="user",
            parts=[types.Part(text=context + "\n\nThe user's first question is below.")]
        ))
        
        # Add conversation history
        for msg in request.conversation_history:
            contents.append(types.Content(
                role="user" if msg.role == "user" else "model",
                parts=[types.Part(text=msg.content)]
            ))
        
        # Add current message
        contents.append(types.Content(
            role="user",
            parts=[types.Part(text=request.message)]
        ))
        
        # Generate response
        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=contents
        )
        
        return AnalysisChatResponse(response=response.text)
        
    except Exception as e:
        logger.error(f"Analysis chat error: {e}")
        return AnalysisChatResponse(
            response="",
            error=f"Failed to generate response: {str(e)}"
        )


# ============================================================================
# Notes Management
# ============================================================================

class AnalysisNote(BaseModel):
    """A note associated with analysis."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    vulnerability_id: Optional[str] = None
    category: str = "general"  # general, vulnerability, poc, remediation
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: Optional[str] = None

class NotesStore(BaseModel):
    """Collection of notes for an analysis session."""
    session_id: str
    binary_name: str
    notes: List[AnalysisNote] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class CreateNoteRequest(BaseModel):
    """Request to create a new note."""
    session_id: str
    binary_name: str
    content: str
    vulnerability_id: Optional[str] = None
    category: str = "general"

class UpdateNoteRequest(BaseModel):
    """Request to update an existing note."""
    session_id: str
    note_id: str
    content: str

class DeleteNoteRequest(BaseModel):
    """Request to delete a note."""
    session_id: str
    note_id: str

class ExportNotesRequest(BaseModel):
    """Request to export notes."""
    session_id: str
    format: str = "markdown"  # markdown, json, txt

# In-memory storage for notes (in production, use database)
_notes_storage: Dict[str, NotesStore] = {}

@router.post("/notes/create", response_model=AnalysisNote)
async def create_note(request: CreateNoteRequest):
    """Create a new note for the analysis session."""
    session_id = request.session_id
    
    # Initialize session if needed
    if session_id not in _notes_storage:
        _notes_storage[session_id] = NotesStore(
            session_id=session_id,
            binary_name=request.binary_name
        )
    
    # Create new note
    note = AnalysisNote(
        content=request.content,
        vulnerability_id=request.vulnerability_id,
        category=request.category
    )
    
    _notes_storage[session_id].notes.append(note)
    
    logger.info(f"Created note {note.id} for session {session_id}")
    return note


@router.post("/notes/list", response_model=NotesStore)
async def list_notes(session_id: str):
    """List all notes for an analysis session."""
    if session_id not in _notes_storage:
        return NotesStore(session_id=session_id, binary_name="Unknown")
    
    return _notes_storage[session_id]


@router.post("/notes/update", response_model=AnalysisNote)
async def update_note(request: UpdateNoteRequest):
    """Update an existing note."""
    if request.session_id not in _notes_storage:
        raise HTTPException(status_code=404, detail="Session not found")
    
    store = _notes_storage[request.session_id]
    for note in store.notes:
        if note.id == request.note_id:
            note.content = request.content
            note.updated_at = datetime.utcnow().isoformat()
            logger.info(f"Updated note {note.id}")
            return note
    
    raise HTTPException(status_code=404, detail="Note not found")


@router.delete("/notes/delete")
async def delete_note(request: DeleteNoteRequest):
    """Delete a note."""
    if request.session_id not in _notes_storage:
        raise HTTPException(status_code=404, detail="Session not found")
    
    store = _notes_storage[request.session_id]
    original_length = len(store.notes)
    store.notes = [n for n in store.notes if n.id != request.note_id]
    
    if len(store.notes) == original_length:
        raise HTTPException(status_code=404, detail="Note not found")
    
    logger.info(f"Deleted note {request.note_id}")
    return {"status": "deleted", "note_id": request.note_id}


@router.post("/notes/export")
async def export_notes(request: ExportNotesRequest):
    """Export notes in the specified format."""
    if request.session_id not in _notes_storage:
        raise HTTPException(status_code=404, detail="Session not found")
    
    store = _notes_storage[request.session_id]
    
    if request.format == "json":
        return {
            "format": "json",
            "content": store.model_dump(),
            "filename": f"{store.binary_name}_notes.json"
        }
    
    elif request.format == "markdown":
        md_content = f"# Analysis Notes: {store.binary_name}\n\n"
        md_content += f"*Session: {store.session_id}*\n"
        md_content += f"*Created: {store.created_at}*\n\n"
        
        # Group by category
        categories = {}
        for note in store.notes:
            cat = note.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(note)
        
        for category, notes in categories.items():
            md_content += f"## {category.title()} Notes\n\n"
            for note in notes:
                md_content += f"### Note ({note.created_at})\n"
                if note.vulnerability_id:
                    md_content += f"*Linked to vulnerability: {note.vulnerability_id}*\n\n"
                md_content += f"{note.content}\n\n"
                md_content += "---\n\n"
        
        return {
            "format": "markdown",
            "content": md_content,
            "filename": f"{store.binary_name}_notes.md"
        }
    
    else:  # txt
        txt_content = f"Analysis Notes: {store.binary_name}\n"
        txt_content += f"Session: {store.session_id}\n"
        txt_content += f"Created: {store.created_at}\n"
        txt_content += "=" * 50 + "\n\n"
        
        for note in store.notes:
            txt_content += f"[{note.category.upper()}] {note.created_at}\n"
            if note.vulnerability_id:
                txt_content += f"Vulnerability: {note.vulnerability_id}\n"
            txt_content += "-" * 30 + "\n"
            txt_content += f"{note.content}\n\n"
        
        return {
            "format": "txt",
            "content": txt_content,
            "filename": f"{store.binary_name}_notes.txt"
        }


# ============================================================================
# AI Decompiler Enhancement
# ============================================================================

class EnhanceCodeRequest(BaseModel):
    """Request to enhance decompiled code with AI."""
    code: str = Field(..., description="Decompiled code to enhance")
    function_name: str = Field(default="unknown", description="Original function name")
    binary_context: Optional[Dict[str, Any]] = Field(default=None, description="Additional binary context")
    enhancement_level: str = Field(default="full", description="Enhancement level: basic, standard, full")
    include_security_analysis: bool = Field(default=True, description="Include security vulnerability annotations")


class EnhancedVariable(BaseModel):
    """An enhanced/renamed variable."""
    original_name: str
    suggested_name: str
    inferred_type: str
    confidence: float
    reasoning: str


class EnhancedCodeBlock(BaseModel):
    """A code block with explanation."""
    start_line: int
    end_line: int
    purpose: str
    security_notes: Optional[str] = None


class DataStructure(BaseModel):
    """Reconstructed data structure."""
    name: str
    inferred_type: str
    fields: List[Dict[str, str]]
    usage_context: str


class SecurityAnnotation(BaseModel):
    """Security-related annotation in code."""
    line: int
    severity: str  # info, low, medium, high, critical
    issue_type: str
    description: str
    cwe_id: Optional[str] = None


class EnhanceCodeResponse(BaseModel):
    """Response with enhanced decompiled code."""
    original_code: str
    enhanced_code: str
    suggested_function_name: str
    function_purpose: str
    variables: List[EnhancedVariable]
    code_blocks: List[EnhancedCodeBlock]
    data_structures: List[DataStructure]
    security_annotations: List[SecurityAnnotation]
    complexity_score: int  # 1-10
    readability_improvement: int  # percentage
    inline_comments_added: int
    api_calls_identified: List[Dict[str, str]]


@router.post("/binary/enhance-code", response_model=EnhanceCodeResponse)
async def enhance_decompiled_code(request: EnhanceCodeRequest):
    """
    AI-powered decompiled code enhancement.
    
    Takes Ghidra/IDA decompiled code and makes it human-readable:
    - Renames variables intelligently (var_14 → encryptionKey)
    - Adds inline comments explaining code blocks
    - Identifies and documents data structures
    - Suggests original function names based on behavior
    - Annotates security vulnerabilities inline
    - Identifies API calls and their purposes
    
    Enhancement levels:
    - basic: Variable renaming only
    - standard: Variables + inline comments
    - full: Everything including security analysis
    """
    from backend.core.config import settings
    import google.generativeai as genai
    
    if not settings.GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Gemini API key not configured")
    
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")
    
    # Build context
    context_info = ""
    if request.binary_context:
        if "imports" in request.binary_context:
            context_info += f"\nImported functions: {', '.join(request.binary_context['imports'][:20])}"
        if "strings" in request.binary_context:
            context_info += f"\nInteresting strings: {', '.join(request.binary_context['strings'][:10])}"
        if "architecture" in request.binary_context:
            context_info += f"\nArchitecture: {request.binary_context['architecture']}"
    
    # Determine what to analyze based on enhancement level
    analyze_security = request.include_security_analysis and request.enhancement_level == "full"
    analyze_structures = request.enhancement_level in ("standard", "full")
    
    prompt = f"""You are an expert reverse engineer and code analyst. Analyze this decompiled code and enhance it for readability.

**Original Function Name:** {request.function_name}
**Enhancement Level:** {request.enhancement_level}
{context_info}

**Decompiled Code:**
```c
{request.code}
```

Provide a comprehensive analysis in the following JSON format:

{{
    "suggested_function_name": "descriptive_name_based_on_behavior",
    "function_purpose": "Clear description of what this function does",
    "enhanced_code": "The complete enhanced code with renamed variables and inline comments",
    "variables": [
        {{
            "original_name": "var_14",
            "suggested_name": "buffer_size",
            "inferred_type": "size_t",
            "confidence": 0.85,
            "reasoning": "Used as size parameter in memcpy"
        }}
    ],
    "code_blocks": [
        {{
            "start_line": 1,
            "end_line": 5,
            "purpose": "Initialize encryption context",
            "security_notes": "Uses hardcoded IV - potential weakness"
        }}
    ],
    "data_structures": [
        {{
            "name": "connection_info",
            "inferred_type": "struct",
            "fields": [{{"name": "socket_fd", "type": "int"}}, {{"name": "buffer", "type": "char*"}}],
            "usage_context": "Network connection state"
        }}
    ],
    "security_annotations": [
        {{
            "line": 12,
            "severity": "high",
            "issue_type": "buffer_overflow",
            "description": "strcpy without bounds checking",
            "cwe_id": "CWE-120"
        }}
    ],
    "api_calls_identified": [
        {{
            "name": "memcpy",
            "purpose": "Copy decrypted data to output buffer",
            "line": 15
        }}
    ],
    "complexity_score": 6,
    "readability_improvement": 75
}}

Guidelines for enhanced_code:
1. Replace generic variable names (var_X, param_X) with meaningful names
2. Add // comments explaining non-obvious operations
3. Group related operations with block comments
4. Keep the code syntactically valid C
5. Preserve the original logic exactly
{"6. Add security warning comments for dangerous patterns" if analyze_security else ""}

Return ONLY valid JSON, no markdown formatting."""

    try:
        response = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=8000,
                )
            )
        )
        
        result_text = response.text.strip()
        
        # Clean up response
        if result_text.startswith("```json"):
            result_text = result_text[7:]
        if result_text.startswith("```"):
            result_text = result_text[3:]
        if result_text.endswith("```"):
            result_text = result_text[:-3]
        result_text = result_text.strip()
        
        result = json.loads(result_text)
        
        return EnhanceCodeResponse(
            original_code=request.code,
            enhanced_code=result.get("enhanced_code", request.code),
            suggested_function_name=result.get("suggested_function_name", request.function_name),
            function_purpose=result.get("function_purpose", "Unknown"),
            variables=[EnhancedVariable(**v) for v in result.get("variables", [])],
            code_blocks=[EnhancedCodeBlock(**b) for b in result.get("code_blocks", [])],
            data_structures=[DataStructure(**d) for d in result.get("data_structures", [])],
            security_annotations=[SecurityAnnotation(**s) for s in result.get("security_annotations", [])] if analyze_security else [],
            complexity_score=result.get("complexity_score", 5),
            readability_improvement=result.get("readability_improvement", 50),
            inline_comments_added=result.get("enhanced_code", "").count("//") - request.code.count("//"),
            api_calls_identified=result.get("api_calls_identified", []),
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI response: {e}")
        # Return basic response
        return EnhanceCodeResponse(
            original_code=request.code,
            enhanced_code=request.code,
            suggested_function_name=request.function_name,
            function_purpose="Analysis failed - could not parse AI response",
            variables=[],
            code_blocks=[],
            data_structures=[],
            security_annotations=[],
            complexity_score=5,
            readability_improvement=0,
            inline_comments_added=0,
            api_calls_identified=[],
        )
    except Exception as e:
        logger.error(f"Code enhancement failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enhancement failed: {str(e)}")


# ============================================================================
# Natural Language Binary Search
# ============================================================================

class NaturalLanguageSearchRequest(BaseModel):
    """Request for natural language search across binary."""
    query: str = Field(..., description="Natural language search query")
    functions: List[Dict[str, Any]] = Field(..., description="List of functions with their decompiled code")
    max_results: int = Field(default=10, ge=1, le=50, description="Maximum results to return")
    include_explanations: bool = Field(default=True, description="Include AI explanations for matches")
    search_scope: str = Field(default="all", description="Search scope: all, security, network, crypto, file_io")


class SearchMatch(BaseModel):
    """A matching function from natural language search."""
    function_name: str
    address: Optional[str] = None
    relevance_score: float  # 0-1
    match_reason: str
    code_snippet: str
    key_indicators: List[str]
    security_relevant: bool
    category: str  # network, crypto, file_io, memory, string, etc.


class NaturalLanguageSearchResponse(BaseModel):
    """Response from natural language binary search."""
    query: str
    interpreted_query: str  # How AI understood the query
    total_functions_searched: int
    matches: List[SearchMatch]
    search_suggestions: List[str]  # Related queries user might want
    categories_found: Dict[str, int]  # Category distribution


@router.post("/binary/nl-search", response_model=NaturalLanguageSearchResponse)
async def natural_language_search(request: NaturalLanguageSearchRequest):
    """
    Natural language search across decompiled binary functions.
    
    Search by description instead of exact strings:
    - "Find the function that handles network authentication"
    - "Show me code that writes to files"
    - "Where is the encryption key derived?"
    - "Functions that parse user input"
    - "Code vulnerable to buffer overflow"
    
    The AI semantically searches across all decompiled functions
    and returns the most relevant matches with explanations.
    """
    from backend.core.config import settings
    import google.generativeai as genai
    
    if not settings.GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Gemini API key not configured")
    
    if not request.functions:
        raise HTTPException(status_code=400, detail="No functions provided to search")
    
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")
    
    # Build function summaries for the AI to search
    # Limit to prevent token overflow
    max_funcs = min(len(request.functions), 100)
    function_summaries = []
    
    for i, func in enumerate(request.functions[:max_funcs]):
        code = func.get("code", func.get("decompiled", ""))[:2000]  # Limit code length
        name = func.get("name", func.get("function_name", f"func_{i}"))
        addr = func.get("address", func.get("entry_point", "unknown"))
        
        function_summaries.append({
            "index": i,
            "name": name,
            "address": str(addr),
            "code_preview": code
        })
    
    # Build the search prompt
    scope_hint = ""
    if request.search_scope != "all":
        scope_hints = {
            "security": "Focus on security-sensitive functions (input validation, auth, crypto, memory operations)",
            "network": "Focus on network-related functions (sockets, HTTP, DNS, protocols)",
            "crypto": "Focus on cryptographic functions (encryption, hashing, key management)",
            "file_io": "Focus on file operations (read, write, open, delete, permissions)",
        }
        scope_hint = scope_hints.get(request.search_scope, "")
    
    prompt = f"""You are an expert reverse engineer searching through decompiled binary code.

**User's Search Query:** "{request.query}"
{f"**Search Scope:** {scope_hint}" if scope_hint else ""}

**Functions to Search ({len(function_summaries)} total):**

{json.dumps(function_summaries, indent=2)}

Analyze each function and find the ones that best match the user's query. Consider:
1. Function behavior and purpose
2. API calls and system interactions
3. Data flow and transformations
4. Security implications
5. Semantic meaning, not just keyword matching

Return your analysis as JSON:

{{
    "interpreted_query": "How you understood the user's intent",
    "matches": [
        {{
            "function_index": 0,
            "function_name": "actual_name",
            "address": "0x401000",
            "relevance_score": 0.95,
            "match_reason": "This function implements network authentication by...",
            "code_snippet": "Key lines that match the query",
            "key_indicators": ["calls socket()", "compares credentials", "returns auth token"],
            "security_relevant": true,
            "category": "network"
        }}
    ],
    "search_suggestions": [
        "Related query 1 the user might want",
        "Related query 2"
    ],
    "categories_found": {{
        "network": 2,
        "crypto": 1,
        "file_io": 0
    }}
}}

Return up to {request.max_results} most relevant matches, sorted by relevance_score (highest first).
Only include functions with relevance_score >= 0.3.
Return ONLY valid JSON, no markdown."""

    try:
        response = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.2,
                    max_output_tokens=4000,
                )
            )
        )
        
        result_text = response.text.strip()
        
        # Clean up response
        if result_text.startswith("```json"):
            result_text = result_text[7:]
        if result_text.startswith("```"):
            result_text = result_text[3:]
        if result_text.endswith("```"):
            result_text = result_text[:-3]
        result_text = result_text.strip()
        
        result = json.loads(result_text)
        
        # Build response matches
        matches = []
        for match in result.get("matches", []):
            idx = match.get("function_index", -1)
            if 0 <= idx < len(function_summaries):
                orig_func = function_summaries[idx]
                matches.append(SearchMatch(
                    function_name=match.get("function_name", orig_func["name"]),
                    address=match.get("address", orig_func["address"]),
                    relevance_score=min(1.0, max(0.0, match.get("relevance_score", 0.5))),
                    match_reason=match.get("match_reason", "Matched search criteria"),
                    code_snippet=match.get("code_snippet", orig_func["code_preview"][:500]),
                    key_indicators=match.get("key_indicators", []),
                    security_relevant=match.get("security_relevant", False),
                    category=match.get("category", "unknown"),
                ))
        
        return NaturalLanguageSearchResponse(
            query=request.query,
            interpreted_query=result.get("interpreted_query", request.query),
            total_functions_searched=len(function_summaries),
            matches=matches[:request.max_results],
            search_suggestions=result.get("search_suggestions", [])[:5],
            categories_found=result.get("categories_found", {}),
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse search response: {e}")
        return NaturalLanguageSearchResponse(
            query=request.query,
            interpreted_query=request.query,
            total_functions_searched=len(function_summaries),
            matches=[],
            search_suggestions=["Try a more specific query", "Use keywords like 'network', 'file', 'crypto'"],
            categories_found={},
        )
    except Exception as e:
        logger.error(f"Natural language search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.post("/binary/smart-rename")
async def smart_rename_function(
    function_code: str = Query(..., description="Decompiled function code"),
    current_name: str = Query(default="FUN_00401000", description="Current function name"),
    context_hints: Optional[str] = Query(default=None, description="Additional context about the binary"),
):
    """
    AI-powered function renaming suggestion.
    
    Analyzes decompiled code and suggests a meaningful function name
    based on the function's behavior, API calls, and data flow.
    """
    from backend.core.config import settings
    import google.generativeai as genai
    
    if not settings.GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Gemini API key not configured")
    
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")
    
    prompt = f"""Analyze this decompiled function and suggest a meaningful name.

**Current Name:** {current_name}
{f"**Context:** {context_hints}" if context_hints else ""}

**Decompiled Code:**
```c
{function_code[:4000]}
```

Respond with JSON:
{{
    "suggested_name": "descriptive_function_name",
    "confidence": 0.85,
    "reasoning": "Why this name fits",
    "alternative_names": ["other_option_1", "other_option_2"],
    "detected_purpose": "Brief description of what the function does",
    "naming_convention": "snake_case"
}}

Use snake_case. Be specific but concise. Examples:
- "validate_user_credentials" not "check_stuff"
- "decrypt_aes_buffer" not "crypto_function"
- "parse_http_headers" not "process_data"

Return ONLY valid JSON."""

    try:
        response = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.2,
                    max_output_tokens=500,
                )
            )
        )
        
        result_text = response.text.strip()
        if result_text.startswith("```"):
            result_text = result_text.split("```")[1]
            if result_text.startswith("json"):
                result_text = result_text[4:]
        result_text = result_text.strip()
        
        result = json.loads(result_text)
        return result
        
    except Exception as e:
        logger.error(f"Smart rename failed: {e}")
        return {
            "suggested_name": current_name,
            "confidence": 0.0,
            "reasoning": f"Analysis failed: {str(e)}",
            "alternative_names": [],
            "detected_purpose": "Unknown",
            "naming_convention": "unknown"
        }


# ============================================================================
# Live Attack Simulation Mode
# ============================================================================

class AttackSimulationRequest(BaseModel):
    """Request for attack simulation."""
    vulnerability: Dict[str, Any] = Field(..., description="The vulnerability finding to simulate")
    target_code: Optional[str] = Field(None, description="Relevant decompiled code")
    binary_context: Optional[Dict[str, Any]] = Field(None, description="Binary context (architecture, imports)")
    simulation_depth: str = Field("standard", description="Depth: quick, standard, or comprehensive")


class RegisterState(BaseModel):
    """CPU register state at a simulation step."""
    name: str
    value: str
    description: Optional[str] = None
    is_controlled: bool = False  # Whether attacker controls this value


class MemoryRegion(BaseModel):
    """Memory region state at a simulation step."""
    address: str
    size: int
    label: str  # e.g., "stack buffer", "heap chunk", "return address"
    state: str  # "normal", "corrupted", "overwritten", "controlled"
    content_preview: Optional[str] = None


class AttackStep(BaseModel):
    """A single step in the attack simulation."""
    step_number: int
    phase: str  # "setup", "trigger", "corruption", "control", "payload", "execution"
    title: str
    description: str
    technical_detail: str
    code_location: Optional[str] = None
    registers: List[RegisterState] = []
    memory_regions: List[MemoryRegion] = []
    attacker_input: Optional[str] = None
    visual_indicator: str  # "info", "warning", "danger", "success"


class ExploitPrimitive(BaseModel):
    """An exploit primitive that can be achieved."""
    name: str  # e.g., "arbitrary write", "code execution", "info leak"
    description: str
    prerequisites: List[str]
    achieved_at_step: int


class Mitigation(BaseModel):
    """A mitigation that could prevent the attack."""
    name: str
    description: str
    effectiveness: str  # "blocks", "hinders", "ineffective"
    bypass_possible: bool
    bypass_technique: Optional[str] = None


class AttackSimulationResponse(BaseModel):
    """Response containing the full attack simulation."""
    vulnerability_title: str
    vulnerability_type: str
    severity: str
    
    # Attack overview
    attack_summary: str
    success_probability: float  # 0-1
    required_conditions: List[str]
    
    # Step-by-step simulation
    total_steps: int
    steps: List[AttackStep]
    
    # What the attacker achieves
    exploit_primitives: List[ExploitPrimitive]
    final_impact: str
    
    # Defense analysis
    mitigations: List[Mitigation]
    detection_opportunities: List[str]
    
    # Additional context
    real_world_examples: List[str]
    cve_references: List[str]
    difficulty_rating: str  # "trivial", "easy", "moderate", "hard", "expert"


@router.post("/binary/simulate-attack", response_model=AttackSimulationResponse)
async def simulate_attack(request: AttackSimulationRequest):
    """
    Live Attack Simulation Mode.
    
    Takes a discovered vulnerability and generates a step-by-step simulation
    of how an attacker would exploit it. Shows:
    - Each phase of the attack (setup, trigger, corruption, control, execution)
    - Register and memory state at each step
    - What attacker input causes each state change
    - Exploit primitives achieved
    - Mitigations and their effectiveness
    - Real-world examples of similar attacks
    
    This helps security teams understand the practical impact of vulnerabilities
    and prioritize fixes based on exploitability.
    """
    from backend.core.config import settings
    import google.generativeai as genai
    
    if not settings.GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Gemini API key not configured")
    
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")
    
    # Extract vulnerability details
    vuln = request.vulnerability
    vuln_type = vuln.get("vulnerability_type", vuln.get("type", vuln.get("title", "Unknown")))
    vuln_title = vuln.get("title", vuln.get("function_name", f"{vuln_type} Vulnerability"))
    severity = vuln.get("severity", "medium")
    technical_details = vuln.get("technical_details", vuln.get("description", ""))
    poc = vuln.get("proof_of_concept", "")
    
    # Build context
    context_parts = []
    if request.target_code:
        context_parts.append(f"**Vulnerable Code:**\n```c\n{request.target_code[:3000]}\n```")
    if request.binary_context:
        if request.binary_context.get("architecture"):
            context_parts.append(f"**Architecture:** {request.binary_context['architecture']}")
        if request.binary_context.get("imports"):
            context_parts.append(f"**Key Imports:** {', '.join(request.binary_context['imports'][:15])}")
    
    context = "\n".join(context_parts) if context_parts else "No additional context provided."
    
    # Determine simulation depth
    step_count = {"quick": 4, "standard": 6, "comprehensive": 10}.get(request.simulation_depth, 6)
    
    prompt = f"""You are an expert exploit developer and security researcher. Generate a detailed, step-by-step attack simulation for this vulnerability.

**Vulnerability Type:** {vuln_type}
**Title:** {vuln_title}
**Severity:** {severity}

**Technical Details:**
{technical_details}

{f"**Proof of Concept:**{chr(10)}{poc}" if poc else ""}

{context}

Generate a realistic attack simulation showing exactly how an attacker would exploit this vulnerability. Be technical and specific.

Respond with JSON (and ONLY JSON, no markdown):

{{
    "vulnerability_title": "{vuln_title}",
    "vulnerability_type": "{vuln_type}",
    "severity": "{severity}",
    
    "attack_summary": "A 2-3 sentence summary of the attack",
    "success_probability": 0.75,
    "required_conditions": [
        "Condition 1 needed for exploit",
        "Condition 2"
    ],
    
    "total_steps": {step_count},
    "steps": [
        {{
            "step_number": 1,
            "phase": "setup",
            "title": "Prepare Malicious Input",
            "description": "The attacker crafts a specially formatted input...",
            "technical_detail": "Create a buffer of 0x108 bytes followed by the target return address",
            "code_location": "Line 42: memcpy(local_buf, user_input, input_len)",
            "registers": [
                {{"name": "RSP", "value": "0x7fffffffe000", "description": "Stack pointer", "is_controlled": false}},
                {{"name": "RDI", "value": "0x7fffffffe010", "description": "Destination buffer", "is_controlled": false}}
            ],
            "memory_regions": [
                {{
                    "address": "0x7fffffffe010",
                    "size": 256,
                    "label": "local_buf (stack buffer)",
                    "state": "normal",
                    "content_preview": "00 00 00 00 00 00 00 00..."
                }},
                {{
                    "address": "0x7fffffffe110",
                    "size": 8,
                    "label": "saved return address",
                    "state": "normal",
                    "content_preview": "Address of caller"
                }}
            ],
            "attacker_input": "A * 264 + pack('<Q', 0x401234)",
            "visual_indicator": "info"
        }},
        {{
            "step_number": 2,
            "phase": "trigger",
            "title": "Trigger the Vulnerability",
            "description": "The vulnerable function is called with oversized input...",
            "technical_detail": "memcpy copies 280 bytes into 256-byte buffer",
            "code_location": "Line 42: memcpy(local_buf, user_input, input_len)",
            "registers": [
                {{"name": "RDX", "value": "0x118", "description": "Copy size (280 bytes)", "is_controlled": true}}
            ],
            "memory_regions": [
                {{
                    "address": "0x7fffffffe010",
                    "size": 256,
                    "label": "local_buf",
                    "state": "corrupted",
                    "content_preview": "41 41 41 41 41 41 41 41..."
                }}
            ],
            "attacker_input": null,
            "visual_indicator": "warning"
        }},
        {{
            "step_number": 3,
            "phase": "corruption",
            "title": "Stack Corruption Occurs",
            "description": "The overflow overwrites the saved return address...",
            "technical_detail": "Bytes 256-263 overwrite saved RBP, bytes 264-271 overwrite return address",
            "code_location": null,
            "registers": [],
            "memory_regions": [
                {{
                    "address": "0x7fffffffe110",
                    "size": 8,
                    "label": "saved return address",
                    "state": "overwritten",
                    "content_preview": "34 12 40 00 00 00 00 00"
                }}
            ],
            "attacker_input": null,
            "visual_indicator": "danger"
        }},
        {{
            "step_number": 4,
            "phase": "control",
            "title": "Attacker Gains Control",
            "description": "When the function returns, execution jumps to attacker-controlled address...",
            "technical_detail": "RET instruction pops 0x401234 into RIP",
            "code_location": "Function epilogue: ret",
            "registers": [
                {{"name": "RIP", "value": "0x401234", "description": "Instruction pointer", "is_controlled": true}}
            ],
            "memory_regions": [],
            "attacker_input": null,
            "visual_indicator": "danger"
        }},
        {{
            "step_number": 5,
            "phase": "payload",
            "title": "ROP Chain Execution",
            "description": "The attacker's ROP chain begins executing...",
            "technical_detail": "First gadget: pop rdi; ret - sets up argument for system()",
            "code_location": "0x401234 (gadget)",
            "registers": [
                {{"name": "RDI", "value": "0x402000", "description": "Pointer to '/bin/sh'", "is_controlled": true}}
            ],
            "memory_regions": [],
            "attacker_input": null,
            "visual_indicator": "danger"
        }},
        {{
            "step_number": 6,
            "phase": "execution",
            "title": "Code Execution Achieved",
            "description": "The attacker achieves arbitrary code execution...",
            "technical_detail": "system('/bin/sh') spawns a shell with process privileges",
            "code_location": "system() in libc",
            "registers": [
                {{"name": "RAX", "value": "0x0", "description": "system() return value", "is_controlled": false}}
            ],
            "memory_regions": [],
            "attacker_input": null,
            "visual_indicator": "success"
        }}
    ],
    
    "exploit_primitives": [
        {{
            "name": "Stack Buffer Overflow",
            "description": "Overwrite stack data beyond buffer bounds",
            "prerequisites": ["No stack canaries or canary bypass"],
            "achieved_at_step": 2
        }},
        {{
            "name": "Return Address Control",
            "description": "Redirect execution to arbitrary address",
            "prerequisites": ["Stack overflow reaching return address"],
            "achieved_at_step": 3
        }},
        {{
            "name": "Arbitrary Code Execution",
            "description": "Execute attacker-controlled code/ROP chain",
            "prerequisites": ["Return address control", "Known gadget addresses"],
            "achieved_at_step": 6
        }}
    ],
    
    "final_impact": "The attacker achieves remote code execution with the privileges of the vulnerable process, potentially leading to full system compromise.",
    
    "mitigations": [
        {{
            "name": "Stack Canaries",
            "description": "Random value placed before return address, checked before function returns",
            "effectiveness": "blocks",
            "bypass_possible": true,
            "bypass_technique": "Information leak to read canary value, or format string to overwrite"
        }},
        {{
            "name": "ASLR",
            "description": "Randomize memory layout including stack and library addresses",
            "effectiveness": "hinders",
            "bypass_possible": true,
            "bypass_technique": "Information leak or brute force (32-bit)"
        }},
        {{
            "name": "DEP/NX",
            "description": "Mark stack as non-executable",
            "effectiveness": "hinders",
            "bypass_possible": true,
            "bypass_technique": "Return-Oriented Programming (ROP)"
        }},
        {{
            "name": "Safe Functions",
            "description": "Use strncpy/memcpy_s with size limits",
            "effectiveness": "blocks",
            "bypass_possible": false,
            "bypass_technique": null
        }}
    ],
    
    "detection_opportunities": [
        "Monitor for crashes/segfaults indicating exploitation attempts",
        "Detect anomalous memory access patterns",
        "Intrusion detection signatures for known exploit payloads",
        "Runtime canary violation alerts"
    ],
    
    "real_world_examples": [
        "CVE-2021-3156 (sudo heap overflow)",
        "CVE-2017-5638 (Apache Struts RCE)"
    ],
    
    "cve_references": [],
    
    "difficulty_rating": "moderate"
}}

IMPORTANT:
- Generate realistic register values (use x86-64 conventions)
- Show actual memory corruption with hex previews
- Make the attack technically accurate for the vulnerability type
- Adjust the simulation for the specific vulnerability (buffer overflow, format string, use-after-free, etc.)
- Include {step_count} detailed steps covering setup through execution
- Return ONLY valid JSON"""

    try:
        response = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=8000,
                )
            )
        )
        
        result_text = response.text.strip()
        
        # Clean up response
        if result_text.startswith("```json"):
            result_text = result_text[7:]
        if result_text.startswith("```"):
            result_text = result_text[3:]
        if result_text.endswith("```"):
            result_text = result_text[:-3]
        result_text = result_text.strip()
        
        result = json.loads(result_text)
        
        # Build response with proper validation
        steps = []
        for step_data in result.get("steps", []):
            registers = [RegisterState(**r) for r in step_data.get("registers", [])]
            memory_regions = [MemoryRegion(**m) for m in step_data.get("memory_regions", [])]
            steps.append(AttackStep(
                step_number=step_data.get("step_number", 0),
                phase=step_data.get("phase", "unknown"),
                title=step_data.get("title", "Unknown Step"),
                description=step_data.get("description", ""),
                technical_detail=step_data.get("technical_detail", ""),
                code_location=step_data.get("code_location"),
                registers=registers,
                memory_regions=memory_regions,
                attacker_input=step_data.get("attacker_input"),
                visual_indicator=step_data.get("visual_indicator", "info"),
            ))
        
        exploit_primitives = [
            ExploitPrimitive(**p) for p in result.get("exploit_primitives", [])
        ]
        
        mitigations = [
            Mitigation(**m) for m in result.get("mitigations", [])
        ]
        
        return AttackSimulationResponse(
            vulnerability_title=result.get("vulnerability_title", vuln_title),
            vulnerability_type=result.get("vulnerability_type", vuln_type),
            severity=result.get("severity", severity),
            attack_summary=result.get("attack_summary", "Attack simulation generated"),
            success_probability=min(1.0, max(0.0, result.get("success_probability", 0.5))),
            required_conditions=result.get("required_conditions", []),
            total_steps=len(steps),
            steps=steps,
            exploit_primitives=exploit_primitives,
            final_impact=result.get("final_impact", "Unknown impact"),
            mitigations=mitigations,
            detection_opportunities=result.get("detection_opportunities", []),
            real_world_examples=result.get("real_world_examples", []),
            cve_references=result.get("cve_references", []),
            difficulty_rating=result.get("difficulty_rating", "unknown"),
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse attack simulation response: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate attack simulation")
    except Exception as e:
        logger.error(f"Attack simulation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")


# ============================================================================
# Symbolic Execution Traces
# ============================================================================

class PathConstraint(BaseModel):
    """A constraint on a path (e.g., input must be > 0)."""
    variable: str
    operator: str  # "==", "!=", ">", "<", ">=", "<=", "contains", "matches"
    value: str
    description: str
    is_satisfiable: bool = True


class TaintedVariable(BaseModel):
    """A variable that is tainted (derived from user input)."""
    name: str
    source: str  # Where the taint originated (e.g., "argv[1]", "read()", "recv()")
    taint_type: str  # "direct", "derived", "partial"
    propagation_chain: List[str]  # How taint spread: ["argv[1]", "buffer", "ptr"]
    reaches_sink: bool = False
    sink_name: Optional[str] = None  # e.g., "strcpy", "system", "eval"


class BasicBlock(BaseModel):
    """A basic block in the control flow graph."""
    id: str
    start_address: str
    end_address: str
    instructions_count: int
    code_preview: str
    is_entry: bool = False
    is_exit: bool = False
    is_reachable: bool = True
    predecessors: List[str] = []
    successors: List[str] = []
    dominates: List[str] = []
    tainted_at_entry: List[str] = []  # Which variables are tainted when entering this block


class ExecutionPath(BaseModel):
    """A single execution path through the function."""
    path_id: str
    blocks: List[str]  # Block IDs in order
    constraints: List[PathConstraint]  # Constraints to reach this path
    probability: float  # Estimated likelihood (0-1)
    is_feasible: bool = True
    leads_to_vulnerability: bool = False
    vulnerability_type: Optional[str] = None
    tainted_at_end: List[TaintedVariable] = []
    path_description: str
    interesting_operations: List[str] = []  # Notable things that happen on this path


class SymbolicState(BaseModel):
    """Symbolic state at a specific point in execution."""
    location: str  # Address or line
    variables: Dict[str, str]  # Variable name -> symbolic expression
    memory_regions: Dict[str, str]  # Address range -> description
    constraints: List[PathConstraint]
    tainted: List[str]  # Variable names that are tainted


class DangerousSink(BaseModel):
    """A dangerous function that tainted data might reach."""
    function_name: str
    address: str
    sink_type: str  # "memory", "command", "format", "file", "network"
    severity: str  # "critical", "high", "medium", "low"
    tainted_arguments: List[int]  # Which arguments are tainted (0-indexed)
    reachable_from: List[str]  # Path IDs that can reach this sink
    description: str
    cwe_id: Optional[str] = None


class SymbolicTraceRequest(BaseModel):
    """Request for symbolic execution trace."""
    code: str = Field(..., description="Decompiled function code")
    function_name: str = Field(default="unknown", description="Function name")
    entry_point: Optional[str] = Field(None, description="Entry point address")
    input_sources: List[str] = Field(
        default=["argv", "stdin", "recv", "read", "fgets", "scanf", "getenv"],
        description="Functions/variables considered as input sources (taint sources)"
    )
    dangerous_sinks: List[str] = Field(
        default=["strcpy", "strcat", "sprintf", "gets", "system", "exec", "eval", "memcpy", "memmove"],
        description="Dangerous functions to track (taint sinks)"
    )
    max_paths: int = Field(default=20, ge=1, le=100, description="Maximum paths to analyze")
    max_depth: int = Field(default=50, ge=5, le=200, description="Maximum path depth")
    binary_context: Optional[Dict[str, Any]] = Field(None, description="Additional binary context")


class SymbolicTraceResponse(BaseModel):
    """Response containing symbolic execution trace analysis."""
    function_name: str
    analysis_summary: str
    
    # Control Flow
    total_basic_blocks: int
    basic_blocks: List[BasicBlock]
    entry_block: str
    exit_blocks: List[str]
    
    # Paths
    total_paths_analyzed: int
    feasible_paths: int
    vulnerable_paths: int
    paths: List[ExecutionPath]
    
    # Taint Analysis
    input_sources_found: List[str]
    tainted_variables: List[TaintedVariable]
    dangerous_sinks_reached: List[DangerousSink]
    taint_summary: str
    
    # Symbolic States (at key points)
    symbolic_states: List[SymbolicState]
    
    # Security Assessment
    reachability_score: float  # 0-1, how much code is reachable
    vulnerability_score: float  # 0-1, likelihood of exploitable bugs
    recommended_focus_areas: List[str]
    
    # Integration data for AI Decompiler
    path_annotations: Dict[str, str]  # line/address -> annotation
    taint_annotations: Dict[str, str]  # variable -> taint info


@router.post("/binary/symbolic-trace", response_model=SymbolicTraceResponse)
async def analyze_symbolic_trace(request: SymbolicTraceRequest):
    """
    AI-powered Symbolic Execution Trace Analysis.
    
    Performs comprehensive path and taint analysis on decompiled code:
    
    **Control Flow Analysis:**
    - Identifies all basic blocks and their relationships
    - Maps control flow graph structure
    - Determines reachable vs unreachable code
    
    **Path Enumeration:**
    - Enumerates execution paths through the function
    - Calculates constraints needed to reach each path
    - Identifies which paths lead to dangerous operations
    
    **Taint Analysis:**
    - Tracks user input from sources (argv, stdin, recv, etc.)
    - Propagates taint through assignments and operations
    - Identifies when tainted data reaches dangerous sinks
    
    **Integration with AI Decompiler:**
    - Returns annotations that can be used to enhance code
    - Marks lines with taint information
    - Highlights vulnerable paths in the code
    
    This analysis helps answer:
    - "Can user input reach this vulnerable function?"
    - "What input triggers this specific code path?"
    - "Which variables are attacker-controlled?"
    """
    from backend.core.config import settings
    import google.generativeai as genai
    
    if not settings.GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Gemini API key not configured")
    
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")
    
    # Build context
    context_parts = []
    if request.binary_context:
        if request.binary_context.get("architecture"):
            context_parts.append(f"Architecture: {request.binary_context['architecture']}")
        if request.binary_context.get("imports"):
            context_parts.append(f"Imports: {', '.join(request.binary_context['imports'][:20])}")
    context = "\n".join(context_parts) if context_parts else "No additional context."
    
    prompt = f"""You are an expert binary analyst performing symbolic execution and taint analysis on decompiled code.

**Function Name:** {request.function_name}
**Entry Point:** {request.entry_point or "Unknown"}

**Input Sources (Taint Sources):** {", ".join(request.input_sources)}
**Dangerous Sinks:** {", ".join(request.dangerous_sinks)}

**Binary Context:**
{context}

**Decompiled Code:**
```c
{request.code[:8000]}
```

Perform comprehensive symbolic execution analysis:

1. **Control Flow Analysis**: Identify basic blocks, their relationships, and the CFG structure
2. **Path Analysis**: Enumerate distinct execution paths with their constraints
3. **Taint Analysis**: Track data flow from input sources to dangerous sinks
4. **Vulnerability Assessment**: Identify paths that lead to exploitable conditions

Respond with JSON (ONLY valid JSON, no markdown):

{{
    "function_name": "{request.function_name}",
    "analysis_summary": "Brief summary of the analysis findings",
    
    "total_basic_blocks": 8,
    "basic_blocks": [
        {{
            "id": "BB0",
            "start_address": "0x401000",
            "end_address": "0x401020",
            "instructions_count": 12,
            "code_preview": "if (argc < 2) return -1;",
            "is_entry": true,
            "is_exit": false,
            "is_reachable": true,
            "predecessors": [],
            "successors": ["BB1", "BB2"],
            "dominates": ["BB1", "BB2", "BB3"],
            "tainted_at_entry": []
        }},
        {{
            "id": "BB1",
            "start_address": "0x401024",
            "end_address": "0x401050",
            "instructions_count": 15,
            "code_preview": "buffer = malloc(size); strcpy(buffer, argv[1]);",
            "is_entry": false,
            "is_exit": false,
            "is_reachable": true,
            "predecessors": ["BB0"],
            "successors": ["BB3"],
            "dominates": [],
            "tainted_at_entry": ["argv[1]", "size"]
        }}
    ],
    "entry_block": "BB0",
    "exit_blocks": ["BB7"],
    
    "total_paths_analyzed": 5,
    "feasible_paths": 4,
    "vulnerable_paths": 2,
    "paths": [
        {{
            "path_id": "P1",
            "blocks": ["BB0", "BB1", "BB3", "BB5", "BB7"],
            "constraints": [
                {{
                    "variable": "argc",
                    "operator": ">=",
                    "value": "2",
                    "description": "Program requires at least one argument",
                    "is_satisfiable": true
                }},
                {{
                    "variable": "strlen(argv[1])",
                    "operator": ">",
                    "value": "256",
                    "description": "Input must overflow the buffer",
                    "is_satisfiable": true
                }}
            ],
            "probability": 0.3,
            "is_feasible": true,
            "leads_to_vulnerability": true,
            "vulnerability_type": "buffer_overflow",
            "tainted_at_end": [
                {{
                    "name": "buffer",
                    "source": "argv[1]",
                    "taint_type": "direct",
                    "propagation_chain": ["argv[1]", "buffer"],
                    "reaches_sink": true,
                    "sink_name": "strcpy"
                }}
            ],
            "path_description": "Main execution path that processes user input and copies to fixed buffer",
            "interesting_operations": ["malloc allocation", "strcpy without bounds check", "buffer passed to printf"]
        }}
    ],
    
    "input_sources_found": ["argv[1]", "getenv('HOME')"],
    "tainted_variables": [
        {{
            "name": "buffer",
            "source": "argv[1]",
            "taint_type": "direct",
            "propagation_chain": ["argv[1]", "buffer"],
            "reaches_sink": true,
            "sink_name": "strcpy"
        }},
        {{
            "name": "size",
            "source": "argv[2]",
            "taint_type": "derived",
            "propagation_chain": ["argv[2]", "atoi()", "size"],
            "reaches_sink": true,
            "sink_name": "malloc"
        }}
    ],
    "dangerous_sinks_reached": [
        {{
            "function_name": "strcpy",
            "address": "0x401030",
            "sink_type": "memory",
            "severity": "critical",
            "tainted_arguments": [1],
            "reachable_from": ["P1", "P2"],
            "description": "strcpy called with tainted source from argv[1], destination is 256-byte stack buffer",
            "cwe_id": "CWE-120"
        }},
        {{
            "function_name": "printf",
            "address": "0x401080",
            "sink_type": "format",
            "severity": "high",
            "tainted_arguments": [0],
            "reachable_from": ["P1"],
            "description": "printf called with tainted format string",
            "cwe_id": "CWE-134"
        }}
    ],
    "taint_summary": "User input from argv[1] flows directly to strcpy without length validation, allowing buffer overflow. Additionally, the buffer is later used as a printf format string.",
    
    "symbolic_states": [
        {{
            "location": "0x401024",
            "variables": {{
                "argc": "concrete: user-provided",
                "argv[1]": "symbolic: user_input_0",
                "buffer": "uninitialized"
            }},
            "memory_regions": {{
                "stack[rbp-0x100]": "256-byte local buffer (uninitialized)"
            }},
            "constraints": [
                {{
                    "variable": "argc",
                    "operator": ">=",
                    "value": "2",
                    "description": "Passed argument check",
                    "is_satisfiable": true
                }}
            ],
            "tainted": ["argv[1]"]
        }}
    ],
    
    "reachability_score": 0.85,
    "vulnerability_score": 0.75,
    "recommended_focus_areas": [
        "The strcpy at 0x401030 is the primary vulnerability - user input copied without bounds checking",
        "The printf at 0x401080 may allow format string exploitation",
        "Consider the malloc size being derived from user input - potential integer overflow"
    ],
    
    "path_annotations": {{
        "0x401024": "⚠️ Taint: argv[1] enters here",
        "0x401030": "🔴 SINK: strcpy with tainted source, CWE-120",
        "0x401050": "Taint propagates: buffer now tainted",
        "0x401080": "🔴 SINK: printf with tainted format, CWE-134"
    }},
    "taint_annotations": {{
        "buffer": "🔴 TAINTED from argv[1] → reaches strcpy, printf",
        "size": "⚠️ TAINTED from argv[2] → reaches malloc (potential int overflow)",
        "result": "✅ CLEAN - derived from return value, not user input"
    }}
}}

Analysis Guidelines:
1. Be thorough in identifying ALL paths, not just obvious ones
2. Track taint precisely through all operations (assignments, arithmetic, casts)
3. Consider indirect taint (e.g., array index from tainted value)
4. Identify ALL dangerous sinks the tainted data reaches
5. Provide actionable annotations for code enhancement
6. Focus on {request.max_paths} most interesting/vulnerable paths
7. Generate realistic addresses based on typical binary layouts

Return ONLY valid JSON."""

    try:
        response = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.2,
                    max_output_tokens=12000,
                )
            )
        )
        
        result_text = response.text.strip()
        
        # Clean up response
        if result_text.startswith("```json"):
            result_text = result_text[7:]
        if result_text.startswith("```"):
            result_text = result_text[3:]
        if result_text.endswith("```"):
            result_text = result_text[:-3]
        result_text = result_text.strip()
        
        result = json.loads(result_text)
        
        # Build response with proper validation
        basic_blocks = [BasicBlock(**bb) for bb in result.get("basic_blocks", [])]
        
        paths = []
        for path_data in result.get("paths", []):
            constraints = [PathConstraint(**c) for c in path_data.get("constraints", [])]
            tainted = [TaintedVariable(**t) for t in path_data.get("tainted_at_end", [])]
            paths.append(ExecutionPath(
                path_id=path_data.get("path_id", ""),
                blocks=path_data.get("blocks", []),
                constraints=constraints,
                probability=path_data.get("probability", 0.5),
                is_feasible=path_data.get("is_feasible", True),
                leads_to_vulnerability=path_data.get("leads_to_vulnerability", False),
                vulnerability_type=path_data.get("vulnerability_type"),
                tainted_at_end=tainted,
                path_description=path_data.get("path_description", ""),
                interesting_operations=path_data.get("interesting_operations", []),
            ))
        
        tainted_vars = [TaintedVariable(**t) for t in result.get("tainted_variables", [])]
        
        dangerous_sinks = [DangerousSink(**s) for s in result.get("dangerous_sinks_reached", [])]
        
        symbolic_states = []
        for state_data in result.get("symbolic_states", []):
            constraints = [PathConstraint(**c) for c in state_data.get("constraints", [])]
            symbolic_states.append(SymbolicState(
                location=state_data.get("location", ""),
                variables=state_data.get("variables", {}),
                memory_regions=state_data.get("memory_regions", {}),
                constraints=constraints,
                tainted=state_data.get("tainted", []),
            ))
        
        return SymbolicTraceResponse(
            function_name=result.get("function_name", request.function_name),
            analysis_summary=result.get("analysis_summary", ""),
            total_basic_blocks=result.get("total_basic_blocks", len(basic_blocks)),
            basic_blocks=basic_blocks,
            entry_block=result.get("entry_block", ""),
            exit_blocks=result.get("exit_blocks", []),
            total_paths_analyzed=result.get("total_paths_analyzed", len(paths)),
            feasible_paths=result.get("feasible_paths", len(paths)),
            vulnerable_paths=result.get("vulnerable_paths", 0),
            paths=paths,
            input_sources_found=result.get("input_sources_found", []),
            tainted_variables=tainted_vars,
            dangerous_sinks_reached=dangerous_sinks,
            taint_summary=result.get("taint_summary", ""),
            symbolic_states=symbolic_states,
            reachability_score=min(1.0, max(0.0, result.get("reachability_score", 0.5))),
            vulnerability_score=min(1.0, max(0.0, result.get("vulnerability_score", 0.0))),
            recommended_focus_areas=result.get("recommended_focus_areas", []),
            path_annotations=result.get("path_annotations", {}),
            taint_annotations=result.get("taint_annotations", {}),
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse symbolic trace response: {e}")
        raise HTTPException(status_code=500, detail="Failed to parse symbolic analysis results")
    except Exception as e:
        logger.error(f"Symbolic trace analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ============================================================================
# Enhanced Code with Symbolic Data Integration
# ============================================================================

class EnhanceCodeWithSymbolicRequest(BaseModel):
    """Request to enhance code with symbolic execution data."""
    code: str = Field(..., description="Decompiled code to enhance")
    function_name: str = Field(default="unknown", description="Function name")
    symbolic_trace: Optional[Dict[str, Any]] = Field(None, description="Symbolic trace data from /binary/symbolic-trace")
    binary_context: Optional[Dict[str, Any]] = Field(None, description="Additional binary context")
    enhancement_level: str = Field(default="full", description="Enhancement level: basic, standard, full")


class SymbolicEnhancedCodeResponse(BaseModel):
    """Response with code enhanced using symbolic execution data."""
    original_code: str
    enhanced_code: str
    suggested_function_name: str
    function_purpose: str
    
    # Standard enhancements
    variables: List[EnhancedVariable]
    code_blocks: List[EnhancedCodeBlock]
    data_structures: List[DataStructure]
    security_annotations: List[SecurityAnnotation]
    
    # Symbolic execution enhancements
    taint_annotations: List[Dict[str, Any]]  # Line-level taint info
    path_annotations: List[Dict[str, Any]]  # Which paths reach each line
    reachability_info: Dict[str, bool]  # Line -> is reachable
    constraint_annotations: List[Dict[str, Any]]  # Input constraints per block
    
    # Summary
    complexity_score: int
    vulnerability_paths_highlighted: int
    tainted_sinks_marked: int
    integration_quality: str  # How well symbolic data enhanced the analysis


@router.post("/binary/enhance-code-symbolic", response_model=SymbolicEnhancedCodeResponse)
async def enhance_code_with_symbolic(request: EnhanceCodeWithSymbolicRequest):
    """
    AI-powered code enhancement with symbolic execution integration.
    
    This endpoint combines:
    1. **Standard Enhancement**: Variable renaming, comments, structure detection
    2. **Symbolic Integration**: Taint annotations, path info, reachability
    
    When symbolic_trace data is provided (from /binary/symbolic-trace):
    - Annotates variables with taint information
    - Shows which paths reach each code block
    - Highlights lines where tainted data reaches dangerous sinks
    - Marks unreachable code
    - Shows input constraints needed to reach specific lines
    
    This creates a comprehensive view that shows:
    - WHAT the code does (standard enhancement)
    - HOW data flows through it (taint tracking)
    - WHICH inputs trigger which behaviors (path constraints)
    - WHERE vulnerabilities exist (sink annotations)
    """
    from backend.core.config import settings
    import google.generativeai as genai
    
    if not settings.GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Gemini API key not configured")
    
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")
    
    # Build symbolic context
    symbolic_context = ""
    if request.symbolic_trace:
        st = request.symbolic_trace
        symbolic_context = f"""
**SYMBOLIC EXECUTION DATA AVAILABLE:**

Taint Summary: {st.get('taint_summary', 'N/A')}

Tainted Variables:
{json.dumps(st.get('tainted_variables', [])[:10], indent=2)}

Dangerous Sinks Reached:
{json.dumps(st.get('dangerous_sinks_reached', [])[:5], indent=2)}

Path Annotations:
{json.dumps(st.get('path_annotations', {}), indent=2)}

Taint Annotations:
{json.dumps(st.get('taint_annotations', {}), indent=2)}

Vulnerable Paths: {st.get('vulnerable_paths', 0)}
Vulnerability Score: {st.get('vulnerability_score', 0)}

Recommended Focus Areas:
{json.dumps(st.get('recommended_focus_areas', []), indent=2)}
"""
    
    # Build binary context
    binary_context = ""
    if request.binary_context:
        if request.binary_context.get("architecture"):
            binary_context += f"Architecture: {request.binary_context['architecture']}\n"
        if request.binary_context.get("imports"):
            binary_context += f"Imports: {', '.join(request.binary_context['imports'][:15])}\n"
    
    prompt = f"""You are an expert reverse engineer enhancing decompiled code with symbolic execution insights.

**Function Name:** {request.function_name}
**Enhancement Level:** {request.enhancement_level}

{binary_context}

{symbolic_context}

**Decompiled Code:**
```c
{request.code[:6000]}
```

Enhance this code by:
1. Renaming variables based on their usage AND taint status
2. Adding comments that explain BOTH behavior AND data flow
3. Marking tainted variables with special annotations
4. Highlighting lines where tainted data reaches dangerous sinks
5. Showing path constraints as comments where relevant

Respond with JSON (ONLY valid JSON):

{{
    "suggested_function_name": "process_user_input_unsafe",
    "function_purpose": "Processes command-line argument and copies to buffer without validation, vulnerable to overflow",
    
    "enhanced_code": "/* FUNCTION: process_user_input_unsafe
 * PURPOSE: Process user input (VULNERABLE - buffer overflow)
 * TAINT: argv[1] -> buffer -> strcpy sink
 * PATHS: 2 paths lead to vulnerable strcpy
 */
int process_user_input_unsafe(int argc, char **argv) {{
    // [PATH CONSTRAINT: argc >= 2 to reach this code]
    if (argc < 2) {{
        return -1;  // Early exit path (safe)
    }}
    
    // [TAINT SOURCE] user_input receives tainted data from argv[1]
    char *user_input = argv[1];  // 🔴 TAINTED: direct from argv
    
    // [ALLOCATION] Fixed-size buffer on stack
    char local_buffer[256];  // ⚠️ Target of overflow
    
    // [VULNERABLE SINK] strcpy with tainted source
    // 🔴 CWE-120: Buffer overflow - no bounds checking
    // CONSTRAINT: strlen(argv[1]) > 256 triggers overflow
    strcpy(local_buffer, user_input);  // 🔴 SINK: tainted data
    
    // [SECOND SINK] Format string vulnerability
    // 🔴 CWE-134: Tainted data used as format string
    printf(local_buffer);  // 🔴 SINK: format string
    
    return 0;
}}",
    
    "variables": [
        {{
            "original_name": "param_1",
            "suggested_name": "argc",
            "inferred_type": "int",
            "confidence": 0.95,
            "reasoning": "Standard main() argument count parameter"
        }},
        {{
            "original_name": "param_2",
            "suggested_name": "argv",
            "inferred_type": "char**",
            "confidence": 0.95,
            "reasoning": "Standard main() argument vector, TAINT SOURCE"
        }},
        {{
            "original_name": "local_108",
            "suggested_name": "local_buffer",
            "inferred_type": "char[256]",
            "confidence": 0.9,
            "reasoning": "Stack buffer used as strcpy destination, becomes tainted"
        }}
    ],
    
    "code_blocks": [
        {{
            "start_line": 1,
            "end_line": 4,
            "purpose": "Argument validation - early exit if no input",
            "security_notes": "Safe path - exits before processing tainted data"
        }},
        {{
            "start_line": 6,
            "end_line": 10,
            "purpose": "Tainted input processing - copies to fixed buffer",
            "security_notes": "CRITICAL: Buffer overflow vulnerability, tainted data from argv[1] copied without bounds check"
        }}
    ],
    
    "data_structures": [],
    
    "security_annotations": [
        {{
            "line": 8,
            "severity": "critical",
            "issue_type": "buffer_overflow",
            "description": "strcpy copies tainted argv[1] to 256-byte buffer without length check",
            "cwe_id": "CWE-120"
        }},
        {{
            "line": 10,
            "severity": "high",
            "issue_type": "format_string",
            "description": "Tainted buffer used directly as printf format string",
            "cwe_id": "CWE-134"
        }}
    ],
    
    "taint_annotations": [
        {{
            "line": 6,
            "variable": "user_input",
            "taint_source": "argv[1]",
            "taint_type": "direct",
            "annotation": "🔴 TAINTED: Direct user input from command line"
        }},
        {{
            "line": 8,
            "variable": "local_buffer",
            "taint_source": "argv[1]",
            "taint_type": "propagated",
            "annotation": "🔴 TAINTED: Contains copy of tainted argv[1]"
        }}
    ],
    
    "path_annotations": [
        {{
            "line": 3,
            "paths": ["P1"],
            "constraint": "argc < 2",
            "annotation": "Early exit path - safe, no tainted data processed"
        }},
        {{
            "line": 8,
            "paths": ["P2", "P3"],
            "constraint": "argc >= 2",
            "annotation": "Vulnerable path - tainted data reaches strcpy"
        }}
    ],
    
    "reachability_info": {{
        "1": true,
        "2": true,
        "3": true,
        "6": true,
        "8": true,
        "10": true
    }},
    
    "constraint_annotations": [
        {{
            "block": "argument_check",
            "constraint": "argc >= 2",
            "satisfiable": true,
            "annotation": "Requires at least one command-line argument"
        }},
        {{
            "block": "overflow_trigger",
            "constraint": "strlen(argv[1]) > 256",
            "satisfiable": true,
            "annotation": "Triggers buffer overflow when input exceeds buffer size"
        }}
    ],
    
    "complexity_score": 3,
    "vulnerability_paths_highlighted": 2,
    "tainted_sinks_marked": 2,
    "integration_quality": "excellent"
}}

Guidelines:
1. In enhanced_code, add visual markers: 🔴 for sinks, ⚠️ for warnings, ✅ for safe
2. Include taint flow in function header comment
3. Add PATH CONSTRAINT comments showing what inputs reach each block
4. Mark EVERY tainted variable with its source
5. Highlight ALL dangerous sinks with CWE IDs
6. Make the code self-documenting for security review

Return ONLY valid JSON."""

    try:
        response = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=10000,
                )
            )
        )
        
        result_text = response.text.strip()
        
        # Clean up response
        if result_text.startswith("```json"):
            result_text = result_text[7:]
        if result_text.startswith("```"):
            result_text = result_text[3:]
        if result_text.endswith("```"):
            result_text = result_text[:-3]
        result_text = result_text.strip()
        
        result = json.loads(result_text)
        
        return SymbolicEnhancedCodeResponse(
            original_code=request.code,
            enhanced_code=result.get("enhanced_code", request.code),
            suggested_function_name=result.get("suggested_function_name", request.function_name),
            function_purpose=result.get("function_purpose", "Unknown"),
            variables=[EnhancedVariable(**v) for v in result.get("variables", [])],
            code_blocks=[EnhancedCodeBlock(**b) for b in result.get("code_blocks", [])],
            data_structures=[DataStructure(**d) for d in result.get("data_structures", [])],
            security_annotations=[SecurityAnnotation(**s) for s in result.get("security_annotations", [])],
            taint_annotations=result.get("taint_annotations", []),
            path_annotations=result.get("path_annotations", []),
            reachability_info=result.get("reachability_info", {}),
            constraint_annotations=result.get("constraint_annotations", []),
            complexity_score=result.get("complexity_score", 5),
            vulnerability_paths_highlighted=result.get("vulnerability_paths_highlighted", 0),
            tainted_sinks_marked=result.get("tainted_sinks_marked", 0),
            integration_quality=result.get("integration_quality", "unknown"),
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse symbolic enhancement response: {e}")
        raise HTTPException(status_code=500, detail="Failed to parse enhancement results")
    except Exception as e:
        logger.error(f"Symbolic code enhancement failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enhancement failed: {str(e)}")


# ============================================================================
# APK Analysis
# ============================================================================

async def analyze_apk(
    file: UploadFile = File(..., description="Android APK file to analyze"),
    include_ai: bool = Query(True, description="Include AI-powered analysis"),
):
    """
    Analyze an Android APK file.
    
    Extracts:
    - Package info (name, version, SDK levels)
    - Permissions (with dangerous permission detection)
    - App components (activities, services, receivers, providers)
    - Strings from DEX files
    - Hardcoded URLs and secrets
    - Native libraries
    - Security issues
    
    Supported formats: APK, AAB
    """
    filename = file.filename or "unknown.apk"
    suffix = Path(filename).suffix.lower()
    
    if suffix not in ALLOWED_APK_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed extensions: {', '.join(ALLOWED_APK_EXTENSIONS)}"
        )
    
    tmp_dir = None
    try:
        # Save file to temp location
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_apk_"))
        tmp_path = tmp_dir / filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"Analyzing APK: {filename} ({file_size:,} bytes)")
        
        # Perform analysis
        result = re_service.analyze_apk(tmp_path)
        
        # Run AI analysis if requested (text analysis only - diagrams are generated after JADX decompilation)
        if include_ai and not result.error:
            result.ai_analysis = await re_service.analyze_apk_with_ai(result)
            # Note: Architecture diagram is only generated after JADX decompilation for proper context
        
        # Count dangerous permissions
        dangerous_count = sum(1 for p in result.permissions if p.is_dangerous)
        
        # Convert to response model
        return ApkAnalysisResponse(
            filename=result.filename,
            package_name=result.package_name,
            version_name=result.version_name,
            version_code=result.version_code,
            min_sdk=result.min_sdk,
            target_sdk=result.target_sdk,
            permissions=[
                ApkPermissionResponse(
                    name=p.name,
                    is_dangerous=p.is_dangerous,
                    description=p.description,
                )
                for p in result.permissions
            ],
            dangerous_permissions_count=dangerous_count,
            components=[
                ApkComponentResponse(
                    name=c.name,
                    component_type=c.component_type,
                    is_exported=c.is_exported,
                    intent_filters=c.intent_filters,
                )
                for c in result.components
            ],
            strings_count=len(result.strings),
            secrets=[
                SecretResponse(
                    type=s["type"],
                    value=s["value"],
                    masked_value=s["masked_value"],
                    severity=s["severity"],
                    context=s.get("context"),
                )
                for s in result.secrets
            ],
            urls=result.urls[:100],
            native_libraries=result.native_libraries,
            security_issues=[
                ApkSecurityIssueResponse(
                    category=issue["category"],
                    severity=issue["severity"],
                    description=issue["description"],
                    details=issue.get("details"),
                )
                for issue in result.security_issues
            ],
            ai_analysis=result.ai_analysis,
            ai_report_functionality=result.ai_report_functionality,
            ai_report_security=result.ai_report_security,
            ai_architecture_diagram=result.ai_architecture_diagram,
            ai_data_flow_diagram=result.ai_data_flow_diagram,
            error=result.error,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"APK analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.get("/analyze-docker/{image_name:path}", response_model=DockerAnalysisResponse)
async def analyze_docker_image(
    image_name: str,
    include_ai: bool = Query(True, description="Include AI-powered analysis"),
):
    """
    Analyze Docker image layers for secrets and security issues.
    
    Examines:
    - Image history and layer commands
    - ENV/ARG secrets
    - Hardcoded credentials in RUN commands
    - Security misconfigurations (root user, chmod 777, etc.)
    - Suspicious operations (curl | sh, sensitive file access)
    
    Note: Requires Docker to be installed and the image must be pulled locally.
    """
    if not check_docker_available():
        raise HTTPException(
            status_code=503,
            detail="Docker is not available. Please install Docker to use this feature."
        )
    
    logger.info(f"Analyzing Docker image: {image_name}")
    
    try:
        # Perform analysis
        result = re_service.analyze_docker_image(image_name)
        
        if result.error:
            raise HTTPException(status_code=400, detail=result.error)
        
        # Run AI analysis if requested
        if include_ai:
            result.ai_analysis = await re_service.analyze_docker_with_ai(result)
        
        # Convert to response model
        return DockerAnalysisResponse(
            image_name=result.image_name,
            image_id=result.image_id,
            total_layers=result.total_layers,
            total_size=result.total_size,
            total_size_human=format_size(result.total_size),
            base_image=result.base_image,
            layers=[
                DockerLayerResponse(
                    id=layer["id"],
                    command=layer["command"],
                    size=layer["size"],
                )
                for layer in result.layers
            ],
            secrets=[
                DockerSecretResponse(
                    layer_id=s.layer_id,
                    layer_command=s.layer_command,
                    secret_type=s.secret_type,
                    value=s.value,
                    masked_value=s.masked_value,
                    context=s.context,
                    severity=s.severity,
                )
                for s in result.secrets
            ],
            deleted_files=result.deleted_files,
            security_issues=[
                DockerSecurityIssueResponse(
                    category=issue["category"],
                    severity=issue["severity"],
                    description=issue["description"],
                    command=issue.get("command"),
                )
                for issue in result.security_issues
            ],
            ai_analysis=result.ai_analysis,
            error=result.error,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Docker analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/docker-images")
async def list_local_docker_images():
    """
    List locally available Docker images for analysis.
    """
    if not check_docker_available():
        raise HTTPException(
            status_code=503,
            detail="Docker is not available."
        )
    
    import subprocess
    
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}|||{{.ID}}|||{{.Size}}|||{{.CreatedAt}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="Failed to list Docker images")
        
        images = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('|||')
            if len(parts) >= 4:
                images.append({
                    "name": parts[0],
                    "id": parts[1][:12],
                    "size": parts[2],
                    "created": parts[3],
                })
        
        return {"images": images, "total": len(images)}
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Docker command timed out")
    except Exception as e:
        logger.error(f"Failed to list Docker images: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Hex Viewer Endpoint
# ============================================================================

# Store uploaded files temporarily for hex viewing
_hex_view_cache: Dict[str, Path] = {}


@router.post("/hex-upload")
async def upload_for_hex_view(
    file: UploadFile = File(..., description="Binary file to view in hex"),
):
    """
    Upload a file for hex viewing. Returns a file ID for subsequent hex view requests.
    """
    import uuid
    
    filename = file.filename or "unknown"
    file_id = str(uuid.uuid4())
    
    tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_hex_"))
    tmp_path = tmp_dir / filename
    
    file_size = 0
    with tmp_path.open("wb") as f:
        while chunk := await file.read(65536):
            file_size += len(chunk)
            if file_size > MAX_FILE_SIZE:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                raise HTTPException(
                    status_code=400,
                    detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
                )
            f.write(chunk)
    
    _hex_view_cache[file_id] = tmp_path
    
    logger.info(f"Uploaded file for hex view: {filename} ({file_size:,} bytes), ID: {file_id}")
    
    return {
        "file_id": file_id,
        "filename": filename,
        "file_size": file_size,
    }


@router.get("/hex/{file_id}", response_model=HexViewResponse)
async def get_hex_view(
    file_id: str,
    offset: int = Query(0, ge=0, description="Byte offset to start from"),
    length: int = Query(512, ge=16, le=4096, description="Number of bytes to return"),
):
    """
    Get hex view of an uploaded file.
    
    Returns hex dump with:
    - Offset, hex bytes, and ASCII preview
    - Structured rows (16 bytes per row)
    """
    if file_id not in _hex_view_cache:
        raise HTTPException(status_code=404, detail="File not found. Upload a file first.")
    
    file_path = _hex_view_cache[file_id]
    
    if not file_path.exists():
        del _hex_view_cache[file_id]
        raise HTTPException(status_code=404, detail="File no longer available. Please re-upload.")
    
    try:
        total_size = file_path.stat().st_size
        
        # Ensure offset is valid
        if offset >= total_size:
            offset = max(0, total_size - length)
        
        # Read the requested chunk
        with file_path.open("rb") as f:
            f.seek(offset)
            data = f.read(length)
        
        # Build hex rows (16 bytes per row)
        rows = []
        row_offset = offset
        for i in range(0, len(data), 16):
            row_data = data[i:i+16]
            hex_bytes = ' '.join(f'{b:02x}' for b in row_data)
            # Pad hex to align columns
            hex_bytes = hex_bytes.ljust(47)  # 16*2 + 15 spaces
            
            # ASCII preview (printable chars only)
            ascii_chars = ''.join(
                chr(b) if 32 <= b < 127 else '.'
                for b in row_data
            )
            
            rows.append({
                "offset": row_offset,
                "offset_hex": f"{row_offset:08x}",
                "hex": hex_bytes,
                "ascii": ascii_chars,
                "bytes": list(row_data),
            })
            row_offset += 16
        
        # Full hex and ASCII for the chunk
        hex_data = ' '.join(f'{b:02x}' for b in data)
        ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        
        return HexViewResponse(
            offset=offset,
            length=len(data),
            total_size=total_size,
            hex_data=hex_data,
            ascii_preview=ascii_preview,
            rows=rows,
        )
        
    except Exception as e:
        logger.error(f"Hex view error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")


@router.get("/hex/{file_id}/search")
async def search_hex(
    file_id: str,
    query: str = Query(..., min_length=1, max_length=100, description="Search string (text or hex)"),
    search_type: str = Query("text", description="Search type: 'text' or 'hex'"),
    max_results: int = Query(50, ge=1, le=200, description="Maximum results to return"),
):
    """
    Search for a pattern in the hex file.
    
    Supports:
    - Text search (ASCII)
    - Hex pattern search (e.g., "4d5a" or "4d 5a 90")
    """
    if file_id not in _hex_view_cache:
        raise HTTPException(status_code=404, detail="File not found.")
    
    file_path = _hex_view_cache[file_id]
    
    if not file_path.exists():
        del _hex_view_cache[file_id]
        raise HTTPException(status_code=404, detail="File no longer available.")
    
    try:
        with file_path.open("rb") as f:
            data = f.read()
        
        # Prepare search pattern
        if search_type == "hex":
            # Parse hex string (remove spaces)
            hex_clean = query.replace(" ", "").replace("-", "")
            try:
                pattern = bytes.fromhex(hex_clean)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid hex pattern")
        else:
            pattern = query.encode('utf-8')
        
        # Find all occurrences
        results = []
        start = 0
        while len(results) < max_results:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            
            # Get context around the match
            ctx_start = max(0, pos - 16)
            ctx_end = min(len(data), pos + len(pattern) + 16)
            context = data[ctx_start:ctx_end]
            
            results.append({
                "offset": pos,
                "offset_hex": f"{pos:08x}",
                "match_length": len(pattern),
                "context_hex": ' '.join(f'{b:02x}' for b in context),
                "context_ascii": ''.join(chr(b) if 32 <= b < 127 else '.' for b in context),
                "match_offset_in_context": pos - ctx_start,
            })
            
            start = pos + 1
        
        return {
            "query": query,
            "search_type": search_type,
            "pattern_hex": pattern.hex(),
            "total_matches": len(results),
            "results": results,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Hex search error: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.delete("/hex/{file_id}")
async def delete_hex_file(file_id: str):
    """Delete an uploaded hex view file to free resources."""
    if file_id not in _hex_view_cache:
        raise HTTPException(status_code=404, detail="File not found.")
    
    file_path = _hex_view_cache[file_id]
    
    try:
        if file_path.exists():
            shutil.rmtree(file_path.parent, ignore_errors=True)
        del _hex_view_cache[file_id]
        return {"message": "File deleted", "file_id": file_id}
    except Exception as e:
        logger.error(f"Failed to delete hex file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Report Management Endpoints
# ============================================================================

class SaveReportRequest(BaseModel):
    """Request to save a reverse engineering report."""
    analysis_type: str  # 'binary', 'apk', 'docker'
    title: str
    filename: Optional[str] = None
    project_id: Optional[int] = None
    
    # Risk assessment
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    
    # Type-specific fields
    file_type: Optional[str] = None
    architecture: Optional[str] = None
    file_size: Optional[int] = None
    is_packed: Optional[bool] = None
    packer_name: Optional[str] = None
    
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    
    image_name: Optional[str] = None
    image_id: Optional[str] = None
    total_layers: Optional[int] = None
    base_image: Optional[str] = None
    
    # Counts
    strings_count: Optional[int] = None
    imports_count: Optional[int] = None
    exports_count: Optional[int] = None
    secrets_count: Optional[int] = None
    
    # JSON data
    suspicious_indicators: Optional[List[Dict[str, Any]]] = None
    permissions: Optional[List[Dict[str, Any]]] = None
    security_issues: Optional[List[Dict[str, Any]]] = None
    full_analysis_data: Optional[Dict[str, Any]] = None
    
    # AI Analysis
    ai_analysis_raw: Optional[str] = None
    
    # JADX Full Scan Data
    jadx_total_classes: Optional[int] = None
    jadx_total_files: Optional[int] = None
    jadx_output_directory: Optional[str] = None
    jadx_classes_sample: Optional[List[Dict[str, Any]]] = None
    jadx_security_issues: Optional[List[Dict[str, Any]]] = None
    
    # AI-Generated Reports (Deep Analysis)
    ai_functionality_report: Optional[str] = None
    ai_security_report: Optional[str] = None
    ai_privacy_report: Optional[str] = None
    ai_architecture_diagram: Optional[str] = None
    ai_attack_surface_map: Optional[str] = None  # Mermaid attack tree diagram
    ai_threat_model: Optional[Dict[str, Any]] = None
    ai_vuln_scan_result: Optional[Dict[str, Any]] = None
    ai_chat_history: Optional[List[Dict[str, Any]]] = None
    
    # Library CVE Analysis
    detected_libraries: Optional[List[Dict[str, Any]]] = None  # Libraries detected in APK
    library_cves: Optional[List[Dict[str, Any]]] = None  # CVEs found in libraries
    
    # Tags and notes
    tags: Optional[List[str]] = None
    notes: Optional[str] = None


class ReportSummaryResponse(BaseModel):
    """Summary of a saved report."""
    id: int
    analysis_type: str
    title: str
    filename: Optional[str] = None
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    created_at: datetime
    tags: Optional[List[str]] = None


class ReportDetailResponse(BaseModel):
    """Full report detail response."""
    id: int
    analysis_type: str
    title: str
    filename: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    project_id: Optional[int] = None
    
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    
    file_type: Optional[str] = None
    architecture: Optional[str] = None
    file_size: Optional[int] = None
    is_packed: Optional[str] = None
    packer_name: Optional[str] = None
    
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    
    image_name: Optional[str] = None
    image_id: Optional[str] = None
    total_layers: Optional[int] = None
    base_image: Optional[str] = None
    
    strings_count: Optional[int] = None
    imports_count: Optional[int] = None
    exports_count: Optional[int] = None
    secrets_count: Optional[int] = None
    
    suspicious_indicators: Optional[List[Dict[str, Any]]] = None
    permissions: Optional[List[Dict[str, Any]]] = None
    security_issues: Optional[List[Dict[str, Any]]] = None
    full_analysis_data: Optional[Dict[str, Any]] = None
    
    ai_analysis_raw: Optional[str] = None
    ai_analysis_structured: Optional[Dict[str, Any]] = None
    
    # JADX Full Scan Data
    jadx_total_classes: Optional[int] = None
    jadx_total_files: Optional[int] = None
    jadx_data: Optional[Dict[str, Any]] = None
    
    # AI-Generated Reports
    ai_functionality_report: Optional[str] = None
    ai_security_report: Optional[str] = None
    ai_privacy_report: Optional[str] = None
    ai_architecture_diagram: Optional[str] = None
    ai_attack_surface_map: Optional[str] = None  # Mermaid attack tree diagram
    ai_threat_model: Optional[Dict[str, Any]] = None
    ai_vuln_scan_result: Optional[Dict[str, Any]] = None
    ai_chat_history: Optional[List[Dict[str, Any]]] = None
    
    # Library CVE Analysis
    detected_libraries: Optional[List[Dict[str, Any]]] = None
    library_cves: Optional[List[Dict[str, Any]]] = None
    
    tags: Optional[List[str]] = None
    notes: Optional[str] = None


@router.post("/reports", response_model=ReportSummaryResponse)
def save_report(
    request: SaveReportRequest,
    db: Session = Depends(get_db),
):
    """
    Save a reverse engineering analysis report.
    
    Stores the full analysis data for later review, comparison, or export.
    """
    from backend.models.models import ReverseEngineeringReport
    
    try:
        # Parse risk level from AI analysis if not provided
        risk_level = request.risk_level
        risk_score = request.risk_score
        
        if not risk_level and request.ai_analysis_raw:
            # Try to extract risk level from AI analysis
            ai_text = request.ai_analysis_raw.lower()
            if 'critical' in ai_text[:500]:
                risk_level = 'Critical'
                risk_score = risk_score or 90
            elif 'high' in ai_text[:500]:
                risk_level = 'High'
                risk_score = risk_score or 70
            elif 'medium' in ai_text[:500]:
                risk_level = 'Medium'
                risk_score = risk_score or 50
            elif 'low' in ai_text[:500]:
                risk_level = 'Low'
                risk_score = risk_score or 30
            elif 'clean' in ai_text[:500]:
                risk_level = 'Clean'
                risk_score = risk_score or 10
        
        report = ReverseEngineeringReport(
            analysis_type=request.analysis_type,
            title=request.title,
            filename=request.filename,
            project_id=request.project_id,
            
            risk_level=risk_level,
            risk_score=risk_score,
            
            file_type=request.file_type,
            architecture=request.architecture,
            file_size=request.file_size,
            is_packed=str(request.is_packed) if request.is_packed is not None else None,
            packer_name=request.packer_name,
            
            package_name=request.package_name,
            version_name=request.version_name,
            min_sdk=request.min_sdk,
            target_sdk=request.target_sdk,
            
            image_name=request.image_name,
            image_id=request.image_id,
            total_layers=request.total_layers,
            base_image=request.base_image,
            
            strings_count=request.strings_count,
            imports_count=request.imports_count,
            exports_count=request.exports_count,
            secrets_count=request.secrets_count,
            
            suspicious_indicators=request.suspicious_indicators,
            permissions=request.permissions,
            security_issues=request.security_issues,
            full_analysis_data=request.full_analysis_data,
            
            ai_analysis_raw=request.ai_analysis_raw,
            
            # JADX Full Scan Data
            jadx_total_classes=request.jadx_total_classes,
            jadx_total_files=request.jadx_total_files,
            jadx_data={
                "output_directory": request.jadx_output_directory,
                "classes_sample": request.jadx_classes_sample,
                "security_issues": request.jadx_security_issues,
            } if request.jadx_total_classes else None,
            
            # AI-Generated Reports
            ai_functionality_report=request.ai_functionality_report,
            ai_security_report=request.ai_security_report,
            ai_privacy_report=request.ai_privacy_report,
            ai_architecture_diagram=request.ai_architecture_diagram,
            ai_attack_surface_map=request.ai_attack_surface_map,
            ai_threat_model=request.ai_threat_model,
            ai_vuln_scan_result=request.ai_vuln_scan_result,
            ai_chat_history=request.ai_chat_history,
            
            # Library CVE Analysis
            detected_libraries=request.detected_libraries,
            library_cves=request.library_cves,
            
            tags=request.tags,
            notes=request.notes,
        )
        
        db.add(report)
        db.commit()
        db.refresh(report)
        
        logger.info(f"Saved RE report {report.id}: {request.title}")
        
        return ReportSummaryResponse(
            id=report.id,
            analysis_type=report.analysis_type,
            title=report.title,
            filename=report.filename,
            risk_level=report.risk_level,
            risk_score=report.risk_score,
            created_at=report.created_at,
            tags=report.tags,
        )
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to save report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save report: {str(e)}")


@router.get("/reports", response_model=List[ReportSummaryResponse])
def list_reports(
    analysis_type: Optional[str] = Query(None, description="Filter by analysis type (binary, apk, docker)"),
    project_id: Optional[int] = Query(None, description="Filter by project ID"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """
    List saved reverse engineering reports.
    
    Returns summaries of saved reports with optional filtering.
    """
    from backend.models.models import ReverseEngineeringReport
    
    query = db.query(ReverseEngineeringReport)
    
    if analysis_type:
        query = query.filter(ReverseEngineeringReport.analysis_type == analysis_type)
    if project_id:
        query = query.filter(ReverseEngineeringReport.project_id == project_id)
    if risk_level:
        query = query.filter(ReverseEngineeringReport.risk_level == risk_level)
    
    reports = query.order_by(ReverseEngineeringReport.created_at.desc()).offset(offset).limit(limit).all()
    
    return [
        ReportSummaryResponse(
            id=r.id,
            analysis_type=r.analysis_type,
            title=r.title,
            filename=r.filename,
            risk_level=r.risk_level,
            risk_score=r.risk_score,
            created_at=r.created_at,
            tags=r.tags,
        )
        for r in reports
    ]


@router.get("/reports/{report_id}", response_model=ReportDetailResponse)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
):
    """
    Get full details of a saved reverse engineering report.
    """
    from backend.models.models import ReverseEngineeringReport
    
    report = db.query(ReverseEngineeringReport).filter(ReverseEngineeringReport.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return ReportDetailResponse(
        id=report.id,
        analysis_type=report.analysis_type,
        title=report.title,
        filename=report.filename,
        created_at=report.created_at,
        updated_at=report.updated_at,
        project_id=report.project_id,
        
        risk_level=report.risk_level,
        risk_score=report.risk_score,
        
        file_type=report.file_type,
        architecture=report.architecture,
        file_size=report.file_size,
        is_packed=report.is_packed,
        packer_name=report.packer_name,
        
        package_name=report.package_name,
        version_name=report.version_name,
        min_sdk=report.min_sdk,
        target_sdk=report.target_sdk,
        
        image_name=report.image_name,
        image_id=report.image_id,
        total_layers=report.total_layers,
        base_image=report.base_image,
        
        strings_count=report.strings_count,
        imports_count=report.imports_count,
        exports_count=report.exports_count,
        secrets_count=report.secrets_count,
        
        suspicious_indicators=report.suspicious_indicators,
        permissions=report.permissions,
        security_issues=report.security_issues,
        full_analysis_data=report.full_analysis_data,
        
        ai_analysis_raw=report.ai_analysis_raw,
        ai_analysis_structured=report.ai_analysis_structured,
        
        # JADX Full Scan Data
        jadx_total_classes=report.jadx_total_classes,
        jadx_total_files=report.jadx_total_files,
        jadx_data=report.jadx_data,
        
        # AI-Generated Reports
        ai_functionality_report=report.ai_functionality_report,
        ai_security_report=report.ai_security_report,
        ai_privacy_report=report.ai_privacy_report,
        ai_architecture_diagram=report.ai_architecture_diagram,
        ai_attack_surface_map=report.ai_attack_surface_map,
        ai_threat_model=report.ai_threat_model,
        ai_vuln_scan_result=report.ai_vuln_scan_result,
        ai_chat_history=report.ai_chat_history,
        
        # Library CVE Analysis
        detected_libraries=report.detected_libraries,
        library_cves=report.library_cves,
        
        tags=report.tags,
        notes=report.notes,
    )


@router.get("/reports/{report_id}/export")
def export_saved_report(
    report_id: int,
    format: str = Query(..., description="Export format: markdown, pdf, docx"),
    db: Session = Depends(get_db),
):
    """
    Export a saved reverse engineering report to Markdown, PDF, or Word format.
    
    Includes all analysis data, AI reports, and JADX findings if available.
    """
    from fastapi.responses import Response
    from backend.models.models import ReverseEngineeringReport
    
    if format not in ["markdown", "pdf", "docx"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use: markdown, pdf, docx")
    
    report = db.query(ReverseEngineeringReport).filter(ReverseEngineeringReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    try:
        # Generate comprehensive export
        content = _generate_full_report_export(report, format)
        
        # Set filename
        base_name = report.package_name or report.image_name or report.filename or f"report_{report_id}"
        base_name = base_name.replace('/', '_').replace('\\', '_').split('.')[-2] if '.' in str(base_name) else base_name
        
        if format == "markdown":
            return Response(
                content=content.encode('utf-8'),
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="{base_name}_full_report.md"'}
            )
        elif format == "pdf":
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{base_name}_full_report.pdf"'}
            )
        elif format == "docx":
            return Response(
                content=content,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f'attachment; filename="{base_name}_full_report.docx"'}
            )
    except Exception as e:
        logger.error(f"Failed to export report {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


@router.post("/binary/export-from-result")
async def export_binary_report_from_result(
    result: BinaryAnalysisResponse,
    format: str = Query(..., description="Export format: markdown, pdf, docx"),
):
    """
    Export a binary analysis result to Markdown, PDF, or Word format.
    """
    if format not in ["markdown", "pdf", "docx"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use: markdown, pdf, docx")

    report = SimpleNamespace(
        title=f"Binary Analysis: {result.filename}",
        created_at=datetime.now(),
        updated_at=datetime.now(),
        analysis_type="binary",
        filename=result.filename,
        risk_level=None,
        risk_score=None,
        file_type=result.metadata.file_type,
        architecture=result.metadata.architecture,
        file_size=result.metadata.file_size,
        is_packed=str(result.metadata.is_packed),
        packer_name=result.metadata.packer_name,
        strings_count=result.strings_count,
        imports_count=len(result.imports),
        exports_count=len(result.exports),
        secrets_count=len(result.secrets),
        suspicious_indicators=[s.model_dump() for s in result.suspicious_indicators],
        permissions=None,
        security_issues=None,
        full_analysis_data={
            "metadata": result.metadata.model_dump(),
            "strings_sample": [s.model_dump() for s in result.strings_sample],
            "imports": [i.model_dump() for i in result.imports],
            "exports": result.exports,
            "secrets": [s.model_dump() for s in result.secrets],
            "ghidra_analysis": result.ghidra_analysis,
            "ghidra_ai_summaries": result.ghidra_ai_summaries,
        },
        ai_analysis_raw=result.ai_analysis,
        ai_analysis_structured=None,
        tags=None,
        notes=None,
        ai_functionality_report=None,
        ai_security_report=None,
        ai_privacy_report=None,
        ai_architecture_diagram=None,
        ai_attack_surface_map=None,
        ai_threat_model=None,
        ai_vuln_scan_result=None,
        ai_chat_history=None,
        detected_libraries=None,
        library_cves=None,
    )

    try:
        content = _generate_full_report_export(report, format)
        base_name = f"binary_analysis_{result.filename}".replace(" ", "_")

        if format == "markdown":
            return Response(
                content=content.encode("utf-8"),
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="{base_name}.md"'}
            )
        if format == "pdf":
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{base_name}.pdf"'}
            )
        return Response(
            content=content,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{base_name}.docx"'}
        )
    except Exception as e:
        logger.error(f"Binary export failed: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


def _generate_full_report_export(report, format: str):
    """Generate full export content for a saved report with clean, organized structure."""
    from io import BytesIO
    
    # Build comprehensive markdown content with clean structure
    # Structure: Executive Summary → Security Findings → Architecture → AI Analysis → Attack Surface → Secrets
    
    md_content = f"""# {report.title}

**Generated:** {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}
**Risk Level:** {report.risk_level or 'Not Assessed'} ({report.risk_score or 0}/100)

---

"""
    
    # =====================================================
    # SECTION 1: Executive Summary - What Does This APK Do?
    # =====================================================
    md_content += """## Executive Summary

"""
    
    # Basic identification info (minimal)
    if report.analysis_type == 'apk':
        md_content += f"**Package:** `{report.package_name or 'N/A'}` | **Version:** {report.version_name or 'N/A'}\n\n"
    elif report.analysis_type == 'binary':
        md_content += f"**Type:** {report.file_type or 'N/A'} | **Architecture:** {report.architecture or 'N/A'}\n\n"
    elif report.analysis_type == 'docker':
        md_content += f"**Image:** `{report.image_name or 'N/A'}` | **Base:** {report.base_image or 'N/A'}\n\n"
    
    # AI Functionality Report - What the app does
    if report.ai_functionality_report:
        md_content += f"""### What This Application Does

{report.ai_functionality_report}

"""
    elif report.ai_analysis_raw:
        # Fallback to quick analysis if no functionality report
        md_content += f"""### Application Overview

{report.ai_analysis_raw}

"""
    
    # =====================================================
    # SECTION 2: Security Findings - Attacker's Perspective
    # =====================================================
    md_content += """---

## Security Assessment - Attack Surface Analysis

This section analyzes the application from an attacker's perspective, identifying exploitable weaknesses and potential attack vectors.

"""
    
    # AI Security Report (high-level security assessment)
    if report.ai_security_report:
        md_content += f"""{report.ai_security_report}

"""
    
    # Consolidated security issues summary with attacker focus
    critical_count = high_count = medium_count = low_count = 0
    if report.security_issues:
        for issue in report.security_issues:
            sev = issue.get('severity', 'info').lower()
            if sev == 'critical': critical_count += 1
            elif sev == 'high': high_count += 1
            elif sev == 'medium': medium_count += 1
            elif sev == 'low': low_count += 1
        
        md_content += f"""### Vulnerability Summary

| Severity | Count | Attack Priority |
|----------|-------|-----------------|
| Critical | {critical_count} | Immediate exploitation possible |
| High | {high_count} | High-value targets |
| Medium | {medium_count} | Secondary targets |
| Low | {low_count} | Opportunistic |

"""
        # List critical and high issues with attacker-focused descriptions
        critical_high = [i for i in report.security_issues if i.get('severity', '').lower() in ['critical', 'high']]
        if critical_high:
            md_content += "### Exploitable Vulnerabilities\n\n"
            md_content += "*These issues present immediate exploitation opportunities:*\n\n"
            for issue in critical_high[:15]:
                severity = issue.get('severity', 'info')
                title = issue.get('title', issue.get('category', 'Unknown Issue'))
                md_content += f"#### {title} ({severity.upper()})\n\n"
                
                if issue.get('description'):
                    md_content += f"**Finding:** {issue.get('description')[:300]}\n\n"
                
                # Add exploitation context
                category = issue.get('category', '').lower()
                if 'sql' in category or 'injection' in category:
                    md_content += "**Attack Vector:** Database manipulation, data exfiltration, authentication bypass\n\n"
                elif 'crypto' in category or 'encrypt' in category:
                    md_content += "**Attack Vector:** Decrypt sensitive data, forge tokens, bypass integrity checks\n\n"
                elif 'auth' in category or 'permission' in category:
                    md_content += "**Attack Vector:** Privilege escalation, unauthorized access to protected resources\n\n"
                elif 'webview' in category or 'javascript' in category:
                    md_content += "**Attack Vector:** JavaScript injection, steal cookies/tokens, phishing\n\n"
                elif 'export' in category or 'component' in category:
                    md_content += "**Attack Vector:** Intent hijacking, data theft via exported components\n\n"
                elif 'network' in category or 'http' in category:
                    md_content += "**Attack Vector:** Man-in-the-middle, traffic interception, credential theft\n\n"
                elif 'secret' in category or 'key' in category or 'credential' in category:
                    md_content += "**Attack Vector:** Use hardcoded credentials for unauthorized API/service access\n\n"
                elif 'debug' in category:
                    md_content += "**Attack Vector:** Attach debugger, inspect memory, modify runtime behavior\n\n"
                
                # Include file/location for manual review
                file_loc = issue.get('file', issue.get('location', issue.get('affected_class', '')))
                if file_loc:
                    md_content += f"**Target Location:** `{file_loc}`\n\n"
    
    # Dangerous permissions with exploitation context
    if report.permissions:
        dangerous = [p for p in report.permissions if p.get('is_dangerous')]
        if dangerous:
            md_content += "### Dangerous Permissions - Attack Enablers\n\n"
            md_content += "*These permissions grant capabilities that can be abused:*\n\n"
            for p in dangerous[:10]:
                perm_name = p.get('name', '')
                md_content += f"- **{perm_name}**\n"
                
                # Add exploitation context for common dangerous permissions
                if 'CAMERA' in perm_name:
                    md_content += "  - *Exploitation:* Covert photo/video capture, surveillance\n"
                elif 'MICROPHONE' in perm_name or 'RECORD_AUDIO' in perm_name:
                    md_content += "  - *Exploitation:* Audio surveillance, conversation recording\n"
                elif 'LOCATION' in perm_name:
                    md_content += "  - *Exploitation:* User tracking, location history theft\n"
                elif 'READ_CONTACTS' in perm_name or 'WRITE_CONTACTS' in perm_name:
                    md_content += "  - *Exploitation:* Contact list exfiltration, spam distribution\n"
                elif 'READ_SMS' in perm_name or 'SEND_SMS' in perm_name:
                    md_content += "  - *Exploitation:* 2FA bypass, premium SMS fraud\n"
                elif 'READ_EXTERNAL_STORAGE' in perm_name or 'WRITE_EXTERNAL_STORAGE' in perm_name:
                    md_content += "  - *Exploitation:* Data theft from shared storage, malware staging\n"
                elif 'READ_CALL_LOG' in perm_name:
                    md_content += "  - *Exploitation:* Call history surveillance, contact profiling\n"
                elif 'SYSTEM_ALERT_WINDOW' in perm_name:
                    md_content += "  - *Exploitation:* Overlay attacks, clickjacking, credential theft\n"
                else:
                    md_content += f"  - {p.get('description', 'Review for abuse potential')}\n"
            md_content += "\n"
    
    # =====================================================
    # SECTION 2B: Known CVEs in Third-Party Libraries
    # =====================================================
    if report.library_cves:
        cves = report.library_cves
        critical_cves = [c for c in cves if c.get('severity', '').lower() == 'critical']
        high_cves = [c for c in cves if c.get('severity', '').lower() == 'high']
        
        md_content += f"""### Known Vulnerabilities in Dependencies (CVE Lookup)

**Total CVEs Found:** {len(cves)} | **Critical:** {len(critical_cves)} | **High:** {len(high_cves)}

*These are known, published vulnerabilities in the third-party libraries bundled with this application.*

"""
        
        # Critical CVEs first - immediate exploitation risk
        if critical_cves:
            md_content += "#### Critical CVEs - Immediate Exploitation Risk\n\n"
            for cve in critical_cves[:10]:
                cve_id = cve.get('cve_id', 'Unknown')
                library = cve.get('library', 'Unknown')
                summary = cve.get('summary', 'No description')[:200]
                exploitation = cve.get('exploitation_potential', 'Review required')
                attack_vector = cve.get('attack_vector', 'Unknown')
                
                md_content += f"**{cve_id}** in `{library}`\n\n"
                md_content += f"- **Summary:** {summary}\n"
                md_content += f"- **CVSS Score:** {cve.get('cvss_score', 'N/A')}\n"
                md_content += f"- **Exploitation:** {exploitation}\n"
                md_content += f"- **Attack Vector:** {attack_vector}\n"
                
                if cve.get('affected_versions'):
                    md_content += f"- **Fix:** {', '.join(cve.get('affected_versions', []))}\n"
                
                if cve.get('references'):
                    md_content += f"- **Reference:** {cve.get('references', [''])[0]}\n"
                
                md_content += "\n"
        
        # High severity CVEs
        if high_cves:
            md_content += "#### High Severity CVEs\n\n"
            for cve in high_cves[:10]:
                cve_id = cve.get('cve_id', 'Unknown')
                library = cve.get('library', 'Unknown')
                summary = cve.get('summary', 'No description')[:150]
                
                md_content += f"- **{cve_id}** in `{library}`: {summary}\n"
                md_content += f"  - CVSS: {cve.get('cvss_score', 'N/A')} | {cve.get('exploitation_potential', '')}\n"
            
            md_content += "\n"
        
        # Summary table of all CVEs
        if len(cves) > 0:
            md_content += "#### All Detected CVEs\n\n"
            md_content += "| CVE ID | Library | Severity | CVSS |\n"
            md_content += "|--------|---------|----------|------|\n"
            for cve in cves[:25]:
                md_content += f"| {cve.get('cve_id', 'N/A')} | {cve.get('library', 'N/A')[:30]} | {cve.get('severity', 'N/A').upper()} | {cve.get('cvss_score', 'N/A')} |\n"
            
            if len(cves) > 25:
                md_content += f"\n*...and {len(cves) - 25} more CVEs*\n"
            
            md_content += "\n"
    
    # Detected libraries summary (even if no CVEs)
    if report.detected_libraries and not report.library_cves:
        libs = report.detected_libraries
        high_risk = [l for l in libs if l.get('is_high_risk')]
        
        md_content += f"""### Detected Third-Party Libraries

**Total Libraries:** {len(libs)} | **High-Risk Libraries:** {len(high_risk)}

*No known CVEs found in OSV database for the detected library versions.*

"""
        if high_risk:
            md_content += "**High-Risk Libraries (historically vulnerable):**\n\n"
            for lib in high_risk:
                md_content += f"- `{lib.get('maven_coordinate', 'Unknown')}` - {lib.get('risk_reason', 'Review recommended')}\n"
            md_content += "\n"

    # =====================================================
    # SECTION 2C: Binary Static Analysis (Binary only)
    # =====================================================
    if report.analysis_type == 'binary':
        md_content += """---

## Binary Static Analysis

"""
        md_content += f"**File Type:** {report.file_type or 'N/A'} | **Architecture:** {report.architecture or 'N/A'}\n\n"
        md_content += f"- **File Size:** {format_size(report.file_size or 0)}\n"
        md_content += f"- **Strings:** {report.strings_count or 0}\n"
        md_content += f"- **Imports:** {report.imports_count or 0}\n"
        md_content += f"- **Exports:** {report.exports_count or 0}\n"
        md_content += f"- **Secrets:** {report.secrets_count or 0}\n"
        md_content += f"- **Packed:** {report.is_packed or 'unknown'} {f'({report.packer_name})' if report.packer_name else ''}\n\n"

        if report.suspicious_indicators:
            md_content += "### Suspicious Indicators\n\n"
            for indicator in report.suspicious_indicators[:25]:
                md_content += f"- **{indicator.get('severity', 'info').upper()}** {indicator.get('category', 'Unknown')}: {indicator.get('description', '')}\n"
            if len(report.suspicious_indicators) > 25:
                md_content += f"\n*...and {len(report.suspicious_indicators) - 25} more indicators*\n"
            md_content += "\n"

        ctx = report.full_analysis_data or {}
        imports = ctx.get("imports", []) if isinstance(ctx, dict) else []
        suspicious_imports = [i for i in imports if i.get("is_suspicious")]
        if suspicious_imports:
            md_content += "### Suspicious Imports\n\n"
            for imp in suspicious_imports[:30]:
                md_content += f"- `{imp.get('name')}` ({imp.get('library')}): {imp.get('reason', 'Suspicious API')}\n"
            if len(suspicious_imports) > 30:
                md_content += f"\n*...and {len(suspicious_imports) - 30} more suspicious imports*\n"
            md_content += "\n"

        secrets = ctx.get("secrets", []) if isinstance(ctx, dict) else []
        if secrets:
            md_content += "### Potential Secrets\n\n"
            for s in secrets[:20]:
                md_content += f"- **{s.get('severity', 'medium').upper()}** {s.get('type')}: `{s.get('masked_value')}`\n"
            if len(secrets) > 20:
                md_content += f"\n*...and {len(secrets) - 20} more secrets*\n"
            md_content += "\n"

        ghidra = ctx.get("ghidra_analysis", {}) if isinstance(ctx, dict) else {}
        ghidra_ai = ctx.get("ghidra_ai_summaries", []) if isinstance(ctx, dict) else []
        if ghidra:
            md_content += "### Ghidra Decompilation\n\n"
            if ghidra.get("error"):
                md_content += f"**Ghidra Error:** {ghidra.get('error')}\n\n"
            else:
                program = ghidra.get("program", {})
                md_content += "**Program Metadata**\n\n"
                md_content += f"- **Name:** `{program.get('name', 'N/A')}`\n"
                md_content += f"- **Processor:** `{program.get('processor', 'N/A')}`\n"
                md_content += f"- **Language ID:** `{program.get('language_id', 'N/A')}`\n"
                md_content += f"- **Compiler Spec:** `{program.get('compiler_spec', 'N/A')}`\n"
                md_content += f"- **Image Base:** `{program.get('image_base', 'N/A')}`\n\n"

                functions = ghidra.get("functions", []) or []
                total_functions = ghidra.get("functions_total", len(functions))
                max_export = 30
                md_content += f"**Decompiled Functions (showing {min(len(functions), max_export)} of {total_functions})**\n\n"

                summary_map = {}
                for summary in ghidra_ai or []:
                    key = f"{summary.get('name')}:{summary.get('entry')}"
                    summary_map[key] = summary

                for fn in functions[:max_export]:
                    fn_name = fn.get("name", "unknown")
                    fn_entry = fn.get("entry", "0x0")
                    fn_size = fn.get("size", 0)
                    md_content += f"#### {fn_name} ({fn_entry})\n\n"
                    md_content += f"- **Size:** {fn_size} bytes\n"
                    if fn.get("called_functions"):
                        called = fn.get("called_functions", [])
                        md_content += f"- **Calls:** {', '.join(called[:12])}"
                        if len(called) > 12:
                            md_content += f" (+{len(called) - 12} more)"
                        md_content += "\n"

                    summary_key = f"{fn_name}:{fn_entry}"
                    summary = summary_map.get(summary_key)
                    if summary and summary.get("summary"):
                        md_content += "\n**Gemini Summary**\n\n"
                        md_content += f"{summary.get('summary')}\n\n"

                    if fn.get("decompiled"):
                        md_content += "```c\n"
                        md_content += f"{fn.get('decompiled')}\n"
                        md_content += "```\n\n"

                if total_functions > max_export:
                    md_content += f"*...and {total_functions - max_export} more functions*\n\n"
    
    # =====================================================
    # SECTION 3: Architecture Diagram
    # =====================================================
    if report.ai_architecture_diagram:
        md_content += f"""---

## Application Architecture

The following diagram illustrates the high-level architecture and component relationships within the application.

```mermaid
{report.ai_architecture_diagram}
```

"""
    
    # =====================================================
    # SECTION 4: AI Cross-Class Vulnerability Analysis
    # =====================================================
    if report.ai_vuln_scan_result:
        vuln_data = report.ai_vuln_scan_result
        
        # Check if we have enhanced security data embedded
        enhanced_security = vuln_data.get('enhanced_security')
        
        if enhanced_security:
            # Use enhanced security data for the main analysis section
            md_content += f"""---

## Comprehensive Security Analysis

**Analysis Sources:** Pattern Detection + AI Analysis + CVE Lookup

**Overall Risk Level:** {enhanced_security.get('overall_risk', 'N/A').upper()}

### Executive Summary

{enhanced_security.get('executive_summary', 'No summary available.')}

### Risk Distribution

| Severity | Count |
|----------|-------|
| Critical | {enhanced_security.get('risk_summary', {}).get('critical', 0)} |
| High | {enhanced_security.get('risk_summary', {}).get('high', 0)} |
| Medium | {enhanced_security.get('risk_summary', {}).get('medium', 0)} |
| Low | {enhanced_security.get('risk_summary', {}).get('low', 0)} |
| Info | {enhanced_security.get('risk_summary', {}).get('info', 0)} |

### Analysis Metadata

- **Classes Scanned:** {enhanced_security.get('analysis_metadata', {}).get('classes_scanned', 0)}
- **Libraries Detected:** {enhanced_security.get('analysis_metadata', {}).get('libraries_detected', 0)}
- **CVEs Found:** {enhanced_security.get('analysis_metadata', {}).get('cves_found', 0)}

"""
            # Offensive Plan Summary (AI-generated assessment - this is the main export content)
            offensive_plan = enhanced_security.get('offensive_plan_summary')
            if offensive_plan:
                md_content += """---

## Offensive Security Assessment

"""
                if offensive_plan.get('threat_assessment'):
                    md_content += f"""### Threat Assessment

{offensive_plan.get('threat_assessment')}

"""
                
                if offensive_plan.get('attack_surface_summary'):
                    md_content += f"""### Attack Surface

{offensive_plan.get('attack_surface_summary')}

"""
                
                # Primary Attack Vectors
                attack_vectors = offensive_plan.get('primary_attack_vectors', [])
                if attack_vectors:
                    md_content += "### Primary Attack Vectors\n\n"
                    for i, vector in enumerate(attack_vectors, 1):
                        md_content += f"#### {i}. {vector.get('vector', 'Unknown')}\n\n"
                        md_content += f"**Likelihood:** {vector.get('likelihood', 'Unknown')} | "
                        md_content += f"**Impact:** {vector.get('impact', 'Unknown')}\n\n"
                        md_content += f"{vector.get('description', '')}\n\n"
                        if vector.get('prerequisites'):
                            md_content += f"**Prerequisites:** {vector.get('prerequisites')}\n\n"
                
                # Recommended Test Scenarios
                test_scenarios = offensive_plan.get('recommended_test_scenarios', [])
                if test_scenarios:
                    md_content += "### Recommended Penetration Tests\n\n"
                    for i, scenario in enumerate(test_scenarios, 1):
                        md_content += f"{i}. {scenario}\n"
                    md_content += "\n"
                
                # Priority Targets
                priority_targets = offensive_plan.get('priority_targets', [])
                if priority_targets:
                    md_content += "### Priority Targets\n\n"
                    for target in priority_targets:
                        md_content += f"- {target}\n"
                    md_content += "\n"
                
                # Risk Rating and Confidence
                md_content += f"""### Assessment Summary

- **Risk Rating:** {offensive_plan.get('risk_rating', 'Unknown').upper()}
- **Confidence Level:** {offensive_plan.get('confidence_level', 'Unknown')}

"""
            
            # Recommendations from enhanced security
            recommendations = enhanced_security.get('recommendations', [])
            if recommendations:
                md_content += "### Remediation Recommendations\n\n"
                for rec in recommendations:
                    md_content += f"- {rec}\n"
                md_content += "\n"
            
            # Brief summary of findings (counts only, not individual details)
            combined_findings = enhanced_security.get('combined_findings', [])
            if combined_findings:
                md_content += f"""### Findings Summary

A total of **{len(combined_findings)}** security findings were identified:

"""
                # Group by severity for count summary
                for severity in ['critical', 'high', 'medium', 'low']:
                    severity_findings = [f for f in combined_findings if f.get('severity', '').lower() == severity]
                    if severity_findings:
                        # Get unique titles for this severity
                        unique_titles = list(set(f.get('title', 'Unknown') for f in severity_findings))[:5]
                        md_content += f"- **{severity.upper()}** ({len(severity_findings)}): {', '.join(unique_titles)}"
                        if len(severity_findings) > 5:
                            md_content += f" and {len(severity_findings) - 5} more"
                        md_content += "\n"
                
                md_content += "\n*Note: Individual findings are available in the application for detailed review.*\n\n"
        
        else:
            # Fall back to original AI vuln scan format
            md_content += f"""---

## AI Deep Vulnerability Analysis

**Classes Analyzed:** {vuln_data.get('classes_scanned', 0)} | **Overall Risk:** {vuln_data.get('overall_risk', 'N/A')}

### Risk Distribution
- Critical: {vuln_data.get('risk_summary', {}).get('critical', 0)}
- High: {vuln_data.get('risk_summary', {}).get('high', 0)}
- Medium: {vuln_data.get('risk_summary', {}).get('medium', 0)}
- Low: {vuln_data.get('risk_summary', {}).get('low', 0)}

"""
            if vuln_data.get('vulnerabilities'):
                md_content += "### Key Vulnerabilities\n\n"
                for vuln in vuln_data.get('vulnerabilities', [])[:15]:
                    severity = vuln.get('severity', 'N/A')
                    md_content += f"#### {vuln.get('title', 'Vulnerability')} ({severity.upper()})\n\n"
                    md_content += f"- **Category:** {vuln.get('category', 'N/A')}\n"
                    if vuln.get('cwe_id'):
                        md_content += f"- **CWE:** {vuln.get('cwe_id')}\n"
                    md_content += f"- **Description:** {vuln.get('description', 'N/A')}\n"
                    
                    # Include affected class/method for manual code review
                    affected_class = vuln.get('affected_class', '')
                    affected_method = vuln.get('affected_method', '')
                    if affected_class:
                        md_content += f"- **Affected Class:** `{affected_class}`\n"
                    if affected_method:
                        md_content += f"- **Affected Method:** `{affected_method}`\n"
                    
                    # Include code snippet if available
                    if vuln.get('code_snippet'):
                        snippet = vuln.get('code_snippet', '')[:500]
                        md_content += f"- **Code to Review:**\n```java\n{snippet}\n```\n"
                    
                    if vuln.get('impact'):
                        md_content += f"- **Impact:** {vuln.get('impact')}\n"
                    if vuln.get('remediation'):
                        md_content += f"- **Remediation:** {vuln.get('remediation')}\n"
                    md_content += "\n"
        
        # Attack chains if available (fallback for non-enhanced data)
        if not enhanced_security and vuln_data.get('attack_chains'):
            md_content += "### Attack Chains\n\n"
            for chain in vuln_data.get('attack_chains', [])[:5]:
                md_content += f"#### {chain.get('name', 'Attack Chain')}\n\n"
                md_content += f"**Likelihood:** {chain.get('likelihood', 'Unknown')} | **Impact:** {chain.get('impact', 'Unknown')}\n\n"
                if chain.get('steps'):
                    md_content += "**Steps:**\n"
                    for i, step in enumerate(chain.get('steps', []), 1):
                        md_content += f"{i}. {step}\n"
                md_content += "\n"
        
        # Recommendations for further research (fallback for non-enhanced data)
        if not enhanced_security and vuln_data.get('recommendations'):
            md_content += "### Recommendations for Further Analysis\n\n"
            for rec in vuln_data.get('recommendations', []):
                md_content += f"- {rec}\n"
            md_content += "\n"
    
    # =====================================================
    # SECTION 5: Attack Surface Map
    # =====================================================
    if report.ai_attack_surface_map:
        md_content += f"""---

## Attack Surface Map

This attack tree visualizes entry points, vulnerabilities, and potential attack paths discovered through AI analysis of the decompiled source code.

```mermaid
{report.ai_attack_surface_map}
```

"""
    
    # =====================================================
    # SECTION 6: Exposed Secrets
    # =====================================================
    secrets_found = []
    
    # Collect secrets from various sources
    if report.jadx_data and report.jadx_data.get('secrets'):
        secrets_found.extend(report.jadx_data.get('secrets', []))
    
    if report.security_issues:
        for issue in report.security_issues:
            if 'secret' in issue.get('category', '').lower() or 'key' in issue.get('category', '').lower() or 'credential' in issue.get('category', '').lower():
                secrets_found.append({
                    'type': issue.get('category', 'Secret'),
                    'description': issue.get('description', '')[:100],
                    'location': issue.get('file', issue.get('location', 'Unknown'))
                })
    
    if secrets_found or (report.secrets_count and report.secrets_count > 0):
        md_content += f"""---

## Exposed Secrets & Credentials

**Total Secrets Found:** {report.secrets_count or len(secrets_found)}

"""
        if secrets_found:
            md_content += "| Type | Location | Details |\n|------|----------|--------|\n"
            for secret in secrets_found[:20]:
                if isinstance(secret, dict):
                    stype = secret.get('type', secret.get('category', 'Secret'))
                    loc = secret.get('location', secret.get('file', 'Unknown'))[:50]
                    desc = secret.get('description', secret.get('value', ''))[:40]
                    md_content += f"| {stype} | `{loc}` | {desc}... |\n"
                else:
                    md_content += f"| Secret | - | {str(secret)[:50]}... |\n"
            md_content += "\n"
            if len(secrets_found) > 20:
                md_content += f"*...and {len(secrets_found) - 20} more secrets*\n\n"
    
    # =====================================================
    # SECTION 7: Privacy Analysis (if available)
    # =====================================================
    if report.ai_privacy_report:
        md_content += f"""---

## Privacy Analysis

{report.ai_privacy_report}

"""
    
    # =====================================================
    # SECTION 8: Threat Model (if available)
    # =====================================================
    if report.ai_threat_model:
        tm = report.ai_threat_model
        md_content += """---

## Threat Model

"""
        if tm.get('threat_actors'):
            md_content += "### Potential Threat Actors\n\n"
            for actor in tm.get('threat_actors', [])[:5]:
                md_content += f"- **{actor.get('name', 'Unknown')}**: {actor.get('description', '')}\n"
            md_content += "\n"
        
        if tm.get('attack_scenarios'):
            md_content += "### Attack Scenarios\n\n"
            for scenario in tm.get('attack_scenarios', [])[:3]:
                md_content += f"**{scenario.get('name', 'Scenario')}:** {scenario.get('description', '')}\n\n"
    
    # =====================================================
    # SECTION 9: Appendix - Technical Details
    # =====================================================
    md_content += """---

## Appendix

"""
    
    # Analysis metadata
    if report.analysis_type == 'apk':
        md_content += f"""### Technical Details

| Property | Value |
|----------|-------|
| Package Name | `{report.package_name or 'N/A'}` |
| Version Name | {report.version_name or 'N/A'} |
| Min SDK | {report.min_sdk or 'N/A'} |
| Target SDK | {report.target_sdk or 'N/A'} |

"""
    
    # JADX stats if available
    if report.jadx_total_classes:
        md_content += f"""### Code Analysis Statistics

| Metric | Value |
|--------|-------|
| Total Classes | {report.jadx_total_classes:,} |
| Total Files | {report.jadx_total_files:,} |

"""
    
    # Notes
    if report.notes:
        md_content += f"""### Analyst Notes

{report.notes}

"""
    
    # Tags
    if report.tags:
        md_content += f"""### Tags

{', '.join(f'`{tag}`' for tag in report.tags)}

"""

    md_content += f"""---

*Report generated by VRAgent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

    # Return based on format
    if format == "markdown":
        return md_content
    
    elif format == "pdf":
        # Generate properly formatted PDF
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_LEFT, TA_CENTER
            import re
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=20, spaceAfter=20, alignment=TA_CENTER, textColor=colors.darkblue)
            h1_style = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=16, spaceBefore=20, spaceAfter=10, textColor=colors.darkblue)
            h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, spaceBefore=15, spaceAfter=8, textColor=colors.darkblue)
            h3_style = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=12, spaceBefore=12, spaceAfter=6)
            body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, spaceBefore=4, spaceAfter=4, leading=14)
            code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=9, backColor=colors.lightgrey, leftIndent=10, rightIndent=10, spaceBefore=6, spaceAfter=6)
            bullet_style = ParagraphStyle('Bullet', parent=body_style, leftIndent=20, bulletIndent=10)
            
            story = []
            
            # Title
            story.append(Paragraph(report.title, title_style))
            story.append(Spacer(1, 12))
            
            # Parse markdown and convert to PDF elements
            lines = md_content.split('\n')
            i = 0
            in_code_block = False
            code_content = []
            code_language = None
            in_table = False
            table_rows = []
            
            while i < len(lines):
                line = lines[i]
                
                # Handle code blocks
                if line.strip().startswith('```'):
                    if in_code_block:
                        # End code block
                        if code_content:
                            if code_language == 'mermaid':
                                # Render mermaid as image
                                mermaid_code = '\n'.join(code_content)
                                img_bytes = _render_mermaid_to_image(mermaid_code, 'png')
                                if img_bytes:
                                    from reportlab.platypus import Image
                                    img_buffer = BytesIO(img_bytes)
                                    try:
                                        img = Image(img_buffer, width=450, height=300)
                                        img.hAlign = 'CENTER'
                                        story.append(img)
                                        story.append(Spacer(1, 10))
                                    except Exception as img_err:
                                        logger.warning(f"Failed to add mermaid image to PDF: {img_err}")
                                        # Fallback to code
                                        code_text = '<br/>'.join([l.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;') for l in code_content])
                                        story.append(Paragraph(code_text, code_style))
                                else:
                                    # Fallback: show as code block
                                    code_text = '<br/>'.join([l.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;') for l in code_content])
                                    story.append(Paragraph(code_text, code_style))
                            else:
                                # Regular code block
                                code_text = '<br/>'.join([l.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;') for l in code_content])
                                story.append(Paragraph(code_text, code_style))
                            story.append(Spacer(1, 6))
                        code_content = []
                        code_language = None
                        in_code_block = False
                    else:
                        in_code_block = True
                        # Check for language specification
                        lang_match = line.strip()[3:].strip()
                        code_language = lang_match if lang_match else None
                    i += 1
                    continue
                
                if in_code_block:
                    code_content.append(line)
                    i += 1
                    continue
                
                # Handle tables
                if '|' in line and line.strip().startswith('|'):
                    if not in_table:
                        in_table = True
                        table_rows = []
                    
                    # Skip separator lines (|---|---|)
                    if re.match(r'^\|[\s\-:]+\|', line):
                        i += 1
                        continue
                    
                    # Parse table row
                    cells = [c.strip() for c in line.split('|')[1:-1]]
                    if cells:
                        table_rows.append(cells)
                    i += 1
                    continue
                elif in_table:
                    # End of table
                    if table_rows:
                        # Create table with proper styling
                        col_count = max(len(row) for row in table_rows)
                        # Normalize rows and clean cell content
                        normalized = []
                        for row in table_rows:
                            cleaned_row = []
                            for cell in row:
                                # Strip markdown and escape for PDF
                                clean = _strip_markdown_formatting(cell)
                                clean = clean.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                                cleaned_row.append(clean)
                            # Pad row to match column count
                            cleaned_row += [''] * (col_count - len(cleaned_row))
                            normalized.append(cleaned_row)
                        t = Table(normalized, repeatRows=1)
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.darkblue),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ]))
                        story.append(t)
                        story.append(Spacer(1, 10))
                    table_rows = []
                    in_table = False
                
                # Headers
                if line.startswith('# '):
                    text = line[2:]
                    text = _html_to_reportlab(text) if '<' in text else _format_inline_markdown(text)
                    story.append(Paragraph(text, h1_style))
                elif line.startswith('## '):
                    text = line[3:]
                    text = _html_to_reportlab(text) if '<' in text else _format_inline_markdown(text)
                    story.append(Paragraph(text, h1_style))
                elif line.startswith('### '):
                    text = line[4:]
                    text = _html_to_reportlab(text) if '<' in text else _format_inline_markdown(text)
                    story.append(Paragraph(text, h2_style))
                elif line.startswith('#### '):
                    text = line[5:]
                    text = _html_to_reportlab(text) if '<' in text else _format_inline_markdown(text)
                    story.append(Paragraph(text, h3_style))
                # Bullet points
                elif line.strip().startswith('- ') or line.strip().startswith('* ') or line.strip().startswith('• '):
                    text = line.strip()[2:]
                    # Check if content has HTML
                    if '<' in text and '>' in text:
                        text = _html_to_reportlab(text)
                    else:
                        text = _format_inline_markdown(text)
                    story.append(Paragraph(f"• {text}", bullet_style))
                # Numbered lists
                elif re.match(r'^\s*\d+\.\s+', line):
                    text = re.sub(r'^\s*\d+\.\s+', '', line)
                    if '<' in text and '>' in text:
                        text = _html_to_reportlab(text)
                    else:
                        text = _format_inline_markdown(text)
                    num = re.match(r'^\s*(\d+)\.', line).group(1)
                    story.append(Paragraph(f"{num}. {text}", bullet_style))
                # Horizontal rule
                elif line.strip() == '---':
                    story.append(Spacer(1, 10))
                # Regular paragraph
                elif line.strip():
                    text = line.strip()
                    # Check if content has HTML tags
                    if '<' in text and '>' in text:
                        text = _html_to_reportlab(text)
                    else:
                        text = _format_inline_markdown(text)
                    story.append(Paragraph(text, body_style))
                # Empty line
                else:
                    story.append(Spacer(1, 6))
                
                i += 1
            
            doc.build(story)
            return buffer.getvalue()
            
        except ImportError as e:
            logger.error(f"PDF generation failed - missing library: {e}")
            # Fallback: return markdown as plain text
            return md_content.encode('utf-8')
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return md_content.encode('utf-8')
    
    elif format == "docx":
        # Generate properly formatted Word document
        try:
            from docx import Document
            from docx.shared import Inches, Pt, RGBColor
            from docx.enum.text import WD_ALIGN_PARAGRAPH
            from docx.enum.style import WD_STYLE_TYPE
            from docx.oxml.ns import qn
            from docx.oxml import OxmlElement
            import re
            
            doc = Document()
            
            # Set document properties
            core_props = doc.core_properties
            core_props.title = report.title
            core_props.author = "VRAgent Security Scanner"
            
            # Title
            title_para = doc.add_heading(report.title, 0)
            title_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            # Parse markdown and convert to Word elements
            lines = md_content.split('\n')
            i = 0
            in_code_block = False
            code_content = []
            code_language = None
            in_table = False
            table_rows = []
            
            while i < len(lines):
                line = lines[i]
                
                # Handle code blocks
                if line.strip().startswith('```'):
                    if in_code_block:
                        # End code block
                        if code_content:
                            if code_language == 'mermaid':
                                # Render mermaid as image
                                mermaid_code = '\n'.join(code_content)
                                img_bytes = _render_mermaid_to_image(mermaid_code, 'png')
                                if img_bytes:
                                    try:
                                        img_buffer = BytesIO(img_bytes)
                                        doc.add_picture(img_buffer, width=Inches(6))
                                        # Center the image
                                        last_para = doc.paragraphs[-1]
                                        last_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                                    except Exception as img_err:
                                        logger.warning(f"Failed to add mermaid image to Word: {img_err}")
                                        # Fallback to code
                                        p = doc.add_paragraph()
                                        p.paragraph_format.left_indent = Inches(0.25)
                                        run = p.add_run('\n'.join(code_content))
                                        run.font.name = 'Consolas'
                                        run.font.size = Pt(9)
                                else:
                                    # Fallback: show as code block
                                    p = doc.add_paragraph()
                                    p.paragraph_format.left_indent = Inches(0.25)
                                    run = p.add_run('\n'.join(code_content))
                                    run.font.name = 'Consolas'
                                    run.font.size = Pt(9)
                            else:
                                # Regular code block
                                p = doc.add_paragraph()
                                p.paragraph_format.left_indent = Inches(0.25)
                                run = p.add_run('\n'.join(code_content))
                                run.font.name = 'Consolas'
                                run.font.size = Pt(9)
                                # Add shading
                                shading = OxmlElement('w:shd')
                                shading.set(qn('w:fill'), 'E8E8E8')
                                p._p.get_or_add_pPr().append(shading)
                        code_content = []
                        code_language = None
                        in_code_block = False
                    else:
                        in_code_block = True
                        # Check for language specification
                        lang_match = line.strip()[3:].strip()
                        code_language = lang_match if lang_match else None
                    i += 1
                    continue
                
                if in_code_block:
                    code_content.append(line)
                    i += 1
                    continue
                
                # Handle tables
                if '|' in line and line.strip().startswith('|'):
                    if not in_table:
                        in_table = True
                        table_rows = []
                    
                    # Skip separator lines
                    if re.match(r'^\|[\s\-:]+\|', line):
                        i += 1
                        continue
                    
                    cells = [c.strip() for c in line.split('|')[1:-1]]
                    if cells:
                        table_rows.append(cells)
                    i += 1
                    continue
                elif in_table:
                    # End of table - create Word table
                    if table_rows:
                        col_count = max(len(row) for row in table_rows)
                        table = doc.add_table(rows=len(table_rows), cols=col_count)
                        table.style = 'Table Grid'
                        
                        for row_idx, row_data in enumerate(table_rows):
                            row = table.rows[row_idx]
                            for col_idx, cell_text in enumerate(row_data):
                                if col_idx < col_count:
                                    cell = row.cells[col_idx]
                                    # Clean markdown from cell text
                                    clean_text = re.sub(r'\*\*([^*]+)\*\*', r'\1', cell_text)
                                    clean_text = re.sub(r'`([^`]+)`', r'\1', clean_text)
                                    cell.text = clean_text
                                    # Bold header row
                                    if row_idx == 0:
                                        for para in cell.paragraphs:
                                            for run in para.runs:
                                                run.bold = True
                        
                        doc.add_paragraph()  # Space after table
                    table_rows = []
                    in_table = False
                
                # Headers
                if line.startswith('# '):
                    text = _html_to_plain_text(line[2:]) if '<' in line else _strip_markdown_formatting(line[2:])
                    doc.add_heading(text, 1)
                elif line.startswith('## '):
                    text = _html_to_plain_text(line[3:]) if '<' in line else _strip_markdown_formatting(line[3:])
                    doc.add_heading(text, 1)
                elif line.startswith('### '):
                    text = _html_to_plain_text(line[4:]) if '<' in line else _strip_markdown_formatting(line[4:])
                    doc.add_heading(text, 2)
                elif line.startswith('#### '):
                    text = _html_to_plain_text(line[5:]) if '<' in line else _strip_markdown_formatting(line[5:])
                    doc.add_heading(text, 3)
                # Bullet points
                elif line.strip().startswith('- ') or line.strip().startswith('* ') or line.strip().startswith('• '):
                    text = line.strip()[2:]
                    p = doc.add_paragraph(style='List Bullet')
                    _add_formatted_text(p, text)
                # Numbered lists
                elif re.match(r'^\s*\d+\.\s+', line):
                    text = re.sub(r'^\s*\d+\.\s+', '', line)
                    p = doc.add_paragraph(style='List Number')
                    _add_formatted_text(p, text)
                # Horizontal rule
                elif line.strip() == '---':
                    p = doc.add_paragraph()
                    p.paragraph_format.space_before = Pt(12)
                    p.paragraph_format.space_after = Pt(12)
                # Regular paragraph
                elif line.strip():
                    p = doc.add_paragraph()
                    _add_formatted_text(p, line)
                
                i += 1
            
            buffer = BytesIO()
            doc.save(buffer)
            return buffer.getvalue()
            
        except ImportError as e:
            logger.error(f"DOCX generation failed - missing library: {e}")
            return md_content.encode('utf-8')
        except Exception as e:
            logger.error(f"DOCX generation failed: {e}")
            return md_content.encode('utf-8')


def _format_inline_markdown(text: str) -> str:
    """Convert inline markdown to ReportLab XML tags for PDF."""
    import re
    
    # First, escape ampersands that aren't already part of entities
    text = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;)', '&amp;', text)
    
    # Escape < and > that aren't part of our formatting
    # We'll process markdown first, then escape remaining angle brackets
    
    # Process bold markdown: **text**
    def bold_replace(match):
        content = match.group(1)
        # Escape any angle brackets in the content
        content = content.replace('<', '&lt;').replace('>', '&gt;')
        return f'<b>{content}</b>'
    
    text = re.sub(r'\*\*([^*]+)\*\*', bold_replace, text)
    
    # Process italic markdown: *text* (but not **)
    def italic_replace(match):
        content = match.group(1)
        content = content.replace('<', '&lt;').replace('>', '&gt;')
        return f'<i>{content}</i>'
    
    text = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', italic_replace, text)
    
    # Process inline code: `text`
    def code_replace(match):
        content = match.group(1)
        content = content.replace('<', '&lt;').replace('>', '&gt;')
        return f'<font face="Courier" size="9">{content}</font>'
    
    text = re.sub(r'`([^`]+)`', code_replace, text)
    
    # Now escape any remaining < and > that weren't part of our tags
    # Split by our known tags and escape content between them
    parts = re.split(r'(</?b>|</?i>|<font[^>]*>|</font>)', text)
    result = []
    for part in parts:
        if re.match(r'^</?b>$|^</?i>$|^<font[^>]*>$|^</font>$', part):
            # This is a tag, keep it
            result.append(part)
        else:
            # This is content, escape any remaining angle brackets
            part = part.replace('<', '&lt;').replace('>', '&gt;')
            result.append(part)
    
    return ''.join(result)


def _html_to_reportlab(text: str) -> str:
    """Convert HTML tags to ReportLab-compatible XML tags."""
    import re
    
    if not text:
        return ''
    
    # First escape ampersands
    text = re.sub(r'&(?!amp;|lt;|gt;|quot;|nbsp;)', '&amp;', text)
    
    # Convert HTML tags to ReportLab equivalents
    # Bold: <strong> -> <b>
    text = re.sub(r'<strong>([^<]*)</strong>', r'<b>\1</b>', text)
    text = re.sub(r'<b>([^<]*)</b>', r'<b>\1</b>', text)
    
    # Italic: <em> -> <i>
    text = re.sub(r'<em>([^<]*)</em>', r'<i>\1</i>', text)
    
    # Code: <code> -> monospace font
    text = re.sub(r'<code>([^<]*)</code>', r'<font face="Courier" size="9">\1</font>', text)
    
    # Remove unsupported tags but keep content
    text = re.sub(r'</?p>', '', text)
    text = re.sub(r'</?div>', '', text)
    text = re.sub(r'</?span[^>]*>', '', text)
    text = re.sub(r'<br\s*/?>', '<br/>', text)
    
    # Convert headers to bold
    text = re.sub(r'<h[1-6][^>]*>([^<]*)</h[1-6]>', r'<b>\1</b>', text)
    
    # Handle lists - convert to bullet points
    text = re.sub(r'<ul[^>]*>', '', text)
    text = re.sub(r'</ul>', '', text)
    text = re.sub(r'<ol[^>]*>', '', text)
    text = re.sub(r'</ol>', '', text)
    text = re.sub(r'<li[^>]*>([^<]*)</li>', r'• \1<br/>', text)
    text = re.sub(r'<li[^>]*>', '• ', text)
    text = re.sub(r'</li>', '<br/>', text)
    
    # Remove any remaining HTML tags we don't support
    text = re.sub(r'<(?!/?b>|/?i>|/?u>|font[^>]*>|/font>|br/>)[^>]+>', '', text)
    
    return text.strip()


def _html_to_plain_text(text: str) -> str:
    """Convert HTML to plain text for Word documents."""
    import re
    from html import unescape
    
    if not text:
        return ''
    
    # Decode HTML entities
    text = unescape(text)
    
    # Replace <br> with newlines
    text = re.sub(r'<br\s*/?>', '\n', text)
    
    # Replace </p> and </div> with newlines
    text = re.sub(r'</p>', '\n', text)
    text = re.sub(r'</div>', '\n', text)
    
    # Replace </li> with newlines
    text = re.sub(r'</li>', '\n', text)
    
    # Add bullet for list items
    text = re.sub(r'<li[^>]*>', '• ', text)
    
    # Remove all remaining HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Clean up multiple newlines
    text = re.sub(r'\n{3,}', '\n\n', text)
    
    return text.strip()


def _strip_markdown_formatting(text: str) -> str:
    """Remove markdown formatting for plain text."""
    import re
    text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)
    text = re.sub(r'\*([^*]+)\*', r'\1', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    # Also strip HTML if present
    text = _html_to_plain_text(text)
    return text.strip()


def _render_mermaid_to_image(mermaid_code: str, output_format: str = 'png') -> Optional[bytes]:
    """
    Render mermaid diagram code to an image using Kroki API.
    Returns image bytes or None if rendering fails.
    """
    import base64
    import zlib
    import httpx
    
    try:
        # Clean up mermaid code
        mermaid_code = mermaid_code.strip()
        if not mermaid_code:
            return None
        
        # Kroki API endpoint
        kroki_url = f"https://kroki.io/mermaid/{output_format}"
        
        # Encode the mermaid code for Kroki
        # Kroki accepts plain text POST or base64 encoded in URL
        encoded = base64.urlsafe_b64encode(
            zlib.compress(mermaid_code.encode('utf-8'), 9)
        ).decode('ascii')
        
        # Use GET with encoded diagram (more reliable)
        url = f"https://kroki.io/mermaid/{output_format}/{encoded}"
        
        with httpx.Client(timeout=30.0) as client:
            response = client.get(url)
            
            if response.status_code == 200:
                return response.content
            else:
                logger.warning(f"Mermaid rendering failed: {response.status_code} - {response.text[:200]}")
                return None
                
    except Exception as e:
        logger.warning(f"Failed to render mermaid diagram: {e}")
        return None


def _add_formatted_text(paragraph, text: str):
    """Add text to a Word paragraph with markdown/HTML formatting converted."""
    import re
    from docx.shared import Pt
    from html import unescape
    
    # First check if text has HTML - convert to plain text
    if '<' in text and '>' in text:
        text = _html_to_plain_text(text)
    
    # Decode any HTML entities
    text = unescape(text)
    
    # Pattern to find bold, italic, and code (markdown style)
    pattern = r'(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)'
    parts = re.split(pattern, text)
    
    for part in parts:
        if not part:
            continue
        if part.startswith('**') and part.endswith('**'):
            # Bold
            run = paragraph.add_run(part[2:-2])
            run.bold = True
        elif part.startswith('*') and part.endswith('*') and not part.startswith('**'):
            # Italic
            run = paragraph.add_run(part[1:-1])
            run.italic = True
        elif part.startswith('`') and part.endswith('`'):
            # Code
            run = paragraph.add_run(part[1:-1])
            run.font.name = 'Consolas'
            run.font.size = Pt(9)
        else:
            paragraph.add_run(part)


@router.delete("/reports/{report_id}")
def delete_report(
    report_id: int,
    db: Session = Depends(get_db),
):
    """
    Delete a saved reverse engineering report.
    """
    from backend.models.models import ReverseEngineeringReport
    
    report = db.query(ReverseEngineeringReport).filter(ReverseEngineeringReport.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    db.delete(report)
    db.commit()
    
    logger.info(f"Deleted RE report {report_id}")
    
    return {"message": "Report deleted successfully", "id": report_id}


@router.patch("/reports/{report_id}")
def update_report(
    report_id: int,
    notes: Optional[str] = None,
    tags: Optional[List[str]] = None,
    title: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Update notes, tags, or title of a saved report.
    """
    from backend.models.models import ReverseEngineeringReport
    
    report = db.query(ReverseEngineeringReport).filter(ReverseEngineeringReport.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if notes is not None:
        report.notes = notes
    if tags is not None:
        report.tags = tags
    if title is not None:
        report.title = title
    
    db.commit()
    db.refresh(report)
    
    return {"message": "Report updated successfully", "id": report_id}


# ============================================================================
# AI-Powered Analysis Endpoints
# ============================================================================

class ApkChatMessage(BaseModel):
    """A message in the APK analysis chat."""
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: Optional[datetime] = None


class ApkChatRequest(BaseModel):
    """Request for APK chat interaction."""
    message: str
    conversation_history: List[ApkChatMessage] = []
    analysis_context: Dict[str, Any]  # The APK analysis result
    beginner_mode: bool = False


class ApkChatResponse(BaseModel):
    """Response from APK chat."""
    response: str
    suggested_questions: List[str] = []
    related_findings: List[str] = []
    learning_tip: Optional[str] = None


class ThreatModelRequest(BaseModel):
    """Request for threat modeling."""
    analysis_context: Dict[str, Any]
    focus_areas: List[str] = []  # e.g., ['data_exfiltration', 'authentication', 'injection']
    attacker_profile: str = "skilled"  # 'script_kiddie', 'skilled', 'nation_state'


class ThreatModelResponse(BaseModel):
    """Threat modeling response."""
    threat_actors: List[Dict[str, Any]]
    attack_scenarios: List[Dict[str, Any]]
    attack_tree: Dict[str, Any]
    mitre_attack_mappings: List[Dict[str, Any]]
    risk_matrix: Dict[str, Any]
    prioritized_threats: List[Dict[str, Any]]
    executive_summary: str


class ExploitSuggestionRequest(BaseModel):
    """Request for exploit suggestions."""
    analysis_context: Dict[str, Any]
    vulnerability_focus: Optional[str] = None  # Specific issue to focus on
    include_poc: bool = True
    skill_level: str = "intermediate"  # 'beginner', 'intermediate', 'advanced'


class ExploitSuggestionResponse(BaseModel):
    """Exploit suggestion response."""
    vulnerabilities: List[Dict[str, Any]]
    exploitation_paths: List[Dict[str, Any]]
    tools_required: List[Dict[str, Any]]
    poc_scripts: List[Dict[str, Any]]
    mitigation_bypasses: List[Dict[str, Any]]
    difficulty_assessment: Dict[str, Any]


class WalkthroughStep(BaseModel):
    """A step in the analysis walkthrough."""
    step_number: int
    phase: str
    title: str
    description: str
    technical_detail: str
    beginner_explanation: str
    why_it_matters: str
    findings_count: int = 0
    severity: Optional[str] = None
    progress_percent: int


class AnalysisWalkthroughResponse(BaseModel):
    """Complete walkthrough of analysis."""
    total_steps: int
    steps: List[WalkthroughStep]
    glossary: Dict[str, str]
    learning_resources: List[Dict[str, str]]
    next_steps: List[str]


@router.post("/apk/chat", response_model=ApkChatResponse)
async def chat_about_apk(request: ApkChatRequest):
    """
    Interactive AI chat about APK analysis findings.
    
    Supports multi-turn conversations with context about the analyzed APK.
    Can answer questions about permissions, security issues, what they mean,
    and provide recommendations.
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="AI features require Gemini API key")
    
    try:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build context from analysis
        ctx = request.analysis_context
        package_name = ctx.get('package_name', 'Unknown')
        
        # Build conversation history for Gemini
        contents = []
        
        # System context as first user message
        system_context = f"""You are an expert Android security analyst assistant helping users understand APK analysis results.

## APK BEING ANALYZED
- **Package:** {package_name}
- **Version:** {ctx.get('version_name', 'N/A')}
- **Target SDK:** {ctx.get('target_sdk', 'N/A')}
- **Min SDK:** {ctx.get('min_sdk', 'N/A')}
- **Debuggable:** {ctx.get('debuggable', False)}
- **Allow Backup:** {ctx.get('allow_backup', True)}

## PERMISSIONS ({len(ctx.get('permissions', []))})
{chr(10).join(f"- {p.get('name', 'Unknown')}{' [DANGEROUS]' if p.get('is_dangerous') else ''}" for p in ctx.get('permissions', [])[:20])}

## SECURITY ISSUES ({len(ctx.get('security_issues', []))})
{chr(10).join(f"- [{i.get('severity', 'INFO')}] {i.get('category', 'Unknown')}: {i.get('description', '')[:100]}" for i in ctx.get('security_issues', [])[:15])}

## SECRETS FOUND ({len(ctx.get('secrets', []))})
{chr(10).join(f"- {s.get('type', 'Unknown')}: {s.get('masked_value', '***')}" for s in ctx.get('secrets', [])[:10])}

## HARDENING SCORE
{f"Grade: {ctx.get('hardening_score', {}).get('grade', 'N/A')} ({ctx.get('hardening_score', {}).get('overall_score', 'N/A')}/100)" if ctx.get('hardening_score') else "Not calculated"}

## DYNAMIC ANALYSIS
- SSL Pinning Detected: {ctx.get('dynamic_analysis', {}).get('ssl_pinning_detected', False)}
- Root Detection: {ctx.get('dynamic_analysis', {}).get('root_detection_detected', False)}
- Emulator Detection: {ctx.get('dynamic_analysis', {}).get('emulator_detection_detected', False)}

{"## BEGINNER MODE ENABLED - Please explain concepts simply, use analogies, and define technical terms." if request.beginner_mode else ""}

Guidelines:
1. Be helpful and educational
2. Reference specific findings from the analysis
3. Suggest follow-up questions
4. {"Use simple language and analogies for beginners" if request.beginner_mode else "Be technically precise"}
5. Provide actionable recommendations
6. If asked about exploitation, focus on defensive understanding"""
        
        contents.append(types.Content(role="user", parts=[types.Part(text=system_context)]))
        contents.append(types.Content(role="model", parts=[types.Part(text="I understand. I'm ready to help you understand this APK analysis. What would you like to know?")]))
        
        # Add conversation history
        for msg in request.conversation_history[-10:]:  # Last 10 messages
            role = "user" if msg.role == "user" else "model"
            contents.append(types.Content(role=role, parts=[types.Part(text=msg.content)]))
        
        # Add current message
        contents.append(types.Content(role="user", parts=[types.Part(text=request.message)]))
        
        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=contents,
        )
        
        response_text = response.text
        
        # Generate suggested follow-up questions
        suggested_questions = []
        if "permission" in request.message.lower():
            suggested_questions = [
                "What data could this app access with these permissions?",
                "Are there any permission combinations that are concerning?",
                "How do these permissions compare to similar apps?",
            ]
        elif "security" in request.message.lower() or "issue" in request.message.lower():
            suggested_questions = [
                "How could an attacker exploit these issues?",
                "What's the priority order for fixing these?",
                "Are there any quick wins for improving security?",
            ]
        elif "secret" in request.message.lower() or "api key" in request.message.lower():
            suggested_questions = [
                "How can secrets be properly protected in Android apps?",
                "What's the risk if these secrets are exposed?",
                "How can I detect if these keys have been abused?",
            ]
        else:
            suggested_questions = [
                "What are the most critical security issues?",
                "Is this app safe to use?",
                "What would you recommend fixing first?",
            ]
        
        # Generate learning tip for beginner mode
        learning_tip = None
        if request.beginner_mode:
            tips = [
                "💡 Tip: Dangerous permissions don't mean the app is malicious - they just require extra scrutiny.",
                "💡 Tip: A low hardening score doesn't always mean the app is insecure - context matters!",
                "💡 Tip: SSL pinning is a defense mechanism that makes it harder to intercept app traffic.",
                "💡 Tip: Root detection helps apps protect themselves, but can be bypassed for security testing.",
                "💡 Tip: Exported components are entry points that other apps can interact with.",
            ]
            import random
            learning_tip = random.choice(tips)
        
        return ApkChatResponse(
            response=response_text,
            suggested_questions=suggested_questions,
            related_findings=[],
            learning_tip=learning_tip,
        )
        
    except Exception as e:
        logger.error(f"APK chat failed: {e}")
        raise HTTPException(status_code=500, detail=f"Chat failed: {str(e)}")


@router.post("/apk/threat-model", response_model=ThreatModelResponse)
async def generate_threat_model(request: ThreatModelRequest):
    """
    Generate AI-powered threat model for the APK.
    
    Creates attack scenarios, threat actors, MITRE ATT&CK mappings,
    and prioritized threat assessment.
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="AI features require Gemini API key")
    
    try:
        from google import genai
        from google.genai import types
        import json
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        ctx = request.analysis_context
        package_name = ctx.get('package_name', 'Unknown')
        
        attacker_profiles = {
            "script_kiddie": "Low skill, uses automated tools, opportunistic",
            "skilled": "Moderate skill, can develop custom exploits, targeted",
            "nation_state": "Advanced persistent threat, unlimited resources, sophisticated techniques"
        }
        
        prompt = f"""You are an expert mobile security threat modeler. Generate a comprehensive threat model for this Android application.

## APPLICATION CONTEXT
- **Package:** {package_name}
- **Version:** {ctx.get('version_name', 'N/A')}
- **Target SDK:** {ctx.get('target_sdk', 'N/A')}
- **Debuggable:** {ctx.get('debuggable', False)}

## ATTACK SURFACE
**Permissions ({len(ctx.get('permissions', []))}):**
{chr(10).join(f"- {p.get('name')}" for p in ctx.get('permissions', []) if p.get('is_dangerous'))[:10]}

**Exported Components:**
- Activities: {len([c for c in ctx.get('components', []) if c.get('component_type') == 'activity' and c.get('is_exported')])}
- Services: {len([c for c in ctx.get('components', []) if c.get('component_type') == 'service' and c.get('is_exported')])}
- Receivers: {len([c for c in ctx.get('components', []) if c.get('component_type') == 'receiver' and c.get('is_exported')])}
- Providers: {len([c for c in ctx.get('components', []) if c.get('component_type') == 'provider' and c.get('is_exported')])}

**Deep Links:** {len(ctx.get('intent_filter_analysis', {}).get('deep_links', []))}

**Security Issues ({len(ctx.get('security_issues', []))}):**
{chr(10).join(f"- [{i.get('severity')}] {i.get('description', '')[:80]}" for i in ctx.get('security_issues', [])[:10])}

**Native Libraries:** {len(ctx.get('native_libraries', []))}
**Secrets Found:** {len(ctx.get('secrets', []))}

## ATTACKER PROFILE
**Type:** {request.attacker_profile}
**Description:** {attacker_profiles.get(request.attacker_profile, 'Unknown')}

## FOCUS AREAS
{', '.join(request.focus_areas) if request.focus_areas else 'All attack vectors'}

Generate a JSON response with the following structure:
{{
    "threat_actors": [
        {{
            "name": "Actor name",
            "motivation": "Financial/Espionage/Disruption",
            "capability": "Low/Medium/High",
            "likelihood": "Low/Medium/High",
            "description": "Brief description"
        }}
    ],
    "attack_scenarios": [
        {{
            "id": "AS-001",
            "name": "Scenario name",
            "description": "Detailed attack scenario",
            "preconditions": ["Required conditions"],
            "attack_steps": ["Step 1", "Step 2"],
            "impact": "What damage could occur",
            "likelihood": "Low/Medium/High",
            "severity": "Low/Medium/High/Critical",
            "mitre_techniques": ["T1234"]
        }}
    ],
    "attack_tree": {{
        "goal": "Compromise application",
        "branches": [
            {{
                "method": "Attack vector",
                "sub_branches": ["Sub-attack 1", "Sub-attack 2"],
                "difficulty": "Easy/Medium/Hard"
            }}
        ]
    }},
    "mitre_attack_mappings": [
        {{
            "technique_id": "T1234",
            "technique_name": "Technique Name",
            "tactic": "Initial Access/Execution/etc",
            "relevance": "How it applies to this app",
            "finding_reference": "Which finding relates to this"
        }}
    ],
    "risk_matrix": {{
        "critical_risks": ["List of critical risks"],
        "high_risks": ["List of high risks"],
        "medium_risks": ["List of medium risks"],
        "low_risks": ["List of low risks"],
        "accepted_risks": ["Risks that may be acceptable"]
    }},
    "prioritized_threats": [
        {{
            "rank": 1,
            "threat": "Threat name",
            "risk_score": 85,
            "rationale": "Why this is prioritized",
            "recommendation": "What to do about it"
        }}
    ],
    "executive_summary": "2-3 paragraph executive summary of the threat landscape"
}}

Be thorough and realistic. Consider the specific findings from this APK."""

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=[types.Content(role="user", parts=[types.Part(text=prompt)])],
        )
        
        # Parse JSON from response
        response_text = response.text
        
        # Extract JSON from markdown code blocks if present
        if "```json" in response_text:
            json_start = response_text.find("```json") + 7
            json_end = response_text.find("```", json_start)
            response_text = response_text[json_start:json_end].strip()
        elif "```" in response_text:
            json_start = response_text.find("```") + 3
            json_end = response_text.find("```", json_start)
            response_text = response_text[json_start:json_end].strip()
        
        try:
            threat_data = json.loads(response_text)
        except json.JSONDecodeError:
            # Fallback structure if JSON parsing fails
            threat_data = {
                "threat_actors": [{"name": "Unknown", "motivation": "Various", "capability": "Medium", "likelihood": "Medium", "description": response_text[:200]}],
                "attack_scenarios": [],
                "attack_tree": {"goal": "Compromise application", "branches": []},
                "mitre_attack_mappings": [],
                "risk_matrix": {"critical_risks": [], "high_risks": [], "medium_risks": [], "low_risks": [], "accepted_risks": []},
                "prioritized_threats": [],
                "executive_summary": response_text[:500]
            }
        
        return ThreatModelResponse(
            threat_actors=threat_data.get("threat_actors", []),
            attack_scenarios=threat_data.get("attack_scenarios", []),
            attack_tree=threat_data.get("attack_tree", {}),
            mitre_attack_mappings=threat_data.get("mitre_attack_mappings", []),
            risk_matrix=threat_data.get("risk_matrix", {}),
            prioritized_threats=threat_data.get("prioritized_threats", []),
            executive_summary=threat_data.get("executive_summary", ""),
        )
        
    except Exception as e:
        logger.error(f"Threat modeling failed: {e}")
        raise HTTPException(status_code=500, detail=f"Threat modeling failed: {str(e)}")


@router.post("/apk/exploit-suggestions", response_model=ExploitSuggestionResponse)
async def get_exploit_suggestions(request: ExploitSuggestionRequest):
    """
    Generate AI-powered exploit suggestions for identified vulnerabilities.
    
    Provides exploitation paths, required tools, PoC scripts, and difficulty assessments.
    For educational/defensive purposes only.
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="AI features require Gemini API key")
    
    try:
        from google import genai
        from google.genai import types
        import json
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        ctx = request.analysis_context
        package_name = ctx.get('package_name', 'Unknown')
        
        skill_descriptions = {
            "beginner": "Basic Android knowledge, can follow step-by-step guides",
            "intermediate": "Familiar with Android internals, can modify existing tools",
            "advanced": "Expert level, can develop custom exploits and bypass protections"
        }
        
        prompt = f"""You are a mobile security penetration tester. Generate exploitation guidance for DEFENSIVE and EDUCATIONAL purposes to help developers understand and fix vulnerabilities.

## APPLICATION
- **Package:** {package_name}
- **Version:** {ctx.get('version_name', 'N/A')}
- **Debuggable:** {ctx.get('debuggable', False)}
- **Allow Backup:** {ctx.get('allow_backup', True)}

## IDENTIFIED VULNERABILITIES
{chr(10).join(f"- [{i.get('severity', 'INFO')}] {i.get('category', 'Unknown')}: {i.get('description', '')}" for i in ctx.get('security_issues', [])[:15])}

## SECRETS FOUND
{chr(10).join(f"- {s.get('type', 'Unknown')}: {s.get('masked_value', '***')}" for s in ctx.get('secrets', [])[:5])}

## ATTACK SURFACE
- Exported Activities: {len([c for c in ctx.get('components', []) if c.get('component_type') == 'activity' and c.get('is_exported')])}
- Deep Links: {ctx.get('intent_filter_analysis', {}).get('attack_surface_summary', {}).get('total_deep_links', 0)}
- Native Libraries: {len(ctx.get('native_libraries', []))}

## PROTECTIONS DETECTED
- SSL Pinning: {ctx.get('dynamic_analysis', {}).get('ssl_pinning_detected', False)}
- Root Detection: {ctx.get('dynamic_analysis', {}).get('root_detection_detected', False)}
- Emulator Detection: {ctx.get('dynamic_analysis', {}).get('emulator_detection_detected', False)}
- Anti-Tampering: {ctx.get('dynamic_analysis', {}).get('anti_tampering_detected', False)}

## TESTER SKILL LEVEL
**Level:** {request.skill_level}
**Description:** {skill_descriptions.get(request.skill_level, 'Unknown')}

{f"## FOCUS ON: {request.vulnerability_focus}" if request.vulnerability_focus else ""}

Generate a JSON response with DEFENSIVE exploitation guidance:
{{
    "vulnerabilities": [
        {{
            "id": "VULN-001",
            "name": "Vulnerability name",
            "category": "OWASP Mobile category",
            "severity": "Critical/High/Medium/Low",
            "description": "What the vulnerability is",
            "root_cause": "Why this vulnerability exists",
            "affected_component": "Which part of the app"
        }}
    ],
    "exploitation_paths": [
        {{
            "vulnerability_id": "VULN-001",
            "name": "Exploitation path name",
            "prerequisites": ["What's needed before exploitation"],
            "steps": [
                {{
                    "step": 1,
                    "action": "What to do",
                    "command": "adb shell command if applicable",
                    "expected_result": "What should happen"
                }}
            ],
            "success_indicators": ["How to know if it worked"],
            "impact": "What an attacker could achieve"
        }}
    ],
    "tools_required": [
        {{
            "name": "Tool name",
            "purpose": "What it's used for",
            "installation": "How to install it",
            "usage_example": "Example command"
        }}
    ],
    "poc_scripts": [
        {{
            "vulnerability_id": "VULN-001",
            "name": "PoC name",
            "language": "python/bash/frida",
            "description": "What the script does",
            "code": "The actual code",
            "usage": "How to run it"
        }}
    ],
    "mitigation_bypasses": [
        {{
            "protection": "SSL Pinning/Root Detection/etc",
            "bypass_method": "How to bypass",
            "tools": ["Required tools"],
            "difficulty": "Easy/Medium/Hard",
            "detection_risk": "How likely to be detected"
        }}
    ],
    "difficulty_assessment": {{
        "overall_difficulty": "Easy/Medium/Hard/Expert",
        "time_estimate": "Hours/days estimate",
        "skill_requirements": ["Required skills"],
        "resource_requirements": ["Required resources"],
        "success_probability": "High/Medium/Low"
    }}
}}

IMPORTANT: This is for DEFENSIVE purposes - helping developers understand how attackers think so they can build better defenses. Include remediation guidance."""

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=[types.Content(role="user", parts=[types.Part(text=prompt)])],
        )
        
        # Parse JSON from response
        response_text = response.text
        
        # Extract JSON from markdown code blocks if present
        if "```json" in response_text:
            json_start = response_text.find("```json") + 7
            json_end = response_text.find("```", json_start)
            response_text = response_text[json_start:json_end].strip()
        elif "```" in response_text:
            json_start = response_text.find("```") + 3
            json_end = response_text.find("```", json_start)
            response_text = response_text[json_start:json_end].strip()
        
        try:
            exploit_data = json.loads(response_text)
        except json.JSONDecodeError:
            exploit_data = {
                "vulnerabilities": [],
                "exploitation_paths": [],
                "tools_required": [],
                "poc_scripts": [],
                "mitigation_bypasses": [],
                "difficulty_assessment": {
                    "overall_difficulty": "Unknown",
                    "time_estimate": "Unknown",
                    "skill_requirements": [],
                    "resource_requirements": [],
                    "success_probability": "Unknown"
                }
            }
        
        return ExploitSuggestionResponse(
            vulnerabilities=exploit_data.get("vulnerabilities", []),
            exploitation_paths=exploit_data.get("exploitation_paths", []),
            tools_required=exploit_data.get("tools_required", []),
            poc_scripts=exploit_data.get("poc_scripts", []) if request.include_poc else [],
            mitigation_bypasses=exploit_data.get("mitigation_bypasses", []),
            difficulty_assessment=exploit_data.get("difficulty_assessment", {}),
        )
        
    except Exception as e:
        logger.error(f"Exploit suggestions failed: {e}")
        raise HTTPException(status_code=500, detail=f"Exploit suggestions failed: {str(e)}")


@router.post("/apk/walkthrough", response_model=AnalysisWalkthroughResponse)
async def generate_walkthrough(analysis_context: Dict[str, Any]):
    """
    Generate a beginner-friendly walkthrough of the APK analysis.
    
    Provides step-by-step explanations of each analysis phase,
    what was found, and why it matters for security.
    """
    ctx = analysis_context
    
    # Security Glossary
    glossary = {
        "APK": "Android Package Kit - the file format used to distribute Android apps",
        "SDK": "Software Development Kit - tools for building Android apps. Min SDK is the oldest Android version supported, Target SDK is what the app is optimized for",
        "Permission": "A declaration that an app needs access to certain device features or data",
        "Dangerous Permission": "Permissions that could affect user privacy or device security, requiring explicit user approval",
        "Exported Component": "An app component (activity, service, etc.) that can be accessed by other apps",
        "Intent": "A messaging object used to request actions from other app components",
        "Deep Link": "A URL that opens a specific screen in an app",
        "SSL Pinning": "A security technique that ensures an app only trusts specific certificates",
        "Root Detection": "Code that checks if the device has been rooted (given superuser access)",
        "Obfuscation": "Making code harder to understand to prevent reverse engineering",
        "Hardcoded Secret": "Sensitive data (like API keys) embedded directly in the app code",
        "Native Library": "Code written in C/C++ compiled for specific processor architectures",
        "DEX": "Dalvik Executable - the compiled bytecode format for Android apps",
        "Smali": "Human-readable representation of DEX bytecode",
        "Frida": "A dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers",
        "OWASP": "Open Web Application Security Project - organization that publishes security guidelines",
        "CVE": "Common Vulnerabilities and Exposures - standardized identifiers for security vulnerabilities",
    }
    
    # Build walkthrough steps
    steps = []
    progress = 0
    step_num = 0
    
    # Step 1: Basic Info
    step_num += 1
    progress = 10
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Basic Information",
        title="Extracting App Identity",
        description=f"Analyzed the AndroidManifest.xml to extract basic app information.",
        technical_detail=f"Package: {ctx.get('package_name', 'Unknown')}, Version: {ctx.get('version_name', 'N/A')}, Target SDK: {ctx.get('target_sdk', 'N/A')}",
        beginner_explanation="Every Android app has an identity - its package name (like a unique address), version number, and the Android versions it supports. This is like checking someone's ID card.",
        why_it_matters="The target SDK tells us if the app takes advantage of newer security features. Apps targeting older SDKs may have weaker security.",
        findings_count=1,
        severity="info",
        progress_percent=progress,
    ))
    
    # Step 2: Permissions
    step_num += 1
    progress = 20
    permissions = ctx.get('permissions', [])
    dangerous = [p for p in permissions if p.get('is_dangerous')]
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Permission Analysis",
        title="Checking What the App Can Access",
        description=f"Found {len(permissions)} permissions, {len(dangerous)} are classified as dangerous.",
        technical_detail=f"Dangerous permissions: {', '.join(p.get('name', '').split('.')[-1] for p in dangerous[:5])}",
        beginner_explanation="Permissions are like keys to different parts of your phone. Camera permission lets the app use your camera, location permission lets it know where you are. 'Dangerous' permissions can access sensitive data.",
        why_it_matters=f"This app requests {len(dangerous)} dangerous permissions. Each one is a potential privacy concern if misused. We check if these make sense for what the app does.",
        findings_count=len(dangerous),
        severity="high" if len(dangerous) > 5 else "medium" if len(dangerous) > 2 else "low",
        progress_percent=progress,
    ))
    
    # Step 3: Security Issues
    step_num += 1
    progress = 35
    issues = ctx.get('security_issues', [])
    critical_issues = [i for i in issues if i.get('severity', '').lower() == 'critical']
    high_issues = [i for i in issues if i.get('severity', '').lower() == 'high']
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Security Issue Detection",
        title="Scanning for Vulnerabilities",
        description=f"Identified {len(issues)} potential security issues: {len(critical_issues)} critical, {len(high_issues)} high severity.",
        technical_detail=f"Categories: {', '.join(set(i.get('category', 'Unknown') for i in issues[:10]))}",
        beginner_explanation="We automatically scan the app for common security mistakes - like leaving debug mode on (makes it easier to hack), allowing backups (your data could be copied), or using old encryption methods.",
        why_it_matters="These issues could let attackers steal data, bypass security controls, or gain unauthorized access. Critical issues should be addressed immediately.",
        findings_count=len(issues),
        severity="critical" if critical_issues else "high" if high_issues else "medium",
        progress_percent=progress,
    ))
    
    # Step 4: Secrets Detection
    step_num += 1
    progress = 45
    secrets = ctx.get('secrets', [])
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Secret Detection",
        title="Finding Hardcoded Secrets",
        description=f"Found {len(secrets)} potential hardcoded secrets in the app.",
        technical_detail=f"Types found: {', '.join(set(s.get('type', 'Unknown') for s in secrets[:10]))}",
        beginner_explanation="Developers sometimes accidentally leave passwords, API keys, or encryption keys directly in their code. This is like writing your house key on your front door - anyone can find it!",
        why_it_matters="Hardcoded secrets can be extracted by anyone who downloads the app. Attackers could use these to access backend services, steal data, or impersonate the app.",
        findings_count=len(secrets),
        severity="critical" if len(secrets) > 3 else "high" if secrets else "low",
        progress_percent=progress,
    ))
    
    # Step 5: Component Analysis
    step_num += 1
    progress = 55
    components = ctx.get('components', [])
    exported = [c for c in components if c.get('is_exported')]
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Component Analysis",
        title="Mapping the Attack Surface",
        description=f"Found {len(components)} components, {len(exported)} are exported (accessible to other apps).",
        technical_detail=f"Exported: {len([c for c in exported if c.get('component_type') == 'activity'])} activities, {len([c for c in exported if c.get('component_type') == 'service'])} services",
        beginner_explanation="Apps are made of building blocks called components. 'Exported' components can be triggered by other apps. It's like having multiple doors to your house - each one needs to be secured.",
        why_it_matters="Exported components are entry points that attackers can target. They might be able to trigger functionality without proper authorization or inject malicious data.",
        findings_count=len(exported),
        severity="medium" if len(exported) > 5 else "low",
        progress_percent=progress,
    ))
    
    # Step 6: Dynamic Analysis Prep
    step_num += 1
    progress = 65
    dynamic = ctx.get('dynamic_analysis', {})
    protections = sum([
        1 if dynamic.get('ssl_pinning_detected') else 0,
        1 if dynamic.get('root_detection_detected') else 0,
        1 if dynamic.get('emulator_detection_detected') else 0,
        1 if dynamic.get('anti_tampering_detected') else 0,
    ])
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Protection Detection",
        title="Identifying Security Protections",
        description=f"Detected {protections} security protection mechanisms.",
        technical_detail=f"SSL Pinning: {dynamic.get('ssl_pinning_detected', False)}, Root Detection: {dynamic.get('root_detection_detected', False)}, Emulator Detection: {dynamic.get('emulator_detection_detected', False)}",
        beginner_explanation="Apps can include protections against tampering and analysis. SSL pinning ensures connections can't be intercepted. Root detection stops the app on hacked devices. These are like security cameras and alarms.",
        why_it_matters=f"The app has {protections}/4 common protections. Missing protections make it easier for attackers to analyze and exploit the app.",
        findings_count=4 - protections,
        severity="medium" if protections < 2 else "low",
        progress_percent=progress,
    ))
    
    # Step 7: Frida Scripts
    step_num += 1
    progress = 75
    scripts_count = dynamic.get('total_scripts', 0)
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Frida Script Generation",
        title="Creating Testing Scripts",
        description=f"Generated {scripts_count} Frida scripts for dynamic testing.",
        technical_detail=f"Categories: SSL bypass, root bypass, crypto hooks, auth monitoring, emulator bypass, debugger bypass",
        beginner_explanation="Frida is a tool that lets security researchers modify app behavior in real-time. We generated scripts that can bypass protections, monitor sensitive operations, and help test the app's security.",
        why_it_matters="These scripts help testers evaluate how the app behaves under attack conditions. If protections can be bypassed, they might not provide real security value.",
        findings_count=scripts_count,
        severity="info",
        progress_percent=progress,
    ))
    
    # Step 8: Native Analysis
    step_num += 1
    progress = 85
    native = ctx.get('native_analysis', {})
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Native Library Analysis",
        title="Analyzing Native Code",
        description=f"Analyzed {native.get('total_libraries', 0)} native libraries for security issues.",
        technical_detail=f"JNI functions: {native.get('total_jni_functions', 0)}, Anti-debug: {native.get('has_native_anti_debug', False)}, Native crypto: {native.get('has_native_crypto', False)}",
        beginner_explanation="Some app code is written in C/C++ and compiled to 'native' code that runs directly on the processor. This code is harder to analyze but can contain secrets and vulnerabilities.",
        why_it_matters=f"Risk level: {native.get('risk_level', 'unknown')}. Native code can hide sensitive operations and is often used for security-critical functionality.",
        findings_count=native.get('total_suspicious_functions', 0),
        severity=native.get('risk_level', 'medium'),
        progress_percent=progress,
    ))
    
    # Step 9: Hardening Score
    step_num += 1
    progress = 95
    score = ctx.get('hardening_score', {})
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Security Scoring",
        title="Calculating Hardening Score",
        description=f"Overall security grade: {score.get('grade', 'N/A')} ({score.get('overall_score', 0)}/100)",
        technical_detail=f"Risk level: {score.get('risk_level', 'unknown')}. Categories evaluated: code protection, network security, data storage, crypto, platform security.",
        beginner_explanation="We calculate an overall security score based on multiple factors - like a report card for the app's security. A higher score means better security practices.",
        why_it_matters=f"Grade {score.get('grade', 'N/A')} indicates the app's security posture. This helps prioritize which apps need more attention from a security perspective.",
        findings_count=1,
        severity="critical" if score.get('grade') in ['D', 'F'] else "high" if score.get('grade') == 'C' else "medium" if score.get('grade') == 'B' else "low",
        progress_percent=progress,
    ))
    
    # Step 10: Summary
    step_num += 1
    progress = 100
    steps.append(WalkthroughStep(
        step_number=step_num,
        phase="Analysis Complete",
        title="Summary & Recommendations",
        description="Analysis complete. Review findings and take action on critical issues.",
        technical_detail=f"Total issues: {len(issues)}, Secrets: {len(secrets)}, Exported components: {len(exported)}",
        beginner_explanation="We've completed a comprehensive security analysis. The findings show areas where the app could be improved. Critical and high severity issues should be addressed first.",
        why_it_matters="Use these findings to prioritize security improvements. Start with critical issues, then work through high and medium severity items.",
        findings_count=len(issues) + len(secrets),
        severity="info",
        progress_percent=progress,
    ))
    
    # Learning resources
    resources = [
        {"title": "OWASP Mobile Top 10", "url": "https://owasp.org/www-project-mobile-top-10/", "description": "Top 10 mobile security risks"},
        {"title": "Android Security Best Practices", "url": "https://developer.android.com/topic/security/best-practices", "description": "Official Android security guide"},
        {"title": "Frida Documentation", "url": "https://frida.re/docs/", "description": "Learn dynamic instrumentation"},
        {"title": "Mobile Security Testing Guide", "url": "https://mas.owasp.org/MASTG/", "description": "Comprehensive mobile pentesting guide"},
    ]
    
    # Next steps based on findings
    next_steps = []
    if critical_issues:
        next_steps.append("🚨 Address critical security issues immediately")
    if secrets:
        next_steps.append("🔑 Remove hardcoded secrets and use secure storage")
    if len(exported) > 5:
        next_steps.append("🚪 Review exported components for proper access control")
    if not dynamic.get('ssl_pinning_detected'):
        next_steps.append("🔒 Implement SSL certificate pinning")
    if ctx.get('debuggable'):
        next_steps.append("⚠️ Disable debug mode for production builds")
    if not next_steps:
        next_steps.append("✅ App has good security posture - continue monitoring")
    
    return AnalysisWalkthroughResponse(
        total_steps=len(steps),
        steps=steps,
        glossary=glossary,
        learning_resources=resources,
        next_steps=next_steps,
    )


# ============================================================================
# Unified APK Scan Endpoint (SSE Progress Streaming)
# ============================================================================

class UnifiedApkScanPhase(BaseModel):
    """A phase in the unified APK scan."""
    id: str
    label: str
    description: str
    status: str  # "pending", "in_progress", "completed", "error"
    progress: int = 0  # 0-100
    details: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class UnifiedApkScanProgress(BaseModel):
    """Progress update for unified APK scan."""
    scan_id: str
    current_phase: str
    overall_progress: int  # 0-100
    phases: List[UnifiedApkScanPhase]
    message: str
    error: Optional[str] = None


class UnifiedApkScanResult(BaseModel):
    """Complete result from unified APK scan."""
    scan_id: str
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    
    # Quick Analysis Results
    permissions: List[Dict[str, Any]] = []
    dangerous_permissions_count: int = 0
    components: List[Dict[str, Any]] = []
    secrets: List[Dict[str, Any]] = []
    urls: List[str] = []
    native_libraries: List[str] = []
    security_issues: List[Dict[str, Any]] = []
    
    # JADX Decompilation Results
    jadx_session_id: Optional[str] = None
    total_classes: int = 0
    total_files: int = 0
    classes_summary: List[Dict[str, Any]] = []
    source_tree: Optional[Dict[str, Any]] = None
    jadx_security_issues: List[Dict[str, Any]] = []
    decompilation_time: float = 0
    
    # AI Analysis Results  
    ai_functionality_report: Optional[str] = None
    ai_security_report: Optional[str] = None
    ai_architecture_diagram: Optional[str] = None
    ai_attack_surface_map: Optional[str] = None  # Mermaid attack tree diagram
    
    # Decompiled Source Code Security Findings (pattern-based scanners)
    decompiled_code_findings: List[Dict[str, Any]] = []  # Individual vulnerability findings
    decompiled_code_summary: Dict[str, Any] = {}  # Summary with counts by severity/category
    
    # Vulnerability-Specific Frida Hooks (auto-generated from findings)
    vulnerability_frida_hooks: Optional[Dict[str, Any]] = None  # Targeted Frida scripts
    
    # Metadata
    scan_time: float = 0
    filename: str = ""
    file_size: int = 0


@router.post("/apk/unified-scan")
async def unified_apk_scan(
    file: UploadFile = File(..., description="APK file to analyze"),
):
    """
    Perform a complete APK analysis with streaming progress updates.
    
    This unified scan combines:
    1. Manifest & permission analysis
    2. Secret & string extraction
    3. JADX decompilation to Java source
    4. AI-powered functionality report
    5. AI-powered security report
    6. Architecture diagram generation
    
    Returns SSE stream with progress updates and final result.
    """
    scan_id = str(uuid.uuid4())
    filename = file.filename or "unknown.apk"
    suffix = Path(filename).suffix.lower()
    
    if suffix not in ALLOWED_APK_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_APK_EXTENSIONS)}"
        )
    
    # Check JADX availability
    if not check_jadx_available():
        raise HTTPException(
            status_code=503,
            detail="JADX is not available. Full analysis requires JADX."
        )
    
    # Save file to temp location
    tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_unified_"))
    tmp_path = tmp_dir / filename
    
    file_size = 0
    try:
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    
    logger.info(f"Starting unified APK scan: {filename} ({file_size:,} bytes)")
    
    # Initialize scan session
    _unified_scan_sessions[scan_id] = {
        "cancelled": False,
        "tmp_dir": tmp_dir,
        "file_path": tmp_path,
    }
    
    # Define phases
    phases = [
        UnifiedApkScanPhase(
            id="manifest",
            label="Manifest Analysis",
            description="Extracting package info, permissions, and components",
            status="pending"
        ),
        UnifiedApkScanPhase(
            id="secrets",
            label="Secret Detection",
            description="Scanning for hardcoded secrets, URLs, and API keys",
            status="pending"
        ),
        UnifiedApkScanPhase(
            id="jadx",
            label="JADX Decompilation",
            description="Decompiling DEX to Java source code",
            status="pending"
        ),
        UnifiedApkScanPhase(
            id="ai_functionality",
            label="AI Functionality Report",
            description="Generating AI-powered 'What Does This APK Do?' report",
            status="pending"
        ),
        UnifiedApkScanPhase(
            id="ai_security",
            label="AI Security Report",
            description="Generating AI-powered security analysis",
            status="pending"
        ),
        UnifiedApkScanPhase(
            id="ai_diagram",
            label="Architecture Diagram",
            description="Generating visual architecture diagram",
            status="pending"
        ),
    ]
    
    async def run_unified_scan():
        """Generator that yields SSE progress events."""
        result = UnifiedApkScanResult(
            scan_id=scan_id,
            package_name="",
            filename=filename,
            file_size=file_size,
        )
        start_time = datetime.now()
        current_phase_idx = 0
        apk_result = None
        jadx_result = None
        
        def make_progress(message: str, phase_progress: int = 0) -> str:
            nonlocal phases, current_phase_idx
            overall = (current_phase_idx * 100 // len(phases)) + (phase_progress // len(phases))
            progress = UnifiedApkScanProgress(
                scan_id=scan_id,
                current_phase=phases[current_phase_idx].id,
                overall_progress=min(overall, 100),
                phases=phases,
                message=message,
            )
            return f"data: {json.dumps({'type': 'progress', 'data': progress.model_dump()})}\n\n"
        
        def update_phase(phase_id: str, status: str, details: str = None, progress: int = 0):
            for p in phases:
                if p.id == phase_id:
                    p.status = status
                    p.progress = progress
                    if details:
                        p.details = details
                    if status == "in_progress" and not p.started_at:
                        p.started_at = datetime.now().isoformat()
                    if status == "completed":
                        p.completed_at = datetime.now().isoformat()
                        p.progress = 100
                    break
        
        try:
            # Check if cancelled
            if _unified_scan_sessions.get(scan_id, {}).get("cancelled"):
                yield f"data: {json.dumps({'type': 'cancelled'})}\n\n"
                return
            
            # =================================================================
            # Phase 1: Manifest Analysis
            # =================================================================
            current_phase_idx = 0
            update_phase("manifest", "in_progress")
            yield make_progress("Extracting AndroidManifest.xml...", 10)
            
            try:
                apk_result = re_service.analyze_apk(tmp_path)
                result.package_name = apk_result.package_name or ""
                result.version_name = apk_result.version_name
                result.version_code = apk_result.version_code
                result.min_sdk = apk_result.min_sdk
                result.target_sdk = apk_result.target_sdk
                result.permissions = [
                    {"name": p.name, "is_dangerous": p.is_dangerous, "description": p.description}
                    for p in apk_result.permissions
                ]
                result.dangerous_permissions_count = sum(1 for p in apk_result.permissions if p.is_dangerous)
                result.components = [
                    {"name": c.name, "component_type": c.component_type, "is_exported": c.is_exported, "intent_filters": c.intent_filters}
                    for c in apk_result.components
                ]
                result.native_libraries = apk_result.native_libraries
                update_phase("manifest", "completed", f"Found {len(result.permissions)} permissions, {len(result.components)} components")
            except Exception as e:
                update_phase("manifest", "error", str(e))
                logger.error(f"Manifest analysis failed: {e}")
            
            yield make_progress("Manifest analysis complete", 100)
            await asyncio.sleep(0.1)  # Allow UI to update
            
            # =================================================================
            # Phase 2: Secret Detection
            # =================================================================
            current_phase_idx = 1
            update_phase("secrets", "in_progress")
            yield make_progress("Scanning for secrets and URLs...", 10)
            
            if apk_result:
                result.secrets = [
                    {"type": s["type"], "value": s["value"], "masked_value": s["masked_value"], "severity": s["severity"]}
                    for s in apk_result.secrets
                ]
                result.urls = apk_result.urls[:100]
                result.security_issues = [
                    {"category": i["category"], "severity": i["severity"], "description": i["description"]}
                    for i in apk_result.security_issues
                ]
                update_phase("secrets", "completed", f"Found {len(result.secrets)} secrets, {len(result.urls)} URLs")
            else:
                update_phase("secrets", "completed", "Skipped - manifest failed")
            
            yield make_progress("Secret detection complete", 100)
            await asyncio.sleep(0.1)
            
            # =================================================================
            # Phase 3: JADX Decompilation
            # =================================================================
            current_phase_idx = 2
            update_phase("jadx", "in_progress")
            yield make_progress("Starting JADX decompilation (this may take a while)...", 10)
            
            try:
                jadx_result = re_service.decompile_apk_with_jadx(tmp_path)
                
                # Store in cache for later queries
                jadx_session_id = str(uuid.uuid4())
                _jadx_cache[jadx_session_id] = Path(jadx_result.output_directory)
                
                result.jadx_session_id = jadx_session_id
                result.total_classes = jadx_result.total_classes
                result.total_files = jadx_result.total_files
                result.decompilation_time = jadx_result.decompilation_time
                result.source_tree = jadx_result.source_tree
                
                # Log source tree info for debugging
                logger.info(f"JADX source tree has {len(jadx_result.source_tree)} top-level entries")
                
                # Collect security issues
                all_jadx_issues = []
                for cls in jadx_result.classes:
                    all_jadx_issues.extend(cls.security_issues)
                result.jadx_security_issues = all_jadx_issues[:100]
                
                # Classes summary
                result.classes_summary = [
                    {
                        "class_name": c.class_name,
                        "package_name": c.package_name,
                        "file_path": c.file_path,
                        "line_count": c.line_count,
                        "is_activity": c.is_activity,
                        "is_service": c.is_service,
                        "security_issues_count": len(c.security_issues),
                    }
                    for c in jadx_result.classes[:500]
                ]
                
                update_phase("jadx", "completed", f"Decompiled {jadx_result.total_classes} classes in {jadx_result.decompilation_time:.1f}s")
            except Exception as e:
                update_phase("jadx", "error", str(e))
                logger.error(f"JADX decompilation failed: {e}", exc_info=True)
            
            yield make_progress("JADX decompilation complete", 100)
            await asyncio.sleep(0.1)
            
            # =================================================================
            # Phase 3b: Decompiled Source Code Security Scan (RUN EARLY for AI context)
            # =================================================================
            yield make_progress("Running decompiled code security scanners...", 10)
            
            try:
                if jadx_result and jadx_result.output_directory:
                    jadx_output_path = Path(jadx_result.output_directory)
                    if jadx_output_path.exists():
                        yield make_progress("Scanning WebView, crypto, SQL injection...", 20)
                        code_scan_results = re_service.scan_decompiled_source_comprehensive(jadx_output_path)
                        result.decompiled_code_findings = code_scan_results.get("findings", [])
                        result.decompiled_code_summary = code_scan_results.get("summary", {})
                        
                        finding_count = len(result.decompiled_code_findings)
                        critical_count = code_scan_results.get("summary", {}).get("by_severity", {}).get("critical", 0)
                        high_count = code_scan_results.get("summary", {}).get("by_severity", {}).get("high", 0)
                        
                        logger.info(f"Decompiled code scan found {finding_count} issues ({critical_count} critical, {high_count} high)")
            except Exception as e:
                logger.error(f"Decompiled code security scan failed: {e}")
            
            yield make_progress("Decompiled code scan complete", 100)
            await asyncio.sleep(0.1)
            
            # =================================================================
            # Phase 4: AI Functionality Report
            # =================================================================
            current_phase_idx = 3
            update_phase("ai_functionality", "in_progress")
            yield make_progress("Generating AI functionality report...", 10)
            
            try:
                if apk_result:
                    # Pass JADX output directory for source code context
                    jadx_output_path = Path(jadx_result.output_directory) if jadx_result else None
                    # Pass decompiled code findings for enhanced AI analysis
                    ai_reports = await re_service.analyze_apk_with_ai(
                        apk_result, 
                        jadx_output_path,
                        decompiled_findings=result.decompiled_code_findings
                    )
                    if ai_reports:
                        result.ai_functionality_report = apk_result.ai_report_functionality
                update_phase("ai_functionality", "completed", "Report generated")
            except Exception as e:
                update_phase("ai_functionality", "error", str(e))
                logger.error(f"AI functionality report failed: {e}")
            
            yield make_progress("AI functionality report complete", 100)
            await asyncio.sleep(0.1)
            
            # =================================================================
            # Phase 5: AI Security Report
            # =================================================================
            current_phase_idx = 4
            update_phase("ai_security", "in_progress")
            yield make_progress("Generating AI security report...", 10)
            
            try:
                if apk_result and apk_result.ai_report_security:
                    result.ai_security_report = apk_result.ai_report_security
                update_phase("ai_security", "completed", "Report generated")
            except Exception as e:
                update_phase("ai_security", "error", str(e))
                logger.error(f"AI security report failed: {e}")
            
            yield make_progress("AI security report complete", 100)
            await asyncio.sleep(0.1)
            
            # =================================================================
            # Phase 6: Architecture Diagram
            # =================================================================
            current_phase_idx = 5
            update_phase("ai_diagram", "in_progress")
            yield make_progress("Generating architecture diagram...", 10)
            
            try:
                if apk_result:
                    # Pass JADX output directory for source code context
                    jadx_output_path = Path(jadx_result.output_directory) if jadx_result else None
                    # Get JADX result summary dict for additional context
                    jadx_summary = None
                    if jadx_output_path and jadx_output_path.exists():
                        try:
                            jadx_summary = re_service.get_jadx_result_summary(jadx_output_path)
                        except Exception:
                            pass  # Continue without summary
                    diagram = await re_service.generate_ai_architecture_diagram(apk_result, jadx_summary, output_dir=jadx_output_path)
                    result.ai_architecture_diagram = diagram
                update_phase("ai_diagram", "completed", "Diagram generated")
            except Exception as e:
                update_phase("ai_diagram", "error", str(e))
                logger.error(f"Architecture diagram generation failed: {e}")
            
            yield make_progress("Architecture diagram complete", 100)
            
            # =================================================================
            # Phase 6b: Attack Surface Map (AI-powered attack tree)
            # =================================================================
            yield make_progress("Generating AI attack surface map...", 10)
            
            try:
                if apk_result:
                    jadx_output_path = Path(jadx_result.output_directory) if jadx_result else None
                    if jadx_output_path and jadx_output_path.exists():
                        # Generate attack surface map first
                        attack_surface = re_service.generate_attack_surface_map(tmp_path)
                        # Then generate AI-powered attack tree with decompiled findings
                        attack_tree = await re_service.generate_ai_attack_tree_mermaid(
                            attack_surface, 
                            jadx_output_path,
                            decompiled_findings=result.decompiled_code_findings
                        )
                        result.ai_attack_surface_map = attack_tree
                        logger.info("Generated AI attack surface map for unified scan")
            except Exception as e:
                logger.error(f"Attack surface map generation failed: {e}")
            
            yield make_progress("Attack surface map complete", 100)
            
            # =================================================================
            # Phase 6c: Enhanced Frida Hooks (Vulnerability-specific)
            # =================================================================
            yield make_progress("Generating vulnerability-specific Frida hooks...", 10)
            
            try:
                if result.decompiled_code_findings and apk_result:
                    # Generate targeted Frida hooks based on discovered vulnerabilities
                    vuln_frida_hooks = re_service.generate_vulnerability_specific_frida_hooks(
                        package_name=apk_result.package_name,
                        decompiled_findings=result.decompiled_code_findings,
                        manifest_analysis=apk_result.manifest_analysis if hasattr(apk_result, 'manifest_analysis') else None
                    )
                    
                    if vuln_frida_hooks and vuln_frida_hooks.get("vulnerability_scripts"):
                        result.vulnerability_frida_hooks = vuln_frida_hooks
                        hook_count = len(vuln_frida_hooks.get("vulnerability_scripts", []))
                        logger.info(f"Generated {hook_count} vulnerability-specific Frida scripts")
            except Exception as e:
                logger.error(f"Vulnerability Frida hook generation failed: {e}")
            
            yield make_progress("Frida hooks generated", 100)
            
            # =================================================================
            # Final Result
            # =================================================================
            result.scan_time = (datetime.now() - start_time).total_seconds()
            
            yield f"data: {json.dumps({'type': 'result', 'data': result.model_dump()})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
            
        except Exception as e:
            logger.error(f"Unified scan failed: {e}")
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
        finally:
            # Cleanup session (but keep JADX cache for browsing)
            if scan_id in _unified_scan_sessions:
                del _unified_scan_sessions[scan_id]
            # Note: Don't delete tmp_dir yet - JADX cache needs it
    
    return StreamingResponse(
        run_unified_scan(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@router.post("/apk/unified-scan/{scan_id}/cancel")
async def cancel_unified_scan(scan_id: str):
    """Cancel an in-progress unified scan."""
    if scan_id in _unified_scan_sessions:
        _unified_scan_sessions[scan_id]["cancelled"] = True
        return {"status": "cancelled"}
    raise HTTPException(status_code=404, detail="Scan session not found")


# ============================================================================
# JADX Decompilation Endpoints
# ============================================================================

class JadxDecompilationResponse(BaseModel):
    """Response for JADX decompilation."""
    package_name: str
    total_classes: int
    total_files: int
    output_directory: str
    decompilation_time: float
    classes: List[Dict[str, Any]]
    source_tree: Dict[str, Any]
    security_issues: List[Dict[str, Any]]
    errors: List[str] = []
    warnings: List[str] = []


class JadxSourceResponse(BaseModel):
    """Response for getting decompiled source."""
    class_name: str
    package_name: str
    file_path: str
    source_code: str
    line_count: int
    is_activity: bool
    is_service: bool
    is_receiver: bool
    is_provider: bool
    extends: Optional[str] = None
    implements: List[str] = []
    methods: List[str] = []
    security_issues: List[Dict[str, Any]] = []


class JadxSearchResponse(BaseModel):
    """Response for searching decompiled sources."""
    query: str
    total_results: int
    results: List[Dict[str, Any]]


# Store JADX output directories for session
_jadx_cache: Dict[str, Path] = {}


def _resolve_jadx_output_dir(output_directory: str) -> Path:
    """
    Resolve output_directory to an actual Path.
    
    The output_directory can be either:
    1. A JADX session ID (UUID) - looked up from _jadx_cache
    2. A direct filesystem path
    
    Returns:
        Path to the JADX output directory
        
    Raises:
        HTTPException if not found
    """
    # First, check if it's a session ID in the cache
    if output_directory in _jadx_cache:
        return _jadx_cache[output_directory]
    
    # Otherwise, try as a direct path
    output_path = Path(output_directory)
    if output_path.exists():
        return output_path
    
    # Check if it's a session ID that looks like a path (backwards compatibility)
    # Sometimes the frontend might send the session ID
    for session_id, cached_path in _jadx_cache.items():
        if str(cached_path) == output_directory or session_id in output_directory:
            return cached_path
    
    raise HTTPException(
        status_code=404, 
        detail=f"Decompiled sources not found. Session may have expired. Please run the scan again."
    )


@router.post("/apk/decompile", response_model=JadxDecompilationResponse)
async def decompile_apk(
    file: UploadFile = File(..., description="APK file to decompile"),
):
    """
    Decompile an APK to Java source code using JADX.
    
    Returns:
    - Decompiled Java classes with metadata
    - Source code tree structure
    - Security issues found in code
    
    Note: This can take a while for large APKs.
    """
    if not check_jadx_available():
        raise HTTPException(
            status_code=503,
            detail="JADX is not available. Please ensure JADX is installed."
        )
    
    filename = file.filename or "unknown.apk"
    suffix = Path(filename).suffix.lower()
    
    if suffix not in ALLOWED_APK_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_APK_EXTENSIONS)}"
        )
    
    tmp_dir = None
    try:
        # Save file to temp location
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_jadx_"))
        tmp_path = tmp_dir / filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"Decompiling APK with JADX: {filename} ({file_size:,} bytes)")
        
        # Run JADX decompilation
        result = re_service.decompile_apk_with_jadx(tmp_path)
        
        # Store output directory for later queries
        import uuid
        session_id = str(uuid.uuid4())
        _jadx_cache[session_id] = Path(result.output_directory)
        
        # Collect security issues from all classes
        all_security_issues = []
        for cls in result.classes:
            all_security_issues.extend(cls.security_issues)
        
        # Limit classes in response for performance
        classes_summary = [
            {
                "class_name": c.class_name,
                "package_name": c.package_name,
                "file_path": c.file_path,
                "line_count": c.line_count,
                "is_activity": c.is_activity,
                "is_service": c.is_service,
                "is_receiver": c.is_receiver,
                "is_provider": c.is_provider,
                "extends": c.extends,
                "security_issues_count": len(c.security_issues),
            }
            for c in result.classes[:500]  # Limit to 500 classes
        ]
        
        return JadxDecompilationResponse(
            package_name=result.package_name,
            total_classes=result.total_classes,
            total_files=result.total_files,
            output_directory=session_id,  # Return session ID, not actual path
            decompilation_time=result.decompilation_time,
            classes=classes_summary,
            source_tree=result.source_tree,
            security_issues=all_security_issues[:100],  # Limit issues
            errors=result.errors,
            warnings=result.warnings[:20],
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"JADX decompilation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Decompilation failed: {str(e)}")


@router.get("/apk/decompile/{session_id}/source/{class_path:path}", response_model=JadxSourceResponse)
async def get_decompiled_source(
    session_id: str,
    class_path: str,
):
    """
    Get the decompiled Java source code for a specific class.
    
    Args:
        session_id: The session ID from decompilation
        class_path: Path to the Java file (e.g., "com/example/MainActivity.java")
    """
    if session_id not in _jadx_cache:
        raise HTTPException(status_code=404, detail="Decompilation session not found. Please decompile the APK again.")
    
    output_dir = _jadx_cache[session_id]
    
    source_code = re_service.get_jadx_class_source(output_dir, class_path)
    
    if source_code is None:
        raise HTTPException(status_code=404, detail=f"Class not found: {class_path}")
    
    # Parse class info
    class_info = re_service._parse_java_class(source_code, class_path)
    
    return JadxSourceResponse(
        class_name=class_info.class_name,
        package_name=class_info.package_name,
        file_path=class_path,
        source_code=source_code,
        line_count=class_info.line_count,
        is_activity=class_info.is_activity,
        is_service=class_info.is_service,
        is_receiver=class_info.is_receiver,
        is_provider=class_info.is_provider,
        extends=class_info.extends,
        implements=class_info.implements,
        methods=class_info.methods,
        security_issues=class_info.security_issues,
    )


@router.get("/apk/decompile/{session_id}/search", response_model=JadxSearchResponse)
async def search_decompiled_sources(
    session_id: str,
    query: str = Query(..., min_length=2, max_length=100, description="Search string"),
    max_results: int = Query(50, ge=1, le=200),
):
    """
    Search for a string in decompiled Java sources.
    
    Useful for finding:
    - API endpoints and URLs
    - Method names
    - Hardcoded strings
    - Security-sensitive patterns
    """
    if session_id not in _jadx_cache:
        raise HTTPException(status_code=404, detail="Decompilation session not found.")
    
    output_dir = _jadx_cache[session_id]
    
    results = re_service.search_jadx_sources(output_dir, query, max_results)
    
    return JadxSearchResponse(
        query=query,
        total_results=len(results),
        results=results,
    )


@router.delete("/apk/decompile/{session_id}")
async def cleanup_decompilation(session_id: str):
    """Clean up decompiled sources to free disk space."""
    if session_id not in _jadx_cache:
        raise HTTPException(status_code=404, detail="Session not found.")
    
    output_dir = _jadx_cache[session_id]
    
    try:
        if output_dir.exists():
            shutil.rmtree(output_dir, ignore_errors=True)
        del _jadx_cache[session_id]
        return {"message": "Decompilation session cleaned up", "session_id": session_id}
    except Exception as e:
        logger.error(f"Failed to clean up JADX session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class AiDiagramResponse(BaseModel):
    """Response for AI-generated Mermaid diagrams."""
    session_id: str
    architecture_diagram: Optional[str] = None
    data_flow_diagram: Optional[str] = None
    generation_time: float
    error: Optional[str] = None


@router.post("/apk/decompile/{session_id}/ai-diagrams", response_model=AiDiagramResponse)
async def generate_ai_diagrams_from_decompilation(
    session_id: str,
    include_architecture: bool = Query(True, description="Generate architecture diagram"),
    include_data_flow: bool = Query(True, description="Generate data flow diagram"),
):
    """
    Generate AI-powered Mermaid diagrams from decompiled APK sources.
    
    Uses Gemini AI to analyze the decompiled Java source code and generate:
    - **Architecture Diagram**: Shows app components, activities, services, and their relationships
    - **Data Flow Diagram**: Shows how data moves through the app, including privacy-sensitive data
    
    The diagrams use Iconify icons for better visual representation:
    - fa6-brands:android, mdi:application, mdi:cog for components
    - fa6-solid:shield, fa6-solid:lock, fa6-solid:bug for security elements
    
    Note: Requires GEMINI_API_KEY to be configured.
    """
    import time
    start_time = time.time()
    
    if session_id not in _jadx_cache:
        raise HTTPException(status_code=404, detail="Decompilation session not found. Please decompile the APK first.")
    
    output_dir = _jadx_cache[session_id]
    
    if not output_dir.exists():
        raise HTTPException(status_code=404, detail="Decompilation output no longer exists.")
    
    try:
        # Get JADX result summary for AI context
        jadx_result = re_service.get_jadx_result_summary(output_dir)
        
        # Create a minimal ApkAnalysisResult for the diagram generators
        # We'll populate it from the JADX decompilation info
        from services.reverse_engineering_service import ApkAnalysisResult, ApkPermission, ApkComponent, ExtractedString
        
        result = ApkAnalysisResult(
            filename=f"{jadx_result.get('package_name', 'unknown')}.apk",
            package_name=jadx_result.get('package_name', 'unknown'),
            version_name=None,
            version_code=None,
            min_sdk=None,
            target_sdk=None,
            permissions=[],
            components=[
                ApkComponent(
                    name=cls.get('class_name', ''),
                    component_type='activity' if cls.get('is_activity') else 
                                   'service' if cls.get('is_service') else 
                                   'receiver' if cls.get('is_receiver') else 
                                   'provider' if cls.get('is_provider') else 'class',
                    is_exported=False,
                    intent_filters=[]
                )
                for cls in jadx_result.get('classes', [])[:100]  # Limit for context
            ],
            strings=[],
            secrets=[],
            urls=[],
            native_libraries=[],
            activities=[cls.get('class_name', '') for cls in jadx_result.get('classes', []) if cls.get('is_activity')],
            services=[cls.get('class_name', '') for cls in jadx_result.get('classes', []) if cls.get('is_service')],
            receivers=[cls.get('class_name', '') for cls in jadx_result.get('classes', []) if cls.get('is_receiver')],
            providers=[cls.get('class_name', '') for cls in jadx_result.get('classes', []) if cls.get('is_provider')],
        )
        
        architecture_diagram = None
        data_flow_diagram = None
        
        # Generate diagrams (these are async functions)
        if include_architecture:
            architecture_diagram = await re_service.generate_ai_architecture_diagram(result, jadx_result, output_dir=output_dir)
        
        if include_data_flow:
            data_flow_diagram = await re_service.generate_ai_data_flow_diagram(result, jadx_result, output_dir=output_dir)
        
        generation_time = time.time() - start_time
        
        return AiDiagramResponse(
            session_id=session_id,
            architecture_diagram=architecture_diagram,
            data_flow_diagram=data_flow_diagram,
            generation_time=generation_time,
        )
        
    except Exception as e:
        logger.error(f"AI diagram generation failed: {e}")
        return AiDiagramResponse(
            session_id=session_id,
            generation_time=time.time() - start_time,
            error=str(e),
        )


# ============================================================================
# AI Code Analysis Endpoints
# ============================================================================

class AICodeExplanationRequest(BaseModel):
    """Request for AI code explanation."""
    source_code: str
    class_name: str
    explanation_type: str = "general"  # general, security, method
    method_name: Optional[str] = None

class AICodeExplanationResponse(BaseModel):
    """Response with AI explanation."""
    class_name: str
    explanation_type: str
    explanation: str
    key_points: List[str]
    security_concerns: List[Dict[str, Any]]
    method_name: Optional[str] = None

class AIVulnerabilityAnalysisRequest(BaseModel):
    """Request for AI vulnerability analysis."""
    source_code: str
    class_name: str

class AIVulnerabilityAnalysisResponse(BaseModel):
    """Response with vulnerability analysis."""
    class_name: str
    risk_level: str  # critical, high, medium, low, info
    vulnerabilities: List[Dict[str, Any]]
    recommendations: List[str]
    exploitation_scenarios: List[str]
    summary: str


@router.post("/apk/decompile/ai/explain", response_model=AICodeExplanationResponse)
async def explain_code_with_ai(request: AICodeExplanationRequest):
    """
    Use AI to explain decompiled Java/Kotlin code.
    
    Explanation types:
    - general: What does this class/code do?
    - security: Security-focused analysis
    - method: Explain a specific method
    """
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="AI features require Gemini API key")
    
    try:
        result = await re_service.explain_code_with_ai(
            source_code=request.source_code,
            class_name=request.class_name,
            explanation_type=request.explanation_type,
            method_name=request.method_name
        )
        return AICodeExplanationResponse(**result)
    except Exception as e:
        logger.error(f"AI code explanation failed: {e}")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")


@router.post("/apk/decompile/ai/vulnerabilities", response_model=AIVulnerabilityAnalysisResponse)
async def analyze_vulnerabilities_with_ai(request: AIVulnerabilityAnalysisRequest):
    """
    Use AI to perform deep vulnerability analysis on decompiled code.
    
    Returns:
    - Identified vulnerabilities with severity
    - Exploitation scenarios
    - Fix recommendations
    """
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="AI features require Gemini API key")
    
    try:
        result = await re_service.analyze_code_vulnerabilities_with_ai(
            source_code=request.source_code,
            class_name=request.class_name
        )
        return AIVulnerabilityAnalysisResponse(**result)
    except Exception as e:
        logger.error(f"AI vulnerability analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")


# ============================================================================
# Data Flow Analysis Endpoints
# ============================================================================

class DataFlowSourceSink(BaseModel):
    """A data source or sink in the flow analysis."""
    type: str
    pattern: Optional[str] = None
    line: int
    code: str
    variable: Optional[str] = None


class DataFlow(BaseModel):
    """A data flow from source to sink."""
    source: Dict[str, Any]
    sink: Dict[str, Any]
    risk: str


class DataFlowSummary(BaseModel):
    """Summary of data flow analysis."""
    total_sources: int
    total_sinks: int
    potential_leaks: int
    risk_level: str


class DataFlowAnalysisRequest(BaseModel):
    """Request to analyze data flow in code."""
    source_code: str
    class_name: str


class DataFlowAnalysisResponse(BaseModel):
    """Response from data flow analysis."""
    class_name: str
    sources: List[Dict[str, Any]]
    sinks: List[Dict[str, Any]]
    flows: List[DataFlow]
    risk_flows: List[DataFlow]
    summary: DataFlowSummary


@router.post("/apk/decompile/dataflow", response_model=DataFlowAnalysisResponse)
async def analyze_data_flow(request: DataFlowAnalysisRequest):
    """
    Analyze data flow in decompiled Java/Kotlin code.
    
    Performs lightweight taint analysis to track:
    - Data sources (user input, files, network, sensors)
    - Data sinks (logging, network, storage, IPC)
    - Potential data leakage paths
    """
    try:
        result = re_service.analyze_data_flow(
            source_code=request.source_code,
            class_name=request.class_name
        )
        return DataFlowAnalysisResponse(**result)
    except Exception as e:
        logger.error(f"Data flow analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Data flow analysis failed: {str(e)}")


# ============================================================================
# Method Call Graph Endpoints
# ============================================================================

class MethodInfo(BaseModel):
    """Information about a method."""
    name: str
    return_type: str
    parameters: List[Dict[str, str]]
    line_start: int
    line_end: int
    is_entry_point: bool
    calls: List[Dict[str, Any]]
    called_by: List[str] = []
    modifiers: List[str] = []


class CallInfo(BaseModel):
    """Information about a method call."""
    caller: str
    caller_line: int
    callee: str
    callee_class: str
    line: int
    is_internal: bool


class GraphNode(BaseModel):
    """A node in the call graph."""
    id: str
    label: str
    type: str
    is_entry_point: bool
    line: Optional[int] = None


class GraphEdge(BaseModel):
    """An edge in the call graph."""
    source: str = Field(alias="from")
    target: str = Field(alias="to")
    label: str

    class Config:
        populate_by_name = True


class CallGraphStatistics(BaseModel):
    """Statistics about the call graph."""
    total_methods: int
    total_internal_calls: int
    total_external_calls: int
    max_depth: int
    cyclomatic_complexity: int


class CallGraphRequest(BaseModel):
    """Request to build method call graph."""
    source_code: str
    class_name: str


class CallGraphResponse(BaseModel):
    """Response from call graph analysis."""
    class_name: str
    methods: List[MethodInfo]
    calls: List[CallInfo]
    entry_points: List[Dict[str, Any]]
    external_calls: List[CallInfo]
    graph: Dict[str, Any]
    statistics: CallGraphStatistics


@router.post("/apk/decompile/callgraph", response_model=CallGraphResponse)
async def build_call_graph(request: CallGraphRequest):
    """
    Build a method call graph from decompiled Java/Kotlin code.
    
    Returns:
    - Method definitions and signatures
    - Internal and external method calls
    - Entry points (lifecycle methods, callbacks)
    - Graph structure for visualization
    - Code complexity statistics
    """
    try:
        result = re_service.build_call_graph(
            source_code=request.source_code,
            class_name=request.class_name
        )
        return CallGraphResponse(**result)
    except Exception as e:
        logger.error(f"Call graph analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Call graph analysis failed: {str(e)}")


# ============================================================================
# Smart Search Endpoints
# ============================================================================

class SmartSearchMatch(BaseModel):
    """A match from smart search."""
    file: str
    line: int
    code: str
    match: str
    context: Optional[str] = None
    vuln_type: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None


class VulnSummaryItem(BaseModel):
    """Vulnerability summary item."""
    count: int
    severity: str
    description: str


class SmartSearchRequest(BaseModel):
    """Request for smart search."""
    output_directory: str
    query: str
    search_type: str = "smart"  # smart, vuln, regex, exact
    max_results: int = 100


class SmartSearchResponse(BaseModel):
    """Response from smart search."""
    query: str
    search_type: str
    total_matches: int
    files_searched: int
    matches: List[SmartSearchMatch]
    vulnerability_summary: Dict[str, VulnSummaryItem] = {}
    expanded_terms: List[str] = []
    suggestions: List[str] = []
    error: Optional[str] = None


@router.post("/apk/decompile/smart-search", response_model=SmartSearchResponse)
async def smart_search(request: SmartSearchRequest):
    """
    Perform smart/semantic search across decompiled sources.
    
    Search types:
    - smart: Expands query with related security terms
    - vuln: Searches for vulnerability patterns  
    - regex: Direct regex search
    - exact: Exact string match
    
    Returns matches with context and vulnerability classification.
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.smart_search(
            output_dir=output_dir,
            query=request.query,
            search_type=request.search_type,
            max_results=request.max_results
        )
        return SmartSearchResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Smart search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Smart search failed: {str(e)}")


# ============================================================================
# AI Vulnerability Scan Endpoints
# ============================================================================

class AIVulnScanVulnerability(BaseModel):
    """A vulnerability from AI scan."""
    id: str = ""
    title: str
    severity: str
    category: str = ""
    affected_class: str = ""
    affected_method: str = ""
    description: str
    code_snippet: str = ""
    impact: str = ""
    remediation: str = ""
    cwe_id: str = ""


class AIVulnScanAttackChain(BaseModel):
    """An attack chain from AI scan."""
    name: str
    steps: List[str]
    impact: str
    likelihood: str = "medium"


class AIVulnScanRiskSummary(BaseModel):
    """Risk summary from AI scan."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class AIVulnScanRequest(BaseModel):
    """Request for AI vulnerability scan."""
    output_directory: str
    scan_type: str = "quick"  # quick, deep, focused
    focus_areas: List[str] = []  # auth, crypto, network, storage


class AIVulnScanResponse(BaseModel):
    """Response from AI vulnerability scan."""
    scan_type: str
    focus_areas: List[str]
    classes_scanned: int
    vulnerabilities: List[AIVulnScanVulnerability]
    risk_summary: AIVulnScanRiskSummary
    attack_chains: List[AIVulnScanAttackChain] = []
    recommendations: List[str] = []
    summary: str
    overall_risk: str = "low"
    error: Optional[str] = None


@router.post("/apk/decompile/ai-vulnscan", response_model=AIVulnScanResponse)
async def ai_vulnerability_scan(request: AIVulnScanRequest):
    """
    Perform AI-powered vulnerability scan across multiple classes.
    
    Scan types:
    - quick: Scan key classes (activities, services, network) - ~10 classes
    - deep: Scan all relevant classes - ~25 classes
    - focused: Scan specific areas (auth, crypto, network, storage)
    
    Returns comprehensive vulnerability analysis with attack chains.
    """
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="AI features require Gemini API key")
    
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = await re_service.ai_vulnerability_scan(
            output_dir=output_dir,
            scan_type=request.scan_type,
            focus_areas=request.focus_areas if request.focus_areas else None
        )
        return AIVulnScanResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI vulnerability scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"AI vulnerability scan failed: {str(e)}")


# ============================================================================
# Library CVE Scan Endpoint
# ============================================================================

class LibraryCVEScanRequest(BaseModel):
    """Request for library CVE scan."""
    output_directory: str
    gradle_content: Optional[str] = None  # Optional gradle file content


class DetectedLibrary(BaseModel):
    """A detected library in the APK."""
    package_prefix: str
    maven_coordinate: str
    ecosystem: str
    version: Optional[str] = None
    class_count: int = 0
    is_high_risk: bool = False
    risk_reason: Optional[str] = None


class LibraryCVE(BaseModel):
    """A CVE found in a library."""
    library: str
    library_version: str
    cve_id: str
    aliases: List[str] = []
    summary: str
    details: str = ""
    severity: str
    cvss_score: Optional[float] = None
    affected_versions: List[str] = []
    references: List[str] = []
    published: str = ""
    modified: str = ""
    exploitation_potential: str = ""
    attack_vector: str = ""


class LibraryCVEScanResponse(BaseModel):
    """Response from library CVE scan."""
    total_libraries: int
    high_risk_libraries: int
    total_cves: int
    critical_cves: int
    high_cves: int
    libraries: List[DetectedLibrary]
    cves: List[LibraryCVE]
    error: Optional[str] = None


@router.post("/apk/decompile/library-cve-scan", response_model=LibraryCVEScanResponse)
async def library_cve_scan(request: LibraryCVEScanRequest):
    """
    Scan decompiled APK for third-party libraries and look up known CVEs.
    
    This endpoint:
    1. Extracts class names from decompiled source
    2. Identifies third-party libraries by package prefixes
    3. Looks up CVEs for each library via OSV.dev API
    4. Returns exploitation-focused vulnerability assessment
    
    Use this to identify known vulnerabilities in bundled dependencies.
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        # Get all class names from decompiled source
        class_names = []
        sources_dir = output_dir / "sources"
        
        if sources_dir.exists():
            for java_file in sources_dir.rglob("*.java"):
                # Convert file path to class name
                try:
                    rel_path = java_file.relative_to(sources_dir)
                    class_name = str(rel_path).replace("/", ".").replace("\\", ".").replace(".java", "")
                    class_names.append(class_name)
                except Exception:
                    pass
        
        if not class_names:
            return LibraryCVEScanResponse(
                total_libraries=0,
                high_risk_libraries=0,
                total_cves=0,
                critical_cves=0,
                high_cves=0,
                libraries=[],
                cves=[],
                error="No decompiled classes found. Run JADX decompilation first."
            )
        
        # Extract dependencies from class names
        from backend.services.reverse_engineering_service import extract_apk_dependencies, lookup_apk_cves
        
        libraries = extract_apk_dependencies(class_names, request.gradle_content)
        
        # Convert to response format
        lib_responses = [
            DetectedLibrary(
                package_prefix=lib.package_prefix,
                maven_coordinate=lib.maven_coordinate,
                ecosystem=lib.ecosystem,
                version=lib.version,
                class_count=lib.class_count,
                is_high_risk=lib.is_high_risk,
                risk_reason=lib.risk_reason,
            )
            for lib in libraries
        ]
        
        # Look up CVEs for detected libraries
        cves_raw = await lookup_apk_cves(libraries)
        
        # Convert to response format
        cve_responses = [
            LibraryCVE(
                library=cve.get('library', ''),
                library_version=cve.get('library_version', 'unknown'),
                cve_id=cve.get('cve_id', ''),
                aliases=cve.get('aliases', []),
                summary=cve.get('summary', ''),
                details=cve.get('details', ''),
                severity=cve.get('severity', 'unknown'),
                cvss_score=cve.get('cvss_score'),
                affected_versions=cve.get('affected_versions', []),
                references=cve.get('references', []),
                published=cve.get('published', ''),
                modified=cve.get('modified', ''),
                exploitation_potential=cve.get('exploitation_potential', ''),
                attack_vector=cve.get('attack_vector', ''),
            )
            for cve in cves_raw
        ]
        
        # Calculate counts
        high_risk_libs = sum(1 for lib in libraries if lib.is_high_risk)
        critical_cves = sum(1 for cve in cves_raw if cve.get('severity', '').lower() == 'critical')
        high_cves = sum(1 for cve in cves_raw if cve.get('severity', '').lower() == 'high')
        
        logger.info(f"Library CVE scan: {len(libraries)} libraries, {len(cves_raw)} CVEs found")
        
        return LibraryCVEScanResponse(
            total_libraries=len(libraries),
            high_risk_libraries=high_risk_libs,
            total_cves=len(cves_raw),
            critical_cves=critical_cves,
            high_cves=high_cves,
            libraries=lib_responses,
            cves=cve_responses,
        )
        
    except Exception as e:
        logger.error(f"Library CVE scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Library CVE scan failed: {str(e)}")


# ============================================================================
# Enhanced Security Analysis Endpoint (Combined Pattern + AI + CVE)
# ============================================================================

class EnhancedSecurityFinding(BaseModel):
    """A unified security finding from any detection method."""
    source: str  # "pattern", "ai", or "cve"
    detection_method: str
    title: str
    severity: str
    category: str = ""
    affected_class: str = ""
    affected_method: str = ""
    description: str = ""
    code_snippet: str = ""
    line_number: int = 0
    impact: str = ""
    remediation: str = ""
    cve_id: str = ""
    cvss_score: Optional[float] = None
    cwe_id: str = ""
    affected_library: str = ""
    attack_vector: str = ""
    exploitation_potential: str = ""
    references: List[str] = []


class AttackChain(BaseModel):
    """A multi-step attack scenario."""
    name: str
    steps: List[str]
    impact: str
    likelihood: str = "medium"
    classes_involved: List[str] = []


class EnhancedSecurityRiskSummary(BaseModel):
    """Risk summary from enhanced security analysis."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class EnhancedSecurityMetadata(BaseModel):
    """Metadata about the security analysis."""
    pattern_scan_enabled: bool = True
    ai_scan_enabled: bool = True
    cve_lookup_enabled: bool = True
    classes_scanned: int = 0
    libraries_detected: int = 0
    cves_found: int = 0
    ai_scan_error: Optional[str] = None
    cve_lookup_error: Optional[str] = None


class EnhancedSecurityRequest(BaseModel):
    """Request for enhanced security analysis."""
    output_directory: str
    include_ai_scan: bool = True
    include_cve_lookup: bool = True
    ai_scan_type: str = "quick"  # quick, deep, focused


class EnhancedSecurityResponse(BaseModel):
    """Combined security analysis response."""
    pattern_findings: List[Dict[str, Any]] = []
    ai_findings: List[EnhancedSecurityFinding] = []
    cve_findings: List[EnhancedSecurityFinding] = []
    combined_findings: List[EnhancedSecurityFinding] = []
    attack_chains: List[AttackChain] = []
    risk_summary: EnhancedSecurityRiskSummary
    overall_risk: str = "low"
    recommendations: List[str] = []
    executive_summary: str = ""
    analysis_metadata: EnhancedSecurityMetadata
    error: Optional[str] = None


@router.post("/apk/decompile/enhanced-security", response_model=EnhancedSecurityResponse)
async def enhanced_security_scan(request: EnhancedSecurityRequest):
    """
    Perform comprehensive security analysis combining multiple detection methods.
    
    This unified scan combines:
    1. **Pattern-based Detection** (fast) - Regex scanning for known vulnerability patterns
    2. **AI-powered Analysis** (thorough) - Cross-class vulnerability detection using Gemini AI
    3. **CVE Lookup** (authoritative) - Known vulnerabilities in third-party libraries via OSV.dev
    
    Returns deduplicated, prioritized findings with attack chains and recommendations.
    
    Scan options:
    - include_ai_scan: Enable AI cross-class analysis (requires Gemini API key)
    - include_cve_lookup: Enable CVE lookup for dependencies
    - ai_scan_type: "quick" (fast), "deep" (thorough), or "focused" (specific areas)
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = await re_service.enhanced_security_analysis(
            output_dir=output_dir,
            include_ai_scan=request.include_ai_scan,
            include_cve_lookup=request.include_cve_lookup,
            ai_scan_type=request.ai_scan_type
        )
        
        if "error" in result and result.get("combined_findings") is None:
            return EnhancedSecurityResponse(
                risk_summary=EnhancedSecurityRiskSummary(),
                analysis_metadata=EnhancedSecurityMetadata(),
                error=result["error"]
            )
        
        return EnhancedSecurityResponse(
            pattern_findings=result.get("pattern_findings", []),
            ai_findings=[EnhancedSecurityFinding(**f) for f in result.get("ai_findings", []) if isinstance(f, dict)],
            cve_findings=[EnhancedSecurityFinding(**f) for f in result.get("cve_findings", []) if isinstance(f, dict)],
            combined_findings=[EnhancedSecurityFinding(**f) if isinstance(f, dict) else f for f in result.get("combined_findings", [])],
            attack_chains=[AttackChain(**c) if isinstance(c, dict) else c for c in result.get("attack_chains", [])],
            risk_summary=EnhancedSecurityRiskSummary(**result.get("risk_summary", {})),
            overall_risk=result.get("overall_risk", "low"),
            recommendations=result.get("recommendations", []),
            executive_summary=result.get("executive_summary", ""),
            analysis_metadata=EnhancedSecurityMetadata(**result.get("analysis_metadata", {})),
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enhanced security scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enhanced security scan failed: {str(e)}")


# ============================================================================
# Smali View Endpoints
# ============================================================================

class SmaliInstruction(BaseModel):
    """A Smali instruction."""
    method: str
    instruction: str
    category: str


class SmaliBytecodStats(BaseModel):
    """Smali bytecode statistics."""
    invocations: Dict[str, int] = {}
    field_ops: Dict[str, int] = {}
    control_flow: Dict[str, int] = {}
    suspicious_ops: Dict[str, int] = {}


class SmaliViewRequest(BaseModel):
    """Request for Smali view."""
    output_directory: str
    class_path: str


class SmaliViewResponse(BaseModel):
    """Response with Smali bytecode."""
    class_path: str
    smali_code: str
    bytecode_stats: SmaliBytecodStats = SmaliBytecodStats()
    registers_used: int = 0
    method_count: int = 0
    field_count: int = 0
    instructions: List[SmaliInstruction] = []
    is_pseudo: bool = False
    error: Optional[str] = None


@router.post("/apk/decompile/smali", response_model=SmaliViewResponse)
async def get_smali_view(request: SmaliViewRequest):
    """
    Get Smali bytecode view for a class.
    
    Returns the Dalvik bytecode (Smali) representation of a class,
    which shows low-level operations and is useful for:
    - Analyzing obfuscated code
    - Understanding actual runtime behavior
    - Finding hidden functionality
    - Patching/modifying APKs
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.get_smali_for_class(output_dir, request.class_path)
        
        if result is None:
            return SmaliViewResponse(
                class_path=request.class_path,
                smali_code="# Smali not available\n# Try using baksmali on the original APK",
                is_pseudo=True,
                error="Smali bytecode not available for this class"
            )
        
        return SmaliViewResponse(
            class_path=result["class_path"],
            smali_code=result["smali_code"],
            bytecode_stats=SmaliBytecodStats(**result.get("bytecode_stats", {})) if isinstance(result.get("bytecode_stats"), dict) and "invocations" in result.get("bytecode_stats", {}) else SmaliBytecodStats(),
            registers_used=result.get("registers_used", 0),
            method_count=result.get("method_count", 0),
            field_count=result.get("field_count", 0),
            instructions=[SmaliInstruction(**i) for i in result.get("instructions", [])],
            is_pseudo=result.get("is_pseudo", False),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Smali view failed: {e}")
        raise HTTPException(status_code=500, detail=f"Smali view failed: {str(e)}")


# ============================================================================
# String Extraction Endpoints
# ============================================================================

class ExtractedString(BaseModel):
    """An extracted string with metadata."""
    value: str
    file: str
    line: int
    categories: List[str]
    severity: str
    length: int
    is_resource: bool = False


class StringExtractionRequest(BaseModel):
    """Request for string extraction."""
    output_directory: str
    filters: Optional[List[str]] = None  # url, api_key, password, etc.


class StringExtractionResponse(BaseModel):
    """Response with extracted strings."""
    total_strings: int
    files_scanned: int
    strings: List[ExtractedString]
    stats: Dict[str, int]
    severity_counts: Dict[str, int]
    top_categories: List[List[Any]]
    error: Optional[str] = None


@router.post("/apk/decompile/strings", response_model=StringExtractionResponse)
async def extract_strings(request: StringExtractionRequest):
    """
    Extract and categorize all strings from decompiled sources.
    
    Automatically classifies strings into categories:
    - url: HTTP/HTTPS URLs
    - api_key: API keys and secrets
    - password: Hardcoded passwords
    - firebase: Firebase URLs and keys
    - sql_query: SQL queries
    - file_path: File system paths
    - ip_address: IP addresses
    - email: Email addresses
    - jwt: JSON Web Tokens
    - And more...
    
    Use filters to narrow results (e.g., ["url", "api_key"]).
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.extract_all_strings(output_dir, request.filters)
        
        if "error" in result:
            return StringExtractionResponse(
                total_strings=0,
                files_scanned=0,
                strings=[],
                stats={},
                severity_counts={},
                top_categories=[],
                error=result["error"]
            )
        
        return StringExtractionResponse(
            total_strings=result["total_strings"],
            files_scanned=result["files_scanned"],
            strings=[ExtractedString(**s) for s in result["strings"]],
            stats=result["stats"],
            severity_counts=result["severity_counts"],
            top_categories=result["top_categories"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"String extraction failed: {e}")
        raise HTTPException(status_code=500, detail=f"String extraction failed: {str(e)}")


# ============================================================================
# Cross-Reference (XREF) Endpoints
# ============================================================================

class XrefCaller(BaseModel):
    """A caller reference."""
    class_name: str = Field(alias="class")
    file: str
    method: str
    line: int

    class Config:
        populate_by_name = True


class XrefCallee(BaseModel):
    """An outgoing call reference."""
    method: str
    object: str
    line: int


class XrefMethod(BaseModel):
    """Method with cross-references."""
    name: str
    return_type: str
    params: str
    signature: str
    line: int
    callers: List[Dict[str, Any]] = []
    callees: List[XrefCallee] = []
    caller_count: int = 0
    callee_count: int = 0


class XrefField(BaseModel):
    """Field with cross-references."""
    name: str
    type: str
    line: int
    readers: List[Dict[str, Any]] = []
    writers: List[Dict[str, Any]] = []
    read_count: int = 0
    write_count: int = 0


class XrefStatistics(BaseModel):
    """Cross-reference statistics."""
    method_count: int
    field_count: int
    total_incoming_refs: int
    total_outgoing_refs: int
    is_heavily_used: bool
    is_hub_class: bool


class CrossReferenceRequest(BaseModel):
    """Request for cross-references."""
    output_directory: str
    class_path: str


class CrossReferenceResponse(BaseModel):
    """Response with cross-references."""
    class_name: str
    package: str
    file_path: str
    methods: List[XrefMethod]
    fields: List[XrefField]
    statistics: XrefStatistics
    summary: str
    error: Optional[str] = None


@router.post("/apk/decompile/xref", response_model=CrossReferenceResponse)
async def get_cross_references(request: CrossReferenceRequest):
    """
    Build cross-references for a class.
    
    Returns:
    - All methods defined in the class
    - Who calls each method (incoming references)
    - What each method calls (outgoing references)
    - Field read/write references
    - Statistics about class usage
    
    Useful for:
    - Understanding how a class is used
    - Finding entry points to functionality
    - Tracing data flow through the app
    - Identifying critical/hub classes
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.build_cross_references(output_dir, request.class_path)
        
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        
        return CrossReferenceResponse(
            class_name=result["class_name"],
            package=result["package"],
            file_path=result["file_path"],
            methods=[XrefMethod(
                name=m["name"],
                return_type=m["return_type"],
                params=m["params"],
                signature=m["signature"],
                line=m["line"],
                callers=m["callers"],
                callees=[XrefCallee(**c) for c in m["callees"]],
                caller_count=m["caller_count"],
                callee_count=m["callee_count"],
            ) for m in result["methods"]],
            fields=[XrefField(
                name=f["name"],
                type=f["type"],
                line=f["line"],
                readers=f["readers"],
                writers=f["writers"],
                read_count=f["read_count"],
                write_count=f["write_count"],
            ) for f in result["fields"]],
            statistics=XrefStatistics(**result["statistics"]),
            summary=result["summary"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cross-reference failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cross-reference failed: {str(e)}")


# ============================================================================
# Download Project ZIP Endpoint
# ============================================================================

class ProjectZipInfoResponse(BaseModel):
    """Information about project ZIP."""
    total_files: int
    total_size_bytes: int
    total_size_mb: float
    file_types: Dict[str, int]
    estimated_zip_size_mb: float
    error: Optional[str] = None


class DownloadProjectRequest(BaseModel):
    """Request to download project as ZIP."""
    output_directory: str


@router.post("/apk/decompile/zip-info", response_model=ProjectZipInfoResponse)
async def get_project_zip_info(request: DownloadProjectRequest):
    """
    Get information about what would be in the project ZIP.
    
    Returns file counts, sizes, and estimated download size.
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.get_project_zip_info(output_dir)
        
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        
        return ProjectZipInfoResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get ZIP info failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/apk/decompile/download-zip")
async def download_project_zip(request: DownloadProjectRequest):
    """
    Create and download the decompiled project as a ZIP file.
    
    Returns the ZIP file as a downloadable response.
    """
    from fastapi.responses import FileResponse
    
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        zip_path = re_service.create_project_zip(output_dir)
        
        return FileResponse(
            path=str(zip_path),
            filename=zip_path.name,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename={zip_path.name}"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create ZIP failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create ZIP: {str(e)}")


# ============================================================================
# Permission Analyzer Endpoint
# ============================================================================

class PermissionInfo(BaseModel):
    """Information about a single permission."""
    name: str
    short_name: str
    level: str  # dangerous, normal, signature, deprecated, unknown
    description: str
    category: str


class DangerousCombination(BaseModel):
    """A dangerous permission combination."""
    permissions: List[str]
    risk: str
    description: str


class PermissionAnalysisResponse(BaseModel):
    """Permission analysis results."""
    total_permissions: int
    permissions: List[PermissionInfo]
    by_level: Dict[str, List[PermissionInfo]]
    by_category: Dict[str, List[PermissionInfo]]
    dangerous_combinations: List[DangerousCombination]
    risk_score: int
    overall_risk: str
    summary: str
    error: Optional[str] = None


class PermissionAnalysisRequest(BaseModel):
    """Request for permission analysis."""
    output_directory: str


@router.post("/apk/decompile/permissions", response_model=PermissionAnalysisResponse)
async def analyze_permissions(request: PermissionAnalysisRequest):
    """
    Analyze permissions from AndroidManifest.xml.
    
    Returns:
    - All requested permissions
    - Categorized by danger level (dangerous, normal, signature)
    - Categorized by type (location, camera, storage, etc.)
    - Dangerous permission combinations
    - Overall risk score and assessment
    
    Useful for:
    - Understanding what the app can access
    - Identifying privacy risks
    - Finding potential malware indicators
    - Security auditing
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.analyze_permissions(output_dir)
        
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        
        return PermissionAnalysisResponse(
            total_permissions=result["total_permissions"],
            permissions=[PermissionInfo(**p) for p in result["permissions"]],
            by_level={k: [PermissionInfo(**p) for p in v] for k, v in result["by_level"].items()},
            by_category={k: [PermissionInfo(**p) for p in v] for k, v in result["by_category"].items()},
            dangerous_combinations=[DangerousCombination(**c) for c in result["dangerous_combinations"]],
            risk_score=result["risk_score"],
            overall_risk=result["overall_risk"],
            summary=result["summary"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Permission analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Permission analysis failed: {str(e)}")


# ============================================================================
# Network Endpoint Extractor Endpoint
# ============================================================================

class NetworkEndpoint(BaseModel):
    """A single network endpoint."""
    value: str
    type: str
    category: str
    risk: str
    file: str
    line: int


class NetworkEndpointResponse(BaseModel):
    """Network endpoint extraction results."""
    total_endpoints: int
    endpoints: List[NetworkEndpoint]
    by_category: Dict[str, List[NetworkEndpoint]]
    by_risk: Dict[str, List[NetworkEndpoint]]
    unique_domains: List[str]
    domain_count: int
    summary: str
    error: Optional[str] = None


class NetworkEndpointRequest(BaseModel):
    """Request for network endpoint extraction."""
    output_directory: str


@router.post("/apk/decompile/network-endpoints", response_model=NetworkEndpointResponse)
async def extract_network_endpoints(request: NetworkEndpointRequest):
    """
    Extract all network endpoints from decompiled sources.
    
    Scans for:
    - HTTP/HTTPS URLs
    - IP addresses (IPv4)
    - API endpoints and paths
    - WebSocket URLs
    - Cloud service URLs (Firebase, AWS, Azure, GCP)
    - Webhooks (Slack, Discord)
    - Payment APIs (Stripe, etc.)
    
    Returns:
    - All found endpoints with file locations
    - Categorized by type and risk level
    - List of unique domains
    - Risk assessment
    
    Useful for:
    - Finding API keys and secrets
    - Identifying C&C servers
    - Understanding app network behavior
    - Security auditing
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.extract_network_endpoints(output_dir)
        
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        
        return NetworkEndpointResponse(
            total_endpoints=result["total_endpoints"],
            endpoints=[NetworkEndpoint(**e) for e in result["endpoints"]],
            by_category={k: [NetworkEndpoint(**e) for e in v] for k, v in result["by_category"].items()},
            by_risk={k: [NetworkEndpoint(**e) for e in v] for k, v in result["by_risk"].items()},
            unique_domains=result["unique_domains"],
            domain_count=result["domain_count"],
            summary=result["summary"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Network endpoint extraction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Network endpoint extraction failed: {str(e)}")


# ============================================================================
# Manifest Visualization Endpoints
# ============================================================================

class ManifestNodeResponse(BaseModel):
    """A node in the manifest visualization."""
    id: str
    name: str
    node_type: str
    label: str
    is_exported: bool = False
    is_main: bool = False
    is_dangerous: bool = False
    attributes: Dict[str, Any] = {}


class ManifestEdgeResponse(BaseModel):
    """An edge in the manifest visualization."""
    source: str
    target: str
    edge_type: str
    label: str = ""


class ManifestVisualizationResponse(BaseModel):
    """Complete manifest visualization response."""
    package_name: str
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    nodes: List[ManifestNodeResponse]
    edges: List[ManifestEdgeResponse]
    component_counts: Dict[str, int]
    permission_summary: Dict[str, int]
    exported_count: int
    main_activity: Optional[str] = None
    deep_link_schemes: List[str] = []
    mermaid_diagram: str
    # AI-enhanced fields
    ai_analysis: Optional[str] = None
    component_purposes: Optional[Dict[str, str]] = None
    security_assessment: Optional[str] = None
    intent_filter_analysis: Optional[Dict[str, Any]] = None


@router.post("/apk/manifest-visualization", response_model=ManifestVisualizationResponse)
async def get_manifest_visualization(
    file: UploadFile = File(..., description="APK file to visualize"),
):
    """
    Generate visualization data for an APK's AndroidManifest.
    
    Returns:
    - Graph nodes for all components and permissions
    - Graph edges showing relationships
    - Component counts by type
    - Mermaid diagram for rendering
    
    Use this data to render an interactive component graph.
    """
    filename = file.filename or "unknown.apk"
    suffix = Path(filename).suffix.lower()
    
    if suffix not in ALLOWED_APK_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_APK_EXTENSIONS)}"
        )
    
    tmp_dir = None
    try:
        # Save file to temp location
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_manifest_"))
        tmp_path = tmp_dir / filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum: {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"Generating manifest visualization: {filename}")
        
        # Generate visualization
        result = re_service.generate_manifest_visualization(tmp_path)
        
        return ManifestVisualizationResponse(
            package_name=result.package_name,
            app_name=result.app_name,
            version_name=result.version_name,
            nodes=[
                ManifestNodeResponse(
                    id=n.id,
                    name=n.name,
                    node_type=n.node_type,
                    label=n.label,
                    is_exported=n.is_exported,
                    is_main=n.is_main,
                    is_dangerous=n.is_dangerous,
                    attributes=n.attributes,
                )
                for n in result.nodes
            ],
            edges=[
                ManifestEdgeResponse(
                    source=e.source,
                    target=e.target,
                    edge_type=e.edge_type,
                    label=e.label,
                )
                for e in result.edges
            ],
            component_counts=result.component_counts,
            permission_summary=result.permission_summary,
            exported_count=result.exported_count,
            main_activity=result.main_activity,
            deep_link_schemes=result.deep_link_schemes,
            mermaid_diagram=result.mermaid_diagram,
            ai_analysis=getattr(result, 'ai_analysis', None),
            component_purposes=getattr(result, 'component_purposes', None),
            security_assessment=getattr(result, 'security_assessment', None),
            intent_filter_analysis=getattr(result, 'intent_filter_analysis', None),
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Manifest visualization failed: {e}")
        raise HTTPException(status_code=500, detail=f"Visualization failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
# Attack Surface Map Endpoints
# ============================================================================

class AttackVectorResponse(BaseModel):
    """An attack vector in the attack surface."""
    id: str
    name: str
    vector_type: str
    component: str
    severity: str
    description: str
    exploitation_steps: List[str]
    required_permissions: List[str] = []
    adb_command: Optional[str] = None
    intent_example: Optional[str] = None
    mitigation: Optional[str] = None


class DeepLinkResponse(BaseModel):
    """A deep link entry."""
    scheme: str
    host: str
    path: str
    full_url: str
    handling_activity: str
    parameters: List[str] = []
    is_verified: bool = False
    security_notes: List[str] = []


class ExposedDataPathResponse(BaseModel):
    """An exposed data path in content provider."""
    provider_name: str
    uri_pattern: str
    permissions_required: List[str]
    operations: List[str]
    is_exported: bool
    potential_data: str
    risk_level: str


class AttackSurfaceMapResponse(BaseModel):
    """Complete attack surface map response."""
    package_name: str
    total_attack_vectors: int
    attack_vectors: List[AttackVectorResponse]
    exposed_data_paths: List[ExposedDataPathResponse]
    deep_links: List[DeepLinkResponse]
    overall_exposure_score: int
    risk_level: str
    risk_breakdown: Dict[str, int]
    priority_targets: List[str]
    automated_tests: List[Dict[str, Any]]
    mermaid_attack_tree: str


@router.post("/apk/attack-surface", response_model=AttackSurfaceMapResponse)
async def get_attack_surface_map(
    file: UploadFile = File(..., description="APK file to analyze"),
    include_ai_analysis: bool = Query(False, description="Include AI analysis of decompiled source code (slower but more accurate)"),
):
    """
    Generate a comprehensive attack surface map for an APK.
    
    Returns:
    - All attack vectors with exploitation steps
    - Deep links and their security implications
    - Exposed content provider paths
    - ADB commands for testing
    - Risk assessment and prioritization
    - Mermaid attack tree diagram
    
    Set include_ai_analysis=true to enable AI-powered analysis of decompiled source code
    for more accurate vulnerability detection (requires JADX decompilation).
    
    This provides a penetration tester's view of the app's attack surface.
    """
    filename = file.filename or "unknown.apk"
    suffix = Path(filename).suffix.lower()
    
    if suffix not in ALLOWED_APK_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_APK_EXTENSIONS)}"
        )
    
    tmp_dir = None
    try:
        # Save file to temp location
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_attack_"))
        tmp_path = tmp_dir / filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum: {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"Generating attack surface map: {filename}")
        
        # Generate basic attack surface map
        result = re_service.generate_attack_surface_map(tmp_path)
        
        # Enhance with AI analysis if requested
        if include_ai_analysis:
            logger.info("Running JADX decompilation for AI attack surface analysis...")
            try:
                jadx_result = re_service.decompile_apk_with_jadx(tmp_path)
                output_dir = Path(jadx_result.output_directory)
                
                logger.info("Enhancing attack surface with AI analysis of source code...")
                result = await re_service.enhance_attack_surface_with_ai(result, output_dir)
                
                # Generate AI-powered attack tree from source code
                logger.info("Generating AI-powered attack tree from source code analysis...")
                ai_attack_tree = await re_service.generate_ai_attack_tree_mermaid(result, output_dir)
                if ai_attack_tree:
                    result.mermaid_attack_tree = ai_attack_tree
                
                # Clean up JADX output
                shutil.rmtree(output_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"AI attack surface enhancement failed, using basic analysis: {e}")
        
        return AttackSurfaceMapResponse(
            package_name=result.package_name,
            total_attack_vectors=result.total_attack_vectors,
            attack_vectors=[
                AttackVectorResponse(
                    id=v.id,
                    name=v.name,
                    vector_type=v.vector_type,
                    component=v.component,
                    severity=v.severity,
                    description=v.description,
                    exploitation_steps=v.exploitation_steps,
                    required_permissions=v.required_permissions,
                    adb_command=v.adb_command,
                    intent_example=v.intent_example,
                    mitigation=v.mitigation,
                )
                for v in result.attack_vectors
            ],
            exposed_data_paths=[
                ExposedDataPathResponse(
                    provider_name=p.provider_name,
                    uri_pattern=p.uri_pattern,
                    permissions_required=p.permissions_required,
                    operations=p.operations,
                    is_exported=p.is_exported,
                    potential_data=p.potential_data,
                    risk_level=p.risk_level,
                )
                for p in result.exposed_data_paths
            ],
            deep_links=[
                DeepLinkResponse(
                    scheme=d.scheme,
                    host=d.host,
                    path=d.path,
                    full_url=d.full_url,
                    handling_activity=d.handling_activity,
                    parameters=d.parameters,
                    is_verified=d.is_verified,
                    security_notes=d.security_notes,
                )
                for d in result.deep_links
            ],
            overall_exposure_score=result.overall_exposure_score,
            risk_level=result.risk_level,
            risk_breakdown=result.risk_breakdown,
            priority_targets=result.priority_targets,
            automated_tests=result.automated_tests,
            mermaid_attack_tree=result.mermaid_attack_tree,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Attack surface mapping failed: {e}")
        raise HTTPException(status_code=500, detail=f"Attack surface mapping failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


class AIAttackSurfaceRequest(BaseModel):
    """Request to enhance attack surface with AI analysis."""
    session_id: str = Field(..., description="JADX decompilation session ID")


@router.post("/apk/decompile/attack-surface-ai", response_model=AttackSurfaceMapResponse)
async def get_ai_attack_surface_map(request: AIAttackSurfaceRequest):
    """
    Generate AI-enhanced attack surface map using an existing JADX session.
    
    This endpoint analyzes decompiled source code to find real vulnerabilities
    in exported components, providing:
    - Code-level vulnerability detection
    - Specific exploitation steps based on actual code
    - Attack chain analysis
    - AI-powered severity assessment
    
    Prerequisites: APK must be decompiled first using /apk/decompile endpoint.
    """
    session_id = request.session_id
    
    if session_id not in _jadx_cache:
        raise HTTPException(
            status_code=404, 
            detail="Decompilation session not found. Please decompile the APK first."
        )
    
    output_dir = _jadx_cache[session_id]
    
    if not output_dir.exists():
        raise HTTPException(status_code=404, detail="Decompilation output no longer exists.")
    
    try:
        # Find the APK path - look for it in the parent of the output dir
        apk_path = None
        for ext in ['.apk', '.APK']:
            for apk in output_dir.parent.glob(f"*{ext}"):
                apk_path = apk
                break
            if apk_path:
                break
        
        if not apk_path:
            # Create minimal attack surface from JADX info
            jadx_summary = re_service.get_jadx_result_summary(output_dir)
            
            # Build a basic attack surface from the JADX classes
            attack_vectors = []
            for cls in jadx_summary.get('classes', []):
                if cls.get('is_activity'):
                    attack_vectors.append(re_service.AttackVector(
                        id=f"activity_{cls.get('class_name', 'unknown').split('.')[-1]}",
                        name=f"Activity: {cls.get('class_name', 'unknown').split('.')[-1]}",
                        vector_type="exported_activity",
                        component=cls.get('class_name', 'unknown'),
                        severity="medium",
                        description=f"Activity found in decompiled code",
                        exploitation_steps=["Analyze source code for vulnerabilities"],
                        required_permissions=[],
                        adb_command="",
                        intent_example="",
                        mitigation=""
                    ))
            
            basic_surface = re_service.AttackSurfaceMap(
                package_name=jadx_summary.get('package_name', 'unknown'),
                total_attack_vectors=len(attack_vectors),
                attack_vectors=attack_vectors,
                exposed_data_paths=[],
                deep_links=[],
                ipc_endpoints=[],
                overall_exposure_score=50,
                risk_level="medium",
                risk_breakdown={'critical': 0, 'high': 0, 'medium': len(attack_vectors), 'low': 0},
                priority_targets=[],
                automated_tests=[],
                mermaid_attack_tree="flowchart TD\n  A[Analysis from decompiled code]"
            )
            result = await re_service.enhance_attack_surface_with_ai(basic_surface, output_dir)
            
            # Generate AI-powered attack tree from source code
            ai_attack_tree = await re_service.generate_ai_attack_tree_mermaid(result, output_dir)
            if ai_attack_tree:
                result.mermaid_attack_tree = ai_attack_tree
        else:
            # Generate full attack surface from APK
            basic_surface = re_service.generate_attack_surface_map(apk_path)
            result = await re_service.enhance_attack_surface_with_ai(basic_surface, output_dir)
            
            # Generate AI-powered attack tree from source code
            ai_attack_tree = await re_service.generate_ai_attack_tree_mermaid(result, output_dir)
            if ai_attack_tree:
                result.mermaid_attack_tree = ai_attack_tree
        
        return AttackSurfaceMapResponse(
            package_name=result.package_name,
            total_attack_vectors=result.total_attack_vectors,
            attack_vectors=[
                AttackVectorResponse(
                    id=v.id,
                    name=v.name,
                    vector_type=v.vector_type,
                    component=v.component,
                    severity=v.severity,
                    description=v.description,
                    exploitation_steps=v.exploitation_steps,
                    required_permissions=v.required_permissions,
                    adb_command=v.adb_command,
                    intent_example=v.intent_example,
                    mitigation=v.mitigation,
                )
                for v in result.attack_vectors
            ],
            exposed_data_paths=[
                ExposedDataPathResponse(
                    provider_name=p.provider_name,
                    uri_pattern=p.uri_pattern,
                    permissions_required=p.permissions_required,
                    operations=p.operations,
                    is_exported=p.is_exported,
                    potential_data=p.potential_data,
                    risk_level=p.risk_level,
                )
                for p in result.exposed_data_paths
            ],
            deep_links=[
                DeepLinkResponse(
                    scheme=d.scheme,
                    host=d.host,
                    path=d.path,
                    full_url=d.full_url,
                    handling_activity=d.handling_activity,
                    parameters=d.parameters,
                    is_verified=d.is_verified,
                    security_notes=d.security_notes,
                )
                for d in result.deep_links
            ],
            overall_exposure_score=result.overall_exposure_score,
            risk_level=result.risk_level,
            risk_breakdown=result.risk_breakdown,
            priority_targets=result.priority_targets,
            automated_tests=result.automated_tests,
            mermaid_attack_tree=result.mermaid_attack_tree,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI attack surface analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"AI attack surface analysis failed: {str(e)}")


# ============================================================================
# Obfuscation Analysis Response Models
# ============================================================================

class ObfuscationIndicatorResponse(BaseModel):
    """Response model for obfuscation indicator."""
    indicator_type: str
    confidence: str
    description: str
    evidence: List[str]
    location: Optional[str] = None
    deobfuscation_hint: Optional[str] = None


class StringEncryptionPatternResponse(BaseModel):
    """Response model for string encryption pattern."""
    pattern_name: str
    class_name: str
    method_name: str
    encrypted_strings_count: int
    decryption_method_signature: Optional[str] = None
    sample_encrypted_values: List[str] = []
    suggested_frida_hook: Optional[str] = None


class ClassNamingAnalysisResponse(BaseModel):
    """Response model for class naming analysis."""
    total_classes: int
    single_letter_classes: int
    short_name_classes: int
    meaningful_name_classes: int
    obfuscation_ratio: float
    sample_obfuscated_names: List[str]
    sample_original_names: List[str]


class ControlFlowObfuscationResponse(BaseModel):
    """Response model for control flow obfuscation."""
    pattern_type: str
    affected_methods: int
    sample_classes: List[str]
    complexity_score: float


class NativeProtectionResponse(BaseModel):
    """Response model for native protection analysis."""
    has_native_libs: bool
    native_lib_names: List[str]
    protection_indicators: List[str]
    jni_functions: List[str]


class ObfuscationAnalysisResponse(BaseModel):
    """Response model for complete obfuscation analysis."""
    package_name: str
    overall_obfuscation_level: str
    obfuscation_score: int
    detected_tools: List[str]
    
    indicators: List[ObfuscationIndicatorResponse]
    class_naming: ClassNamingAnalysisResponse
    string_encryption: List[StringEncryptionPatternResponse]
    control_flow: List[ControlFlowObfuscationResponse]
    native_protection: NativeProtectionResponse
    
    deobfuscation_strategies: List[str]
    recommended_tools: List[str]
    frida_hooks: List[str]
    
    analysis_time: float
    warnings: List[str]
    
    # AI-enhanced fields
    ai_analysis_summary: Optional[str] = None
    reverse_engineering_difficulty: Optional[str] = None
    ai_recommended_approach: Optional[str] = None


@router.post("/apk/obfuscation-analysis", response_model=ObfuscationAnalysisResponse)
async def analyze_apk_obfuscation(
    file: UploadFile = File(..., description="APK file to analyze for obfuscation"),
):
    """
    Analyze an APK for obfuscation techniques.
    
    Detects:
    - ProGuard/R8 obfuscation patterns
    - DexGuard commercial protection
    - String encryption methods
    - Control flow obfuscation
    - Native library protection
    - Reflection-based API hiding
    
    Returns analysis with:
    - Detected obfuscation tools
    - Obfuscation score (0-100)
    - Deobfuscation strategies
    - Auto-generated Frida hooks
    """
    tmp_dir = None
    
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        filename = file.filename.lower()
        if not filename.endswith(('.apk', '.aab')):
            raise HTTPException(status_code=400, detail="Only APK/AAB files are supported")
        
        # Save file temporarily
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_obfusc_"))
        tmp_path = tmp_dir / filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum: {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"Analyzing obfuscation for: {filename}")
        
        # Perform obfuscation analysis
        result = re_service.analyze_apk_obfuscation(tmp_path)
        
        return ObfuscationAnalysisResponse(
            package_name=result.package_name,
            overall_obfuscation_level=result.overall_obfuscation_level,
            obfuscation_score=result.obfuscation_score,
            detected_tools=result.detected_tools,
            indicators=[
                ObfuscationIndicatorResponse(
                    indicator_type=i.indicator_type,
                    confidence=i.confidence,
                    description=i.description,
                    evidence=i.evidence,
                    location=i.location,
                    deobfuscation_hint=i.deobfuscation_hint,
                )
                for i in result.indicators
            ],
            class_naming=ClassNamingAnalysisResponse(
                total_classes=result.class_naming.total_classes,
                single_letter_classes=result.class_naming.single_letter_classes,
                short_name_classes=result.class_naming.short_name_classes,
                meaningful_name_classes=result.class_naming.meaningful_name_classes,
                obfuscation_ratio=result.class_naming.obfuscation_ratio,
                sample_obfuscated_names=result.class_naming.sample_obfuscated_names,
                sample_original_names=result.class_naming.sample_original_names,
            ),
            string_encryption=[
                StringEncryptionPatternResponse(
                    pattern_name=s.pattern_name,
                    class_name=s.class_name,
                    method_name=s.method_name,
                    encrypted_strings_count=s.encrypted_strings_count,
                    decryption_method_signature=s.decryption_method_signature,
                    sample_encrypted_values=s.sample_encrypted_values,
                    suggested_frida_hook=s.suggested_frida_hook,
                )
                for s in result.string_encryption
            ],
            control_flow=[
                ControlFlowObfuscationResponse(
                    pattern_type=c.pattern_type,
                    affected_methods=c.affected_methods,
                    sample_classes=c.sample_classes,
                    complexity_score=c.complexity_score,
                )
                for c in result.control_flow
            ],
            native_protection=NativeProtectionResponse(
                has_native_libs=result.native_protection.has_native_libs,
                native_lib_names=result.native_protection.native_lib_names,
                protection_indicators=result.native_protection.protection_indicators,
                jni_functions=result.native_protection.jni_functions,
            ),
            deobfuscation_strategies=result.deobfuscation_strategies,
            recommended_tools=result.recommended_tools,
            frida_hooks=result.frida_hooks,
            analysis_time=result.analysis_time,
            warnings=result.warnings,
            ai_analysis_summary=getattr(result, 'ai_analysis_summary', None),
            reverse_engineering_difficulty=getattr(result, 'reverse_engineering_difficulty', None),
            ai_recommended_approach=getattr(result, 'ai_recommended_approach', None),
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Obfuscation analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Obfuscation analysis failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/apk/obfuscation-analysis/ai-enhanced", response_model=ObfuscationAnalysisResponse)
async def analyze_apk_obfuscation_ai_enhanced(
    file: UploadFile = File(..., description="APK file to analyze for obfuscation"),
):
    """
    AI-ENHANCED obfuscation analysis with deep code pattern recognition.
    
    This endpoint combines fast static analysis with AI-powered insights:
    - Identifies specific obfuscation tools (ProGuard, DexGuard, Allatori, etc.)
    - Analyzes code samples to detect obfuscation patterns
    - Provides tailored deobfuscation strategies
    - Generates custom Frida hooks for specific patterns
    - Assesses reverse engineering difficulty
    
    Returns enhanced analysis with AI insights and recommendations.
    """
    tmp_dir = None
    
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        filename = file.filename.lower()
        if not filename.endswith(('.apk', '.aab')):
            raise HTTPException(status_code=400, detail="Only APK/AAB files are supported")
        
        # Save file temporarily
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_obfusc_ai_"))
        tmp_path = tmp_dir / filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum: {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"AI-enhanced obfuscation analysis for: {filename}")
        
        # Run JADX decompilation to get source code for AI analysis
        jadx_output_dir = None
        try:
            jadx_result = re_service.decompile_apk_with_jadx(tmp_path)
            jadx_output_dir = Path(jadx_result.output_directory)
            logger.info(f"JADX decompilation complete for obfuscation AI analysis")
        except Exception as e:
            logger.warning(f"JADX decompilation failed, continuing without source code: {e}")
        
        # Perform AI-enhanced obfuscation analysis with source code context
        result = await re_service.analyze_apk_obfuscation_ai_enhanced(tmp_path, jadx_output_dir)
        
        # Clean up JADX output
        if jadx_output_dir and jadx_output_dir.exists():
            shutil.rmtree(jadx_output_dir, ignore_errors=True)
        
        return ObfuscationAnalysisResponse(
            package_name=result.package_name,
            overall_obfuscation_level=result.overall_obfuscation_level,
            obfuscation_score=result.obfuscation_score,
            detected_tools=result.detected_tools,
            indicators=[
                ObfuscationIndicatorResponse(
                    indicator_type=i.indicator_type,
                    confidence=i.confidence,
                    description=i.description,
                    evidence=i.evidence,
                    location=getattr(i, 'location', None),
                    deobfuscation_hint=getattr(i, 'deobfuscation_hint', None),
                )
                for i in result.indicators
            ],
            class_naming=ClassNamingAnalysisResponse(
                total_classes=result.class_naming.total_classes,
                single_letter_classes=result.class_naming.single_letter_classes,
                short_name_classes=result.class_naming.short_name_classes,
                meaningful_name_classes=result.class_naming.meaningful_name_classes,
                obfuscation_ratio=result.class_naming.obfuscation_ratio,
                sample_obfuscated_names=result.class_naming.sample_obfuscated_names,
                sample_original_names=result.class_naming.sample_original_names,
            ),
            string_encryption=[
                StringEncryptionPatternResponse(
                    pattern_name=getattr(s, 'pattern_name', s.pattern_type),
                    class_name=getattr(s, 'class_name', ''),
                    method_name=getattr(s, 'method_name', ''),
                    encrypted_strings_count=getattr(s, 'encrypted_strings_count', s.occurrences),
                    decryption_method_signature=getattr(s, 'decryption_method_signature', ''),
                    sample_encrypted_values=getattr(s, 'sample_encrypted_values', s.sample_encrypted),
                    suggested_frida_hook=getattr(s, 'suggested_frida_hook', s.decryption_hint),
                )
                for s in result.string_encryption
            ],
            control_flow=[
                ControlFlowObfuscationResponse(
                    pattern_type=c.pattern_type,
                    affected_methods=c.affected_methods,
                    sample_classes=c.sample_classes,
                    complexity_score=c.complexity_score,
                )
                for c in result.control_flow
            ],
            native_protection=NativeProtectionResponse(
                has_native_libs=result.native_protection.has_native_libs,
                native_lib_names=getattr(result.native_protection, 'native_lib_names', result.native_protection.native_libs),
                protection_indicators=result.native_protection.protection_indicators,
                jni_functions=getattr(result.native_protection, 'jni_functions', []),
            ),
            deobfuscation_strategies=result.deobfuscation_strategies,
            recommended_tools=result.recommended_tools,
            frida_hooks=result.frida_hooks,
            analysis_time=result.analysis_time,
            warnings=result.warnings,
            ai_analysis_summary=getattr(result, 'ai_analysis_summary', None),
            reverse_engineering_difficulty=getattr(result, 'reverse_engineering_difficulty', None),
            ai_recommended_approach=getattr(result, 'ai_recommended_approach', None),
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI-enhanced obfuscation analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"AI-enhanced obfuscation analysis failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/apk/manifest-visualization/ai-enhanced", response_model=ManifestVisualizationResponse)
async def get_manifest_visualization_ai_enhanced(
    file: UploadFile = File(..., description="APK file to visualize"),
):
    """
    AI-ENHANCED manifest visualization with deep component analysis.
    
    This endpoint provides:
    - Standard manifest visualization (graph, mermaid diagram)
    - AI analysis of component purposes based on names and code
    - Security assessment of exported components
    - Intent filter analysis for security implications
    - Component relationship mapping
    
    Returns visualization data enriched with AI insights.
    """
    filename = file.filename or "unknown.apk"
    suffix = Path(filename).suffix.lower()
    
    if suffix not in ALLOWED_APK_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_APK_EXTENSIONS)}"
        )
    
    tmp_dir = None
    try:
        # Save file to temp location
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_manifest_ai_"))
        tmp_path = tmp_dir / filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum: {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"Generating AI-enhanced manifest visualization: {filename}")
        
        # Run JADX decompilation to get source code for AI analysis
        jadx_output_dir = None
        try:
            jadx_result = re_service.decompile_apk_with_jadx(tmp_path)
            jadx_output_dir = Path(jadx_result.output_directory)
            logger.info(f"JADX decompilation complete for manifest AI analysis")
        except Exception as e:
            logger.warning(f"JADX decompilation failed, continuing without source code: {e}")
        
        # Generate AI-enhanced visualization with source code context
        result = await re_service.generate_ai_enhanced_manifest_visualization(tmp_path, jadx_output_dir)
        
        # Clean up JADX output
        if jadx_output_dir and jadx_output_dir.exists():
            shutil.rmtree(jadx_output_dir, ignore_errors=True)
        
        return ManifestVisualizationResponse(
            package_name=result.package_name,
            app_name=result.app_name,
            version_name=result.version_name,
            nodes=[
                ManifestNodeResponse(
                    id=n.id,
                    name=n.name,
                    node_type=n.node_type,
                    label=n.label,
                    is_exported=n.is_exported,
                    is_main=n.is_main,
                    is_dangerous=n.is_dangerous,
                    attributes=n.attributes,
                )
                for n in result.nodes
            ],
            edges=[
                ManifestEdgeResponse(
                    source=e.source,
                    target=e.target,
                    edge_type=e.edge_type,
                    label=e.label,
                )
                for e in result.edges
            ],
            component_counts=result.component_counts,
            permission_summary=result.permission_summary,
            exported_count=result.exported_count,
            main_activity=result.main_activity,
            deep_link_schemes=result.deep_link_schemes,
            mermaid_diagram=result.mermaid_diagram,
            ai_analysis=result.ai_analysis,
            component_purposes=result.component_purposes,
            security_assessment=result.security_assessment,
            intent_filter_analysis=result.intent_filter_analysis,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI-enhanced manifest visualization failed: {e}")
        raise HTTPException(status_code=500, detail=f"AI-enhanced visualization failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
# Binary Entropy Analysis
# ============================================================================

class EntropyDataPointResponse(BaseModel):
    """Response model for entropy data point."""
    offset: int
    entropy: float
    size: int


class EntropyRegionResponse(BaseModel):
    """Response model for entropy region."""
    start_offset: int
    end_offset: int
    avg_entropy: float
    max_entropy: float
    min_entropy: float
    classification: str
    section_name: Optional[str] = None
    description: str = ""


class EntropyAnalysisResponse(BaseModel):
    """Response model for entropy analysis."""
    filename: str
    file_size: int
    overall_entropy: float
    entropy_data: List[EntropyDataPointResponse]
    regions: List[EntropyRegionResponse]
    is_likely_packed: bool
    packing_confidence: float
    detected_packers: List[str]
    section_entropy: List[Dict[str, Any]]
    analysis_notes: List[str]
    window_size: int
    step_size: int


@router.post("/binary/entropy", response_model=EntropyAnalysisResponse)
async def analyze_binary_entropy(
    file: UploadFile = File(..., description="Binary file to analyze"),
    window_size: int = Query(256, ge=64, le=4096, description="Entropy calculation window size"),
    step_size: int = Query(128, ge=32, le=2048, description="Step size between measurements"),
):
    """
    Analyze entropy distribution across a binary file.
    
    Entropy analysis helps identify:
    - Packed or compressed code sections
    - Encrypted regions
    - Normal code vs data sections
    - Potential malware indicators
    
    Returns entropy data points for visualization and region classification.
    """
    tmp_dir = None
    
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Save file temporarily
        tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_entropy_"))
        tmp_path = tmp_dir / file.filename
        
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum: {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
        
        logger.info(f"Analyzing entropy for: {file.filename}")
        
        # Perform entropy analysis
        result = re_service.analyze_binary_entropy(tmp_path, window_size, step_size)
        
        return EntropyAnalysisResponse(
            filename=result.filename,
            file_size=result.file_size,
            overall_entropy=result.overall_entropy,
            entropy_data=[
                EntropyDataPointResponse(
                    offset=p.offset,
                    entropy=p.entropy,
                    size=p.size
                )
                for p in result.entropy_data
            ],
            regions=[
                EntropyRegionResponse(
                    start_offset=r.start_offset,
                    end_offset=r.end_offset,
                    avg_entropy=r.avg_entropy,
                    max_entropy=r.max_entropy,
                    min_entropy=r.min_entropy,
                    classification=r.classification,
                    section_name=r.section_name,
                    description=r.description
                )
                for r in result.regions
            ],
            is_likely_packed=result.is_likely_packed,
            packing_confidence=result.packing_confidence,
            detected_packers=result.detected_packers,
            section_entropy=result.section_entropy,
            analysis_notes=result.analysis_notes,
            window_size=result.window_size,
            step_size=result.step_size
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Entropy analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Entropy analysis failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
# APK Report Export Endpoints
# ============================================================================

@router.post("/apk/export")
async def export_apk_report(
    file: UploadFile = File(...),
    format: str = Query(..., description="Export format: markdown, pdf, docx"),
    report_type: str = Query("both", description="Report type: functionality, security, both"),
):
    """
    Analyze an APK and export the report to Markdown, PDF, or Word format.
    
    - **format**: Export format (markdown, pdf, docx)
    - **report_type**: Which report to generate (functionality, security, both)
    """
    from fastapi.responses import Response
    
    if format not in ["markdown", "pdf", "docx"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use: markdown, pdf, docx")
    
    if report_type not in ["functionality", "security", "both"]:
        raise HTTPException(status_code=400, detail="Invalid report_type. Use: functionality, security, both")
    
    # Validate file
    filename = file.filename or "unknown.apk"
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_APK_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_APK_EXTENSIONS)}"
        )
    
    tmp_dir = None
    try:
        # Save uploaded file
        tmp_dir = tempfile.mkdtemp()
        tmp_path = Path(tmp_dir) / filename
        
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail=f"File too large. Max: {MAX_FILE_SIZE // (1024*1024)}MB")
        
        with open(tmp_path, "wb") as f:
            f.write(content)
        
        # Analyze APK
        result = await re_service.analyze_apk(tmp_path)
        
        # Generate AI reports if Gemini is available
        await re_service.analyze_apk_with_ai(result)
        
        # Generate export based on format
        base_filename = Path(filename).stem
        
        if format == "markdown":
            markdown_content = re_service.generate_apk_markdown_report(result, report_type)
            return Response(
                content=markdown_content.encode('utf-8'),
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="{base_filename}_report.md"'}
            )
        
        elif format == "pdf":
            pdf_bytes = re_service.generate_apk_pdf_report(result, report_type)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{base_filename}_report.pdf"'}
            )
        
        elif format == "docx":
            docx_bytes = re_service.generate_apk_docx_report(result, report_type)
            return Response(
                content=docx_bytes,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f'attachment; filename="{base_filename}_report.docx"'}
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"APK export failed: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/apk/export-from-result")
async def export_apk_report_from_result(
    result_data: Dict[str, Any],
    format: str = Query(..., description="Export format: markdown, pdf, docx"),
    report_type: str = Query("both", description="Report type: functionality, security, both"),
):
    """
    Export an existing APK analysis result to Markdown, PDF, or Word format.
    
    Use this when you already have analysis results and don't want to re-analyze.
    """
    from fastapi.responses import Response
    
    if format not in ["markdown", "pdf", "docx"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use: markdown, pdf, docx")
    
    if report_type not in ["functionality", "security", "both"]:
        raise HTTPException(status_code=400, detail="Invalid report_type. Use: functionality, security, both")
    
    try:
        # Reconstruct ApkAnalysisResult from dict
        from dataclasses import fields
        
        # Create permission objects
        permissions = []
        for p in result_data.get('permissions', []):
            permissions.append(re_service.ApkPermission(
                name=p.get('name', ''),
                description=p.get('description'),
                is_dangerous=p.get('is_dangerous', False),
                protection_level=p.get('protection_level')
            ))
        
        # Create certificate object if present
        certificate = None
        if result_data.get('certificate'):
            cert_data = result_data['certificate']
            certificate = re_service.ApkCertificate(
                subject=cert_data.get('subject', ''),
                issuer=cert_data.get('issuer', ''),
                fingerprint_sha256=cert_data.get('fingerprint_sha256', ''),
                fingerprint_sha1=cert_data.get('fingerprint_sha1'),
                fingerprint_md5=cert_data.get('fingerprint_md5'),
                serial_number=cert_data.get('serial_number'),
                valid_from=cert_data.get('valid_from'),
                valid_until=cert_data.get('valid_until'),
                is_debug_cert=cert_data.get('is_debug_cert', False),
                is_expired=cert_data.get('is_expired', False),
                is_self_signed=cert_data.get('is_self_signed', False),
                signature_version=cert_data.get('signature_version', 'v1'),
                public_key_algorithm=cert_data.get('public_key_algorithm'),
                public_key_bits=cert_data.get('public_key_bits')
            )
        
        # Create result object
        result = re_service.ApkAnalysisResult(
            filename=result_data.get('filename', 'unknown.apk'),
            package_name=result_data.get('package_name', ''),
            version_name=result_data.get('version_name'),
            version_code=result_data.get('version_code'),
            min_sdk=result_data.get('min_sdk'),
            target_sdk=result_data.get('target_sdk'),
            permissions=permissions,
            components=[],  # Simplified for export
            strings=[],  # Simplified for export
            secrets=result_data.get('secrets', []),
            urls=result_data.get('urls', []),
            native_libraries=result_data.get('native_libraries', []),
            certificate=certificate,
            activities=result_data.get('activities', []),
            services=result_data.get('services', []),
            receivers=result_data.get('receivers', []),
            providers=result_data.get('providers', []),
            uses_features=result_data.get('uses_features', []),
            app_name=result_data.get('app_name'),
            debuggable=result_data.get('debuggable', False),
            allow_backup=result_data.get('allow_backup', True),
            security_issues=result_data.get('security_issues', []),
            ai_analysis=result_data.get('ai_analysis'),
            ai_report_functionality=result_data.get('ai_report_functionality'),
            ai_report_security=result_data.get('ai_report_security'),
            hardening_score=result_data.get('hardening_score'),
        )
        
        # Get decompiled code findings if present
        decompiled_findings = result_data.get('decompiled_code_findings', [])
        
        # Generate export based on format
        package_name = result.package_name.split('.')[-1] if result.package_name else 'apk'
        
        if format == "markdown":
            markdown_content = re_service.generate_apk_markdown_report(result, report_type, decompiled_findings)
            return Response(
                content=markdown_content.encode('utf-8'),
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="{package_name}_report.md"'}
            )
        
        elif format == "pdf":
            pdf_bytes = re_service.generate_apk_pdf_report(result, report_type, decompiled_findings)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{package_name}_report.pdf"'}
            )
        
        elif format == "docx":
            docx_bytes = re_service.generate_apk_docx_report(result, report_type, decompiled_findings)
            return Response(
                content=docx_bytes,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f'attachment; filename="{package_name}_report.docx"'}
            )
    
    except Exception as e:
        logger.error(f"APK export from result failed: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

# ============================================================================
# AI Chat Export Endpoints
# ============================================================================

class ChatExportRequest(BaseModel):
    """Request for exporting chat history."""
    messages: List[ApkChatMessage]
    analysis_context: Dict[str, Any]
    format: str = "markdown"  # "markdown", "json", "pdf"


class ChatExportResponse(BaseModel):
    """Response for chat export."""
    filename: str
    content_type: str


@router.post("/apk/chat/export")
async def export_apk_chat(request: ChatExportRequest):
    """
    Export APK AI chat conversation to various formats.
    
    Supported formats:
    - markdown: Readable markdown format with conversation
    - json: Raw JSON export of messages and context
    - pdf: Formatted PDF document
    """
    from fastapi.responses import Response
    import json
    
    if not request.messages:
        raise HTTPException(status_code=400, detail="No messages to export")
    
    package_name = request.analysis_context.get('package_name', 'unknown')
    app_name = package_name.split('.')[-1] if package_name else 'apk'
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if request.format == "markdown":
        # Generate markdown chat export
        md_lines = [
            f"# APK Analysis Chat Export",
            f"",
            f"**Package:** {package_name}",
            f"**Exported:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Messages:** {len(request.messages)}",
            f"",
            f"---",
            f"",
            f"## Conversation",
            f"",
        ]
        
        for msg in request.messages:
            role_label = "**You:**" if msg.role == "user" else "**AI Assistant:**"
            timestamp_str = ""
            if msg.timestamp:
                ts = msg.timestamp if isinstance(msg.timestamp, datetime) else datetime.fromisoformat(str(msg.timestamp).replace('Z', '+00:00'))
                timestamp_str = f" *({ts.strftime('%H:%M:%S')})*"
            
            md_lines.append(f"### {role_label}{timestamp_str}")
            md_lines.append(f"")
            md_lines.append(msg.content)
            md_lines.append(f"")
            md_lines.append(f"---")
            md_lines.append(f"")
        
        # Add context summary
        md_lines.extend([
            f"## Analysis Context Summary",
            f"",
            f"- **Permissions:** {len(request.analysis_context.get('permissions', []))}",
            f"- **Security Issues:** {len(request.analysis_context.get('security_issues', []))}",
            f"- **Activities:** {len(request.analysis_context.get('activities', []))}",
            f"- **Services:** {len(request.analysis_context.get('services', []))}",
        ])
        
        content = "\n".join(md_lines)
        return Response(
            content=content.encode('utf-8'),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{app_name}_chat_{timestamp}.md"'}
        )
    
    elif request.format == "json":
        # JSON export
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "package_name": package_name,
            "messages": [
                {
                    "role": msg.role,
                    "content": msg.content,
                    "timestamp": msg.timestamp.isoformat() if msg.timestamp else None
                }
                for msg in request.messages
            ],
            "analysis_summary": {
                "permissions_count": len(request.analysis_context.get('permissions', [])),
                "security_issues_count": len(request.analysis_context.get('security_issues', [])),
                "dangerous_permissions": [
                    p.get('name') for p in request.analysis_context.get('permissions', [])
                    if p.get('is_dangerous')
                ],
            }
        }
        
        content = json.dumps(export_data, indent=2)
        return Response(
            content=content.encode('utf-8'),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{app_name}_chat_{timestamp}.json"'}
        )
    
    elif request.format == "pdf":
        # PDF export using reportlab
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_LEFT
            import io
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
            
            styles = getSampleStyleSheet()
            title_style = styles['Heading1']
            heading_style = styles['Heading2']
            
            user_style = ParagraphStyle(
                'UserMessage',
                parent=styles['Normal'],
                backColor=colors.Color(0.9, 0.95, 1.0),
                borderPadding=8,
                leftIndent=20,
                rightIndent=20,
            )
            
            ai_style = ParagraphStyle(
                'AIMessage',
                parent=styles['Normal'],
                backColor=colors.Color(0.95, 0.95, 0.95),
                borderPadding=8,
                leftIndent=20,
                rightIndent=20,
            )
            
            elements = []
            
            # Title
            elements.append(Paragraph("APK Analysis Chat Export", title_style))
            elements.append(Spacer(1, 12))
            
            # Metadata
            elements.append(Paragraph(f"<b>Package:</b> {package_name}", styles['Normal']))
            elements.append(Paragraph(f"<b>Exported:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            elements.append(Paragraph(f"<b>Messages:</b> {len(request.messages)}", styles['Normal']))
            elements.append(Spacer(1, 20))
            
            # Messages
            elements.append(Paragraph("Conversation", heading_style))
            elements.append(Spacer(1, 12))
            
            for msg in request.messages:
                style = user_style if msg.role == "user" else ai_style
                role_label = "You" if msg.role == "user" else "AI Assistant"
                
                # Escape HTML characters
                safe_content = msg.content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                safe_content = safe_content.replace('\n', '<br/>')
                
                elements.append(Paragraph(f"<b>{role_label}:</b>", styles['Normal']))
                elements.append(Paragraph(safe_content, style))
                elements.append(Spacer(1, 12))
            
            doc.build(elements)
            
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{app_name}_chat_{timestamp}.pdf"'}
            )
            
        except ImportError:
            raise HTTPException(status_code=503, detail="PDF export requires reportlab library")
    
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}. Use markdown, json, or pdf.")


# ============================================================================
# AI-Assisted Code Explanation Endpoints
# ============================================================================

class CodeExplanationRequest(BaseModel):
    """Request for AI code explanation."""
    source_code: str
    class_name: str
    language: str = "java"  # java, smali, kotlin
    focus_area: Optional[str] = None  # "security", "functionality", "data_flow", None for general
    beginner_mode: bool = False


class CodeExplanationResponse(BaseModel):
    """Response with AI code explanation."""
    summary: str
    detailed_explanation: str
    security_concerns: List[Dict[str, Any]]
    interesting_findings: List[str]
    data_flow_analysis: Optional[str] = None
    suggested_focus_points: List[str]
    code_quality_notes: List[str]


@router.post("/apk/code/explain", response_model=CodeExplanationResponse)
async def explain_decompiled_code(request: CodeExplanationRequest):
    """
    AI-powered explanation of decompiled code.
    
    Analyzes decompiled Java/Smali code and provides:
    - Natural language explanation of what the code does
    - Security vulnerability analysis
    - Data flow tracking
    - Interesting patterns and behaviors
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="AI features require Gemini API key")
    
    if not request.source_code.strip():
        raise HTTPException(status_code=400, detail="No source code provided")
    
    # Limit code size to prevent token overflow
    max_code_length = 15000
    code_to_analyze = request.source_code[:max_code_length]
    if len(request.source_code) > max_code_length:
        code_to_analyze += "\n\n// ... (code truncated for analysis)"
    
    try:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        focus_prompt = ""
        if request.focus_area == "security":
            focus_prompt = """
Focus particularly on:
- Input validation and sanitization
- Authentication/authorization checks
- Cryptographic implementations
- Data leakage possibilities
- Injection vulnerabilities
- Insecure storage patterns
- Network security issues
"""
        elif request.focus_area == "functionality":
            focus_prompt = """
Focus particularly on:
- Main purpose and functionality
- User-facing features
- Data processing logic
- External integrations
- State management
"""
        elif request.focus_area == "data_flow":
            focus_prompt = """
Focus particularly on:
- Data sources and sinks
- Sensitive data handling
- Data transformations
- Storage locations
- Network transmissions
- Inter-component communication
"""
        
        beginner_note = """
Explain concepts simply using analogies. Define technical terms when you use them.
Assume the reader knows basic programming but not Android security.""" if request.beginner_mode else ""
        
        prompt = f"""You are an expert Android security researcher and code analyst.
Analyze this decompiled {request.language.upper()} code from class '{request.class_name}'.
{focus_prompt}
{beginner_note}

Provide your analysis in this JSON format:
{{
    "summary": "2-3 sentence summary of what this code does",
    "detailed_explanation": "Detailed explanation of the code's functionality, structure, and purpose",
    "security_concerns": [
        {{
            "severity": "critical|high|medium|low",
            "issue": "Description of the security issue",
            "location": "Method or line reference",
            "recommendation": "How to fix or exploit"
        }}
    ],
    "interesting_findings": ["List of interesting behaviors, patterns, or features"],
    "data_flow_analysis": "How data moves through this code (if applicable)",
    "suggested_focus_points": ["Areas worth investigating further"],
    "code_quality_notes": ["Observations about code quality, obfuscation, etc."]
}}

CODE TO ANALYZE:
```{request.language}
{code_to_analyze}
```

Return ONLY valid JSON, no other text."""

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=[types.Content(role="user", parts=[types.Part(text=prompt)])],
        )
        
        # Parse JSON response
        import json
        response_text = response.text.strip()
        
        # Clean up potential markdown code blocks
        if response_text.startswith("```"):
            lines = response_text.split('\n')
            response_text = '\n'.join(lines[1:-1] if lines[-1].strip() == '```' else lines[1:])
        
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                result = json.loads(json_match.group())
            else:
                # Return a basic response if parsing fails
                result = {
                    "summary": "Code analysis completed but response parsing failed.",
                    "detailed_explanation": response_text,
                    "security_concerns": [],
                    "interesting_findings": [],
                    "data_flow_analysis": None,
                    "suggested_focus_points": ["Review the raw analysis above"],
                    "code_quality_notes": []
                }
        
        return CodeExplanationResponse(
            summary=result.get("summary", ""),
            detailed_explanation=result.get("detailed_explanation", ""),
            security_concerns=result.get("security_concerns", []),
            interesting_findings=result.get("interesting_findings", []),
            data_flow_analysis=result.get("data_flow_analysis"),
            suggested_focus_points=result.get("suggested_focus_points", []),
            code_quality_notes=result.get("code_quality_notes", [])
        )
        
    except Exception as e:
        logger.error(f"Code explanation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Code explanation failed: {str(e)}")


class CodeSearchAIRequest(BaseModel):
    """Request for AI-powered code search."""
    session_id: str
    query: str  # Natural language query like "find where API keys are stored"
    max_results: int = 20


class CodeSearchAIResponse(BaseModel):
    """Response for AI code search."""
    query: str
    interpreted_as: str  # How the AI interpreted the query
    search_patterns: List[str]  # Patterns used to search
    results: List[Dict[str, Any]]
    suggestions: List[str]  # Follow-up search suggestions


@router.post("/apk/code/search-ai", response_model=CodeSearchAIResponse)
async def ai_code_search(request: CodeSearchAIRequest):
    """
    AI-powered semantic code search in decompiled sources.
    
    Understands natural language queries like:
    - "Find where user passwords are handled"
    - "Show me network request code"
    - "Where is sensitive data stored"
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="AI features require Gemini API key")
    
    if request.session_id not in _jadx_cache:
        raise HTTPException(status_code=404, detail="Decompilation session not found. Please decompile the APK first.")
    
    output_dir = _jadx_cache[request.session_id]
    
    try:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # First, use AI to understand the query and generate search patterns
        interpret_prompt = f"""You are an Android security researcher.
A user wants to search decompiled Java code for: "{request.query}"

Generate search patterns (regex-compatible strings) that would help find relevant code.
Think about:
- API method names that would be called
- Class names that might be involved
- Variable/field names commonly used
- String literals that might appear
- Android framework classes involved

Return JSON:
{{
    "interpretation": "What the user is looking for in plain English",
    "patterns": ["pattern1", "pattern2", ...],  // Up to 10 patterns
    "follow_up_suggestions": ["Other related things to search for"]
}}

Return ONLY valid JSON."""

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=[types.Content(role="user", parts=[types.Part(text=interpret_prompt)])],
        )
        
        import json
        response_text = response.text.strip()
        if response_text.startswith("```"):
            lines = response_text.split('\n')
            response_text = '\n'.join(lines[1:-1] if lines[-1].strip() == '```' else lines[1:])
        
        try:
            ai_interpretation = json.loads(response_text)
        except json.JSONDecodeError:
            ai_interpretation = {
                "interpretation": request.query,
                "patterns": [request.query],
                "follow_up_suggestions": []
            }
        
        # Search for each pattern
        results = []
        sources_dir = output_dir / "sources"
        
        if sources_dir.exists():
            for pattern in ai_interpretation.get("patterns", [])[:10]:
                for java_file in sources_dir.rglob("*.java"):
                    try:
                        content = java_file.read_text(encoding='utf-8', errors='ignore')
                        if pattern.lower() in content.lower():
                            # Find matching lines
                            lines = content.split('\n')
                            for line_num, line in enumerate(lines, 1):
                                if pattern.lower() in line.lower():
                                    results.append({
                                        "file_path": str(java_file.relative_to(sources_dir)),
                                        "line_number": line_num,
                                        "line_content": line.strip()[:200],
                                        "matched_pattern": pattern,
                                    })
                                    if len(results) >= request.max_results:
                                        break
                    except Exception:
                        continue
                    
                    if len(results) >= request.max_results:
                        break
                
                if len(results) >= request.max_results:
                    break
        
        return CodeSearchAIResponse(
            query=request.query,
            interpreted_as=ai_interpretation.get("interpretation", request.query),
            search_patterns=ai_interpretation.get("patterns", []),
            results=results[:request.max_results],
            suggestions=ai_interpretation.get("follow_up_suggestions", [])
        )
        
    except Exception as e:
        logger.error(f"AI code search failed: {e}")
        raise HTTPException(status_code=500, detail=f"AI code search failed: {str(e)}")


# ============================================================================
# Crypto Audit Endpoints
# ============================================================================

class CryptoFinding(BaseModel):
    """A cryptographic vulnerability finding."""
    type: str
    category: str
    severity: str
    description: str
    recommendation: str
    file: str
    line: int
    match: str
    context: Optional[str] = None


class CryptoGoodPractice(BaseModel):
    """A good cryptographic practice found."""
    type: str
    file: str
    line: int
    match: str


class CryptoMethod(BaseModel):
    """A cryptographic method usage."""
    type: str
    algorithm: str
    file: str
    line: int


class CryptoAuditRequest(BaseModel):
    """Request for crypto audit."""
    output_directory: str


class CryptoAuditResponse(BaseModel):
    """Response with crypto audit results."""
    total_findings: int
    findings: List[CryptoFinding]
    by_severity: Dict[str, List[CryptoFinding]]
    by_category: Dict[str, List[CryptoFinding]]
    good_practices: List[CryptoGoodPractice]
    crypto_methods: List[CryptoMethod]
    files_scanned: int
    risk_score: int
    grade: str
    overall_risk: str
    top_recommendations: List[str]
    summary: str
    error: Optional[str] = None


@router.post("/apk/decompile/crypto-audit", response_model=CryptoAuditResponse)
async def crypto_audit(request: CryptoAuditRequest):
    """
    Perform comprehensive cryptographic audit on decompiled APK sources.
    
    Detects:
    - Weak algorithms (MD5, SHA1, DES, 3DES, RC4)
    - ECB mode usage (insecure)
    - Hardcoded keys and IVs
    - Static/null IVs
    - Insecure random (java.util.Random)
    - RSA without OAEP padding
    - Weak PBKDF iterations
    - Certificate validation bypass
    
    Returns risk score, grade (A-F), and actionable recommendations.
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.crypto_audit(output_dir)
        
        if "error" in result:
            return CryptoAuditResponse(
                total_findings=0,
                findings=[],
                by_severity={},
                by_category={},
                good_practices=[],
                crypto_methods=[],
                files_scanned=0,
                risk_score=0,
                grade="?",
                overall_risk="unknown",
                top_recommendations=[],
                summary="",
                error=result["error"]
            )
        
        return CryptoAuditResponse(
            total_findings=result["total_findings"],
            findings=[CryptoFinding(**f) for f in result["findings"]],
            by_severity={k: [CryptoFinding(**f) for f in v] for k, v in result["by_severity"].items()},
            by_category={k: [CryptoFinding(**f) for f in v] for k, v in result["by_category"].items()},
            good_practices=[CryptoGoodPractice(**p) for p in result["good_practices"]],
            crypto_methods=[CryptoMethod(**m) for m in result["crypto_methods"]],
            files_scanned=result["files_scanned"],
            risk_score=result["risk_score"],
            grade=result["grade"],
            overall_risk=result["overall_risk"],
            top_recommendations=result["top_recommendations"],
            summary=result["summary"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Crypto audit failed: {e}")
        raise HTTPException(status_code=500, detail=f"Crypto audit failed: {str(e)}")


# ============================================================================
# Component Map Endpoints
# ============================================================================

class ComponentInfo(BaseModel):
    """Information about an Android component."""
    name: str
    full_name: str
    exported: bool
    risk: str


class ActivityInfo(ComponentInfo):
    """Activity component info."""
    launcher: bool = False
    actions: List[str] = []
    categories: List[str] = []
    data_schemes: List[str] = []
    theme: Optional[str] = None
    launch_mode: str = "standard"


class ServiceInfo(ComponentInfo):
    """Service component info."""
    actions: List[str] = []
    permission: Optional[str] = None
    foreground: bool = False


class ReceiverInfo(ComponentInfo):
    """Receiver component info."""
    actions: List[str] = []
    permission: Optional[str] = None
    system_broadcast: bool = False


class ProviderInfo(ComponentInfo):
    """Provider component info."""
    authorities: Optional[str] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    grant_uri_permissions: bool = False


class DeepLinkInfo(BaseModel):
    """Deep link info."""
    scheme: str
    host: Optional[str] = None
    path: Optional[str] = None
    component: str
    component_full: str
    type: str


class ConnectionInfo(BaseModel):
    """Component connection info."""
    source: str
    target: str
    type: str


class ComponentMapRequest(BaseModel):
    """Request for component map."""
    output_directory: str


class ComponentMapResponse(BaseModel):
    """Response with component map data."""
    package_name: str
    components: Dict[str, Any]  # activities, services, receivers, providers
    connections: List[ConnectionInfo]
    deep_links: List[DeepLinkInfo]
    stats: Dict[str, int]
    risk_counts: Dict[str, int]
    attack_surface_score: int
    summary: str
    error: Optional[str] = None


@router.post("/apk/decompile/component-map", response_model=ComponentMapResponse)
async def get_component_map(request: ComponentMapRequest):
    """
    Generate visual component map showing activities, services, receivers,
    providers and their relationships.
    
    Returns:
    - All components with export status and risk levels
    - Deep links with schemes and hosts
    - Inter-component connections (intents)
    - Attack surface score
    - Statistics and risk breakdown
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.generate_component_map(output_dir)
        
        if "error" in result:
            return ComponentMapResponse(
                package_name="",
                components={},
                connections=[],
                deep_links=[],
                stats={},
                risk_counts={},
                attack_surface_score=0,
                summary="",
                error=result["error"]
            )
        
        return ComponentMapResponse(
            package_name=result["package_name"],
            components=result["components"],
            connections=[ConnectionInfo(**c) for c in result["connections"]],
            deep_links=[DeepLinkInfo(**d) for d in result["deep_links"]],
            stats=result["stats"],
            risk_counts=result["risk_counts"],
            attack_surface_score=result["attack_surface_score"],
            summary=result["summary"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Component map generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Component map generation failed: {str(e)}")


# ============================================================================
# Class Dependency Graph Endpoint
# ============================================================================

class GraphNode(BaseModel):
    """A node in the dependency graph."""
    id: str
    label: str
    full_name: str
    package: str
    type: str
    color: str
    size: int
    methods: int
    lines: int
    file_path: str


class GraphEdge(BaseModel):
    """An edge in the dependency graph."""
    from_: str = Field(..., alias="from")
    to: str
    type: str
    color: str
    dashes: Optional[Any] = None
    width: Optional[int] = None
    
    class Config:
        populate_by_name = True


class GraphStatistics(BaseModel):
    """Statistics about the dependency graph."""
    total_classes: int
    total_connections: int
    node_types: Dict[str, int]
    edge_types: Dict[str, int]
    packages: Dict[str, int]
    hub_classes: List[Dict[str, Any]]


class DependencyGraphRequest(BaseModel):
    """Request for class dependency graph."""
    output_directory: str
    max_classes: Optional[int] = 100


class DependencyGraphResponse(BaseModel):
    """Response with dependency graph data."""
    nodes: List[GraphNode]
    edges: List[Dict[str, Any]]  # Use Dict to avoid alias issues
    statistics: GraphStatistics
    legend: Dict[str, Dict[str, str]]
    error: Optional[str] = None


@router.post("/apk/decompile/dependency-graph")
async def get_dependency_graph(request: DependencyGraphRequest):
    """
    Generate a class dependency graph showing how classes are interconnected.
    
    Analyzes:
    - Import statements (which classes depend on which)
    - Inheritance (extends relationships)
    - Interface implementation (implements)
    - Method calls between classes
    
    Returns graph data suitable for visualization with nodes and edges.
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.generate_class_dependency_graph(
            output_dir, 
            max_classes=request.max_classes or 100
        )
        
        if "error" in result:
            return {"error": result["error"]}
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dependency graph generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Dependency graph generation failed: {str(e)}")


# ============================================================================
# Symbol Lookup Endpoints (Jump to Definition)
# ============================================================================

class SymbolResult(BaseModel):
    """A symbol lookup result."""
    type: str  # class, method, field
    name: str
    file: str
    line: int
    # Optional fields depending on type
    package: Optional[str] = None
    full_name: Optional[str] = None
    class_name: Optional[str] = Field(None, alias="class")
    signature: Optional[str] = None
    return_type: Optional[str] = None
    params: Optional[str] = None
    field_type: Optional[str] = None
    
    class Config:
        populate_by_name = True


class SymbolLookupRequest(BaseModel):
    """Request for symbol lookup."""
    output_directory: str
    symbol: str
    symbol_type: Optional[str] = None  # class, method, field, or None for all


class SymbolLookupResponse(BaseModel):
    """Response with symbol lookup results."""
    symbol: str
    results: List[SymbolResult]
    total_found: int
    index_stats: Dict[str, int]
    error: Optional[str] = None


@router.post("/apk/decompile/symbol-lookup", response_model=SymbolLookupResponse)
async def lookup_symbol(request: SymbolLookupRequest):
    """
    Look up a symbol (class, method, or field) and return its definition location.
    
    Enables jump-to-definition functionality in the source viewer.
    
    Args:
        symbol: Name to search for (supports partial matching)
        symbol_type: Filter by type (class/method/field) or None for all
    
    Returns file paths and line numbers for navigation.
    """
    try:
        output_dir = _resolve_jadx_output_dir(request.output_directory)
        
        result = re_service.lookup_symbol(output_dir, request.symbol, request.symbol_type)
        
        if "error" in result:
            return SymbolLookupResponse(
                symbol=request.symbol,
                results=[],
                total_found=0,
                index_stats={},
                error=result["error"]
            )
        
        return SymbolLookupResponse(
            symbol=result["symbol"],
            results=[SymbolResult(**r) for r in result["results"]],
            total_found=result["total_found"],
            index_stats=result["index_stats"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Symbol lookup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Symbol lookup failed: {str(e)}")


# ============================================================================
# Enhanced Security Export
# ============================================================================

class ExportEnhancedSecurityRequest(BaseModel):
    """Request to export enhanced security results."""
    results: Dict[str, Any]
    format: str = "markdown"  # markdown, pdf, docx
    include_code_snippets: bool = True
    include_attack_chains: bool = True


@router.post("/apk/decompile/enhanced-security/export")
async def export_enhanced_security(request: ExportEnhancedSecurityRequest):
    """
    Export enhanced security analysis results to Markdown, PDF, or Word format.
    
    Args:
        results: The enhanced security results to export
        format: Export format (markdown, pdf, docx)
        include_code_snippets: Include code snippets in the export
        include_attack_chains: Include attack chain analysis
    
    Returns the exported document as a downloadable file.
    """
    from fastapi.responses import Response
    from io import BytesIO
    from datetime import datetime
    
    if request.format not in ["markdown", "pdf", "docx"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use: markdown, pdf, docx")
    
    try:
        results = request.results
        
        # Generate Markdown content
        md_lines = [
            "# Comprehensive Security Analysis Report",
            f"",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            "---",
            "",
            "## Executive Summary",
            "",
            f"**Overall Risk Level:** {results.get('overall_risk', 'unknown').upper()}",
            "",
            results.get('executive_summary', 'No executive summary available.'),
            "",
            "---",
            "",
            "## Risk Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        
        risk_summary = results.get('risk_summary', {})
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = risk_summary.get(severity, 0)
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}.get(severity, '')
            md_lines.append(f"| {emoji} {severity.capitalize()} | {count} |")
        
        md_lines.extend(["", "---", "", "## Analysis Metadata", ""])
        
        metadata = results.get('analysis_metadata', {})
        md_lines.extend([
            f"- **Classes Scanned:** {metadata.get('classes_scanned', 0)}",
            f"- **Libraries Detected:** {metadata.get('libraries_detected', 0)}",
            f"- **CVEs Found:** {metadata.get('cves_found', 0)}",
            f"- **Pattern Scan:** {'✅ Enabled' if metadata.get('pattern_scan_enabled') else '❌ Disabled'}",
            f"- **AI Scan:** {'✅ Enabled' if metadata.get('ai_scan_enabled') else '❌ Disabled'}",
            f"- **CVE Lookup:** {'✅ Enabled' if metadata.get('cve_lookup_enabled') else '❌ Disabled'}",
            "",
            "---",
            "",
        ])
        
        # Combined Findings
        combined_findings = results.get('combined_findings', [])
        if combined_findings:
            md_lines.extend([
                "## Security Findings",
                "",
                f"Total: **{len(combined_findings)}** findings",
                "",
            ])
            
            # Group by severity
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                severity_findings = [f for f in combined_findings if f.get('severity', '').lower() == severity]
                if severity_findings:
                    md_lines.extend([
                        f"### {severity.upper()} Severity ({len(severity_findings)})",
                        "",
                    ])
                    
                    for i, finding in enumerate(severity_findings, 1):
                        source_badge = f"[{finding.get('source', 'unknown').upper()}]"
                        md_lines.extend([
                            f"#### {i}. {finding.get('title', 'Unknown Issue')} {source_badge}",
                            "",
                            f"**Description:** {finding.get('description', 'No description')}",
                            "",
                        ])
                        
                        if finding.get('affected_class'):
                            location = finding.get('affected_class')
                            if finding.get('affected_method'):
                                location += f" → {finding.get('affected_method')}"
                            if finding.get('line_number'):
                                location += f" (line {finding.get('line_number')})"
                            md_lines.append(f"**Location:** `{location}`")
                            md_lines.append("")
                        
                        if finding.get('affected_library'):
                            md_lines.append(f"**Library:** {finding.get('affected_library')}")
                            md_lines.append("")
                        
                        if finding.get('cve_id'):
                            md_lines.append(f"**CVE:** {finding.get('cve_id')}")
                            md_lines.append("")
                        
                        if finding.get('cwe_id'):
                            md_lines.append(f"**CWE:** {finding.get('cwe_id')}")
                            md_lines.append("")
                        
                        if finding.get('cvss_score'):
                            md_lines.append(f"**CVSS Score:** {finding.get('cvss_score')}")
                            md_lines.append("")
                        
                        if finding.get('impact'):
                            md_lines.append(f"**Impact:** {finding.get('impact')}")
                            md_lines.append("")
                        
                        if finding.get('exploitation_potential'):
                            md_lines.append(f"**Exploitation Potential:** {finding.get('exploitation_potential')}")
                            md_lines.append("")
                        
                        if finding.get('attack_vector'):
                            md_lines.append(f"**Attack Vector:** {finding.get('attack_vector')}")
                            md_lines.append("")
                        
                        if request.include_code_snippets and finding.get('code_snippet'):
                            md_lines.extend([
                                "**Code:**",
                                "```java",
                                finding.get('code_snippet'),
                                "```",
                                "",
                            ])
                        
                        if finding.get('remediation'):
                            md_lines.extend([
                                "**Remediation:**",
                                f"> {finding.get('remediation')}",
                                "",
                            ])
                        
                        md_lines.append("---")
                        md_lines.append("")
        
        # Attack Chains
        if request.include_attack_chains:
            attack_chains = results.get('attack_chains', [])
            if attack_chains:
                md_lines.extend([
                    "## Attack Chain Analysis",
                    "",
                    f"**{len(attack_chains)}** potential attack chains identified:",
                    "",
                ])
                
                for i, chain in enumerate(attack_chains, 1):
                    md_lines.extend([
                        f"### Chain {i}: {chain.get('name', 'Unknown Chain')}",
                        "",
                        f"**Risk Level:** {chain.get('risk_level', 'Unknown')}",
                        "",
                        f"**Description:** {chain.get('description', 'No description')}",
                        "",
                        "**Steps:**",
                    ])
                    
                    for step in chain.get('steps', []):
                        md_lines.append(f"1. {step}")
                    
                    if chain.get('impact'):
                        md_lines.extend(["", f"**Impact:** {chain.get('impact')}"])
                    
                    if chain.get('likelihood'):
                        md_lines.extend(["", f"**Likelihood:** {chain.get('likelihood')}"])
                    
                    md_lines.extend(["", "---", ""])
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            md_lines.extend([
                "## Recommendations",
                "",
            ])
            for rec in recommendations:
                md_lines.append(f"- {rec}")
            md_lines.append("")
        
        # Footer
        md_lines.extend([
            "---",
            "",
            "*Generated by VRAgent Security Analyzer*",
        ])
        
        markdown_content = "\n".join(md_lines)
        
        # Return based on format
        if request.format == "markdown":
            return Response(
                content=markdown_content.encode('utf-8'),
                media_type="text/markdown",
                headers={"Content-Disposition": "attachment; filename=security_analysis_report.md"}
            )
        
        elif request.format == "pdf":
            try:
                from weasyprint import HTML, CSS
                from markdown import markdown
                
                html_content = markdown(markdown_content, extensions=['tables', 'fenced_code'])
                
                styled_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                        h1 {{ color: #1e3a5f; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
                        h2 {{ color: #2c5282; border-bottom: 2px solid #3182ce; padding-bottom: 5px; margin-top: 30px; }}
                        h3 {{ color: #2d3748; margin-top: 20px; }}
                        h4 {{ color: #4a5568; margin-top: 15px; }}
                        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
                        th, td {{ border: 1px solid #e2e8f0; padding: 10px; text-align: left; }}
                        th {{ background-color: #edf2f7; color: #2d3748; }}
                        code {{ background-color: #f7fafc; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; }}
                        pre {{ background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 8px; overflow-x: auto; }}
                        pre code {{ background: none; padding: 0; color: #e2e8f0; }}
                        blockquote {{ border-left: 4px solid #48bb78; padding-left: 15px; margin: 15px 0; color: #2f855a; background: #f0fff4; padding: 10px 15px; }}
                        hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 20px 0; }}
                        ul {{ padding-left: 25px; }}
                        li {{ margin: 5px 0; }}
                    </style>
                </head>
                <body>
                    {html_content}
                </body>
                </html>
                """
                
                pdf_buffer = BytesIO()
                HTML(string=styled_html).write_pdf(pdf_buffer)
                pdf_buffer.seek(0)
                
                return Response(
                    content=pdf_buffer.getvalue(),
                    media_type="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=security_analysis_report.pdf"}
                )
            except ImportError:
                raise HTTPException(status_code=500, detail="PDF export requires weasyprint. Install with: pip install weasyprint")
        
        elif request.format == "docx":
            try:
                from docx import Document
                from docx.shared import Inches, Pt, RGBColor
                from docx.enum.text import WD_ALIGN_PARAGRAPH
                from docx.enum.style import WD_STYLE_TYPE
                
                doc = Document()
                
                # Title
                title = doc.add_heading('Comprehensive Security Analysis Report', 0)
                title.alignment = WD_ALIGN_PARAGRAPH.CENTER
                
                doc.add_paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                doc.add_paragraph()
                
                # Executive Summary
                doc.add_heading('Executive Summary', level=1)
                risk_para = doc.add_paragraph()
                risk_para.add_run(f"Overall Risk Level: ").bold = True
                risk_run = risk_para.add_run(results.get('overall_risk', 'unknown').upper())
                risk_run.bold = True
                risk_color = {'critical': RGBColor(220, 38, 38), 'high': RGBColor(234, 88, 12), 
                             'medium': RGBColor(202, 138, 4), 'low': RGBColor(22, 163, 74)}.get(
                    results.get('overall_risk', '').lower(), RGBColor(107, 114, 128))
                risk_run.font.color.rgb = risk_color
                
                doc.add_paragraph(results.get('executive_summary', 'No executive summary available.'))
                
                # Risk Summary Table
                doc.add_heading('Risk Summary', level=1)
                table = doc.add_table(rows=1, cols=2)
                table.style = 'Table Grid'
                hdr_cells = table.rows[0].cells
                hdr_cells[0].text = 'Severity'
                hdr_cells[1].text = 'Count'
                
                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    row_cells = table.add_row().cells
                    row_cells[0].text = severity.capitalize()
                    row_cells[1].text = str(risk_summary.get(severity, 0))
                
                # Metadata
                doc.add_heading('Analysis Metadata', level=1)
                doc.add_paragraph(f"Classes Scanned: {metadata.get('classes_scanned', 0)}")
                doc.add_paragraph(f"Libraries Detected: {metadata.get('libraries_detected', 0)}")
                doc.add_paragraph(f"CVEs Found: {metadata.get('cves_found', 0)}")
                
                # Findings
                if combined_findings:
                    doc.add_heading('Security Findings', level=1)
                    doc.add_paragraph(f"Total: {len(combined_findings)} findings")
                    
                    for severity in ['critical', 'high', 'medium', 'low', 'info']:
                        severity_findings = [f for f in combined_findings if f.get('severity', '').lower() == severity]
                        if severity_findings:
                            doc.add_heading(f'{severity.upper()} Severity ({len(severity_findings)})', level=2)
                            
                            for finding in severity_findings:
                                p = doc.add_paragraph()
                                p.add_run(f"{finding.get('title', 'Unknown')} ").bold = True
                                p.add_run(f"[{finding.get('source', 'unknown').upper()}]")
                                
                                doc.add_paragraph(finding.get('description', 'No description'))
                                
                                if finding.get('affected_class'):
                                    doc.add_paragraph(f"Location: {finding.get('affected_class')}")
                                
                                if finding.get('remediation'):
                                    rem_para = doc.add_paragraph()
                                    rem_para.add_run("Remediation: ").bold = True
                                    rem_para.add_run(finding.get('remediation'))
                                
                                doc.add_paragraph()  # Spacing
                
                # Recommendations
                if recommendations:
                    doc.add_heading('Recommendations', level=1)
                    for rec in recommendations:
                        doc.add_paragraph(rec, style='List Bullet')
                
                # Save to buffer
                docx_buffer = BytesIO()
                doc.save(docx_buffer)
                docx_buffer.seek(0)
                
                return Response(
                    content=docx_buffer.getvalue(),
                    media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": "attachment; filename=security_analysis_report.docx"}
                )
            except ImportError:
                raise HTTPException(status_code=500, detail="DOCX export requires python-docx. Install with: pip install python-docx")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enhanced security export failed: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")
