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

from fastapi import APIRouter, File, HTTPException, UploadFile, Query, Depends
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
    # ELF-specific
    relro: Optional[str] = None
    stack_canary: bool = False
    nx_enabled: bool = False
    pie_enabled: bool = False
    interpreter: Optional[str] = None
    linked_libraries: List[str] = []


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
    ai_analysis: Optional[str] = None
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
    
    return StatusResponse(
        binary_analysis=True,  # Always available (pure Python)
        apk_analysis=True,     # Basic analysis always available
        docker_analysis=docker_available,
        jadx_available=jadx_available,
        docker_available=docker_available,
        message="Reverse engineering tools ready" if docker_available else "Docker not available - Docker analysis disabled",
    )


@router.post("/analyze-binary", response_model=BinaryAnalysisResponse)
async def analyze_binary(
    file: UploadFile = File(..., description="Binary file to analyze (EXE, ELF, DLL, SO)"),
    include_ai: bool = Query(True, description="Include AI-powered analysis"),
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
                # ELF-specific
                relro=result.metadata.relro,
                stack_canary=result.metadata.stack_canary,
                nx_enabled=result.metadata.nx_enabled,
                pie_enabled=result.metadata.pie_enabled,
                interpreter=result.metadata.interpreter,
                linked_libraries=result.metadata.linked_libraries,
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
            ai_analysis=result.ai_analysis,
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


@router.post("/analyze-apk", response_model=ApkAnalysisResponse)
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
        
        # Run AI analysis if requested (includes text analysis and diagrams)
        if include_ai and not result.error:
            result.ai_analysis = await re_service.analyze_apk_with_ai(result)
            # Generate AI-powered Mermaid diagrams with icons
            result.ai_architecture_diagram = await re_service.generate_ai_architecture_diagram(result)
            result.ai_data_flow_diagram = await re_service.generate_ai_data_flow_diagram(result)
        
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
    ai_threat_model: Optional[Dict[str, Any]] = None
    ai_vuln_scan_result: Optional[Dict[str, Any]] = None
    ai_chat_history: Optional[List[Dict[str, Any]]] = None
    
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
    ai_threat_model: Optional[Dict[str, Any]] = None
    ai_vuln_scan_result: Optional[Dict[str, Any]] = None
    ai_chat_history: Optional[List[Dict[str, Any]]] = None
    
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
            ai_threat_model=request.ai_threat_model,
            ai_vuln_scan_result=request.ai_vuln_scan_result,
            ai_chat_history=request.ai_chat_history,
            
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
        ai_threat_model=report.ai_threat_model,
        ai_vuln_scan_result=report.ai_vuln_scan_result,
        ai_chat_history=report.ai_chat_history,
        
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


def _generate_full_report_export(report, format: str):
    """Generate full export content for a saved report."""
    from io import BytesIO
    
    # Build comprehensive markdown content first
    md_content = f"""# {report.title}

**Analysis Type:** {report.analysis_type.upper()}
**Generated:** {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}
**Risk Level:** {report.risk_level or 'Not Assessed'} ({report.risk_score or 0}/100)

---

"""
    
    # Basic Info Section
    if report.analysis_type == 'apk':
        md_content += f"""## 📱 APK Information

| Property | Value |
|----------|-------|
| Package Name | `{report.package_name or 'N/A'}` |
| Version | {report.version_name or 'N/A'} |
| Min SDK | {report.min_sdk or 'N/A'} |
| Target SDK | {report.target_sdk or 'N/A'} |
| Secrets Found | {report.secrets_count or 0} |

"""
    elif report.analysis_type == 'binary':
        md_content += f"""## 🔧 Binary Information

| Property | Value |
|----------|-------|
| File Type | {report.file_type or 'N/A'} |
| Architecture | {report.architecture or 'N/A'} |
| File Size | {report.file_size or 'N/A'} bytes |
| Packed | {report.is_packed or 'Unknown'} |
| Packer | {report.packer_name or 'N/A'} |
| Strings Count | {report.strings_count or 0} |
| Imports Count | {report.imports_count or 0} |
| Exports Count | {report.exports_count or 0} |

"""
    elif report.analysis_type == 'docker':
        md_content += f"""## 🐳 Docker Image Information

| Property | Value |
|----------|-------|
| Image Name | `{report.image_name or 'N/A'}` |
| Image ID | `{report.image_id or 'N/A'}` |
| Total Layers | {report.total_layers or 0} |
| Base Image | {report.base_image or 'N/A'} |
| Secrets Found | {report.secrets_count or 0} |

"""

    # JADX Full Scan Section
    if report.jadx_total_classes:
        md_content += f"""## 🔍 Deep Code Analysis (JADX)

| Metric | Value |
|--------|-------|
| Total Classes | {report.jadx_total_classes:,} |
| Total Files | {report.jadx_total_files:,} |

"""
        if report.jadx_data and report.jadx_data.get('security_issues'):
            md_content += """### JADX Security Issues

"""
            for issue in report.jadx_data.get('security_issues', [])[:20]:
                severity = issue.get('severity', 'info')
                md_content += f"- **[{severity.upper()}]** {issue.get('title', 'Unknown')}: {issue.get('description', '')[:200]}\n"
            md_content += "\n"

    # Permissions Section (APK)
    if report.permissions:
        md_content += """## 🔐 Permissions

"""
        dangerous = [p for p in report.permissions if p.get('is_dangerous')]
        if dangerous:
            md_content += "### ⚠️ Dangerous Permissions\n\n"
            for p in dangerous:
                md_content += f"- **{p.get('name', '')}**: {p.get('description', 'No description')}\n"
            md_content += "\n"
        
        normal = [p for p in report.permissions if not p.get('is_dangerous')]
        if normal:
            md_content += "### Normal Permissions\n\n"
            for p in normal[:10]:  # Limit to 10
                md_content += f"- {p.get('name', '')}\n"
            if len(normal) > 10:
                md_content += f"- *...and {len(normal) - 10} more*\n"
            md_content += "\n"

    # Security Issues Section
    if report.security_issues:
        md_content += """## 🛡️ Security Issues

"""
        for issue in report.security_issues[:30]:
            severity = issue.get('severity', 'info')
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(severity.lower(), '⚪')
            md_content += f"{emoji} **[{severity.upper()}]** {issue.get('title', issue.get('category', 'Unknown'))}\n"
            if issue.get('description'):
                md_content += f"   {issue.get('description')[:300]}\n"
            md_content += "\n"

    # AI Quick Analysis
    if report.ai_analysis_raw:
        md_content += f"""## 🤖 AI Quick Analysis

{report.ai_analysis_raw}

"""

    # AI Functionality Report
    if report.ai_functionality_report:
        md_content += f"""## 📱 AI Functionality Report

{report.ai_functionality_report}

"""

    # AI Security Report
    if report.ai_security_report:
        md_content += f"""## 🔒 AI Security Report

{report.ai_security_report}

"""

    # AI Privacy Report
    if report.ai_privacy_report:
        md_content += f"""## 🔏 AI Privacy Report

{report.ai_privacy_report}

"""

    # AI Vulnerability Scan Results
    if report.ai_vuln_scan_result:
        vuln_data = report.ai_vuln_scan_result
        md_content += f"""## 🎯 AI Cross-Class Vulnerability Scan

**Scan Type:** {vuln_data.get('scan_type', 'N/A')}
**Classes Scanned:** {vuln_data.get('classes_scanned', 0)}
**Overall Risk:** {vuln_data.get('overall_risk', 'N/A')}

### Risk Summary
- Critical: {vuln_data.get('risk_summary', {}).get('critical', 0)}
- High: {vuln_data.get('risk_summary', {}).get('high', 0)}
- Medium: {vuln_data.get('risk_summary', {}).get('medium', 0)}
- Low: {vuln_data.get('risk_summary', {}).get('low', 0)}

"""
        if vuln_data.get('vulnerabilities'):
            md_content += "### Vulnerabilities Found\n\n"
            for vuln in vuln_data.get('vulnerabilities', [])[:20]:
                md_content += f"#### {vuln.get('title', 'Unknown Vulnerability')}\n"
                md_content += f"- **Severity:** {vuln.get('severity', 'N/A')}\n"
                md_content += f"- **Category:** {vuln.get('category', 'N/A')}\n"
                md_content += f"- **Affected Class:** `{vuln.get('affected_class', 'N/A')}`\n"
                md_content += f"- **Description:** {vuln.get('description', 'N/A')}\n"
                if vuln.get('remediation'):
                    md_content += f"- **Remediation:** {vuln.get('remediation')}\n"
                md_content += "\n"

    # Threat Model
    if report.ai_threat_model:
        tm = report.ai_threat_model
        md_content += """## 🎭 Threat Model

"""
        if tm.get('threat_actors'):
            md_content += "### Threat Actors\n\n"
            for actor in tm.get('threat_actors', [])[:5]:
                md_content += f"- **{actor.get('name', 'Unknown')}**: {actor.get('description', '')}\n"
            md_content += "\n"
        
        if tm.get('attack_scenarios'):
            md_content += "### Attack Scenarios\n\n"
            for scenario in tm.get('attack_scenarios', [])[:5]:
                md_content += f"#### {scenario.get('name', 'Scenario')}\n"
                md_content += f"{scenario.get('description', '')}\n\n"

    # Chat History
    if report.ai_chat_history:
        md_content += """## 💬 AI Chat History

"""
        for msg in report.ai_chat_history[:20]:
            role = msg.get('role', 'unknown').capitalize()
            content = msg.get('content', '')[:500]
            md_content += f"**{role}:**\n{content}\n\n---\n\n"

    # Notes
    if report.notes:
        md_content += f"""## 📝 Notes

{report.notes}

"""

    # Tags
    if report.tags:
        md_content += f"""## 🏷️ Tags

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
            in_table = False
            table_rows = []
            
            while i < len(lines):
                line = lines[i]
                
                # Handle code blocks
                if line.strip().startswith('```'):
                    if in_code_block:
                        # End code block
                        if code_content:
                            code_text = '<br/>'.join(code_content)
                            story.append(Paragraph(code_text, code_style))
                            story.append(Spacer(1, 6))
                        code_content = []
                        in_code_block = False
                    else:
                        in_code_block = True
                    i += 1
                    continue
                
                if in_code_block:
                    # Escape HTML entities in code
                    escaped = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    code_content.append(escaped)
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
                        # Normalize rows
                        normalized = [row + [''] * (col_count - len(row)) for row in table_rows]
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
                    text = _format_inline_markdown(line[2:])
                    story.append(Paragraph(text, h1_style))
                elif line.startswith('## '):
                    text = _format_inline_markdown(line[3:])
                    story.append(Paragraph(text, h1_style))
                elif line.startswith('### '):
                    text = _format_inline_markdown(line[4:])
                    story.append(Paragraph(text, h2_style))
                elif line.startswith('#### '):
                    text = _format_inline_markdown(line[5:])
                    story.append(Paragraph(text, h3_style))
                # Bullet points
                elif line.strip().startswith('- ') or line.strip().startswith('* ') or line.strip().startswith('• '):
                    text = _format_inline_markdown(line.strip()[2:])
                    story.append(Paragraph(f"• {text}", bullet_style))
                # Numbered lists
                elif re.match(r'^\s*\d+\.\s+', line):
                    text = re.sub(r'^\s*\d+\.\s+', '', line)
                    text = _format_inline_markdown(text)
                    num = re.match(r'^\s*(\d+)\.', line).group(1)
                    story.append(Paragraph(f"{num}. {text}", bullet_style))
                # Horizontal rule
                elif line.strip() == '---':
                    story.append(Spacer(1, 10))
                # Regular paragraph
                elif line.strip():
                    text = _format_inline_markdown(line)
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
            in_table = False
            table_rows = []
            
            while i < len(lines):
                line = lines[i]
                
                # Handle code blocks
                if line.strip().startswith('```'):
                    if in_code_block:
                        # End code block - add as formatted text
                        if code_content:
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
                        in_code_block = False
                    else:
                        in_code_block = True
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
                    text = _strip_markdown_formatting(line[2:])
                    doc.add_heading(text, 1)
                elif line.startswith('## '):
                    text = _strip_markdown_formatting(line[3:])
                    doc.add_heading(text, 1)
                elif line.startswith('### '):
                    text = _strip_markdown_formatting(line[4:])
                    doc.add_heading(text, 2)
                elif line.startswith('#### '):
                    text = _strip_markdown_formatting(line[5:])
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
    """Convert inline markdown to ReportLab XML tags."""
    import re
    # Bold
    text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
    # Italic
    text = re.sub(r'\*([^*]+)\*', r'<i>\1</i>', text)
    # Inline code - use different font
    text = re.sub(r'`([^`]+)`', r'<font face="Courier" size="9">\1</font>', text)
    # Escape any remaining special chars
    text = text.replace('&', '&amp;').replace('<b>', '<<<B>>>').replace('</b>', '<<</B>>>')
    text = text.replace('<i>', '<<<I>>>').replace('</i>', '<<</I>>>')
    text = text.replace('<font', '<<<FONT').replace('</font>', '<<</FONT>>>')
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    text = text.replace('<<<B>>>', '<b>').replace('<<</B>>>', '</b>')
    text = text.replace('<<<I>>>', '<i>').replace('<<</I>>>', '</i>')
    text = text.replace('<<<FONT', '<font').replace('<<</FONT>>>', '</font>')
    return text


def _strip_markdown_formatting(text: str) -> str:
    """Remove markdown formatting for plain text."""
    import re
    text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)
    text = re.sub(r'\*([^*]+)\*', r'\1', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    # Remove emoji codes but keep emoji
    return text.strip()


def _add_formatted_text(paragraph, text: str):
    """Add text to a Word paragraph with markdown formatting converted."""
    import re
    from docx.shared import Pt
    
    # Pattern to find bold, italic, and code
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
            architecture_diagram = await re_service.generate_ai_architecture_diagram(result, jadx_result)
        
        if include_data_flow:
            data_flow_diagram = await re_service.generate_ai_data_flow_diagram(result, jadx_result)
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled project not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled project not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled project not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled project not found")
        
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
        
        # Generate attack surface map
        result = re_service.generate_attack_surface_map(tmp_path)
        
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
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Obfuscation analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Obfuscation analysis failed: {str(e)}")
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
        
        # Generate export based on format
        package_name = result.package_name.split('.')[-1] if result.package_name else 'apk'
        
        if format == "markdown":
            markdown_content = re_service.generate_apk_markdown_report(result, report_type)
            return Response(
                content=markdown_content.encode('utf-8'),
                media_type="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="{package_name}_report.md"'}
            )
        
        elif format == "pdf":
            pdf_bytes = re_service.generate_apk_pdf_report(result, report_type)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{package_name}_report.pdf"'}
            )
        
        elif format == "docx":
            docx_bytes = re_service.generate_apk_docx_report(result, report_type)
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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
        output_dir = Path(request.output_directory)
        
        # Check if it's a session ID
        if request.output_directory in _jadx_cache:
            output_dir = _jadx_cache[request.output_directory]
        
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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
        output_dir = Path(request.output_directory)
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail="Decompiled sources not found")
        
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