"""
Unified Binary Scanner - Comprehensive Binary Analysis

Provides a single endpoint that performs complete binary analysis with:
1. Static Analysis (PE/ELF parsing, strings, secrets)
2. Ghidra Decompilation (full source code)
3. Vulnerability Scanning (pattern-based)
4. AI Multi-Pass Vulnerability Hunting (5 passes)
5. Fuzzing (quick 30s scan)
6. Attack Chain Detection
7. Exploit PoC Generation
8. AI Reports (functionality, security, architecture, attack surface)
9. FRIDA Script Generation

Returns streaming progress updates (SSE) with final comprehensive report.
"""

import asyncio
import json
import logging
import tempfile
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, AsyncGenerator
from pydantic import BaseModel, Field

from fastapi import APIRouter, File, Form, UploadFile, HTTPException, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.database import get_db
from backend.core.auth import get_current_active_user
from backend.models.models import User
from backend.core.file_validator import sanitize_filename
from backend.services import reverse_engineering_service as re_service
from backend.services.binary_fuzzer_service import BinaryFuzzer
from backend.services.integrated_binary_analyzer import IntegratedBinaryAnalyzer, AnalysisComponent
from backend.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/unified-binary", tags=["Unified Binary Analysis"])

# Global session tracking
_unified_binary_sessions: Dict[str, Dict] = {}

# Configuration
MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024  # 5GB - supports firmware, game engines, container images (was 500MB)
ALLOWED_EXTENSIONS = {".exe", ".dll", ".so", ".elf", ".bin", ".out", ".o", ".a"}


# ============================================================================
# Pydantic Models
# ============================================================================

class UnifiedBinaryScanPhase(BaseModel):
    """A phase in the unified binary scan."""
    id: str
    label: str
    description: str
    status: str = "pending"  # pending, in_progress, completed, error, skipped
    error: Optional[str] = None
    progress: int = 0  # 0-100


class UnifiedBinaryScanResult(BaseModel):
    """Complete result from unified binary scan."""
    scan_id: str
    filename: str
    file_size: int
    architecture: Optional[str] = None
    file_type: Optional[str] = None

    # Phase 1: Static Analysis
    imports: List[Dict[str, Any]] = []
    exports: List[Dict[str, Any]] = []
    strings: List[Dict[str, Any]] = []
    secrets: List[Dict[str, Any]] = []
    crypto_findings: Dict[str, Any] = {}
    entropy: Optional[float] = None

    # Phase 2: Ghidra Decompilation
    ghidra_session_id: Optional[str] = None
    total_functions: int = 0
    decompiled_functions: List[Dict[str, Any]] = []
    decompilation_time: float = 0

    # Phase 3: Vulnerability Scanning (pattern-based)
    vulnerability_findings: List[Dict[str, Any]] = []
    vulnerability_summary: Dict[str, Any] = {}

    # Phase 4: Multi-Pass AI Vulnerability Hunt
    ai_vuln_hunt_result: Optional[Dict[str, Any]] = None

    # Phase 5: Fuzzing
    fuzzing_result: Optional[Dict[str, Any]] = None

    # Phase 6: Attack Chain Detection
    attack_chains: List[Dict[str, Any]] = []

    # Phase 7: Exploit PoC Generation
    exploit_pocs: List[Dict[str, Any]] = []

    # Phase 8: AI Reports
    ai_functionality_report: Optional[str] = None
    ai_security_report: Optional[str] = None
    ai_architecture_diagram: Optional[str] = None
    ai_attack_surface_map: Optional[str] = None

    # Phase 9: FRIDA Scripts
    frida_scripts: Optional[Dict[str, Any]] = None

    # AI Verification Results
    ai_verification_summary: Optional[Dict[str, Any]] = None
    false_positives_removed: int = 0
    is_legitimate_software: bool = False
    overall_risk_level: Optional[str] = None

    # Metadata
    scan_time: float = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ============================================================================
# Unified Binary Scan Endpoint
# ============================================================================

@router.post("/scan")
async def unified_binary_scan(
    file: UploadFile = File(..., description="Binary file to analyze"),
    include_ghidra: bool = Form(True, description="Enable Ghidra decompilation"),
    include_vuln_hunt: bool = Form(True, description="Enable AI vulnerability hunting"),
    vuln_hunt_passes: int = Form(5, description="Number of AI hunting passes (2-8)", ge=2, le=8),
    include_fuzzing: bool = Form(True, description="Enable quick fuzzing (30s)"),
    include_exploit_pocs: bool = Form(True, description="Generate exploit PoC scripts"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Perform comprehensive unified binary analysis with streaming progress.

    This unified scan combines:
    1. Static Analysis (PE/ELF parsing, strings, secrets)
    2. Ghidra Decompilation (full decompiled source code)
    3. Vulnerability Scanning (pattern-based security scan)
    4. Multi-Pass AI Vulnerability Hunting (deep AI analysis)
    5. Quick Fuzzing (30-second crash detection)
    6. Attack Chain Detection (link vulnerabilities together)
    7. Exploit PoC Generation (working Python scripts)
    8. AI Reports (functionality, security, architecture, attack surface)
    9. FRIDA Script Generation (dynamic analysis scripts)

    Returns SSE stream with real-time progress updates and final result.
    """
    scan_id = str(uuid.uuid4())
    filename = file.filename or "unknown.bin"
    suffix = Path(filename).suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Save file with sanitized filename to prevent path traversal
    tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_unified_binary_"))
    safe_filename = sanitize_filename(filename)
    tmp_path = tmp_dir / safe_filename

    file_size = 0
    try:
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Maximum: {MAX_FILE_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")

    logger.info(f"Starting unified binary scan: {filename} ({file_size:,} bytes)")

    # Initialize session
    _unified_binary_sessions[scan_id] = {
        "cancelled": False,
        "tmp_dir": tmp_dir,
        "file_path": tmp_path,
    }

    # Define phases
    phases = [
        UnifiedBinaryScanPhase(
            id="static",
            label="Static Analysis",
            description="PE/ELF parsing, strings, secrets, and crypto detection"
        ),
    ]

    if include_ghidra:
        phases.append(UnifiedBinaryScanPhase(
            id="ghidra",
            label="Ghidra Decompilation",
            description="Full source code decompilation and function analysis"
        ))

    phases.append(UnifiedBinaryScanPhase(
        id="vuln_scan",
        label="Vulnerability Scanning",
        description="Pattern-based security vulnerability detection"
    ))

    if include_vuln_hunt:
        phases.append(UnifiedBinaryScanPhase(
            id="ai_vuln_hunt",
            label="AI Vulnerability Hunt",
            description=f"Multi-pass AI-guided vulnerability discovery ({vuln_hunt_passes} passes)"
        ))

    if include_fuzzing:
        phases.append(UnifiedBinaryScanPhase(
            id="fuzzing",
            label="Quick Fuzzing",
            description="30-second crash detection fuzzing"
        ))

    phases.extend([
        UnifiedBinaryScanPhase(
            id="ai_verification",
            label="AI Verification",
            description="Deduplicate findings and filter false positives with AI"
        ),
        UnifiedBinaryScanPhase(
            id="attack_chains",
            label="Attack Chain Detection",
            description="Correlate vulnerabilities into exploit chains"
        ),
    ])

    if include_exploit_pocs:
        phases.append(UnifiedBinaryScanPhase(
            id="exploit_pocs",
            label="Exploit PoC Generation",
            description="Generate working exploit scripts"
        ))

    phases.extend([
        UnifiedBinaryScanPhase(
            id="ai_reports",
            label="AI Report Generation",
            description="Generate comprehensive AI analysis reports"
        ),
        UnifiedBinaryScanPhase(
            id="frida",
            label="FRIDA Script Generation",
            description="Generate dynamic analysis scripts"
        ),
    ])

    async def run_unified_binary_scan() -> AsyncGenerator[str, None]:
        """Generator that yields SSE progress events."""
        start_time = datetime.now()
        result = UnifiedBinaryScanResult(
            scan_id=scan_id,
            filename=filename,
            file_size=file_size,
            started_at=start_time
        )

        def make_progress(message: str, progress: int) -> str:
            """Helper to format SSE progress event."""
            return f"data: {json.dumps({'type': 'progress', 'message': message, 'progress': progress})}\n\n"

        def update_phase(phase_id: str, status: str, error: Optional[str] = None, progress: int = 0):
            """Update phase status and send event."""
            for p in phases:
                if p.id == phase_id:
                    p.status = status
                    p.error = error
                    p.progress = progress
                    break

        try:
            current_phase_idx = 0

            # =================================================================
            # PHASE 1: Static Analysis
            # =================================================================
            yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: Static Analysis...", 0)
            update_phase("static", "in_progress")

            try:
                yield make_progress("Analyzing binary structure...", 10)
                binary_result = re_service.analyze_binary(tmp_path)

                result.imports = [
                    {"name": imp.name, "dll": getattr(imp, 'dll', None)}
                    for imp in binary_result.imports[:100]
                ]
                result.exports = [
                    {"name": exp.name, "address": getattr(exp, 'address', None)}
                    for exp in binary_result.exports[:100]
                ]
                result.strings = [
                    {"value": s.value, "offset": getattr(s, 'offset', None)}
                    for s in binary_result.strings[:200]
                ]
                result.secrets = [
                    s.to_dict() if hasattr(s, 'to_dict') else {"value": str(s)}
                    for s in binary_result.secrets
                ]
                result.crypto_findings = binary_result.crypto_findings if hasattr(binary_result, 'crypto_findings') else {}
                result.architecture = binary_result.metadata.architecture if binary_result.metadata else None
                result.file_type = binary_result.metadata.file_type if binary_result.metadata else None
                result.entropy = getattr(binary_result.metadata, 'entropy', None) if binary_result.metadata else None

                yield make_progress(f"Found {len(result.imports)} imports, {len(result.secrets)} secrets", 100)
                update_phase("static", "completed", progress=100)
            except Exception as e:
                logger.error(f"Static analysis failed: {e}", exc_info=True)
                update_phase("static", "error", str(e))
                yield make_progress(f"Static analysis error: {e}", 100)

            await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 2: Ghidra Decompilation (Optional)
            # =================================================================
            ghidra_result = None
            if include_ghidra:
                current_phase_idx += 1
                yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: Ghidra Decompilation...", 0)
                update_phase("ghidra", "in_progress")

                try:
                    yield make_progress("Starting Ghidra headless analysis...", 10)
                    ghidra_result = re_service.analyze_binary_with_ghidra(
                        tmp_path,
                        max_functions=200,
                        decomp_limit=4000
                    )

                    if ghidra_result and "error" not in ghidra_result:
                        functions = ghidra_result.get("functions", [])
                        result.total_functions = len(functions)

                        yield make_progress(f"Decompiled {len(functions)} functions...", 50)

                        # AI function analysis
                        yield make_progress("AI analyzing functions...", 70)
                        ai_summaries = await re_service.analyze_ghidra_functions_with_ai(
                            ghidra_result,
                            max_functions=20
                        )

                        if ai_summaries:
                            result.decompiled_functions = ai_summaries

                        yield make_progress(f"Decompilation complete: {len(functions)} functions", 100)
                        update_phase("ghidra", "completed", progress=100)
                    else:
                        error_msg = ghidra_result.get("error", "Unknown error") if ghidra_result else "No result"
                        update_phase("ghidra", "error", error_msg)
                        yield make_progress(f"Ghidra error: {error_msg}", 100)
                except Exception as e:
                    logger.error(f"Ghidra decompilation failed: {e}", exc_info=True)
                    update_phase("ghidra", "error", str(e))
                    yield make_progress(f"Ghidra error: {e}", 100)

                await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 3: Vulnerability Scanning (Pattern-based)
            # =================================================================
            current_phase_idx += 1
            yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: Vulnerability Scanning...", 0)
            update_phase("vuln_scan", "in_progress")

            try:
                if ghidra_result and "error" not in ghidra_result:
                    yield make_progress("Scanning decompiled code for vulnerabilities...", 20)

                    vuln_scan_result = re_service.scan_decompiled_binary_comprehensive(
                        ghidra_result,
                        is_legitimate_software=False
                    )

                    result.vulnerability_findings = vuln_scan_result.get("findings", [])
                    result.vulnerability_summary = vuln_scan_result.get("summary", {})

                    total_vulns = len(result.vulnerability_findings)
                    yield make_progress(f"Found {total_vulns} potential vulnerabilities", 100)
                    update_phase("vuln_scan", "completed", progress=100)
                else:
                    update_phase("vuln_scan", "skipped", "No Ghidra result available")
                    yield make_progress("Vulnerability scanning skipped (no decompilation)", 100)
            except Exception as e:
                logger.error(f"Vulnerability scanning failed: {e}", exc_info=True)
                update_phase("vuln_scan", "error", str(e))
                yield make_progress(f"Vulnerability scan error: {e}", 100)

            await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 4: Multi-Pass AI Vulnerability Hunt (NEW!)
            # =================================================================
            if include_vuln_hunt:
                current_phase_idx += 1
                yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: AI Vulnerability Hunt...", 0)
                update_phase("ai_vuln_hunt", "in_progress")

                try:
                    if ghidra_result and "error" not in ghidra_result:
                        yield make_progress(f"Starting {vuln_hunt_passes}-pass AI vulnerability hunt...", 10)

                        # AI Vulnerability Hunt (multi-pass)
                        ai_hunt_result = await perform_ai_vulnerability_hunt(
                            ghidra_result=ghidra_result,
                            static_result=binary_result,
                            max_passes=vuln_hunt_passes,
                            progress_callback=lambda msg, prog: None  # Could yield progress here
                        )

                        result.ai_vuln_hunt_result = ai_hunt_result

                        total_ai_vulns = len(ai_hunt_result.get("vulnerabilities", []))
                        yield make_progress(f"AI hunt found {total_ai_vulns} vulnerabilities", 100)
                        update_phase("ai_vuln_hunt", "completed", progress=100)
                    else:
                        update_phase("ai_vuln_hunt", "skipped", "No decompilation available")
                        yield make_progress("AI hunt skipped (no decompilation)", 100)
                except Exception as e:
                    logger.error(f"AI vulnerability hunt failed: {e}", exc_info=True)
                    update_phase("ai_vuln_hunt", "error", str(e))
                    yield make_progress(f"AI hunt error: {e}", 100)

                await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 5: Quick Fuzzing (Optional)
            # =================================================================
            if include_fuzzing:
                current_phase_idx += 1
                yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: Quick Fuzzing...", 0)
                update_phase("fuzzing", "in_progress")

                try:
                    yield make_progress("Starting 30-second fuzzing campaign...", 20)

                    fuzzing_result = await perform_quick_fuzzing(
                        binary_path=tmp_path,
                        max_duration=30
                    )

                    result.fuzzing_result = fuzzing_result

                    crashes = fuzzing_result.get("crashes_found", 0)
                    yield make_progress(f"Fuzzing complete: {crashes} crashes", 100)
                    update_phase("fuzzing", "completed", progress=100)
                except Exception as e:
                    logger.error(f"Fuzzing failed: {e}", exc_info=True)
                    update_phase("fuzzing", "error", str(e))
                    yield make_progress(f"Fuzzing error: {e}", 100)

                await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 5.5: AI Verification & False Positive Filtering (NEW!)
            # =================================================================
            current_phase_idx += 1
            yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: AI Verification...", 0)
            update_phase("ai_verification", "in_progress")

            verified_findings = None
            try:
                yield make_progress("AI analyzing findings for false positives...", 20)

                # Call AI verification to deduplicate and filter false positives
                verified_findings = await verify_all_findings(
                    pattern_findings=result.vulnerability_findings,
                    ai_vuln_findings=result.ai_vuln_hunt_result.get("vulnerabilities", []) if result.ai_vuln_hunt_result else [],
                    secrets=result.secrets,
                    ghidra_result=ghidra_result,
                    binary_result=binary_result,
                    filename=filename
                )

                # Update results with verified findings
                if verified_findings:
                    result.vulnerability_findings = verified_findings.get("verified_vulnerabilities", result.vulnerability_findings)
                    result.secrets = verified_findings.get("verified_secrets", result.secrets)
                    if result.ai_vuln_hunt_result:
                        result.ai_vuln_hunt_result["vulnerabilities"] = verified_findings.get("verified_ai_vulns", result.ai_vuln_hunt_result.get("vulnerabilities", []))

                    # Store verification metadata
                    result.false_positives_removed = verified_findings.get("false_positives_removed", 0)
                    result.is_legitimate_software = verified_findings.get("is_legitimate_software", False)
                    result.overall_risk_level = verified_findings.get("overall_risk", "MEDIUM")
                    result.ai_verification_summary = {
                        "total_verified": verified_findings.get("real_findings", 0),
                        "false_positives_removed": verified_findings.get("false_positives_removed", 0),
                        "overall_risk": verified_findings.get("overall_risk", "MEDIUM"),
                        "summary": verified_findings.get("summary", ""),
                        "prioritized_actions": verified_findings.get("prioritized_actions", [])[:5],
                        "is_legitimate": verified_findings.get("is_legitimate_software", False),
                        "legitimacy_indicators": verified_findings.get("legitimacy_indicators", [])
                    }

                    fp_count = verified_findings.get("false_positives_removed", 0)
                    real_count = verified_findings.get("real_findings", 0)
                    yield make_progress(f"Verification complete: {real_count} real findings, {fp_count} false positives removed", 100)
                    update_phase("ai_verification", "completed", progress=100)
                else:
                    yield make_progress("Verification complete (no AI)", 100)
                    update_phase("ai_verification", "completed", progress=100)

            except Exception as e:
                logger.error(f"AI verification failed: {e}", exc_info=True)
                update_phase("ai_verification", "error", str(e))
                yield make_progress(f"Verification error (continuing with unverified): {e}", 100)

            await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 6: Attack Chain Detection (NEW!)
            # =================================================================
            current_phase_idx += 1
            yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: Attack Chain Detection...", 0)
            update_phase("attack_chains", "in_progress")

            try:
                yield make_progress("Analyzing vulnerability correlations...", 30)

                # Use verified findings if available
                vuln_findings = verified_findings.get("verified_vulnerabilities", result.vulnerability_findings) if verified_findings else result.vulnerability_findings
                ai_vulns = verified_findings.get("verified_ai_vulns", result.ai_vuln_hunt_result.get("vulnerabilities", [])) if verified_findings and result.ai_vuln_hunt_result else (result.ai_vuln_hunt_result.get("vulnerabilities", []) if result.ai_vuln_hunt_result else [])

                # Detect attack chains
                attack_chains = await detect_attack_chains(
                    vulnerability_findings=vuln_findings,
                    ai_vuln_findings=ai_vulns,
                    fuzzing_crashes=result.fuzzing_result.get("crash_details", []) if result.fuzzing_result else []
                )

                result.attack_chains = attack_chains

                yield make_progress(f"Detected {len(attack_chains)} attack chains", 100)
                update_phase("attack_chains", "completed", progress=100)
            except Exception as e:
                logger.error(f"Attack chain detection failed: {e}", exc_info=True)
                update_phase("attack_chains", "error", str(e))
                yield make_progress(f"Attack chain error: {e}", 100)

            await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 7: Exploit PoC Generation (NEW!)
            # =================================================================
            if include_exploit_pocs:
                current_phase_idx += 1
                yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: Exploit PoC Generation...", 0)
                update_phase("exploit_pocs", "in_progress")

                try:
                    yield make_progress("Generating exploit scripts...", 30)

                    # Generate PoCs for top vulnerabilities
                    exploit_pocs = await generate_exploit_pocs(
                        attack_chains=result.attack_chains,
                        vulnerability_findings=result.vulnerability_findings,
                        ghidra_result=ghidra_result,
                        binary_info={
                            "filename": filename,
                            "architecture": result.architecture,
                            "file_type": result.file_type
                        }
                    )

                    result.exploit_pocs = exploit_pocs

                    yield make_progress(f"Generated {len(exploit_pocs)} exploit PoCs", 100)
                    update_phase("exploit_pocs", "completed", progress=100)
                except Exception as e:
                    logger.error(f"Exploit PoC generation failed: {e}", exc_info=True)
                    update_phase("exploit_pocs", "error", str(e))
                    yield make_progress(f"PoC generation error: {e}", 100)

                await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 8: AI Reports Generation
            # =================================================================
            current_phase_idx += 1
            yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: AI Reports...", 0)
            update_phase("ai_reports", "in_progress")

            try:
                yield make_progress("Generating functionality report...", 25)

                # Generate comprehensive AI reports
                ai_reports = await generate_ai_reports(
                    binary_result=binary_result,
                    ghidra_result=ghidra_result,
                    vulnerability_findings=result.vulnerability_findings,
                    ai_vuln_findings=result.ai_vuln_hunt_result.get("vulnerabilities", []) if result.ai_vuln_hunt_result else [],
                    attack_chains=result.attack_chains
                )

                result.ai_functionality_report = ai_reports.get("functionality")
                result.ai_security_report = ai_reports.get("security")
                result.ai_architecture_diagram = ai_reports.get("architecture")
                result.ai_attack_surface_map = ai_reports.get("attack_surface")

                yield make_progress("AI reports generated", 100)
                update_phase("ai_reports", "completed", progress=100)
            except Exception as e:
                logger.error(f"AI report generation failed: {e}", exc_info=True)
                update_phase("ai_reports", "error", str(e))
                yield make_progress(f"AI report error: {e}", 100)

            await asyncio.sleep(0.1)

            # =================================================================
            # PHASE 9: FRIDA Script Generation
            # =================================================================
            current_phase_idx += 1
            yield make_progress(f"Phase {current_phase_idx + 1}/{len(phases)}: FRIDA Scripts...", 0)
            update_phase("frida", "in_progress")

            try:
                yield make_progress("Generating FRIDA hooks...", 50)

                frida_scripts = re_service.generate_binary_frida_scripts(
                    binary_name=filename,
                    static_result=binary_result,
                    ghidra_result=ghidra_result,
                    obfuscation_result=None,
                    verified_findings=result.vulnerability_findings,
                    vuln_hunt_findings=result.ai_vuln_hunt_result.get("vulnerabilities", []) if result.ai_vuln_hunt_result else [],
                    attack_surface_result=None
                )

                result.frida_scripts = frida_scripts

                total_scripts = frida_scripts.get("total_scripts", 0)
                yield make_progress(f"Generated {total_scripts} FRIDA scripts", 100)
                update_phase("frida", "completed", progress=100)
            except Exception as e:
                logger.error(f"FRIDA script generation failed: {e}", exc_info=True)
                update_phase("frida", "error", str(e))
                yield make_progress(f"FRIDA error: {e}", 100)

            # =================================================================
            # Final Result
            # =================================================================
            result.completed_at = datetime.now()
            result.scan_time = (result.completed_at - start_time).total_seconds()

            yield f"data: {json.dumps({'type': 'result', 'data': result.model_dump()})}\n\n"
            yield f"data: {json.dumps({'type': 'phases', 'phases': [p.model_dump() for p in phases]})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"

        except Exception as e:
            logger.error(f"Unified binary scan failed: {e}", exc_info=True)
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
        finally:
            # Cleanup
            if scan_id in _unified_binary_sessions:
                del _unified_binary_sessions[scan_id]
            # Don't delete tmp_dir yet if Ghidra output needs to be browsed

    return StreamingResponse(
        run_unified_binary_scan(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


# ============================================================================
# Helper Functions
# ============================================================================

async def perform_ai_vulnerability_hunt(
    ghidra_result: Dict[str, Any],
    static_result: Any,
    max_passes: int = 5,
    progress_callback=None
) -> Dict[str, Any]:
    """
    Multi-pass AI vulnerability hunting.

    Iteratively uses AI to discover complex vulnerabilities that pattern matching misses.
    """
    if not settings.gemini_api_key:
        return {"error": "Gemini API key not configured", "vulnerabilities": []}

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=settings.gemini_api_key)

        functions = ghidra_result.get("functions", [])
        if not functions:
            return {"vulnerabilities": [], "passes_completed": 0}

        all_vulnerabilities = []
        targets_analyzed = set()

        for pass_num in range(max_passes):
            logger.info(f"AI Vulnerability Hunt - Pass {pass_num + 1}/{max_passes}")

            # Select targets for this pass (prioritize high-risk functions)
            targets = select_vulnerability_targets(
                functions=functions,
                previous_findings=all_vulnerabilities,
                already_analyzed=targets_analyzed,
                max_targets=50
            )

            if not targets:
                logger.info("No more targets to analyze")
                break

            # Analyze targets in parallel
            sem = asyncio.Semaphore(4)  # Limit concurrency

            async def analyze_target(func: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                func_name = func.get("name", "unknown")
                decompiled = func.get("decompiled", "")[:8000]

                if not decompiled:
                    return None

                prompt = f"""You are a security researcher analyzing decompiled binary code for vulnerabilities.

Function: {func_name}
Entry: {func.get("entry", "0x0")}

Decompiled Code:
{decompiled}

Analyze this function for security vulnerabilities. Focus on:
1. Buffer overflows (strcpy, sprintf, memcpy without bounds)
2. Format string vulnerabilities
3. Integer overflows/underflows
4. Use-after-free
5. Double-free
6. Race conditions
7. Logic bugs that could lead to exploitation

Return JSON format:
{{
  "vulnerabilities": [
    {{
      "title": "Buffer Overflow in strcpy",
      "severity": "high",
      "exploitability": "high",
      "description": "Detailed description",
      "location": "{func_name}:line_approx",
      "attack_vector": "How to exploit",
      "confidence": 0.9
    }}
  ]
}}

Only return vulnerabilities you're confident about (confidence >= 0.7)."""

                async with sem:
                    try:
                        from backend.services.reverse_engineering_service import gemini_request_with_retry

                        response = await gemini_request_with_retry(
                            lambda: client.aio.models.generate_content(
                                model=settings.gemini_model_id,
                                contents=[types.Content(role="user", parts=[types.Part(text=prompt)])],
                            ),
                            max_retries=3,
                            base_delay=2.0,
                            timeout_seconds=120.0,
                            operation_name=f"AI Vuln Hunt {func_name}"
                        )

                        if not response or not response.text:
                            return None

                        # Parse JSON response
                        import re
                        json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
                        if json_match:
                            result = json.loads(json_match.group())
                            return result.get("vulnerabilities", [])

                    except Exception as e:
                        logger.warning(f"AI analysis failed for {func_name}: {e}")
                        return None

                return None

            # Analyze all targets
            results = await asyncio.gather(*(analyze_target(t) for t in targets))

            # Collect vulnerabilities
            for vulns in results:
                if vulns and isinstance(vulns, list):
                    all_vulnerabilities.extend(vulns)

            # Mark targets as analyzed
            for t in targets:
                targets_analyzed.add(t.get("entry", "0x0"))

        # Deduplicate and sort by severity
        unique_vulns = {v.get("title") + v.get("location", ""): v for v in all_vulnerabilities}.values()
        sorted_vulns = sorted(unique_vulns, key=lambda v: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(v.get("severity", "low"), 0),
            v.get("confidence", 0)
        ), reverse=True)

        return {
            "total_passes": max_passes,
            "passes_completed": pass_num + 1,
            "targets_analyzed": len(targets_analyzed),
            "vulnerabilities": list(sorted_vulns),
            "total_vulnerabilities": len(sorted_vulns)
        }

    except Exception as e:
        logger.error(f"AI vulnerability hunt failed: {e}", exc_info=True)
        return {"error": str(e), "vulnerabilities": []}


def select_vulnerability_targets(
    functions: List[Dict],
    previous_findings: List[Dict],
    already_analyzed: set,
    max_targets: int = 50
) -> List[Dict]:
    """Select high-priority functions for vulnerability analysis."""
    # Priority factors:
    # 1. Functions with dangerous API calls
    # 2. Large complex functions
    # 3. Functions handling user input
    # 4. Functions not yet analyzed

    dangerous_apis = {
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
        "memcpy", "memmove", "strncpy", "malloc", "free", "realloc"
    }

    scored_functions = []

    for func in functions:
        entry = func.get("entry", "0x0")
        if entry in already_analyzed:
            continue

        score = 0

        # Check for dangerous API calls
        called = func.get("called_functions", [])
        for api in dangerous_apis:
            if any(api.lower() in c.lower() for c in called):
                score += 10

        # Large functions are more complex
        size = func.get("size", 0)
        if size > 1000:
            score += 5
        elif size > 500:
            score += 3

        # Functions with many calls are complex
        if len(called) > 10:
            score += 3

        scored_functions.append((score, func))

    # Sort by score and return top N
    scored_functions.sort(key=lambda x: x[0], reverse=True)
    return [f[1] for f in scored_functions[:max_targets]]


async def perform_quick_fuzzing(binary_path: Path, max_duration: int = 30) -> Dict[str, Any]:
    """Quick fuzzing scan (30 seconds)."""
    try:
        import tempfile

        temp_base = tempfile.mkdtemp(prefix="quick_fuzz_")
        input_dir = Path(temp_base) / "in"
        output_dir = Path(temp_base) / "out"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create seed
        seed_path = input_dir / "seed"
        seed_path.write_bytes(b"A" * 40)

        fuzzer = BinaryFuzzer()

        crashes = []
        executions = 0
        coverage = {}

        try:
            async for progress in fuzzer.fuzz_file(
                target_path=str(binary_path),
                input_dir=str(input_dir),
                output_dir=str(output_dir),
                timeout=5000,
                max_iterations=1000
            ):
                executions = progress.executions
                crashes = progress.crashes
                coverage = progress.coverage if hasattr(progress, 'coverage') else {}

                if progress.elapsed_time if hasattr(progress, 'elapsed_time') else 0 > max_duration:
                    break
        except Exception as e:
            logger.warning(f"Fuzzing iteration error: {e}")

        # Cleanup
        shutil.rmtree(temp_base, ignore_errors=True)

        return {
            "executions": executions,
            "crashes_found": len(crashes),
            "unique_crashes": len(set(getattr(c, 'hash', id(c)) for c in crashes)),
            "coverage": coverage,
            "crash_details": [
                {
                    "type": c.crash_type.value if hasattr(c, 'crash_type') else "unknown",
                    "exploitability": c.severity.value if hasattr(c, 'severity') else "unknown",
                    "address": getattr(c, 'crash_address', 'unknown')
                }
                for c in crashes[:5]
            ]
        }
    except Exception as e:
        logger.error(f"Fuzzing failed: {e}", exc_info=True)
        return {"error": str(e), "executions": 0, "crashes_found": 0}


async def detect_attack_chains(
    vulnerability_findings: List[Dict],
    ai_vuln_findings: List[Dict],
    fuzzing_crashes: List[Dict]
) -> List[Dict[str, Any]]:
    """
    Detect attack chains by correlating vulnerabilities.

    Example: Buffer overflow + return address overwrite + code execution
    """
    all_findings = vulnerability_findings + ai_vuln_findings

    if not all_findings:
        return []

    # Use AI to detect chains
    if not settings.gemini_api_key:
        return []

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=settings.gemini_api_key)

        # Prepare findings summary
        findings_summary = json.dumps([
            {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "location": f.get("location"),
                "description": f.get("description", "")[:200]
            }
            for f in all_findings[:30]
        ], indent=2)

        prompt = f"""Analyze these vulnerabilities and identify attack chains.

An attack chain is a sequence of vulnerabilities that can be exploited together for greater impact.

Vulnerabilities:
{findings_summary}

Identify potential attack chains. Return JSON:
{{
  "attack_chains": [
    {{
      "chain_id": "chain_001",
      "title": "Buffer Overflow → Code Execution",
      "severity": "critical",
      "steps": [
        "Exploit buffer overflow in function X",
        "Overwrite return address",
        "Execute shellcode"
      ],
      "vulnerabilities_used": ["vuln1_title", "vuln2_title"],
      "exploitability": "high",
      "description": "Detailed chain explanation"
    }}
  ]
}}"""

        from backend.services.reverse_engineering_service import gemini_request_with_retry

        response = await gemini_request_with_retry(
            lambda: client.aio.models.generate_content(
                model=settings.gemini_model_id,
                contents=[types.Content(role="user", parts=[types.Part(text=prompt)])],
            ),
            max_retries=3,
            base_delay=2.0,
            timeout_seconds=120.0,
            operation_name="Attack chain detection"
        )

        if response and response.text:
            import re
            json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result.get("attack_chains", [])

    except Exception as e:
        logger.error(f"Attack chain detection failed: {e}", exc_info=True)

    return []


async def generate_exploit_pocs(
    attack_chains: List[Dict],
    vulnerability_findings: List[Dict],
    ghidra_result: Optional[Dict],
    binary_info: Dict
) -> List[Dict[str, Any]]:
    """
    Generate working exploit PoC scripts.
    """
    if not attack_chains and not vulnerability_findings:
        return []

    if not settings.gemini_api_key:
        return []

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=settings.gemini_api_key)

        pocs = []

        # Generate PoCs for top 3 attack chains or vulnerabilities
        targets = attack_chains[:3] if attack_chains else vulnerability_findings[:3]

        for target in targets:
            title = target.get("title", "Unknown")
            description = target.get("description", "")

            prompt = f"""Generate a working exploit PoC script for this vulnerability:

Title: {title}
Description: {description}
Binary: {binary_info.get("filename")}
Architecture: {binary_info.get("architecture")}

Generate a complete Python exploit script. Include:
1. Imports
2. Configuration (target address, offsets)
3. Payload generation
4. Exploit execution
5. Comments explaining each step

Return working Python code that could be used for testing (in a controlled environment)."""

            from backend.services.reverse_engineering_service import gemini_request_with_retry

            response = await gemini_request_with_retry(
                lambda: client.aio.models.generate_content(
                    model=settings.gemini_model_id,
                    contents=[types.Content(role="user", parts=[types.Part(text=prompt)])],
                ),
                max_retries=3,
                base_delay=2.0,
                timeout_seconds=120.0,
                operation_name=f"Exploit PoC for {title}"
            )

            if response and response.text:
                pocs.append({
                    "vulnerability_title": title,
                    "poc_type": "python",
                    "poc_script": response.text,
                    "testing_notes": "Test only in isolated environment. Do not use maliciously."
                })

        return pocs

    except Exception as e:
        logger.error(f"Exploit PoC generation failed: {e}", exc_info=True)
        return []


async def verify_all_findings(
    pattern_findings: List[Dict],
    ai_vuln_findings: List[Dict],
    secrets: List[Dict],
    ghidra_result: Optional[Dict],
    binary_result: Any,
    filename: str
) -> Optional[Dict[str, Any]]:
    """
    AI verification to deduplicate findings and filter false positives.

    Uses the same verification system as APK analyzer to ensure quality.
    """
    if not settings.gemini_api_key:
        logger.warning("No Gemini API key - skipping AI verification")
        return None

    try:
        # Import the verification function from reverse engineering service
        from backend.services.reverse_engineering_service import verify_binary_findings_unified

        # Check if this appears to be legitimate software (reduce false positives)
        is_legitimate = False
        legitimacy_indicators = []

        # Check filename for known publishers
        LEGITIMATE_PUBLISHERS = {
            "microsoft", "google", "mozilla", "apple", "adobe", "oracle",
            "chrome", "firefox", "edge", "vscode", "office", "windows",
        }
        filename_lower = filename.lower()
        for publisher in LEGITIMATE_PUBLISHERS:
            if publisher in filename_lower:
                is_legitimate = True
                legitimacy_indicators.append(f"Filename suggests {publisher} product")
                break

        # Build binary metadata
        binary_metadata = {
            "file_type": binary_result.metadata.file_type if binary_result.metadata else "Unknown",
            "architecture": binary_result.metadata.architecture if binary_result.metadata else "Unknown",
            "entropy": getattr(binary_result.metadata, 'entropy', None) if binary_result.metadata else None,
        }

        # Call unified verification
        verification_result = await verify_binary_findings_unified(
            pattern_findings=pattern_findings,
            cve_findings=[],  # We don't have CVE lookup yet
            sensitive_findings=secrets,
            vuln_hunt_findings=ai_vuln_findings,
            decompiled_code=ghidra_result,
            binary_metadata=binary_metadata,
            is_legitimate_software=is_legitimate,
            legitimacy_indicators=legitimacy_indicators
        )

        if not verification_result:
            return None

        # Extract verified findings
        verified_vulns = []
        for i, verdict in enumerate(verification_result.get("verified_pattern_vulns", [])):
            if verdict.get("verdict") == "REAL" and i < len(pattern_findings):
                finding = pattern_findings[i].copy()
                finding["ai_confidence"] = verdict.get("confidence", 0)
                finding["ai_priority"] = verdict.get("priority", 5)
                finding["ai_reason"] = verdict.get("reason", "")
                verified_vulns.append(finding)

        verified_ai_vulns = []
        for i, verdict in enumerate(verification_result.get("verified_vuln_hunt", [])):
            if verdict.get("verdict") == "REAL" and i < len(ai_vuln_findings):
                finding = ai_vuln_findings[i].copy()
                finding["ai_confidence"] = verdict.get("confidence", 0)
                finding["exploitability"] = verdict.get("exploitability", "MEDIUM")
                finding["ai_reason"] = verdict.get("reason", "")
                verified_ai_vulns.append(finding)

        verified_secrets = []
        for i, verdict in enumerate(verification_result.get("verified_secrets", [])):
            if verdict.get("verdict") == "REAL" and i < len(secrets):
                secret = secrets[i].copy()
                secret["ai_confidence"] = verdict.get("confidence", 0)
                secret["risk_level"] = verdict.get("risk", "MEDIUM")
                secret["ai_reason"] = verdict.get("reason", "")
                verified_secrets.append(secret)

        total_before = len(pattern_findings) + len(ai_vuln_findings) + len(secrets)
        total_after = len(verified_vulns) + len(verified_ai_vulns) + len(verified_secrets)
        fp_removed = total_before - total_after

        logger.info(f"AI Verification: {total_after} real findings, {fp_removed} false positives removed")

        return {
            "verified_vulnerabilities": verified_vulns,
            "verified_ai_vulns": verified_ai_vulns,
            "verified_secrets": verified_secrets,
            "attack_chains": verification_result.get("attack_chains", []),
            "prioritized_actions": verification_result.get("prioritized_actions", []),
            "overall_risk": verification_result.get("overall_risk", "MEDIUM"),
            "summary": verification_result.get("summary", ""),
            "false_positives_removed": fp_removed,
            "real_findings": total_after,
            "is_legitimate_software": is_legitimate,
            "legitimacy_indicators": legitimacy_indicators,
        }

    except Exception as e:
        logger.error(f"AI verification failed: {e}", exc_info=True)
        return None


async def generate_ai_reports(
    binary_result: Any,
    ghidra_result: Optional[Dict],
    vulnerability_findings: List[Dict],
    ai_vuln_findings: List[Dict],
    attack_chains: List[Dict]
) -> Dict[str, str]:
    """Generate comprehensive AI reports with proper Mermaid diagrams."""
    if not settings.gemini_api_key:
        return {}

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=settings.gemini_api_key)

        # Prepare context
        imports = [imp.name for imp in binary_result.imports[:50]] if hasattr(binary_result, 'imports') else []
        exports = [exp.name for exp in binary_result.exports[:20]] if hasattr(binary_result, 'exports') else []
        secrets = [s.to_dict() if hasattr(s, 'to_dict') else str(s) for s in binary_result.secrets[:10]] if hasattr(binary_result, 'secrets') else []

        # Function details from Ghidra
        functions = ghidra_result.get("functions", [])[:30] if ghidra_result else []
        function_names = [f.get("name", "unknown") for f in functions]

        # Build comprehensive context
        context = f"""
=== BINARY INFORMATION ===
Architecture: {binary_result.metadata.architecture if binary_result.metadata else 'Unknown'}
File Type: {binary_result.metadata.file_type if binary_result.metadata else 'Unknown'}
Entropy: {getattr(binary_result.metadata, 'entropy', 'N/A') if binary_result.metadata else 'N/A'}

=== IMPORTS ({len(imports)}) ===
{', '.join(imports[:30])}

=== EXPORTS ({len(exports)}) ===
{', '.join(exports[:20])}

=== FUNCTIONS ({len(functions)}) ===
{', '.join(function_names[:25])}

=== SECURITY FINDINGS ===
Secrets Found: {len(secrets)}
Pattern-Based Vulnerabilities: {len(vulnerability_findings)}
AI-Discovered Vulnerabilities: {len(ai_vuln_findings)}
Attack Chains: {len(attack_chains)}

Top Vulnerabilities:
{chr(10).join(f'  - [{v.get("severity", "?").upper()}] {v.get("title", "Unknown")}' for v in (vulnerability_findings + ai_vuln_findings)[:10])}
"""

        from backend.services.reverse_engineering_service import gemini_request_with_retry

        # ===================================================================
        # 1. Functionality Report
        # ===================================================================
        func_prompt = f"""Analyze this binary and describe its functionality:

{context}

Write a comprehensive functionality report in markdown format covering:
1. **Purpose** - What the binary does
2. **Key Components** - Main functions and modules
3. **Dependencies** - External libraries and APIs used
4. **Data Processing** - How it handles input/output
5. **Network Activity** - Any network-related functionality"""

        func_response = await gemini_request_with_retry(
            lambda: client.aio.models.generate_content(
                model=settings.gemini_model_id,
                contents=[types.Content(role="user", parts=[types.Part(text=func_prompt)])],
            ),
            max_retries=3,
            base_delay=2.0,
            timeout_seconds=120.0,
            operation_name="Functionality report"
        )

        # ===================================================================
        # 2. Security Report
        # ===================================================================
        sec_prompt = f"""Write a comprehensive security analysis report:

{context}

Attack Chains Detected:
{chr(10).join(f'  - {c.get("title", "Unknown")}: {c.get("severity", "?")}' for c in attack_chains[:5])}

Write a security report in markdown format with:
1. **Executive Summary** - Overall security posture
2. **Critical Findings** - High-severity vulnerabilities
3. **Attack Surface** - Entry points and exposure
4. **Recommendations** - Prioritized remediation steps
5. **Risk Assessment** - Overall risk level"""

        sec_response = await gemini_request_with_retry(
            lambda: client.aio.models.generate_content(
                model=settings.gemini_model_id,
                contents=[types.Content(role="user", parts=[types.Part(text=sec_prompt)])],
            ),
            max_retries=3,
            base_delay=2.0,
            timeout_seconds=120.0,
            operation_name="Security report"
        )

        # ===================================================================
        # 3. Architecture Diagram (Mermaid with Icons)
        # ===================================================================
        arch_prompt = f"""Create a Mermaid architecture diagram for this binary.

{context}

Generate a flowchart showing:
1. **Entry Points** - Main function, exports, callbacks
2. **Core Modules** - Key functional components
3. **Data Processing** - How data flows through the binary
4. **External Dependencies** - Libraries, APIs, network services
5. **Security Components** - Crypto, auth, validation

Use Mermaid icon syntax: NodeId@{{{{ icon: "prefix:icon-name", form: "square", label: "Label" }}}}

AVAILABLE ICONS (use EXACTLY these names):
- fa:rocket - Entry point/Main
- fa:gear - Service/Module
- fa:database - Data storage
- fa:shield-halved - Security
- fa:lock - Crypto/Auth
- fa:key - API Keys
- fa:network-wired - Network
- fa:server - Server/Backend
- fa:cloud - Cloud service
- fa:code - Functions
- fa:file-code - Code module
- fa:globe - Internet
- mdi:api - REST API
- fab:windows - Windows specific
- fab:linux - Linux specific

Use subgraphs with emojis:
- "🚀 Entry Points"
- "⚙️ Core Modules"
- "💾 Data Layer"
- "🌐 External Services"
- "🔐 Security"

Return ONLY the Mermaid code starting with "flowchart TD" - no markdown blocks.

Example:
flowchart TD
    subgraph Entry["🚀 Entry Points"]
        A@{{{{ icon: "fa:rocket", form: "square", label: "main()" }}}}
    end
    subgraph Core["⚙️ Core Modules"]
        B@{{{{ icon: "fa:gear", form: "square", label: "ProcessData" }}}}
    end
    A -->|"Initialize"| B"""

        arch_response = await gemini_request_with_retry(
            lambda: client.aio.models.generate_content(
                model=settings.gemini_model_id,
                contents=[types.Content(role="user", parts=[types.Part(text=arch_prompt)])],
            ),
            max_retries=3,
            base_delay=2.0,
            timeout_seconds=120.0,
            operation_name="Architecture diagram"
        )

        # ===================================================================
        # 4. Attack Surface Map (Mermaid with Icons)
        # ===================================================================
        attack_prompt = f"""Create a Mermaid attack surface map for this binary.

{context}

Vulnerability Categories:
{chr(10).join(f'  - {v.get("category", "Unknown")}: {v.get("severity", "?")}' for v in vulnerability_findings[:10])}

Generate a flowchart showing the attack surface from an attacker's perspective:
1. **External Inputs** - Where attackers can provide input (network, files, args)
2. **Attack Vectors** - Exploitable entry points
3. **Vulnerable Components** - Functions with security issues
4. **Potential Impact** - What an attacker could achieve
5. **Mitigations** - Security protections present

Use the same icon syntax and subgraphs:
- "🌐 EXTERNAL INPUTS"
- "⚠️ ATTACK VECTORS"
- "🐛 VULNERABILITIES"
- "💥 POTENTIAL IMPACT"
- "🛡️ MITIGATIONS"

Use color styling:
- Red (:::danger) for critical vulnerabilities
- Yellow (:::warning) for medium severity
- Green (:::safe) for mitigations

Return ONLY the Mermaid code starting with "flowchart TD" - no markdown blocks.

Example:
flowchart TD
    subgraph External["🌐 EXTERNAL INPUTS"]
        E1@{{{{ icon: "fa:network-wired", form: "square", label: "Network Traffic" }}}}
        E2@{{{{ icon: "fa:file-code", form: "square", label: "File Input" }}}}
    end
    subgraph Vulns["🐛 VULNERABILITIES"]
        V1@{{{{ icon: "fa:bug", form: "square", label: "Buffer Overflow" }}}}:::danger
    end
    E1 -->|"Untrusted Data"| V1

    classDef danger fill:#ff6b6b,stroke:#c92a2a,color:#fff
    classDef warning fill:#ffd43b,stroke:#f08c00
    classDef safe fill:#51cf66,stroke:#2f9e44,color:#fff"""

        attack_surface_response = await gemini_request_with_retry(
            lambda: client.aio.models.generate_content(
                model=settings.gemini_model_id,
                contents=[types.Content(role="user", parts=[types.Part(text=attack_prompt)])],
            ),
            max_retries=3,
            base_delay=2.0,
            timeout_seconds=120.0,
            operation_name="Attack surface map"
        )

        # Clean up diagram responses
        def clean_mermaid(text: str) -> str:
            if not text:
                return ""
            text = text.strip()
            if text.startswith("```mermaid"):
                text = text[10:]
            if text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
            return text.strip()

        architecture_diagram = clean_mermaid(arch_response.text if arch_response else "")
        attack_surface_diagram = clean_mermaid(attack_surface_response.text if attack_surface_response else "")

        # Sanitize icons
        architecture_diagram = _sanitize_binary_mermaid_icons(architecture_diagram)
        attack_surface_diagram = _sanitize_binary_mermaid_icons(attack_surface_diagram)

        return {
            "functionality": func_response.text if func_response else "Not available",
            "security": sec_response.text if sec_response else "Not available",
            "architecture": architecture_diagram or "flowchart TD\n    A[Binary] --> B[Analysis Pending]",
            "attack_surface": attack_surface_diagram or "flowchart TD\n    A[Attack Surface] --> B[Analysis Pending]"
        }

    except Exception as e:
        logger.error(f"AI report generation failed: {e}", exc_info=True)
        return {}


@router.post("/scan/{scan_id}/cancel")
async def cancel_unified_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Cancel an in-progress unified binary scan."""
    if scan_id in _unified_binary_sessions:
        _unified_binary_sessions[scan_id]["cancelled"] = True
        return {"status": "cancelled"}
    raise HTTPException(status_code=404, detail="Scan not found")


# ============================================================================
# Mermaid Diagram Sanitization
# ============================================================================

# Valid icons that work with our registered icon packs
_VALID_BINARY_MERMAID_ICONS = {
    # Font Awesome 6 Solid (fa: prefix)
    "fa:rocket", "fa:mobile-screen", "fa:window-maximize", "fa:gear", "fa:database",
    "fa:shield-halved", "fa:lock", "fa:unlock", "fa:key", "fa:bug", "fa:server",
    "fa:cloud", "fa:globe", "fa:network-wired", "fa:tower-broadcast", "fa:code",
    "fa:file-code", "fa:triangle-exclamation", "fa:user", "fa:users", "fa:bell",
    "fa:credit-card", "fa:location-dot", "fa:fingerprint", "fa:user-shield",
    "fa:shield", "fa:cog", "fa:cogs", "fa:terminal", "fa:folder", "fa:file",
    "fa:download", "fa:upload", "fa:link", "fa:envelope", "fa:wifi", "fa:bolt",
    "fa:chart-bar", "fa:chart-line", "fa:check", "fa:xmark", "fa:plus", "fa:minus",
    "fa:search", "fa:eye", "fa:eye-slash", "fa:trash", "fa:pen", "fa:edit",
    "fa:mobile", "fa:tablet", "fa:laptop", "fa:desktop", "fa:home", "fa:building",
    "fa:warning", "fa:exclamation", "fa:info", "fa:question", "fa:times",

    # Font Awesome Brands (fab: prefix)
    "fab:android", "fab:apple", "fab:chrome", "fab:firefox", "fab:windows",
    "fab:linux", "fab:ubuntu", "fab:java", "fab:python", "fab:js", "fab:node",
    "fab:aws", "fab:google", "fab:microsoft",

    # Material Design Icons (mdi: prefix)
    "mdi:database", "mdi:firebase", "mdi:api", "mdi:graphql", "mdi:webhook",
    "mdi:two-factor-authentication", "mdi:language-kotlin", "mdi:language-python",
    "mdi:language-cpp", "mdi:microsoft-azure", "mdi:leaf",
}

def _sanitize_binary_mermaid_icons(diagram: str) -> str:
    """
    Sanitize Mermaid diagram to ensure only valid icons are used.

    Replaces invalid icons with valid alternatives or removes them.
    """
    if not diagram:
        return diagram

    import re

    # Find all icon references: icon: "prefix:icon-name"
    icon_pattern = r'icon:\s*"([^"]+)"'

    def replace_icon(match):
        icon_ref = match.group(1)

        # Check if valid
        if icon_ref in _VALID_BINARY_MERMAID_ICONS:
            return match.group(0)

        # Map common invalid icons to valid alternatives
        icon_mappings = {
            # Generic fallbacks
            "fa:application": "fa:window-maximize",
            "fa:app": "fa:window-maximize",
            "fa:service": "fa:gear",
            "fa:module": "fa:gear",
            "fa:function": "fa:code",
            "fa:api": "mdi:api",
            "fa:web": "fa:globe",
            "fa:internet": "fa:globe",
            "fa:crypto": "fa:lock",
            "fa:encryption": "fa:lock",
            "fa:security": "fa:shield-halved",
            "fa:vulnerability": "fa:bug",
            "fa:exploit": "fa:bug",
            "fa:attack": "fa:triangle-exclamation",
            "fa:data": "fa:database",
            "fa:storage": "fa:database",
            "fa:network": "fa:network-wired",
            "fa:process": "fa:gear",
            "fa:thread": "fa:gear",
            "fa:memory": "fa:database",
            "fa:cpu": "fa:gear",

            # Platform specific
            "mdi:windows": "fab:windows",
            "mdi:linux": "fab:linux",
            "mdi:android": "fab:android",

            # Programming languages
            "fa:c": "fa:code",
            "fa:cpp": "fa:code",
            "fa:rust": "fa:code",
            "fa:go": "fa:code",
            "mdi:c": "fa:code",
            "mdi:cpp": "fa:code",
        }

        # Try mapping
        if icon_ref in icon_mappings:
            return f'icon: "{icon_mappings[icon_ref]}"'

        # Extract category and try generic mapping
        if ":" in icon_ref:
            prefix, name = icon_ref.split(":", 1)

            # Category-based fallbacks
            if any(keyword in name.lower() for keyword in ["security", "secure", "protect"]):
                return 'icon: "fa:shield-halved"'
            elif any(keyword in name.lower() for keyword in ["lock", "encrypt", "crypto"]):
                return 'icon: "fa:lock"'
            elif any(keyword in name.lower() for keyword in ["network", "net", "connection"]):
                return 'icon: "fa:network-wired"'
            elif any(keyword in name.lower() for keyword in ["data", "database", "storage"]):
                return 'icon: "fa:database"'
            elif any(keyword in name.lower() for keyword in ["code", "function", "module"]):
                return 'icon: "fa:code"'
            elif any(keyword in name.lower() for keyword in ["bug", "vuln", "exploit"]):
                return 'icon: "fa:bug"'
            elif any(keyword in name.lower() for keyword in ["server", "service", "daemon"]):
                return 'icon: "fa:server"'
            elif any(keyword in name.lower() for keyword in ["cloud", "remote"]):
                return 'icon: "fa:cloud"'

        # Default fallback - use gear icon
        logger.warning(f"Invalid Mermaid icon '{icon_ref}' replaced with fa:gear")
        return 'icon: "fa:gear"'

    # Replace all icons
    sanitized = re.sub(icon_pattern, replace_icon, diagram)

    return sanitized
