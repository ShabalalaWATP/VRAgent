"""
Network Analysis Router for VRAgent.

Unified endpoints for PCAP and Nmap analysis with export and history.
"""

import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Any

from fastapi import APIRouter, File, HTTPException, UploadFile, Query, Depends
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.models.models import NetworkAnalysisReport
from backend.services import pcap_service, nmap_service, network_export_service

router = APIRouter(prefix="/network", tags=["network-analysis"])
logger = get_logger(__name__)

# Constants
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
NMAP_EXTENSIONS = {".xml", ".nmap", ".gnmap", ".txt"}


# ============================================================================
# Response Models
# ============================================================================

class NetworkFindingResponse(BaseModel):
    category: str
    severity: str
    title: str
    description: str
    host: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    evidence: Optional[str] = None


class NetworkSummaryResponse(BaseModel):
    """Generic summary for both PCAP and Nmap."""
    # Common fields
    total_findings: int
    
    # PCAP-specific
    total_packets: Optional[int] = None
    duration_seconds: Optional[float] = None
    protocols: Optional[dict] = None
    top_talkers: Optional[List[dict]] = None
    dns_queries: Optional[List[str]] = None
    http_hosts: Optional[List[str]] = None
    
    # Nmap-specific
    total_hosts: Optional[int] = None
    hosts_up: Optional[int] = None
    open_ports: Optional[int] = None
    services_detected: Optional[dict] = None
    scan_type: Optional[str] = None
    command: Optional[str] = None


class NetworkAnalysisResponse(BaseModel):
    """Analysis result for a single file."""
    analysis_type: str  # 'pcap' or 'nmap'
    filename: str
    summary: NetworkSummaryResponse
    findings: List[NetworkFindingResponse]
    hosts: Optional[List[dict]] = None  # Nmap hosts
    conversations: Optional[List[dict]] = None  # PCAP conversations
    ai_analysis: Optional[Any] = None


class MultiAnalysisResponse(BaseModel):
    """Combined analysis for multiple files."""
    analysis_type: str
    total_files: int
    total_findings: int
    analyses: List[NetworkAnalysisResponse]
    report_id: Optional[int] = None  # ID of saved report


class SavedReportResponse(BaseModel):
    """Saved report metadata."""
    id: int
    analysis_type: str
    title: str
    filename: Optional[str]
    created_at: datetime
    risk_level: Optional[str]
    risk_score: Optional[int]
    findings_count: int


class StatusResponse(BaseModel):
    """Status of network analysis capabilities."""
    pcap_available: bool
    nmap_available: bool
    nmap_installed: bool = False
    tshark_installed: bool = False
    message: str


class NmapScanTypeInfo(BaseModel):
    """Information about an Nmap scan type."""
    id: str
    name: str
    description: str
    timeout: int
    requires_root: bool
    estimated_time: str = "Unknown"
    intensity: int = 0


class NmapScanRequest(BaseModel):
    """Request to run a live Nmap scan."""
    target: str
    scan_type: str = "basic"
    ports: Optional[str] = None
    title: Optional[str] = None


class CaptureProfileInfo(BaseModel):
    """Information about a packet capture profile."""
    id: str
    name: str
    description: str
    default_filter: str
    timeout: int
    estimated_time: str
    intensity: int


class NetworkInterface(BaseModel):
    """Network interface information."""
    name: str
    description: str


class PacketCaptureRequest(BaseModel):
    """Request to run a live packet capture."""
    interface: str = "any"
    duration: int = 30
    packet_count: Optional[int] = None
    capture_filter: Optional[str] = None
    profile: str = "all"
    title: Optional[str] = None


# ============================================================================
# Helper Functions
# ============================================================================

def convert_pcap_to_response(result: pcap_service.PcapAnalysisResult) -> NetworkAnalysisResponse:
    """Convert PCAP analysis result to unified response."""
    summary = NetworkSummaryResponse(
        total_findings=len(result.findings),
        total_packets=result.summary.total_packets,
        duration_seconds=result.summary.duration_seconds,
        protocols=result.summary.protocols,
        top_talkers=result.summary.top_talkers,
        dns_queries=result.summary.dns_queries,
        http_hosts=result.summary.http_hosts,
    )
    
    findings = [
        NetworkFindingResponse(
            category=f.category,
            severity=f.severity,
            title=f.title,
            description=f.description,
            source_ip=f.source_ip,
            dest_ip=f.dest_ip,
            port=f.port,
            protocol=f.protocol,
            evidence=f.evidence,
        )
        for f in result.findings
    ]
    
    return NetworkAnalysisResponse(
        analysis_type="pcap",
        filename=result.filename,
        summary=summary,
        findings=findings,
        conversations=result.conversations,
        ai_analysis=result.ai_analysis,
    )


def convert_nmap_to_response(result: nmap_service.NmapAnalysisResult) -> NetworkAnalysisResponse:
    """Convert Nmap analysis result to unified response."""
    summary = NetworkSummaryResponse(
        total_findings=len(result.findings),
        total_hosts=result.summary.total_hosts,
        hosts_up=result.summary.hosts_up,
        open_ports=result.summary.open_ports,
        services_detected=result.summary.services_detected,
        scan_type=result.summary.scan_type,
        command=result.summary.command,
    )
    
    findings = [
        NetworkFindingResponse(
            category=f.category,
            severity=f.severity,
            title=f.title,
            description=f.description,
            host=f.host,
            port=f.port,
            service=f.service,
            evidence=f.evidence,
        )
        for f in result.findings
    ]
    
    hosts = [h.to_dict() for h in result.hosts]
    
    return NetworkAnalysisResponse(
        analysis_type="nmap",
        filename=result.filename,
        summary=summary,
        findings=findings,
        hosts=hosts,
        ai_analysis=result.ai_analysis,
    )


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/status", response_model=StatusResponse)
def get_status():
    """Check network analysis capabilities."""
    pcap_available = pcap_service.is_pcap_analysis_available()
    nmap_installed = nmap_service.is_nmap_installed()
    tshark_installed = pcap_service.is_tshark_installed()
    return StatusResponse(
        pcap_available=pcap_available,
        nmap_available=True,  # Nmap parsing is always available
        nmap_installed=nmap_installed,
        tshark_installed=tshark_installed,
        message="Network analysis ready" if pcap_available else "PCAP analysis requires scapy",
    )


@router.post("/pcap/analyze", response_model=MultiAnalysisResponse)
async def analyze_pcap_files(
    files: List[UploadFile] = File(..., description="PCAP files to analyze"),
    include_ai: bool = Query(True, description="Include AI analysis"),
    save_report: bool = Query(True, description="Save report to history"),
    title: Optional[str] = Query(None, description="Custom report title"),
    db: Session = Depends(get_db),
):
    """
    Analyze one or more PCAP files.
    
    Supports .pcap, .pcapng, .cap files up to 100MB each.
    """
    if not pcap_service.is_pcap_analysis_available():
        raise HTTPException(status_code=503, detail="PCAP analysis unavailable. Install scapy.")
    
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    
    analyses = []
    total_findings = 0
    all_findings = []
    combined_summary = {}
    combined_ai = None
    tmp_dirs = []
    
    try:
        for file in files:
            suffix = Path(file.filename or "").suffix.lower()
            if suffix not in PCAP_EXTENSIONS:
                raise HTTPException(status_code=400, detail=f"Invalid file type: {file.filename}")
            
            # Save to temp file
            tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_pcap_"))
            tmp_dirs.append(tmp_dir)
            tmp_path = tmp_dir / (file.filename or "upload.pcap")
            
            file_size = 0
            with tmp_path.open("wb") as f:
                while chunk := await file.read(65536):
                    file_size += len(chunk)
                    if file_size > MAX_FILE_SIZE:
                        raise HTTPException(status_code=400, detail=f"File too large: {file.filename}")
                    f.write(chunk)
            
            # Analyze
            result = pcap_service.analyze_pcap(tmp_path)
            
            # AI analysis
            if include_ai:
                try:
                    result.ai_analysis = await pcap_service.analyze_pcap_with_ai(result)
                    if combined_ai is None and isinstance(result.ai_analysis, dict):
                        combined_ai = result.ai_analysis
                except Exception as e:
                    logger.warning(f"AI analysis failed: {e}")
            
            response = convert_pcap_to_response(result)
            analyses.append(response)
            total_findings += len(result.findings)
            all_findings.extend([f.to_dict() for f in result.findings])
            
            # Combine summaries
            if not combined_summary:
                combined_summary = result.summary.to_dict()
            else:
                combined_summary["total_packets"] = combined_summary.get("total_packets", 0) + result.summary.total_packets
                combined_summary["potential_issues"] = combined_summary.get("potential_issues", 0) + result.summary.potential_issues
        
        # Save report if requested
        report_id = None
        if save_report:
            report_title = title or f"PCAP Analysis - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            filenames = ", ".join(f.filename or "unknown" for f in files)
            
            # Extract risk level from AI report
            risk_level = None
            risk_score = None
            if combined_ai and "structured_report" in combined_ai:
                risk_level = combined_ai["structured_report"].get("risk_level")
                risk_score = combined_ai["structured_report"].get("risk_score")
            
            db_report = NetworkAnalysisReport(
                analysis_type="pcap",
                title=report_title,
                filename=filenames[:500],
                risk_level=risk_level,
                risk_score=risk_score,
                summary_data=combined_summary,
                findings_data=all_findings,
                ai_report=combined_ai,
            )
            db.add(db_report)
            db.commit()
            db.refresh(db_report)
            report_id = db_report.id
        
        return MultiAnalysisResponse(
            analysis_type="pcap",
            total_files=len(analyses),
            total_findings=total_findings,
            analyses=analyses,
            report_id=report_id,
        )
        
    finally:
        for tmp_dir in tmp_dirs:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
# Live Packet Capture Endpoints
# ============================================================================

@router.get("/pcap/capture-profiles", response_model=List[CaptureProfileInfo])
def get_capture_profiles():
    """Get available packet capture profiles."""
    return [
        CaptureProfileInfo(**profile)
        for profile in pcap_service.get_capture_profiles()
    ]


@router.get("/pcap/interfaces", response_model=List[NetworkInterface])
def get_network_interfaces():
    """Get available network interfaces for packet capture."""
    if not pcap_service.is_tshark_installed():
        raise HTTPException(
            status_code=503,
            detail="tshark is not installed on the server"
        )
    
    interfaces = pcap_service.get_network_interfaces()
    return [NetworkInterface(**iface) for iface in interfaces]


@router.post("/pcap/validate-filter")
def validate_capture_filter(filter_expr: str = Query(..., description="BPF filter to validate")):
    """Validate a BPF capture filter expression."""
    is_valid, error = pcap_service.validate_capture_filter(filter_expr)
    return {
        "valid": is_valid,
        "filter": filter_expr,
        "error": error if not is_valid else None,
    }


@router.post("/pcap/capture", response_model=MultiAnalysisResponse)
async def run_packet_capture(
    request: PacketCaptureRequest,
    db: Session = Depends(get_db),
):
    """
    Run a live packet capture and analyze the results.
    
    **Capture Profiles:**
    - `all`: Capture all traffic
    - `http`: HTTP/HTTPS traffic (ports 80, 443, 8080)
    - `dns`: DNS queries and responses
    - `auth`: Authentication traffic (FTP, SSH, Telnet, RDP, SMB)
    - `email`: Email traffic (SMTP, POP3, IMAP)
    - `database`: Database traffic (MySQL, PostgreSQL, MSSQL, MongoDB)
    - `suspicious`: Traffic on commonly exploited ports
    - `icmp`: ICMP/ping traffic
    - `custom`: Use a custom BPF filter
    
    **Parameters:**
    - `interface`: Network interface (default: "any")
    - `duration`: Capture duration in seconds (max 300)
    - `packet_count`: Maximum packets to capture (optional)
    - `capture_filter`: Custom BPF filter (optional)
    - `profile`: Capture profile ID
    """
    # Check if tshark is installed
    if not pcap_service.is_tshark_installed():
        raise HTTPException(
            status_code=503,
            detail="tshark is not installed on the server. Please upload PCAP files instead."
        )
    
    # Check if PCAP analysis is available
    if not pcap_service.is_pcap_analysis_available():
        raise HTTPException(
            status_code=503,
            detail="PCAP analysis is not available (scapy not installed)"
        )
    
    logger.info(f"Starting packet capture: interface={request.interface}, duration={request.duration}, profile={request.profile}")
    
    # Run the capture
    output_file, command_used, error = pcap_service.run_packet_capture(
        interface=request.interface,
        duration=request.duration,
        packet_count=request.packet_count,
        capture_filter=request.capture_filter,
        profile=request.profile,
    )
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    tmp_dir = output_file.parent
    
    try:
        # Analyze the captured packets
        try:
            result = pcap_service.analyze_pcap(output_file)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Failed to analyze capture: {str(e)}")
        
        # Run AI analysis
        try:
            result.ai_analysis = await pcap_service.analyze_pcap_with_ai(result)
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")
        
        # Convert to response
        response = convert_pcap_to_response(result)
        
        # Calculate risk level from findings
        risk_level = "Low"
        risk_score = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in result.findings:
            sev = finding.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        if severity_counts["critical"] > 0:
            risk_level = "Critical"
            risk_score = 90 + min(severity_counts["critical"] * 2, 10)
        elif severity_counts["high"] > 0:
            risk_level = "High"
            risk_score = 70 + min(severity_counts["high"] * 3, 20)
        elif severity_counts["medium"] > 0:
            risk_level = "Medium"
            risk_score = 40 + min(severity_counts["medium"] * 5, 30)
        elif severity_counts["low"] > 0:
            risk_level = "Low"
            risk_score = 20 + min(severity_counts["low"] * 5, 20)
        
        # Override with AI analysis if available
        if result.ai_analysis and isinstance(result.ai_analysis, dict) and "structured_report" in result.ai_analysis:
            ai_risk = result.ai_analysis["structured_report"].get("risk_level")
            ai_score = result.ai_analysis["structured_report"].get("risk_score")
            if ai_risk:
                risk_level = ai_risk
            if ai_score:
                risk_score = ai_score
        
        # Save to database
        report_title = request.title or f"Live Capture: {request.interface} ({request.profile})"
        db_report = NetworkAnalysisReport(
            analysis_type="pcap",
            title=report_title,
            filename=f"Live capture - {request.duration}s on {request.interface}",
            risk_level=risk_level,
            risk_score=risk_score,
            summary_data=result.summary.to_dict(),
            findings_data=[f.to_dict() for f in result.findings],
            ai_report=result.ai_analysis,
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        
        logger.info(f"Capture completed: {len(result.findings)} findings, report ID: {db_report.id}")
        
        return MultiAnalysisResponse(
            analysis_type="pcap",
            total_files=1,
            total_findings=len(result.findings),
            analyses=[response],
            report_id=db_report.id,
        )
        
    finally:
        # Cleanup temp files
        shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/nmap/analyze", response_model=MultiAnalysisResponse)
async def analyze_nmap_files(
    files: List[UploadFile] = File(..., description="Nmap output files to analyze"),
    include_ai: bool = Query(True, description="Include AI analysis"),
    save_report: bool = Query(True, description="Save report to history"),
    title: Optional[str] = Query(None, description="Custom report title"),
    db: Session = Depends(get_db),
):
    """
    Analyze one or more Nmap scan output files.
    
    Supports XML (-oX), grepable (-oG), and normal (-oN) output formats.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    
    analyses = []
    total_findings = 0
    all_findings = []
    combined_summary = {}
    combined_ai = None
    tmp_dirs = []
    
    try:
        for file in files:
            suffix = Path(file.filename or "").suffix.lower()
            if suffix not in NMAP_EXTENSIONS:
                raise HTTPException(status_code=400, detail=f"Invalid file type: {file.filename}. Expected .xml, .nmap, .gnmap, or .txt")
            
            # Save to temp file
            tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_nmap_"))
            tmp_dirs.append(tmp_dir)
            tmp_path = tmp_dir / (file.filename or "upload.xml")
            
            file_size = 0
            with tmp_path.open("wb") as f:
                while chunk := await file.read(65536):
                    file_size += len(chunk)
                    if file_size > MAX_FILE_SIZE:
                        raise HTTPException(status_code=400, detail=f"File too large: {file.filename}")
                    f.write(chunk)
            
            # Analyze
            try:
                result = nmap_service.analyze_nmap(tmp_path)
            except Exception as e:
                raise HTTPException(status_code=422, detail=f"Failed to parse {file.filename}: {str(e)}")
            
            # AI analysis
            if include_ai:
                try:
                    result.ai_analysis = await nmap_service.analyze_nmap_with_ai(result)
                    if combined_ai is None and isinstance(result.ai_analysis, dict):
                        combined_ai = result.ai_analysis
                except Exception as e:
                    logger.warning(f"AI analysis failed: {e}")
            
            response = convert_nmap_to_response(result)
            analyses.append(response)
            total_findings += len(result.findings)
            all_findings.extend([f.to_dict() for f in result.findings])
            
            # Combine summaries
            if not combined_summary:
                combined_summary = result.summary.to_dict()
            else:
                combined_summary["total_hosts"] = combined_summary.get("total_hosts", 0) + result.summary.total_hosts
                combined_summary["hosts_up"] = combined_summary.get("hosts_up", 0) + result.summary.hosts_up
                combined_summary["open_ports"] = combined_summary.get("open_ports", 0) + result.summary.open_ports
        
        # Save report if requested
        report_id = None
        if save_report:
            report_title = title or f"Nmap Scan Analysis - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            filenames = ", ".join(f.filename or "unknown" for f in files)
            
            risk_level = None
            risk_score = None
            if combined_ai and "structured_report" in combined_ai:
                risk_level = combined_ai["structured_report"].get("risk_level")
                risk_score = combined_ai["structured_report"].get("risk_score")
            
            db_report = NetworkAnalysisReport(
                analysis_type="nmap",
                title=report_title,
                filename=filenames[:500],
                risk_level=risk_level,
                risk_score=risk_score,
                summary_data=combined_summary,
                findings_data=all_findings,
                ai_report=combined_ai,
            )
            db.add(db_report)
            db.commit()
            db.refresh(db_report)
            report_id = db_report.id
        
        return MultiAnalysisResponse(
            analysis_type="nmap",
            total_files=len(analyses),
            total_findings=total_findings,
            analyses=analyses,
            report_id=report_id,
        )
        
    finally:
        for tmp_dir in tmp_dirs:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
# Live Nmap Scan Endpoints
# ============================================================================

@router.get("/nmap/scan-types", response_model=List[NmapScanTypeInfo])
def get_nmap_scan_types():
    """Get available Nmap scan types with descriptions."""
    return [
        NmapScanTypeInfo(**scan_type)
        for scan_type in nmap_service.get_scan_types()
    ]


@router.post("/nmap/scan", response_model=MultiAnalysisResponse)
async def run_nmap_scan(
    request: NmapScanRequest,
    db: Session = Depends(get_db),
):
    """
    Run a live Nmap scan against a target.
    
    **Target formats:**
    - Single IP: `192.168.1.1`
    - CIDR range: `192.168.1.0/24` (max /24)
    - Hostname: `example.com`
    
    **Scan types:**
    - `quick`: Fast scan of top 100 ports
    - `basic`: Top 1000 ports with service detection
    - `full`: All 65535 ports (slower)
    - `vuln`: Vulnerability detection scripts
    - `aggressive`: OS detection, version, scripts, traceroute
    
    **Restrictions:**
    - Cannot scan localhost, loopback, or link-local addresses
    - Maximum network size is /24 (256 addresses)
    """
    # Check if nmap is installed
    if not nmap_service.is_nmap_installed():
        raise HTTPException(
            status_code=503,
            detail="Nmap is not installed on the server. Please upload Nmap XML output files instead."
        )
    
    # Validate target
    is_valid, error = nmap_service.validate_target(request.target)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)
    
    logger.info(f"Starting live Nmap scan: target={request.target}, type={request.scan_type}")
    
    # Run the scan
    output_file, command_used, error = nmap_service.run_nmap_scan(
        target=request.target,
        scan_type=request.scan_type,
        ports=request.ports,
    )
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    tmp_dir = output_file.parent
    
    try:
        # Parse and analyze the results
        try:
            result = nmap_service.analyze_nmap(output_file)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Failed to parse scan results: {str(e)}")
        
        # Run AI analysis
        try:
            result.ai_analysis = await nmap_service.analyze_nmap_with_ai(result)
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")
        
        # Convert to response
        response = convert_nmap_to_response(result)
        
        # Calculate risk level from findings
        risk_level = "Low"
        risk_score = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in result.findings:
            sev = finding.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        if severity_counts["critical"] > 0:
            risk_level = "Critical"
            risk_score = 90 + min(severity_counts["critical"] * 2, 10)
        elif severity_counts["high"] > 0:
            risk_level = "High"
            risk_score = 70 + min(severity_counts["high"] * 3, 20)
        elif severity_counts["medium"] > 0:
            risk_level = "Medium"
            risk_score = 40 + min(severity_counts["medium"] * 5, 30)
        elif severity_counts["low"] > 0:
            risk_level = "Low"
            risk_score = 20 + min(severity_counts["low"] * 5, 20)
        
        # Override with AI analysis if available
        if result.ai_analysis and "structured_report" in result.ai_analysis:
            ai_risk = result.ai_analysis["structured_report"].get("risk_level")
            ai_score = result.ai_analysis["structured_report"].get("risk_score")
            if ai_risk:
                risk_level = ai_risk
            if ai_score:
                risk_score = ai_score
        
        # Save to database
        report_title = request.title or f"Nmap Scan: {request.target}"
        db_report = NetworkAnalysisReport(
            analysis_type="nmap",
            title=report_title,
            filename=f"{request.target} ({request.scan_type} scan)",
            risk_level=risk_level,
            risk_score=risk_score,
            summary_data=result.summary.to_dict(),
            findings_data=[f.to_dict() for f in result.findings],
            ai_report=result.ai_analysis,
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        
        logger.info(f"Nmap scan completed: {len(result.findings)} findings, report ID: {db_report.id}")
        
        return MultiAnalysisResponse(
            analysis_type="nmap",
            total_files=1,
            total_findings=len(result.findings),
            analyses=[response],
            report_id=db_report.id,
        )
        
    finally:
        # Cleanup temp files
        shutil.rmtree(tmp_dir, ignore_errors=True)


@router.get("/nmap/validate-target")
def validate_nmap_target(target: str = Query(..., description="Target to validate")):
    """Validate a target before scanning."""
    is_valid, error = nmap_service.validate_target(target)
    return {
        "valid": is_valid,
        "target": target,
        "error": error if not is_valid else None,
    }


@router.get("/reports", response_model=List[SavedReportResponse])
def list_reports(
    analysis_type: Optional[str] = Query(None, description="Filter by type: pcap or nmap"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List saved network analysis reports."""
    query = db.query(NetworkAnalysisReport)
    
    if analysis_type:
        query = query.filter(NetworkAnalysisReport.analysis_type == analysis_type)
    
    reports = query.order_by(NetworkAnalysisReport.created_at.desc()).limit(limit).all()
    
    return [
        SavedReportResponse(
            id=r.id,
            analysis_type=r.analysis_type,
            title=r.title,
            filename=r.filename,
            created_at=r.created_at,
            risk_level=r.risk_level,
            risk_score=r.risk_score,
            findings_count=len(r.findings_data) if r.findings_data else 0,
        )
        for r in reports
    ]


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db)):
    """Get a specific saved report."""
    report = db.query(NetworkAnalysisReport).filter(NetworkAnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {
        "id": report.id,
        "analysis_type": report.analysis_type,
        "title": report.title,
        "filename": report.filename,
        "created_at": report.created_at,
        "risk_level": report.risk_level,
        "risk_score": report.risk_score,
        "summary_data": report.summary_data,
        "findings_data": report.findings_data,
        "ai_report": report.ai_report,
    }


@router.delete("/reports/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    """Delete a saved report."""
    report = db.query(NetworkAnalysisReport).filter(NetworkAnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    db.delete(report)
    db.commit()
    return {"status": "deleted", "report_id": report_id}


@router.get("/reports/{report_id}/export/{format}")
def export_report(
    report_id: int,
    format: str,
    db: Session = Depends(get_db),
):
    """
    Export a report to Markdown, PDF, or Word format.
    
    Supported formats: markdown, pdf, docx
    """
    report = db.query(NetworkAnalysisReport).filter(NetworkAnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if format not in ["markdown", "pdf", "docx"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use: markdown, pdf, docx")
    
    # Generate markdown first (used as base for all formats)
    markdown_content = network_export_service.generate_markdown_report(
        analysis_type=report.analysis_type,
        title=report.title,
        summary_data=report.summary_data or {},
        findings_data=report.findings_data or [],
        ai_report=report.ai_report,
    )
    
    # Update export metadata
    report.last_exported_at = datetime.utcnow()
    existing_formats = report.export_formats or []
    if format not in existing_formats:
        existing_formats.append(format)
        report.export_formats = existing_formats
    db.commit()
    
    filename = f"{report.title.replace(' ', '_')}_{report.id}"
    
    if format == "markdown":
        return Response(
            content=markdown_content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{filename}.md"'},
        )
    
    elif format == "pdf":
        try:
            pdf_bytes = network_export_service.generate_pdf_report(markdown_content)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
            )
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e))
    
    elif format == "docx":
        try:
            docx_bytes = network_export_service.generate_docx_report(markdown_content)
            return Response(
                content=docx_bytes,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": f'attachment; filename="{filename}.docx"'},
            )
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e))


# Keep legacy PCAP endpoint for backwards compatibility
@router.get("/pcap/status")
def get_pcap_status():
    """Legacy endpoint - check if PCAP analysis is available."""
    available = pcap_service.is_pcap_analysis_available()
    return {
        "available": available,
        "message": "PCAP analysis ready" if available else "scapy not installed",
        "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024),
        "allowed_extensions": list(PCAP_EXTENSIONS),
    }


# ============================================================================
# Chat Endpoint
# ============================================================================

class ChatMessage(BaseModel):
    """A single chat message."""
    role: str  # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    """Request to chat about a network analysis."""
    message: str
    conversation_history: List[ChatMessage] = []
    context: dict  # The analysis results to provide context
    analysis_type: str = "nmap"  # "nmap" or "pcap"


class ChatResponse(BaseModel):
    """Response from the chat endpoint."""
    response: str
    error: Optional[str] = None


@router.post("/chat", response_model=ChatResponse)
async def chat_about_analysis(request: ChatRequest):
    """
    Chat with Gemini about a network analysis (Nmap or PCAP).
    
    Allows users to ask follow-up questions about the analysis results.
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        return ChatResponse(
            response="",
            error="Chat unavailable: GEMINI_API_KEY not configured"
        )
    
    try:
        import google.generativeai as genai
        import json
        
        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel(settings.gemini_model_id)
        
        # Build context based on analysis type
        summary = request.context.get("summary", {})
        findings = request.context.get("findings", [])
        hosts = request.context.get("hosts", [])
        ai_report = request.context.get("ai_analysis", {})
        
        # Extract structured report if present
        structured_report = None
        if isinstance(ai_report, dict) and "structured_report" in ai_report:
            structured_report = ai_report["structured_report"]
        
        if request.analysis_type == "nmap":
            context = f"""You are a helpful network security analyst assistant. You have access to an Nmap scan analysis and should answer questions about it.

## NMAP SCAN ANALYSIS CONTEXT

### Summary
- Total Hosts: {summary.get('total_hosts', 'N/A')}
- Hosts Up: {summary.get('hosts_up', 'N/A')}
- Open Ports: {summary.get('open_ports', 'N/A')}
- Services Detected: {json.dumps(summary.get('services_detected', {}), indent=2)}
- Scan Type: {summary.get('scan_type', 'N/A')}
- Command: {summary.get('command', 'N/A')}

### Discovered Hosts
{json.dumps(hosts[:20], indent=2) if hosts else "No host details available."}

### Security Findings ({len(findings)} total)
{json.dumps(findings[:30], indent=2) if findings else "No security findings."}

### AI Security Report
{json.dumps(structured_report, indent=2) if structured_report else "No structured report available."}

---

Answer the user's question based on this Nmap scan analysis. Be helpful, specific, and reference the data when relevant. If the user asks about something not in the data, let them know what information is available.

Keep responses concise but informative. Use technical terms appropriately but explain them if the user seems to need clarification."""
        else:
            # PCAP context
            context = f"""You are a helpful network security analyst assistant. You have access to a PCAP (packet capture) analysis and should answer questions about it.

## PCAP ANALYSIS CONTEXT

### Summary
- Total Packets: {summary.get('total_packets', 'N/A')}
- Duration: {summary.get('duration_seconds', 'N/A')} seconds
- Protocols: {json.dumps(summary.get('protocols', {}), indent=2)}
- Top Talkers: {json.dumps(summary.get('top_talkers', [])[:10], indent=2)}
- DNS Queries: {json.dumps(summary.get('dns_queries', [])[:50], indent=2)}
- HTTP Hosts: {json.dumps(summary.get('http_hosts', [])[:30], indent=2)}

### Security Findings ({len(findings)} total)
{json.dumps(findings[:20], indent=2) if findings else "No automated security findings."}

### AI Security Report
{json.dumps(structured_report, indent=2) if structured_report else "No structured report available."}

---

Answer the user's question based on this PCAP analysis. Be helpful, specific, and reference the data when relevant. If the user asks about something not in the data, let them know what information is available.

Keep responses concise but informative. Use technical terms appropriately but explain them if the user seems to need clarification."""

        # Build conversation messages
        messages = [{"role": "user", "parts": [context + "\n\nThe user's first question is below."]}]
        
        # Add conversation history
        for msg in request.conversation_history:
            if msg.role == "user":
                messages.append({"role": "user", "parts": [msg.content]})
            else:
                messages.append({"role": "model", "parts": [msg.content]})
        
        # Add current message
        messages.append({"role": "user", "parts": [request.message]})
        
        # Generate response
        chat = model.start_chat(history=messages[:-1])
        response = await chat.send_message_async(request.message)
        
        return ChatResponse(response=response.text)
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return ChatResponse(
            response="",
            error=f"Failed to generate response: {str(e)}"
        )
