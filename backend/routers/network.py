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
from backend.core.auth import get_current_active_user
from backend.models.models import NetworkAnalysisReport, User, NmapScanTemplate
from backend.services import pcap_service, nmap_service, network_export_service
from backend.services import ssl_scanner_service, protocol_decoder_service

router = APIRouter(prefix="/network", tags=["network-analysis"])
logger = get_logger(__name__)

# Constants
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2GB per file - supports large network captures (was 100MB)
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
    project_id: Optional[int] = None


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
    template_id: Optional[int] = None  # Use settings from a saved template
    scripts: Optional[List[str]] = None  # Individual NSE scripts to run
    script_categories: Optional[List[str]] = None  # NSE script categories (e.g., "vuln", "safe")


# ============================================================================
# Nmap Scan Template Models
# ============================================================================

class NmapTemplateCreate(BaseModel):
    """Request to create a scan template."""
    name: str
    description: Optional[str] = None
    is_public: bool = False
    scan_type: str = "basic"
    ports: Optional[str] = None
    timing: Optional[str] = None  # T0-T5
    extra_args: Optional[str] = None
    target_pattern: Optional[str] = None


class NmapTemplateUpdate(BaseModel):
    """Request to update a scan template."""
    name: Optional[str] = None
    description: Optional[str] = None
    is_public: Optional[bool] = None
    scan_type: Optional[str] = None
    ports: Optional[str] = None
    timing: Optional[str] = None
    extra_args: Optional[str] = None
    target_pattern: Optional[str] = None


class NmapTemplateResponse(BaseModel):
    """Response for a scan template."""
    id: int
    name: str
    description: Optional[str] = None
    is_public: bool
    scan_type: str
    ports: Optional[str] = None
    timing: Optional[str] = None
    extra_args: Optional[str] = None
    target_pattern: Optional[str] = None
    user_id: Optional[int] = None
    use_count: int = 0
    created_at: datetime
    updated_at: datetime
    last_used_at: Optional[datetime] = None


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
# SSL Scanner Models
# ============================================================================

class SSLScanTarget(BaseModel):
    """A single SSL scan target."""
    host: str
    port: int = 443


class SSLScanRequest(BaseModel):
    """Request to scan SSL/TLS configuration of targets."""
    targets: List[SSLScanTarget]
    timeout: int = 10
    include_ai: bool = True
    title: Optional[str] = None
    project_id: Optional[int] = None  # Optional project association


class SSLCertificateResponse(BaseModel):
    """Certificate information."""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_expired: bool = False
    days_until_expiry: Optional[int] = None
    is_self_signed: bool = False
    signature_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    san: List[str] = []


class SSLFindingResponse(BaseModel):
    """An SSL/TLS security finding."""
    severity: str
    category: str
    title: str
    description: str
    recommendation: Optional[str] = None
    cve: Optional[str] = None


class SSLScanResultResponse(BaseModel):
    """Result for a single host."""
    host: str
    port: int
    certificate: Optional[SSLCertificateResponse] = None
    supported_protocols: List[str] = []
    cipher_suites: List[str] = []
    has_ssl: bool = False
    error: Optional[str] = None
    findings: List[SSLFindingResponse] = []
    vulnerabilities: List[dict] = []  # Detected SSL/TLS vulnerabilities
    chain_info: Optional[dict] = None  # Certificate chain validation info
    offensive_analysis: Optional[dict] = None  # JARM, cert intel, MITM analysis


class SSLScanSummaryResponse(BaseModel):
    """Summary of all SSL scans."""
    total_hosts: int
    hosts_with_ssl: int
    expired_certs: int
    self_signed_certs: int
    weak_protocols: int
    weak_ciphers: int
    critical_findings: int
    high_findings: int
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    exploitable_vulnerabilities: int = 0
    chain_issues: int = 0
    # Offensive analysis summary
    hosts_with_c2_indicators: int = 0
    hosts_with_suspicious_certs: int = 0
    hosts_mitm_possible: int = 0


class SSLScanAnalysisResponse(BaseModel):
    """Complete SSL scan analysis response."""
    results: List[SSLScanResultResponse]
    summary: SSLScanSummaryResponse
    ai_analysis: Optional[Any] = None
    report_id: Optional[int] = None


# ============================================================================
# Protocol Decoder Models
# ============================================================================

class ExtractedCredentialResponse(BaseModel):
    """An extracted credential from network traffic."""
    credential_type: str
    protocol: str
    source_ip: str
    dest_ip: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    context: Optional[str] = None
    severity: str = "critical"


class HTTPTransactionResponse(BaseModel):
    """HTTP request/response info."""
    request_method: str
    request_uri: str
    request_host: str
    source_ip: str
    dest_ip: str
    has_credentials: bool = False
    security_issues: List[str] = []


class DNSQueryResponse(BaseModel):
    """DNS query info."""
    query_name: str
    query_type: str
    source_ip: str
    dest_ip: str
    answers: List[dict] = []
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None


class ProtocolAnalysisResponse(BaseModel):
    """Complete protocol analysis response."""
    credentials: List[ExtractedCredentialResponse]
    http_transactions: List[HTTPTransactionResponse]
    dns_queries: List[DNSQueryResponse]
    ftp_sessions: List[dict]
    smtp_sessions: List[dict]
    telnet_sessions: List[dict]
    total_http_requests: int
    total_dns_queries: int
    cleartext_credentials_found: int
    suspicious_dns_queries: int
    protocol_stats: dict
    ai_analysis: Optional[Any] = None


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
    current_user: User = Depends(get_current_active_user),
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
    current_user: User = Depends(get_current_active_user),
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
    current_user: User = Depends(get_current_active_user),
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


@router.get("/nmap/script-categories")
def get_nmap_script_categories():
    """
    Get available NSE script categories that can be added to scans.
    
    These categories can be used with the `script_categories` parameter
    in the scan request to run additional scripts.
    
    **Categories:**
    - `vuln`: Vulnerability detection scripts (may trigger IDS)
    - `safe`: Non-intrusive scripts
    - `discovery`: Service enumeration
    - `auth`: Authentication checks
    - `brute`: Password brute forcing (use with caution)
    - `exploit`: Exploitation attempts (pentesting only)
    - `malware`: Malware detection
    """
    return nmap_service.get_nse_script_categories()


@router.get("/nmap/scripts")
def get_nmap_scripts():
    """
    Get available individual NSE scripts that can be run.
    
    These scripts can be used with the `scripts` parameter in the scan request.
    
    Returns a list of commonly useful NSE scripts organized by category,
    including vulnerability checks for:
    - SSL/TLS (Heartbleed, POODLE, etc.)
    - SMB (EternalBlue, MS08-067, etc.)
    - HTTP (Shellshock, Struts, Log4j, etc.)
    - Authentication issues
    """
    return nmap_service.get_nse_individual_scripts()


@router.post("/nmap/scan", response_model=MultiAnalysisResponse)
async def run_nmap_scan(
    request: NmapScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
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
    
    **Using Templates:**
    - Pass `template_id` to use saved scan configuration
    - Template settings override individual parameters
    
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
    
    # Apply template settings if template_id provided
    scan_type = request.scan_type
    ports = request.ports
    extra_args = None
    
    if request.template_id:
        template = db.query(NmapScanTemplate).filter(NmapScanTemplate.id == request.template_id).first()
        if not template:
            raise HTTPException(status_code=404, detail="Scan template not found")
        
        # Check access
        if template.user_id != current_user.id and not template.is_public:
            raise HTTPException(status_code=403, detail="Access denied to this template")
        
        # Apply template settings
        scan_type = template.scan_type or scan_type
        ports = template.ports or ports
        extra_args = template.extra_args
        
        # Update template usage stats
        template.use_count = (template.use_count or 0) + 1
        template.last_used_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"Using scan template '{template.name}' (ID: {template.id})")
    
    # Validate target
    is_valid, error = nmap_service.validate_target(request.target)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)
    
    logger.info(f"Starting live Nmap scan: target={request.target}, type={scan_type}, scripts={request.scripts}, script_categories={request.script_categories}")
    
    # Run the scan
    output_file, command_used, error = nmap_service.run_nmap_scan(
        target=request.target,
        scan_type=scan_type,
        ports=ports,
        scripts=request.scripts,
        script_categories=request.script_categories,
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
    project_id: Optional[int] = Query(None, description="Filter by project ID"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List saved network analysis reports."""
    query = db.query(NetworkAnalysisReport)
    
    if analysis_type:
        query = query.filter(NetworkAnalysisReport.analysis_type == analysis_type)
    
    if project_id is not None:
        query = query.filter(NetworkAnalysisReport.project_id == project_id)
    
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
            project_id=r.project_id,
        )
        for r in reports
    ]


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
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
def delete_report(report_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
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
    
    Handles different report types:
    - PCAP analysis reports
    - Nmap scan reports  
    - SSL/TLS scan reports (with exploitation analysis)
    """
    report = db.query(NetworkAnalysisReport).filter(NetworkAnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if format not in ["markdown", "pdf", "docx"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use: markdown, pdf, docx")
    
    # Generate markdown based on report type
    if report.analysis_type == "ssl":
        # SSL reports need special formatting with vulnerability and exploitation data
        markdown_content = network_export_service.generate_ssl_markdown_report(
            title=report.title,
            summary_data=report.summary_data or {},
            results_data=report.findings_data or [],  # SSL stores results in findings_data
            ai_report=report.ai_report,
        )
    else:
        # PCAP and Nmap reports use generic format
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
# SSL Scanner Endpoints
# ============================================================================

@router.post("/ssl/scan", response_model=SSLScanAnalysisResponse)
async def scan_ssl_hosts(
    request: SSLScanRequest,
    save_report: bool = Query(True, description="Save report to history"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Scan SSL/TLS configuration of one or more hosts.
    
    Checks for:
    - Certificate validity and expiration
    - Certificate chain validation
    - Self-signed certificates
    - Weak signature algorithms (SHA-1, MD5)
    - Deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    - Weak cipher suites
    - Key strength
    - Known vulnerabilities (POODLE, BEAST, CRIME, Heartbleed, ROBOT, etc.)
    
    **Example targets:**
    - `{"host": "example.com", "port": 443}`
    - `{"host": "192.168.1.1", "port": 8443}`
    """
    # Convert request targets to tuples
    targets = [(t.host, t.port) for t in request.targets]
    
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided")
    
    if len(targets) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 targets per scan")
    
    logger.info(f"Starting SSL scan for {len(targets)} targets")
    
    # Run the scan
    result = ssl_scanner_service.scan_multiple_hosts(targets, request.timeout)
    
    # AI analysis (exploitation-focused)
    ai_analysis = None
    if request.include_ai:
        try:
            ai_analysis = await ssl_scanner_service.analyze_ssl_with_ai(result)
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")
    
    # Convert to response
    results = []
    for r in result.results:
        cert_response = None
        if r.certificate:
            # Handle subject/issuer which may be dict or string
            subject = r.certificate.subject
            if isinstance(subject, dict):
                subject = subject.get("commonName", str(subject))
            issuer = r.certificate.issuer
            if isinstance(issuer, dict):
                issuer = issuer.get("commonName", str(issuer))
            
            cert_response = SSLCertificateResponse(
                subject=subject,
                issuer=issuer,
                serial_number=r.certificate.serial_number,
                not_before=r.certificate.not_before,
                not_after=r.certificate.not_after,
                is_expired=r.certificate.is_expired,
                days_until_expiry=r.certificate.days_until_expiry,
                is_self_signed=r.certificate.is_self_signed,
                signature_algorithm=r.certificate.signature_algorithm,
                key_type=r.certificate.public_key_type,
                key_size=r.certificate.public_key_bits,
                san=r.certificate.san or [],
            )
        
        findings = [
            SSLFindingResponse(
                severity=f.severity,
                category=f.category,
                title=f.title,
                description=f.description,
                recommendation=f.recommendation,
                cve=f.cve_ids[0] if f.cve_ids else None,
            )
            for f in r.findings
        ]
        
        # Convert vulnerabilities
        vulnerabilities = [v.to_dict() for v in r.vulnerabilities] if r.vulnerabilities else []
        
        # Convert chain info
        chain_info = r.chain_info.to_dict() if r.chain_info else None
        
        # Convert protocols_supported dict to list of supported protocol names
        supported_protocols = [proto for proto, supported in r.protocols_supported.items() if supported]
        
        # Convert cipher_suites from list of dicts to list of strings
        cipher_list = [c.get("name", str(c)) if isinstance(c, dict) else str(c) for c in r.cipher_suites]
        
        # Convert offensive analysis
        offensive_data = r.offensive_analysis.to_dict() if r.offensive_analysis else None
        
        results.append(SSLScanResultResponse(
            host=r.host,
            port=r.port,
            certificate=cert_response,
            supported_protocols=supported_protocols,
            cipher_suites=cipher_list,
            has_ssl=r.is_ssl,
            error=r.error,
            findings=findings,
            vulnerabilities=vulnerabilities,
            chain_info=chain_info,
            offensive_analysis=offensive_data,
        ))
    
    summary = SSLScanSummaryResponse(
        total_hosts=result.summary.total_hosts,
        hosts_with_ssl=result.summary.hosts_with_ssl,
        expired_certs=result.summary.certificates_expired,
        self_signed_certs=result.summary.self_signed_certs,
        weak_protocols=result.summary.hosts_with_weak_protocols,
        weak_ciphers=result.summary.hosts_with_weak_ciphers,
        critical_findings=result.summary.critical_findings,
        high_findings=result.summary.high_findings,
        total_vulnerabilities=result.summary.total_vulnerabilities,
        critical_vulnerabilities=result.summary.critical_vulnerabilities,
        exploitable_vulnerabilities=result.summary.exploitable_vulnerabilities,
        chain_issues=result.summary.chain_issues,
        # Offensive analysis summary
        hosts_with_c2_indicators=result.summary.hosts_with_c2_indicators,
        hosts_with_suspicious_certs=result.summary.hosts_with_suspicious_certs,
        hosts_mitm_possible=result.summary.hosts_mitm_possible,
    )
    
    # Save report
    report_id = None
    if save_report:
        report_title = request.title or f"SSL Scan - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        targets_str = ", ".join(f"{t.host}:{t.port}" for t in request.targets[:10])
        if len(request.targets) > 10:
            targets_str += f" (+{len(request.targets) - 10} more)"
        
        # Calculate risk (factor in vulnerabilities and C2 indicators)
        risk_level = "Low"
        risk_score = 0
        if result.summary.hosts_with_c2_indicators > 0:
            risk_level = "Critical"
            risk_score = 95
        elif result.summary.critical_findings > 0 or result.summary.critical_vulnerabilities > 0:
            risk_level = "Critical"
            risk_score = 90
        elif result.summary.hosts_with_suspicious_certs > 0:
            risk_level = "High"
            risk_score = 75
        elif result.summary.high_findings > 0 or result.summary.exploitable_vulnerabilities > 0:
            risk_level = "High"
            risk_score = 70
        elif result.summary.certificates_expired > 0 or result.summary.hosts_with_weak_protocols > 0:
            risk_level = "Medium"
            risk_score = 50
        
        db_report = NetworkAnalysisReport(
            project_id=request.project_id,  # Associate with project if provided
            analysis_type="ssl",
            title=report_title,
            filename=targets_str,
            risk_level=risk_level,
            risk_score=risk_score,
            summary_data={
                "total_hosts": result.summary.total_hosts,
                "hosts_with_ssl": result.summary.hosts_with_ssl,
                "expired_certs": result.summary.certificates_expired,
                "self_signed_certs": result.summary.self_signed_certs,
                "weak_protocols": result.summary.hosts_with_weak_protocols,
                "weak_ciphers": result.summary.hosts_with_weak_ciphers,
                "total_vulnerabilities": result.summary.total_vulnerabilities,
                "exploitable_vulnerabilities": result.summary.exploitable_vulnerabilities,
                # Offensive analysis summary
                "hosts_with_c2_indicators": result.summary.hosts_with_c2_indicators,
                "hosts_with_suspicious_certs": result.summary.hosts_with_suspicious_certs,
                "hosts_mitm_possible": result.summary.hosts_mitm_possible,
            },
            findings_data=[
                {
                    "host": r.host,
                    "port": r.port,
                    "findings": [f.to_dict() for f in r.findings],
                    "vulnerabilities": [v.to_dict() for v in r.vulnerabilities] if r.vulnerabilities else [],
                    "offensive_analysis": r.offensive_analysis.to_dict() if r.offensive_analysis else None,
                }
                for r in result.results if r.findings or r.vulnerabilities or r.offensive_analysis
            ],
            ai_report=ai_analysis,
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        report_id = db_report.id
    
    logger.info(f"SSL scan completed: {len(results)} hosts scanned, {result.summary.critical_findings} critical findings, {result.summary.total_vulnerabilities} vulnerabilities")
    
    return SSLScanAnalysisResponse(
        results=results,
        summary=summary,
        ai_analysis=ai_analysis,
        report_id=report_id,
    )


@router.get("/ssl/scan-single")
async def scan_ssl_single(
    host: str = Query(..., description="Host to scan"),
    port: int = Query(443, description="Port to scan"),
    timeout: int = Query(10, ge=1, le=30, description="Timeout in seconds"),
):
    """
    Quick SSL scan of a single host without saving to history.
    
    Returns certificate info, security findings, and offensive analysis.
    """
    result = ssl_scanner_service.scan_ssl_host(host, port, timeout)
    
    cert_response = None
    if result.certificate:
        # Handle subject/issuer which may be dict or string
        subject = result.certificate.subject
        if isinstance(subject, dict):
            subject = subject.get("commonName", str(subject))
        issuer = result.certificate.issuer
        if isinstance(issuer, dict):
            issuer = issuer.get("commonName", str(issuer))
            
        cert_response = SSLCertificateResponse(
            subject=subject,
            issuer=issuer,
            serial_number=result.certificate.serial_number,
            not_before=result.certificate.not_before,
            not_after=result.certificate.not_after,
            is_expired=result.certificate.is_expired,
            days_until_expiry=result.certificate.days_until_expiry,
            is_self_signed=result.certificate.is_self_signed,
            signature_algorithm=result.certificate.signature_algorithm,
            key_type=result.certificate.public_key_type,
            key_size=result.certificate.public_key_bits,
            san=result.certificate.san or [],
        )
    
    findings = [
        SSLFindingResponse(
            severity=f.severity,
            category=f.category,
            title=f.title,
            description=f.description,
            recommendation=f.recommendation,
            cve=f.cve_ids[0] if f.cve_ids else None,
        )
        for f in result.findings
    ]
    
    # Convert protocols_supported dict to list
    supported_protocols = [proto for proto, supported in result.protocols_supported.items() if supported]
    
    # Convert cipher_suites
    cipher_list = [c.get("name", str(c)) if isinstance(c, dict) else str(c) for c in result.cipher_suites]
    
    # Convert vulnerabilities
    vulnerabilities = [v.to_dict() for v in result.vulnerabilities] if result.vulnerabilities else []
    
    # Convert chain info
    chain_info = result.chain_info.to_dict() if result.chain_info else None
    
    # Convert offensive analysis
    offensive_data = result.offensive_analysis.to_dict() if result.offensive_analysis else None
    
    return SSLScanResultResponse(
        host=result.host,
        port=result.port,
        certificate=cert_response,
        supported_protocols=supported_protocols,
        cipher_suites=cipher_list,
        has_ssl=result.is_ssl,
        error=result.error,
        findings=findings,
        vulnerabilities=vulnerabilities,
        chain_info=chain_info,
        offensive_analysis=offensive_data,
    )


# ============================================================================
# SSL Chat Endpoint
# ============================================================================

class SSLChatRequest(BaseModel):
    """Request to chat about SSL scan results."""
    message: str
    context: str = ""
    scan_results: Optional[dict] = None


class SSLChatResponse(BaseModel):
    """Response from the SSL chat endpoint."""
    response: str
    error: Optional[str] = None


@router.post("/ssl/chat", response_model=SSLChatResponse)
async def chat_about_ssl_scan(request: SSLChatRequest):
    """
    Chat with AI about SSL/TLS scan results.
    
    Allows users to ask follow-up questions about SSL vulnerabilities,
    certificate issues, and security recommendations.
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        return SSLChatResponse(
            response="",
            error="Chat unavailable: GEMINI_API_KEY not configured"
        )
    
    try:
        from google import genai
        import json
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build context from scan results
        scan_context = request.context or ""
        if request.scan_results:
            results = request.scan_results.get("results", [])
            summary = request.scan_results.get("summary", {})
            ai_analysis = request.scan_results.get("ai_analysis", {})
            
            scan_context = f"""SSL/TLS Scan Results:

## Summary
- Total Hosts Scanned: {summary.get('total_hosts', 'N/A')}
- Hosts with SSL: {summary.get('hosts_with_ssl', 'N/A')}
- Expired Certificates: {summary.get('expired_certs', 0)}
- Self-Signed Certificates: {summary.get('self_signed_certs', 0)}
- Weak Protocols Detected: {summary.get('weak_protocols', 0)}
- Weak Ciphers Detected: {summary.get('weak_ciphers', 0)}
- Critical Findings: {summary.get('critical_findings', 0)}
- High Severity Findings: {summary.get('high_findings', 0)}
- Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}

## Host Details
{json.dumps(results[:10], indent=2, default=str) if results else "No host details"}

## AI Security Analysis
{json.dumps(ai_analysis.get('structured_report', ai_analysis) if ai_analysis else {}, indent=2, default=str)}
"""

        system_prompt = f"""You are an expert SSL/TLS security analyst assistant. You help users understand SSL/TLS scan results, certificate issues, and security vulnerabilities.

{scan_context}

Based on the above SSL/TLS scan context, answer the user's questions. Be specific about:
- Certificate validity and expiration dates
- Protocol vulnerabilities (SSLv3, TLS 1.0, etc.)
- Cipher suite weaknesses
- Known CVEs and their exploitation potential
- Remediation recommendations

Keep responses concise but informative. Use technical terms but explain them when needed."""

        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=[
                {"role": "user", "parts": [{"text": system_prompt}]},
                {"role": "user", "parts": [{"text": request.message}]}
            ],
        )
        
        return SSLChatResponse(response=response.text)
        
    except Exception as e:
        logger.error(f"SSL chat error: {e}")
        return SSLChatResponse(
            response="",
            error=f"Chat failed: {str(e)}"
        )


# ============================================================================
# SSL Scan History Endpoints
# ============================================================================

class SSLScanHistoryItem(BaseModel):
    """SSL scan history item for listing."""
    id: int
    title: str
    targets: str
    created_at: datetime
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    total_hosts: Optional[int] = None
    findings_count: int = 0
    project_id: Optional[int] = None
    project_name: Optional[str] = None


class SSLScanHistoryResponse(BaseModel):
    """SSL scan history list response."""
    scans: List[SSLScanHistoryItem]
    total: int


@router.get("/ssl/history", response_model=SSLScanHistoryResponse)
async def get_ssl_scan_history(
    project_id: Optional[int] = Query(None, description="Filter by project ID"),
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get SSL scan history.
    
    Returns list of past SSL scans with their metadata.
    Optionally filter by project_id.
    """
    from backend.models.models import Project
    
    query = db.query(NetworkAnalysisReport).filter(
        NetworkAnalysisReport.analysis_type == "ssl"
    )
    
    if project_id is not None:
        query = query.filter(NetworkAnalysisReport.project_id == project_id)
    
    total = query.count()
    scans = query.order_by(NetworkAnalysisReport.created_at.desc()).offset(offset).limit(limit).all()
    
    items = []
    for scan in scans:
        summary = scan.summary_data or {}
        findings_count = len(scan.findings_data) if scan.findings_data else 0
        
        # Get project name if associated
        project_name = None
        if scan.project_id:
            project = db.query(Project).filter(Project.id == scan.project_id).first()
            if project:
                project_name = project.name
        
        items.append(SSLScanHistoryItem(
            id=scan.id,
            title=scan.title,
            targets=scan.filename or "",
            created_at=scan.created_at,
            risk_level=scan.risk_level,
            risk_score=scan.risk_score,
            total_hosts=summary.get("total_hosts"),
            findings_count=findings_count,
            project_id=scan.project_id,
            project_name=project_name,
        ))
    
    return SSLScanHistoryResponse(scans=items, total=total)


@router.get("/ssl/history/{scan_id}")
async def get_ssl_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get detailed SSL scan by ID.
    
    Returns full scan data including all findings and AI analysis.
    """
    scan = db.query(NetworkAnalysisReport).filter(
        NetworkAnalysisReport.id == scan_id,
        NetworkAnalysisReport.analysis_type == "ssl"
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="SSL scan not found")
    
    return {
        "id": scan.id,
        "title": scan.title,
        "targets": scan.filename,
        "created_at": scan.created_at,
        "risk_level": scan.risk_level,
        "risk_score": scan.risk_score,
        "summary": scan.summary_data,
        "findings": scan.findings_data,
        "ai_analysis": scan.ai_report,
        "project_id": scan.project_id,
    }


@router.put("/ssl/history/{scan_id}/project")
async def associate_ssl_scan_with_project(
    scan_id: int,
    project_id: int = Query(..., description="Project ID to associate"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Associate an SSL scan with a project.
    
    This allows standalone SSL scans to be included in Combined Analysis.
    """
    from backend.models.models import Project
    
    scan = db.query(NetworkAnalysisReport).filter(
        NetworkAnalysisReport.id == scan_id,
        NetworkAnalysisReport.analysis_type == "ssl"
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="SSL scan not found")
    
    # Verify project exists
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Verify user has access to project
    if project.owner_id != current_user.id and current_user.role != "admin":
        # Check if collaborator
        from backend.models.models import ProjectCollaborator
        collab = db.query(ProjectCollaborator).filter(
            ProjectCollaborator.project_id == project_id,
            ProjectCollaborator.user_id == current_user.id
        ).first()
        if not collab:
            raise HTTPException(status_code=403, detail="No access to this project")
    
    scan.project_id = project_id
    db.commit()
    
    return {"message": f"SSL scan associated with project '{project.name}'", "project_id": project_id}


@router.delete("/ssl/history/{scan_id}")
async def delete_ssl_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Delete an SSL scan from history.
    """
    scan = db.query(NetworkAnalysisReport).filter(
        NetworkAnalysisReport.id == scan_id,
        NetworkAnalysisReport.analysis_type == "ssl"
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="SSL scan not found")
    
    db.delete(scan)
    db.commit()
    
    return {"message": "SSL scan deleted", "id": scan_id}


# ============================================================================
# Protocol Decoder Endpoints
# ============================================================================

@router.post("/pcap/decode-protocols", response_model=ProtocolAnalysisResponse)
async def decode_pcap_protocols(
    file: UploadFile = File(..., description="PCAP file to analyze"),
    include_ai: bool = Query(True, description="Include AI analysis"),
    max_packets: int = Query(50000, ge=1000, le=100000, description="Maximum packets to analyze"),
):
    """
    Deep protocol analysis of a PCAP file.
    
    Extracts:
    - Cleartext credentials (HTTP Basic, FTP, Telnet, SMTP)
    - HTTP transactions with security analysis
    - DNS queries with suspicious pattern detection
    - API keys and tokens
    - Form submissions with sensitive data
    
    **Warning:** This analysis may extract sensitive credentials from the capture.
    Ensure you have authorization to analyze this traffic.
    """
    if not protocol_decoder_service.PYSHARK_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Protocol decoding requires pyshark. Install with: pip install pyshark"
        )
    
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in PCAP_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Invalid file type: {file.filename}")
    
    tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_protocol_"))
    tmp_path = tmp_dir / (file.filename or "upload.pcap")
    
    try:
        # Save uploaded file
        file_size = 0
        with tmp_path.open("wb") as f:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=400, detail="File too large")
                f.write(chunk)
        
        logger.info(f"Starting protocol analysis of {file.filename}")
        
        # Run analysis
        result = protocol_decoder_service.decode_protocols_from_pcap(str(tmp_path), max_packets)
        
        # AI analysis
        ai_analysis = None
        if include_ai:
            try:
                ai_analysis = protocol_decoder_service.analyze_protocols_with_ai(result)
            except Exception as e:
                logger.warning(f"AI analysis failed: {e}")
        
        # Convert to response
        credentials = [
            ExtractedCredentialResponse(
                credential_type=c.credential_type,
                protocol=c.protocol,
                source_ip=c.source_ip,
                dest_ip=c.dest_ip,
                port=c.port,
                username=c.username,
                password=c.password[:3] + "***" if c.password and len(c.password) > 3 else c.password,  # Mask password
                token=c.token[:10] + "..." if c.token and len(c.token) > 10 else c.token,  # Truncate token
                context=c.context,
                severity=c.severity,
            )
            for c in result.credentials
        ]
        
        http_transactions = [
            HTTPTransactionResponse(
                request_method=h.request_method,
                request_uri=h.request_uri[:200],
                request_host=h.request_host,
                source_ip=h.source_ip,
                dest_ip=h.dest_ip,
                has_credentials=h.has_credentials,
                security_issues=h.security_issues,
            )
            for h in result.http_transactions[:100]  # Limit for response size
        ]
        
        dns_queries = [
            DNSQueryResponse(
                query_name=d.query_name,
                query_type=d.query_type,
                source_ip=d.source_ip,
                dest_ip=d.dest_ip,
                answers=d.answers,
                is_suspicious=d.is_suspicious,
                suspicion_reason=d.suspicion_reason,
            )
            for d in result.dns_queries[:200]
        ]
        
        logger.info(f"Protocol analysis completed: {len(credentials)} credentials found")
        
        return ProtocolAnalysisResponse(
            credentials=credentials,
            http_transactions=http_transactions,
            dns_queries=dns_queries,
            ftp_sessions=[s.to_dict() for s in result.ftp_sessions],
            smtp_sessions=[s.to_dict() for s in result.smtp_sessions],
            telnet_sessions=[s.to_dict() for s in result.telnet_sessions],
            total_http_requests=result.total_http_requests,
            total_dns_queries=result.total_dns_queries,
            cleartext_credentials_found=result.cleartext_credentials_found,
            suspicious_dns_queries=result.suspicious_dns_queries,
            protocol_stats=result.protocol_stats,
            ai_analysis=ai_analysis,
        )
        
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@router.get("/pcap/decoder-status")
def get_decoder_status():
    """Check if protocol decoding is available."""
    return {
        "available": protocol_decoder_service.PYSHARK_AVAILABLE,
        "message": "Protocol decoder ready" if protocol_decoder_service.PYSHARK_AVAILABLE else "pyshark not installed",
        "supported_protocols": ["HTTP", "DNS", "FTP", "SMTP", "Telnet"] if protocol_decoder_service.PYSHARK_AVAILABLE else [],
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
        from google import genai
        from google.genai import types
        import json
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
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
        
        return ChatResponse(response=response.text)
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return ChatResponse(
            response="",
            error=f"Failed to generate response: {str(e)}"
        )


# ============================================================================
# Nmap Scan Template Endpoints
# ============================================================================

@router.post("/nmap/templates", response_model=NmapTemplateResponse)
async def create_scan_template(
    template: NmapTemplateCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Create a new Nmap scan template.
    
    Templates can be private (only visible to creator) or public (visible to all).
    Stores scan configuration for reuse.
    """
    db_template = NmapScanTemplate(
        user_id=current_user.id,
        name=template.name,
        description=template.description,
        is_public=template.is_public,
        scan_type=template.scan_type,
        ports=template.ports,
        timing=template.timing,
        extra_args=template.extra_args,
        target_pattern=template.target_pattern,
    )
    db.add(db_template)
    db.commit()
    db.refresh(db_template)
    
    logger.info(f"User {current_user.id} created scan template '{template.name}'")
    
    return NmapTemplateResponse(
        id=db_template.id,
        name=db_template.name,
        description=db_template.description,
        is_public=db_template.is_public,
        scan_type=db_template.scan_type,
        ports=db_template.ports,
        timing=db_template.timing,
        extra_args=db_template.extra_args,
        target_pattern=db_template.target_pattern,
        user_id=db_template.user_id,
        use_count=db_template.use_count,
        created_at=db_template.created_at,
        updated_at=db_template.updated_at,
        last_used_at=db_template.last_used_at,
    )


@router.get("/nmap/templates", response_model=List[NmapTemplateResponse])
async def list_scan_templates(
    include_public: bool = Query(True, description="Include public templates"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    List available Nmap scan templates.
    
    Returns user's own templates plus public templates (if include_public=True).
    """
    query = db.query(NmapScanTemplate)
    
    if include_public:
        # User's templates OR public templates
        query = query.filter(
            (NmapScanTemplate.user_id == current_user.id) |
            (NmapScanTemplate.is_public == True)
        )
    else:
        # Only user's templates
        query = query.filter(NmapScanTemplate.user_id == current_user.id)
    
    templates = query.order_by(NmapScanTemplate.use_count.desc(), NmapScanTemplate.created_at.desc()).all()
    
    return [
        NmapTemplateResponse(
            id=t.id,
            name=t.name,
            description=t.description,
            is_public=t.is_public,
            scan_type=t.scan_type,
            ports=t.ports,
            timing=t.timing,
            extra_args=t.extra_args,
            target_pattern=t.target_pattern,
            user_id=t.user_id,
            use_count=t.use_count,
            created_at=t.created_at,
            updated_at=t.updated_at,
            last_used_at=t.last_used_at,
        )
        for t in templates
    ]


@router.get("/nmap/templates/{template_id}", response_model=NmapTemplateResponse)
async def get_scan_template(
    template_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a specific scan template."""
    template = db.query(NmapScanTemplate).filter(NmapScanTemplate.id == template_id).first()
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    # Check access: must be owner or template must be public
    if template.user_id != current_user.id and not template.is_public:
        raise HTTPException(status_code=403, detail="Access denied to this template")
    
    return NmapTemplateResponse(
        id=template.id,
        name=template.name,
        description=template.description,
        is_public=template.is_public,
        scan_type=template.scan_type,
        ports=template.ports,
        timing=template.timing,
        extra_args=template.extra_args,
        target_pattern=template.target_pattern,
        user_id=template.user_id,
        use_count=template.use_count,
        created_at=template.created_at,
        updated_at=template.updated_at,
        last_used_at=template.last_used_at,
    )


@router.put("/nmap/templates/{template_id}", response_model=NmapTemplateResponse)
async def update_scan_template(
    template_id: int,
    update: NmapTemplateUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update a scan template (owner only)."""
    template = db.query(NmapScanTemplate).filter(NmapScanTemplate.id == template_id).first()
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    # Only owner can update
    if template.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the template owner can update it")
    
    # Update fields
    if update.name is not None:
        template.name = update.name
    if update.description is not None:
        template.description = update.description
    if update.is_public is not None:
        template.is_public = update.is_public
    if update.scan_type is not None:
        template.scan_type = update.scan_type
    if update.ports is not None:
        template.ports = update.ports
    if update.timing is not None:
        template.timing = update.timing
    if update.extra_args is not None:
        template.extra_args = update.extra_args
    if update.target_pattern is not None:
        template.target_pattern = update.target_pattern
    
    db.commit()
    db.refresh(template)
    
    return NmapTemplateResponse(
        id=template.id,
        name=template.name,
        description=template.description,
        is_public=template.is_public,
        scan_type=template.scan_type,
        ports=template.ports,
        timing=template.timing,
        extra_args=template.extra_args,
        target_pattern=template.target_pattern,
        user_id=template.user_id,
        use_count=template.use_count,
        created_at=template.created_at,
        updated_at=template.updated_at,
        last_used_at=template.last_used_at,
    )


@router.delete("/nmap/templates/{template_id}")
async def delete_scan_template(
    template_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Delete a scan template (owner only)."""
    template = db.query(NmapScanTemplate).filter(NmapScanTemplate.id == template_id).first()
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    # Only owner can delete
    if template.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the template owner can delete it")
    
    db.delete(template)
    db.commit()
    
    return {"message": "Template deleted", "id": template_id}
