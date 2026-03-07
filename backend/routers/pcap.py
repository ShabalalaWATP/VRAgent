"""
PCAP Analysis Router for VRAgent.

Endpoints for uploading and analyzing Wireshark packet captures.
"""

import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Any

from fastapi import APIRouter, File, HTTPException, UploadFile, Query, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.logging import get_logger
from backend.core.database import get_db
from backend.core.auth import get_current_active_user
from backend.services import pcap_service, project_service
from backend.models.models import NetworkAnalysisReport, User, DocumentAnalysisReport, ProjectDocument, ProjectNote

router = APIRouter(prefix="/pcap", tags=["pcap"])
logger = get_logger(__name__)

# Constants
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file
MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500MB total
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def _require_project_access(db: Session, project_id: int, current_user: User) -> None:
    """Ensure the current user can access the requested project."""
    if current_user.role == "admin":
        return

    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    can_access, _ = project_service.can_access_project(db, project_id, current_user.id)
    if not can_access:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")


def _get_accessible_pcap_report(db: Session, report_id: int, current_user: User) -> NetworkAnalysisReport:
    """Load a PCAP report if it exists and the current user can access it."""
    report = db.query(NetworkAnalysisReport).filter(
        NetworkAnalysisReport.id == report_id,
        NetworkAnalysisReport.analysis_type == "pcap",
    ).first()

    if not report or not project_service.can_access_network_report(db, report, current_user):
        raise HTTPException(status_code=404, detail="Report not found")

    return report


# ============================================================================
# Response Models
# ============================================================================

class PcapFindingResponse(BaseModel):
    """A security finding from PCAP analysis."""
    category: str
    severity: str
    title: str
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    packet_number: Optional[int] = None
    evidence: Optional[str] = None


class PcapSummaryResponse(BaseModel):
    """Summary statistics from PCAP analysis."""
    total_packets: int
    duration_seconds: float
    protocols: dict[str, int]
    top_talkers: List[dict]
    dns_queries: List[str]
    http_hosts: List[str]
    potential_issues: int
    # Network topology for visualization
    topology_nodes: List[dict] = []
    topology_links: List[dict] = []


# ============================================================================
# Enhanced Protocol Analysis Response Models
# ============================================================================

class TimelineEventResponse(BaseModel):
    """A significant event in the capture timeline."""
    timestamp: float
    event_type: str
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    severity: str = "info"
    details: dict = {}
    packet_number: int = 0


class HTTPSessionResponse(BaseModel):
    """An HTTP request/response pair."""
    session_id: str
    method: str
    url: str
    host: str
    path: str
    request_headers: dict = {}
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: dict = {}
    response_body: Optional[str] = None
    response_size: int = 0
    source_ip: str = ""
    dest_ip: str = ""
    request_time: Optional[float] = None
    response_time: Optional[float] = None
    duration_ms: Optional[float] = None
    request_packet: int = 0
    response_packet: int = 0


class WebSocketMessageResponse(BaseModel):
    """A WebSocket message."""
    opcode: int
    opcode_name: str
    payload: str
    payload_length: int
    is_masked: bool
    direction: str
    timestamp: float
    packet_number: int


class WebSocketSessionResponse(BaseModel):
    """A WebSocket session with messages."""
    session_id: str
    client_ip: str
    server_ip: str
    server_port: int
    url: str
    upgrade_request: Optional[dict] = None
    upgrade_response: Optional[dict] = None
    messages: List[WebSocketMessageResponse] = []
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    message_count: int = 0
    total_bytes: int = 0


class DatabaseQueryResponse(BaseModel):
    """A database query extracted from traffic."""
    protocol: str
    query_type: str
    query: str
    database: Optional[str] = None
    username: Optional[str] = None
    source_ip: str = ""
    dest_ip: str = ""
    packet_number: int = 0


class TCPStreamResponse(BaseModel):
    """A reassembled TCP stream."""
    stream_id: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    client_data_preview: str = ""
    server_data_preview: str = ""
    client_data_size: int = 0
    server_data_size: int = 0
    protocol: str = "TCP"
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    packets_count: int = 0


class ExtractedFileResponse(BaseModel):
    """A file extracted from network traffic."""
    filename: str
    mime_type: str
    size: int
    md5_hash: str
    sha256_hash: str
    source_protocol: str
    source_url: Optional[str] = None
    source_ip: str = ""
    dest_ip: str = ""
    content_preview: Optional[str] = None
    is_executable: bool = False
    packet_number: int = 0


class GRPCCallResponse(BaseModel):
    """A gRPC call extracted from traffic."""
    service: str
    method: str
    path: str
    content_type: str
    source_ip: str = ""
    dest_ip: str = ""
    packet_number: int = 0


class MQTTMessageResponse(BaseModel):
    """An MQTT message from IoT traffic."""
    message_type: str
    topic: Optional[str] = None
    payload: Optional[str] = None
    qos: int = 0
    retain: bool = False
    client_id: Optional[str] = None
    source_ip: str = ""
    dest_ip: str = ""
    packet_number: int = 0


class CoAPMessageResponse(BaseModel):
    """A CoAP message from IoT traffic."""
    message_type: str
    method: str
    uri_path: str
    payload: Optional[str] = None
    message_id: int = 0
    source_ip: str = ""
    dest_ip: str = ""
    packet_number: int = 0


class EnhancedProtocolAnalysisResponse(BaseModel):
    """Enhanced protocol analysis results."""
    # WebSocket
    websocket_sessions: List[WebSocketSessionResponse] = []
    websocket_message_count: int = 0
    
    # gRPC
    grpc_calls: List[GRPCCallResponse] = []
    grpc_services: List[str] = []
    
    # IoT Protocols
    mqtt_messages: List[MQTTMessageResponse] = []
    mqtt_topics: List[str] = []
    mqtt_clients: List[str] = []
    coap_messages: List[CoAPMessageResponse] = []
    
    # Database Traffic
    database_queries: List[DatabaseQueryResponse] = []
    databases_accessed: List[str] = []
    
    # Session Reconstruction
    http_sessions: List[HTTPSessionResponse] = []
    tcp_streams: List[TCPStreamResponse] = []
    
    # File Extraction
    extracted_files: List[ExtractedFileResponse] = []
    
    # Timeline
    timeline_events: List[TimelineEventResponse] = []
    
    # HTTP/2 and QUIC
    quic_connections: List[dict] = []
    http2_streams: List[dict] = []


class SessionReconstructionResponse(BaseModel):
    """Session reconstruction summary."""
    total_http_sessions: int
    total_websocket_sessions: int
    total_tcp_streams: int
    total_database_queries: int
    http_sessions: List[HTTPSessionResponse]
    websocket_sessions: List[WebSocketSessionResponse]
    tcp_streams: List[TCPStreamResponse]
    database_queries: List[DatabaseQueryResponse]


class TimelineAnalysisResponse(BaseModel):
    """Timeline analysis with events and phases."""
    total_events: int
    duration_seconds: float
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    events: List[TimelineEventResponse]
    phases: List[dict] = []  # Attack phases detected
    summary: dict = {}  # Event type counts, severity distribution


class PcapAnalysisResponse(BaseModel):
    """Complete analysis result for a single PCAP file."""
    filename: str
    summary: PcapSummaryResponse
    findings: List[PcapFindingResponse]
    conversations: List[dict]
    ai_analysis: Optional[Any] = None  # Now can be structured report or error dict
    attack_surface: Optional[dict] = None  # Attack surface analysis
    enhanced_protocols: Optional[EnhancedProtocolAnalysisResponse] = None  # Enhanced protocol analysis


class MultiPcapAnalysisResponse(BaseModel):
    """Combined analysis result for multiple PCAP files."""
    total_files: int
    total_packets: int
    total_findings: int
    analyses: List[PcapAnalysisResponse]
    combined_ai_summary: Optional[Any] = None  # Structured report or error dict
    report_id: Optional[int] = None  # ID of the saved report in database


class PcapStatusResponse(BaseModel):
    """Status of PCAP analysis capability."""
    available: bool
    message: str
    max_file_size_mb: int
    allowed_extensions: List[str]


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/status", response_model=PcapStatusResponse)
def get_pcap_status():
    """
    Check if PCAP analysis is available.
    
    Returns availability status and configuration info.
    """
    available = pcap_service.is_pcap_analysis_available()
    return PcapStatusResponse(
        available=available,
        message="PCAP analysis ready" if available else "scapy not installed. Install with: pip install scapy",
        max_file_size_mb=MAX_FILE_SIZE // (1024 * 1024),
        allowed_extensions=list(ALLOWED_EXTENSIONS),
    )


@router.post("/analyze", response_model=MultiPcapAnalysisResponse)
async def analyze_pcaps(
    files: List[UploadFile] = File(..., description="One or more PCAP files to analyze"),
    include_ai: bool = Query(True, description="Include AI-powered analysis"),
    max_packets: int = Query(100000, ge=1000, le=1000000, description="Max packets to analyze per file"),
    save_report: bool = Query(True, description="Save the analysis report to database"),
    project_id: Optional[int] = Query(None, description="Associate report with a project"),
    include_document_analysis: bool = Query(False, description="Include document analysis results in AI context"),
    include_notes: bool = Query(False, description="Include project notes in AI context"),
    user_context: Optional[str] = Query(None, description="User-provided context about the network environment (e.g., VM IPs, target systems, analysis focus)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Upload and analyze one or more PCAP files.
    
    Accepts .pcap, .pcapng, and .cap files.
    
    **Analysis includes:**
    - Protocol distribution
    - Top communicating hosts
    - DNS queries and HTTP hosts
    - Security findings (credentials, cleartext protocols, suspicious traffic)
    - Network conversations
    - AI-powered security assessment (optional)
    
    **Limitations:**
    - Max 100MB per file
    - Max 500MB total upload
    - Max 1M packets analyzed per file
    """
    # Check if analysis is available
    if not pcap_service.is_pcap_analysis_available():
        raise HTTPException(
            status_code=503,
            detail="PCAP analysis unavailable. The server needs scapy installed: pip install scapy"
        )
    
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    if project_id is not None:
        _require_project_access(db, project_id, current_user)
    
    # Validate files
    total_size = 0
    for file in files:
        # Check extension
        suffix = Path(file.filename or "").suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file type: {file.filename}. Allowed extensions: {', '.join(ALLOWED_EXTENSIONS)}"
            )
    
    analyses: List[PcapAnalysisResponse] = []
    total_packets = 0
    total_findings = 0
    tmp_dirs: List[Path] = []
    
    try:
        for file in files:
            # Create temp directory for this file
            tmp_dir = Path(tempfile.mkdtemp(prefix="vragent_pcap_"))
            tmp_dirs.append(tmp_dir)
            tmp_path = tmp_dir / (file.filename or "upload.pcap")
            
            # Save file with size check
            file_size = 0
            with tmp_path.open("wb") as f:
                while chunk := await file.read(65536):  # 64KB chunks
                    file_size += len(chunk)
                    if file_size > MAX_FILE_SIZE:
                        raise HTTPException(
                            status_code=400,
                            detail=f"File too large: {file.filename}. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
                        )
                    total_size += len(chunk)
                    if total_size > MAX_TOTAL_SIZE:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Total upload size exceeds {MAX_TOTAL_SIZE // (1024*1024)}MB limit"
                        )
                    f.write(chunk)
            
            logger.info(f"Analyzing PCAP: {file.filename} ({file_size:,} bytes)")
            
            # Analyze the PCAP
            try:
                result = pcap_service.analyze_pcap(tmp_path, max_packets=max_packets)
            except Exception as e:
                logger.error(f"Failed to analyze {file.filename}: {e}")
                raise HTTPException(
                    status_code=422,
                    detail=f"Failed to parse {file.filename}: {str(e)}"
                )
            
            # Run AI analysis if requested (always analyze, not just when there are findings)
            if include_ai:
                try:
                    # Build additional context from documents and notes if requested
                    additional_context = ""
                    
                    # Add user-provided context first (most important)
                    if user_context and user_context.strip():
                        additional_context += "\n\n## USER-PROVIDED CONTEXT\n"
                        additional_context += "The user has provided the following context about this network capture:\n\n"
                        additional_context += user_context.strip() + "\n"
                        additional_context += "\nPlease take this context into account when analyzing the traffic. "
                        additional_context += "Focus your analysis based on the user's described environment and objectives.\n"
                    
                    if project_id and include_document_analysis:
                        # Fetch document analysis reports
                        doc_reports = db.query(DocumentAnalysisReport).filter(
                            DocumentAnalysisReport.project_id == project_id,
                            DocumentAnalysisReport.status == "completed"
                        ).order_by(DocumentAnalysisReport.created_at.desc()).limit(5).all()
                        
                        if doc_reports:
                            additional_context += "\n\n## PROJECT DOCUMENT ANALYSIS\n"
                            for doc_report in doc_reports:
                                if doc_report.combined_summary:
                                    additional_context += f"\n### Document Analysis Summary:\n{doc_report.combined_summary}\n"
                                if doc_report.combined_key_points:
                                    additional_context += f"\nKey Points:\n"
                                    for point in doc_report.combined_key_points[:10]:
                                        additional_context += f"- {point}\n"
                                        
                                # Include individual document summaries
                                for doc in doc_report.documents:
                                    if doc.summary:
                                        additional_context += f"\n**{doc.original_filename}**: {doc.summary[:500]}\n"
                                    if doc.key_points:
                                        additional_context += "Key points:\n"
                                        for kp in doc.key_points[:5]:
                                            additional_context += f"  - {kp}\n"
                    
                    if project_id and include_notes:
                        # Fetch project notes
                        notes = db.query(ProjectNote).filter(
                            ProjectNote.project_id == project_id
                        ).order_by(ProjectNote.created_at.desc()).limit(20).all()
                        
                        if notes:
                            additional_context += "\n\n## USER NOTES\n"
                            additional_context += "The user has made the following notes about this project:\n\n"
                            for note in notes:
                                note_title = f"[{note.note_type.upper()}] {note.title}" if note.title else f"[{note.note_type.upper()}]"
                                additional_context += f"**{note_title}** ({note.created_at.strftime('%Y-%m-%d')}):\n{note.content}\n\n"
                    
                    ai_text = await pcap_service.analyze_pcap_with_ai(result, additional_context=additional_context)
                    result.ai_analysis = ai_text
                except Exception as e:
                    logger.warning(f"AI analysis failed for {file.filename}: {e}")
                    result.ai_analysis = f"AI analysis failed: {str(e)}"
            
            # Convert enhanced protocols to response model
            enhanced_protocols_response = None
            if result.enhanced_protocols:
                ep = result.enhanced_protocols
                enhanced_protocols_response = EnhancedProtocolAnalysisResponse(
                    websocket_sessions=[
                        WebSocketSessionResponse(
                            session_id=s.session_id,
                            client_ip=s.client_ip,
                            server_ip=s.server_ip,
                            server_port=s.server_port,
                            url=s.url,
                            upgrade_request=s.upgrade_request,
                            upgrade_response=s.upgrade_response,
                            messages=[
                                WebSocketMessageResponse(
                                    opcode=m.opcode,
                                    opcode_name=m.opcode_name,
                                    payload=m.payload,
                                    payload_length=m.payload_length,
                                    is_masked=m.is_masked,
                                    direction=m.direction,
                                    timestamp=m.timestamp,
                                    packet_number=m.packet_number,
                                )
                                for m in s.messages[:50]  # Limit messages per session
                            ],
                            start_time=s.start_time,
                            end_time=s.end_time,
                            message_count=s.message_count,
                            total_bytes=s.total_bytes,
                        )
                        for s in ep.websocket_sessions
                    ],
                    websocket_message_count=ep.websocket_message_count,
                    grpc_calls=[
                        GRPCCallResponse(
                            service=c.service,
                            method=c.method,
                            path=c.path,
                            content_type=c.content_type,
                            source_ip=c.source_ip,
                            dest_ip=c.dest_ip,
                            packet_number=c.packet_number,
                        )
                        for c in ep.grpc_calls
                    ],
                    grpc_services=ep.grpc_services,
                    mqtt_messages=[
                        MQTTMessageResponse(
                            message_type=m.message_type,
                            topic=m.topic,
                            payload=m.payload,
                            qos=m.qos,
                            retain=m.retain,
                            client_id=m.client_id,
                            source_ip=m.source_ip,
                            dest_ip=m.dest_ip,
                            packet_number=m.packet_number,
                        )
                        for m in ep.mqtt_messages[:100]
                    ],
                    mqtt_topics=ep.mqtt_topics,
                    mqtt_clients=ep.mqtt_clients,
                    coap_messages=[
                        CoAPMessageResponse(
                            message_type=m.message_type,
                            method=m.method,
                            uri_path=m.uri_path,
                            payload=m.payload,
                            message_id=m.message_id,
                            source_ip=m.source_ip,
                            dest_ip=m.dest_ip,
                            packet_number=m.packet_number,
                        )
                        for m in ep.coap_messages[:100]
                    ],
                    database_queries=[
                        DatabaseQueryResponse(
                            protocol=q.protocol,
                            query_type=q.query_type,
                            query=q.query,
                            database=q.database,
                            username=q.username,
                            source_ip=q.source_ip,
                            dest_ip=q.dest_ip,
                            packet_number=q.packet_number,
                        )
                        for q in ep.database_queries[:100]
                    ],
                    databases_accessed=ep.databases_accessed,
                    http_sessions=[
                        HTTPSessionResponse(
                            session_id=s.session_id,
                            method=s.method,
                            url=s.url,
                            host=s.host,
                            path=s.path,
                            request_headers=s.request_headers,
                            request_body=s.request_body,
                            response_status=s.response_status,
                            response_headers=s.response_headers,
                            response_body=s.response_body,
                            response_size=s.response_size,
                            source_ip=s.source_ip,
                            dest_ip=s.dest_ip,
                            request_time=s.request_time,
                            response_time=s.response_time,
                            duration_ms=s.duration_ms,
                            request_packet=s.request_packet,
                            response_packet=s.response_packet,
                        )
                        for s in ep.http_sessions[:200]
                    ],
                    tcp_streams=[
                        TCPStreamResponse(
                            stream_id=s.stream_id,
                            client_ip=s.client_ip,
                            server_ip=s.server_ip,
                            client_port=s.client_port,
                            server_port=s.server_port,
                            client_data_preview=s.client_data[:500].decode('utf-8', errors='replace') if s.client_data else "",
                            server_data_preview=s.server_data[:500].decode('utf-8', errors='replace') if s.server_data else "",
                            client_data_size=len(s.client_data) if s.client_data else 0,
                            server_data_size=len(s.server_data) if s.server_data else 0,
                            protocol=s.protocol,
                            start_time=s.start_time,
                            end_time=s.end_time,
                            packets_count=s.packets_count,
                        )
                        for s in ep.tcp_streams[:50]
                    ],
                    extracted_files=[
                        ExtractedFileResponse(
                            filename=f.filename,
                            mime_type=f.mime_type,
                            size=f.size,
                            md5_hash=f.md5_hash,
                            sha256_hash=f.sha256_hash,
                            source_protocol=f.source_protocol,
                            source_url=f.source_url,
                            source_ip=f.source_ip,
                            dest_ip=f.dest_ip,
                            content_preview=f.content_preview,
                            is_executable=f.is_executable,
                            packet_number=f.packet_number,
                        )
                        for f in ep.extracted_files
                    ],
                    timeline_events=[
                        TimelineEventResponse(
                            timestamp=e.timestamp,
                            event_type=e.event_type,
                            description=e.description,
                            source_ip=e.source_ip,
                            dest_ip=e.dest_ip,
                            protocol=e.protocol,
                            severity=e.severity,
                            details=e.details,
                            packet_number=e.packet_number,
                        )
                        for e in ep.timeline_events[:500]
                    ],
                    quic_connections=ep.quic_connections[:50],
                    http2_streams=ep.http2_streams[:100],
                )
            
            # Convert to response model
            analysis = PcapAnalysisResponse(
                filename=result.filename,
                summary=PcapSummaryResponse(
                    total_packets=result.summary.total_packets,
                    duration_seconds=result.summary.duration_seconds,
                    protocols=result.summary.protocols,
                    top_talkers=result.summary.top_talkers,
                    dns_queries=result.summary.dns_queries,
                    http_hosts=result.summary.http_hosts,
                    potential_issues=result.summary.potential_issues,
                    topology_nodes=result.summary.topology_nodes,
                    topology_links=result.summary.topology_links,
                ),
                findings=[
                    PcapFindingResponse(
                        category=f.category,
                        severity=f.severity,
                        title=f.title,
                        description=f.description,
                        source_ip=f.source_ip,
                        dest_ip=f.dest_ip,
                        port=f.port,
                        protocol=f.protocol,
                        packet_number=f.packet_number,
                        evidence=f.evidence,
                    )
                    for f in result.findings
                ],
                conversations=result.conversations,
                ai_analysis=result.ai_analysis,
                attack_surface=result.attack_surface.to_dict() if result.attack_surface else None,
                enhanced_protocols=enhanced_protocols_response,
            )
            
            analyses.append(analysis)
            total_packets += result.summary.total_packets
            total_findings += len(result.findings)
        
        # Build the response
        report_id = None
        
        # Save to database if requested
        if save_report and analyses:
            try:
                # Combine all filenames for title
                filenames = [a.filename for a in analyses]
                title = ", ".join(filenames) if len(filenames) <= 3 else f"{filenames[0]} and {len(filenames)-1} more"
                
                # Extract risk level from AI analysis if available
                risk_level = "medium"  # default
                risk_score = 50.0  # default
                
                # Check first analysis for AI structured report
                if analyses[0].ai_analysis:
                    ai = analyses[0].ai_analysis
                    if isinstance(ai, dict):
                        structured_report = ai.get("structured_report", {})
                        if structured_report:
                            ai_risk = structured_report.get("risk_level", "").lower()
                            if ai_risk in ["critical", "high", "medium", "low", "info"]:
                                risk_level = ai_risk
                            ai_score = structured_report.get("risk_score")
                            if ai_score is not None:
                                risk_score = float(ai_score)
                
                # Prepare JSON data
                summary_data = {
                    "total_files": len(analyses),
                    "total_packets": total_packets,
                    "total_findings": total_findings,
                    "summaries": [a.summary.model_dump() for a in analyses]
                }
                
                findings_data = []
                for a in analyses:
                    for f in a.findings:
                        finding_dict = f.model_dump()
                        finding_dict["filename"] = a.filename
                        findings_data.append(finding_dict)
                
                ai_report_data = {
                    "analyses": [a.ai_analysis for a in analyses]
                }
                report_data = {
                    "analyses": [
                        {
                            "filename": a.filename,
                            "conversations": a.conversations,
                            "attack_surface": a.attack_surface,
                            "enhanced_protocols": a.enhanced_protocols.model_dump() if a.enhanced_protocols else None,
                        }
                        for a in analyses
                    ]
                }
                
                # Create the database record
                db_report = NetworkAnalysisReport(
                    user_id=current_user.id,
                    analysis_type="pcap",
                    title=title,
                    filename=", ".join(filenames),
                    risk_level=risk_level,
                    risk_score=risk_score,
                    summary_data=summary_data,
                    findings_data=findings_data,
                    ai_report=ai_report_data,
                    report_data=report_data,
                    created_at=datetime.utcnow(),
                    project_id=project_id,
                )
                db.add(db_report)
                db.commit()
                db.refresh(db_report)
                report_id = db_report.id
                logger.info(f"Saved PCAP analysis report with ID: {report_id}")
            except Exception as e:
                logger.error(f"Failed to save report to database: {e}")
                # Don't fail the request, just log the error
                db.rollback()
        
        return MultiPcapAnalysisResponse(
            total_files=len(analyses),
            total_packets=total_packets,
            total_findings=total_findings,
            analyses=analyses,
            report_id=report_id,
        )
        
    finally:
        # Cleanup temp directories
        for tmp_dir in tmp_dirs:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass


# ============================================================================
# Chat Endpoint
# ============================================================================

class ChatMessage(BaseModel):
    """A single chat message."""
    role: str  # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    """Request to chat about a PCAP analysis."""
    message: str
    conversation_history: List[ChatMessage] = []
    pcap_context: dict  # The analysis results to provide context


class ChatResponse(BaseModel):
    """Response from the chat endpoint."""
    response: str
    error: Optional[str] = None


@router.post("/chat", response_model=ChatResponse)
async def chat_about_pcap(
    request: ChatRequest,
    current_user: User = Depends(get_current_active_user),
):
    """
    Chat with Gemini about a PCAP analysis.
    
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
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build context from the PCAP analysis
        pcap_summary = request.pcap_context.get("summary", {})
        findings = request.pcap_context.get("findings", [])
        ai_report = request.pcap_context.get("ai_analysis", {})
        captures = request.pcap_context.get("captures", [])
        
        # Extract structured report if present
        structured_report = None
        if isinstance(ai_report, dict) and "structured_report" in ai_report:
            structured_report = ai_report["structured_report"]
        elif isinstance(ai_report, dict) and isinstance(ai_report.get("analyses"), list):
            for analysis in ai_report["analyses"]:
                if isinstance(analysis, dict) and analysis.get("structured_report"):
                    structured_report = analysis["structured_report"]
                    break

        def _clip_text(value: Any, limit: int = 220) -> str:
            if value is None:
                return ""
            text = value if isinstance(value, str) else str(value)
            text = " ".join(text.split())
            if len(text) <= limit:
                return text
            return text[: limit - 3] + "..."

        def _dump_json(value: Any, limit: int = 2000) -> str:
            text = json.dumps(value, indent=2, default=str)
            if len(text) <= limit:
                return text
            return text[: limit - 15] + "\n... [truncated]"

        capture_sections = []
        if isinstance(captures, list):
            for index, capture in enumerate(captures[:6]):
                if not isinstance(capture, dict):
                    continue

                capture_summary = capture.get("summary") or {}
                capture_findings = capture.get("findings") or []
                capture_label = capture.get("label") or f"Capture {index + 1}"
                conversations = capture.get("conversations") or []
                attack_surface = capture.get("attack_surface") or {}
                enhanced_protocols = capture.get("enhanced_protocols") or {}
                capture_ai = capture.get("ai_analysis")
                capture_structured_report = capture_ai.get("structured_report") if isinstance(capture_ai, dict) else None

                section_lines = [
                    f"""#### {capture_label}
- Packets: {capture_summary.get('total_packets', 'N/A')}
- Duration: {capture_summary.get('duration_seconds', 'N/A')} seconds
- Protocols: {_dump_json(capture_summary.get('protocols', {}), limit=800)}
- DNS Queries: {_dump_json((capture_summary.get('dns_queries') or [])[:20], limit=800)}
- HTTP Hosts: {_dump_json((capture_summary.get('http_hosts') or [])[:15], limit=800)}
- Findings: {len(capture_findings)}"""
                ]

                if conversations:
                    section_lines.append(
                        "##### Conversations\n"
                        + _dump_json(
                            [
                                {
                                    "src": f"{conv.get('src')}:{conv.get('sport')}",
                                    "dst": f"{conv.get('dst')}:{conv.get('dport')}",
                                    "service": conv.get("service"),
                                    "packets": conv.get("packets"),
                                    "bytes": conv.get("bytes"),
                                }
                                for conv in conversations[:8]
                            ],
                            limit=1200,
                        )
                    )

                if attack_surface:
                    endpoints = attack_surface.get("endpoints") or []
                    auth_tokens = attack_surface.get("auth_tokens") or []
                    sensitive_leaks = attack_surface.get("sensitive_data_leaks") or []
                    protocol_weaknesses = attack_surface.get("protocol_weaknesses") or []
                    attack_lines = [
                        "##### Attack Surface",
                        f"- Unique Hosts: {_dump_json((attack_surface.get('unique_hosts') or [])[:12], limit=500)}",
                        f"- Auth Mechanisms: {_dump_json(attack_surface.get('auth_mechanisms') or [], limit=500)}",
                        f"- Auth Weaknesses: {_dump_json(attack_surface.get('auth_weaknesses') or [], limit=500)}",
                    ]
                    if endpoints:
                        attack_lines.append(
                            "- API Endpoints:\n"
                            + _dump_json(
                                [
                                    {
                                        "method": endpoint.get("method"),
                                        "url": endpoint.get("url"),
                                        "auth": endpoint.get("auth_type"),
                                        "status": endpoint.get("response_status"),
                                        "source_ip": endpoint.get("source_ip"),
                                        "dest_ip": endpoint.get("dest_ip"),
                                    }
                                    for endpoint in endpoints[:10]
                                ],
                                limit=1800,
                            )
                        )
                    if auth_tokens:
                        attack_lines.append(
                            "- Auth Tokens:\n"
                            + _dump_json(
                                [
                                    {
                                        "token_type": token.get("token_type"),
                                        "token": token.get("token_value_masked") or _clip_text(token.get("token_value"), 24),
                                        "dest_host": token.get("dest_host"),
                                        "endpoint": token.get("endpoint"),
                                        "weaknesses": token.get("jwt_weaknesses") or [],
                                    }
                                    for token in auth_tokens[:8]
                                ],
                                limit=1400,
                            )
                        )
                    if sensitive_leaks:
                        attack_lines.append(
                            "- Sensitive Data Leaks:\n"
                            + _dump_json(
                                [
                                    {
                                        "type": leak.get("data_type"),
                                        "value": _clip_text(leak.get("data_value"), 40),
                                        "context": leak.get("context"),
                                        "endpoint": leak.get("endpoint"),
                                        "severity": leak.get("severity"),
                                    }
                                    for leak in sensitive_leaks[:10]
                                ],
                                limit=1400,
                            )
                        )
                    if protocol_weaknesses:
                        attack_lines.append(
                            "- Protocol Weaknesses:\n"
                            + _dump_json(protocol_weaknesses[:10], limit=1600)
                        )
                    section_lines.append("\n".join(attack_lines))

                if enhanced_protocols:
                    protocol_sections = []
                    http_sessions = enhanced_protocols.get("http_sessions") or []
                    websocket_sessions = enhanced_protocols.get("websocket_sessions") or []
                    tcp_streams = enhanced_protocols.get("tcp_streams") or []
                    database_queries = enhanced_protocols.get("database_queries") or []
                    extracted_files = enhanced_protocols.get("extracted_files") or []
                    timeline_events = enhanced_protocols.get("timeline_events") or []
                    grpc_calls = enhanced_protocols.get("grpc_calls") or []
                    mqtt_messages = enhanced_protocols.get("mqtt_messages") or []
                    coap_messages = enhanced_protocols.get("coap_messages") or []
                    quic_connections = enhanced_protocols.get("quic_connections") or []
                    http2_streams = enhanced_protocols.get("http2_streams") or []

                    if http_sessions:
                        protocol_sections.append(
                            "###### HTTP Sessions\n"
                            + _dump_json(
                                [
                                    {
                                        "request": f"{session.get('method')} {session.get('url') or session.get('host')}{session.get('path') or ''}",
                                        "status": session.get("response_status"),
                                        "request_body": _clip_text(session.get("request_body"), 180),
                                        "response_body": _clip_text(session.get("response_body"), 180),
                                        "duration_ms": session.get("duration_ms"),
                                    }
                                    for session in http_sessions[:12]
                                ],
                                limit=2500,
                            )
                        )

                    if websocket_sessions:
                        protocol_sections.append(
                            "###### WebSocket Payloads\n"
                            + _dump_json(
                                [
                                    {
                                        "url": session.get("url"),
                                        "messages": session.get("message_count"),
                                        "sample_payloads": [
                                            {
                                                "direction": message.get("direction"),
                                                "payload": _clip_text(message.get("payload"), 140),
                                            }
                                            for message in (session.get("messages") or [])[:6]
                                        ],
                                    }
                                    for session in websocket_sessions[:6]
                                ],
                                limit=2200,
                            )
                        )

                    if tcp_streams:
                        protocol_sections.append(
                            "###### TCP Stream Previews\n"
                            + _dump_json(
                                [
                                    {
                                        "stream": f"{stream.get('client_ip')}:{stream.get('client_port')} <-> {stream.get('server_ip')}:{stream.get('server_port')}",
                                        "protocol": stream.get("protocol"),
                                        "client_preview": _clip_text(stream.get("client_data_preview"), 180),
                                        "server_preview": _clip_text(stream.get("server_data_preview"), 180),
                                        "client_bytes": stream.get("client_data_size"),
                                        "server_bytes": stream.get("server_data_size"),
                                    }
                                    for stream in tcp_streams[:10]
                                ],
                                limit=2200,
                            )
                        )

                    if database_queries:
                        protocol_sections.append(
                            "###### Database Queries\n"
                            + _dump_json(
                                [
                                    {
                                        "protocol": query.get("protocol"),
                                        "type": query.get("query_type"),
                                        "database": query.get("database"),
                                        "query": _clip_text(query.get("query"), 220),
                                    }
                                    for query in database_queries[:10]
                                ],
                                limit=1800,
                            )
                        )

                    if extracted_files:
                        protocol_sections.append(
                            "###### Extracted Files\n"
                            + _dump_json(
                                [
                                    {
                                        "filename": file_data.get("filename"),
                                        "mime_type": file_data.get("mime_type"),
                                        "size": file_data.get("size"),
                                        "source_url": file_data.get("source_url"),
                                        "preview": _clip_text(file_data.get("content_preview"), 120),
                                    }
                                    for file_data in extracted_files[:8]
                                ],
                                limit=1600,
                            )
                        )

                    if timeline_events:
                        protocol_sections.append(
                            "###### Timeline\n"
                            + _dump_json(
                                [
                                    {
                                        "severity": event.get("severity"),
                                        "event_type": event.get("event_type"),
                                        "description": event.get("description"),
                                        "source_ip": event.get("source_ip"),
                                        "dest_ip": event.get("dest_ip"),
                                    }
                                    for event in timeline_events[:12]
                                ],
                                limit=1800,
                            )
                        )

                    if grpc_calls:
                        protocol_sections.append(
                            "###### gRPC Calls\n"
                            + _dump_json(grpc_calls[:10], limit=1200)
                        )

                    if mqtt_messages or coap_messages:
                        protocol_sections.append(
                            "###### IoT Protocols\n"
                            + _dump_json(
                                {
                                    "mqtt_messages": [
                                        {
                                            "topic": message.get("topic"),
                                            "payload": _clip_text(message.get("payload"), 140),
                                            "type": message.get("message_type"),
                                        }
                                        for message in mqtt_messages[:8]
                                    ],
                                    "coap_messages": [
                                        {
                                            "method": message.get("method"),
                                            "uri_path": message.get("uri_path"),
                                            "payload": _clip_text(message.get("payload"), 140),
                                        }
                                        for message in coap_messages[:8]
                                    ],
                                },
                                limit=1600,
                            )
                        )

                    if quic_connections or http2_streams:
                        protocol_sections.append(
                            "###### Modern Encrypted/Web Traffic\n"
                            + _dump_json(
                                {
                                    "quic_connections": quic_connections[:8],
                                    "http2_streams": http2_streams[:8],
                                },
                                limit=1200,
                            )
                        )

                    if protocol_sections:
                        section_lines.append("##### Deep Protocol Inspection\n" + "\n\n".join(protocol_sections))

                if capture_structured_report:
                    section_lines.append(
                        "##### Existing AI Narrative\n"
                        + _dump_json(
                            {
                                "executive_summary": capture_structured_report.get("executive_summary"),
                                "what_happened": capture_structured_report.get("what_happened"),
                                "traffic_analysis": capture_structured_report.get("traffic_analysis"),
                            },
                            limit=2200,
                        )
                    )

                capture_sections.append("\n\n".join(section_lines))

        capture_breakdown = "\n\n### Capture Breakdown\n" + "\n\n".join(capture_sections) if capture_sections else ""
        
        # Build the system context
        context = f"""You are a helpful network security analyst assistant. You have access to a PCAP (packet capture) analysis and should answer questions about it.

## PCAP ANALYSIS CONTEXT

### Summary
- Total Files: {pcap_summary.get('total_files', len(captures) or 1)}
- Total Packets: {pcap_summary.get('total_packets', 'N/A')}
- Duration: {pcap_summary.get('duration_seconds', 'N/A')} seconds
- Protocols: {json.dumps(pcap_summary.get('protocols', {}), indent=2)}
- Top Talkers: {json.dumps(pcap_summary.get('top_talkers', [])[:10], indent=2)}
- DNS Queries: {json.dumps(pcap_summary.get('dns_queries', [])[:50], indent=2)}
- HTTP Hosts: {json.dumps(pcap_summary.get('http_hosts', [])[:30], indent=2)}
{capture_breakdown}

### Security Findings ({len(findings)} total)
{json.dumps(findings[:20], indent=2) if findings else "No automated security findings."}

### AI Security Report
{_dump_json(structured_report, limit=3000) if structured_report else "No structured report available."}

---

Answer the user's question based on this PCAP analysis. Be helpful, specific, and reference the data when relevant. If the user asks about follow-stream behavior, plaintext, request/response content, WebSocket payloads, extracted files, database traffic, or timeline sequences, use the deep protocol inspection sections when available. If the user asks about something not in the data, let them know what information is available.

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
# Report Management Endpoints
# ============================================================================

class SavedReportSummary(BaseModel):
    """Summary of a saved PCAP analysis report."""
    id: int
    title: str
    filename: str
    analysis_type: str
    risk_level: str
    risk_score: float
    total_findings: int
    created_at: datetime

class SavedReportList(BaseModel):
    """List of saved reports."""
    reports: List[SavedReportSummary]
    total: int


class SavedReportDetail(BaseModel):
    """Full details of a saved report."""
    id: int
    title: str
    filename: str
    analysis_type: str
    risk_level: str
    risk_score: float
    created_at: datetime
    summary_data: dict
    findings_data: List[dict]
    ai_report: Optional[dict] = None
    report_data: Optional[dict] = None


@router.get("/reports", response_model=SavedReportList)
async def list_pcap_reports(
    skip: int = Query(0, ge=0, description="Number of reports to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum reports to return"),
    project_id: Optional[int] = Query(None, description="Filter by project ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    List all saved PCAP analysis reports.
    
    Returns a summary of each report, ordered by most recent first.
    """
    try:
        if project_id is not None:
            _require_project_access(db, project_id, current_user)

        query = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.analysis_type == "pcap"
        )
        query = project_service.apply_network_report_access_filter(query, db, current_user)

        if project_id is not None:
            query = query.filter(NetworkAnalysisReport.project_id == project_id)

        total = query.count()

        reports = query.order_by(
            NetworkAnalysisReport.created_at.desc()
        ).offset(skip).limit(limit).all()
        
        summaries = []
        for report in reports:
            # Extract total findings from findings_data
            findings_count = len(report.findings_data) if report.findings_data else 0
            
            summaries.append(SavedReportSummary(
                id=report.id,
                title=report.title,
                filename=report.filename or "",
                analysis_type=report.analysis_type,
                risk_level=report.risk_level or "medium",
                risk_score=report.risk_score or 50.0,
                total_findings=findings_count,
                created_at=report.created_at,
            ))
        
        return SavedReportList(reports=summaries, total=total)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list reports: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {str(e)}")


@router.get("/reports/{report_id}", response_model=SavedReportDetail)
async def get_pcap_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get full details of a saved PCAP analysis report.
    """
    try:
        report = _get_accessible_pcap_report(db, report_id, current_user)
        
        return SavedReportDetail(
            id=report.id,
            title=report.title,
            filename=report.filename or "",
            analysis_type=report.analysis_type,
            risk_level=report.risk_level or "medium",
            risk_score=report.risk_score or 50.0,
            created_at=report.created_at,
            summary_data=report.summary_data or {},
            findings_data=report.findings_data or [],
            ai_report=report.ai_report,
            report_data=report.report_data,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get report {report_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get report: {str(e)}")


@router.delete("/reports/{report_id}")
async def delete_pcap_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Delete a saved PCAP analysis report.
    """
    try:
        report = _get_accessible_pcap_report(db, report_id, current_user)
        if not project_service.can_delete_network_report(db, report, current_user):
            raise HTTPException(status_code=403, detail="Not authorized to delete this report")
        
        db.delete(report)
        db.commit()
        
        return {"message": f"Report {report_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete report {report_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete report: {str(e)}")


# ============================================================================
# Timeline and Session Reconstruction Endpoints
# ============================================================================

@router.post("/timeline", response_model=TimelineAnalysisResponse)
async def analyze_timeline(
    files: List[UploadFile] = File(..., description="One or more PCAP files to analyze"),
    max_packets: int = Query(100000, ge=1000, le=1000000, description="Max packets to analyze per file"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Analyze PCAP files and return detailed timeline of events.
    
    Timeline events include:
    - HTTP requests and responses
    - WebSocket connections and messages
    - Database queries
    - Protocol detections (QUIC, HTTP/2, gRPC)
    - File transfers
    - Authentication events
    - Error responses
    
    Events are sorted chronologically and include attack phase detection.
    """
    if not pcap_service.is_pcap_analysis_available():
        raise HTTPException(
            status_code=503,
            detail="PCAP analysis unavailable. The server needs scapy installed."
        )
    
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    
    all_events: List[TimelineEventResponse] = []
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    tmp_dirs: List[Path] = []
    
    try:
        for file in files:
            # Validate extension
            suffix = Path(file.filename or "").suffix.lower()
            if suffix not in ALLOWED_EXTENSIONS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid file type: {file.filename}"
                )
            
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
            result = pcap_service.analyze_pcap(tmp_path, max_packets=max_packets)
            
            if result.enhanced_protocols:
                for event in result.enhanced_protocols.timeline_events:
                    all_events.append(TimelineEventResponse(
                        timestamp=event.timestamp,
                        event_type=event.event_type,
                        description=event.description,
                        source_ip=event.source_ip,
                        dest_ip=event.dest_ip,
                        protocol=event.protocol,
                        severity=event.severity,
                        details=event.details,
                        packet_number=event.packet_number,
                    ))
                    
                    # Track time range
                    if start_time is None or event.timestamp < start_time:
                        start_time = event.timestamp
                    if end_time is None or event.timestamp > end_time:
                        end_time = event.timestamp
        
        # Sort events by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        
        # Detect attack phases
        phases = _detect_attack_phases(all_events)
        
        # Build summary
        summary = _build_timeline_summary(all_events)
        
        duration = (end_time - start_time) if (start_time and end_time) else 0.0
        
        return TimelineAnalysisResponse(
            total_events=len(all_events),
            duration_seconds=duration,
            start_time=start_time,
            end_time=end_time,
            events=all_events[:500],  # Limit events returned
            phases=phases,
            summary=summary,
        )
        
    finally:
        for tmp_dir in tmp_dirs:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass


@router.post("/sessions", response_model=SessionReconstructionResponse)
async def reconstruct_sessions(
    files: List[UploadFile] = File(..., description="One or more PCAP files to analyze"),
    max_packets: int = Query(100000, ge=1000, le=1000000, description="Max packets to analyze per file"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Analyze PCAP files and reconstruct application sessions.
    
    Session reconstruction includes:
    - HTTP request/response pairing with timing
    - WebSocket session tracking with messages
    - TCP stream reassembly
    - Database query extraction
    
    Useful for understanding application behavior and attack sequences.
    """
    if not pcap_service.is_pcap_analysis_available():
        raise HTTPException(
            status_code=503,
            detail="PCAP analysis unavailable. The server needs scapy installed."
        )
    
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    
    all_http_sessions: List[HTTPSessionResponse] = []
    all_ws_sessions: List[WebSocketSessionResponse] = []
    all_tcp_streams: List[TCPStreamResponse] = []
    all_db_queries: List[DatabaseQueryResponse] = []
    tmp_dirs: List[Path] = []
    
    try:
        for file in files:
            # Validate extension
            suffix = Path(file.filename or "").suffix.lower()
            if suffix not in ALLOWED_EXTENSIONS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid file type: {file.filename}"
                )
            
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
            result = pcap_service.analyze_pcap(tmp_path, max_packets=max_packets)
            
            if result.enhanced_protocols:
                ep = result.enhanced_protocols
                
                # HTTP sessions
                for s in ep.http_sessions:
                    all_http_sessions.append(HTTPSessionResponse(
                        session_id=s.session_id,
                        method=s.method,
                        url=s.url,
                        host=s.host,
                        path=s.path,
                        request_headers=s.request_headers,
                        request_body=s.request_body,
                        response_status=s.response_status,
                        response_headers=s.response_headers,
                        response_body=s.response_body,
                        response_size=s.response_size,
                        source_ip=s.source_ip,
                        dest_ip=s.dest_ip,
                        request_time=s.request_time,
                        response_time=s.response_time,
                        duration_ms=s.duration_ms,
                        request_packet=s.request_packet,
                        response_packet=s.response_packet,
                    ))
                
                # WebSocket sessions
                for s in ep.websocket_sessions:
                    all_ws_sessions.append(WebSocketSessionResponse(
                        session_id=s.session_id,
                        client_ip=s.client_ip,
                        server_ip=s.server_ip,
                        server_port=s.server_port,
                        url=s.url,
                        upgrade_request=s.upgrade_request,
                        upgrade_response=s.upgrade_response,
                        messages=[
                            WebSocketMessageResponse(
                                opcode=m.opcode,
                                opcode_name=m.opcode_name,
                                payload=m.payload,
                                payload_length=m.payload_length,
                                is_masked=m.is_masked,
                                direction=m.direction,
                                timestamp=m.timestamp,
                                packet_number=m.packet_number,
                            )
                            for m in s.messages[:50]
                        ],
                        start_time=s.start_time,
                        end_time=s.end_time,
                        message_count=s.message_count,
                        total_bytes=s.total_bytes,
                    ))
                
                # TCP streams
                for s in ep.tcp_streams:
                    all_tcp_streams.append(TCPStreamResponse(
                        stream_id=s.stream_id,
                        client_ip=s.client_ip,
                        server_ip=s.server_ip,
                        client_port=s.client_port,
                        server_port=s.server_port,
                        client_data_preview=s.client_data[:500].decode('utf-8', errors='replace') if s.client_data else "",
                        server_data_preview=s.server_data[:500].decode('utf-8', errors='replace') if s.server_data else "",
                        client_data_size=len(s.client_data) if s.client_data else 0,
                        server_data_size=len(s.server_data) if s.server_data else 0,
                        protocol=s.protocol,
                        start_time=s.start_time,
                        end_time=s.end_time,
                        packets_count=s.packets_count,
                    ))
                
                # Database queries
                for q in ep.database_queries:
                    all_db_queries.append(DatabaseQueryResponse(
                        protocol=q.protocol,
                        query_type=q.query_type,
                        query=q.query,
                        database=q.database,
                        username=q.username,
                        source_ip=q.source_ip,
                        dest_ip=q.dest_ip,
                        packet_number=q.packet_number,
                    ))
        
        return SessionReconstructionResponse(
            total_http_sessions=len(all_http_sessions),
            total_websocket_sessions=len(all_ws_sessions),
            total_tcp_streams=len(all_tcp_streams),
            total_database_queries=len(all_db_queries),
            http_sessions=all_http_sessions[:200],
            websocket_sessions=all_ws_sessions[:50],
            tcp_streams=all_tcp_streams[:50],
            database_queries=all_db_queries[:100],
        )
        
    finally:
        for tmp_dir in tmp_dirs:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass


# ============================================================================
# Helper Functions for Timeline Analysis
# ============================================================================

def _detect_attack_phases(events: List[TimelineEventResponse]) -> List[dict]:
    """
    Detect attack phases from timeline events.
    
    Phases include:
    - Reconnaissance: Port scanning, service enumeration
    - Initial Access: Authentication attempts, credential exposure
    - Execution: Database queries, file operations
    - Persistence: WebSocket connections, repeated requests
    - Exfiltration: File downloads, large data transfers
    """
    phases = []
    
    if not events:
        return phases
    
    # Group events by type
    event_counts = {}
    for event in events:
        event_counts[event.event_type] = event_counts.get(event.event_type, 0) + 1
    
    # Check for reconnaissance phase
    recon_events = [e for e in events if e.event_type in ['protocol', 'http_request'] and e.severity == 'info']
    if len(recon_events) > 10:
        phases.append({
            "phase": "Reconnaissance",
            "description": "Initial probing and service discovery",
            "event_count": len(recon_events),
            "indicators": ["Multiple protocol detections", "Service enumeration"],
            "start_time": recon_events[0].timestamp if recon_events else None,
        })
    
    # Check for credential/auth phase
    auth_events = [e for e in events if e.event_type == 'credential' or 'auth' in e.description.lower()]
    if auth_events:
        phases.append({
            "phase": "Authentication Activity",
            "description": "Credential exposure or authentication attempts detected",
            "event_count": len(auth_events),
            "indicators": ["Credential transmission", "Authentication tokens"],
            "severity": "high",
            "start_time": auth_events[0].timestamp if auth_events else None,
        })
    
    # Check for database activity
    db_events = [e for e in events if e.event_type == 'database']
    if db_events:
        phases.append({
            "phase": "Database Interaction",
            "description": "Database queries and connections detected",
            "event_count": len(db_events),
            "indicators": ["SQL queries", "Database connections"],
            "start_time": db_events[0].timestamp if db_events else None,
        })
    
    # Check for file transfers
    file_events = [e for e in events if e.event_type == 'file_transfer']
    if file_events:
        phases.append({
            "phase": "Data Transfer",
            "description": "File downloads or uploads detected",
            "event_count": len(file_events),
            "indicators": ["File downloads", "Data exfiltration potential"],
            "severity": "medium",
            "start_time": file_events[0].timestamp if file_events else None,
        })
    
    # Check for WebSocket activity
    ws_events = [e for e in events if e.event_type == 'websocket']
    if ws_events:
        phases.append({
            "phase": "Real-time Communication",
            "description": "WebSocket connections established for real-time data",
            "event_count": len(ws_events),
            "indicators": ["WebSocket upgrade", "Bidirectional communication"],
            "start_time": ws_events[0].timestamp if ws_events else None,
        })
    
    # Check for errors (may indicate attack attempts)
    error_events = [e for e in events if e.event_type == 'http_error' or e.severity in ['high', 'critical']]
    if error_events:
        phases.append({
            "phase": "Error Activity",
            "description": "Server errors or suspicious activity detected",
            "event_count": len(error_events),
            "indicators": ["HTTP errors", "Security findings"],
            "severity": "medium",
            "start_time": error_events[0].timestamp if error_events else None,
        })
    
    # Sort phases by start time
    phases.sort(key=lambda p: p.get('start_time') or 0)
    
    return phases


def _build_timeline_summary(events: List[TimelineEventResponse]) -> dict:
    """Build summary statistics for timeline events."""
    if not events:
        return {
            "total_events": 0,
            "event_types": {},
            "severity_distribution": {},
            "protocols": {},
            "unique_hosts": 0,
        }
    
    event_types = {}
    severity_dist = {}
    protocols = {}
    hosts = set()
    
    for event in events:
        # Count event types
        event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
        
        # Count severities
        severity_dist[event.severity] = severity_dist.get(event.severity, 0) + 1
        
        # Count protocols
        if event.protocol:
            protocols[event.protocol] = protocols.get(event.protocol, 0) + 1
        
        # Track unique hosts
        if event.source_ip:
            hosts.add(event.source_ip)
        if event.dest_ip:
            hosts.add(event.dest_ip)
    
    return {
        "total_events": len(events),
        "event_types": event_types,
        "severity_distribution": severity_dist,
        "protocols": protocols,
        "unique_hosts": len(hosts),
        "hosts": list(hosts)[:20],  # Limit
    }

