"""
PCAP Analysis Router for VRAgent.

Endpoints for uploading and analyzing Wireshark packet captures.
"""

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
from backend.services import pcap_service
from backend.models.models import NetworkAnalysisReport

router = APIRouter(prefix="/pcap", tags=["pcap"])
logger = get_logger(__name__)

# Constants
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file
MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500MB total
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


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


class PcapAnalysisResponse(BaseModel):
    """Complete analysis result for a single PCAP file."""
    filename: str
    summary: PcapSummaryResponse
    findings: List[PcapFindingResponse]
    conversations: List[dict]
    ai_analysis: Optional[Any] = None  # Now can be structured report or error dict


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
    db: Session = Depends(get_db),
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
                    ai_text = await pcap_service.analyze_pcap_with_ai(result)
                    result.ai_analysis = ai_text
                except Exception as e:
                    logger.warning(f"AI analysis failed for {file.filename}: {e}")
                    result.ai_analysis = f"AI analysis failed: {str(e)}"
            
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
                    "analyses": [a.ai_analysis for a in analyses if a.ai_analysis]
                }
                
                # Create the database record
                db_report = NetworkAnalysisReport(
                    analysis_type="pcap",
                    title=title,
                    filename=", ".join(filenames),
                    risk_level=risk_level,
                    risk_score=risk_score,
                    summary_data=summary_data,
                    findings_data=findings_data,
                    ai_report=ai_report_data,
                    created_at=datetime.utcnow(),
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
async def chat_about_pcap(request: ChatRequest):
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
        import json
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build context from the PCAP analysis
        pcap_summary = request.pcap_context.get("summary", {})
        findings = request.pcap_context.get("findings", [])
        ai_report = request.pcap_context.get("ai_analysis", {})
        
        # Extract structured report if present
        structured_report = None
        if isinstance(ai_report, dict) and "structured_report" in ai_report:
            structured_report = ai_report["structured_report"]
        
        # Build the system context
        context = f"""You are a helpful network security analyst assistant. You have access to a PCAP (packet capture) analysis and should answer questions about it.

## PCAP ANALYSIS CONTEXT

### Summary
- Total Packets: {pcap_summary.get('total_packets', 'N/A')}
- Duration: {pcap_summary.get('duration_seconds', 'N/A')} seconds
- Protocols: {json.dumps(pcap_summary.get('protocols', {}), indent=2)}
- Top Talkers: {json.dumps(pcap_summary.get('top_talkers', [])[:10], indent=2)}
- DNS Queries: {json.dumps(pcap_summary.get('dns_queries', [])[:50], indent=2)}
- HTTP Hosts: {json.dumps(pcap_summary.get('http_hosts', [])[:30], indent=2)}

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


@router.get("/reports", response_model=SavedReportList)
async def list_pcap_reports(
    skip: int = Query(0, ge=0, description="Number of reports to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum reports to return"),
    db: Session = Depends(get_db),
):
    """
    List all saved PCAP analysis reports.
    
    Returns a summary of each report, ordered by most recent first.
    """
    try:
        # Get total count
        total = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.analysis_type == "pcap"
        ).count()
        
        # Get reports
        reports = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.analysis_type == "pcap"
        ).order_by(
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
        
    except Exception as e:
        logger.error(f"Failed to list reports: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {str(e)}")


@router.get("/reports/{report_id}", response_model=SavedReportDetail)
async def get_pcap_report(
    report_id: int,
    db: Session = Depends(get_db),
):
    """
    Get full details of a saved PCAP analysis report.
    """
    try:
        report = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.id == report_id,
            NetworkAnalysisReport.analysis_type == "pcap"
        ).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
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
):
    """
    Delete a saved PCAP analysis report.
    """
    try:
        report = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.id == report_id,
            NetworkAnalysisReport.analysis_type == "pcap"
        ).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        db.delete(report)
        db.commit()
        
        return {"message": f"Report {report_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete report {report_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete report: {str(e)}")
