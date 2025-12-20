"""
Traceroute Visualization API Router

Endpoints for running traceroute scans and visualizing network paths.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import json
import asyncio
import subprocess
import platform
import re
import socket

from ..core.database import get_db
from ..core.auth import get_current_active_user
from ..models.models import NetworkAnalysisReport, User
from ..core.config import settings
from fastapi import Depends

logger = logging.getLogger("vragent.backend.routers.traceroute")
router = APIRouter(prefix="/traceroute", tags=["Traceroute Visualization"])


# ============================================================================
# Request/Response Models
# ============================================================================

class TracerouteRequest(BaseModel):
    """Request to run a traceroute."""
    target: str = Field(..., description="Target hostname or IP address")
    max_hops: int = Field(default=30, ge=1, le=64, description="Maximum number of hops")
    timeout: int = Field(default=5, ge=1, le=30, description="Timeout per hop in seconds")
    queries: int = Field(default=3, ge=1, le=10, description="Number of queries per hop")
    use_icmp: bool = Field(default=True, description="Use ICMP instead of UDP (requires admin)")
    resolve_hostnames: bool = Field(default=True, description="Resolve IP addresses to hostnames")
    save_report: bool = Field(default=True, description="Save report to database")
    report_title: Optional[str] = Field(default=None, description="Custom title for saved report")
    project_id: Optional[int] = Field(default=None, description="Associate report with a project")


class TracerouteHop(BaseModel):
    """A single hop in the traceroute."""
    hop_number: int
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: List[float] = []  # Round-trip times for each query
    avg_rtt_ms: Optional[float] = None
    packet_loss: float = 0.0  # Percentage of lost packets
    is_destination: bool = False
    is_timeout: bool = False
    asn: Optional[str] = None  # Autonomous System Number
    location: Optional[str] = None  # Geographic location (if available)


class TracerouteResult(BaseModel):
    """Complete traceroute result."""
    target: str
    target_ip: Optional[str] = None
    hops: List[TracerouteHop]
    total_hops: int
    completed: bool
    start_time: str
    end_time: str
    duration_ms: float
    platform: str
    command_used: str


class TracerouteStatusResponse(BaseModel):
    """Status of traceroute service."""
    available: bool
    traceroute_installed: bool
    platform: str
    message: str
    features: Dict[str, bool]


class TracerouteValidateResponse(BaseModel):
    """Response for target validation."""
    valid: bool
    target: Optional[str] = None
    resolved_ip: Optional[str] = None
    error: Optional[str] = None


# ============================================================================
# Helper Functions
# ============================================================================

def get_traceroute_command() -> Optional[str]:
    """Get the appropriate traceroute command for the platform."""
    system = platform.system().lower()
    
    if system == "windows":
        return "tracert"
    elif system in ["linux", "darwin"]:
        # Check if traceroute is installed
        try:
            subprocess.run(["which", "traceroute"], capture_output=True, check=True)
            return "traceroute"
        except subprocess.CalledProcessError:
            # Try mtr as fallback
            try:
                subprocess.run(["which", "mtr"], capture_output=True, check=True)
                return "mtr"
            except subprocess.CalledProcessError:
                return None
    return None


def parse_windows_tracert(output: str, target: str) -> List[TracerouteHop]:
    """Parse Windows tracert output."""
    hops = []
    lines = output.strip().split('\n')
    
    # Pattern for Windows tracert: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
    hop_pattern = re.compile(
        r'^\s*(\d+)\s+'  # Hop number
        r'(?:(\d+)\s*ms|<1\s*ms|\*)\s+'  # RTT 1
        r'(?:(\d+)\s*ms|<1\s*ms|\*)\s+'  # RTT 2
        r'(?:(\d+)\s*ms|<1\s*ms|\*)\s+'  # RTT 3
        r'(.+)$'  # IP/hostname
    )
    
    for line in lines:
        match = hop_pattern.match(line)
        if match:
            hop_num = int(match.group(1))
            rtt_values = []
            timeouts = 0
            
            for i in range(2, 5):
                rtt_str = match.group(i)
                if rtt_str and rtt_str.isdigit():
                    rtt_values.append(float(rtt_str))
                elif '<1' in line:
                    rtt_values.append(0.5)  # Approximate <1ms
                else:
                    timeouts += 1
            
            host_info = match.group(5).strip()
            ip_address = None
            hostname = None
            
            # Extract IP and hostname
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_info)
            if ip_match:
                ip_address = ip_match.group(1)
                # Check if there's a hostname before the IP
                hostname_match = re.match(r'([^\[]+)\s*\[', host_info)
                if hostname_match:
                    hostname = hostname_match.group(1).strip()
            elif host_info != "Request timed out.":
                hostname = host_info
            
            is_timeout = "Request timed out" in host_info or (not ip_address and not hostname)
            
            hop = TracerouteHop(
                hop_number=hop_num,
                ip_address=ip_address,
                hostname=hostname,
                rtt_ms=rtt_values,
                avg_rtt_ms=sum(rtt_values) / len(rtt_values) if rtt_values else None,
                packet_loss=(timeouts / 3) * 100,
                is_timeout=is_timeout,
                is_destination=ip_address == target or hostname == target
            )
            hops.append(hop)
    
    return hops


def parse_linux_traceroute(output: str, target: str, resolve: bool = True) -> List[TracerouteHop]:
    """Parse Linux/macOS traceroute output."""
    hops = []
    lines = output.strip().split('\n')
    
    # Skip the first line (header)
    for line in lines[1:]:
        if not line.strip():
            continue
            
        # Pattern: " 1  192.168.1.1 (192.168.1.1)  0.456 ms  0.389 ms  0.355 ms"
        # Or: " 1  * * *"
        parts = line.split()
        if not parts:
            continue
            
        try:
            hop_num = int(parts[0])
        except ValueError:
            continue
        
        rtt_values = []
        ip_address = None
        hostname = None
        timeouts = 0
        
        i = 1
        while i < len(parts):
            part = parts[i]
            
            if part == '*':
                timeouts += 1
                i += 1
            elif part == 'ms':
                i += 1
            elif re.match(r'^\d+\.\d+$', part):
                rtt_values.append(float(part))
                i += 1
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', part):
                ip_address = part
                i += 1
            elif part.startswith('(') and part.endswith(')'):
                # IP in parentheses
                ip_address = part[1:-1]
                i += 1
            elif not part.startswith('!') and not part == 'ms':
                # Likely a hostname
                if not hostname:
                    hostname = part
                i += 1
            else:
                i += 1
        
        is_timeout = timeouts == 3 and not ip_address
        
        hop = TracerouteHop(
            hop_number=hop_num,
            ip_address=ip_address,
            hostname=hostname if resolve else None,
            rtt_ms=rtt_values,
            avg_rtt_ms=sum(rtt_values) / len(rtt_values) if rtt_values else None,
            packet_loss=(timeouts / 3) * 100 if timeouts <= 3 else 100,
            is_timeout=is_timeout,
            is_destination=False  # Will be set later
        )
        hops.append(hop)
    
    # Mark destination
    if hops:
        for hop in reversed(hops):
            if hop.ip_address:
                hop.is_destination = True
                break
    
    return hops


async def run_traceroute(request: TracerouteRequest) -> TracerouteResult:
    """Run a traceroute and parse the results."""
    system = platform.system().lower()
    start_time = datetime.utcnow()
    
    # Resolve target to IP
    target_ip = None
    try:
        target_ip = socket.gethostbyname(request.target)
    except socket.gaierror:
        pass
    
    # Build command based on platform
    if system == "windows":
        cmd = ["tracert"]
        if not request.resolve_hostnames:
            cmd.append("-d")
        cmd.extend(["-h", str(request.max_hops)])
        cmd.extend(["-w", str(request.timeout * 1000)])  # Windows uses milliseconds
        cmd.append(request.target)
    else:
        cmd = ["traceroute"]
        if not request.resolve_hostnames:
            cmd.append("-n")
        if request.use_icmp:
            cmd.append("-I")  # ICMP mode
        cmd.extend(["-m", str(request.max_hops)])
        cmd.extend(["-w", str(request.timeout)])
        cmd.extend(["-q", str(request.queries)])
        cmd.append(request.target)
    
    command_str = " ".join(cmd)
    logger.info(f"Running traceroute: {command_str}")
    
    try:
        # Run traceroute with timeout
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        total_timeout = request.max_hops * request.timeout * request.queries + 30
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=total_timeout
        )
        
        output = stdout.decode('utf-8', errors='replace')
        
        # Parse output
        if system == "windows":
            hops = parse_windows_tracert(output, target_ip or request.target)
        else:
            hops = parse_linux_traceroute(output, target_ip or request.target, request.resolve_hostnames)
        
        end_time = datetime.utcnow()
        
        # Check if traceroute completed
        completed = any(hop.is_destination for hop in hops)
        
        return TracerouteResult(
            target=request.target,
            target_ip=target_ip,
            hops=hops,
            total_hops=len(hops),
            completed=completed,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_ms=(end_time - start_time).total_seconds() * 1000,
            platform=system,
            command_used=command_str
        )
        
    except asyncio.TimeoutError:
        end_time = datetime.utcnow()
        return TracerouteResult(
            target=request.target,
            target_ip=target_ip,
            hops=[],
            total_hops=0,
            completed=False,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_ms=(end_time - start_time).total_seconds() * 1000,
            platform=system,
            command_used=command_str
        )
    except Exception as e:
        logger.error(f"Traceroute error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def generate_ai_analysis(result: TracerouteResult) -> Dict[str, Any]:
    """Generate AI analysis of traceroute results."""
    try:
        from google import genai
        
        if not settings.gemini_api_key:
            return {"error": "Gemini API key not configured"}
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build context
        hops_summary = []
        for hop in result.hops:
            hop_info = f"Hop {hop.hop_number}: "
            if hop.is_timeout:
                hop_info += "* (timeout)"
            else:
                hop_info += f"{hop.ip_address or 'unknown'}"
                if hop.hostname:
                    hop_info += f" ({hop.hostname})"
                if hop.avg_rtt_ms:
                    hop_info += f" - {hop.avg_rtt_ms:.2f}ms"
                if hop.packet_loss > 0:
                    hop_info += f" [{hop.packet_loss:.0f}% loss]"
            hops_summary.append(hop_info)
        
        prompt = f"""Analyze this traceroute result and provide a structured security and performance assessment:

Target: {result.target} ({result.target_ip or 'IP not resolved'})
Total Hops: {result.total_hops}
Completed: {result.completed}
Duration: {result.duration_ms:.0f}ms

Path:
{chr(10).join(hops_summary)}

Provide analysis in this JSON format:
{{
    "summary": "Brief overview of the network path",
    "network_segments": [
        {{
            "segment": "Local/ISP/Transit/Destination",
            "hops": "1-3",
            "description": "Description of this segment"
        }}
    ],
    "performance_analysis": {{
        "overall_latency": "Assessment of total latency",
        "bottlenecks": ["List of hops with high latency"],
        "packet_loss_concerns": ["List of hops with packet loss"]
    }},
    "security_observations": [
        {{
            "observation": "Security-relevant finding",
            "severity": "info/low/medium/high",
            "details": "Explanation"
        }}
    ],
    "recommendations": [
        "Actionable recommendation 1",
        "Actionable recommendation 2"
    ],
    "risk_score": 0-100
}}"""
        
        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt
        )
        
        # Parse JSON response
        response_text = response.text
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            return json.loads(json_match.group())
        
        return {"raw_analysis": response_text}
        
    except Exception as e:
        logger.error(f"AI analysis error: {e}")
        return {"error": str(e)}


# ============================================================================
# API Endpoints
# ============================================================================

@router.get("/status", response_model=TracerouteStatusResponse)
async def get_traceroute_status():
    """Check if traceroute is available."""
    system = platform.system().lower()
    traceroute_cmd = get_traceroute_command()
    
    features = {
        "icmp_mode": system != "windows",  # Windows tracert always uses ICMP
        "udp_mode": system != "windows",
        "custom_queries": system != "windows",
        "hostname_resolution": True,
        "mtr_available": False
    }
    
    # Check for mtr on Linux/macOS
    if system in ["linux", "darwin"]:
        try:
            subprocess.run(["which", "mtr"], capture_output=True, check=True)
            features["mtr_available"] = True
        except subprocess.CalledProcessError:
            pass
    
    return TracerouteStatusResponse(
        available=traceroute_cmd is not None,
        traceroute_installed=traceroute_cmd is not None,
        platform=system,
        message=f"Traceroute available via '{traceroute_cmd}'" if traceroute_cmd else "Traceroute not installed",
        features=features
    )


@router.post("/validate")
async def validate_target(request: dict):
    """Validate a traceroute target."""
    target = request.get("target", "").strip()
    
    if not target:
        return TracerouteValidateResponse(valid=False, error="Target is required")
    
    # Try to resolve the target
    try:
        resolved_ip = socket.gethostbyname(target)
        return TracerouteValidateResponse(
            valid=True,
            target=target,
            resolved_ip=resolved_ip
        )
    except socket.gaierror as e:
        return TracerouteValidateResponse(
            valid=False,
            target=target,
            error=f"Could not resolve hostname: {e}"
        )


@router.post("/run")
async def run_traceroute_scan(request: TracerouteRequest, current_user: User = Depends(get_current_active_user)):
    """Run a traceroute scan."""
    # Validate target first
    try:
        socket.gethostbyname(request.target)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Could not resolve target: {request.target}")
    
    # Check if traceroute is available
    if not get_traceroute_command():
        raise HTTPException(status_code=503, detail="Traceroute is not installed on this system")
    
    # Run traceroute
    result = await run_traceroute(request)
    
    # Generate AI analysis
    ai_analysis = await generate_ai_analysis(result)
    
    # Save report if requested
    report_id = None
    if request.save_report:
        try:
            db = next(get_db())
            report = NetworkAnalysisReport(
                title=request.report_title or f"Traceroute to {request.target}",
                analysis_type="traceroute",
                report_type="traceroute",
                filename=request.target,
                risk_score=ai_analysis.get("risk_score", 0) if isinstance(ai_analysis, dict) else 0,
                total_findings=len(ai_analysis.get("security_observations", [])) if isinstance(ai_analysis, dict) else 0,
                summary=ai_analysis.get("summary", "") if isinstance(ai_analysis, dict) else "",
                report_data={
                    "result": result.model_dump(),
                    "ai_analysis": ai_analysis
                },
                ai_report=ai_analysis,
                project_id=request.project_id,
            )
            db.add(report)
            db.commit()
            db.refresh(report)
            report_id = report.id
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
    
    return {
        "result": result.model_dump(),
        "ai_analysis": ai_analysis,
        "report_id": report_id
    }


@router.post("/run/stream")
async def run_traceroute_stream(request: TracerouteRequest):
    """Run traceroute with streaming progress updates."""
    
    async def generate():
        system = platform.system().lower()
        start_time = datetime.utcnow()
        
        # Resolve target
        target_ip = None
        try:
            target_ip = socket.gethostbyname(request.target)
            yield f"data: {json.dumps({'type': 'resolved', 'ip': target_ip})}\n\n"
        except socket.gaierror as e:
            yield f"data: {json.dumps({'type': 'error', 'message': f'Could not resolve: {e}'})}\n\n"
            return
        
        # Build command
        if system == "windows":
            cmd = ["tracert", "-h", str(request.max_hops)]
            if not request.resolve_hostnames:
                cmd.append("-d")
            cmd.append(request.target)
        else:
            cmd = ["traceroute", "-m", str(request.max_hops), "-q", str(request.queries)]
            if not request.resolve_hostnames:
                cmd.append("-n")
            if request.use_icmp:
                cmd.append("-I")
            cmd.append(request.target)
        
        yield f"data: {json.dumps({'type': 'started', 'command': ' '.join(cmd)})}\n\n"
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            hops = []
            hop_num = 0
            
            async for line in process.stdout:
                line_str = line.decode('utf-8', errors='replace').strip()
                if not line_str:
                    continue
                
                # Parse and stream each hop
                if system == "windows":
                    hop_match = re.match(r'^\s*(\d+)', line_str)
                    if hop_match:
                        hop_num = int(hop_match.group(1))
                        yield f"data: {json.dumps({'type': 'hop', 'number': hop_num, 'raw': line_str})}\n\n"
                else:
                    if line_str[0].isdigit():
                        parts = line_str.split()
                        if parts:
                            try:
                                hop_num = int(parts[0])
                                yield f"data: {json.dumps({'type': 'hop', 'number': hop_num, 'raw': line_str})}\n\n"
                            except ValueError:
                                pass
                
                await asyncio.sleep(0.1)
            
            await process.wait()
            
            # Run full parse for final result
            result = await run_traceroute(request)
            ai_analysis = await generate_ai_analysis(result)
            
            # Save report
            report_id = None
            if request.save_report:
                try:
                    db = next(get_db())
                    report = NetworkAnalysisReport(
                        title=request.report_title or f"Traceroute to {request.target}",
                        analysis_type="traceroute",
                        report_type="traceroute",
                        filename=request.target,
                        risk_score=ai_analysis.get("risk_score", 0) if isinstance(ai_analysis, dict) else 0,
                        total_findings=len(ai_analysis.get("security_observations", [])) if isinstance(ai_analysis, dict) else 0,
                        summary=ai_analysis.get("summary", "") if isinstance(ai_analysis, dict) else "",
                        report_data={
                            "result": result.model_dump(),
                            "ai_analysis": ai_analysis
                        },
                        ai_report=ai_analysis,
                        project_id=request.project_id,
                    )
                    db.add(report)
                    db.commit()
                    db.refresh(report)
                    report_id = report.id
                except Exception as e:
                    logger.error(f"Failed to save report: {e}")
            
            yield f"data: {json.dumps({'type': 'complete', 'result': result.model_dump(), 'ai_analysis': ai_analysis, 'report_id': report_id})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.post("/chat")
async def chat_about_traceroute(request: dict):
    """Chat about traceroute results."""
    try:
        from google import genai
        
        if not settings.gemini_api_key:
            return {"error": "Gemini API key not configured"}
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        message = request.get("message", "")
        traceroute_context = request.get("traceroute_context", {})
        chat_history = request.get("chat_history", [])
        
        # Build context
        context = f"""You are analyzing a traceroute result. Here's the context:

Target: {traceroute_context.get('target', 'Unknown')}
Total Hops: {traceroute_context.get('total_hops', 0)}
Completed: {traceroute_context.get('completed', False)}

Answer questions about network paths, latency, routing, and security implications.
Be concise and technical but accessible."""
        
        # Build conversation
        messages = [{"role": "user", "parts": [{"text": context}]}]
        for msg in chat_history[-10:]:  # Last 10 messages
            messages.append({
                "role": "user" if msg["role"] == "user" else "model",
                "parts": [{"text": msg["content"]}]
            })
        messages.append({"role": "user", "parts": [{"text": message}]})
        
        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=messages
        )
        
        return {"response": response.text}
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return {"error": str(e)}


@router.get("/reports")
async def get_traceroute_reports():
    """Get all saved traceroute reports."""
    try:
        from sqlalchemy import or_
        db = next(get_db())
        reports = db.query(NetworkAnalysisReport).filter(
            or_(
                NetworkAnalysisReport.analysis_type == "traceroute",
                NetworkAnalysisReport.report_type == "traceroute"
            )
        ).order_by(NetworkAnalysisReport.created_at.desc()).all()
        
        return [
            {
                "id": r.id,
                "title": r.title,
                "filename": r.filename,
                "risk_score": r.risk_score,
                "total_findings": r.total_findings,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "summary": r.summary
            }
            for r in reports
        ]
    except Exception as e:
        logger.error(f"Failed to get reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/{report_id}")
async def get_traceroute_report(report_id: int):
    """Get a specific traceroute report."""
    try:
        db = next(get_db())
        report = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.id == report_id
        ).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        return {
            "id": report.id,
            "title": report.title,
            "filename": report.filename,
            "analysis_type": report.analysis_type,
            "risk_score": report.risk_score,
            "total_findings": report.total_findings,
            "summary": report.summary,
            "report_data": report.report_data,
            "ai_report": report.ai_report,
            "created_at": report.created_at.isoformat() if report.created_at else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/reports/{report_id}")
async def delete_traceroute_report(report_id: int):
    """Delete a traceroute report."""
    try:
        db = next(get_db())
        report = db.query(NetworkAnalysisReport).filter(
            NetworkAnalysisReport.id == report_id
        ).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        db.delete(report)
        db.commit()
        
        return {"status": "deleted", "report_id": report_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete report: {e}")
        raise HTTPException(status_code=500, detail=str(e))
